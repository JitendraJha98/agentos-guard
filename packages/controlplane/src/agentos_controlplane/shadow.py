"""DISC-04 — shadow-agent detection: who is acting without being registered.

The pipeline already DENIES these (IDN-02); this store makes them VISIBLE, because a hundred denies
from one unregistered id is an incident and a single deny is noise. Recording only — no new deny
path. Adding a second deny would change behaviour, not visibility.

Everything here treats `claimed_agent_id` as hostile input: it is whatever an UNVERIFIED caller put
in its token, so it is

  * bounded and sanitized before storage — a 10 MB id must not become a 10 MB row, and SQLite does
    not enforce the column width, so bounding happens at the source and both backends store the
    same row;
  * never a metric label (the Phase-6 cardinality lesson — an unbounded label set is a DoS, and the
    pipeline's own `verified_box` guard already refuses to label with an unverified id);
  * never placed RAW in a hash-covered audit body. The body carries the bounded sanitized id plus a
    digest of the FULL raw string, so an attacker cannot name itself after a credential and trip
    the AUD-04 secret gate to permanently block its own sighting, and truncation cannot make two
    different attackers indistinguishable in the evidence chain.

`action_type` is not caller text — the pipeline passes a closed `ActionType` enum value.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone

from sqlalchemy import select

from agentos_controlplane.secret_scan import scan
from agentos_controlplane.store.models import ShadowAgent

_MAX_ID = 255
# Control characters and anything exotic are replaced rather than stored: an operator reads these in
# a dashboard and a log, and a claimed id is a place to hide terminal escapes or a payload.
_SAFE = re.compile(r"[^A-Za-z0-9._:@-]")

# `<` and `>` are OUTSIDE the accepted charset above, so no claimed id can sanitize INTO either
# placeholder and impersonate the anonymous bucket or a redaction.
EMPTY_ID = "<empty>"
SECRET_LIKE_ID = "<secret-like>"


def sanitize_claimed_id(raw: str) -> str:
    """Bound and flatten an attacker-controlled identifier. Empty input becomes a stable
    placeholder so anonymous probes still aggregate into one row instead of vanishing."""
    text = _SAFE.sub("?", (raw or "")[:_MAX_ID])
    return text or EMPTY_ID


def claimed_id_digest(raw: str) -> str:
    """A short digest of the FULL raw id, so truncation cannot make two different attackers look
    like one in the evidence chain."""
    return hashlib.sha256((raw or "").encode("utf-8", "replace")).hexdigest()[:16]


def chain_safe_id(safe: str) -> str:
    """The sanitized id AS IT MAY APPEAR IN THE HASH-COVERED BODY.

    Sanitizing is not enough on its own: `AKIAIOSFODNN7EXAMPLE` survives the charset filter
    unchanged, so an attacker could name itself after a credential, trip AUD-04's fail-closed
    secret gate, and permanently prevent its own sighting from being recorded. Pre-screening with
    the SAME scanner the gate uses turns that into a placeholder instead. The recognisable id still
    reaches the operator through the `shadow_agent` TABLE — the Phase-9 convention that hostile or
    free-text detail lives in the row while the chain carries identifiers + a digest — and the
    digest keeps two such attackers distinct.
    """
    return SECRET_LIKE_ID if scan(safe) else safe


def _now() -> datetime:
    """Python-side UTC stamp (naive, matching the stored rows). Used instead of `func.now()` so
    `last_seen_at` has sub-second resolution — SQLite's CURRENT_TIMESTAMP is second-granular, which
    would make "most recent sighting first" arbitrary during a burst."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class ShadowAgentStore:
    """Records sightings of unregistered actors and audits the FIRST one per claimed id."""

    def __init__(self, session_factory, audit) -> None:
        self._sf = session_factory
        self._audit = audit

    async def record(self, claimed_agent_id: str, action_type: str) -> bool:
        """Record one sighting. Returns True if this was the FIRST time this id was seen.

        Only a first sighting is audited: a flood of attempts from one id is a single incident, and
        appending an event per attempt would let an unregistered caller grow the hash chain at will.
        """
        safe = sanitize_claimed_id(claimed_agent_id)
        now = _now()
        with self._sf() as s:
            row = s.get(ShadowAgent, safe)
            first = row is None
            if row is None:
                s.add(
                    ShadowAgent(
                        claimed_agent_id=safe,
                        action_type=action_type,
                        attempts=1,
                        first_seen_at=now,
                        last_seen_at=now,
                    )
                )
            else:
                row.attempts += 1
                row.action_type = action_type
                row.last_seen_at = now
            s.commit()
        if first:
            await self._audit.append_event(
                "shadow_agent_detected",
                {
                    "claimed_agent_id": chain_safe_id(safe),
                    "claimed_id_digest": claimed_id_digest(claimed_agent_id),
                    "action_type": action_type,
                },
            )
        return first

    def list_shadow_agents(self) -> list[dict]:
        with self._sf() as s:
            rows = s.scalars(select(ShadowAgent).order_by(ShadowAgent.last_seen_at.desc())).all()
            return [
                {
                    "claimed_agent_id": r.claimed_agent_id,
                    "action_type": r.action_type,
                    "attempts": r.attempts,
                    "first_seen_at": r.first_seen_at.isoformat() if r.first_seen_at else None,
                    "last_seen_at": r.last_seen_at.isoformat() if r.last_seen_at else None,
                }
                for r in rows
            ]
