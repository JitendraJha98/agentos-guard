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
    the AUD-04 secret gate to permanently block its own sighting.

## Two dimensions, two bounds

Bounding one attempt is not bounding the attacker. Only a FIRST sighting is audited, which caps
what ONE claimed id can do — but the caller picks the id, so rotating it bought a new row AND a new
tamper-evident chain record per probe. So the number of DISTINCT ids is capped as well
(`max_rows`): past the cap every further new id folds into a single `<overflow>` bucket whose
`attempts` still counts. The operator keeps the signal ("an unregistered actor is probing, here are
the first N ids and how much was folded away") and the growth lever is finite. The read is bounded
at the query too — a table that predates the cap must still not become one multi-hundred-MB JSON
response (the dashboard's `.limit(50)` / reputation's `_max_signals` precedent).

## Row identity is the DIGEST, not the display text

Sanitizing is lossy: every disallowed character maps to the same `?`, so `агент` and `エージェン`
and `!!!!!` all flatten to `?????`, and two 269-char ids can share their first 255. Keyed by that
text they would be ONE row — and because only a first sighting is audited, the colliding attacker's
digest would never reach the chain at all, defeating the digest defence exactly where it is needed.
So the row is keyed by `claimed_id_digest(raw)` and the sanitized text is a display column.

## Evidence ordering

The chain entry is appended BEFORE the row is written (the DISC-03 discipline): a transient append
failure then leaves nothing claiming the id was seen and the next sighting retries, instead of
marking the id already-seen forever and losing its only event.

## Observation must never degrade enforcement

This runs on the identity-deny path, whose caller is by definition unauthenticated. The DB work is
synchronous, so it goes to a worker thread (`asyncio.to_thread`) rather than holding the event loop
that every other governed agent's decision shares. The audit append stays on the loop — one
single-writer chain, one lock (see `framework_discovery`'s note on not driving it from a second
loop).

`action_type` is not caller text — the pipeline passes a closed `ActionType` enum value.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
from datetime import datetime, timezone

from sqlalchemy import func, select

from agentos_controlplane.secret_scan import scan
from agentos_controlplane.store.models import ShadowAgent

_MAX_ID = 255
# How many DISTINCT claimed ids are tracked individually before the rest fold into one bucket.
# Sized like reputation.py's `_max_signals`: generous enough that a real incident is fully legible,
# finite enough that an id-rotating prober cannot grow the table or the chain without limit.
_MAX_ROWS = 1000
# Control characters and anything exotic are replaced rather than stored: an operator reads these in
# a dashboard and a log, and a claimed id is a place to hide terminal escapes or a payload.
_SAFE = re.compile(r"[^A-Za-z0-9._:@-]")

# `<` and `>` are OUTSIDE the accepted charset above, so no claimed id can sanitize INTO any
# placeholder and impersonate the anonymous bucket, a redaction, or the overflow bucket. That also
# makes OVERFLOW_ID safe as a primary KEY: a real digest is 16 hex chars and can never collide.
EMPTY_ID = "<empty>"
SECRET_LIKE_ID = "<secret-like>"
OVERFLOW_ID = "<overflow>"


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

    def __init__(self, session_factory, audit, *, max_rows: int = _MAX_ROWS) -> None:
        self._sf = session_factory
        self._audit = audit
        # Bounds the DISTINCT-id dimension: the caller chooses the id, so without this a prober
        # that rotates it grows both the table and the hash chain without limit.
        self._max_rows = max_rows
        # "Is this the first sighting?" spans a read, an append and a write, and the DB work now
        # suspends (worker thread) — so concurrent sightings of one id would EACH read "no row yet"
        # and each append, turning a burst back into N chain records. One lock (the AuditWriter's
        # own single-writer discipline) makes the decision atomic. Held across the append, which is
        # safe because the caller bounds this whole call with a timeout.
        self._lock = asyncio.Lock()

    async def record(self, claimed_agent_id: str, action_type: str) -> bool:
        """Record one sighting. Returns True if this was the FIRST sighting of its row.

        Only a first sighting is audited: a flood of attempts from one id is a single incident, and
        appending an event per attempt would let an unregistered caller grow the hash chain at will.
        Past `max_rows` distinct ids the sighting folds into the `<overflow>` bucket, so the same
        holds for a caller that rotates the id instead of repeating it.

        The DB work runs in a worker thread and the chain entry is appended BEFORE the row.
        """
        safe = sanitize_claimed_id(claimed_agent_id)
        async with self._lock:
            key, display, first = await asyncio.to_thread(
                self._bucket, claimed_id_digest(claimed_agent_id), safe
            )
            if first:
                # First: if this raises, no row claims the sighting and the next one retries.
                # `claimed_id_digest` is the row's KEY — a real digest, or the overflow
                # placeholder when the event is the bucket's rather than one id's.
                await self._audit.append_event(
                    "shadow_agent_detected",
                    {
                        "claimed_agent_id": chain_safe_id(display),
                        "claimed_id_digest": key,
                        "action_type": action_type,
                    },
                )
            await asyncio.to_thread(self._upsert, key, display, action_type)
        return first

    def _bucket(self, digest: str, safe: str) -> tuple[str, str, bool]:
        """Which ROW this sighting belongs to and whether it is that row's first — the read half,
        run in a worker thread. A known id keeps its row; a new one gets its own until the cap is
        reached, after which everything folds into the single overflow bucket."""
        with self._sf() as s:
            if s.get(ShadowAgent, digest) is not None:
                return digest, safe, False
            if (s.scalar(select(func.count()).select_from(ShadowAgent)) or 0) < self._max_rows:
                return digest, safe, True
            return OVERFLOW_ID, OVERFLOW_ID, s.get(ShadowAgent, OVERFLOW_ID) is None

    def _upsert(self, key: str, display: str, action_type: str) -> None:
        """The write half, run in a worker thread. Keyed by the digest of the FULL raw id, so two
        ids that sanitize to the same display text remain two rows."""
        now = _now()
        with self._sf() as s:
            row = s.get(ShadowAgent, key)
            if row is None:
                s.add(
                    ShadowAgent(
                        claimed_id_digest=key,
                        claimed_agent_id=display,
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

    def list_shadow_agents(self) -> list[dict]:
        """The most recent sightings, BOUNDED — the route materializes every row it selects into
        one JSON response, and a table written before the cap existed is still attacker-sized."""
        with self._sf() as s:
            rows = s.scalars(
                select(ShadowAgent)
                .order_by(ShadowAgent.last_seen_at.desc())
                .limit(self._max_rows + 1)  # the tracked ids + the overflow bucket
            ).all()
            return [
                {
                    "claimed_agent_id": r.claimed_agent_id,
                    "claimed_id_digest": r.claimed_id_digest,
                    "action_type": r.action_type,
                    "attempts": r.attempts,
                    "first_seen_at": r.first_seen_at.isoformat() if r.first_seen_at else None,
                    "last_seen_at": r.last_seen_at.isoformat() if r.last_seen_at else None,
                }
                for r in rows
            ]
