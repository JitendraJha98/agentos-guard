"""DISC-05 — rogue-agent detection: a REGISTERED agent acting outside its DECLARED scope.

Phase 5 already stores the two halves this needs — `source="declared"` (the registration manifest,
authoritative) and `source="observed"` (what actually happened) — and `InventoryStore._upsert` keeps
a declared component marked declared even after it is observed. So a row still marked `observed` is
precisely a component the agent never declared: the divergence, already latent in the data. No
second source of truth, no second interception point.

ADVISORY by design: this adds no deny path. A declaration gap is evidence, not proof — a manifest
goes stale the moment a team ships a new tool — so findings are surfaced for an operator, who
escalates with Phase-9 containment (kill switch, breaker, rings) if warranted. Turning a stale
manifest into an automatic fleet-wide deny would make the feature unusable in practice.

An agent that declared NOTHING is NOT flagged: Phase 5 made the manifest optional, so no
declarations means "scope unknown", not "scope empty". Flagging those would bury the real signal
under every unmanifested agent in the fleet.

Off the per-action hot path entirely — this is a batch sweep an operator or a schedule drives.

## Only a FULL-FIDELITY observation is a divergence

`observed` and `observed_class` are different claims (see inventory.py). The class-level row
`enrich_from_audit` writes is named after its own class ('tool','tool'), because the audit body
omits the per-action target; a manifest declares per-tool names ('tool','http_get'). Those keys can
never reconcile, so comparing across the two naming schemes flagged EVERY manifest-declaring agent
in the fleet the moment it made one governed call — the false positive this feature lives or dies
on. Only `observed` rows are compared, so the placeholder cannot manufacture a finding and the
feature stays latent until per-tool observation is wired (Slice 5d).

## Evidence ordering

The chain entry is appended BEFORE the row (the DISC-03/04 discipline). Committing the row first
meant a transient append failure left a row claiming the divergence was already known, so the next
sweep skipped it and its event was never written — permanent, silent evidence loss. Each
divergence is also isolated: one refused append costs ITS evidence for one pass, not the rest of
the batch, and the retry happens on the next sweep because no row was written.

## Hostile identifiers must not bloat or BLOCK the chain

An agent names its own components in its manifest and (from 5d) in its actions, so both halves of a
divergence are caller text. They are bounded + sanitized before they reach the hash-covered body or
the row (a 10 000-char name is not a 10 000-byte chain record, and SQLite does not enforce
String(255)), and pre-screened with the SAME AUD-04 scanner the gate uses — otherwise a name shaped
like a credential, or merely a long PascalCase tool name tripping the documented entropy false
positive, fails the record closed and blocks its own evidence. Truncation and the `<secret-like>`
placeholder are both lossy, so the digest of the full value travels with them: two distinct
components can never collapse into one record.

## Observation must never degrade enforcement

The detector shares its session factory and its AuditWriter with the pipeline, so a sweep driven in
that process would add its whole wall time to every in-flight governed decision. The DB work is
synchronous, so it goes to a worker thread (`asyncio.to_thread`) rather than holding the event loop
(the DISC-04 rule), and the comparison is a fixed number of statements — not one SELECT per
divergence over a fully materialized inventory.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session, aliased

from agentos_controlplane.inventory import DECLARED, OBSERVED
from agentos_controlplane.shadow import chain_safe_id, claimed_id_digest, sanitize_claimed_id
from agentos_controlplane.store.models import InventoryComponent, RogueFinding

# The `rogue_finding` column widths — bounded at the source so SQLite (which does not enforce
# String(n)) and Postgres (which would fail the INSERT and abort the sweep) store the same row.
_MAX_ID = 255
_MAX_KIND = 32
_DIGEST_SUFFIX = 17  # "#" + the 16 hex chars `claimed_id_digest` returns
# How many findings one read returns. The route materializes everything it selects into ONE JSON
# response (the shadow / dashboard `.limit()` precedent), and the table grows with the fleet.
_MAX_FINDINGS = 1000


def bounded(raw: str, limit: int = _MAX_ID) -> str:
    """The identifier AS RECORDED: sanitized (an operator reads these in a dashboard and a log) and
    bounded to the column width.

    Both are lossy, so a value that had to be altered carries a digest of the FULL original — `#`
    is outside the accepted charset, so the suffix can never collide with an unaltered identifier
    and two distinct components can never become one finding.
    """
    safe = sanitize_claimed_id(raw)[:limit]
    return safe if safe == raw else f"{safe[: limit - _DIGEST_SUFFIX]}#{claimed_id_digest(raw)}"


@dataclass(frozen=True)
class Divergence:
    """One component an agent used but never declared, as it is recorded (see `bounded`)."""

    agent_id: str
    kind: str
    name: str


def _body(d: Divergence) -> dict:
    """The hash-covered event body. `component_kind`/`component_name`, not `kind`/`name`: `kind` is
    a RESERVED chain field carrying the event kind itself, and a body that shadows it is rejected
    fail-closed. Short identifiers only, per the Phase-9 convention — the recognisable text stays
    in the `rogue_finding` TABLE, and the digests keep two findings distinct when the identifier
    itself had to be replaced."""
    return {
        "agent_id": chain_safe_id(d.agent_id),
        "agent_id_digest": claimed_id_digest(d.agent_id),
        "component_kind": chain_safe_id(d.kind),
        "component_name": chain_safe_id(d.name),
        "component_name_digest": claimed_id_digest(d.name),
    }


class RogueDetector:
    def __init__(
        self, session_factory, audit, inventory=None, *, max_findings: int = _MAX_FINDINGS
    ) -> None:
        self._sf = session_factory
        self._audit = audit
        # `inventory` is kept in the signature for the existing call sites but no longer read: the
        # comparison runs against the inventory TABLE on this same session factory (the detector
        # and the InventoryStore share one store, D-14), which is what turns an O(inventory) sweep
        # into a fixed number of statements.
        self._max_findings = max_findings

    def divergences(self) -> list[Divergence]:
        """Pure comparison: components observed for an agent that DECLARED something but never
        declared this one. No DB writes, no audit events — so a dry run ("what would this flag?")
        is free and commits no evidence.

        The correlated EXISTS is the "unknown scope is not empty scope" rule: an agent with no
        declared rows at all is not held to a manifest it never filed.
        """
        with self._sf() as s:
            return self._candidates(s)

    def _candidates(self, s: Session) -> list[Divergence]:
        declared = aliased(InventoryComponent)
        rows = s.execute(
            select(
                InventoryComponent.agent_id, InventoryComponent.kind, InventoryComponent.name
            ).where(
                InventoryComponent.source == OBSERVED,  # never `observed_class` — see the docstring
                select(declared.id)
                .where(
                    declared.agent_id == InventoryComponent.agent_id,
                    declared.source == DECLARED,
                )
                .exists(),
            )
        ).all()
        return sorted(
            (
                Divergence(
                    agent_id=bounded(agent_id),
                    kind=bounded(kind, _MAX_KIND),
                    name=bounded(name),
                )
                for agent_id, kind, name in rows
            ),
            key=lambda d: (d.agent_id, d.kind, d.name),
        )

    def _fresh(self) -> list[Divergence]:
        """The divergences not already recorded — the read half, run in a worker thread.

        Two statements, not one per divergence. It is a set difference rather than a LEFT JOIN
        because a finding is keyed by the BOUNDED identifier, which SQL cannot derive from the
        inventory's own column.
        """
        with self._sf() as s:
            candidates = self._candidates(s)
            known = {
                tuple(r)
                for r in s.execute(
                    select(RogueFinding.agent_id, RogueFinding.kind, RogueFinding.name)
                ).all()
            }
        return [d for d in candidates if (d.agent_id, d.kind, d.name) not in known]

    async def scan(self) -> list[Divergence]:
        """Audit + persist every NEW divergence, returning just those.

        Idempotent: a repeat scan of an unchanged fleet inserts no row and appends no event, so a
        scheduled sweep cannot bloat the table or the hash chain. An already-RESOLVED finding stays
        resolved for the same reason — the divergence is still in the inventory (the agent really
        did use that tool), and re-raising it would turn an operator's acknowledgement into an
        endless alert loop.
        """
        recorded: list[Divergence] = []
        for d in await asyncio.to_thread(self._fresh):
            try:
                # Chain entry FIRST: if this raises, no row claims the divergence is known and the
                # next sweep retries it.
                await self._audit.append_event("rogue_agent_detected", _body(d))
                await asyncio.to_thread(self._insert, d)
            except Exception:
                # Isolation: one refused divergence must not cost the rest of the batch its
                # evidence. It is retried on the next sweep, because nothing was written.
                continue
            recorded.append(d)
        return recorded

    def _insert(self, d: Divergence) -> None:
        """The write half, run in a worker thread."""
        with self._sf() as s:
            s.add(RogueFinding(id=uuid4(), agent_id=d.agent_id, kind=d.kind, name=d.name))
            s.commit()

    def list_findings(self, *, include_resolved: bool = False) -> list[dict]:
        """Open findings, newest first, BOUNDED — the route materializes every row it selects into
        one JSON response. `first_seen_at` is second-granular on SQLite, so the identity columns
        break ties and the order stays stable for one scan's batch."""
        with self._sf() as s:
            stmt = (
                select(RogueFinding)
                .order_by(
                    RogueFinding.first_seen_at.desc(),
                    RogueFinding.agent_id,
                    RogueFinding.kind,
                    RogueFinding.name,
                )
                .limit(self._max_findings)
            )
            if not include_resolved:
                stmt = stmt.where(RogueFinding.resolved.is_(False))
            return [
                {
                    "id": str(r.id),
                    "agent_id": r.agent_id,
                    "kind": r.kind,
                    "name": r.name,
                    "resolved": r.resolved,
                    "first_seen_at": r.first_seen_at.isoformat() if r.first_seen_at else None,
                }
                for r in s.scalars(stmt).all()
            ]

    def resolve(self, finding_id: str) -> bool:
        """Operator acknowledgement — the finding leaves the open list; the audit chain keeps the
        original sighting either way. An unknown or malformed id is False, never an error: the id
        comes from a human or a UI and a typo is not an incident."""
        try:
            key = UUID(finding_id)
        except (ValueError, AttributeError, TypeError):
            return False
        with self._sf() as s:
            row = s.get(RogueFinding, key)
            if row is None:
                return False
            row.resolved = True
            s.commit()
        return True
