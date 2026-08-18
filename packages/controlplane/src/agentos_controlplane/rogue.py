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
"""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID, uuid4

from sqlalchemy import select

from agentos_controlplane.store.models import RogueFinding


@dataclass(frozen=True)
class Divergence:
    """One component an agent used but never declared."""

    agent_id: str
    kind: str
    name: str


class RogueDetector:
    def __init__(self, session_factory, audit, inventory) -> None:
        self._sf = session_factory
        self._audit = audit
        self._inventory = inventory

    def divergences(self) -> list[Divergence]:
        """Pure comparison: components observed for an agent that DECLARED something but never
        declared this one. No DB writes, no audit events — so a dry run ("what would this flag?")
        is free and commits no evidence.

        `c.agent_id in declarers` is the "unknown scope is not empty scope" rule: an agent with no
        declared rows at all is not held to a manifest it never filed.
        """
        components = self._inventory.list_inventory()
        declarers = {c.agent_id for c in components if c.source == "declared"}
        return sorted(
            (
                Divergence(agent_id=c.agent_id, kind=c.kind, name=c.name)
                for c in components
                if c.source == "observed" and c.agent_id in declarers
            ),
            key=lambda d: (d.agent_id, d.kind, d.name),
        )

    async def scan(self) -> list[Divergence]:
        """Persist + audit every NEW divergence, returning just those.

        Idempotent: a repeat scan of an unchanged fleet inserts no row and appends no event, so a
        scheduled sweep cannot bloat the table or the hash chain. An already-RESOLVED finding stays
        resolved for the same reason — the divergence is still in the inventory (the agent really
        did use that tool), and re-raising it would turn an operator's acknowledgement into an
        endless alert loop.
        """
        fresh: list[Divergence] = []
        with self._sf() as s:
            for d in self.divergences():
                existing = s.scalar(
                    select(RogueFinding).where(
                        RogueFinding.agent_id == d.agent_id,
                        RogueFinding.kind == d.kind,
                        RogueFinding.name == d.name,
                    )
                )
                if existing is None:
                    s.add(
                        RogueFinding(id=uuid4(), agent_id=d.agent_id, kind=d.kind, name=d.name)
                    )
                    fresh.append(d)
            s.commit()
        for d in fresh:
            # `component_kind`/`component_name`, not `kind`/`name`: `kind` is a RESERVED chain
            # field carrying the event kind itself, and a body that shadows it is rejected
            # fail-closed. Short identifiers only, per the Phase-9 convention.
            await self._audit.append_event(
                "rogue_agent_detected",
                {"agent_id": d.agent_id, "component_kind": d.kind, "component_name": d.name},
            )
        return fresh

    def list_findings(self, *, include_resolved: bool = False) -> list[dict]:
        """Open findings, newest first. `first_seen_at` is second-granular on SQLite, so the
        identity columns break ties and the order stays stable for one scan's batch."""
        with self._sf() as s:
            stmt = select(RogueFinding).order_by(
                RogueFinding.first_seen_at.desc(),
                RogueFinding.agent_id,
                RogueFinding.kind,
                RogueFinding.name,
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
