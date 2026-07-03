"""DISC-01/02 — authoritative agent inventory. Declared (registration manifest, authoritative) +
observed (reconciled from activity). Sync store over the shared session_factory (D-14).

A single `inventory_component` table is UNIQUE on (agent_id, kind, name): `declare(...)` writes
authoritative `source="declared"` rows; `observe(agent_id, kind, name)` upserts a `source="observed"`
row and RECONCILES with a declared row of the same key (declared wins; `last_seen_at` always bumped),
so declare + observe of the same component collapse into ONE row.

Honest scope: the audit-record body intentionally omits per-action `target` (it stores agent_id +
action_type + a redacted payload only — see audit.py), so `enrich_from_audit` observes at the
CAPABILITY-CLASS level (tool/memory/mcp/model/delegation, one row per agent per class) and skips
event records (their body carries a "kind"). The `observe()` seam itself is full-fidelity — precise
per-tool observation is wired in Slice 5d where the SDK still holds the full AgentAction.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from agentos_controlplane.store.models import AuditRecord, InventoryComponent

# action_type -> inventory capability class (audit body omits per-action target -> class-level).
_KIND_BY_ACTION = {
    "tool_call": "tool",
    "memory_access": "memory",
    "mcp_call": "mcp",
    "model_invocation": "model",
    "delegation": "delegation",
}


@dataclass(frozen=True)
class ComponentData:
    agent_id: str
    kind: str
    name: str
    source: str
    first_seen_at: str | None
    last_seen_at: str | None


class InventoryStore:
    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._sf = session_factory

    def declare(self, agent_id: str, *, tools=(), prompts=(), memories=()) -> None:
        """Upsert authoritative declared rows from a registration manifest (DISC-01)."""
        items = (
            [("tool", n) for n in tools]
            + [("prompt", n) for n in prompts]
            + [("memory", n) for n in memories]
        )
        with self._sf() as s:
            for kind, name in items:
                self._upsert(s, agent_id, kind, name, source="declared")
            s.commit()

    def observe(self, agent_id: str, kind: str, name: str) -> None:
        """Upsert an observed row; reconcile with a declared row of the same key (declared wins;
        last_seen_at always bumped)."""
        with self._sf() as s:
            self._upsert(s, agent_id, kind, name, source="observed")
            s.commit()

    def enrich_from_audit(self, audit_session_factory: sessionmaker[Session] | None = None) -> int:
        """Scan decision audit records and record observed capability-class activity per agent.
        Returns the number of (agent, class) observations applied. Class-level by design (the audit
        body omits target); event records (body has 'kind') are skipped."""
        sf = audit_session_factory or self._sf
        with sf() as s:
            rows = s.scalars(select(AuditRecord).order_by(AuditRecord.seq)).all()
            seen = []
            for r in rows:
                body = r.body
                if "kind" in body:  # event record, not a decision — skip
                    continue
                agent_id = body.get("agent_id")
                klass = _KIND_BY_ACTION.get(body.get("action_type"))
                if agent_id and klass:
                    seen.append((agent_id, klass))
        for agent_id, klass in seen:
            self.observe(agent_id, klass, klass)  # class-level name
        return len(seen)

    def list_inventory(self) -> list[ComponentData]:
        with self._sf() as s:
            rows = s.scalars(
                select(InventoryComponent).order_by(
                    InventoryComponent.agent_id, InventoryComponent.kind, InventoryComponent.name
                )
            ).all()
            return [self._cd(r) for r in rows]

    def get_inventory(self, agent_id: str) -> list[ComponentData]:
        with self._sf() as s:
            rows = s.scalars(
                select(InventoryComponent)
                .where(InventoryComponent.agent_id == agent_id)
                .order_by(InventoryComponent.kind, InventoryComponent.name)
            ).all()
            return [self._cd(r) for r in rows]

    @staticmethod
    def _upsert(s: Session, agent_id: str, kind: str, name: str, *, source: str) -> None:
        row = s.scalar(
            select(InventoryComponent).where(
                InventoryComponent.agent_id == agent_id,
                InventoryComponent.kind == kind,
                InventoryComponent.name == name,
            )
        )
        if row is None:
            s.add(InventoryComponent(agent_id=agent_id, kind=kind, name=name, source=source))
            return
        # declared is authoritative: never downgrade declared -> observed; always bump last_seen.
        if source == "declared":
            row.source = "declared"
        row.last_seen_at = func.now()

    @staticmethod
    def _cd(r: InventoryComponent) -> ComponentData:
        return ComponentData(
            r.agent_id, r.kind, r.name, r.source,
            r.first_seen_at.isoformat() if r.first_seen_at else None,
            r.last_seen_at.isoformat() if r.last_seen_at else None,
        )
