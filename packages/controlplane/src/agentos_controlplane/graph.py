"""DISC-06 — the live agent graph.

Nodes are agents and the components they use; edges are `uses` (agent -> component) and `delegates`
(agent -> agent, lineage derived from `parent_action_id`). This is the "what talks to what" map the
Phase-13 permission calculus will walk to compute transitive permissions.

THE DELEGATION EDGE IS THE POINT. The audit body names the parent ACTION, never the parent AGENT, so
an edge exists only because this pass resolves who performed that parent action. Two consequences
are deliberate, not oversights:
  * a `parent_action_id` pointing at an action by the SAME agent is that agent's OWN lineage and
    draws no edge — otherwise every multi-step agent would look like a delegation hub;
  * a parent the log never recorded is SKIPPED. This runs on a schedule against a log that may be
    truncated or partially retained, and a crash here would rot every derived view behind it.

SOURCE OF TRUTH AND ITS LIMIT: the audit body carries action_id / agent_id / action_type /
parent_action_id, but NOT `target` — redaction deliberately keeps tool names out of the hash-covered
body. So audit-derived component nodes are CAPABILITY-CLASS nodes (tool, model, mcp, memory), and
per-NAME component nodes come from the InventoryStore, which does hold names. Both are materialized
and neither is invented; anything the evidence cannot support is simply absent.

This is a BATCH pass, never the per-action hot path.
"""

from __future__ import annotations

from dataclasses import dataclass
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from agentos_controlplane.store.models import AuditRecord, GraphEdge, GraphNode

# action_type -> the capability class it exercises (audit bodies carry no target).
_CLASS_BY_ACTION = {
    "tool_call": "tool",
    "model_invocation": "model",
    "mcp_call": "mcp",
    "memory_access": "memory",
    "delegation": "delegation",
}


@dataclass(frozen=True)
class GraphView:
    nodes: list[dict]
    edges: list[dict]


class AgentGraphStore:
    def __init__(self, session_factory, *, inventory=None) -> None:
        self._sf = session_factory
        self._inventory = inventory

    def materialize(self) -> int:
        """Rebuild the graph from the audit log (+ the inventory when wired). Returns the number of
        NEW nodes/edges, so a converged graph reports 0 and the reconciler's "changed" count stays
        meaningful. Idempotent: re-running on unchanged evidence adds no rows — a repeat sighting
        lands on an existing edge's `observations`, which therefore ranks hot paths across sweeps
        rather than counting distinct actions.
        """
        # Read the inventory BEFORE opening the graph session. `list_inventory()` opens its OWN
        # session, and a second session over a shared connection (SQLite/StaticPool, which is how
        # the reconciler's worker thread reaches this store) closes by rolling back the connection's
        # transaction — discarding this pass's already-flushed nodes. Read first, write once.
        declared = list(self._inventory.list_inventory()) if self._inventory is not None else []
        with self._sf() as s:
            rows = s.scalars(select(AuditRecord).order_by(AuditRecord.seq)).all()
            # action_id -> agent_id, so a child action can resolve WHO its parent was. Built in
            # full before any edge is drawn, so lineage resolves regardless of record order.
            actor_by_action: dict[str, str] = {}
            decisions: list[tuple[str, str, str | None]] = []  # (agent_id, action_type, parent)
            for r in rows:
                body = r.body
                if "kind" in body:  # an event record (an observation), not a decision
                    continue
                agent_id = body.get("agent_id")
                action_type = body.get("action_type")
                action_id = body.get("action_id")
                if not agent_id or not action_type:
                    continue
                if action_id:
                    actor_by_action[str(action_id)] = agent_id
                decisions.append((agent_id, action_type, body.get("parent_action_id")))

            applied = 0
            for agent_id, action_type, parent in decisions:
                applied += self._upsert_node(s, "agent", agent_id)
                klass = _CLASS_BY_ACTION.get(action_type)
                if klass:
                    applied += self._upsert_node(s, klass, klass)
                    applied += self._upsert_edge(s, "agent", agent_id, klass, klass, "uses")
                if parent:
                    parent_agent = actor_by_action.get(str(parent))
                    # A delegation edge only exists between DIFFERENT agents; an unresolvable
                    # parent yields no edge at all (see the module docstring).
                    if parent_agent and parent_agent != agent_id:
                        applied += self._upsert_node(s, "agent", parent_agent)
                        applied += self._upsert_edge(
                            s, "agent", parent_agent, "agent", agent_id, "delegates"
                        )

            # The per-NAME half the audit body cannot supply.
            for c in declared:
                applied += self._upsert_node(s, "agent", c.agent_id)
                applied += self._upsert_node(s, c.kind, c.name)
                applied += self._upsert_edge(s, "agent", c.agent_id, c.kind, c.name, "uses")
            s.commit()
            return applied

    def view(self) -> GraphView:
        with self._sf() as s:
            nodes = [
                {"kind": n.kind, "name": n.name}
                for n in s.scalars(
                    select(GraphNode).order_by(GraphNode.kind, GraphNode.name)
                ).all()
            ]
            edges = [
                {
                    "src": {"kind": e.src_kind, "name": e.src_name},
                    "dst": {"kind": e.dst_kind, "name": e.dst_name},
                    "relation": e.relation,
                    "observations": e.observations,
                }
                for e in s.scalars(
                    select(GraphEdge).order_by(
                        GraphEdge.relation, GraphEdge.src_name, GraphEdge.dst_name
                    )
                ).all()
            ]
            return GraphView(nodes=nodes, edges=edges)

    @staticmethod
    def _upsert_node(s: Session, kind: str, name: str) -> int:
        row = s.scalar(select(GraphNode).where(GraphNode.kind == kind, GraphNode.name == name))
        if row is None:
            s.add(GraphNode(id=uuid4(), kind=kind, name=name))
            return 1
        return 0

    @staticmethod
    def _upsert_edge(s: Session, sk: str, sn: str, dk: str, dn: str, relation: str) -> int:
        row = s.scalar(
            select(GraphEdge).where(
                GraphEdge.src_kind == sk,
                GraphEdge.src_name == sn,
                GraphEdge.dst_kind == dk,
                GraphEdge.dst_name == dn,
                GraphEdge.relation == relation,
            )
        )
        if row is None:
            s.add(
                GraphEdge(
                    id=uuid4(),
                    src_kind=sk,
                    src_name=sn,
                    dst_kind=dk,
                    dst_name=dn,
                    relation=relation,
                    observations=1,
                )
            )
            return 1
        row.observations += 1
        return 0
