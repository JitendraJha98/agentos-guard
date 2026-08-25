# Phase 10 · Slice 10f — Live Agent Graph & Lineage (DISC-06) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Commits end
> with a second `-m "Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"`. Tests:
> `./.venv/Scripts/python.exe -m pytest`. TDD per task, one commit each. Gates `floor_invariant`
> + `regression_lock` green at every commit. (`-m latency` is wall-clock and marginal on this box —
> re-run when idle and compare against a scratch worktree at `886ad59` before claiming a regression.
> NEVER loosen the budget.)

**Goal (DISC-06):** Materialize a **live agent graph** — agents, tools, MCP servers, models and
memories as first-class **nodes**, plus **delegation edges between agents** whose lineage derives from
`parent_action_id` — and expose it for reading. This is the "what talks to what" map that the Phase-13
permission calculus will walk.

**Architecture:** An `AgentGraphStore` materializes `graph_node` and `graph_edge` from the audit log
in a **batch reconciler pass** (never the per-action hot path). Two edge kinds:
- `uses` — `agent -> component`, from each decision record's `agent_id` + `action_type`;
- `delegates` — `agent -> agent`, from `parent_action_id`: an action whose parent action was performed
  by a DIFFERENT agent is a delegation edge from the parent's agent to this one.

Phase 7's `GraphReconciler` docstring already defers exactly this ("the full live agent graph —
delegation edges, models, MCP servers, memories as first-class nodes — is DISC-06 in Phase 10"), so
this slice supersedes that capability-class seed rather than duplicating it.

**The audit body is the only source.** It carries `action_id`, `agent_id`, `action_type`,
`parent_action_id` and `conversation_id`, but NOT `target` (redaction keeps tool names out of the
hash-covered body — confirmed in `audit.py`). So component nodes are **capability-class** nodes
(`tool`, `model`, `mcp`, `memory`, `delegation`), and per-name component nodes come from the
`InventoryStore`, which does hold names. Both sources are joined; neither is invented. State that
limit in the module docstring rather than implying per-tool fidelity the evidence cannot support.

**Tech Stack:** SQLAlchemy 2.0 + Alembic, FastAPI, pytest.

> First commit in this slice: `docs(phase-10): Slice 10f plan` for this file, then the tasks below.

## File structure
- Modify `.../store/models.py` — `GraphNode`, `GraphEdge`.
- Create `.../store/migrations/versions/0020_agent_graph.py` (down_revision `0019_rogue_finding`).
- Create `.../agentos_controlplane/graph.py` — `AgentGraphStore`.
- Modify `.../reconcile.py` — `GraphReconciler` drives the new store.
- Modify `.../api.py` — a read route.
- Tests: `tests/unit/test_agent_graph.py`, `tests/integration/test_agent_graph_api.py`.

---

### Task 1: models + migration 0020

**Files:** modify `.../store/models.py`; create the migration; test `tests/unit/test_agent_graph.py`
(round-trip portion).

```python
class GraphNode(Base):
    """DISC-06 — one node in the live agent graph: an agent or a component it uses."""

    __tablename__ = "graph_node"
    __table_args__ = (UniqueConstraint("kind", "name", name="uq_graph_node"),)

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)   # agent|tool|model|mcp|memory|delegation
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )


class GraphEdge(Base):
    """DISC-06 — a directed edge. `uses` is agent -> component; `delegates` is agent -> agent, with
    lineage derived from `parent_action_id`. `observations` counts how often it was seen, so an
    operator can tell a one-off from a hot path."""

    __tablename__ = "graph_edge"
    __table_args__ = (
        UniqueConstraint("src_kind", "src_name", "dst_kind", "dst_name", "relation", name="uq_graph_edge"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    src_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    src_name: Mapped[str] = mapped_column(String(255), nullable=False)
    dst_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    dst_name: Mapped[str] = mapped_column(String(255), nullable=False)
    relation: Mapped[str] = mapped_column(String(32), nullable=False)  # uses | delegates
    observations: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )
```

Migration `0020_agent_graph.py` (`revision = "0020_agent_graph"`,
`down_revision = "0019_rogue_finding"`): create both tables with those columns and the two named
unique constraints; `downgrade` drops `graph_edge` then `graph_node`.

**Steps:**
- [ ] Failing test: in-memory store; insert a `GraphNode(kind="agent", name="a")` and a
  `GraphEdge(src_kind="agent", src_name="a", dst_kind="tool", dst_name="tool", relation="uses")`,
  read both back; a duplicate `(kind, name)` node and a duplicate 5-tuple edge each raise
  `IntegrityError`. Run → fails.
- [ ] Add models + migration. Run → passes; verify a SINGLE head (`['0020_agent_graph']`).
- [ ] Commit `feat(controlplane): graph_node + graph_edge tables + migration 0020 (DISC-06)`.

---

### Task 2: `AgentGraphStore` — materialize nodes + edges

**Files:** create `.../agentos_controlplane/graph.py`; test `tests/unit/test_agent_graph.py`.

Read `audit.py`'s decision-body construction first to confirm the available fields
(`action_id`, `agent_id`, `action_type`, `parent_action_id`, `conversation_id`; event records carry a
`"kind"` and must be skipped), and `inventory.py` for `list_inventory()`.

```python
"""DISC-06 — the live agent graph.

Nodes are agents and the components they use; edges are `uses` (agent -> component) and `delegates`
(agent -> agent, lineage derived from `parent_action_id`). This is the "what talks to what" map the
Phase-13 permission calculus will walk to compute transitive permissions.

SOURCE OF TRUTH AND ITS LIMIT: the audit body carries action_id / agent_id / action_type /
parent_action_id, but NOT `target` — redaction deliberately keeps tool names out of the hash-covered
body. So audit-derived component nodes are CAPABILITY-CLASS nodes (tool, model, mcp, memory), and
per-NAME component nodes come from the InventoryStore, which does hold names. Both are materialized
and neither is invented; anything the evidence cannot support is simply absent.

This is a BATCH pass, never the per-action hot path.
"""
from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID, uuid4

from sqlalchemy import select

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
        node/edge upserts applied. Idempotent: re-running on unchanged evidence changes nothing but
        `last_seen_at`/`observations`."""
        with self._sf() as s:
            rows = s.scalars(select(AuditRecord).order_by(AuditRecord.seq)).all()
            # action_id -> agent_id, so a child action can resolve WHO its parent was.
            actor_by_action: dict[str, str] = {}
            decisions: list[tuple[str, str, str | None]] = []  # (agent_id, action_type, parent)
            for r in rows:
                body = r.body
                if "kind" in body:  # an event record, not a decision
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
                    # A delegation edge only exists between DIFFERENT agents: a parent_action_id
                    # pointing at the same agent is that agent's own lineage, not a delegation.
                    if parent_agent and parent_agent != agent_id:
                        applied += self._upsert_node(s, "agent", parent_agent)
                        applied += self._upsert_edge(
                            s, "agent", parent_agent, "agent", agent_id, "delegates"
                        )

            if self._inventory is not None:
                for c in self._inventory.list_inventory():
                    applied += self._upsert_node(s, "agent", c.agent_id)
                    applied += self._upsert_node(s, c.kind, c.name)
                    applied += self._upsert_edge(
                        s, "agent", c.agent_id, c.kind, c.name, "uses"
                    )
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
    def _upsert_node(s, kind: str, name: str) -> int:
        row = s.scalar(select(GraphNode).where(GraphNode.kind == kind, GraphNode.name == name))
        if row is None:
            s.add(GraphNode(id=uuid4(), kind=kind, name=name))
            return 1
        return 0

    @staticmethod
    def _upsert_edge(s, sk: str, sn: str, dk: str, dn: str, relation: str) -> int:
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
                    id=uuid4(), src_kind=sk, src_name=sn, dst_kind=dk, dst_name=dn,
                    relation=relation, observations=1,
                )
            )
            return 1
        row.observations += 1
        return 0
```

**Steps (TDD):**
- [ ] Failing tests over a shared in-memory store with a real `AuditWriter`:
  - append decisions for agent `a` doing a `tool_call` and a `model_invocation` → after
    `materialize()`, `view().nodes` contains `{"kind": "agent", "name": "a"}`, `tool` and `model`
    nodes, and `uses` edges from `a` to each;
  - **the delegation edge (the load-bearing DISC-06 assertion)**: append a parent action by agent
    `a`, then a child action by agent `b` whose `context.parent_action_id` is the parent's id →
    `view().edges` contains `{"src": agent a, "dst": agent b, "relation": "delegates"}`;
  - a `parent_action_id` pointing at an action by the SAME agent produces NO delegates edge (own
    lineage is not delegation);
  - a `parent_action_id` that references an action the graph never saw is skipped without raising
    (a truncated/partial log must not crash the sweep);
  - event records (body has `"kind"`) are ignored;
  - idempotence: a second `materialize()` adds no NODES and no new EDGES, and bumps `observations`
    rather than duplicating (assert the edge count is unchanged);
  - with an `InventoryStore` wired, a declared `tool` named `http_get` becomes a per-NAME node with a
    `uses` edge — proving the two sources are joined rather than one overwriting the other.
  Run → fails.
- [ ] Implement `graph.py`. Run → passes.
- [ ] Commit `feat(controlplane): AgentGraphStore — nodes + delegation edges from lineage (DISC-06)`.

---

### Task 3: reconciler + read API + full gate

**Files:** modify `.../reconcile.py`, `.../api.py`; test `tests/integration/test_agent_graph_api.py`.

`reconcile.py` — `GraphReconciler` currently only calls `inventory.enrich_from_audit()`. Give it the
graph store while KEEPING the inventory enrichment (the inventory is what supplies per-name nodes):

```python
class GraphReconciler:
    """Materialize the live agent graph (DISC-06) and keep the observed inventory current.

    Phase 7 shipped only the capability-class seed and its docstring deferred the real graph to
    DISC-06; this now drives `AgentGraphStore.materialize()` as well, so nodes, delegation edges and
    the observed inventory converge on the same pass.
    """

    name = "graph"

    def __init__(self, inventory, *, graph=None, interval_s: float = DEFAULT_INTERVALS["graph"]) -> None:
        self._inventory = inventory
        self._graph = graph
        self.interval_s = interval_s

    def reconcile(self) -> int:
        changed = int(self._inventory.enrich_from_audit() or 0)
        if self._graph is not None:
            changed += int(self._graph.materialize() or 0)
        return changed
```

`api.py` — extend `build_inventory_router` with `graph: "AgentGraphStore | None" = None` (thread
`graph_store` through `create_app`, defaulting to `None`) and add:

```python
    @router.get("/discovery/graph")
    def agent_graph() -> dict:
        """DISC-06 — the live agent graph: nodes + edges (delegation lineage included)."""
        if graph is None:
            raise HTTPException(status_code=404, detail="the agent graph is not wired")
        view = graph.view()
        return {"nodes": view.nodes, "edges": view.edges}
```

**Steps (TDD):**
- [ ] Failing e2e over the REAL stack sharing ONE store: run real governed actions through a pipeline
  (including a delegation whose child carries `parent_action_id`, mirroring how
  `tests/integration/test_all_action_types_e2e.py` builds delegation actions), then
  `GraphReconciler(inventory, graph=AgentGraphStore(sf, inventory=inventory)).reconcile()`. Assert:
  - `GET /discovery/graph` → 200 with `nodes` and `edges`;
  - an `agent` node exists for each acting agent and a `delegates` edge connects the delegating pair;
  - a second `reconcile()` does not duplicate nodes or edges (idempotent through the reconciler too);
  - the existing `GraphReconciler` behaviour still holds — the observed inventory is still enriched
    (keep/adapt the assertion in `tests/integration/test_reconcile_e2e.py::test_graph_reconciler_materializes_observed_activity`);
  - no token → 401; app built without a graph store → 404.
- [ ] Run → fails, then passes.
- [ ] `pytest -q` green; `-m floor_invariant`, `-m regression_lock` green; `-m latency`
  (baseline-check before attributing a wall-clock failure — materialization is a batch pass, entirely
  off the per-action hot path).
- [ ] Commit `feat(controlplane): agent-graph reconciler pass + read API (DISC-06)`.

## Self-review
DISC-06 is realized: agents and components are first-class nodes and delegation edges are derived from
`parent_action_id` by resolving which agent performed the parent action — asserted directly, including
the two cases that make it honest (same-agent lineage is NOT delegation; an unresolvable parent is
skipped rather than crashing the sweep). The evidence limit is stated rather than papered over: audit
bodies carry no `target`, so audit-derived component nodes are capability classes and per-name nodes
come from the inventory, with both sources joined. Materialization is idempotent and runs as a batch
reconciler pass, so the per-action hot path is untouched and a scheduled sweep cannot duplicate the
graph. Phase 7's seed is superseded, not duplicated, and its existing reconciler assertion still holds.
Migration 0020 single-head; the API parameter defaults to `None` so existing callers are unchanged.
