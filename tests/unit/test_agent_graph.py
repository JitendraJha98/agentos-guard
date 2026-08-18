"""DISC-06 — the live agent graph: nodes, edges and delegation lineage (Slice 10f).

The schema half first: a `graph_node` is unique on (kind, name) and a `graph_edge` on the
(src, dst, relation) 5-tuple, so a repeated materialization pass converges on the SAME rows instead
of growing a new copy of the graph on every sweep. That idempotence is enforced by the schema, not
only by the store's read-before-write.

Then the materialization itself, over a REAL audit chain. The load-bearing assertion is the
delegation edge: an action whose `parent_action_id` names an action performed by a DIFFERENT agent
is a delegation from that agent to this one. The two cases that keep it honest are pinned beside
it — a parent by the SAME agent is that agent's own lineage and draws no edge, and a parent the log
never recorded is skipped rather than crashing the sweep.
"""

from __future__ import annotations

import asyncio
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.pool import StaticPool

from agentos_contract import ActionType, AgentAction, Decision, Outcome, Reason
from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.graph import AgentGraphStore
from agentos_controlplane.inventory import DECLARED, OBSERVED, OBSERVED_CLASS, InventoryStore
from agentos_controlplane.shadow import OVERFLOW_ID
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import GraphEdge, GraphNode, GraphWatermark

# What the real pipeline appends when — and only when — the identity stage verified the caller
# (runner.py). The graph is built from these records ONLY, so a forged or unregistered caller
# cannot draw itself onto the map.
VERIFIED = [Reason(stage="identity", code="identity_verified", detail="ok")]
FORGED = [Reason(stage="identity", code="forged_identity", detail="unknown agent")]

_PAYLOADS = {
    ActionType.tool_call: {"url": "https://x.example.com/", "content": ""},
    ActionType.model_invocation: {"model": "claude", "messages": "hi"},
    ActionType.memory_access: {"operation": "read", "key": "k", "value": ""},
    ActionType.mcp_call: {"server": "github", "tool": "list_issues", "args": ""},
    ActionType.delegation: {"to_agent": "worker", "task": "t"},
}


@pytest.fixture
def store():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    create_all(engine)
    return create_session_factory(engine)


@pytest.fixture
def audit(store) -> AuditWriter:
    return AuditWriter(store)


@pytest.fixture
def graph(store) -> AgentGraphStore:
    return AgentGraphStore(store)


def act(
    audit: AuditWriter,
    agent_id: str,
    action_type=ActionType.tool_call,
    *,
    parent=None,
    reasons=None,
    outcome=Outcome.allow,
):
    """Append ONE real decision record; return the action so a child can name it as parent.

    `reasons` defaults to the verified-identity reason the real pipeline emits on every success
    path, because that is the only record shape the graph is allowed to trust."""
    action = AgentAction(
        agent_id=agent_id,
        type=action_type,
        target="http_get",
        payload=dict(_PAYLOADS[action_type]),
    )
    if parent is not None:
        action.context.parent_action_id = parent
    asyncio.run(
        audit.append(
            action,
            Decision(
                action_id=action.id,
                outcome=outcome,
                risk_score=0.0,
                trust_score=0.5,
                reasons=list(VERIFIED if reasons is None else reasons),
            ),
        )
    )
    return action


def edges(graph: AgentGraphStore) -> set[tuple[str, str, str]]:
    return {(e["src"]["name"], e["dst"]["name"], e["relation"]) for e in graph.view().edges}


def nodes(graph: AgentGraphStore) -> set[tuple[str, str]]:
    return {(n["kind"], n["name"]) for n in graph.view().nodes}


def test_node_and_edge_round_trip(store) -> None:
    with store() as s:
        s.add(GraphNode(kind="agent", name="a"))
        s.add(
            GraphEdge(
                src_kind="agent", src_name="a", dst_kind="tool", dst_name="tool", relation="uses"
            )
        )
        s.commit()

    with store() as s:
        node = s.scalar(select(GraphNode))
        edge = s.scalar(select(GraphEdge))
        assert (node.kind, node.name) == ("agent", "a")
        assert (edge.src_name, edge.dst_name, edge.relation) == ("a", "tool", "uses")
        assert edge.observations == 1
        assert node.first_seen_at is not None and node.last_seen_at is not None


def test_a_duplicate_node_is_rejected_by_the_schema(store) -> None:
    with store() as s:
        s.add(GraphNode(kind="agent", name="a"))
        s.commit()

    with pytest.raises(IntegrityError):
        with store() as s:
            s.add(GraphNode(kind="agent", name="a"))
            s.commit()


def test_a_duplicate_edge_is_rejected_by_the_schema(store) -> None:
    """The 5-tuple is the key: the same pair with a DIFFERENT relation is a different edge."""
    with store() as s:
        s.add(
            GraphEdge(
                src_kind="agent", src_name="a", dst_kind="agent", dst_name="b", relation="delegates"
            )
        )
        s.commit()

    with store() as s:
        # Same pair, different relation — allowed.
        s.add(
            GraphEdge(
                src_kind="agent", src_name="a", dst_kind="agent", dst_name="b", relation="uses"
            )
        )
        s.commit()

    with pytest.raises(IntegrityError):
        with store() as s:
            s.add(
                GraphEdge(
                    src_kind="agent",
                    src_name="a",
                    dst_kind="agent",
                    dst_name="b",
                    relation="delegates",
                )
            )
            s.commit()


# ------------------------------------------------------------------- materialization


def test_agents_and_the_classes_they_exercise_become_nodes_and_uses_edges(audit, graph) -> None:
    act(audit, "a", ActionType.tool_call)
    act(audit, "a", ActionType.model_invocation)

    graph.materialize()

    assert {("agent", "a"), ("tool", "tool"), ("model", "model")} <= nodes(graph)
    assert {("a", "tool", "uses"), ("a", "model", "uses")} <= edges(graph)


def test_a_delegation_edge_is_derived_from_parent_lineage(audit, graph) -> None:
    """THE DISC-06 assertion: the audit body names the parent ACTION, not the parent AGENT, so the
    edge only exists if materialization resolves who performed that parent action."""
    parent = act(audit, "a", ActionType.delegation)
    act(audit, "b", ActionType.tool_call, parent=parent.id)

    graph.materialize()

    assert ("a", "b", "delegates") in edges(graph)
    assert ("agent", "a") in nodes(graph) and ("agent", "b") in nodes(graph)


def test_a_parent_by_the_same_agent_is_own_lineage_not_delegation(audit, graph) -> None:
    """An agent chaining its own actions delegates to nobody; drawing a self-edge here would make
    every multi-step agent look like a delegation hub."""
    parent = act(audit, "solo", ActionType.tool_call)
    act(audit, "solo", ActionType.tool_call, parent=parent.id)

    graph.materialize()

    assert not [e for e in edges(graph) if e[2] == "delegates"]


def test_an_unresolvable_parent_is_skipped_without_crashing(audit, graph) -> None:
    """A truncated or partially-retained log must degrade to a missing edge, never a failed sweep —
    this runs on a schedule, and a crash here would rot every derived view behind it."""
    act(audit, "orphan", ActionType.tool_call, parent=uuid4())

    graph.materialize()

    assert ("agent", "orphan") in nodes(graph)
    assert not [e for e in edges(graph) if e[2] == "delegates"]


def test_event_records_are_not_mistaken_for_decisions(store, audit, graph) -> None:
    """Event bodies carry a `kind` and describe an OBSERVATION, not an action someone performed.

    Real event kinds DO carry an agent_id AND an action_type — `sandbox_executed` (sandbox.py) and
    `resource_limit_exceeded` (resource_governor.py) carry both, plus the action_id that would
    pollute delegation lineage. So the `kind` guard is the ONLY thing between an observation and a
    phantom agent node with a phantom `uses` edge; the second body adds a verified-looking
    `reasons` list so the identity filter cannot stand in for it.
    """
    asyncio.run(
        audit.append_event(
            "sandbox_executed",
            {
                "action_id": str(uuid4()),
                "agent_id": "phantom-from-an-event",
                "action_type": "tool_call",
                "run_id": str(uuid4()),
                "outcome": "allow",
            },
        )
    )
    asyncio.run(
        audit.append_event(
            "sandbox_executed",
            {
                "action_id": str(uuid4()),
                "agent_id": "phantom-with-reasons",
                "action_type": "tool_call",
                "run_id": str(uuid4()),
                "outcome": "allow",
                "reasons": [r.model_dump(mode="json") for r in VERIFIED],
            },
        )
    )

    graph.materialize()

    assert nodes(graph) == set()
    assert edges(graph) == set()


def test_materialize_is_idempotent(audit, graph) -> None:
    """It is a SCHEDULED batch pass: a second sweep over unchanged evidence must converge, not
    grow a second copy of the graph."""
    parent = act(audit, "a", ActionType.delegation)
    act(audit, "b", ActionType.tool_call, parent=parent.id)

    assert graph.materialize() > 0
    before = graph.view()

    assert graph.materialize() == 0, "a converged graph still reports changes"

    after = graph.view()
    assert [(n["kind"], n["name"]) for n in after.nodes] == [
        (n["kind"], n["name"]) for n in before.nodes
    ]
    assert len(after.edges) == len(before.edges)
    # `observations` counts ACTIONS, not sweeps: a pass that consumed no new audit record must
    # leave every count exactly where it was.
    assert [e["observations"] for e in after.edges] == [e["observations"] for e in before.edges]


def test_the_inventory_supplies_per_name_nodes_alongside_the_audit_classes(
    store, audit, inventory_and_graph
) -> None:
    """The honest limit, asserted: the audit body has no `target`, so it can only prove "this agent
    used A tool". The inventory holds the NAME. Both sources are joined — neither overwrites the
    other."""
    inventory, graph = inventory_and_graph
    act(audit, "a", ActionType.tool_call)
    inventory.declare("a", tools=["http_get"])

    graph.materialize()

    assert ("tool", "tool") in nodes(graph), "the audit-derived capability class is missing"
    assert ("tool", "http_get") in nodes(graph), "the inventory's per-name node is missing"
    assert {("a", "tool", "uses"), ("a", "http_get", "uses")} <= edges(graph)


@pytest.fixture
def inventory_and_graph(store):
    inventory = InventoryStore(store)
    return inventory, AgentGraphStore(store, inventory=inventory)


# ------------------------------------------------------- claimed identity is not identity


def _forged(audit: AuditWriter, agent_id: str, action_type=ActionType.tool_call):
    """The record the identity short-circuit writes for a caller holding no credential: audited
    verbatim, denied, and carrying the identity stage's REFUSAL rather than its blessing."""
    return act(audit, agent_id, action_type, reasons=FORGED, outcome=Outcome.deny)


def test_a_record_whose_identity_never_verified_draws_nothing(audit, graph) -> None:
    """THE trust boundary. `agent_id` is attacker-chosen and goes RAW into the hash-covered body,
    and the pipeline audits an unknown caller's action verbatim before denying it — so a caller
    holding no credential could otherwise name a real agent as its delegator and serve itself a
    capability map it never earned. Only a record carrying the identity stage's own
    `identity_verified` reason is evidence of anything."""
    forged_parent = _forged(audit, "finance-approver-prod", ActionType.delegation)
    act(
        audit,
        "attacker-owned-worker",
        ActionType.mcp_call,
        parent=forged_parent.id,
        reasons=FORGED,
        outcome=Outcome.deny,
    )

    graph.materialize()

    assert nodes(graph) == set()
    assert edges(graph) == set()


def test_a_verified_child_cannot_inherit_an_unverified_parent(audit, graph) -> None:
    """The lineage half of the same boundary: a spoofed parent action is not a delegator."""
    forged_parent = _forged(audit, "finance-approver-prod", ActionType.delegation)
    act(audit, "worker", parent=forged_parent.id)

    graph.materialize()

    assert ("agent", "finance-approver-prod") not in nodes(graph)
    assert not [e for e in edges(graph) if e[2] == "delegates"]


# ------------------------------------------------------- hostile identifiers are bounded


def test_a_hostile_agent_id_is_bounded_and_carries_a_digest(audit, graph) -> None:
    """`graph_node.name` is String(255): SQLite stores 4000 chars happily, Postgres — the
    production target named in migration 0021 — raises StringDataRightTruncation and aborts the
    whole sweep, forever, because the same audit row is re-read every pass."""
    act(audit, "rogue-" + "A" * 4000)

    graph.materialize()

    names = [n for k, n in nodes(graph) if k == "agent"]
    assert len(names) == 1
    stored = names[0]
    assert len(stored) <= 255, "an unbounded name reaches a String(255) column"
    assert "#" in stored, "a truncated id must carry a digest of the full original"
    assert all(len(e[0]) <= 255 and len(e[1]) <= 255 for e in edges(graph))


def test_distinct_ids_past_the_cap_fold_into_one_overflow_node(store, audit) -> None:
    """An id-rotating prober holds no credential and picks a new id per probe, so bounding one
    attempt is not bounding the attacker (the DISC-04 lesson). Asserted against the TABLE: the
    growth this bounds is rows, not one response."""
    graph = AgentGraphStore(store, max_nodes=3)
    for i in range(10):
        act(audit, f"probe-{i}")

    graph.materialize()

    with store() as s:
        agents = set(s.scalars(select(GraphNode.name).where(GraphNode.kind == "agent")).all())
    assert len(agents) == 4, f"the distinct-id dimension is unbounded: {len(agents)} agent nodes"
    assert OVERFLOW_ID in agents, "the folded-away signal must survive as one bucket"


def test_two_overflowed_ids_do_not_delegate_to_each_other(store, audit) -> None:
    """Both fold to the same bucket name, and a self-edge would invent a delegation."""
    graph = AgentGraphStore(store, max_nodes=1)
    parent = act(audit, "keeper", ActionType.delegation)
    first = act(audit, "over-1", ActionType.delegation, parent=parent.id)
    act(audit, "over-2", parent=first.id)

    graph.materialize()

    assert not [e for e in edges(graph) if e[0] == e[1]]


# ------------------------------------------------------- the read is bounded


def test_the_view_is_bounded(store, audit) -> None:
    """`view()` materializes every row it selects into ONE JSON response, over a table an
    unauthenticated prober grows (the shadow / rogue / dashboard `.limit()` precedent)."""
    graph = AgentGraphStore(store, max_nodes=50, max_edges=3)
    for i in range(20):
        act(audit, f"a-{i}", ActionType.tool_call)
        act(audit, f"a-{i}", ActionType.mcp_call)
    for _ in range(4):
        act(audit, "a-0", ActionType.tool_call)  # one hot path among forty edges
    graph.materialize()

    view = graph.view()

    assert len(view.nodes) <= 50
    assert len(view.edges) == 3, "the edge read is unbounded"
    # Truncation keeps the hot paths, not an arbitrary forty.
    assert (view.edges[0]["src"]["name"], view.edges[0]["observations"]) == ("a-0", 5)


# ------------------------------------------------------- incremental, not O(all history)


def test_a_sweep_consumes_only_the_records_past_the_watermark(store, audit, graph) -> None:
    """The pass shares its database — and therefore its write lock — with the AuditWriter, so
    re-reading the whole log every 120 s stalls and then FAILS audit appends, which drives the
    pipeline's fail-safe. Cost must be O(new records), not O(all history)."""
    for i in range(6):
        act(audit, f"a-{i}")
    graph.materialize()

    with store() as s:
        mark = s.get(GraphWatermark, "graph")
        assert mark is not None and mark.seq == 5, "the watermark did not advance"

    with store() as s:
        engine = s.get_bind()
    seen: list[str] = []

    def _record(conn, cursor, statement, params, context, executemany):
        if "audit_record" in statement:
            seen.append(statement)

    event.listen(engine, "before_cursor_execute", _record)
    try:
        assert graph.materialize() == 0
    finally:
        event.remove(engine, "before_cursor_execute", _record)

    assert len(seen) == 1, f"a converged sweep re-read the audit log: {len(seen)} queries"


def test_observations_count_actions_not_sweeps(audit, graph) -> None:
    """The model docstring promises an operator can tell a one-off from a hot path. Counting
    sweeps inverted that: a one-off outranked a hot path purely for being older."""
    for _ in range(2):
        act(audit, "busy")
    act(audit, "quiet")
    graph.materialize()

    for _ in range(3):  # three more real actions, consumed by ONE later sweep
        act(audit, "busy")
    graph.materialize()
    graph.materialize()  # ...and a sweep that consumed nothing at all

    counts = {e["src"]["name"]: e["observations"] for e in graph.view().edges}
    assert counts["busy"] == 5, "an existing edge must grow by the ACTIONS since the watermark"
    assert counts["quiet"] == 1


def test_the_inventory_pass_does_not_double_count(audit, inventory_and_graph) -> None:
    """The declared half is a MANIFEST, not activity: bumping the same edge from both halves made
    one action read as two."""
    inventory, graph = inventory_and_graph
    act(audit, "a", ActionType.tool_call)
    inventory.declare("a", tools=["tool"])  # the manifest names the class itself

    graph.materialize()
    graph.materialize()

    counts = {(e["src"]["name"], e["dst"]["name"]): e["observations"] for e in graph.view().edges}
    assert counts[("a", "tool")] == 1


def test_the_inventory_cannot_smuggle_an_unverified_agent_onto_the_map(
    audit, inventory_and_graph
) -> None:
    """`enrich_from_audit` writes a class-level row for EVERY decision body, verified or not, and
    the GraphReconciler drives it on this very pass — so projecting observed rows would reinstate
    the trust boundary the identity filter exists to draw, through the side door."""
    inventory, graph = inventory_and_graph
    _forged(audit, "forged-caller")
    inventory.enrich_from_audit()  # exactly what GraphReconciler.reconcile does first

    graph.materialize()

    assert ("agent", "forged-caller") not in nodes(graph)
    assert edges(graph) == set()


# ------------------------------------------------------- fidelity survives the projection


def test_nodes_and_edges_record_where_they_came_from(audit, inventory_and_graph) -> None:
    """A capability-class placeholder ('tool','tool') is byte-identical to a genuine component
    named 'tool'; without `source` a Phase-13 walk cannot tell a placeholder from evidence — the
    exact collapse that made DISC-05 flag every declaring agent in the fleet."""
    inventory, graph = inventory_and_graph
    act(audit, "a", ActionType.tool_call)
    inventory.declare("a", tools=["http_get"])

    graph.materialize()

    node_source = {(n["kind"], n["name"]): n["source"] for n in graph.view().nodes}
    edge_source = {
        (e["src"]["name"], e["dst"]["name"]): e["source"] for e in graph.view().edges
    }
    assert node_source[("tool", "tool")] == OBSERVED_CLASS, "the placeholder claims full fidelity"
    assert node_source[("tool", "http_get")] == DECLARED
    assert edge_source[("a", "tool")] == OBSERVED_CLASS
    assert edge_source[("a", "http_get")] == DECLARED


def test_a_row_is_never_downgraded(audit, inventory_and_graph) -> None:
    """`inventory._upsert`'s precedence rule, carried into the graph: a manifest declaration
    outranks an observation and a later sweep must not walk it back."""
    inventory, graph = inventory_and_graph
    inventory.declare("a", tools=["tool"])
    graph.materialize()

    act(audit, "a", ActionType.tool_call)
    graph.materialize()

    view = graph.view()
    node_source = {(n["kind"], n["name"]): n["source"] for n in view.nodes}
    assert node_source[("tool", "tool")] == DECLARED
    assert node_source[("agent", "a")] == DECLARED
    assert [e["source"] for e in view.edges] == [DECLARED]


def test_an_agent_that_only_acted_is_observed(audit, graph) -> None:
    """Full fidelity: the agent id IS the identity, and it verified — unlike the class placeholder
    hanging off it."""
    act(audit, "a", ActionType.tool_call)

    graph.materialize()

    node_source = {(n["kind"], n["name"]): n["source"] for n in graph.view().nodes}
    assert node_source[("agent", "a")] == OBSERVED
