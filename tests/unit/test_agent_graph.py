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
from sqlalchemy import create_engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.pool import StaticPool

from agentos_contract import ActionType, AgentAction, Decision, Outcome
from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.graph import AgentGraphStore
from agentos_controlplane.inventory import InventoryStore
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import GraphEdge, GraphNode

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


def act(audit: AuditWriter, agent_id: str, action_type=ActionType.tool_call, *, parent=None):
    """Append ONE real decision record; return the action so a child can name it as parent."""
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
                outcome=Outcome.allow,
                risk_score=0.0,
                trust_score=0.5,
                reasons=[],
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
    """Event bodies carry a `kind` and describe an OBSERVATION, not an action someone performed —
    even when they mention an agent_id and an action_type."""
    asyncio.run(
        audit.append_event(
            "shadow_agent_detected", {"claimed_agent_id": "ghost", "action_type": "tool_call"}
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
    # The repeat sighting lands on `observations`, not on a duplicate row.
    assert all(a["observations"] > b["observations"] for a, b in zip(after.edges, before.edges))


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
