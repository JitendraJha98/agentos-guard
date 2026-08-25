"""DISC-06 e2e — the live agent graph over the REAL governed stack (Slice 10f).

One shared store carrying the real registry (which declares the registration manifest into the
inventory), the real pipeline + audit chain, the real `InventoryStore`, the real `AgentGraphStore`
and the real `GraphReconciler` behind the API gate. The sharing is the point: the unit tests prove
the materialization rules, this proves the half that WRITES the evidence and the half an operator
READS are the same store.

The load-bearing assertion is the delegation edge. Nothing in the audit body says "a delegated to
b" — it says "this action's parent was that action". The edge exists only because the pass resolved
who performed the parent, and the pipeline that recorded it here is the real one.
"""

from __future__ import annotations

import asyncio

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from agentos_contract import ActionType, AgentAction, Outcome
from agentos_controlplane.api import create_app
from agentos_controlplane.approvals import ApprovalStore
from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.audit_verify import verify_chain
from agentos_controlplane.graph import AgentGraphStore
from agentos_controlplane.inventory import OBSERVED_CLASS, InventoryStore
from agentos_controlplane.reconcile import GraphReconciler
from agentos_controlplane.registry import Registry
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_pipeline.identity import IdentityStage
from agentos_pipeline.policy import ConstitutionPolicyEngine
from agentos_pipeline.risk import PromptInjectionScorer
from agentos_pipeline.runner import Pipeline

TOKEN = "test-token"
AUTH = {"Authorization": f"Bearer {TOKEN}"}
PLANNER = "planner-agent"
WORKER = "worker-agent"
ALLOWED_URL = "https://api.example.com/data"  # in the test constitution's egress_allowlist


class _Stack:
    """The pipeline, the inventory, the graph and the app over ONE store."""

    def __init__(self, constitution_wasm, *, wire_graph: bool = True) -> None:
        engine = create_engine(
            "sqlite+pysqlite:///:memory:",
            poolclass=StaticPool,
            connect_args={"check_same_thread": False},
        )
        create_all(engine)
        self.store = create_session_factory(engine)
        self.inventory = InventoryStore(self.store)
        registry = Registry(self.store, inventory=self.inventory)
        self.planner_token = registry.register(PLANNER, manifest={"tools": ["http_get"]})
        self.worker_token = registry.register(WORKER)
        # ONE AuditWriter per store (the chain-head cache), shared by the pipeline.
        audit = AuditWriter(self.store, signer=registry.identity)
        self.graph = AgentGraphStore(self.store, inventory=self.inventory) if wire_graph else None
        self.pipeline = Pipeline(
            identity=IdentityStage(registry.identity),
            policy=ConstitutionPolicyEngine(
                wasm_path=str(constitution_wasm.wasm_path),
                lists=constitution_wasm.bundle.lists,
                constitution_version=constitution_wasm.bundle.constitution_version,
                principles_meta=constitution_wasm.principles_meta,
            ),
            scorers=[PromptInjectionScorer()],
            audit=audit,
        )
        self.app = create_app(
            ApprovalStore(self.store, audit),
            inventory_store=self.inventory,
            api_token=TOKEN,
            graph_store=self.graph,
        )
        self.client = TestClient(self.app)
        self.client.headers.update(AUTH)

    def act(self, *, agent_id: str, token: str, parent=None) -> tuple[AgentAction, object]:
        action = AgentAction(
            agent_id=agent_id,
            type=ActionType.tool_call,
            target="http_get",
            payload={"url": ALLOWED_URL},
            identity_token=token,
        )
        if parent is not None:
            action.context.parent_action_id = parent
        return action, asyncio.run(self.pipeline.evaluate(action))

    def reconcile(self) -> int:
        return GraphReconciler(self.inventory, graph=self.graph).reconcile()

    def fetch(self) -> dict:
        r = self.client.get("/discovery/graph")
        assert r.status_code == 200, r.text
        return r.json()


@pytest.fixture
def stack(constitution_wasm) -> _Stack:
    return _Stack(constitution_wasm)


def _delegated(stack: _Stack) -> None:
    """A real governed action by the planner, then a real governed action by the worker whose
    lineage names the planner's action as its parent."""
    parent, decision = stack.act(agent_id=PLANNER, token=stack.planner_token)
    assert decision.outcome is Outcome.allow
    _, child = stack.act(agent_id=WORKER, token=stack.worker_token, parent=parent.id)
    assert child.outcome is Outcome.allow


def test_the_graph_exposes_agents_components_and_the_delegation_edge(stack) -> None:
    _delegated(stack)

    assert stack.reconcile() > 0

    body = stack.fetch()
    nodes = {(n["kind"], n["name"]) for n in body["nodes"]}
    edges = {(e["src"]["name"], e["dst"]["name"], e["relation"]) for e in body["edges"]}

    # Both actors are first-class nodes...
    assert {("agent", PLANNER), ("agent", WORKER)} <= nodes
    # ...the capability class the audit body CAN prove, and the per-name node only the inventory
    # holds — the two sources joined, neither invented.
    assert ("tool", "tool") in nodes
    assert ("tool", "http_get") in nodes
    # ...and the lineage the whole slice exists for.
    assert (PLANNER, WORKER, "delegates") in edges
    assert (PLANNER, "tool", "uses") in edges
    assert verify_chain(stack.store).ok


def test_a_second_reconcile_pass_does_not_duplicate_the_graph(stack) -> None:
    """It runs on a schedule: a converged graph must report zero changes and the same rows."""
    _delegated(stack)
    stack.reconcile()
    first = stack.fetch()

    stack.reconcile()
    second = stack.fetch()

    assert [(n["kind"], n["name"]) for n in second["nodes"]] == [
        (n["kind"], n["name"]) for n in first["nodes"]
    ]
    assert len(second["edges"]) == len(first["edges"])
    # The graph half of the pass reports zero: converged, with the repeat sighting on
    # `observations` rather than on duplicate rows.
    assert stack.graph.materialize() == 0, "the graph reconciler churns on unchanged state"


def test_the_reconciler_still_enriches_the_observed_inventory(stack) -> None:
    """Phase 7's behaviour is SUPERSEDED, not dropped: the inventory is what supplies the per-name
    nodes above, so the graph pass must keep enriching it."""
    _delegated(stack)

    stack.reconcile()

    observed = {(c.kind, c.name, c.source) for c in stack.inventory.get_inventory(PLANNER)}
    assert ("tool", "tool", OBSERVED_CLASS) in observed
    assert ("tool", "http_get", "declared") in observed


def test_the_route_is_behind_the_shared_token_gate(stack) -> None:
    """Who talks to whom is a map of the fleet's blast radius — never public."""
    unauthenticated = TestClient(stack.app)  # no default auth header

    assert unauthenticated.get("/discovery/graph").status_code == 401


def test_app_without_a_graph_store_has_no_route(constitution_wasm) -> None:
    """Backward compat: unwired -> 404, and the sibling inventory route still works."""
    stack = _Stack(constitution_wasm, wire_graph=False)

    assert stack.client.get("/discovery/graph").status_code == 404
    assert stack.client.get("/inventory").status_code == 200
