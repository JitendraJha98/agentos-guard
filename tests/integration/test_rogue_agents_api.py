"""DISC-05 e2e — rogue-agent detection over the REAL governed stack (Slice 10e).

One shared store carrying the real registry (which declares the registration manifest into the
inventory), the real pipeline + audit chain, the real `InventoryStore` and the real `RogueDetector`
behind the API gate. The sharing is the point: the unit tests prove the detector's rules, this
proves the half that WRITES the inventory and the half an operator READS are the same store.

What DISC-05 delivers is ADVISORY visibility. The assertions pin that too — a declared component
never appears, an undeclared one does, enforcement is untouched (the governed action's outcome is
the same with the detector wired), and an operator's acknowledgement is a read-filter, not a
deletion.
"""

from __future__ import annotations

import asyncio

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.pool import StaticPool

from agentos_contract import ActionType, AgentAction, Outcome
from agentos_controlplane.api import create_app
from agentos_controlplane.approvals import ApprovalStore
from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.audit_verify import verify_chain
from agentos_controlplane.inventory import OBSERVED_CLASS, InventoryStore
from agentos_controlplane.reconcile import GraphReconciler
from agentos_controlplane.registry import Registry
from agentos_controlplane.rogue import RogueDetector
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import AuditRecord
from agentos_pipeline.identity import IdentityStage
from agentos_pipeline.policy import ConstitutionPolicyEngine
from agentos_pipeline.risk import PromptInjectionScorer
from agentos_pipeline.runner import Pipeline

TOKEN = "test-token"
AUTH = {"Authorization": f"Bearer {TOKEN}"}
AGENT_ID = "declared-agent"
QUIET_ID = "no-manifest-agent"
ALLOWED_URL = "https://api.example.com/data"  # in the test constitution's egress_allowlist


class _Stack:
    """The pipeline, the inventory and the app over ONE store and ONE RogueDetector."""

    def __init__(self, constitution_wasm, *, wire_rogue: bool = True) -> None:
        engine = create_engine(
            "sqlite+pysqlite:///:memory:",
            poolclass=StaticPool,
            connect_args={"check_same_thread": False},
        )
        create_all(engine)
        self.store = create_session_factory(engine)
        self.inventory = InventoryStore(self.store)
        registry = Registry(self.store, inventory=self.inventory)
        # The manifest is what makes this agent accountable: DISC-01 writes it as `declared`.
        self.token = registry.register(AGENT_ID, manifest={"tools": ["http_get"]})
        # A second agent registers with NO manifest — the negative control for "unknown scope".
        self.quiet_token = registry.register(QUIET_ID)
        # ONE AuditWriter per store (the chain-head cache) shared by pipeline and detector.
        audit = AuditWriter(self.store, signer=registry.identity)
        self.detector = (
            RogueDetector(self.store, audit, self.inventory) if wire_rogue else None
        )
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
            rogue_detector=self.detector,
        )
        self.client = TestClient(self.app)
        self.client.headers.update(AUTH)

    def act(self, *, agent_id: str, token: str, target: str):
        return asyncio.run(
            self.pipeline.evaluate(
                AgentAction(
                    agent_id=agent_id,
                    type=ActionType.tool_call,
                    target=target,
                    payload={"url": ALLOWED_URL},
                    identity_token=token,
                )
            )
        )

    def findings(self, *, include_resolved: bool = False) -> list[dict]:
        r = self.client.get(
            "/discovery/rogue-agents", params={"include_resolved": include_resolved}
        )
        assert r.status_code == 200, r.text
        return r.json()

    def rogue_events(self) -> list[dict]:
        with self.store() as s:
            rows = s.scalars(select(AuditRecord).order_by(AuditRecord.seq.asc())).all()
            return [r.body for r in rows if r.body.get("kind") == "rogue_agent_detected"]


@pytest.fixture
def stack(constitution_wasm) -> _Stack:
    return _Stack(constitution_wasm)


def test_undeclared_component_is_flagged_and_declared_one_is_not(stack) -> None:
    """The whole slice in one assertion set: the agent really did use `http_get` (declared, so
    invisible here) and also `db_drop` (never declared, so surfaced)."""
    assert stack.findings() == []

    # A real governed action against the DECLARED tool, then the same agent observed using one it
    # never declared.
    assert stack.act(agent_id=AGENT_ID, token=stack.token, target="http_get").outcome is (
        Outcome.allow
    )
    stack.inventory.observe(AGENT_ID, "tool", "http_get")
    stack.inventory.observe(AGENT_ID, "tool", "db_drop")

    asyncio.run(stack.detector.scan())

    rows = stack.findings()
    assert [(r["agent_id"], r["kind"], r["name"], r["resolved"]) for r in rows] == [
        (AGENT_ID, "tool", "db_drop", False)
    ]
    assert "http_get" not in {r["name"] for r in rows}
    assert len(stack.rogue_events()) == 1
    assert verify_chain(stack.store).ok


def test_the_real_observation_path_does_not_flag_a_compliant_agent(stack) -> None:
    """The false positive this whole feature lives or dies on, driven by the REAL writer.

    Every other test here seeds the inventory with `observe(agent, 'tool', 'http_get')` — per-tool
    fidelity that NO production path emits. The only production writer is
    `GraphReconciler.reconcile()` -> `InventoryStore.enrich_from_audit()`, and because the audit
    body omits the per-action target it records a CLASS-level placeholder ('tool','tool'). Compared
    against the manifest's per-tool names it can never reconcile, so a fully compliant agent making
    exactly one governed call produced a `rogue_finding` row and a permanent chain record.
    """
    assert stack.act(agent_id=AGENT_ID, token=stack.token, target="http_get").outcome is (
        Outcome.allow
    )

    assert GraphReconciler(stack.inventory).reconcile() >= 1
    observed = {(c.kind, c.name, c.source) for c in stack.inventory.get_inventory(AGENT_ID)}
    assert ("tool", "tool", OBSERVED_CLASS) in observed  # the class-level row really was written
    assert ("tool", "http_get", "declared") in observed  # ...alongside the manifest's own row

    assert asyncio.run(stack.detector.scan()) == []
    assert stack.findings() == []
    assert stack.rogue_events() == []
    assert verify_chain(stack.store).ok


def test_agent_with_no_manifest_is_not_flagged_e2e(stack) -> None:
    """Registered but never declared a scope: unknown scope is not empty scope. Pinned here as
    well as in the unit tests because it is the rule most likely to be "fixed" into flagging the
    whole fleet."""
    assert stack.act(
        agent_id=QUIET_ID, token=stack.quiet_token, target="http_get"
    ).outcome is Outcome.allow
    stack.inventory.observe(QUIET_ID, "tool", "db_drop")

    asyncio.run(stack.detector.scan())

    assert stack.findings() == []
    assert stack.rogue_events() == []


def test_detection_never_denies(stack) -> None:
    """ADVISORY: the flagged agent keeps acting exactly as before. A stale manifest must never
    become an automatic outage — escalation is an operator's call, not this detector's."""
    stack.inventory.observe(AGENT_ID, "tool", "db_drop")
    asyncio.run(stack.detector.scan())
    assert len(stack.findings()) == 1

    after = stack.act(agent_id=AGENT_ID, token=stack.token, target="http_get")

    assert after.outcome is Outcome.allow


def test_resolve_filters_the_default_list_but_keeps_the_row(stack) -> None:
    stack.inventory.observe(AGENT_ID, "tool", "db_drop")
    asyncio.run(stack.detector.scan())
    finding_id = stack.findings()[0]["id"]

    assert stack.detector.resolve(finding_id) is True

    assert stack.findings() == []
    kept = stack.findings(include_resolved=True)
    assert [(r["id"], r["resolved"]) for r in kept] == [(finding_id, True)]
    assert len(stack.rogue_events()) == 1  # the sighting is still in the chain
    assert verify_chain(stack.store).ok


def test_repeat_scan_over_the_real_stack_is_idempotent(stack) -> None:
    stack.inventory.observe(AGENT_ID, "tool", "db_drop")
    asyncio.run(stack.detector.scan())
    asyncio.run(stack.detector.scan())
    asyncio.run(stack.detector.scan())

    assert len(stack.findings()) == 1
    assert len(stack.rogue_events()) == 1


def test_the_route_is_behind_the_shared_token_gate(stack) -> None:
    """Which agents are outside their declared scope is not public information."""
    unauthenticated = TestClient(stack.app)  # no default auth header

    assert unauthenticated.get("/discovery/rogue-agents").status_code == 401


def test_app_without_a_detector_has_no_route(constitution_wasm) -> None:
    """Backward compat: unwired -> 404, and the sibling inventory route still works."""
    stack = _Stack(constitution_wasm, wire_rogue=False)

    assert stack.client.get("/discovery/rogue-agents").status_code == 404
    assert stack.client.get("/inventory").status_code == 200
