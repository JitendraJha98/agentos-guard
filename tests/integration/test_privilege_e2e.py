"""Privilege rings e2e over the REAL governed stack (RUN-04, Slice 9b, Task 4).

The RUN-04 acceptance proof over ONE shared store and the SAME PrivilegeRingStore instance (so the
in-memory map the pipeline's stage-1e check reads is the one administration updates):

  - baseline: a benign allowlisted `http_get` is ALLOWED (so a later deny is attributable to the ring)
  - register the target at ring 2   -> the same action denies with `privilege`/`insufficient_ring`
  - promote the agent to ring 2     -> allowed again
  - a DIFFERENT agent (ring 0)      -> still denied for that target (per-agent tiering)
  - a ring-0 principal delegating to a ring-2 delegate -> STILL denied (the ring is chain-capped,
    mirroring the TRST-04 trust budget: privilege is not borrowable across a delegation edge)
  - both administrative changes landed as `privilege_ring_set` events and the chain still verifies

The pipeline runs the REAL compiled-constitution engine over a benign allowed action, so the ONLY
reason a ring can deny it is stage 1e.
"""

from __future__ import annotations

import asyncio

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.pool import StaticPool

from agentos_contract import ActionType, AgentAction, Outcome
from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.audit_verify import verify_chain
from agentos_controlplane.privilege import PrivilegeRingStore
from agentos_controlplane.registry import Registry
from agentos_controlplane.resources import ResourceStore
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import AuditRecord
from agentos_pipeline.delegation import DelegationLedger, DelegationResolver
from agentos_pipeline.identity import IdentityStage
from agentos_pipeline.policy import ConstitutionPolicyEngine
from agentos_pipeline.posture import PostureMap
from agentos_pipeline.risk import PromptInjectionScorer
from agentos_pipeline.runner import Pipeline

AGENT_ID = "test-agent"
OTHER_AGENT = "other-agent"


class Wired:
    """Pipeline + PrivilegeRingStore over ONE shared store and the SAME store instance
    (the in-memory ring map is shared administration<->pipeline)."""

    def __init__(self, constitution_wasm) -> None:
        engine = create_engine(
            "sqlite+pysqlite:///:memory:",
            poolclass=StaticPool,
            connect_args={"check_same_thread": False},
        )
        create_all(engine)
        self.store = create_session_factory(engine)
        registry = Registry(self.store)
        self.token = registry.register(AGENT_ID)
        self.other_token = registry.register(OTHER_AGENT)
        audit = AuditWriter(self.store)
        self.rings = PrivilegeRingStore(self.store, audit)
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
            posture=PostureMap(),
            # TRST-04 resolver: wired so the ring cap over a real delegation chain is exercised.
            delegation=DelegationResolver(ResourceStore(self.store), ledger=DelegationLedger()),
            privilege=self.rings,  # SAME instance administration updates
        )

    def action(self, agent_id: str, token: str) -> AgentAction:
        # A benign, allowed action: the only thing that can deny it is the privilege ring.
        return AgentAction(
            agent_id=agent_id,
            type=ActionType.tool_call,
            target="http_get",
            payload={"url": "https://api.example.com/data", "content": ""},
            identity_token=token,
        )

    def evaluate(self, agent_id: str, token: str):
        return asyncio.run(self.pipeline.evaluate(self.action(agent_id, token)))


@pytest.fixture
def wired(constitution_wasm) -> Wired:
    return Wired(constitution_wasm)


def _events(store, kind: str) -> list[dict]:
    with store() as s:
        rows = s.scalars(select(AuditRecord).order_by(AuditRecord.seq))
        return [r.body for r in rows if r.body.get("kind") == kind]


def test_baseline_action_is_allowed(wired: Wired) -> None:
    """Sanity: with no target registered, the benign action is allowed — so a later deny is the ring.
    This is the registered-sensitivity model: an unregistered target is ungated by stage 1e."""
    assert wired.evaluate(AGENT_ID, wired.token).outcome is Outcome.allow


def test_ring_gate_denies_then_promotion_permits(wired: Wired) -> None:
    """The RUN-04 acceptance proof: register the target -> deny; promote the agent -> allow."""
    asyncio.run(wired.rings.set_target_ring("http_get", 2, set_by="op@x"))

    denied = wired.evaluate(AGENT_ID, wired.token)
    assert denied.outcome is Outcome.deny
    assert denied.reasons[-1].stage == "privilege"
    assert denied.reasons[-1].code == "insufficient_ring"
    assert "requires privilege ring 2" in denied.reasons[-1].detail
    assert denied.evidence_ref is not None  # audited as a DECISION record

    asyncio.run(wired.rings.set_agent_ring(AGENT_ID, 2, set_by="op@x"))
    assert wired.evaluate(AGENT_ID, wired.token).outcome is Outcome.allow


def test_promotion_is_per_agent(wired: Wired) -> None:
    """Per-agent tiering: promoting one agent leaves every other agent at ring 0."""
    asyncio.run(wired.rings.set_target_ring("http_get", 2, set_by="op"))
    asyncio.run(wired.rings.set_agent_ring(AGENT_ID, 2, set_by="op"))

    assert wired.evaluate(AGENT_ID, wired.token).outcome is Outcome.allow
    other = wired.evaluate(OTHER_AGENT, wired.other_token)
    assert other.outcome is Outcome.deny
    assert other.reasons[-1].code == "insufficient_ring"


def test_a_low_ring_principal_cannot_escalate_through_a_high_ring_delegate(wired: Wired) -> None:
    """The privilege-ring half of the anti-laundering property, over the real stack: a ring-0
    principal delegating a ring-gated call to a ring-2 delegate must STILL be denied. Without the
    chain cap the delegate's action carries its own agent_id, holds 2 >= 2, and is allowed —
    delegation becomes a privilege-escalation path around the whole gate."""
    asyncio.run(wired.rings.set_target_ring("http_get", 2, set_by="op"))
    asyncio.run(wired.rings.set_agent_ring(OTHER_AGENT, 2, set_by="op"))

    # Control: the delegate acting as a chain ROOT holds ring 2 in its own right -> allowed.
    assert wired.evaluate(OTHER_AGENT, wired.other_token).outcome is Outcome.allow

    # The escalation attempt: the ring-0 principal acts (establishing the chain root), then hands
    # the same call to the ring-2 delegate.
    root = wired.action(AGENT_ID, wired.token)
    asyncio.run(wired.pipeline.evaluate(root))
    delegated = wired.action(OTHER_AGENT, wired.other_token)
    delegated.context.parent_action_id = root.id
    decision = asyncio.run(wired.pipeline.evaluate(delegated))

    assert decision.outcome is Outcome.deny
    assert decision.reasons[-1].stage == "privilege"
    assert decision.reasons[-1].code == "insufficient_ring"
    # The detail names the cap, so an operator can see WHY a ring-2 delegate was refused.
    assert "chain-capped" in decision.reasons[-1].detail


def test_admin_changes_are_audited_and_chain_verifies(wired: Wired) -> None:
    asyncio.run(wired.rings.set_target_ring("http_get", 2, set_by="op"))
    asyncio.run(wired.rings.set_agent_ring(AGENT_ID, 2, set_by="op"))
    wired.evaluate(AGENT_ID, wired.token)

    bodies = _events(wired.store, "privilege_ring_set")
    assert len(bodies) == 2
    assert {(b["scope"], b["key"], b["ring"]) for b in bodies} == {
        ("target", "http_get", 2),
        ("agent", AGENT_ID, 2),
    }
    assert verify_chain(wired.store).ok


def test_rings_survive_a_fresh_store_over_the_same_tables(wired: Wired) -> None:
    """Durability: a restarted control plane reloads the rings and keeps denying."""
    asyncio.run(wired.rings.set_target_ring("http_get", 2, set_by="op"))
    fresh = PrivilegeRingStore(wired.store, AuditWriter(wired.store))
    assert fresh.required_ring("http_get") == 2
    assert fresh.check(AGENT_ID, "http_get") is not None
