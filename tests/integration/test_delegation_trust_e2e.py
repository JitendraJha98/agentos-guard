"""TRST-04 end-to-end: the trust-laundering attack, driven through the real pipeline.

The unit tests cover the authority algebra. This proves the property that actually
matters at runtime: a distrusted agent cannot recover authority by delegating to a
trusted sub-agent, because the pipeline scores the delegate with its CHAIN-CAPPED
trust rather than its own standing.

Wired against the real Pipeline (real identity engine, real registry, real audit,
real graduated stage) with a permissive stub policy — the floor is not what is
under test here, the trust budget is.
"""

from __future__ import annotations

import asyncio
from uuid import uuid4

import pytest
from sqlalchemy import create_engine

from agentos_contract import ActionType, AgentAction, Outcome
from agentos_contract.policy_io import ConstitutionResult
from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.registry import Registry
from agentos_controlplane.resources import ResourceStore
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_pipeline.delegation import DelegationLedger, DelegationResolver
from agentos_pipeline.graduated import GraduatedThresholds
from agentos_pipeline.identity import IdentityStage
from agentos_pipeline.posture import PostureMap
from agentos_pipeline.runner import Pipeline


class _AllowAllPolicy:
    """A permissive policy floor: this suite tests the trust budget, not the floor."""

    constitution_version = "test-const-v1"
    policy_version = "test-pol-v1"

    def evaluate(self, policy_input: dict) -> ConstitutionResult:
        return ConstitutionResult(matched=(), no_match=True)


@pytest.fixture()
def wired():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    sf = create_session_factory(engine)
    registry, resources = Registry(sf), ResourceStore(sf)
    ledger = DelegationLedger()

    pipeline = Pipeline(
        identity=IdentityStage(registry.identity),
        policy=_AllowAllPolicy(),
        scorers=[],
        audit=AuditWriter(sf),
        thresholds=GraduatedThresholds(),
        posture=PostureMap(),
        delegation=DelegationResolver(resources, ledger=ledger),
    )
    return pipeline, registry, resources, ledger


def _action(agent_id: str, token: str, *, parent=None) -> AgentAction:
    action = AgentAction(
        agent_id=agent_id,
        type=ActionType.tool_call,
        target="http_get",
        payload={"url": "https://api.example.com/x", "content": ""},
        identity_token=token,
    )
    if parent is not None:
        action.context.parent_action_id = parent
    return action


def test_trust_laundering_through_delegation_fails(wired):
    """A distrusted principal must not borrow a trusted delegate's standing.

    Without the TRST-04 budget the delegate would be scored at its own 1.0 and the
    reputation engine that ground the principal down to 0.05 would be bypassed in
    a single delegation hop.
    """
    pipeline, registry, resources, ledger = wired
    bad_token = registry.register("distrusted")
    good_token = registry.register("trusted")
    resources.put_trust_profile("distrusted", trust_score=0.05, band=None, expected_version=None)
    resources.put_trust_profile("trusted", trust_score=1.0, band=None, expected_version=None)

    # The distrusted principal acts (establishing the chain root)...
    root = _action("distrusted", bad_token)
    root_decision = asyncio.run(pipeline.evaluate(root))
    assert root_decision.trust_score == pytest.approx(0.05)

    # ...then delegates to the fully-trusted agent.
    delegated = _action("trusted", good_token, parent=root.id)
    decision = asyncio.run(pipeline.evaluate(delegated))

    assert decision.trust_score <= 0.05, (
        f"trust laundering succeeded: a 0.05-trust principal's delegate acted at "
        f"{decision.trust_score}"
    )


def test_a_root_action_acts_with_its_own_trust(wired):
    """No lineage == chain root: the budget must not penalise ordinary traffic."""
    pipeline, registry, resources, ledger = wired
    token = registry.register("solo")
    resources.put_trust_profile("solo", trust_score=0.9, band=None, expected_version=None)

    decision = asyncio.run(pipeline.evaluate(_action("solo", token)))

    assert decision.outcome == Outcome.allow
    assert decision.trust_score == pytest.approx(0.9)


def test_trust_decays_along_a_real_delegation_chain(wired):
    pipeline, registry, resources, ledger = wired
    tokens = {a: registry.register(a) for a in ("a", "b", "c")}
    for a in tokens:
        resources.put_trust_profile(a, trust_score=1.0, band=None, expected_version=None)

    a1 = _action("a", tokens["a"])
    asyncio.run(pipeline.evaluate(a1))
    b1 = _action("b", tokens["b"], parent=a1.id)
    d_b = asyncio.run(pipeline.evaluate(b1))
    c1 = _action("c", tokens["c"], parent=b1.id)
    d_c = asyncio.run(pipeline.evaluate(c1))

    assert 1.0 > d_b.trust_score > d_c.trust_score, "trust did not decay down the chain"


def test_unknown_lineage_is_denied_fail_closed(wired):
    """An invented parent_action_id must not be treated as 'no parent, so root'."""
    pipeline, registry, resources, ledger = wired
    token = registry.register("sneaky")
    resources.put_trust_profile("sneaky", trust_score=1.0, band=None, expected_version=None)

    decision = asyncio.run(pipeline.evaluate(_action("sneaky", token, parent=uuid4())))

    assert decision.outcome == Outcome.deny
    assert any(r.stage == "delegation" for r in decision.reasons)


def test_delegation_conferring_an_empty_scope_is_denied(wired):
    """Scope intersection at runtime: B's db.drop is unreachable when A lacks it."""
    pipeline, registry, resources, ledger = wired
    a_token = registry.register("reader")
    b_token = registry.register("dropper")
    resources.put_trust_profile(
        "reader", trust_score=1.0, band=None, expected_version=None, scope=["read"]
    )
    resources.put_trust_profile(
        "dropper", trust_score=1.0, band=None, expected_version=None, scope=["db.drop"]
    )

    a1 = _action("reader", a_token)
    asyncio.run(pipeline.evaluate(a1))
    decision = asyncio.run(pipeline.evaluate(_action("dropper", b_token, parent=a1.id)))

    assert decision.outcome == Outcome.deny
    assert any("scope" in r.detail.lower() for r in decision.reasons if r.stage == "delegation")


def test_a_denied_delegation_is_audited(wired):
    """Evidence exists before enforcement, as on every other terminal deny path."""
    pipeline, registry, resources, ledger = wired
    token = registry.register("x")
    decision = asyncio.run(pipeline.evaluate(_action("x", token, parent=uuid4())))
    assert decision.outcome == Outcome.deny
    assert decision.evidence_ref is not None, "denied delegation left no audit evidence"


def test_pipeline_without_a_resolver_is_unchanged(wired):
    """None default: unwired deployments keep exactly the pre-Phase-7 behavior."""
    _, registry, resources, _ = wired
    engine = create_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    sf = create_session_factory(engine)
    reg = Registry(sf)
    token = reg.register("plain")

    pipeline = Pipeline(
        identity=IdentityStage(reg.identity),
        policy=_AllowAllPolicy(),
        scorers=[],
        audit=AuditWriter(sf),
        thresholds=GraduatedThresholds(),
        posture=PostureMap(),
    )
    # An unknown parent would be a fail-closed deny WITH a resolver; without one it flows.
    decision = asyncio.run(pipeline.evaluate(_action("plain", token, parent=uuid4())))
    assert decision.outcome == Outcome.allow
