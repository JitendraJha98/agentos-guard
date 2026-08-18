"""ECON-02 — spend gates through the CONSTITUTION, and nothing else.

Two things are proved here and neither is assumed.

The FIRST is that the numeric comparison path actually works. `gte`/`lte` have been in the schema
and the compiler since Phase 3 with no numeric field to act on — `POLICY_INPUT_FIELDS` declared only
str/bool/list — so nothing has ever compiled one to Rego and evaluated it. `cost.*` is their first
live consumer, negated leaves included, and a silently inverted comparison would fire on exactly the
actions it should leave alone.

The SECOND is the ECON-02 claim itself: an over-budget action is escalated by the graduated-response
engine reading a principle, not by a budget enforcer running beside it. The regression lock is what
discriminates — the SAME pipeline, recompiled from a constitution with the budget principle DELETED,
must let the over-budget action straight through. If it still blocks there, something else is
enforcing, which is precisely what ECON-02 forbids.

Every pipeline test here runs the agent at trust 0.99. A budget floor that a trusted agent can walk
through is not a floor (POL-05/TRST-02), so the whole file is run under the condition most likely to
relax one.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from _opa import build_constitution_wasm, find_opa
from agentos_contract import ActionType, AgentAction, Outcome
from agentos_contract.policy_io import select_floor
from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.budget import BudgetLedger, CostPosture
from agentos_controlplane.registry import Registry
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_pipeline.enrichment import enrich
from agentos_pipeline.identity import IdentityStage
from agentos_pipeline.policy import ConstitutionPolicyEngine
from agentos_pipeline.policy_input import build_policy_input
from agentos_pipeline.posture import PostureMap
from agentos_pipeline.runner import Pipeline

pytestmark = pytest.mark.skipif(
    find_opa() is None, reason="no OPA binary (vendored tools/opa/opa.exe or PATH)"
)

AGENT_ID = "a1"
UNBUDGETED_ID = "never-configured"

_HEADER = """schema_version: 1
name: budget-probe
principles:
"""

# The two budget principles exactly as `policies/constitution.yaml` ships them, and nothing else: an
# isolated constitution means the only thing that can move an outcome here is the budget.
_BUDGET_PRINCIPLES = """
  - id: "5.1"
    title: Spending beyond budget requires approval
    statement: An agent that has consumed its budget may not continue spending without human approval.
    effect: require_approval
    when: {field: cost.budget_used_ratio, op: gte, value: 1.0}
  - id: "5.2"
    title: Approaching budget proceeds under governance review
    statement: An agent that has consumed most of its budget proceeds, but is opened for asynchronous governance review.
    effect: governance_review
    when: {field: cost.budget_used_ratio, op: gte, value: 0.8}
"""

# The deleted-principle variant. A constitution needs at least one principle to be valid, so it keeps
# one the budget probe can never satisfy — the file differs from the one above ONLY by the absence
# of 5.1/5.2, which is what makes the lock attribute any flip to those two principles alone.
_NO_BUDGET_PRINCIPLE = """
  - id: "9.9"
    title: Placeholder
    statement: A principle the budget probe cannot satisfy, so the file is still a valid constitution.
    effect: deny
    when: {field: intent.class, op: eq, value: NEVER_TAGGED_BY_THE_ENRICHER}
"""


def _compile(yaml_text: str, out_dir: Path) -> ConstitutionPolicyEngine:
    path = Path(out_dir) / "constitution.yaml"
    path.write_text(yaml_text, encoding="utf-8")
    built = build_constitution_wasm(path, Path(out_dir))
    return ConstitutionPolicyEngine(
        wasm_path=str(built.wasm_path),
        lists=built.bundle.lists,
        constitution_version=built.bundle.constitution_version,
        principles_meta=built.principles_meta,
    )


def _action(agent: str = AGENT_ID) -> AgentAction:
    """A deliberately dull model invocation: no PII, no injection, no unlisted egress. The ONLY
    thing that can move this action's outcome is the budget."""
    return AgentAction(
        agent_id=agent,
        type=ActionType.model_invocation,
        target="chat",
        payload={"model": "gpt-4o", "messages": "summarise the meeting notes"},
    )


def _policy_input(ratio: float, spend_usd: float = 0.0) -> dict:
    action = _action()
    posture = CostPosture(spend_usd=spend_usd, budget_used_ratio=ratio)
    return build_policy_input(action, enrich(action), cost=posture)


# --------------------------------------------------------- the numeric operator path (first use)


@pytest.fixture(scope="module")
def numeric_engine(tmp_path_factory) -> ConstitutionPolicyEngine:
    return _compile(_HEADER + _BUDGET_PRINCIPLES, tmp_path_factory.mktemp("wasm_budget"))


@pytest.fixture(scope="module")
def negated_engine(tmp_path_factory) -> ConstitutionPolicyEngine:
    yaml_text = (
        _HEADER
        + """
  - id: "9.2"
    title: Under budget proceeds
    statement: An agent below its budget proceeds.
    effect: warn
    when: {not: {field: cost.budget_used_ratio, op: gte, value: 1.0}}
"""
    )
    return _compile(yaml_text, tmp_path_factory.mktemp("wasm_budget_neg"))


def test_the_numeric_operator_path_works_end_to_end(numeric_engine) -> None:
    """gte has lived in the schema and the compiler since Phase 3 with NO numeric field to act on.
    This is its first real exercise: YAML -> Rego -> WASM -> evaluate."""
    over = numeric_engine.evaluate(_policy_input(1.0))
    near = numeric_engine.evaluate(_policy_input(0.9))

    assert select_floor(over.matched) is Outcome.require_approval
    assert select_floor(near.matched) is Outcome.governance_review
    assert numeric_engine.evaluate(_policy_input(0.79)).matched == ()


def test_gte_is_inclusive_at_the_boundary(numeric_engine) -> None:
    """The boundary is the whole point of a limit: exactly-at-the-line must count as reached, or an
    agent parked on its budget keeps spending one action at a time forever."""
    assert numeric_engine.evaluate(_policy_input(0.8)).matched != ()
    assert numeric_engine.evaluate(_policy_input(0.799999)).matched == ()


def test_the_negated_numeric_leaf_inverts_correctly(negated_engine) -> None:
    """The compiler maps gte->lt under a `not:` node. Nothing has ever exercised that inversion, and
    a wrong one fires on exactly the actions it should leave alone."""
    assert select_floor(negated_engine.evaluate(_policy_input(0.5)).matched) is Outcome.warn
    assert negated_engine.evaluate(_policy_input(1.0)).matched == ()
    assert negated_engine.evaluate(_policy_input(1.5)).matched == ()


# ---------------------------------------------------------------- the ECON-02 claim, end to end


def _new_store():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    create_all(engine)
    return create_session_factory(engine)


def _wire(engine: ConstitutionPolicyEngine):
    """The SAME wiring for both halves of the lock — they differ ONLY in the compiled constitution,
    so any outcome flip is attributable to the principle and to nothing else."""
    store = _new_store()
    registry = Registry(store)
    tokens = {
        AGENT_ID: registry.register(AGENT_ID, trust_score=0.99),
        UNBUDGETED_ID: registry.register(UNBUDGETED_ID, trust_score=0.99),
    }
    ledger = BudgetLedger(store)
    pipeline = Pipeline(
        identity=IdentityStage(registry.identity),
        policy=engine,
        scorers=[],
        audit=AuditWriter(store, signer=registry.identity),
        posture=PostureMap(),
        budget=ledger,
    )
    return pipeline, ledger, tokens


@pytest.fixture
def pipeline_with_budget(numeric_engine):
    return _wire(numeric_engine)


@pytest.fixture
def pipeline_no_budget_principle(tmp_path_factory):
    return _wire(
        _compile(_HEADER + _NO_BUDGET_PRINCIPLE, tmp_path_factory.mktemp("wasm_no_budget"))
    )


def _evaluate(pipeline, tokens, agent: str = AGENT_ID):
    action = _action(agent)
    action.identity_token = tokens[agent]
    return asyncio.run(pipeline.evaluate(action))


@pytest.mark.regression_lock
def test_an_over_budget_action_is_escalated_by_the_graduated_engine(pipeline_with_budget) -> None:
    """ECON-02's core claim. Note WHAT is asserted: the outcome carries a POLICY-stage reason naming
    principle 5.1 — proving the constitution did this, not an enforcer running beside it."""
    pipeline, ledger, tokens = pipeline_with_budget
    ledger.set_budget(AGENT_ID, limit_micro_usd=1_000_000)
    ledger.note_spend(AGENT_ID, 1_200_000)

    decision = _evaluate(pipeline, tokens)

    assert decision.outcome is Outcome.require_approval
    assert any(r.stage == "policy" and r.principle_ref == "5.1" for r in decision.reasons)


@pytest.mark.regression_lock
def test_removing_the_principle_flips_the_over_budget_action_to_allow(
    pipeline_no_budget_principle,
) -> None:
    """The D-04-style lock: if the constitution is what enforces the budget, deleting the principle
    must let the over-budget action through. If it still blocks, something ELSE is enforcing — and a
    parallel enforcer is exactly what ECON-02 forbids."""
    pipeline, ledger, tokens = pipeline_no_budget_principle
    ledger.set_budget(AGENT_ID, limit_micro_usd=1_000_000)
    ledger.note_spend(AGENT_ID, 5_000_000)  # five times over

    assert _evaluate(pipeline, tokens).outcome is Outcome.allow


def test_an_agent_with_no_budget_configured_is_unaffected(pipeline_with_budget) -> None:
    """The fleet-wide-outage guard, asserted through the real pipeline: a deployment that never
    opted into budgets must not be denied by the mere presence of the fields."""
    pipeline, ledger, tokens = pipeline_with_budget
    ledger.note_spend(UNBUDGETED_ID, 900_000_000)  # $900 spent, no limit ever set

    assert _evaluate(pipeline, tokens, UNBUDGETED_ID).outcome is Outcome.allow


def test_unpriced_spend_never_crosses_the_line(pipeline_with_budget) -> None:
    """An unpriced action burned tokens we cannot convert to dollars. Advancing the budget by an
    invented figure would let the constitution deny on a number nobody can reconcile."""
    pipeline, ledger, tokens = pipeline_with_budget
    ledger.set_budget(AGENT_ID, limit_micro_usd=1_000_000)
    for _ in range(100):
        ledger.note_spend(AGENT_ID, None)

    assert _evaluate(pipeline, tokens).outcome is Outcome.allow


def test_overshoot_is_bounded_to_one_action(pipeline_with_budget) -> None:
    """The honest bound from the design (D-4), asserted rather than asserted-in-prose: the action
    that CROSSES the line completes, and the very next one is stopped."""
    pipeline, ledger, tokens = pipeline_with_budget
    ledger.set_budget(AGENT_ID, limit_micro_usd=1_000_000)
    ledger.note_spend(AGENT_ID, 799_999)  # a hair under the 5.2 review band

    assert _evaluate(pipeline, tokens).outcome is Outcome.allow  # the crossing action proceeds
    ledger.note_spend(AGENT_ID, 500_000)  # it cost $0.50 and blew the budget
    assert _evaluate(pipeline, tokens).outcome is Outcome.require_approval  # the NEXT one stops


@pytest.mark.floor_invariant
def test_the_budget_floor_is_never_relaxed_by_trust(pipeline_with_budget) -> None:
    """POL-05/TRST-02: a policy floor is terminal. A highly trusted agent must not spend past its
    budget just because it is trusted — risk and trust may only restrict further."""
    pipeline, ledger, tokens = pipeline_with_budget
    ledger.set_budget(AGENT_ID, limit_micro_usd=1_000_000)
    ledger.note_spend(AGENT_ID, 9_000_000)

    decision = _evaluate(pipeline, tokens)

    assert decision.trust_score == pytest.approx(0.99)
    assert decision.outcome is Outcome.require_approval
    assert any(r.stage == "policy" and r.principle_ref == "5.1" for r in decision.reasons)
