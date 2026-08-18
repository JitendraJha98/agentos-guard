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


@pytest.fixture(scope="module")
def lte_engine(tmp_path_factory) -> ConstitutionPolicyEngine:
    """`lte` and `cost.spend_usd` are the halves of this registry entry that the shipped
    constitution does not use — so nothing else compiles either one."""
    yaml_text = (
        _HEADER
        + """
  - id: "9.3"
    title: A small share of budget is only warned about
    statement: An agent that has used no more than half its budget proceeds with a warning.
    effect: warn
    when: {field: cost.budget_used_ratio, op: lte, value: 0.5}
  - id: "9.4"
    title: A large absolute spend is opened for review
    statement: An agent that has spent more than one hundred dollars is opened for review.
    effect: governance_review
    when: {field: cost.spend_usd, op: gte, value: 100.0}
"""
    )
    return _compile(yaml_text, tmp_path_factory.mktemp("wasm_budget_lte"))


@pytest.fixture(scope="module")
def negated_lte_engine(tmp_path_factory) -> ConstitutionPolicyEngine:
    yaml_text = (
        _HEADER
        + """
  - id: "9.5"
    title: Spending past half the budget is denied
    statement: An agent that has used more than half its budget may not act.
    effect: deny
    when: {not: {field: cost.budget_used_ratio, op: lte, value: 0.5}}
"""
    )
    return _compile(yaml_text, tmp_path_factory.mktemp("wasm_budget_neg_lte"))


def test_lte_is_inclusive_at_the_boundary_and_spend_usd_is_a_live_field(lte_engine) -> None:
    """The other half of the numeric path. `lte` is in the same schema/compiler branch as `gte` and
    has no consumer in the shipped constitution; `cost.spend_usd` is a registered, emitted field
    with no consumer either. A field the registry publishes and no test ever compiles is a field an
    operator can author a principle against and discover is broken in production."""
    assert select_floor(lte_engine.evaluate(_policy_input(0.5)).matched) is Outcome.warn
    assert lte_engine.evaluate(_policy_input(0.500001)).matched == ()

    over = lte_engine.evaluate(_policy_input(0.9, spend_usd=150.0))
    assert select_floor(over.matched) is Outcome.governance_review
    assert lte_engine.evaluate(_policy_input(0.9, spend_usd=99.99)).matched == ()


def test_the_negated_lte_leaf_inverts_to_a_strict_greater_than(negated_lte_engine) -> None:
    """`not: {op: lte}` compiles to `>`, so the boundary flips from inclusive to exclusive. An
    off-by-one here denies the one agent sitting exactly on the threshold it was told it could use."""
    assert negated_lte_engine.evaluate(_policy_input(0.5)).matched == ()  # NOT(<= 0.5) is false AT it
    assert select_floor(negated_lte_engine.evaluate(_policy_input(0.6)).matched) is Outcome.deny


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


def test_a_serial_agent_overshoots_by_the_one_action_that_crossed_the_line(
    pipeline_with_budget,
) -> None:
    """The bound in the SERIAL case, asserted rather than asserted-in-prose: the action that crosses
    the line completes, and the very next one is stopped."""
    pipeline, ledger, tokens = pipeline_with_budget
    ledger.set_budget(AGENT_ID, limit_micro_usd=1_000_000)
    ledger.note_spend(AGENT_ID, 799_999)  # a hair under the 5.2 review band

    assert _evaluate(pipeline, tokens).outcome is Outcome.allow  # the crossing action proceeds
    ledger.note_spend(AGENT_ID, 500_000)  # it cost $0.50 and blew the budget
    assert _evaluate(pipeline, tokens).outcome is Outcome.require_approval  # the NEXT one stops


def test_everything_already_in_flight_crosses_the_line_together(pipeline_with_budget) -> None:
    """The bound this design ACTUALLY provides: overshoot is bounded by what is IN FLIGHT.

    The ledger moves only when a call RETURNS and its cost lands, so every action in flight when the
    line is crossed was gated on the same pre-crossing reading. An agent that fans out N parallel
    calls therefore overshoots by N costs, and N is the agent's choice — `asyncio.gather` walks
    straight through a "bounded to one action" claim. That is what the module docstring says and what
    an operator must size a limit against.

    What this test does and does not discriminate, stated exactly, because the previous version
    claimed more than it delivered. Asserting eight allows establishes nothing: starting under both
    bands they are trivially true, and the arithmetic after them is just eight manual `note_spend`
    calls. Replacing `gather` with a serial loop also changes nothing — and that is not a weakness,
    it is the property: a snapshot ledger reads the same posture either way.

    The discriminating assertion is on the READINGS. Eight gates, one distinct value. That fails
    immediately against a RESERVATION-based ledger (one that debits at gate time rather than at
    settle time), which is the alternative design this bound rules out — verified by mutating
    `posture_for` to reserve as it reads, which turns this test red.
    """
    pipeline, ledger, tokens = pipeline_with_budget
    ledger.set_budget(AGENT_ID, limit_micro_usd=1_000_000)
    ledger.note_spend(AGENT_ID, 700_000)  # under the 5.2 band, so only the budget can move these
    readings: list[float] = []
    real_posture_for = ledger.posture_for

    def _recording(agent_id: str):
        posture = real_posture_for(agent_id)
        readings.append(posture.budget_used_ratio)
        return posture

    ledger.posture_for = _recording

    async def _fan_out():
        actions = []
        for _ in range(8):
            action = _action()
            action.identity_token = tokens[AGENT_ID]
            actions.append(action)
        return await asyncio.gather(*(pipeline.evaluate(a) for a in actions))

    outcomes = [decision.outcome for decision in asyncio.run(_fan_out())]

    assert outcomes == [Outcome.allow] * 8
    assert len(readings) == 8, "every action must be gated on its own reading"
    assert set(readings) == {0.7}, "all eight gated on the SAME pre-crossing posture"
    del ledger.posture_for
    for _ in range(8):
        ledger.note_spend(AGENT_ID, 500_000)  # each cost $0.50, each landing after its own gate

    assert ledger.posture_for(AGENT_ID).budget_used_ratio == pytest.approx(4.7)  # not 1.5
    assert _evaluate(pipeline, tokens).outcome is Outcome.require_approval


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
