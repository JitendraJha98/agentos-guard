"""Side-effect derivation + dispatch — PIPE-09 (6b-1 producers, 6b-3 dispatcher).

Side effects are composable, outcome-ORTHOGONAL escalations: fired principles'
authored `side_effects` (via principles_meta) flow onto the Decision (dedup,
order-stable); any risk finding with non-empty `matched` adds `risk_flag`; a
fail-open fail-safe carries `notify`. One decision can permit AND escalate
(allow + risk_flag) — that is the whole point of keeping them orthogonal.

Dispatch (6b-3): one `side_effect` audit event per effect through the ONE hash
chain + an optional callback sink; a raising sink is CONTAINED (logged, never
blocks the action result, never raises into the caller).
"""

from __future__ import annotations

import asyncio
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine, select

from agentos_contract import (
    ActionType,
    AgentAction,
    Decision,
    Outcome,
    Reason,
    RiskFinding,
    SideEffect,
)
from agentos_contract.policy_io import ConstitutionResult, MatchedPrinciple
from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.coordinator import AuditSideEffectDispatcher
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import AuditRecord
from agentos_pipeline.posture import PostureMap
from agentos_pipeline.runner import Pipeline
from agentos_sdk.enforce import governed_call


class _Identity:
    class _V:
        ok = True
        trust_score = 0.5
        detail = ""

    def verify(self, action):
        return self._V()


class _Policy:
    """Returns the scripted matched principles; principles_meta declares side_effects."""

    constitution_version = "sha256:stub-c"
    policy_version = "sha256:stub-p"

    def __init__(self, matched: tuple[MatchedPrinciple, ...], meta: dict[str, dict]) -> None:
        self._matched = matched
        self.principles_meta = meta

    def evaluate(self, input: dict) -> ConstitutionResult:
        return ConstitutionResult(matched=self._matched, no_match=not self._matched)


class _RaisingPolicy:
    constitution_version = "sha256:stub-c"
    policy_version = "sha256:stub-p"
    principles_meta: dict = {}

    def evaluate(self, input: dict) -> ConstitutionResult:
        raise RuntimeError("engine down")


class _Scorer:
    name = "spy.v1"
    inline = True

    def __init__(self, risk: float, matched: list[str]) -> None:
        self._risk = risk
        self._matched = matched

    def score(self, action: AgentAction) -> RiskFinding:
        return RiskFinding(
            scorer=self.name, category="prompt_injection",
            risk_score=self._risk, matched=self._matched, detail="spy",
        )


class _Audit:
    async def append(self, action, decision) -> UUID:
        return uuid4()


def _action() -> AgentAction:
    return AgentAction(
        agent_id="agent-1", type=ActionType.tool_call, target="http_get",
        payload={"url": "https://api.example.com/x"}, identity_token="tok",
    )


def _evaluate(pipeline: Pipeline):
    return asyncio.run(pipeline.evaluate(_action()))


def _pipeline(policy, scorers=(), posture=None) -> Pipeline:
    return Pipeline(
        identity=_Identity(), policy=policy, scorers=list(scorers), audit=_Audit(),
        posture=posture if posture is not None else PostureMap(),
    )


def test_fired_principle_declared_side_effects_flow_onto_decision() -> None:
    policy = _Policy(
        matched=(MatchedPrinciple(principle_ref="4.1", effect="warn"),),
        meta={"4.1": {"title": "t", "effect": "warn", "side_effects": ["notify"]}},
    )
    decision = _evaluate(_pipeline(policy))
    assert decision.outcome is Outcome.warn
    assert SideEffect.notify in decision.side_effects


def test_matched_risk_finding_adds_risk_flag() -> None:
    policy = _Policy(matched=(), meta={})
    decision = _evaluate(_pipeline(policy, scorers=[_Scorer(0.2, ["spy_hit"])]))
    assert SideEffect.risk_flag in decision.side_effects


def test_allow_and_risk_flag_coexist_permit_and_escalate() -> None:
    """PIPE-09: one decision can PERMIT (allow) and ESCALATE (risk_flag)."""
    policy = _Policy(matched=(), meta={})
    decision = _evaluate(_pipeline(policy, scorers=[_Scorer(0.2, ["spy_hit"])]))
    assert decision.outcome is Outcome.allow
    assert decision.side_effects == [SideEffect.risk_flag]


def test_unmatched_risk_finding_adds_no_risk_flag() -> None:
    policy = _Policy(matched=(), meta={})
    decision = _evaluate(_pipeline(policy, scorers=[_Scorer(0.0, [])]))
    assert decision.side_effects == []


def test_side_effects_dedup_order_stable_and_bounded() -> None:
    """Two principles declaring overlapping effects + a matched finding: each
    effect appears once, in first-seen order, bounded by the enum size."""
    policy = _Policy(
        matched=(
            MatchedPrinciple(principle_ref="4.1", effect="warn"),
            MatchedPrinciple(principle_ref="4.2", effect="warn"),
        ),
        meta={
            "4.1": {"side_effects": ["notify", "risk_flag"]},
            "4.2": {"side_effects": ["notify", "additional_monitoring"]},
        },
    )
    decision = _evaluate(_pipeline(policy, scorers=[_Scorer(0.2, ["spy_hit"])]))
    assert decision.side_effects == [
        SideEffect.notify,
        SideEffect.risk_flag,            # declared once; the finding-derived one dedups
        SideEffect.additional_monitoring,
    ]
    assert len(decision.side_effects) == len(set(decision.side_effects))
    assert len(decision.side_effects) <= len(SideEffect)


def test_malformed_declared_side_effect_is_skipped_not_fatal() -> None:
    policy = _Policy(
        matched=(MatchedPrinciple(principle_ref="4.1", effect="warn"),),
        meta={"4.1": {"side_effects": ["notify", "not_a_side_effect"]}},
    )
    decision = _evaluate(_pipeline(policy))
    assert decision.side_effects == [SideEffect.notify]


def test_fail_open_fail_safe_carries_notify() -> None:
    posture = PostureMap(fail_open_types=frozenset({ActionType.tool_call}))
    decision = _evaluate(_pipeline(_RaisingPolicy(), posture=posture))
    assert decision.outcome is Outcome.allow  # explicitly-opened class
    assert SideEffect.notify in decision.side_effects


def test_fail_closed_fail_safe_has_no_notify() -> None:
    decision = _evaluate(_pipeline(_RaisingPolicy()))
    assert decision.outcome is Outcome.deny
    assert decision.side_effects == []


# --- 6b-3: dispatch — one audit event per effect + contained sink ---------------


@pytest.fixture
def store():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    return create_session_factory(engine)


class _ScriptedPipeline:
    def __init__(self, decision: Decision) -> None:
        self._decision = decision

    async def evaluate(self, action):
        return self._decision


class _RunSpy:
    def __init__(self) -> None:
        self.ran = 0

    async def __call__(self):
        self.ran += 1
        return "ran"


def _flagged_decision(action: AgentAction) -> Decision:
    return Decision(
        action_id=action.id,
        outcome=Outcome.allow,
        reasons=[Reason(stage="graduated", code="allow")],
        side_effects=[SideEffect.notify, SideEffect.risk_flag],
    )


def _side_effect_events(store) -> list[dict]:
    with store() as session:
        rows = session.scalars(select(AuditRecord).order_by(AuditRecord.seq))
        return [r.body for r in rows if r.body.get("kind") == "side_effect"]


def test_dispatch_writes_one_audit_event_per_effect(store) -> None:
    action = _action()
    dispatcher = AuditSideEffectDispatcher(AuditWriter(store))
    op = _RunSpy()
    result = asyncio.run(
        governed_call(
            _ScriptedPipeline(_flagged_decision(action)), action, op,
            dispatcher=dispatcher,
        )
    )
    assert result == "ran" and op.ran == 1  # permit AND escalate
    events = _side_effect_events(store)
    assert [e["effect"] for e in events] == ["notify", "risk_flag"]
    assert all(e["action_id"] == str(action.id) for e in events)
    assert all(e["agent_id"] == "agent-1" for e in events)


def test_dispatch_invokes_optional_sink_per_effect(store) -> None:
    action = _action()
    seen: list[SideEffect] = []
    dispatcher = AuditSideEffectDispatcher(
        AuditWriter(store), sink=lambda a, d, effect: seen.append(effect)
    )
    asyncio.run(
        governed_call(
            _ScriptedPipeline(_flagged_decision(action)), action, _RunSpy(),
            dispatcher=dispatcher,
        )
    )
    assert seen == [SideEffect.notify, SideEffect.risk_flag]


def test_raising_sink_is_contained_never_blocks_the_action(store, caplog) -> None:
    """A broken sink may not cost the caller anything: the result returns, the
    audit events are all written, the failure is logged — never raised."""
    action = _action()

    def bad_sink(a, d, effect):
        raise RuntimeError("sink down")

    dispatcher = AuditSideEffectDispatcher(AuditWriter(store), sink=bad_sink)
    op = _RunSpy()
    with caplog.at_level("WARNING"):
        result = asyncio.run(
            governed_call(
                _ScriptedPipeline(_flagged_decision(action)), action, op,
                dispatcher=dispatcher,
            )
        )
    assert result == "ran" and op.ran == 1          # never blocks the action result
    assert len(_side_effect_events(store)) == 2     # the events were still written
    assert any("side-effect sink failed" in r.message for r in caplog.records)


def test_no_side_effects_dispatches_nothing(store) -> None:
    action = _action()
    decision = Decision(action_id=action.id, outcome=Outcome.allow)
    dispatcher = AuditSideEffectDispatcher(AuditWriter(store))
    asyncio.run(
        governed_call(_ScriptedPipeline(decision), action, _RunSpy(), dispatcher=dispatcher)
    )
    assert _side_effect_events(store) == []
