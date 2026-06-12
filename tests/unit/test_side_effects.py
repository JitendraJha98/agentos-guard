"""Side-effect derivation — the PIPE-09 producers (6b-1).

Side effects are composable, outcome-ORTHOGONAL escalations: fired principles'
authored `side_effects` (via principles_meta) flow onto the Decision (dedup,
order-stable); any risk finding with non-empty `matched` adds `risk_flag`; a
fail-open fail-safe carries `notify`. One decision can permit AND escalate
(allow + risk_flag) — that is the whole point of keeping them orthogonal.
"""

from __future__ import annotations

import asyncio
from uuid import UUID, uuid4

from agentos_contract import ActionType, AgentAction, Outcome, RiskFinding, SideEffect
from agentos_contract.policy_io import ConstitutionResult, MatchedPrinciple
from agentos_pipeline.posture import PostureMap
from agentos_pipeline.runner import Pipeline


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
