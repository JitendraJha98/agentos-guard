"""SEC-03 — cheap-inline / expensive-flag-gated risk tiering.

The expensive tier (inline=False scorers) is a REAL seam, proven by a counting
stub (no fake model): expensive scorers run ONLY when the inline pass produced
at least one finding with non-empty `matched` — never unconditionally on the
hot path (Pitfall 1), and never at all by default (`expensive_scorers=()`).
"""

import asyncio
from uuid import uuid4

from agentos_contract import ActionType, AgentAction, Outcome, RiskFinding
from agentos_contract.policy_io import ConstitutionResult
from agentos_pipeline.risk import PiiScorer, assess_risk
from agentos_pipeline.runner import Pipeline


class CountingExpensiveScorer:
    """An inline=False stub that counts .score() calls and returns a 0.6 finding."""

    name = "expensive.v1"
    inline = False

    def __init__(self) -> None:
        self.calls = 0

    def score(self, action: AgentAction) -> RiskFinding:
        self.calls += 1
        return RiskFinding(
            scorer=self.name, category="unsafe_content", risk_score=0.6,
            matched=["expensive_hit"], detail="expensive tier", inline=False,
        )


def _tool(payload):
    return AgentAction(agent_id="a", type=ActionType.tool_call, target="http_post", payload=payload)


def test_benign_action_never_triggers_expensive_tier():
    expensive = CountingExpensiveScorer()
    risk, findings = assess_risk(
        _tool({"content": "the weather is nice"}), [PiiScorer()],
        expensive_scorers=[expensive],
    )
    assert expensive.calls == 0  # no inline flag -> the expensive tier never runs
    assert all(f.scorer != "expensive.v1" for f in findings)


def test_flagged_action_runs_expensive_tier_once_and_max_pools():
    expensive = CountingExpensiveScorer()
    risk, findings = assess_risk(
        _tool({"content": "mail jane.doe@example.com"}), [PiiScorer()],
        expensive_scorers=[expensive],
    )
    assert expensive.calls == 1  # gated in: exactly one expensive pass
    assert any(f.scorer == "expensive.v1" for f in findings)
    assert risk == 0.6  # the max-pool includes the expensive finding


def test_expensive_tier_never_runs_when_not_configured():
    # Default expensive_scorers=(): even a flagged action runs inline-only.
    risk, findings = assess_risk(
        _tool({"content": "mail jane.doe@example.com"}), [PiiScorer()]
    )
    assert [f.scorer for f in findings] == ["pii.v1"]
    assert risk == 0.35


def test_pipeline_passes_expensive_scorers_through():
    """The Pipeline seam: an enrichment-flagged (PII) action gates the expensive
    tier in via stage 4; the expensive finding restricts the outcome (0.6 ->
    sandbox band)."""

    class _OkIdentity:
        def verify(self, action):
            class V:
                ok = True
                trust_score = 0.5
                detail = ""
            return V()

    class _NoMatchPolicy:
        constitution_version = "sha256:stub"
        policy_version = "sha256:stub"
        principles_meta: dict = {}

        def evaluate(self, input: dict) -> ConstitutionResult:
            return ConstitutionResult(matched=(), no_match=True)

    class _FakeAudit:
        async def append(self, action, decision):
            return uuid4()

    expensive = CountingExpensiveScorer()
    pipeline = Pipeline(
        identity=_OkIdentity(), policy=_NoMatchPolicy(), scorers=[],
        audit=_FakeAudit(), expensive_scorers=[expensive],
    )
    action = _tool({"content": "mail jane.doe@example.com"})
    decision = asyncio.run(pipeline.evaluate(action))
    assert expensive.calls == 1
    assert decision.risk_score == 0.6
    assert decision.outcome is Outcome.sandbox
