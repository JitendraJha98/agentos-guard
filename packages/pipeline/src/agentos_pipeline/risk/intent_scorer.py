"""IntentScorer — the SEC-12 advisory intent-to-risk bridge (Slice 3).

Re-derives the deterministic intent tag via `enrichment.tag_intent` (stateless,
pure CPU — same closed vocabulary the policy floor sees) and contributes a small
ADVISORY finding: risk_score 0.15 when tagged, which can never reach the sandbox
band (0.4) alone. The authoritative response to dangerous intent is the
constitution principle conditioned on `intent.class` (e.g. 2.1 require_approval);
this scorer only corroborates in the risk stage.

Mirrors PromptInjectionScorer's RiskScorer interface exactly: inline=True,
`score(action) -> RiskFinding`; `matched` carries the intent class (a closed
vocabulary token, never raw payload).
"""

from agentos_contract import AgentAction, RiskFinding

from agentos_pipeline.enrichment import tag_intent

_TAGGED_RISK = 0.15  # advisory: < sandbox_at (0.4) by design


class IntentScorer:
    """Inline advisory scorer: deterministic intent tag -> small risk contribution."""

    name = "intent.v1"
    inline = True

    def score(self, action: AgentAction) -> RiskFinding:
        intent = tag_intent(action)
        return RiskFinding(
            scorer=self.name,
            category="intent",
            risk_score=_TAGGED_RISK if intent else 0.0,
            matched=[intent] if intent else [],
            detail=intent or "no intent tagged",
            inline=True,
        )
