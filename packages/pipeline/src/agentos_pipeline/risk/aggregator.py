"""assess_risk - the risk-stage aggregator (pipeline stage 3).

Source: 01-AI-SPEC.md S4. Runs ONLY inline=True scorers on the hot path, max-pools
their risk_score (most-severe wins), and performs NO I/O. Stateless and pure - no
accumulation across calls (statefulness would reintroduce flakiness into the D-04 CI
gate). The detector is advisory; the policy floor (plan 01-05) is authoritative.
"""

from agentos_contract import AgentAction, RiskFinding, RiskScorer


def assess_risk(
    action: AgentAction, scorers: list[RiskScorer]
) -> tuple[float, list[RiskFinding]]:
    """Run inline scorers, return (max risk_score, findings). No I/O."""
    findings = [s.score(action) for s in scorers if s.inline]  # sub-ms, deterministic
    risk_score = max((f.risk_score for f in findings), default=0.0)  # most-severe wins
    return risk_score, findings
