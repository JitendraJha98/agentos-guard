"""assess_risk - the risk-stage aggregator (pipeline stage 4).

Source: 01-AI-SPEC.md S4. Runs ONLY inline=True scorers on the hot path, max-pools
their risk_score (most-severe wins), and performs NO I/O. Stateless and pure - no
accumulation across calls (statefulness would reintroduce flakiness into the D-04 CI
gate). The detector is advisory; the policy floor (plan 01-05) is authoritative.

`extra_findings` carries findings produced earlier in the pipeline (the Slice-4
guardrail scorers run ONCE in enrich(); their findings are merged here, never
re-run) — the max-pool is over the union.

SEC-03 tiering: `expensive_scorers` (inline=False) run ONLY when the inline
pass — including the carried extra_findings — produced at least one finding
with non-empty `matched`. Expensive detectors fire on inline flags, never
unconditionally on the hot path (Pitfall 1).
"""

from typing import Sequence

from agentos_contract import AgentAction, RiskFinding, RiskScorer


def assess_risk(
    action: AgentAction,
    scorers: list[RiskScorer],
    extra_findings: tuple[RiskFinding, ...] = (),
    expensive_scorers: Sequence[RiskScorer] = (),
) -> tuple[float, list[RiskFinding]]:
    """Run inline scorers, merge `extra_findings`, gate the expensive tier on
    inline flags (SEC-03), return (max risk_score, findings). No model I/O on
    the unflagged path."""
    findings = [s.score(action) for s in scorers if s.inline]  # sub-ms, deterministic
    findings += list(extra_findings)  # carried guardrail findings — not re-run
    if any(f.matched for f in findings):  # SEC-03: expensive tier only on a flag
        findings += [s.score(action) for s in expensive_scorers if not s.inline]
    risk_score = max((f.risk_score for f in findings), default=0.0)  # most-severe wins
    return risk_score, findings
