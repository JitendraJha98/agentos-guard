"""Graduated-response stage (POL-06) — the floor-respecting {policy, risk, trust}
-> outcome map.

Source: 01-RESEARCH.md § "Trust & Graduated Response"; 01-AI-SPEC.md §4;
ADR-0005; CONTEXT.md D-11/D-13.

INVARIANT (POL-05/TRST-02 — the P0-killer the red-team gate proves):
risk and trust may only RESTRICT, never relax, the deterministic policy floor. A
policy `deny` is TERMINAL — no (risk, trust) combination can upgrade it. This is
checked explicitly by the `floor_invariant`-marked property sweep.

Phase-3 scope: the full graduated spectrum is mapped here — `GraduatedThresholds`
sets the policy-driven risk bands, the restrictiveness ladder orders all outcomes,
and a conservative (hardening-only) trust band lets low trust tighten one risk
step while trust never relaxes. The deterministic policy floor remains a strict
lower bound on the result.
"""

from __future__ import annotations

from dataclasses import dataclass

from agentos_contract import Outcome


@dataclass(frozen=True)
class GraduatedThresholds:
    """Policy-driven graduated thresholds (POL-06). Defaults preserve the Phase-1 risk
    bands (sandbox at 0.4, deny at 0.7) and realize the TRST-02 trust band as
    conservative hardening-only (low trust tightens; trust never relaxes risk)."""

    sandbox_at: float = 0.4
    deny_at: float = 0.7
    trust_harden_at: float = 0.2   # trust <= this -> tighten one risk step (TRST-02, conservative)

    def __post_init__(self) -> None:
        if not (0.0 <= self.sandbox_at <= self.deny_at <= 1.0):
            raise ValueError(
                "GraduatedThresholds require 0.0 <= sandbox_at <= deny_at <= 1.0, "
                f"got sandbox_at={self.sandbox_at}, deny_at={self.deny_at}"
            )
        if not (0.0 <= self.trust_harden_at <= 1.0):
            raise ValueError(
                f"GraduatedThresholds require 0.0 <= trust_harden_at <= 1.0, got {self.trust_harden_at}"
            )


# Restrictiveness ladder for the floor clamp (higher = more restrictive). The graduated
# stage NEVER returns a result less restrictive than the policy floor.
_RANK: dict[Outcome, int] = {
    Outcome.allow: 0,
    Outcome.warn: 1,
    Outcome.governance_review: 2,
    Outcome.temporary_exception: 2,
    Outcome.sandbox: 3,
    Outcome.require_consensus: 4,
    Outcome.require_approval: 5,
    Outcome.deny: 6,
}
# The subset risk alone can produce, ordered least->most restrictive (for trust stepping).
_RISK_LADDER = [Outcome.allow, Outcome.sandbox, Outcome.deny]


def _more_restrictive(a: Outcome, b: Outcome) -> Outcome:
    return a if _RANK[a] >= _RANK[b] else b


def _risk_to_outcome(risk_score: float, t: GraduatedThresholds) -> Outcome:
    if risk_score >= t.deny_at:
        return Outcome.deny
    if risk_score >= t.sandbox_at:
        return Outcome.sandbox
    return Outcome.allow


def _apply_trust_band(base: Outcome, trust: float, t: GraduatedThresholds) -> Outcome:
    """TRST-02: trust modulates WITHIN a band. Conservative default = hardening-only —
    low trust (<= trust_harden_at) tightens the risk outcome by one ladder step; trust
    NEVER relaxes (defends Pitfall 10 trust-farming) and never crosses the deny ceiling."""
    if trust <= t.trust_harden_at and base in _RISK_LADDER:
        i = _RISK_LADDER.index(base)
        return _RISK_LADDER[min(i + 1, len(_RISK_LADDER) - 1)]
    return base


def graduated_response(
    policy_outcome: Outcome,
    risk_score: float,
    trust: float,
    thresholds: GraduatedThresholds = GraduatedThresholds(),
) -> Outcome:
    """Map {policy, risk, trust} to one outcome, never relaxing the policy floor.

    INVARIANT (POL-05/TRST-02): the result is never LESS restrictive than
    `policy_outcome`; a policy `deny` is terminal; risk/trust may only RESTRICT.
    """
    if policy_outcome == Outcome.deny:
        return Outcome.deny  # terminal floor (POL-05)
    risk_outcome = _apply_trust_band(_risk_to_outcome(risk_score, thresholds), trust, thresholds)
    return _more_restrictive(policy_outcome, risk_outcome)
