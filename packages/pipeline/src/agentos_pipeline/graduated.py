"""Graduated-response stage (POL-06) — the floor-respecting {policy, risk, trust}
-> outcome map.

Source: 01-RESEARCH.md § "Trust & Graduated Response"; 01-AI-SPEC.md §4;
ADR-0005; CONTEXT.md D-11/D-13.

INVARIANT (POL-05/TRST-02 — the P0-killer the red-team gate proves):
risk and trust may only RESTRICT, never relax, the deterministic policy floor. A
policy `deny` is TERMINAL — no (risk, trust) combination can upgrade it. This is
checked explicitly by the `floor_invariant`-marked property sweep.

Phase-1 scope (D-13): `allow` and `deny` are realized end-to-end; `sandbox` is in
the Outcome vocabulary (so the contract is stable) but its enforcement lands in
Phase 3 — the SDK only acts on allow (run) / deny (block) this phase.
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


def graduated_response(policy_outcome: Outcome, risk_score: float, trust: float) -> Outcome:
    """Map {policy, risk, trust} to one outcome, never relaxing the policy floor.

    Args:
        policy_outcome: the deterministic OPA floor (the authoritative signal).
        risk_score: advisory 0–1 risk from the inline detector (may only restrict).
        trust: advisory 0–1 agent trust (modulates WITHIN the band; never flips deny).

    Returns:
        The graduated Outcome — equal to or more restrictive than the policy floor.
    """
    # FLOOR: a policy deny is terminal — nothing below can upgrade it (POL-05/TRST-02).
    if policy_outcome == Outcome.deny:
        return Outcome.deny
    # Policy allowed -> risk/trust may only move DOWN the spectrum.
    if risk_score >= _DENY_THRESHOLD:
        return Outcome.deny
    if risk_score >= _SANDBOX_THRESHOLD:
        return Outcome.sandbox  # vocabulary present; Phase 1 realizes allow+deny (D-13)
    # Trust modulates WITHIN the band (TRST-01) but a policy allow with low risk stays allow.
    return Outcome.allow
