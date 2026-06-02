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

from agentos_contract import Outcome

# Risk thresholds on a policy-ALLOWED action (the band, applied only above the floor).
_DENY_THRESHOLD = 0.7   # high risk on an allowed action -> block
_SANDBOX_THRESHOLD = 0.4  # mid risk -> sandbox vocabulary (enforcement is Phase 3)


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
