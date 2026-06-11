"""Floor-respecting graduated_response — POL-06 + the POL-05/TRST-02 invariant.

Behavior (plan 01-05 Task 1):
  - FLOOR (floor_invariant): a policy `deny` is terminal. graduated_response(deny,
    risk=0.0, trust=1.0) == deny — even a risk of 0 and max trust CANNOT relax it.
  - property (floor_invariant): for ANY (risk in [0,1], trust in [0,1]),
    graduated_response(deny, risk, trust) == deny (parametrized sweep).
  - restrict: graduated_response(allow, risk=0.7, trust=anything) == deny (high risk
    on an allowed action blocks).
  - band: graduated_response(allow, risk=0.45, trust=0.5) == sandbox (vocabulary
    present; not enforced this phase — D-13).
  - pass: graduated_response(allow, risk=0.0, trust=0.9) == allow.

The floor invariant is the P0-killer the red-team gate (plan 01-06) proves: risk/trust
may only RESTRICT, never relax, the deterministic policy floor.
"""

from __future__ import annotations

import pytest

from agentos_contract import Outcome
from agentos_pipeline.graduated import graduated_response


@pytest.mark.floor_invariant
def test_floor_deny_is_terminal_even_at_zero_risk_max_trust() -> None:
    # A risk_score of 0 and maximum trust must NOT upgrade a policy deny.
    assert graduated_response(Outcome.deny, risk_score=0.0, trust=1.0) is Outcome.deny


@pytest.mark.floor_invariant
@pytest.mark.parametrize("risk", [0.0, 0.1, 0.39, 0.4, 0.6, 0.69, 0.7, 0.99, 1.0])
@pytest.mark.parametrize("trust", [0.0, 0.25, 0.5, 0.75, 1.0])
def test_floor_deny_never_upgraded_property_sweep(risk: float, trust: float) -> None:
    # For ANY (risk, trust), a policy deny stays deny (POL-05/TRST-02 invariant).
    assert graduated_response(Outcome.deny, risk_score=risk, trust=trust) is Outcome.deny


def test_high_risk_on_allowed_action_restricts_to_deny() -> None:
    # risk >= 0.7 on a policy-allowed action escalates DOWN the spectrum to deny.
    assert graduated_response(Outcome.allow, risk_score=0.7, trust=1.0) is Outcome.deny
    assert graduated_response(Outcome.allow, risk_score=0.95, trust=0.0) is Outcome.deny


def test_mid_risk_on_allowed_action_lands_in_sandbox_band() -> None:
    # 0.4 <= risk < 0.7 -> sandbox vocabulary (present; enforcement is Phase 3 — D-13).
    assert graduated_response(Outcome.allow, risk_score=0.45, trust=0.5) is Outcome.sandbox
    assert graduated_response(Outcome.allow, risk_score=0.4, trust=0.9) is Outcome.sandbox


def test_low_risk_on_allowed_action_stays_allow() -> None:
    assert graduated_response(Outcome.allow, risk_score=0.0, trust=0.9) is Outcome.allow
    assert graduated_response(Outcome.allow, risk_score=0.39, trust=1.0) is Outcome.allow


from agentos_pipeline.graduated import GraduatedThresholds, _more_restrictive, _risk_to_outcome


def test_risk_to_outcome_default_bands():
    t = GraduatedThresholds()
    assert _risk_to_outcome(0.0, t) is Outcome.allow
    assert _risk_to_outcome(0.39, t) is Outcome.allow
    assert _risk_to_outcome(0.4, t) is Outcome.sandbox
    assert _risk_to_outcome(0.69, t) is Outcome.sandbox
    assert _risk_to_outcome(0.7, t) is Outcome.deny


def test_more_restrictive_picks_higher_rank():
    assert _more_restrictive(Outcome.allow, Outcome.require_approval) is Outcome.require_approval
    assert _more_restrictive(Outcome.deny, Outcome.sandbox) is Outcome.deny
    assert _more_restrictive(Outcome.warn, Outcome.allow) is Outcome.warn


def test_low_trust_hardens_within_band():
    # trust <= 0.2 tightens the risk outcome one step; never below floor, never relaxes.
    assert graduated_response(Outcome.allow, risk_score=0.45, trust=0.1) is Outcome.deny     # sandbox -> deny
    assert graduated_response(Outcome.allow, risk_score=0.0, trust=0.1) is Outcome.sandbox   # allow -> sandbox


def test_high_trust_is_neutral_baseline():
    # high trust does NOT relax risk (conservative hardening-only band).
    assert graduated_response(Outcome.allow, risk_score=0.45, trust=1.0) is Outcome.sandbox
    assert graduated_response(Outcome.allow, risk_score=0.0, trust=1.0) is Outcome.allow


def test_policy_floor_is_a_lower_bound():
    # A principle effect of require_approval is never relaxed by low risk/high trust.
    assert graduated_response(Outcome.require_approval, risk_score=0.0, trust=1.0) is Outcome.require_approval
    # ...but risk can still escalate ABOVE the floor.
    assert graduated_response(Outcome.sandbox, risk_score=0.8, trust=1.0) is Outcome.deny
    assert graduated_response(Outcome.warn, risk_score=0.0, trust=1.0) is Outcome.warn
