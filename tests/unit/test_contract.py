"""Contract package boundary tests (PIPE-07 / D-08).

Covers the <behavior> cases in 01-01-PLAN Task 2:
- AgentAction / Decision round-trip through JSON without loss
- both reject unknown fields at the serialization boundary (extra="forbid")
- score bounds are enforced
- RiskFinding rejects raw payload in `matched` and is frozen
"""

import pytest
from pydantic import ValidationError

from agentos_contract import (
    AgentAction,
    ActionType,
    Decision,
    Outcome,
    Reason,
    RiskFinding,
    SideEffect,
)


def test_agent_action_json_roundtrip():
    action = AgentAction(
        agent_id="agent-1",
        type=ActionType.tool_call,
        target="http_get",
        payload={"url": "https://api.example.com"},
    )
    restored = AgentAction.model_validate_json(action.model_dump_json())
    assert restored == action


def test_agent_action_rejects_unknown_field():
    with pytest.raises(ValidationError):
        AgentAction(
            agent_id="agent-1",
            type=ActionType.tool_call,
            target="http_get",
            payload={},
            surprise="boom",
        )


def test_decision_json_roundtrip_preserves_reasons():
    decision = Decision(
        action_id="11111111-1111-1111-1111-111111111111",
        outcome=Outcome.deny,
        reasons=[
            Reason(stage="policy", code="egress_allowlist_violation",
                   policy_id="egress.allow", detail="host not in allowlist"),
            Reason(stage="graduated", code="deny"),
        ],
    )
    restored = Decision.model_validate_json(decision.model_dump_json())
    assert restored == decision
    assert restored.reasons[0].stage == "policy"
    assert restored.reasons[0].code == "egress_allowlist_violation"
    assert restored.reasons[0].policy_id == "egress.allow"


def test_decision_rejects_out_of_range_risk_score():
    with pytest.raises(ValidationError):
        Decision(
            action_id="11111111-1111-1111-1111-111111111111",
            outcome=Outcome.allow,
            risk_score=1.5,
        )


def test_risk_finding_accepts_pattern_ids():
    finding = RiskFinding(
        scorer="prompt_injection.v1",
        category="prompt_injection",
        risk_score=0.7,
        matched=["instruction_override"],
    )
    assert finding.matched == ["instruction_override"]


def test_risk_finding_rejects_url_like_matched():
    with pytest.raises(ValueError):
        RiskFinding(
            scorer="prompt_injection.v1",
            category="prompt_injection",
            risk_score=0.7,
            matched=["https://attacker.example/x"],
        )


def test_risk_finding_rejects_long_matched():
    with pytest.raises(ValueError):
        RiskFinding(
            scorer="prompt_injection.v1",
            category="prompt_injection",
            risk_score=0.7,
            matched=["a" * 65],
        )


def test_risk_finding_is_frozen():
    finding = RiskFinding(
        scorer="prompt_injection.v1",
        category="prompt_injection",
        risk_score=0.4,
        matched=["instruction_override"],
    )
    with pytest.raises(ValidationError):
        finding.risk_score = 0.9


def test_outcome_has_full_phase3_spectrum():
    names = {o.value for o in Outcome}
    assert names == {
        "allow", "warn", "sandbox", "require_consensus",
        "require_approval", "temporary_exception", "governance_review", "deny",
    }


def test_side_effect_members():
    assert {s.value for s in SideEffect} == {
        "notify", "additional_monitoring", "risk_flag", "create_incident",
    }


def test_reason_carries_explainable_denial_fields():
    r = Reason(
        stage="policy", code="pii_egress_violation", detail="PII to non-allowlisted host",
        policy_id="constitution.3_2", principle_ref="3.2",
        rationale="Principle 3.2 forbids sending user PII to unapproved hosts.",
        evidence={"matched": "email_address", "host": "attacker.example"},
    )
    restored = Reason.model_validate_json(r.model_dump_json())
    assert restored == r
    assert restored.principle_ref == "3.2"
    assert restored.evidence == {"matched": "email_address", "host": "attacker.example"}
