"""Contract package boundary tests (PIPE-07 / D-08).

Covers the <behavior> cases in 01-01-PLAN Task 2:
- AgentAction / Decision round-trip through JSON without loss
- both reject unknown fields at the serialization boundary (extra="forbid")
- score bounds are enforced
- RiskFinding rejects raw payload in `matched` and is frozen
"""

from datetime import datetime, timezone

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
            Reason(stage="policy", code="constitution_principle_fired",
                   policy_id="constitution.1.1", principle_ref="1.1",
                   detail="host not in allowlist"),
            Reason(stage="graduated", code="deny"),
        ],
    )
    restored = Decision.model_validate_json(decision.model_dump_json())
    assert restored == decision
    assert restored.reasons[0].stage == "policy"
    assert restored.reasons[0].code == "constitution_principle_fired"
    assert restored.reasons[0].policy_id == "constitution.1.1"


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


def test_decision_full_phase3_shape_roundtrip():
    d = Decision(
        action_id="11111111-1111-1111-1111-111111111111",
        outcome=Outcome.temporary_exception,
        side_effects=[SideEffect.notify, SideEffect.additional_monitoring],
        inferred_intent="DATA_DESTRUCTION",
        remediation=["Request approval via the dashboard", "Narrow the tool scope"],
        constitution_version="sha256:abc",
        policy_version="sha256:def",
        expires_at=datetime(2026, 6, 11, 12, 0, tzinfo=timezone.utc),
    )
    restored = Decision.model_validate_json(d.model_dump_json())
    assert restored == d
    assert restored.side_effects == [SideEffect.notify, SideEffect.additional_monitoring]
    assert restored.inferred_intent == "DATA_DESTRUCTION"


def test_decision_defaults_are_empty_and_still_forbid_unknown():
    d = Decision(action_id="11111111-1111-1111-1111-111111111111", outcome=Outcome.allow)
    assert d.side_effects == [] and d.remediation == []
    assert d.inferred_intent is None and d.policy_version is None and d.expires_at is None
    with pytest.raises(ValidationError):
        Decision(action_id="11111111-1111-1111-1111-111111111111", outcome=Outcome.allow, mystery=1)


def test_reason_small_evidence_roundtrips():
    r = Reason(stage="risk", code="pii_egress", evidence={"matched": "email_address", "host": "api.example.com"})
    assert Reason.model_validate_json(r.model_dump_json()) == r


def test_reason_rejects_oversized_evidence():
    # evidence flows into the un-redactable, hash-covered audit log (T-01-02).
    with pytest.raises(ValidationError):
        Reason(stage="risk", code="pii_egress", evidence={"payload": "a" * 2000})


def test_reason_rejects_long_rationale():
    with pytest.raises(ValidationError):
        Reason(stage="policy", code="x", rationale="a" * 600)


def test_reason_rejects_unknown_field():
    with pytest.raises(ValidationError):
        Reason(stage="x", code="y", bogus=1)


# --- H2: evidence must be JSON-native and URL-free (audit hash safety) ---------


def test_reason_rejects_non_json_native_evidence():
    # A UUID validates under a lenient default=str measure but CRASHES the audit
    # writer's strict canonical_json at hash time — reject at the contract.
    from uuid import uuid4

    with pytest.raises(ValidationError):
        Reason(stage="risk", code="x", evidence={"id": uuid4()})


def test_reason_rejects_url_in_evidence_value():
    # Full URLs carry query-string secrets; host-only is the audit convention.
    with pytest.raises(ValidationError):
        Reason(stage="risk", code="x", evidence={"u": "https://x.example/p?k=s"})


def test_reason_rejects_url_in_nested_evidence():
    with pytest.raises(ValidationError):
        Reason(stage="risk", code="x", evidence={"a": {"b": "http://x"}})


def test_reason_plain_small_evidence_still_ok():
    r = Reason(stage="risk", code="x", evidence={"host": "api.example.com", "n": 3})
    assert r.evidence == {"host": "api.example.com", "n": 3}


# --- H6: bounds on audit-bound Decision/Reason fields --------------------------


def test_reason_rejects_long_detail():
    with pytest.raises(ValidationError):
        Reason(stage="policy", code="x", detail="a" * 513)


def test_decision_rejects_long_inferred_intent():
    with pytest.raises(ValidationError):
        Decision(
            action_id="11111111-1111-1111-1111-111111111111",
            outcome=Outcome.allow,
            inferred_intent="a" * 65,
        )


def test_decision_rejects_too_many_remediation_items():
    with pytest.raises(ValidationError):
        Decision(
            action_id="11111111-1111-1111-1111-111111111111",
            outcome=Outcome.allow,
            remediation=[f"step {i}" for i in range(11)],
        )


def test_decision_rejects_oversized_remediation_item():
    with pytest.raises(ValidationError):
        Decision(
            action_id="11111111-1111-1111-1111-111111111111",
            outcome=Outcome.allow,
            remediation=["a" * 257],
        )


def test_decision_rejects_tz_naive_expires_at():
    with pytest.raises(ValidationError):
        Decision(
            action_id="11111111-1111-1111-1111-111111111111",
            outcome=Outcome.allow,
            expires_at=datetime(2026, 6, 11, 12, 0),  # naive — no tzinfo
        )


def test_decision_accepts_tz_aware_expires_at():
    d = Decision(
        action_id="11111111-1111-1111-1111-111111111111",
        outcome=Outcome.allow,
        expires_at=datetime(2026, 6, 11, 12, 0, tzinfo=timezone.utc),
    )
    assert d.expires_at.tzinfo is not None
