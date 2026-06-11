"""Audit body completeness (H3) — the hash must cover EVERY Decision field.

A Decision field that is neither persisted in the hashed body nor explicitly
excluded is an audit gap: it could change without the chain noticing. The
classification test fails CLOSED — adding a Decision field forces a conscious
choice here.
"""

import asyncio
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, select

from agentos_contract import ActionType, AgentAction, Decision, Outcome, Reason, SideEffect
from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import AuditRecord

_PERSISTED = {"action_id", "outcome", "risk_score", "trust_score", "reasons",
              "side_effects", "inferred_intent", "remediation",
              "constitution_version", "policy_version", "expires_at"}
_EXCLUDED = {"evidence_ref"}  # set after the write; not part of the hashed body


def test_every_decision_field_is_classified_for_audit():
    assert set(Decision.model_fields) == _PERSISTED | _EXCLUDED


@pytest.fixture
def audit_writer() -> AuditWriter:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    return AuditWriter(create_session_factory(engine))


def _body(audit_writer: AuditWriter) -> dict:
    with audit_writer.session_factory() as session:
        return session.scalars(select(AuditRecord)).first().body


def test_appended_body_carries_all_persisted_decision_fields(audit_writer: AuditWriter) -> None:
    action = AgentAction(
        agent_id="agent-1", type=ActionType.tool_call, target="http_get",
        payload={"url": "https://api.example.com/x"},
    )
    expires = datetime(2026, 6, 12, 9, 0, tzinfo=timezone.utc)
    decision = Decision(
        action_id=action.id,
        outcome=Outcome.temporary_exception,
        risk_score=0.3,
        trust_score=0.6,
        reasons=[Reason(stage="policy", code="ok")],
        side_effects=[SideEffect.notify, SideEffect.risk_flag],
        inferred_intent="DATA_READ",
        remediation=["Request approval via the dashboard"],
        constitution_version="sha256:abc",
        policy_version="sha256:def",
        expires_at=expires,
    )
    asyncio.run(audit_writer.append(action, decision))
    body = _body(audit_writer)
    assert body["side_effects"] == ["notify", "risk_flag"]
    assert body["inferred_intent"] == "DATA_READ"
    assert body["remediation"] == ["Request approval via the dashboard"]
    assert body["constitution_version"] == "sha256:abc"
    assert body["policy_version"] == "sha256:def"
    assert body["expires_at"] == expires.isoformat()


def test_appended_body_serializes_null_slice1_fields(audit_writer: AuditWriter) -> None:
    # The default (unpopulated) Decision still hash-covers the Slice-1 fields as nulls.
    action = AgentAction(
        agent_id="agent-1", type=ActionType.tool_call, target="http_get",
        payload={"url": "https://api.example.com/x"},
    )
    decision = Decision(action_id=action.id, outcome=Outcome.allow)
    asyncio.run(audit_writer.append(action, decision))
    body = _body(audit_writer)
    assert body["side_effects"] == []
    assert body["inferred_intent"] is None
    assert body["remediation"] == []
    assert body["constitution_version"] is None
    assert body["policy_version"] is None
    assert body["expires_at"] is None
