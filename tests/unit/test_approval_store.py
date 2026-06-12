"""Approval persistence (POL-07 / POL-13 / POL-14) — models + ApprovalStore.

6a-1: the three lifecycle tables (ApprovalRequest / TemporaryException /
GovernanceReview) round-trip on the SQLite Store (D-14). Status transitions are
deliberately NOT constrained at the DB layer — the ApprovalStore (6a-3) is the
single writer that constrains them, so the columns are plain strings here.
"""

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, select

from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import (
    ApprovalRequest,
    GovernanceReview,
    TemporaryException,
)


@pytest.fixture
def store():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    return create_session_factory(engine)


def test_approval_request_round_trips(store) -> None:
    row_id, action_id = uuid4(), uuid4()
    deadline = datetime(2026, 6, 12, 12, 0, 0)
    with store() as session:
        session.add(
            ApprovalRequest(
                id=row_id,
                action_id=action_id,
                agent_id="test-agent",
                action_type="tool_call",
                target="http_get",
                context={"url": "https://api.example.com"},
                reasons=[{"stage": "policy", "code": "constitution_principle_fired"}],
                risk_score=0.3,
                trust_score=0.5,
                status="pending",
                deadline_at=deadline,
            )
        )
        session.commit()
    with store() as session:
        row = session.get(ApprovalRequest, row_id)
        assert row is not None
        assert row.action_id == action_id
        assert row.agent_id == "test-agent"
        assert row.action_type == "tool_call"
        assert row.target == "http_get"
        assert row.context == {"url": "https://api.example.com"}
        assert row.reasons[0]["code"] == "constitution_principle_fired"
        assert row.risk_score == 0.3 and row.trust_score == 0.5
        assert row.status == "pending"
        assert row.deadline_at == deadline
        assert row.created_at is not None
        # Unresolved: the resolution columns are NULL until the store resolves.
        assert row.resolved_at is None and row.resolver is None
        assert row.resolution_note is None


def test_temporary_exception_round_trips(store) -> None:
    row_id, approval_id = uuid4(), uuid4()
    expires = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(hours=1)
    with store() as session:
        session.add(
            TemporaryException(
                id=row_id,
                agent_id="test-agent",
                principle_ref="1.1",
                granted_by="operator@example.com",
                approval_id=approval_id,
                expires_at=expires,
            )
        )
        session.commit()
    with store() as session:
        row = session.get(TemporaryException, row_id)
        assert row is not None
        assert (row.agent_id, row.principle_ref) == ("test-agent", "1.1")
        assert row.granted_by == "operator@example.com"
        assert row.approval_id == approval_id
        assert row.expires_at == expires
        assert row.revoked is False  # default: active until expiry or revoke
        assert row.created_at is not None


def test_governance_review_round_trips(store) -> None:
    row_id, action_id = uuid4(), uuid4()
    with store() as session:
        session.add(
            GovernanceReview(
                id=row_id,
                action_id=action_id,
                agent_id="test-agent",
                summary="risk-escalated review",
                status="open",
            )
        )
        session.commit()
    with store() as session:
        row = session.get(GovernanceReview, row_id)
        assert row is not None
        assert row.action_id == action_id
        assert row.summary == "risk-escalated review"
        assert row.status == "open"
        assert row.opened_at is not None and row.closed_at is None


def test_status_not_constrained_at_db_layer(store) -> None:
    """The DB accepts any status string — the ApprovalStore (6a-3) is the single
    writer that constrains transitions (pending -> approved|denied|timed_out)."""
    with store() as session:
        session.add(
            ApprovalRequest(
                id=uuid4(),
                action_id=uuid4(),
                agent_id="a",
                action_type="tool_call",
                target="t",
                context={},
                reasons=[],
                risk_score=0.0,
                trust_score=0.0,
                status="not-a-real-status",
                deadline_at=datetime(2026, 1, 1),
            )
        )
        session.commit()
    with store() as session:
        assert (
            session.scalars(select(ApprovalRequest)).first().status
            == "not-a-real-status"
        )
