"""Approval persistence (POL-07 / POL-13 / POL-14) — models + ApprovalStore.

6a-1: the three lifecycle tables (ApprovalRequest / TemporaryException /
GovernanceReview) round-trip on the SQLite Store (D-14). Status transitions are
deliberately NOT constrained at the DB layer — the ApprovalStore (6a-3) is the
single writer that constrains them, so the columns are plain strings here.

6a-3: the ApprovalStore — park (context redacted fail-closed via the AUDIT
redactor), resolve (single transition, 409-style on double-resolve, optional
human-ratified exception grant), store-awaited blocking (`wait_resolved` polls
the persisted row — never an in-process future, D3), read-time exception expiry
(auto-revoke, POL-13), and review open/close (POL-14). Lifecycle mutations
write events through the ONE audit hash chain.
"""

import asyncio
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, func, select

from agentos_contract import ActionType, AgentAction, Decision, Outcome, Reason
from agentos_controlplane.approvals import AlreadyResolvedError, ApprovalStore
from agentos_controlplane.audit import AuditWriter, RedactionError
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import (
    ApprovalRequest,
    AuditRecord,
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


# --- 6a-3: ApprovalStore -----------------------------------------------------------


@pytest.fixture
def approvals(store) -> ApprovalStore:
    return ApprovalStore(store, AuditWriter(store))


def _action(
    url: str = "https://api.example.com/data?token=SECRET",
    payload: dict | None = None,
) -> AgentAction:
    return AgentAction(
        agent_id="test-agent",
        type=ActionType.tool_call,
        target="http_get",
        payload=payload if payload is not None else {"url": url, "content": ""},
    )


def _decision(action: AgentAction, refs: tuple[str, ...] = ("1.1",)) -> Decision:
    return Decision(
        action_id=action.id,
        outcome=Outcome.require_approval,
        risk_score=0.2,
        trust_score=0.5,
        reasons=[
            Reason(
                stage="policy",
                code="constitution_principle_fired",
                principle_ref=ref,
                evidence={"effect": "deny"},
            )
            for ref in refs
        ],
    )


def _events(store, kind: str) -> list[dict]:
    with store() as session:
        rows = session.scalars(select(AuditRecord).order_by(AuditRecord.seq))
        return [r.body for r in rows if r.body.get("kind") == kind]


def test_create_redacts_context_through_audit_redactor(approvals, store) -> None:
    """The stored context goes through the SAME redactor the audit writer uses:
    a secret-bearing URL is host-only in the row (POL-07 'full context, redacted')."""
    action = _action(url="https://api.evil.example/path?token=SECRET")
    approval_id = approvals.create(action, _decision(action), deadline_s=60)
    with store() as session:
        row = session.get(ApprovalRequest, approval_id)
    assert row.status == "pending"
    assert row.context["url"] == "https://api.evil.example"
    assert "SECRET" not in str(row.context)
    assert row.agent_id == "test-agent" and row.action_type == "tool_call"
    assert row.reasons[0]["principle_ref"] == "1.1"
    assert row.deadline_at > datetime.now(timezone.utc).replace(tzinfo=None)


def test_create_unclassifiable_payload_fails_closed_no_row(approvals, store) -> None:
    action = _action(payload={"mystery_field": "raw secret material"})
    with pytest.raises(RedactionError):
        approvals.create(action, _decision(action), deadline_s=60)
    with store() as session:
        assert session.scalar(select(func.count()).select_from(ApprovalRequest)) == 0


def test_resolve_approve_updates_row_and_audits(approvals, store) -> None:
    action = _action()
    approval_id = approvals.create(action, _decision(action), deadline_s=60)
    row = asyncio.run(
        approvals.resolve(approval_id, approved=True, resolver="op@example.com", note="ok")
    )
    assert row.status == "approved"
    assert row.resolver == "op@example.com" and row.resolution_note == "ok"
    assert row.resolved_at is not None
    events = _events(store, "approval_resolved")
    assert len(events) == 1
    assert events[0]["approval_id"] == str(approval_id)
    assert events[0]["approved"] is True


def test_double_resolve_raises_already_resolved(approvals) -> None:
    action = _action()
    approval_id = approvals.create(action, _decision(action), deadline_s=60)
    asyncio.run(approvals.resolve(approval_id, approved=False, resolver="op"))
    with pytest.raises(AlreadyResolvedError):
        asyncio.run(approvals.resolve(approval_id, approved=True, resolver="op2"))


def test_resolve_unknown_id_raises_key_error(approvals) -> None:
    with pytest.raises(KeyError):
        asyncio.run(approvals.resolve(uuid4(), approved=True, resolver="op"))


def test_wait_resolved_returns_promptly_after_concurrent_resolve(approvals) -> None:
    """Store-awaited blocking (D3): a concurrent resolve is observed by POLLING
    the persisted row — wait returns ~0.3s in, far before the 5s deadline."""
    action = _action()
    approval_id = approvals.create(action, _decision(action), deadline_s=5)

    async def scenario():
        async def resolve_later():
            await asyncio.sleep(0.3)
            await approvals.resolve(approval_id, approved=True, resolver="op")

        resolver = asyncio.create_task(resolve_later())
        start = asyncio.get_running_loop().time()
        row = await approvals.wait_resolved(approval_id, deadline_s=5, poll_s=0.05)
        elapsed = asyncio.get_running_loop().time() - start
        await resolver
        return row, elapsed

    row, elapsed = asyncio.run(scenario())
    assert row is not None and row.status == "approved"
    assert elapsed < 2.0  # returned promptly, nowhere near the 5s deadline


def test_wait_resolved_timeout_marks_row_and_returns_none(approvals, store) -> None:
    action = _action()
    approval_id = approvals.create(action, _decision(action), deadline_s=0.2)
    row = asyncio.run(approvals.wait_resolved(approval_id, deadline_s=0.2, poll_s=0.05))
    assert row is None
    with store() as session:
        assert session.get(ApprovalRequest, approval_id).status == "timed_out"
    events = _events(store, "approval_timed_out")
    assert len(events) == 1 and events[0]["approval_id"] == str(approval_id)


def test_active_exceptions_read_time_expiry_and_revoked(approvals, store) -> None:
    """Auto-revoke = read-time expiry (POL-13): expired rows are simply absent
    from the lookup — no background job; `revoked` rows are absent too."""
    now = datetime.now(timezone.utc)
    with store() as session:
        session.add(
            TemporaryException(
                agent_id="test-agent", principle_ref="1.1", granted_by="op",
                expires_at=(now + timedelta(hours=1)).replace(tzinfo=None),
            )
        )
        session.add(  # EXPIRED -> absent (auto-revoke at read time)
            TemporaryException(
                agent_id="test-agent", principle_ref="2.1", granted_by="op",
                expires_at=(now - timedelta(seconds=1)).replace(tzinfo=None),
            )
        )
        session.add(  # REVOKED -> absent
            TemporaryException(
                agent_id="test-agent", principle_ref="3.2", granted_by="op",
                expires_at=(now + timedelta(hours=1)).replace(tzinfo=None),
                revoked=True,
            )
        )
        session.add(  # other agent -> absent (scope is (agent_id, principle_ref))
            TemporaryException(
                agent_id="other-agent", principle_ref="3.5", granted_by="op",
                expires_at=(now + timedelta(hours=1)).replace(tzinfo=None),
            )
        )
        session.commit()
    active = approvals.active_exceptions("test-agent", ("1.1", "2.1", "3.2", "3.5"))
    assert set(active) == {"1.1"}
    assert active["1.1"].tzinfo is not None  # returned tz-aware (contract needs it)
    assert active["1.1"] > now


def test_revoke_kills_an_active_exception(approvals, store) -> None:
    now = datetime.now(timezone.utc)
    with store() as session:
        exc_row = TemporaryException(
            agent_id="test-agent", principle_ref="1.1", granted_by="op",
            expires_at=(now + timedelta(hours=1)).replace(tzinfo=None),
        )
        session.add(exc_row)
        session.commit()
        exc_id = exc_row.id
    assert approvals.active_exceptions("test-agent", ("1.1",))
    approvals.revoke(exc_id)
    assert approvals.active_exceptions("test-agent", ("1.1",)) == {}


def test_resolve_with_grant_creates_exception_and_audits(approvals, store) -> None:
    """grant_exception_until on an APPROVE creates the (agent, ref) exception for
    each fired principle ref + an `exception_granted` event (human-only, POL-13)."""
    action = _action()
    approval_id = approvals.create(action, _decision(action, refs=("1.1",)), deadline_s=60)
    until = datetime.now(timezone.utc) + timedelta(hours=2)
    asyncio.run(
        approvals.resolve(
            approval_id, approved=True, resolver="op@example.com",
            grant_exception_until=until,
        )
    )
    with store() as session:
        exc = session.scalars(select(TemporaryException)).one()
        assert (exc.agent_id, exc.principle_ref) == ("test-agent", "1.1")
        assert exc.granted_by == "op@example.com"
        assert exc.approval_id == approval_id
        assert exc.revoked is False
    active = approvals.active_exceptions("test-agent", ("1.1",))
    assert abs((active["1.1"] - until).total_seconds()) < 1
    events = _events(store, "exception_granted")
    assert len(events) == 1
    assert events[0]["principle_ref"] == "1.1"
    assert events[0]["granted_by"] == "op@example.com"


def test_open_and_close_review(approvals, store) -> None:
    action = _action()
    review_id = asyncio.run(
        approvals.open_review(action.id, "test-agent", summary="risk-escalated")
    )
    with store() as session:
        row = session.get(GovernanceReview, review_id)
        assert row.status == "open" and row.summary == "risk-escalated"
    events = _events(store, "review_opened")
    assert len(events) == 1 and events[0]["review_id"] == str(review_id)
    approvals.close_review(review_id)
    with store() as session:
        row = session.get(GovernanceReview, review_id)
        assert row.status == "closed" and row.closed_at is not None


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
