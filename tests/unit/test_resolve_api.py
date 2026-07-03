"""The minimal operator resolve API (API-03) — FastAPI router over the ApprovalStore.

GET /approvals?status= lists requests; POST /approvals/{id}/resolve transitions
one (404 unknown, 409 already-resolved) and may grant a temporary exception
(POL-13, human-only); GET /reviews?status= lists reviews. The API holds no state
of its own — it is just another writer against the persisted rows (D3), which is
exactly why blocking waits resolve across processes.
"""

from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.pool import StaticPool

from agentos_contract import ActionType, AgentAction, Decision, Outcome, Reason
from agentos_controlplane.api import create_app
from agentos_controlplane.approvals import ApprovalStore
from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import AuditRecord, TemporaryException


@pytest.fixture
def store():
    # TestClient drives async endpoints from a portal THREAD; a per-connection
    # in-memory SQLite would give that thread an empty database. StaticPool +
    # check_same_thread=False shares the ONE in-memory connection across threads.
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    create_all(engine)
    return create_session_factory(engine)


@pytest.fixture
def approvals(store) -> ApprovalStore:
    return ApprovalStore(store, AuditWriter(store))


@pytest.fixture
def client(approvals) -> TestClient:
    c = TestClient(create_app(approvals, api_token="test-token"))
    c.headers["Authorization"] = "Bearer test-token"
    return c


def _park(approvals: ApprovalStore) -> UUID:
    action = AgentAction(
        agent_id="test-agent",
        type=ActionType.tool_call,
        target="drop_table",
        payload={"url": "https://api.example.com/x", "content": ""},
    )
    decision = Decision(
        action_id=action.id,
        outcome=Outcome.require_approval,
        reasons=[
            Reason(
                stage="policy",
                code="constitution_principle_fired",
                principle_ref="2.1",
                evidence={"effect": "require_approval"},
            )
        ],
    )
    return approvals.create(action, decision, deadline_s=300)


def _events(store, kind: str) -> list[dict]:
    with store() as session:
        rows = session.scalars(select(AuditRecord).order_by(AuditRecord.seq))
        return [r.body for r in rows if r.body.get("kind") == kind]


def test_list_pending_approvals(client, approvals) -> None:
    approval_id = _park(approvals)
    resp = client.get("/approvals", params={"status": "pending"})
    assert resp.status_code == 200
    rows = resp.json()
    assert len(rows) == 1
    assert rows[0]["id"] == str(approval_id)
    assert rows[0]["status"] == "pending"
    assert rows[0]["agent_id"] == "test-agent"
    assert rows[0]["target"] == "drop_table"


def test_resolve_approve_updates_row_and_audits(client, approvals, store) -> None:
    approval_id = _park(approvals)
    resp = client.post(
        f"/approvals/{approval_id}/resolve",
        json={"approved": True, "resolver": "op@example.com"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "approved"
    assert body["resolver"] == "op@example.com"
    assert approvals.get(approval_id).status == "approved"
    events = _events(store, "approval_resolved")
    assert len(events) == 1 and events[0]["approved"] is True


def test_double_resolve_conflicts_409(client, approvals) -> None:
    approval_id = _park(approvals)
    first = client.post(
        f"/approvals/{approval_id}/resolve",
        json={"approved": True, "resolver": "op"},
    )
    assert first.status_code == 200
    second = client.post(
        f"/approvals/{approval_id}/resolve",
        json={"approved": False, "resolver": "op2"},
    )
    assert second.status_code == 409


def test_resolve_unknown_id_404(client) -> None:
    resp = client.post(
        f"/approvals/{uuid4()}/resolve",
        json={"approved": True, "resolver": "op"},
    )
    assert resp.status_code == 404


def test_resolve_deny_with_note(client, approvals) -> None:
    approval_id = _park(approvals)
    resp = client.post(
        f"/approvals/{approval_id}/resolve",
        json={"approved": False, "resolver": "op", "note": "too risky today"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "denied"
    assert body["resolution_note"] == "too risky today"


def test_resolve_bounds_operator_inputs(client, approvals) -> None:
    """Operator inputs are bounded: resolver > 128 or note > 512 chars -> 422."""
    approval_id = _park(approvals)
    resp = client.post(
        f"/approvals/{approval_id}/resolve",
        json={"approved": True, "resolver": "x" * 200},
    )
    assert resp.status_code == 422
    resp = client.post(
        f"/approvals/{approval_id}/resolve",
        json={"approved": True, "resolver": "op", "note": "n" * 513},
    )
    assert resp.status_code == 422
    assert approvals.get(approval_id).status == "pending"  # nothing resolved


def test_resolve_with_exception_expires_at_grants_exception(
    client, approvals, store
) -> None:
    approval_id = _park(approvals)
    until = datetime.now(timezone.utc) + timedelta(hours=4)
    resp = client.post(
        f"/approvals/{approval_id}/resolve",
        json={
            "approved": True,
            "resolver": "op@example.com",
            "exception_expires_at": until.isoformat(),
        },
    )
    assert resp.status_code == 200
    with store() as session:
        exc = session.scalars(select(TemporaryException)).one()
        assert (exc.agent_id, exc.principle_ref) == ("test-agent", "2.1")
        assert exc.approval_id == approval_id
    assert approvals.active_exceptions("test-agent", ("2.1",))
    assert len(_events(store, "exception_granted")) == 1


def test_list_reviews(client, approvals) -> None:
    import asyncio

    review_id = asyncio.run(
        approvals.open_review(uuid4(), "test-agent", summary="async review")
    )
    resp = client.get("/reviews", params={"status": "open"})
    assert resp.status_code == 200
    rows = resp.json()
    assert len(rows) == 1
    assert rows[0]["id"] == str(review_id)
    assert rows[0]["status"] == "open" and rows[0]["summary"] == "async review"
