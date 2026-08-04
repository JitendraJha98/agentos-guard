"""RUN-03 — the `sandbox_run` record + the concrete QuarantineSandbox runner (Slice 9a).

The AUD-04 secret-gate scans every audit body, so a containment event that carried the
action's payload could be REFUSED by the gate — meaning a sandbox outcome would fail to
audit. The event body therefore carries SHORT IDENTIFIERS ONLY; the redacted human detail
lives in the `sandbox_run` table. `SECRET-CANARY` proves both halves of that split.
"""

from __future__ import annotations

import asyncio

import pytest
from sqlalchemy import create_engine, select

from agentos_contract import ActionType, AgentAction, Decision, Outcome, Reason
from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.audit_verify import verify_chain
from agentos_controlplane.sandbox import QuarantineSandbox
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import AuditRecord, SandboxRun


@pytest.fixture
def store():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    return create_session_factory(engine)


def _action() -> AgentAction:
    return AgentAction(
        agent_id="quarantine-agent",
        type=ActionType.tool_call,
        target="http_post",
        payload={"url": "https://api.example.com/send", "content": "SECRET-CANARY"},
        identity_token="tok",
    )


def _decision(action: AgentAction) -> Decision:
    return Decision(
        action_id=action.id,
        outcome=Outcome.sandbox,
        reasons=[Reason(stage="graduated", code="sandbox")],
    )


def _events(store, kind: str) -> list[dict]:
    with store() as session:
        rows = session.scalars(select(AuditRecord).order_by(AuditRecord.seq))
        return [r.body for r in rows if r.body.get("kind") == kind]


# --- the record + the event kind ------------------------------------------------


def test_sandbox_run_row_round_trips(store) -> None:
    with store() as session:
        session.add(
            SandboxRun(
                action_id=_action().id,
                agent_id="a1",
                action_type="tool_call",
                target="http_post",
                detail="quarantined",
            )
        )
        session.commit()
    with store() as session:
        row = session.scalars(select(SandboxRun)).one()
        assert row.quarantined is True and row.agent_id == "a1"
        assert row.created_at is not None


def test_sandbox_executed_is_an_allowlisted_event_kind(store) -> None:
    audit = AuditWriter(store)
    asyncio.run(audit.append_event("sandbox_executed", {"action_id": "x"}))
    assert len(_events(store, "sandbox_executed")) == 1
    with pytest.raises(ValueError):
        asyncio.run(audit.append_event("sandbox_invented", {"action_id": "x"}))


# --- the runner ------------------------------------------------------------------


def test_quarantine_sandbox_persists_audits_and_keeps_the_payload_out(store) -> None:
    action = _action()
    decision = _decision(action)
    audit = AuditWriter(store)

    result = asyncio.run(QuarantineSandbox(store, audit).run(action, decision))

    assert result.quarantined is True and result.run_id
    assert "SECRET-CANARY" not in result.detail

    with store() as session:
        row = session.scalars(select(SandboxRun)).one()
    assert row.action_id == action.id
    assert row.agent_id == action.agent_id
    assert row.target == action.target
    assert row.quarantined is True
    # The redacted detail lives HERE — but still never the raw payload value.
    assert row.detail and "SECRET-CANARY" not in row.detail

    events = _events(store, "sandbox_executed")
    assert len(events) == 1
    body = events[0]
    assert body["action_id"] == str(action.id)
    assert body["agent_id"] == action.agent_id
    assert body["run_id"] == str(row.id)
    assert body["outcome"] == "sandbox"
    # Short identifiers ONLY: no target, no payload, no free-text detail — so the
    # AUD-04 secret gate can never refuse (and thereby block) a containment event.
    assert "target" not in body and "payload" not in body and "detail" not in body
    assert "SECRET-CANARY" not in str(body)

    assert verify_chain(store).ok  # the containment event rides the ONE chain
