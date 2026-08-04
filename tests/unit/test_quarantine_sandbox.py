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
