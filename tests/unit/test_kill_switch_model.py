"""KillSwitch table + the two kill-switch audit event kinds (RUN-01/02, Task 1).

The `kill_switch` table holds the CURRENT operator-halt state (target -> active +
reason + set_by); the immutable history of toggles lives on the audit hash chain via
the new `kill_switch_set` / `kill_switch_cleared` event kinds. The free-text reason
lives ONLY in the table, never in the event body — so the 4d secret-gate on
`append_event` can never block an emergency kill.
"""

import asyncio

import pytest
from sqlalchemy import create_engine, func, select

from agentos_controlplane.audit import EVENT_KINDS, AuditWriter
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import AuditRecord, KillSwitch


@pytest.fixture
def store():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    return create_session_factory(engine)


def test_kill_switch_row_round_trips(store) -> None:
    with store() as s:
        s.add(KillSwitch(target="agent-1", active=True, reason="rogue", set_by="op@x"))
        s.add(KillSwitch(target="*", active=True, reason="incident", set_by="op@x"))
        s.commit()
    with store() as s:
        agent = s.get(KillSwitch, "agent-1")
        fleet = s.get(KillSwitch, "*")
    assert agent.active is True and agent.reason == "rogue" and agent.set_by == "op@x"
    assert fleet.target == "*" and fleet.active is True
    assert agent.updated_at is not None  # server_default fires


def test_kill_switch_active_defaults_false(store) -> None:
    with store() as s:
        s.add(KillSwitch(target="agent-2"))
        s.commit()
    with store() as s:
        assert s.get(KillSwitch, "agent-2").active is False


def test_new_event_kinds_registered() -> None:
    assert "kill_switch_set" in EVENT_KINDS
    assert "kill_switch_cleared" in EVENT_KINDS


@pytest.mark.parametrize("kind", ["kill_switch_set", "kill_switch_cleared"])
def test_kill_event_kinds_accepted_by_append_event(store, kind: str) -> None:
    writer = AuditWriter(store)
    asyncio.run(
        writer.append_event(kind, {"target": "agent-1", "scope": "agent", "set_by": "op"})
    )
    with store() as s:
        row = s.scalars(select(AuditRecord).order_by(AuditRecord.seq.desc()).limit(1)).first()
    assert row.body["kind"] == kind
    assert row.body["target"] == "agent-1"


def test_unknown_kind_still_raises(store) -> None:
    writer = AuditWriter(store)
    with pytest.raises(ValueError):
        asyncio.run(writer.append_event("kill_switch_invented", {"target": "a"}))
    with store() as s:
        assert s.scalar(select(func.count()).select_from(AuditRecord)) == 0
