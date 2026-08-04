"""Privilege-ring tables + the administrative audit event kind (RUN-04, Slice 9b, Task 1).

`agent_privilege` holds the capability tier an agent HOLDS; `target_privilege` holds the ring a
sensitive TARGET REQUIRES. Registered-sensitivity model: only rows in `target_privilege` are gated —
an unregistered target is ring 0 and stays governed by the constitution floor.

The immutable history of administrative assignments lives on the audit hash chain via the new
`privilege_ring_set` event kind. The per-action deny is audited as a DECISION record (carrying its
`privilege`/`insufficient_ring` reason), NOT as a duplicate per-action event — the convention every
other post-identity deny gate (1b/1c/1d) follows.
"""

import asyncio

import pytest
from sqlalchemy import create_engine, select

from agentos_controlplane.audit import EVENT_KINDS, AuditWriter
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import AgentPrivilege, AuditRecord, TargetPrivilege


@pytest.fixture
def store():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    return create_session_factory(engine)


def _events(store, kind: str) -> list[dict]:
    with store() as s:
        rows = s.scalars(select(AuditRecord).order_by(AuditRecord.seq))
        return [r.body for r in rows if r.body.get("kind") == kind]


def test_agent_privilege_row_round_trips(store) -> None:
    with store() as s:
        s.add(AgentPrivilege(agent_id="a", ring=2, set_by="op@x"))
        s.commit()
    with store() as s:
        row = s.get(AgentPrivilege, "a")
    assert row.ring == 2 and row.set_by == "op@x"
    assert row.updated_at is not None  # server_default fires


def test_target_privilege_row_round_trips(store) -> None:
    with store() as s:
        s.add(TargetPrivilege(target="db_drop", required_ring=3, set_by="op@x"))
        s.commit()
    with store() as s:
        row = s.get(TargetPrivilege, "db_drop")
    assert row.required_ring == 3 and row.set_by == "op@x"
    assert row.updated_at is not None


def test_rings_default_to_zero(store) -> None:
    """Absent/unset means ring 0 — least privileged agent, ungated target."""
    with store() as s:
        s.add(AgentPrivilege(agent_id="b"))
        s.add(TargetPrivilege(target="http_get"))
        s.commit()
    with store() as s:
        assert s.get(AgentPrivilege, "b").ring == 0
        assert s.get(TargetPrivilege, "http_get").required_ring == 0


def test_privilege_ring_set_is_a_known_event_kind(store) -> None:
    """The body uses `scope` (agent|target), NOT `kind` — `kind` is a reserved chain field the
    writer computes itself, so a body carrying it is rejected fail-closed (same shape as
    `kill_switch_set`, which also names its discriminator `scope`)."""
    assert "privilege_ring_set" in EVENT_KINDS
    audit = AuditWriter(store)
    asyncio.run(
        audit.append_event(
            "privilege_ring_set", {"scope": "target", "key": "db_drop", "ring": 3, "set_by": "op"}
        )
    )
    bodies = _events(store, "privilege_ring_set")
    assert len(bodies) == 1 and bodies[0]["key"] == "db_drop" and bodies[0]["ring"] == 3


def test_unknown_event_kind_still_rejected(store) -> None:
    audit = AuditWriter(store)
    with pytest.raises(ValueError):
        asyncio.run(audit.append_event("privilege_denied", {"key": "db_drop"}))
