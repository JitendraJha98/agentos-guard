"""KillSwitchStore — in-memory current state, table persistence, audited toggles
(RUN-01/02, Task 2).

The store keeps the active kills in memory (the hot-path lookup the pipeline's stage-0
check uses), backed by the `kill_switch` table for durability and reloaded at
construction (`_load`). Every kill/clear writes a `kill_switch_set`/`kill_switch_cleared`
event onto the audit hash chain — body = short identifiers only (target/scope/set_by),
NEVER the free-text reason.
"""

import asyncio

import pytest
from sqlalchemy import create_engine, select

from agentos_controlplane.audit import AuditWriter, canonical_json
from agentos_controlplane.killswitch import KillSwitchStore
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import AuditRecord, KillSwitch


@pytest.fixture
def store():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    return create_session_factory(engine)


@pytest.fixture
def ks(store) -> KillSwitchStore:
    return KillSwitchStore(store, AuditWriter(store))


def _events(store, kind: str) -> list[dict]:
    with store() as s:
        rows = s.scalars(select(AuditRecord).order_by(AuditRecord.seq))
        return [r.body for r in rows if r.body.get("kind") == kind]


def test_kill_agent_then_status(ks: KillSwitchStore) -> None:
    asyncio.run(ks.kill("agent-1", set_by="op@x", reason="rogue"))
    status = ks.status("agent-1")
    assert status is not None and status.scope == "agent" and status.reason == "rogue"
    assert ks.status("other-agent") is None  # only the targeted agent


def test_clear_agent_restores(ks: KillSwitchStore) -> None:
    asyncio.run(ks.kill("agent-1", set_by="op"))
    asyncio.run(ks.clear("agent-1", set_by="op"))
    assert ks.status("agent-1") is None


def test_fleet_kill_denies_any_agent(ks: KillSwitchStore) -> None:
    asyncio.run(ks.kill_fleet(set_by="op", reason="incident"))
    for agent_id in ("a", "b", "anything"):
        status = ks.status(agent_id)
        assert status is not None and status.scope == "fleet" and status.reason == "incident"


def test_clear_fleet_restores(ks: KillSwitchStore) -> None:
    asyncio.run(ks.kill_fleet(set_by="op"))
    asyncio.run(ks.clear_fleet(set_by="op"))
    assert ks.status("a") is None


def test_fleet_overrides_per_agent(ks: KillSwitchStore) -> None:
    """A fleet kill shadows everyone, even an agent that is not individually killed."""
    asyncio.run(ks.kill("agent-1", set_by="op", reason="agent-reason"))
    asyncio.run(ks.kill_fleet(set_by="op", reason="fleet-reason"))
    # fleet takes precedence in status()
    assert ks.status("agent-1").scope == "fleet"
    assert ks.status("agent-2").scope == "fleet"


def test_state_persists_to_table(ks: KillSwitchStore, store) -> None:
    asyncio.run(ks.kill("agent-1", set_by="op@x", reason="rogue"))
    with store() as s:
        row = s.get(KillSwitch, "agent-1")
    assert row.active is True and row.reason == "rogue" and row.set_by == "op@x"


def test_clear_marks_row_inactive(ks: KillSwitchStore, store) -> None:
    asyncio.run(ks.kill("agent-1", set_by="op"))
    asyncio.run(ks.clear("agent-1", set_by="op2"))
    with store() as s:
        row = s.get(KillSwitch, "agent-1")
    assert row.active is False and row.set_by == "op2"  # row kept, flipped inactive


def test_fresh_store_reloads_active_kills(store) -> None:
    """A new KillSwitchStore over the same factory reloads active kills from the table."""
    first = KillSwitchStore(store, AuditWriter(store))
    asyncio.run(first.kill("agent-1", set_by="op", reason="rogue"))
    asyncio.run(first.kill_fleet(set_by="op", reason="fleet"))
    asyncio.run(first.clear("agent-1", set_by="op"))  # cleared -> must NOT reload

    second = KillSwitchStore(store, AuditWriter(store))
    assert second.status("agent-1").scope == "fleet"  # only the fleet kill survived
    assert second.status("agent-1").reason == "fleet"
    asyncio.run(second.clear_fleet(set_by="op"))
    assert second.status("agent-1") is None


def test_list_active(ks: KillSwitchStore) -> None:
    asyncio.run(ks.kill("agent-1", set_by="op", reason="r1"))
    asyncio.run(ks.kill_fleet(set_by="op", reason="r2"))
    active = ks.list_active()
    targets = {a["target"]: a for a in active}
    assert targets["*"]["scope"] == "fleet"
    assert targets["agent-1"]["scope"] == "agent" and targets["agent-1"]["reason"] == "r1"


def test_each_toggle_writes_an_audit_event(ks: KillSwitchStore, store) -> None:
    asyncio.run(ks.kill("agent-1", set_by="op", reason="rogue"))
    asyncio.run(ks.clear("agent-1", set_by="op"))
    set_events = _events(store, "kill_switch_set")
    cleared_events = _events(store, "kill_switch_cleared")
    assert len(set_events) == 1 and set_events[0]["target"] == "agent-1"
    assert set_events[0]["scope"] == "agent" and set_events[0]["set_by"] == "op"
    assert len(cleared_events) == 1 and cleared_events[0]["target"] == "agent-1"


def test_event_body_excludes_free_text_reason(ks: KillSwitchStore, store) -> None:
    """The free-text reason lives in the TABLE only — never the event body (so the
    4d secret-gate on append_event can never block an emergency kill)."""
    secret_reason = "rotate sk-live-ABCDEF1234567890 immediately"
    asyncio.run(ks.kill("agent-1", set_by="op", reason=secret_reason))
    event = _events(store, "kill_switch_set")[0]
    assert "reason" not in event
    assert secret_reason not in canonical_json(event).decode("utf-8")


def test_chain_stays_continuous(ks: KillSwitchStore, store) -> None:
    asyncio.run(ks.kill("agent-1", set_by="op"))
    asyncio.run(ks.kill_fleet(set_by="op"))
    asyncio.run(ks.clear_fleet(set_by="op"))
    with store() as s:
        rows = list(s.scalars(select(AuditRecord).order_by(AuditRecord.seq)))
    assert [r.seq for r in rows] == [0, 1, 2]
    assert rows[0].prev_hash is None
    assert rows[1].prev_hash == rows[0].record_hash
    assert rows[2].prev_hash == rows[1].record_hash
