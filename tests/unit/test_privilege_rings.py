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
from agentos_controlplane.audit_verify import verify_chain
from agentos_controlplane.privilege import PrivilegeRingStore
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


# --- Task 2: PrivilegeRingStore ---------------------------------------------


@pytest.fixture
def rings(store) -> PrivilegeRingStore:
    return PrivilegeRingStore(store, AuditWriter(store))


def test_unregistered_target_is_permitted(rings: PrivilegeRingStore) -> None:
    """Registered-sensitivity model: an unregistered target is ring 0 — this stage does not gate
    it (it stays governed by the constitution floor)."""
    assert rings.check("a", "http_get") is None
    assert rings.required_ring("http_get") == 0


def test_registered_target_refuses_a_ring_zero_agent(rings: PrivilegeRingStore) -> None:
    asyncio.run(rings.set_target_ring("db_drop", 3, set_by="op"))
    verdict = rings.check("a", "db_drop")
    assert verdict is not None
    assert verdict.target == "db_drop" and verdict.required == 3 and verdict.held == 0


def test_equal_ring_passes_higher_passes_lower_refuses(rings: PrivilegeRingStore) -> None:
    asyncio.run(rings.set_target_ring("db_drop", 3, set_by="op"))

    asyncio.run(rings.set_agent_ring("a", 3, set_by="op"))
    assert rings.check("a", "db_drop") is None  # equal ring passes
    assert rings.ring_for("a") == 3

    asyncio.run(rings.set_agent_ring("a", 4, set_by="op"))
    assert rings.check("a", "db_drop") is None  # higher passes

    asyncio.run(rings.set_agent_ring("a", 2, set_by="op"))
    refused = rings.check("a", "db_drop")
    assert refused is not None and refused.held == 2  # lower refuses


def test_per_agent_tiering(rings: PrivilegeRingStore) -> None:
    """The ring is per agent: promoting one agent never promotes another."""
    asyncio.run(rings.set_target_ring("db_drop", 2, set_by="op"))
    asyncio.run(rings.set_agent_ring("a", 2, set_by="op"))
    assert rings.check("a", "db_drop") is None
    assert rings.check("b", "db_drop") is not None


def test_fresh_store_reloads_both_maps(store) -> None:
    """Durability: a new store over the same factory reloads agent AND target rings (_load)."""
    first = PrivilegeRingStore(store, AuditWriter(store))
    asyncio.run(first.set_target_ring("db_drop", 3, set_by="op"))
    asyncio.run(first.set_agent_ring("a", 3, set_by="op"))

    fresh = PrivilegeRingStore(store, AuditWriter(store))
    assert fresh.required_ring("db_drop") == 3
    assert fresh.ring_for("a") == 3
    assert fresh.check("a", "db_drop") is None
    assert fresh.check("b", "db_drop") is not None


def test_each_admin_call_is_audited_and_chain_verifies(store, rings: PrivilegeRingStore) -> None:
    asyncio.run(rings.set_target_ring("db_drop", 3, set_by="op"))
    asyncio.run(rings.set_agent_ring("a", 3, set_by="op"))
    bodies = _events(store, "privilege_ring_set")
    assert len(bodies) == 2
    assert {b["scope"] for b in bodies} == {"target", "agent"}
    assert verify_chain(store).ok


def test_negative_ring_rejected_and_changes_nothing(store, rings: PrivilegeRingStore) -> None:
    with pytest.raises(ValueError):
        asyncio.run(rings.set_agent_ring("a", -1, set_by="op"))
    with pytest.raises(ValueError):
        asyncio.run(rings.set_target_ring("db_drop", -1, set_by="op"))
    assert rings.ring_for("a") == 0 and rings.required_ring("db_drop") == 0
    assert rings.list_rings() == {"agents": {}, "targets": {}}
    with store() as s:
        assert s.get(AgentPrivilege, "a") is None
        assert s.get(TargetPrivilege, "db_drop") is None
    assert _events(store, "privilege_ring_set") == []


def test_durable_first_a_failed_persist_leaves_memory_unchanged(store) -> None:
    """Fail-toward-contained ordering (the Slice-4e lesson): the row is persisted+committed BEFORE
    the in-memory hot-path map is updated, so a failed commit can never leave the hot path
    believing a LOWER target requirement (or a HIGHER agent tier) than the table records."""
    rings = PrivilegeRingStore(store, AuditWriter(store))
    asyncio.run(rings.set_target_ring("db_drop", 3, set_by="op"))

    class _CommitRaises:
        """A session-factory whose session commits explode."""

        def __init__(self, inner):
            self._inner = inner

        def __call__(self):
            return self

        def __enter__(self):
            self._s = self._inner().__enter__()
            return _Sess(self._s)

        def __exit__(self, *exc):
            return False

    class _Sess:
        def __init__(self, s):
            self._s = s

        def __getattr__(self, name):
            return getattr(self._s, name)

        def commit(self):
            raise RuntimeError("durability failure")

    rings._sf = _CommitRaises(store)  # noqa: SLF001 — the point of the test
    with pytest.raises(RuntimeError):
        asyncio.run(rings.set_target_ring("db_drop", 1, set_by="op"))  # a RELAXATION

    # The hot path still enforces the DURABLE requirement, not the failed relaxation.
    assert rings.required_ring("db_drop") == 3
    assert rings.check("a", "db_drop") is not None
    # No audit event claimed a change that never landed.
    assert len(_events(store, "privilege_ring_set")) == 1


def test_list_rings_reports_both_maps(rings: PrivilegeRingStore) -> None:
    asyncio.run(rings.set_agent_ring("a", 2, set_by="op"))
    asyncio.run(rings.set_target_ring("db_drop", 3, set_by="op"))
    assert rings.list_rings() == {"agents": {"a": 2}, "targets": {"db_drop": 3}}
