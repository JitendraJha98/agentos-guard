"""Circuit breakers — table + store (RUN-06, Slice 9d, Tasks 1-2).

`circuit_breaker_state` holds the DURABLE state of one breaker (`key` is an agent_id, or
"agent_id|target"). Only TRANSITIONS are persisted: the rolling-window counters live in memory
because a window is a recent-history view, not durable state. The immutable transition history rides
the audit hash chain via the new `circuit_tripped` / `circuit_reset` event kinds; the per-action deny
is audited as a DECISION record (stage 1f), NOT as a duplicate per-action event — the convention
every other post-identity deny gate follows.
"""

import asyncio

import pytest
from sqlalchemy import create_engine, select

from agentos_controlplane.audit import EVENT_KINDS, AuditWriter
from agentos_controlplane.audit_verify import verify_chain
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import AuditRecord, CircuitBreakerState


@pytest.fixture
def store():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    return create_session_factory(engine)


def _events(store, kind: str) -> list[dict]:
    with store() as s:
        rows = s.scalars(select(AuditRecord).order_by(AuditRecord.seq))
        return [r.body for r in rows if r.body.get("kind") == kind]


# --- Task 1: the table + the event kinds -------------------------------------


def test_circuit_breaker_state_row_round_trips(store) -> None:
    with store() as s:
        s.add(
            CircuitBreakerState(
                key="a|http_get", scope="tool", state="open", opened_at=1000.0, trip_count=1
            )
        )
        s.commit()
    with store() as s:
        row = s.get(CircuitBreakerState, "a|http_get")
    assert row.scope == "tool" and row.state == "open"
    # `opened_at` is epoch SECONDS (a float), not a DateTime: cooldown arithmetic is the only use,
    # and a plain epoch avoids naive/aware conversion bugs across the SQLite/Postgres split.
    assert row.opened_at == 1000.0
    assert row.trip_count == 1
    assert row.updated_at is not None  # server_default fires


def test_trip_count_defaults_to_zero(store) -> None:
    with store() as s:
        s.add(CircuitBreakerState(key="a", scope="agent", state="closed"))
        s.commit()
    with store() as s:
        row = s.get(CircuitBreakerState, "a")
    assert row.trip_count == 0 and row.opened_at is None


def test_circuit_event_kinds_are_known(store) -> None:
    """The bodies name their discriminator `scope` and NOT `kind` — `kind` is a reserved chain field
    the writer computes itself, so a body carrying it is rejected fail-closed (the same shape as
    `privilege_ring_set`)."""
    assert "circuit_tripped" in EVENT_KINDS
    assert "circuit_reset" in EVENT_KINDS
    audit = AuditWriter(store)
    asyncio.run(
        audit.append_event(
            "circuit_tripped", {"key": "a", "scope": "agent", "observed": 3, "threshold": 3}
        )
    )
    asyncio.run(
        audit.append_event(
            "circuit_reset",
            {"key": "a", "scope": "agent", "reason": "operator_reset", "set_by": "op"},
        )
    )
    assert [b["key"] for b in _events(store, "circuit_tripped")] == ["a"]
    assert [b["reason"] for b in _events(store, "circuit_reset")] == ["operator_reset"]
    assert verify_chain(store).ok


def test_unknown_event_kind_still_raises(store) -> None:
    audit = AuditWriter(store)
    with pytest.raises(ValueError):
        asyncio.run(audit.append_event("circuit_exploded", {"key": "a"}))
