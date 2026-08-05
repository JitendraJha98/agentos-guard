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
from agentos_controlplane.circuit_breaker import CircuitBreakerStore
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


# --- Task 2: the store — rolling window, trip, cooldown, close ---------------


@pytest.fixture
def clock():
    """An injectable wall clock: `clock[0]` is "now" in epoch seconds."""
    return [1000.0]


def _breaker(store, clock, **kw) -> CircuitBreakerStore:
    kw.setdefault("failure_threshold", 3)
    return CircuitBreakerStore(store, AuditWriter(store), now=lambda: clock[0], **kw)


def _row(store, key: str) -> CircuitBreakerState | None:
    with store() as s:
        return s.get(CircuitBreakerState, key)


def test_threshold_must_be_at_least_one(store) -> None:
    with pytest.raises(ValueError):
        CircuitBreakerStore(store, AuditWriter(store), failure_threshold=0)


def test_below_threshold_is_permitted(store, clock) -> None:
    cb = _breaker(store, clock)
    asyncio.run(cb.record_failure("a", "http_get"))
    asyncio.run(cb.record_failure("a", "http_get"))
    assert cb.status("a", "http_get") is None
    assert _row(store, "a") is None  # nothing durable until a transition happens


def test_threshold_failures_trip_the_breaker(store, clock) -> None:
    cb = _breaker(store, clock)
    for _ in range(3):
        asyncio.run(cb.record_failure("a", "http_get"))

    verdict = cb.status("a", "http_get")
    assert verdict is not None and verdict.state == "open"
    # The AGENT breaker is checked first (broader containment) — both scopes crossed the threshold.
    assert verdict.scope == "agent" and verdict.key == "a"
    # One event per tripped scope, and the durable rows agree with the hot path.
    tripped = _events(store, "circuit_tripped")
    assert {b["key"]: b["scope"] for b in tripped} == {"a": "agent", "a|http_get": "tool"}
    assert all(b["threshold"] == 3 and b["observed"] == 3 for b in tripped)
    assert _row(store, "a").state == "open" and _row(store, "a").trip_count == 1
    assert _row(store, "a|http_get").state == "open"
    assert sorted(e["key"] for e in cb.list_open()) == ["a", "a|http_get"]


def test_a_trip_is_per_agent(store, clock) -> None:
    """Per-agent isolation: one agent tripping its breaker must never contain another agent."""
    cb = _breaker(store, clock)
    for _ in range(3):
        asyncio.run(cb.record_failure("a", "http_get"))
    assert cb.status("a", "http_get") is not None
    assert cb.status("b", "http_get") is None


def test_the_window_is_ROLLING_stale_failures_age_out(store, clock) -> None:
    """Two failures, then a gap longer than the window, then one more: the stale pair aged out, so
    the breaker must NOT trip. A cumulative counter would trip here — that is the bug this asserts."""
    cb = _breaker(store, clock, window_s=60.0)
    asyncio.run(cb.record_failure("a", "http_get"))
    asyncio.run(cb.record_failure("a", "http_get"))
    clock[0] += 61.0
    asyncio.run(cb.record_failure("a", "http_get"))
    assert cb.status("a", "http_get") is None
    assert _events(store, "circuit_tripped") == []


def test_cooldown_elapsing_admits_trials_half_open(store, clock) -> None:
    cb = _breaker(store, clock, failure_threshold=2, cooldown_s=30.0)
    for _ in range(2):
        asyncio.run(cb.record_failure("a", "http_get"))
    assert cb.status("a", "http_get") is not None  # still OPEN inside the cooldown

    clock[0] += 30.0
    assert cb.status("a", "http_get") is None  # cooldown elapsed -> HALF_OPEN admits a trial


def test_a_failed_trial_reopens_immediately(store, clock) -> None:
    """HALF_OPEN is not a fresh window: ONE failure re-opens, without waiting for the threshold."""
    cb = _breaker(store, clock, failure_threshold=2, cooldown_s=30.0)
    for _ in range(2):
        asyncio.run(cb.record_failure("a", "http_get"))
    clock[0] += 30.0
    assert cb.status("a", "http_get") is None  # -> HALF_OPEN

    clock[0] += 1.0
    asyncio.run(cb.record_failure("a", "http_get"))
    verdict = cb.status("a", "http_get")
    assert verdict is not None and verdict.state == "open"
    assert _row(store, "a").trip_count == 2
    assert len([b for b in _events(store, "circuit_tripped") if b["key"] == "a"]) == 2


def test_a_successful_trial_closes_the_breaker(store, clock) -> None:
    cb = _breaker(store, clock, failure_threshold=2, cooldown_s=30.0)
    for _ in range(2):
        asyncio.run(cb.record_failure("a", "http_get"))
    clock[0] += 30.0
    assert cb.status("a", "http_get") is None  # -> HALF_OPEN

    asyncio.run(cb.record_success("a", "http_get"))
    assert cb.status("a", "http_get") is None
    assert cb.list_open() == []
    assert _row(store, "a").state == "closed" and _row(store, "a").opened_at is None
    reasons = {b["key"]: b["reason"] for b in _events(store, "circuit_reset")}
    assert reasons == {"a": "trial_succeeded", "a|http_get": "trial_succeeded"}


def test_success_does_not_close_an_OPEN_breaker(store, clock) -> None:
    """Only a HALF_OPEN breaker closes on success — an OPEN one must serve its cooldown first,
    otherwise any unrelated allowed action would un-contain the agent instantly."""
    cb = _breaker(store, clock, failure_threshold=2, cooldown_s=30.0)
    for _ in range(2):
        asyncio.run(cb.record_failure("a", "http_get"))
    asyncio.run(cb.record_success("a", "http_get"))
    assert cb.status("a", "http_get") is not None
    assert _events(store, "circuit_reset") == []


def test_operator_reset_closes_an_open_breaker(store, clock) -> None:
    cb = _breaker(store, clock)
    for _ in range(3):
        asyncio.run(cb.record_failure("a", "http_get"))

    asyncio.run(cb.reset("a", set_by="op@x"))
    assert _row(store, "a").state == "closed"
    assert [b["key"] for b in cb.list_open()] == ["a|http_get"]
    body = _events(store, "circuit_reset")[0]
    assert body == {
        **{k: body[k] for k in ("seq", "prev_hash", "kind")},
        "key": "a",
        "scope": "agent",
        "reason": "operator_reset",
        "set_by": "op@x",
    }


def test_the_tool_pair_stays_contained_after_the_agent_breaker_clears(store, clock) -> None:
    """Tool scoping: the (agent, target) breaker is independent of the agent-wide one. Clearing the
    agent breaker leaves the poisoned TARGET contained, while every OTHER target is permitted."""
    cb = _breaker(store, clock)
    for _ in range(3):
        asyncio.run(cb.record_failure("a", "http_get"))
    asyncio.run(cb.reset("a", set_by="op"))

    verdict = cb.status("a", "http_get")
    assert verdict is not None and verdict.scope == "tool" and verdict.key == "a|http_get"
    assert cb.status("a", "db_query") is None  # a DIFFERENT target for the same agent


def test_an_open_breaker_survives_a_restart(store, clock) -> None:
    """A restart must not silently un-trip a breaker: a fresh store over the same tables reloads the
    OPEN state (and its `opened_at`, so the cooldown continues from the ORIGINAL trip)."""
    cb = _breaker(store, clock)
    for _ in range(3):
        asyncio.run(cb.record_failure("a", "http_get"))

    fresh = _breaker(store, clock, cooldown_s=30.0)
    assert fresh.status("a", "http_get") is not None
    clock[0] += 30.0
    assert fresh.status("a", "http_get") is None  # cooldown measured from the persisted opened_at


def test_a_closed_row_is_not_reloaded_as_containment(store, clock) -> None:
    cb = _breaker(store, clock)
    for _ in range(3):
        asyncio.run(cb.record_failure("a", "http_get"))
    asyncio.run(cb.reset("a", set_by="op"))
    asyncio.run(cb.reset("a|http_get", set_by="op"))

    fresh = _breaker(store, clock)
    assert fresh.list_open() == []
    assert fresh.status("a", "http_get") is None


def test_the_hot_path_never_reads_the_database(store, clock) -> None:
    """`status` is called on EVERY action: it must be an in-memory lookup. Proven by breaking the
    session factory after construction — a status check that touched the DB would raise."""
    cb = _breaker(store, clock)
    for _ in range(3):
        asyncio.run(cb.record_failure("a", "http_get"))

    def exploding_factory():
        raise AssertionError("status() must not open a session on the hot path")

    cb._sf = exploding_factory
    assert cb.status("a", "http_get") is not None
    assert cb.status("b", "http_get") is None


def test_transitions_are_audited_without_any_payload(store, clock) -> None:
    cb = _breaker(store, clock, failure_threshold=2, cooldown_s=30.0)
    for _ in range(2):
        asyncio.run(cb.record_failure("a", "secret_tool"))
    clock[0] += 30.0
    cb.status("a", "secret_tool")
    asyncio.run(cb.record_success("a", "secret_tool"))

    allowed = {
        "seq", "prev_hash", "kind",  # chain fields the writer computes
        "key", "scope", "observed", "threshold", "reason", "set_by",
    }
    bodies = _events(store, "circuit_tripped") + _events(store, "circuit_reset")
    assert bodies, "transitions must be on the chain"
    for body in bodies:
        assert set(body) <= allowed, f"unexpected audit body key(s): {sorted(set(body) - allowed)}"
    assert verify_chain(store).ok
