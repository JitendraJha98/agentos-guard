"""Circuit breakers — table + store (RUN-06, Slice 9d, Tasks 1-2).

`circuit_breaker_state` holds the DURABLE state of one breaker, identified by the COMPOSITE key
(scope, agent_id, target) — three columns, never a concatenated string. A `f"{agent_id}|{target}"`
key let one breaker ALIAS another (a `team-a|http_get` agent id is the same string as the
(`team-a`, `http_get`) tool pair), which turned a self-service registration into a remote deny for a
victim agent; both directions are regression-tested below.

Only TRANSITIONS are persisted: the rolling-window counters live in memory because a window is a
recent-history view, not durable state. The immutable transition history rides the audit hash chain
via the new `circuit_tripped` / `circuit_reset` event kinds; the per-action deny is audited as a
DECISION record (stage 1f), NOT as a duplicate per-action event — the convention every other
post-identity deny gate follows.
"""

import asyncio

import pytest
from sqlalchemy import create_engine, select

from agentos_controlplane.audit import EVENT_KINDS, AuditWriter
from agentos_controlplane.audit_verify import verify_chain
from agentos_controlplane.circuit_breaker import CircuitBreakerStore
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import AuditRecord, CircuitBreakerState

_AGENT, _TOOL = "agent", "tool"


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
                scope="tool", agent_id="a", target="http_get",
                state="open", opened_at=1000.0, trip_count=1,
            )
        )
        s.commit()
    with store() as s:
        row = s.get(CircuitBreakerState, ("tool", "a", "http_get"))
    assert row.scope == "tool" and row.state == "open"
    # `opened_at` is epoch SECONDS (a float), not a DateTime: cooldown arithmetic is the only use,
    # and a plain epoch avoids naive/aware conversion bugs across the SQLite/Postgres split.
    assert row.opened_at == 1000.0
    assert row.trip_count == 1
    assert row.updated_at is not None  # server_default fires


def test_the_composite_key_cannot_alias_another_breaker(store) -> None:
    """The rows an f-string key would COLLIDE on are distinct rows here: an agent literally named
    "a|http_get" and the (a, http_get) tool pair share no primary key."""
    with store() as s:
        s.add(CircuitBreakerState(scope="tool", agent_id="a", target="http_get", state="open"))
        s.add(CircuitBreakerState(scope="agent", agent_id="a|http_get", target="", state="open"))
        s.commit()
    with store() as s:
        assert s.get(CircuitBreakerState, ("tool", "a", "http_get")) is not None
        assert s.get(CircuitBreakerState, ("agent", "a|http_get", "")) is not None


def test_trip_count_defaults_to_zero(store) -> None:
    with store() as s:
        s.add(CircuitBreakerState(scope="agent", agent_id="a", target="", state="closed"))
        s.commit()
    with store() as s:
        row = s.get(CircuitBreakerState, ("agent", "a", ""))
    assert row.trip_count == 0 and row.opened_at is None


def test_circuit_event_kinds_are_known(store) -> None:
    """The bodies name their discriminator `scope` and NOT `kind` — `kind` is a reserved chain field
    the writer computes itself, so a body carrying it is rejected fail-closed (the same shape as
    `privilege_ring_set`). `agent_id` and `target` are SEPARATE fields, so forensics can never
    misread which breaker moved."""
    assert "circuit_tripped" in EVENT_KINDS
    assert "circuit_reset" in EVENT_KINDS
    audit = AuditWriter(store)
    asyncio.run(
        audit.append_event(
            "circuit_tripped",
            {"scope": "agent", "agent_id": "a", "target": "", "observed": 3, "threshold": 3},
        )
    )
    asyncio.run(
        audit.append_event(
            "circuit_reset",
            {
                "scope": "agent", "agent_id": "a", "target": "",
                "reason": "operator_reset", "set_by": "op",
            },
        )
    )
    assert [b["agent_id"] for b in _events(store, "circuit_tripped")] == ["a"]
    assert [b["reason"] for b in _events(store, "circuit_reset")] == ["operator_reset"]
    assert verify_chain(store).ok


def test_unknown_event_kind_still_raises(store) -> None:
    audit = AuditWriter(store)
    with pytest.raises(ValueError):
        asyncio.run(audit.append_event("circuit_exploded", {"agent_id": "a"}))


# --- Task 2: the store — rolling window, trip, cooldown, close ---------------


@pytest.fixture
def clock():
    """An injectable wall clock: `clock[0]` is "now" in epoch seconds."""
    return [1000.0]


def _breaker(store, clock, **kw) -> CircuitBreakerStore:
    kw.setdefault("failure_threshold", 3)
    return CircuitBreakerStore(store, AuditWriter(store), now=lambda: clock[0], **kw)


def _row(store, scope: str, agent_id: str, target: str = "") -> CircuitBreakerState | None:
    with store() as s:
        return s.get(CircuitBreakerState, (scope, agent_id, target))


def _open_keys(cb: CircuitBreakerStore) -> list[tuple[str, str, str]]:
    return sorted((e["scope"], e["agent_id"], e["target"]) for e in cb.list_open())


def test_threshold_must_be_at_least_one(store) -> None:
    with pytest.raises(ValueError):
        CircuitBreakerStore(store, AuditWriter(store), failure_threshold=0)


def test_below_threshold_is_permitted(store, clock) -> None:
    cb = _breaker(store, clock)
    asyncio.run(cb.record_failure("a", "http_get"))
    asyncio.run(cb.record_failure("a", "http_get"))
    assert cb.status("a", "http_get") is None
    assert _row(store, _AGENT, "a") is None  # nothing durable until a transition happens


def test_threshold_failures_trip_the_breaker(store, clock) -> None:
    cb = _breaker(store, clock)
    for _ in range(3):
        asyncio.run(cb.record_failure("a", "http_get"))

    verdict = cb.status("a", "http_get")
    assert verdict is not None and verdict.state == "open"
    # The AGENT breaker is checked first (broader containment) — both scopes crossed the threshold.
    assert verdict.scope == "agent" and verdict.agent_id == "a" and verdict.target == ""
    # One event per tripped scope, and the durable rows agree with the hot path.
    tripped = _events(store, "circuit_tripped")
    assert {(b["scope"], b["agent_id"], b["target"]) for b in tripped} == {
        ("agent", "a", ""),
        ("tool", "a", "http_get"),
    }
    assert all(b["threshold"] == 3 and b["observed"] == 3 for b in tripped)
    agent_row = _row(store, _AGENT, "a")
    assert agent_row.state == "open" and agent_row.trip_count == 1
    assert _row(store, _TOOL, "a", "http_get").state == "open"
    assert _open_keys(cb) == [("agent", "a", ""), ("tool", "a", "http_get")]


def test_a_trip_is_per_agent(store, clock) -> None:
    """Per-agent isolation: one agent tripping its breaker must never contain another agent."""
    cb = _breaker(store, clock)
    for _ in range(3):
        asyncio.run(cb.record_failure("a", "http_get"))
    assert cb.status("a", "http_get") is not None
    assert cb.status("b", "http_get") is None


def test_a_TOOL_trip_cannot_ALIAS_a_victims_AGENT_breaker(store, clock) -> None:
    """CROSS-AGENT DoS, direction 1: agent ids are free-form and hierarchical names ("team|agent")
    are a natural convention. With an f-string key, `team-a`'s OWN (team-a, http_get) tool breaker
    was the SAME key as the agent breaker of an agent literally named `team-a|http_get` — so the
    prefix holder could deny that victim FLEET-WIDE on every target, needing only an
    attacker-chosen target string."""
    cb = _breaker(store, clock)
    for _ in range(3):
        asyncio.run(cb.record_failure("team-a", "http_get"))  # the ATTACKER's own violations

    assert cb.status("team-a", "http_get") is not None  # the attacker IS contained
    assert cb.status("team-a|http_get", "db_query") is None  # the victim is untouched
    assert cb.status("team-a|http_get", "http_get") is None


def test_an_AGENT_trip_cannot_ALIAS_a_victims_TOOL_breaker(store, clock) -> None:
    """CROSS-AGENT DoS, direction 2: an attacker who can self-register picks the id
    `victim-agent|http_get`; with an f-string key its OWN agent breaker tripping was the victim's
    (victim-agent, http_get) tool key — a remote, attacker-chosen tool denial for any victim."""
    cb = _breaker(store, clock)
    for _ in range(3):
        asyncio.run(cb.record_failure("victim-agent|http_get", "x"))

    assert cb.status("victim-agent|http_get", "x") is not None  # the attacker IS contained
    assert cb.status("victim-agent", "http_get") is None  # the victim keeps its tool


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


def test_an_UNRECORDED_trial_re_arms_the_breaker(store, clock) -> None:
    """The leak this closes: admitting a trial USED to be a one-way read-time mutation to HALF_OPEN,
    so a trial whose verdict is never recorded (a PIPE-05 fail-safe records NOTHING by design) left
    the breaker permanently disarmed — on a fail-open action class that is unlimited traffic during
    exactly the control-plane outage containment matters most. An admission now re-stamps the clock,
    so an unreported trial simply serves another cooldown."""
    cb = _breaker(store, clock, failure_threshold=2, cooldown_s=30.0)
    for _ in range(2):
        asyncio.run(cb.record_failure("a", "http_get"))
    clock[0] += 30.0
    assert cb.status("a", "http_get") is None  # the ONE admitted trial

    # No outcome recorded (the fail-safe path). The very next action must still be refused.
    verdict = cb.status("a", "http_get")
    assert verdict is not None and verdict.state == "half_open"
    clock[0] += 29.0
    assert cb.status("a", "http_get") is not None  # still inside the fresh cooldown
    clock[0] += 1.0
    assert cb.status("a", "http_get") is None  # another cooldown served -> another single trial


def test_at_most_ONE_admission_per_cooldown_window(store, clock) -> None:
    """HALF_OPEN must not admit a flood: a tripped agent regaining full throughput on every cooldown
    boundary is a containment control that stops containing."""
    cb = _breaker(store, clock, failure_threshold=2, cooldown_s=30.0)
    for _ in range(2):
        asyncio.run(cb.record_failure("a", "http_get"))
    clock[0] += 30.0

    admitted = sum(1 for _ in range(1000) if cb.status("a", "http_get") is None)
    assert admitted == 1


def test_a_failed_trial_reopens_immediately(store, clock) -> None:
    """HALF_OPEN is not a fresh window: ONE failure re-opens, without waiting for the threshold.
    `window_s` is deliberately SHORTER than the cooldown so the two pre-trip failures have aged out
    by the time the trial runs — otherwise the re-trip could ride the threshold branch and this
    assertion would have no teeth."""
    cb = _breaker(store, clock, failure_threshold=2, window_s=10.0, cooldown_s=30.0)
    for _ in range(2):
        asyncio.run(cb.record_failure("a", "http_get"))
    clock[0] += 30.0
    assert cb.status("a", "http_get") is None  # -> HALF_OPEN

    clock[0] += 1.0
    asyncio.run(cb.record_failure("a", "http_get"))
    assert len(cb._fails[(_AGENT, "a", "")]) == 1  # the pre-trip pair aged out: ONE failure re-opened
    verdict = cb.status("a", "http_get")
    assert verdict is not None and verdict.state == "open"
    assert _row(store, _AGENT, "a").trip_count == 2
    tripped = [b for b in _events(store, "circuit_tripped") if b["scope"] == "agent"]
    assert len(tripped) == 2


def test_a_successful_trial_closes_the_breaker(store, clock) -> None:
    cb = _breaker(store, clock, failure_threshold=2, cooldown_s=30.0)
    for _ in range(2):
        asyncio.run(cb.record_failure("a", "http_get"))
    clock[0] += 30.0
    assert cb.status("a", "http_get") is None  # -> HALF_OPEN

    asyncio.run(cb.record_success("a", "http_get"))
    assert cb.status("a", "http_get") is None
    assert cb.list_open() == []
    row = _row(store, _AGENT, "a")
    assert row.state == "closed" and row.opened_at is None
    reset = {(b["scope"], b["agent_id"], b["target"]): b["reason"] for b in _events(store, "circuit_reset")}
    assert reset == {
        ("agent", "a", ""): "trial_succeeded",
        ("tool", "a", "http_get"): "trial_succeeded",
    }


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

    asyncio.run(cb.reset(_AGENT, "a", set_by="op@x"))
    assert _row(store, _AGENT, "a").state == "closed"
    assert _open_keys(cb) == [("tool", "a", "http_get")]
    body = _events(store, "circuit_reset")[0]
    assert body == {
        **{k: body[k] for k in ("seq", "prev_hash", "kind")},
        "scope": "agent",
        "agent_id": "a",
        "target": "",
        "reason": "operator_reset",
        "set_by": "op@x",
    }


def test_operator_reset_takes_the_scope_EXPLICITLY(store, clock) -> None:
    """Scope is never INFERRED from the key's punctuation: an agent id containing `|` used to be
    audited as `scope="tool"`, corrupting the forensics of exactly the keys under attack."""
    cb = _breaker(store, clock)
    for _ in range(3):
        asyncio.run(cb.record_failure("team-a|agent-7", "http_get"))

    asyncio.run(cb.reset(_AGENT, "team-a|agent-7", set_by="op"))
    body = _events(store, "circuit_reset")[0]
    assert body["scope"] == "agent" and body["agent_id"] == "team-a|agent-7"
    assert body["target"] == ""
    assert cb.status("team-a|agent-7", "db_query") is None  # the agent breaker really cleared


def test_the_tool_pair_stays_contained_after_the_agent_breaker_clears(store, clock) -> None:
    """Tool scoping: the (agent, target) breaker is independent of the agent-wide one. Clearing the
    agent breaker leaves the poisoned TARGET contained, while every OTHER target is permitted."""
    cb = _breaker(store, clock)
    for _ in range(3):
        asyncio.run(cb.record_failure("a", "http_get"))
    asyncio.run(cb.reset(_AGENT, "a", set_by="op"))

    verdict = cb.status("a", "http_get")
    assert verdict is not None and verdict.scope == "tool"
    assert verdict.agent_id == "a" and verdict.target == "http_get"
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
    asyncio.run(cb.reset(_AGENT, "a", set_by="op"))
    asyncio.run(cb.reset(_TOOL, "a", "http_get", set_by="op"))

    fresh = _breaker(store, clock)
    assert fresh.list_open() == []
    assert fresh.status("a", "http_get") is None


def test_the_hot_path_never_reads_the_database(store, clock) -> None:
    """`status` is called on EVERY action: it must be an in-memory lookup. Proven by breaking the
    session factory after construction — a status check that touched the DB would raise. This is
    also why admitting a trial re-stamps the IN-MEMORY clock only: at worst a restart re-serves a
    cooldown from the persisted `opened_at`, which is the contained direction."""
    cb = _breaker(store, clock, cooldown_s=30.0)
    for _ in range(3):
        asyncio.run(cb.record_failure("a", "http_get"))

    def exploding_factory():
        raise AssertionError("status() must not open a session on the hot path")

    cb._sf = exploding_factory
    assert cb.status("a", "http_get") is not None
    assert cb.status("b", "http_get") is None
    clock[0] += 30.0
    assert cb.status("a", "http_get") is None  # admitting a trial stays in-memory too


def test_a_trip_CONTAINS_even_when_the_durable_write_FAILS(store, clock) -> None:
    """Fail-toward-contained on the ARMING direction (mirroring `KillSwitchStore._set`): the hot-path
    cache is set BEFORE the row is persisted, so a database outage cannot silently stop the breaker
    from containing in-process. The raised error is advisory telemetry to the caller — the pipeline
    swallows it rather than letting it rewrite an already-audited decision."""
    cb = _breaker(store, clock, failure_threshold=2)
    asyncio.run(cb.record_failure("a", "http_get"))

    def exploding_factory():
        raise RuntimeError("database down")

    cb._sf = exploding_factory
    with pytest.raises(RuntimeError):
        asyncio.run(cb.record_failure("a", "http_get"))  # crosses the threshold

    verdict = cb.status("a", "http_get")
    assert verdict is not None and verdict.state == "open"


def test_transitions_are_audited_without_any_payload(store, clock) -> None:
    cb = _breaker(store, clock, failure_threshold=2, cooldown_s=30.0)
    for _ in range(2):
        asyncio.run(cb.record_failure("a", "secret_tool"))
    clock[0] += 30.0
    cb.status("a", "secret_tool")
    asyncio.run(cb.record_success("a", "secret_tool"))

    allowed = {
        "seq", "prev_hash", "kind",  # chain fields the writer computes
        "scope", "agent_id", "target", "observed", "threshold", "reason", "set_by",
    }
    bodies = _events(store, "circuit_tripped") + _events(store, "circuit_reset")
    assert bodies, "transitions must be on the chain"
    for body in bodies:
        assert set(body) <= allowed, f"unexpected audit body key(s): {sorted(set(body) - allowed)}"
    assert verify_chain(store).ok
