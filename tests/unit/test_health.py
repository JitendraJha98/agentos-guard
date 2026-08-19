"""OBS-04 — agent health: liveness, error rate and circuit-breaker state (Slice 12d).

Two numbers here are easy to get wrong in the direction that HURTS, and both are pinned by test.

Liveness (spec D-5): an agent with nothing to do is byte-identical in the audit log to one that
crashed, so `last_seen_at` is reported as a FACT and the output carries no verdict key at all. A
module that asserted "down" would page someone at 3am about a healthy nightly batch job, and the
lesson learned would be to ignore this page.

The error rate (spec D-6): a `deny` is the system WORKING. Counting denials as errors makes the
best-governed agent in a fleet — the one attracting the most correctly-blocked attempts — look like
the sickest, and the fix an operator reaches for to make that chart green is to loosen the guard.
"""

from __future__ import annotations

import asyncio
import inspect
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, update
from sqlalchemy.pool import StaticPool

from agentos_contract import ActionType, AgentAction, Decision, Outcome, Reason
from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.health import (
    _BLOCKED_OUTCOMES,
    _EXECUTED_OUTCOMES,
    AgentHealth,
    HealthStore,
)
from agentos_controlplane.shadow import OVERFLOW_ID
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import AuditRecord

# What the real pipeline appends once — and only once — the identity stage vouched for the caller
# (runner.py). Health counts these records ONLY, for the same reason the DISC-06 graph draws from
# these records only: `agent_id` on an unregistered caller is attacker-chosen (DISC-04).
VERIFIED = [Reason(stage="identity", code="identity_verified", detail="ok")]
FORGED = [Reason(stage="identity", code="forged_identity", detail="unknown agent")]

_PAYLOAD = {"url": "https://x.example.com/", "content": ""}


@pytest.fixture
def store():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    create_all(engine)
    return create_session_factory(engine)


@pytest.fixture
def audit(store) -> AuditWriter:
    """ONE writer over the store — a second instance caches a stale chain head."""
    return AuditWriter(store)


class _Breakers:
    """The slice of `CircuitBreakerStore` health reads: `list_open()` and nothing else."""

    def __init__(self, rows=()) -> None:
        self._rows = list(rows)

    def list_open(self) -> list[dict]:
        return list(self._rows)


def act(audit: AuditWriter, agent_id: str, outcome=Outcome.allow, *, reasons=None) -> None:
    """Append ONE real decision record through the real writer."""
    action = AgentAction(
        agent_id=agent_id,
        type=ActionType.tool_call,
        target="http_get",
        payload=dict(_PAYLOAD),
    )
    asyncio.run(
        audit.append(
            action,
            Decision(
                action_id=action.id,
                outcome=outcome,
                risk_score=0.0,
                trust_score=0.5,
                reasons=list(VERIFIED if reasons is None else reasons),
            ),
        )
    )


def seed(audit: AuditWriter, agent_id: str, outcomes) -> None:
    for outcome in outcomes:
        act(audit, agent_id, Outcome(outcome))


def age_everything(store, delta: timedelta) -> None:
    """Push every audit record back in time, so a window has something to exclude."""
    with store() as s:
        s.execute(
            update(AuditRecord).values(
                created_at=datetime.now(timezone.utc).replace(tzinfo=None) - delta
            )
        )
        s.commit()


# --------------------------------------------------------------- liveness is a fact, not a verdict


def test_liveness_is_a_timestamp_not_a_verdict(store, audit) -> None:
    """SPEC D-5. An agent with nothing to do is byte-identical to one that crashed, and only the
    operator knows which they have. A module that asserted "down" would page someone at 3am for a
    healthy nightly job."""
    seed(audit, "a1", ["allow"])

    health = HealthStore(store).for_agent("a1")

    assert health["last_seen_at"] is not None
    assert not any(k in health for k in ("alive", "up", "down", "healthy", "status"))


def test_no_row_anywhere_carries_a_verdict_key(store, audit) -> None:
    """Structural, over the FLEET read too — the surface a dashboard iterates. The temptation to add
    a `status` is exactly what would turn a healthy nightly agent into a 3am page."""
    seed(audit, "a1", ["allow", "deny"])

    for row in HealthStore(store).fleet():
        assert not any(k in row for k in ("alive", "up", "down", "healthy", "status", "state"))


def test_a_never_seen_agent_reports_null_last_seen_not_an_old_timestamp(store) -> None:
    """None means "we have no record of this agent acting", which is a different statement from a
    stale timestamp — and a different statement again from "it is down", which this never makes."""
    health = HealthStore(store).for_agent("never-heard-of-it")

    assert health["last_seen_at"] is None
    assert health["actions"] == 0


def test_the_window_travels_with_the_null_so_it_can_be_read(store, audit) -> None:
    """A null `last_seen_at` means "not within the window we examined". That is only honest if the
    window is stated beside it — and widening `hours` is then a real lever an operator can pull to
    tell "idle for a week" apart from "never seen"."""
    seed(audit, "a1", ["allow"])
    age_everything(store, timedelta(days=7))

    narrow = HealthStore(store).for_agent("a1", window=timedelta(hours=1))
    wide = HealthStore(store).for_agent("a1", window=timedelta(days=30))

    assert narrow["last_seen_at"] is None and narrow["window_hours"] == pytest.approx(1.0)
    assert wide["last_seen_at"] is not None and wide["window_hours"] == pytest.approx(720.0)


# ------------------------------------------------------------------ a governance deny is not an error


def test_a_DENY_is_not_counted_as_an_error(store, audit) -> None:
    """THE property of this slice. A deny is the system working. Counting it as an error makes the
    best-governed agent in a fleet look like the sickest, and the fix an operator reaches for is to
    loosen the guard."""
    seed(audit, "a1", ["allow", "deny", "deny", "deny"])

    health = HealthStore(store).for_agent("a1")

    assert health["blocked"] == 3 and health["executed"] == 1
    assert health["execution_failure_rate"] in (None, 0.0)
    assert health["execution_failure_rate"] != 0.75, "denials must not read as a 75% error rate"


def test_every_blocking_outcome_is_counted_as_blocked_not_as_an_error(store, audit) -> None:
    """`sandbox`, `require_approval` and `require_consensus` are the same statement as `deny`: the
    control plane stopped the action. An approval-shaped workload must not read as a broken one."""
    seed(audit, "a1", ["sandbox", "require_approval", "require_consensus", "allow"])

    health = HealthStore(store).for_agent("a1")

    assert health["blocked"] == 3 and health["executed"] == 1


def test_the_error_rate_denominator_is_EXECUTED_actions() -> None:
    """An action the control plane refused never reached the code that could fail, so it does not
    belong in the denominator either. 1 failure out of 4 executed is 25%, never 10%."""
    row = AgentHealth(
        agent_id="a1",
        window_hours=24.0,
        last_seen_at=None,
        actions=10,
        executed=4,
        blocked=6,
        resource_limit_breaches=1,
        breakers_open=0,
        execution_failures=1,
    )

    assert row.execution_failure_rate == pytest.approx(0.25)


def test_an_agent_that_executed_nothing_has_a_null_rate_not_zero() -> None:
    """0.0 is the claim "everything that ran, ran fine". An agent that ran nothing has not made it —
    the same absent-is-not-zero rule ECON-01 established for an unpriced model."""
    row = AgentHealth(
        agent_id="a1",
        window_hours=24.0,
        last_seen_at=None,
        actions=3,
        executed=0,
        blocked=3,
        resource_limit_breaches=0,
        breakers_open=0,
        execution_failures=0,
    )

    assert row.execution_failure_rate is None


def test_the_two_outcome_sets_partition_the_contract(store, audit) -> None:
    """Every `Outcome` must land in exactly one of the two counts. An outcome in neither would go
    uncounted the day it is added, and one in both would be counted twice."""
    assert _EXECUTED_OUTCOMES | _BLOCKED_OUTCOMES == {o.value for o in Outcome}
    assert not _EXECUTED_OUTCOMES & _BLOCKED_OUTCOMES


def test_the_execution_failure_count_is_null_because_the_log_does_not_carry_it(store, audit) -> None:
    """The honest answer, and the field exists SO THAT it can be given. A tool that simply raised is
    reported to the RUN-06 breaker and audited nowhere, so no total is recoverable — and dropping the
    field would leave a dashboard free to substitute the denial count, which is the D-6 inversion."""
    seed(audit, "a1", ["allow", "allow"])

    health = HealthStore(store).for_agent("a1")

    assert "execution_failures" in health and health["execution_failures"] is None
    assert health["execution_failure_rate"] is None


def test_the_one_audited_execution_failure_class_is_counted_under_its_own_name(store, audit) -> None:
    """RUN-05 budget breaches are the only EXECUTION failures on the chain. Counted, and named for
    exactly what they are — calling a lower bound `execution_failures` would be the same lie as
    calling denials errors, one field across."""
    seed(audit, "a1", ["allow", "allow"])
    asyncio.run(
        audit.append_event(
            "resource_limit_exceeded",
            {"action_id": "x", "agent_id": "a1", "action_type": "tool_call",
             "limit": "wall_s", "budget": 1.0, "observed": 9.0},
        )
    )

    health = HealthStore(store).for_agent("a1")

    assert health["resource_limit_breaches"] == 1
    assert health["executed"] == 2, "an event record is not an action"
    assert health["actions"] == 2


# ------------------------------------------------------------------------------- breakers, window, bounds


def test_breaker_state_is_reported_per_agent(store, audit) -> None:
    """OBS-04 names circuit-breaker state explicitly, and it is the one health signal that is already
    a verdict the system itself made — so it is reported as one."""
    seed(audit, "a1", ["allow"])
    seed(audit, "a2", ["allow"])
    breakers = _Breakers(
        [
            {"scope": "agent", "agent_id": "a1", "target": "", "state": "open", "opened_at": 1.0},
            {"scope": "tool", "agent_id": "a1", "target": "http_get", "state": "open",
             "opened_at": 1.0},
        ]
    )

    by_agent = {r["agent_id"]: r for r in HealthStore(store, breakers=breakers).fleet()}

    assert by_agent["a1"]["breakers_open"] == 2
    assert by_agent["a2"]["breakers_open"] == 0


def test_a_contained_agent_appears_even_with_no_activity_in_the_window(store) -> None:
    """The most health-relevant agent in a fleet is the one that has been cut off, and an OPEN
    breaker denies — so containment itself makes the agent quiet. Reading only the audit log would
    drop exactly the row an operator opened this page for."""
    breakers = _Breakers(
        [{"scope": "agent", "agent_id": "contained", "target": "", "state": "open",
          "opened_at": 1.0}]
    )

    rows = {r["agent_id"]: r for r in HealthStore(store, breakers=breakers).fleet()}

    assert rows["contained"]["breakers_open"] == 1
    assert rows["contained"]["last_seen_at"] is None
    assert rows["contained"]["actions"] == 0


def test_a_contained_agent_keeps_its_row_on_a_fleet_that_fills_the_budget(store, audit) -> None:
    """The cap is spent in SCAN ORDER, and containment is what makes an agent quiet — so on a busy
    fleet the contained agent is precisely the one the budget never reaches. It has to claim its slot
    BEFORE the scan, or the page reports nothing contained during the incident it exists for."""
    for i in range(8):
        seed(audit, f"noisy{i}", ["allow"])
    breakers = _Breakers(
        [{"scope": "agent", "agent_id": "contained", "target": "", "state": "open",
          "opened_at": 1.0}]
    )

    rows = {r["agent_id"]: r for r in HealthStore(store, breakers=breakers, max_agents=3).fleet()}

    assert rows["contained"]["breakers_open"] == 1
    assert rows["contained"]["actions"] == 0


def test_a_contained_agent_that_is_still_acting_is_not_folded_into_the_overflow_bucket(
    store, audit
) -> None:
    """Same loss, one step later: the agent acts, but eight others acted first, so the budget is
    gone by the time the scan meets it and its breaker disappears into a bucket."""
    for i in range(8):
        seed(audit, f"noisy{i}", ["allow"])
    seed(audit, "contained", ["deny"])
    breakers = _Breakers(
        [{"scope": "tool", "agent_id": "contained", "target": "http_get", "state": "open",
          "opened_at": 1.0}]
    )

    rows = {r["agent_id"]: r for r in HealthStore(store, breakers=breakers, max_agents=3).fleet()}

    assert rows["contained"]["breakers_open"] == 1
    assert rows["contained"]["blocked"] == 1


def test_no_open_breaker_is_lost_or_reported_as_zero_when_the_read_is_capped(store) -> None:
    """More contained agents than the hard cap allows rows. The cap still holds — but the breakers
    that fold are SUMMED into the bucket, because `0` there is the positive claim "nothing is holding
    these back" about the one row that is holding contained agents."""
    breakers = _Breakers(
        [{"scope": "agent", "agent_id": f"c{i:04d}", "target": "", "state": "open", "opened_at": 1.0}
         for i in range(600)]
    )

    rows = HealthStore(store, breakers=breakers, max_agents=10_000).fleet(limit=10_000)

    assert len(rows) <= 501, "max_agents cannot be raised past the hard cap"
    assert OVERFLOW_ID in {r["agent_id"] for r in rows}
    assert sum(r["breakers_open"] for r in rows) == 600, "no containment falls off the page"


def test_a_half_open_breaker_is_reported_as_half_open_rather_than_as_open(store) -> None:
    """A half-open breaker is serving a cooldown between single trials — the agent is throttled, not
    cut off. Counting it as open says "contained" about an agent that is executing again; counting it
    nowhere says nothing is holding back an agent limited to one action per cooldown."""
    breakers = _Breakers(
        [{"scope": "agent", "agent_id": "recovering", "target": "", "state": "half_open",
          "opened_at": 1.0}]
    )

    row = HealthStore(store, breakers=breakers).for_agent("recovering")

    assert row["breakers_open"] == 0
    assert row["breakers_half_open"] == 1


def test_a_resource_breach_is_evidence_the_agent_acted(store, audit) -> None:
    """RUN-05 breaches are raised at the EXECUTION site. A row reading "never seen acting" beside
    "breached a resource budget" contradicts itself, and it under-reports liveness for exactly the
    agent that was executing longest — the one whose decision record fell the other side of the
    window edge."""
    asyncio.run(
        audit.append_event(
            "resource_limit_exceeded",
            {"action_id": "x", "agent_id": "a1", "action_type": "tool_call",
             "limit": "wall_s", "budget": 1.0, "observed": 9.0},
        )
    )

    health = HealthStore(store).for_agent("a1")

    assert health["resource_limit_breaches"] == 1
    assert health["last_seen_at"] is not None
    assert health["actions"] == 0, "an event record is still not an action"


def test_an_aware_last_seen_at_is_converted_to_utc_not_relabelled() -> None:
    """`created_at` reads back naive on SQLite and AWARE on the Postgres target. Stamping UTC onto an
    aware value moves the instant by the session offset — five and a half hours, on the one field
    D-5 leaves the operator."""
    row = AgentHealth(
        agent_id="a1",
        window_hours=24.0,
        last_seen_at=datetime(2026, 8, 19, 23, 30, tzinfo=timezone(timedelta(hours=5, minutes=30))),
        actions=1,
        executed=1,
        blocked=0,
        resource_limit_breaches=0,
        breakers_open=0,
    )

    assert row.as_dict()["last_seen_at"] == "2026-08-19T18:00:00+00:00"


def test_the_window_filters(store, audit) -> None:
    """A health page showing last quarter's activity as if it were today's is worse than no health
    page: it reports a dead agent as busy."""
    seed(audit, "a1", ["allow", "allow"])
    assert HealthStore(store).for_agent("a1", window=timedelta(hours=1))["actions"] == 2

    age_everything(store, timedelta(days=30))

    assert HealthStore(store).for_agent("a1", window=timedelta(hours=1))["actions"] == 0
    assert HealthStore(store).for_agent("a1", window=timedelta(days=90))["actions"] == 2
    assert HealthStore(store).fleet(window=timedelta(hours=1)) == []


def test_a_non_positive_window_is_refused_rather_than_answered(store) -> None:
    """A window ending before it starts puts `since` in the FUTURE and answers "no activity" —
    indistinguishable from a silent fleet, which is the one conclusion this surface must not invent."""
    with pytest.raises(ValueError):
        HealthStore(store).fleet(window=timedelta(hours=-1))


def test_the_fleet_read_is_bounded(store, audit) -> None:
    """Phase 6's Slice 6b review found a metric-cardinality DoS in exactly this shape, and `agent_id`
    on an unregistered caller is attacker-influenced (DISC-04). Past the cap the remainder folds into
    ONE bucket, so the page still says there is more rather than truncating silently."""
    for i in range(8):
        seed(audit, f"a{i}", ["allow"])

    rows = HealthStore(store, max_agents=3).fleet()

    assert len(rows) <= 4  # the budget, plus the single overflow bucket
    assert OVERFLOW_ID in {r["agent_id"] for r in rows}
    assert sum(r["actions"] for r in rows) == 8, "the overflow bucket still carries the count"


def test_an_unverified_caller_cannot_animate_another_agents_health(store, audit) -> None:
    """`agent_id` is attacker-chosen until the identity stage vouches for it, and the pipeline audits
    an unregistered caller's action VERBATIM before denying it. Taken as fact, a prober naming a dead
    agent would keep that agent's `last_seen_at` moving — suppressing the one signal D-5 leaves the
    operator. The same filter the DISC-06 graph applies, for the same reason.

    The cost is stated rather than hidden: an agent whose OWN credentials broke shows up here as
    ZERO activity, not as errors. That reads correctly — it is not acting — and the DISC-04 shadow
    surface says why.
    """
    seed(audit, "victim", ["allow"])
    age_everything(store, timedelta(days=7))
    for _ in range(5):
        act(audit, "victim", Outcome.deny, reasons=FORGED)

    health = HealthStore(store).for_agent("victim", window=timedelta(hours=1))

    assert health["actions"] == 0
    assert health["last_seen_at"] is None


def test_health_opens_no_second_writer(store) -> None:
    """Structural: this module must not INSERT. A second source of health facts is a second thing
    that can disagree with the audit log, and the disagreement surfaces during an incident."""
    import agentos_controlplane.health as mod

    source = inspect.getsource(mod)

    assert "s.add(" not in source and "insert(" not in source
