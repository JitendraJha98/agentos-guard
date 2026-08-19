# Phase 12 · Slice 12d — Agent Health Monitoring (OBS-04) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Commits end
> with `-m "Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"`. TDD per task, one
> commit each. Gates green at every commit. Run the WHOLE suite before committing.

**Goal (OBS-04):** Report **liveness, error rate and circuit-breaker state per agent**, so an operator
can see an agent misbehaving before it fails rather than after.

**Architecture:** A **read-side** `HealthStore` over data that already exists — the audit log and
`CircuitBreakerStore`. No new table, no new writer, nothing on the hot path. Health is a *query*, not
a subsystem: every fact it reports is already being recorded for another reason, and adding a second
writer would create a second thing that can disagree with the audit log.

**Tech Stack:** SQLAlchemy 2.0, FastAPI, pytest. No new dependency, no migration.

## The two numbers that are easy to get wrong, and why they matter

**Liveness: idle is not dead (spec D-5).** Liveness derived from audit records means an agent with
nothing to do is byte-identical to one that crashed. So this reports `last_seen_at` as a **fact** and
never asserts "down". The operator's own threshold decides — a batch agent that runs nightly and a
request handler that should act every second have wildly different answers, and only the operator
knows which they have. Asserting a verdict here would make a healthy nightly agent page someone at
3am, and teach them to ignore the health page.

**Error rate: a governance deny is not an error (spec D-6).** The denominator has to be named, or the
number lies in the most damaging direction. A `deny` is the system **working**; counting it as an
error makes a well-governed agent — one attracting lots of correctly-blocked attempts — look like the
sickest thing in the fleet, and pushes an operator to loosen the guard to make the chart green. So
this counts **execution failures against executed actions** and says so in the field names.

## File structure
- Create `.../agentos_controlplane/health.py` — `HealthStore`.
- Modify `.../api.py` — a gated read route.
- Tests: `tests/unit/test_health.py`, `tests/integration/test_health_api.py`.

---

### Task 1: `HealthStore`

**Files:** create `.../agentos_controlplane/health.py`; test `tests/unit/test_health.py`.

```python
"""OBS-04 — agent health: liveness, error rate, breaker state.

A READ, NOT A SUBSYSTEM. Every fact here is already recorded for another reason — the audit log
knows when an agent last acted and how its actions turned out, and `CircuitBreakerStore` knows which
breakers are open. Adding a health WRITER would add a second source that can disagree with the audit
log, and the disagreement would be discovered while diagnosing an incident.

IDLE IS NOT DEAD. `last_seen_at` is reported as a fact and never as a verdict. An agent with nothing
to do is byte-identical in the log to one that crashed, and only the operator knows which they have:
a nightly batch agent and a request handler have opposite expectations. A module that asserted "down"
would page someone at 3am for a healthy nightly job, and the lesson learned would be to ignore this
page.

A DENY IS NOT AN ERROR. `deny`, `sandbox` and `require_approval` are the system working. Counting
them as errors would make the best-governed agent in a fleet — the one attracting the most
correctly-blocked attempts — look like the sickest, and the natural fix an operator would reach for
is to loosen the guard. So the denominator is EXECUTED actions and the numerator is EXECUTION
failures, and both are named in the output rather than left for a reader to assume.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select

from agentos_controlplane.store.models import AuditRecord

_MAX_AGENTS = 500          # a gated route is still a route
_DEFAULT_WINDOW = timedelta(hours=24)

# Outcomes where the action was PERMITTED to run. The error rate's denominator is these, because an
# action the control plane refused never reached the code that could fail.
_EXECUTED_OUTCOMES = frozenset({"allow", "warn", "governance_review", "temporary_exception"})
# Outcomes where the control plane STOPPED the action. Counted and reported separately — they are
# governance working, and folding them into an error rate inverts what the number means.
_BLOCKED_OUTCOMES = frozenset({"deny", "sandbox", "require_approval", "require_consensus"})


@dataclass(frozen=True)
class AgentHealth:
    agent_id: str
    last_seen_at: str | None      # a FACT. Never a verdict — see the module docstring.
    actions: int
    executed: int
    blocked: int
    execution_failures: int
    breakers_open: int

    @property
    def execution_failure_rate(self) -> float | None:
        """Failures per EXECUTED action, or None when nothing executed.

        None rather than 0.0, on the same reasoning ECON-01 uses for an unpriced model: 0.0 is the
        claim "everything that ran, ran fine", and an agent that ran nothing has not made it.
        """
        return None if not self.executed else self.execution_failures / self.executed
```

`HealthStore(session_factory, breakers=None)` exposes `fleet(window=..., limit=_MAX_AGENTS)` and
`for_agent(agent_id, window=...)`, both returning dicts that carry **every field above**, including
the two counts behind the rate (the Slice 12a lesson: a rate without its denominator is unreadable).

**Where the counts come from.** Decision records in `audit_record.body` carry `agent_id` and
`outcome` (`_REQUIRED_DECISION_KEYS`). Execution failures are the RUN-06 signal the breaker already
counts — read `breakers_open` from the injected `CircuitBreakerStore.list_open()`, and derive
`execution_failures` from the audit events the breaker writes rather than inventing a new counter.
**Read `circuit_breaker.py` first** and use whatever it actually records; if no per-agent failure
count is recoverable from the log, report `execution_failures` as `None` and say so in the docstring
rather than substituting a number that means something else.

- [ ] **Step 1: Write the failing tests**

```python
def test_liveness_is_a_timestamp_not_a_verdict(store, audit) -> None:
    """SPEC D-5. An agent with nothing to do is byte-identical to one that crashed, and only the
    operator knows which they have. A module that asserted 'down' would page someone at 3am for a
    healthy nightly job."""
    health = HealthStore(store).for_agent("a1")

    assert health["last_seen_at"] is not None
    assert not any(k in health for k in ("alive", "up", "down", "healthy", "status"))


def test_a_never_seen_agent_reports_null_last_seen_not_an_old_timestamp(store) -> None:
    """None means 'we have never seen this agent act', which is a different statement from 'it acted
    a long time ago'."""


def test_a_DENY_is_not_counted_as_an_error(store, audit) -> None:
    """THE property of this slice. A deny is the system working. Counting it as an error makes the
    best-governed agent in a fleet look like the sickest, and the fix an operator reaches for is to
    loosen the guard."""
    _seed_decisions(audit, "a1", ["allow", "deny", "deny", "deny"])

    health = HealthStore(store).for_agent("a1")

    assert health["blocked"] == 3 and health["executed"] == 1
    assert health["execution_failure_rate"] in (None, 0.0)
    assert health["execution_failure_rate"] != 0.75, "denials must not read as a 75% error rate"


def test_the_error_rate_denominator_is_EXECUTED_actions(store, audit) -> None:
    """An action the control plane refused never reached the code that could fail, so it does not
    belong in the denominator either."""


def test_an_agent_that_executed_nothing_has_a_null_rate_not_zero(store, audit) -> None:
    """0.0 is the claim "everything that ran, ran fine". An agent that ran nothing has not made it —
    the same absent-vs-zero rule ECON-01 established."""


def test_breaker_state_is_reported_per_agent(store, audit, breakers) -> None:
    """OBS-04 names circuit-breaker state explicitly, and it is the one health signal that is already
    a verdict the system itself made."""


def test_the_window_filters(store, audit) -> None:
    """A health page showing last quarter's activity as if it were today's is worse than no health
    page: it reports a dead agent as busy."""


def test_the_fleet_read_is_bounded(store, audit) -> None:
    """Phase 6's Slice 6b review found a metric-cardinality DoS in exactly this shape, and `agent_id`
    on an unregistered caller is attacker-influenced (DISC-04)."""


def test_health_opens_no_second_writer(store) -> None:
    """Structural: this module must not INSERT. A second source of health facts is a second thing
    that can disagree with the audit log, and the disagreement surfaces during an incident."""
    import inspect

    import agentos_controlplane.health as mod

    source = inspect.getsource(mod)
    assert "s.add(" not in source and "insert(" not in source
```

- [ ] **Step 2: Run → fails.** **Step 3: Implement.** **Step 4: Run → passes.**
- [ ] **Step 5: Commit** `feat(controlplane): agent health as a read over facts already recorded (OBS-04)`.

---

### Task 2: gated read route + full gate

Append `health: "HealthStore | None" = None` LAST to `build_inventory_router` and `create_app`:

```python
    @router.get("/health/agents")
    def fleet_health(hours: int = 24) -> list[dict]:
        """OBS-04 — per-agent liveness, error rate and breaker state.

        `last_seen_at` is a FACT, not a verdict: an idle agent and a dead one look identical here and
        only the operator's own expectation separates them. The failure rate counts EXECUTION
        failures over EXECUTED actions — a governance block is not an error, and folding blocks in
        would make a well-governed agent look like the worst one in the fleet.
        """
```

`hours` must be validated (positive, bounded) → 422 otherwise; an unbounded or negative window is a
different question than the one asked.

- [ ] **Step 1: Failing tests** — 200 with the seeded agent; `?hours=-1` → 422; 401 without a token;
  404 when unwired while `/inventory` still 200.
- [ ] **Step 2: Run → fails.** **Step 3: Implement.**
- [ ] **Step 4: Run → passes**, then the FULL gate on the WHOLE suite.
- [ ] **Step 5: Commit** `feat(controlplane): gated agent-health read route (OBS-04)`.

## Self-review

OBS-04 names three things and each is present: liveness, error rate, and circuit-breaker state, per
agent.

The two ways this could have been quietly wrong are both closed by test. Liveness is a timestamp and
the output carries no `status`/`alive`/`healthy` key at all — asserted structurally, because the
temptation to add one is exactly what would page an operator about a healthy nightly job. And a
governance block is counted separately from an execution failure, with a test that would fail if
three denials rendered as a 75% error rate; that number would push an operator to loosen the guard to
make a chart green, which is the worst thing a health page could cause.

Absence stays absence: a never-seen agent has a null `last_seen_at`, and an agent that executed
nothing has a null rate rather than 0.0 — the ECON-01 rule applied to a second metric. And the module
is structurally a reader: a test asserts it contains no insert, because a second writer of health
facts is a second thing that can disagree with the audit log.
