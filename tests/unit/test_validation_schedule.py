"""TEST-08 — continuous validation on a schedule.

The properties asserted here are the ones that stop being test concerns and start being incident
concerns once the suites run on a timer against a live deployment:

  * **nothing executes** (spec D-1) — the probe asks the PDP and never reaches a handler;
  * **a failing suite is isolated** — a validation loop that quietly stopped running is
    indistinguishable from a guard that is holding;
  * **runs are tagged `scheduled`** — a human running suites while debugging must not be able to
    pollute the continuous signal;
  * **the REAL `ReconciliationLoop` actually runs the work** — Slice 11c shipped an async/sync
    mismatch that only the real loop exposes, and a stub loop passes either way.
"""

from __future__ import annotations

import asyncio
import threading

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.pool import StaticPool

from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.reconcile import ReconciliationLoop
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import RedTeamRun
from agentos_controlplane.validation import ValidationStore
from agentos_controlplane.validation_schedule import ValidationReconciler


@pytest.fixture
def store():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    create_all(engine)
    return create_session_factory(engine)


@pytest.fixture
def validation(store) -> ValidationStore:
    return ValidationStore(store, AuditWriter(store))


# --- stand-ins ----------------------------------------------------------------------------------
#
# Local rather than imported: the control plane must NOT import `agentos_sdk` (STATE.md records one
# undeclared controlplane -> SDK edge as a blocker), and the reconciler takes `run_suite` injected
# precisely so this seam can be stood in for. These mirror 12a's stand-ins.


class _Row:
    def __init__(self, attack_id, suite, outcome, blocked):
        self.attack_id, self.suite, self.outcome, self.blocked = attack_id, suite, outcome, blocked


class _Res:
    def __init__(self, rows):
        self.results = tuple(rows)


class _Seam:
    """A governed agent that can BOTH decide and execute. D-1 says the scheduler touches only the
    first, so `execute` raises: any code path that reached it would, against a real deployment with
    a hole in its guard, have PERFORMED the attack it was checking for."""

    def __init__(self, outcome: str = "deny") -> None:
        self.evaluated: list[object] = []
        self._outcome = outcome

    async def evaluate(self, action):
        self.evaluated.append(action)
        return self._outcome

    async def execute(self, action):  # pragma: no cover - failing it is the assertion
        raise AssertionError("an attack payload was EXECUTED — spec D-1 violated")


class _Harness:
    """A faithful miniature of `agentos_sdk.redteam.run_suite`: build a probe, await the DECISION
    seam, score whether the outcome blocked it. Faithful in the one way this slice depends on —
    it reaches the pipeline through `evaluate` and through nothing else."""

    def __init__(self, *, fail_on=()) -> None:
        self.calls: list[str] = []
        self.seen_kwargs: list[dict] = []
        self.threads: list[int] = []
        self._fail_on = set(fail_on)

    async def run_suite(self, evaluate, suite, *, agent_id, token):
        if suite in self._fail_on:
            raise RuntimeError(f"suite {suite!r} exploded")
        self.calls.append(suite)
        self.seen_kwargs.append({"agent_id": agent_id, "token": token})
        self.threads.append(threading.get_ident())
        outcome = await evaluate({"suite": suite, "agent_id": agent_id})
        return _Res([_Row(f"{suite}_1", suite, outcome, outcome == "deny")])


def _reconciler(validation, harness, seam, suites=("jailbreak", "exfiltration"), **kw):
    return ValidationReconciler(
        validation,
        seam.evaluate,
        harness.run_suite,
        suites,
        agent_id="a1",
        token="tok",
        **kw,
    )


def _runs(store) -> list[RedTeamRun]:
    with store() as s:
        return list(s.scalars(select(RedTeamRun)).all())


# --- every suite is asked, every answer is kept -------------------------------------------------


def test_every_suite_is_run_and_recorded(store, validation) -> None:
    harness, seam = _Harness(), _Seam()
    r = _reconciler(validation, harness, seam)

    assert asyncio.run(r.reconcile_async()) == 2

    assert harness.calls == ["jailbreak", "exfiltration"]
    assert {run.suite for run in _runs(store)} == {"jailbreak", "exfiltration"}


def test_the_probe_runs_as_the_agent_being_validated(store, validation) -> None:
    """Validating agent A with agent B's identity measures B's guard and files it under A."""
    harness, seam = _Harness(), _Seam()

    asyncio.run(_reconciler(validation, harness, seam, suites=("jailbreak",)).reconcile_async())

    assert harness.seen_kwargs == [{"agent_id": "a1", "token": "tok"}]
    assert [run.agent_id for run in _runs(store)] == ["a1"]


# --- spec D-1 -----------------------------------------------------------------------------------


def test_nothing_executes_an_attack(store, validation) -> None:
    """SPEC D-1, the phase's cardinal rule, asserted rather than trusted.

    The seam's `execute` raises if it is ever awaited. On a timer this is the difference between a
    test and an incident: an executing probe against a deployment whose guard has a hole performs
    the exfiltration it was checking for, every pass, in production.
    """
    harness, seam = _Harness(), _Seam()

    asyncio.run(_reconciler(validation, harness, seam).reconcile_async())  # must not raise

    # Non-vacuity: a reconciler that did NOTHING would also never execute an attack. The probes
    # genuinely went through the decision path — which is the whole of what the scheduler may do.
    assert len(seam.evaluated) == 2


def test_the_reconciler_holds_no_execution_seam_at_all(validation) -> None:
    """The structural half of D-1. Isolation by construction beats isolation by discipline: the
    scheduler is handed the decision callable and never the object it hangs off, so there is no
    attribute on it from which a later edit could reach a handler."""
    harness, seam = _Harness(), _Seam()

    r = _reconciler(validation, harness, seam)

    assert seam.execute not in vars(r).values()
    assert seam not in vars(r).values()


# --- a failing suite is isolated, not fatal -----------------------------------------------------


def test_a_failing_suite_does_not_stop_the_others(store, validation) -> None:
    """A loop that dies on one bad suite stops producing the signal it exists for — and a validation
    loop that silently stopped is indistinguishable from a guard that is holding."""
    harness, seam = _Harness(fail_on={"jailbreak"}), _Seam()
    r = _reconciler(validation, harness, seam, suites=("jailbreak", "exfiltration"))

    assert asyncio.run(r.reconcile_async()) == 1

    assert harness.calls == ["exfiltration"]
    assert [run.suite for run in _runs(store)] == ["exfiltration"]


def test_a_failing_suite_is_LOGGED_not_swallowed(validation, caplog) -> None:
    """Isolated is not the same as hidden. A pass that quietly recorded fewer suites than it was
    asked for leaves the operator reading a partial trend as a complete one."""
    harness, seam = _Harness(fail_on={"jailbreak"}), _Seam()

    with caplog.at_level("WARNING"):
        asyncio.run(_reconciler(validation, harness, seam).reconcile_async())

    assert any("jailbreak" in rec.getMessage() for rec in caplog.records)


def test_a_suite_that_fails_to_RECORD_is_isolated_too(validation) -> None:
    """The other half of the pass can fail as well — a full disk, a lock timeout, an over-long
    suite name the store refuses. Isolating only the probe would let the recording half kill the
    loop, which is the same outage by a different door."""
    harness, seam = _Harness(), _Seam()
    r = _reconciler(validation, harness, seam, suites=("x" * 200, "jailbreak"))

    assert asyncio.run(r.reconcile_async()) == 1
    assert harness.calls == ["x" * 200, "jailbreak"]


# --- the continuous signal stays separable from a human's -------------------------------------


def test_the_run_is_recorded_as_scheduled_not_manual(store, validation) -> None:
    """A human runs the same suites while debugging a regression, and those runs would otherwise be
    indistinguishable from the timer's — turning the continuous signal into a mixture nobody can
    read."""
    harness, seam = _Harness(), _Seam()

    asyncio.run(_reconciler(validation, harness, seam, suites=("jailbreak",)).reconcile_async())

    assert [run.source for run in _runs(store)] == ["scheduled"]


# --- it runs under the REAL loop ----------------------------------------------------------------


def test_it_drives_through_the_REAL_reconciliation_loop(validation) -> None:
    """Slice 11c shipped an async `reconcile` the loop mishandled — it drove a coroutine through
    `asyncio.to_thread`, `int(changed)` raised TypeError, and the loop reported an error every pass
    while the work NEVER RAN. A stub loop cannot catch that; the real one can."""
    harness, seam = _Harness(), _Seam()
    r = _reconciler(validation, harness, seam, suites=("jailbreak",))

    results = asyncio.run(ReconciliationLoop([r]).run_once())

    assert [x.error for x in results] == [None]
    assert [x.changed for x in results] == [1]
    assert harness.calls == ["jailbreak"], "the loop must actually have run the work"


def test_the_loop_can_schedule_it(validation) -> None:
    """`periodic` keys on `name` and `interval_s`; without both the loop would run it every tick."""
    harness, seam = _Harness(), _Seam()

    r = _reconciler(validation, harness, seam)

    assert r.name == "validation" and r.interval_s > 0


def test_the_async_pass_runs_on_the_LOOP_and_a_sync_one_still_runs_in_a_THREAD(validation) -> None:
    """The reconciler awaits the LIVE pipeline, whose async state is bound to the control plane's
    running event loop — driving it on a second loop inside a worker thread is a harder-to-find
    version of exactly the 11c bug. So the async path stays on the loop.

    And the sync path must NOT follow it there: the four shipped reconcilers do blocking SQLAlchemy
    I/O, and moving that onto the event loop would stall the pipeline's async audit writes — the
    reason `to_thread` is there at all.
    """
    harness, seam = _Harness(), _Seam()
    threads: list[int] = []

    class _Sync:
        name, interval_s = "sync", 1.0

        def reconcile(self) -> int:
            threads.append(threading.get_ident())
            return 0

    r = _reconciler(validation, harness, seam, suites=("jailbreak",))
    asyncio.run(ReconciliationLoop([r, _Sync()]).run_once())

    assert harness.threads == [threading.get_ident()], "the async pass must stay on the event loop"
    assert threads and threads[0] != threading.get_ident(), "a sync pass must stay in a thread"
