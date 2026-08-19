"""TEST-08 — continuous validation on a schedule.

The properties asserted here are the ones that stop being test concerns and start being incident
concerns once the suites run on a timer against a live deployment:

  * **nothing executes** (spec D-1) — the probe asks the PDP and never reaches a handler;
  * **nothing is attributed to the production agent** — a healthy guard denies every probe, and
    those denials feed the breaker and the reputation of whatever identity ran them;
  * **the pass proves it reached the policy engine** — a probe short-circuited before policy scores
    100% blocked, which is the most reassuring output this loop can produce and a total lie;
  * **a failing suite is isolated, a wholly failing pass is not** — a validation loop that quietly
    stopped running is indistinguishable from a guard that is holding;
  * **a hanging probe cannot wedge the loop** — `run_once` is sequential, so an unbounded await here
    stops every other reconciler and shutdown with them;
  * **runs are tagged `scheduled`** — a human running suites while debugging must not be able to
    pollute the continuous signal;
  * **the REAL `ReconciliationLoop` actually runs the work** — Slice 11c shipped an async/sync
    mismatch that only the real loop exposes, and a stub loop passes either way.
"""

from __future__ import annotations

import asyncio
import threading
import time

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
# precisely so this seam can be stood in for. These mirror 12a's stand-ins. The real `run_suite` is
# driven end to end in `tests/integration/test_validation_schedule_real_suite.py`.


class _Row:
    def __init__(self, attack_id, suite, outcome, blocked):
        self.attack_id, self.suite, self.outcome, self.blocked = attack_id, suite, outcome, blocked


class _Res:
    def __init__(self, rows):
        self.results = tuple(rows)


class _Reason:
    def __init__(self, stage: str) -> None:
        self.stage = stage


class _Decision:
    """The shape the seam returns: an outcome for the corpus runner, reasons for the control probe.

    `stages` is what the control probe reads — a decision that reached the policy engine always
    carries a `policy` reason, and one short-circuited at identity or the breaker does not.
    """

    def __init__(self, outcome: str, stages: tuple[str, ...]) -> None:
        self.outcome = outcome
        self.reasons = [_Reason(s) for s in stages]


class _Seam:
    """A governed agent that can BOTH decide and execute. D-1 says the scheduler touches only the
    first, so `execute` raises: any code path that reached it would, against a real deployment with
    a hole in its guard, have PERFORMED the attack it was checking for."""

    def __init__(self, outcome: str = "deny", stages: tuple[str, ...] = ("policy", "graduated")) -> None:
        self.evaluated: list[object] = []
        self._outcome = outcome
        self._stages = stages

    async def evaluate(self, action):
        self.evaluated.append(action)
        return _Decision(self._outcome, self._stages)

    async def execute(self, action):  # pragma: no cover - failing it is the assertion
        raise AssertionError("an attack payload was EXECUTED — spec D-1 violated")


class _Harness:
    """A faithful miniature of `agentos_sdk.redteam.run_suite`: build a probe, await the DECISION
    seam, score whether the outcome blocked it. Faithful in the one way this slice depends on —
    it reaches the pipeline through `evaluate` and through nothing else."""

    def __init__(self, *, fail_on=(), hang_on=()) -> None:
        self.calls: list[str] = []
        self.seen_kwargs: list[dict] = []
        self.threads: list[int] = []
        self._fail_on = set(fail_on)
        self._hang_on = set(hang_on)

    async def run_suite(self, evaluate, suite, *, agent_id, token):
        if suite in self._fail_on:
            raise RuntimeError(f"suite {suite!r} exploded")
        if suite in self._hang_on:
            self.calls.append(suite)
            await asyncio.Event().wait()  # never returns — a stalled interpreter or a hung DB
        self.calls.append(suite)
        self.seen_kwargs.append({"agent_id": agent_id, "token": token})
        self.threads.append(threading.get_ident())
        decision = await evaluate({"suite": suite, "agent_id": agent_id})
        outcome = decision.outcome
        return _Res([_Row(f"{suite}_1", suite, outcome, outcome == "deny")])


def _reconciler(validation, harness, seam, suites=("jailbreak", "exfiltration"), **kw):
    return ValidationReconciler(
        validation,
        seam.evaluate,
        harness.run_suite,
        suites,
        agent_id="a1",
        probe_agent_id="a1#validation",
        probe_token="probe-tok",
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


# --- the probe is NOT the production agent ------------------------------------------------------


def test_the_probes_run_as_the_validation_principal_not_the_validated_agent(store, validation) -> None:
    """A healthy guard DENIES every probe, and a deny is a RUN-06 breaker failure and a TRST-03
    reputation signal against whatever identity ran it. Attributed to the production agent, one pass
    (9 corpus attacks, default threshold 5) opens its breaker and denies its real traffic, and the
    TrustReconciler persists the floored score — a health check that takes the patient offline,
    more reliably the better the guard is.

    So the probes carry the validation principal, while the TREND is still filed under the agent
    being measured: the question is "is a1's guard holding", answered on a principal the deployment
    configured to mirror a1.
    """
    harness, seam = _Harness(), _Seam()

    asyncio.run(_reconciler(validation, harness, seam, suites=("jailbreak",)).reconcile_async())

    assert harness.seen_kwargs == [{"agent_id": "a1#validation", "token": "probe-tok"}]
    assert [run.agent_id for run in _runs(store)] == ["a1"]


def test_probing_as_the_validated_agent_itself_is_REFUSED(validation) -> None:
    """Enforced at construction rather than documented: the misconfiguration is invisible until it
    has already opened the production agent's breaker, and by then the timer has done it again."""
    harness, seam = _Harness(), _Seam()

    with pytest.raises(ValueError, match="probe_agent_id must differ"):
        ValidationReconciler(
            validation,
            seam.evaluate,
            harness.run_suite,
            ("jailbreak",),
            agent_id="a1",
            probe_agent_id="a1",
            probe_token="t",
        )


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
    assert len(seam.evaluated) == 3  # the control probe + one per suite


def test_the_reconciler_holds_no_execution_seam_at_all(validation) -> None:
    """The structural half of D-1. Isolation by construction beats isolation by discipline: the
    scheduler is handed the decision callable and never the object it hangs off, so there is no
    attribute on it from which a later edit could reach a handler."""
    harness, seam = _Harness(), _Seam()

    r = _reconciler(validation, harness, seam)

    assert seam.execute not in vars(r).values()
    assert seam not in vars(r).values()


def test_the_control_probe_is_not_itself_an_attack(validation) -> None:
    """The pass gained an extra evaluation, and an extra evaluation is an extra chance to smuggle a
    payload onto a timer. The control probe exists to prove the engine RAN, so it carries nothing."""
    harness, seam = _Harness(), _Seam()

    asyncio.run(_reconciler(validation, harness, seam, suites=("jailbreak",)).reconcile_async())

    control = seam.evaluated[0]
    assert control.payload == {}
    assert control.target == "validation_control"


# --- the pass must prove it reached the policy engine -------------------------------------------


def test_a_pass_that_never_reaches_POLICY_fails_instead_of_scoring_a_perfect_guard(validation) -> None:
    """The disguise that is worse than silence. If the probe token expired, the probe agent was
    kill-switched, or its breaker opened, every probe short-circuits to `deny` BEFORE policy — and
    `deny` counts as blocked, so the pass records 100% blocked, ASR 0.0, a flat green line drawn by
    a policy path that never ran. Positive evidence for the wrong conclusion.
    """
    harness = _Harness()
    seam = _Seam("deny", stages=("identity", "circuit_breaker"))
    r = _reconciler(validation, harness, seam)

    with pytest.raises(RuntimeError, match="never reached the policy stage"):
        asyncio.run(r.reconcile_async())

    assert harness.calls == [], "no suite may be scored on a pass that could not exercise the guard"


def test_the_control_probe_does_not_care_WHAT_policy_said(store, validation) -> None:
    """Only that it spoke. What is benign under one constitution is denied under another, so
    checking the control probe's OUTCOME would make a strict-posture deployment error every pass."""
    harness, seam = _Harness(), _Seam("deny", stages=("policy",))

    assert asyncio.run(_reconciler(validation, harness, seam, suites=("jailbreak",)).reconcile_async()) == 1
    assert len(_runs(store)) == 1


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


# --- but a WHOLLY failed pass is an error, not a converged zero ---------------------------------


def test_a_pass_where_EVERY_suite_fails_is_an_ERROR_not_a_converged_zero(validation) -> None:
    """`changed == 0` is the loop's word for CONVERGED. A pass that measured nothing at all —
    expired credentials, a stale pipeline handle, a typo'd suite name — reporting `ok=True,
    changed=0` hands the health surface the exact signal for "healthy and idle" to describe "this
    loop has stopped telling you anything". The two states an operator most needs to tell apart
    would render identically.

    Driven through the REAL loop, because the isolation that turns the raise back into a recorded
    error result lives there.
    """
    harness, seam = _Harness(fail_on={"jailbreak", "exfiltration"}), _Seam()
    r = _reconciler(validation, harness, seam)

    results = asyncio.run(ReconciliationLoop([r]).run_once())

    assert results[0].error is not None and not results[0].ok
    assert "every scheduled suite failed" in results[0].error


def test_a_wholly_failed_pass_does_not_stop_the_NEXT_one(validation) -> None:
    """The error must be a report, not a death: the loop catches it and the timer keeps its
    appointment. A validation loop that gave up on its first bad pass is the silence again."""
    harness, seam = _Harness(fail_on={"jailbreak"}), _Seam()
    r = _reconciler(validation, harness, seam, suites=("jailbreak",))
    loop = ReconciliationLoop([r])

    async def _two_passes():
        first = await loop.run_once()
        harness._fail_on.clear()
        return first, await loop.run_once()

    first, second = asyncio.run(_two_passes())

    assert first[0].error is not None
    assert second[0].error is None and second[0].changed == 1


def test_a_reconciler_with_NO_suites_is_refused_at_construction(validation) -> None:
    """Otherwise it reports a clean converged pass forever, which reads exactly like a guard that is
    holding — the same lie as the wholly-failed pass, arriving through configuration."""
    harness, seam = _Harness(), _Seam()

    with pytest.raises(ValueError, match="suites must not be empty"):
        _reconciler(validation, harness, seam, suites=())


def test_an_interval_below_the_floor_is_refused(validation) -> None:
    """`interval_s=0` runs a pass every loop tick: ~86k passes a day, each appending a record per
    probe to the serialized audit chain the hot path shares. This is the one reconciler whose cost
    is paid in audit appends, so the interval has a floor rather than only a sign check."""
    harness, seam = _Harness(), _Seam()

    with pytest.raises(ValueError, match="interval_s must be at least"):
        _reconciler(validation, harness, seam, interval_s=0.0)


# --- a hanging probe cannot wedge the loop ------------------------------------------------------


def test_a_hanging_suite_is_BOUNDED_and_its_siblings_still_run(store, validation) -> None:
    """The wait is genuinely unbounded — the interpreter is a remote call and a red-team corpus is
    exactly the `no_match` population that reaches it — so it is bounded here. A timeout lands in
    the same isolation branch as any other suite failure."""
    harness, seam = _Harness(hang_on={"jailbreak"}), _Seam()
    r = _reconciler(validation, harness, seam, suite_timeout_s=0.05)

    started = time.monotonic()
    assert asyncio.run(r.reconcile_async()) == 1
    assert time.monotonic() - started < 5.0

    assert [run.suite for run in _runs(store)] == ["exfiltration"]


def test_a_hanging_suite_does_not_wedge_the_WHOLE_reconciliation_loop(validation) -> None:
    """`run_once` is SEQUENTIAL and `_loop` awaits it, so an unbounded await in the async shape does
    not merely lose this pass: it permanently stops constitution, trust, graph, cache and budget
    reconciliation — a stale policy cache then enforces the wrong constitution — and `stop()` never
    returns either. Only the async shape can do this; the sync ones are in threads.
    """
    harness, seam = _Harness(hang_on={"jailbreak"}), _Seam()
    ran: list[str] = []

    class _Sibling:
        name, interval_s = "sibling", 1.0

        def reconcile(self) -> int:
            ran.append(self.name)
            return 0

    r = _reconciler(validation, harness, seam, suites=("jailbreak",), suite_timeout_s=0.05)
    results = asyncio.run(ReconciliationLoop([r, _Sibling()]).run_once())

    assert ran == ["sibling"], "a hung probe must not starve the other reconcilers"
    assert results[0].error is not None  # the pass measured nothing, and says so
    assert results[1].ok


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
