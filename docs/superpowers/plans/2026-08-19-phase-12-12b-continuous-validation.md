# Phase 12 · Slice 12b — Continuous Validation on a Schedule (TEST-08) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Commits end
> with `-m "Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"`. Tests:
> `./.venv/Scripts/python.exe -m pytest`. TDD per task, one commit each. Gates `floor_invariant`,
> `regression_lock`, `latency` green at every commit. Run the WHOLE suite before committing.

**Goal (TEST-08):** Re-run the red-team suites against the **live agent's decision path** on a
schedule, so "the guard holds" becomes a continuously re-established fact rather than a claim from
the last CI run.

**Architecture:** A `ValidationReconciler` following the shipped API-04 pattern (`reconcile() -> int`
returning items changed, `interval_s`, driven by `ReconciliationLoop`). Each pass runs the suites
through the live `pipeline.evaluate` and records a run via Slice 12a's `ValidationStore`.

**Tech Stack:** existing `agentos_sdk.redteam`, `agentos_controlplane.validation`, `reconcile.py`.
No new dependency, no migration.

## THE INVARIANT THIS SLICE EXISTS UNDER (spec D-1)

`run_suite` feeds each attack through `evaluate(action) -> Decision` and **never invokes the
handler**. This slice puts that on a timer, which is precisely where getting it wrong stops being a
test bug and becomes an incident: an *executing* probe, run every few minutes against a deployment
whose guard has a hole, would **perform the exfiltration it was checking for**. The validation tool
would become the breach it exists to detect, on a schedule, in production.

So: no code path added here may invoke a tool handler, a model, or the network with an attack
payload. The reviewer is asked to read the call graph rather than take this on trust.

## Where the SDK boundary sits

`run_suite` lives in `agentos_sdk.redteam`; `ValidationStore` lives in the control plane, which must
not import the SDK (STATE.md records an existing undeclared edge — do not add a second). So the
reconciler takes **`run_suite` as an injected callable**, exactly as the pipeline takes its
collaborators. That also makes the scheduler testable without the SDK present.

## File structure
- Create `.../agentos_controlplane/validation_schedule.py` — `ValidationReconciler`.
- Modify `.../reconcile.py` — add `"validation"` to `DEFAULT_INTERVALS`.
- Tests: `tests/unit/test_validation_schedule.py`.

---

### Task 1: `ValidationReconciler`

**Files:** create `.../agentos_controlplane/validation_schedule.py`; modify `.../reconcile.py`; test
`tests/unit/test_validation_schedule.py`.

```python
"""TEST-08 — continuous validation. Does the guard STILL hold, right now?

Phase 6 answers that in CI, against the corpus, at merge time. Between merges the answer can change
without anyone touching the red-team suite: a constitution edit, a threshold change, a detector
regression, a rollback. This reconciler re-asks on a timer and records the answer as a trend point
(TEST-07), so a guard that quietly stopped holding shows up as a moving line rather than as an
incident.

IT ASKS; IT DOES NOT ATTACK (spec D-1). Every probe goes through `evaluate(action) -> Decision` — the
PDP — and NOTHING here invokes a handler. That distinction is cheap in CI and load-bearing on a
schedule: an executing probe against a deployment whose guard has a hole would PERFORM the
exfiltration it was checking for, every few minutes, in production. A validation tool that becomes
the breach it detects is the worst outcome this phase could produce.

WHAT IT DETECTS, STATED HONESTLY. Regression, not novelty. It re-runs a fixed, shipped corpus against
the live decision path, so it answers "did something that used to be blocked stop being blocked?".
It is not a pentest and it discovers nothing new; Phase 14's self-play is where novel attacks come
from. An operator who reads a flat green line as "we are secure" is reading more than it says.
"""
from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable

_log = logging.getLogger(__name__)


class ValidationReconciler:
    """API-04 reconciler that re-runs the red-team suites against the live decision path.

    `run_suite` is INJECTED rather than imported: it lives in `agentos_sdk.redteam` and the control
    plane does not import the SDK. `evaluate` is the live `Pipeline.evaluate`.
    """

    name = "validation"

    def __init__(
        self,
        store,                    # ValidationStore
        evaluate,                 # the LIVE pipeline's evaluate (async)
        run_suite,                # agentos_sdk.redteam.run_suite (async, evaluate-only)
        suites,                   # the suite names to run
        *,
        agent_id: str,
        token: str,
        interval_s: float = 900.0,
    ) -> None:
        self._store = store
        self._evaluate = evaluate
        self._run_suite = run_suite
        self._suites = tuple(suites)
        self._agent_id = agent_id
        self._token = token
        self.interval_s = interval_s

    async def reconcile_async(self) -> int:
        """Run every suite once and record each result. Returns suites RECORDED.

        A failing suite is isolated rather than fatal, the Phase-7 reconciler lesson: a loop that
        dies on one bad suite stops producing the signal it exists for, and a validation loop that
        silently stopped running is indistinguishable from a guard that is holding.
        """
        recorded = 0
        for suite in self._suites:
            try:
                results = await self._run_suite(
                    self._evaluate, suite, agent_id=self._agent_id, token=self._token
                )
                await self._store.record(self._agent_id, suite, results, source="scheduled")
                recorded += 1
            except Exception:
                _log.warning("scheduled validation of suite %r failed", suite, exc_info=True)
        return recorded
```

**On `reconcile()` vs `reconcile_async()`** — the shipped `Reconciler` Protocol is **synchronous**
(`def reconcile(self) -> int`), and `ReconciliationLoop._run` does
`await asyncio.to_thread(r.reconcile)`. Slice 11c hit this exact trap: an `async def reconcile` hands
the loop a coroutine, the loop's `int(changed)` raises `TypeError`, and it reports an error every pass
while the work never runs. But this reconciler's body is genuinely async (it awaits the pipeline), and
`to_thread` would run it in a thread with no running loop.

**Resolve it by reading `reconcile.py` first**, then pick one and say which in your report:
either give the class a sync `reconcile()` that drives `reconcile_async()` on its own event loop
(safe only if the loop thread has none — verify), or add async-reconciler support to
`ReconciliationLoop` and keep every existing reconciler working unchanged. Do **not** ship an
`async def reconcile` that the current loop will silently mishandle — write a test that runs it
through the REAL `ReconciliationLoop` and asserts the work happened, so this cannot pass on a stub.

Add to `DEFAULT_INTERVALS` in `reconcile.py`, in the file's comment style:
```python
    # TEST-08: re-running the corpus is pure CPU against the in-process PDP, but it is still N
    # evaluations per pass; 15 minutes is often enough to catch a regression the same working day
    # and rare enough that it never competes with real traffic.
    "validation": 900.0,
```

- [ ] **Step 1: Write the failing tests**

```python
"""TEST-08 — continuous validation on a schedule."""
from __future__ import annotations

import asyncio

import pytest

from agentos_controlplane.validation_schedule import ValidationReconciler


class _Spy:
    """Records what it was asked, and — the point of this fixture — whether anything EXECUTED."""

    def __init__(self, blocked=True, fail_on=()):
        self.calls = []
        self.executed = []
        self.blocked = blocked
        self.fail_on = set(fail_on)

    async def run_suite(self, evaluate, suite, *, agent_id, token):
        if suite in self.fail_on:
            raise RuntimeError("suite exploded")
        self.calls.append(suite)
        await evaluate(object())          # goes through the DECISION seam, like the real harness
        return _Results([_Row(f"{suite}_1", suite, "deny" if self.blocked else "allow", self.blocked)])


def test_every_suite_is_run_and_recorded(store) -> None:
    ...  # asserts recorded == len(suites) and one RedTeamRun row per suite, source="scheduled"


def test_a_failing_suite_does_not_stop_the_others(store) -> None:
    """A loop that dies on one bad suite stops producing the signal it exists for — and a validation
    loop that silently stopped is indistinguishable from a guard that is holding."""
    spy = _Spy(fail_on={"jailbreak"})
    r = _reconciler(store, spy, suites=("jailbreak", "exfiltration"))

    assert asyncio.run(r.reconcile_async()) == 1
    assert spy.calls == ["exfiltration"]


def test_nothing_executes_an_attack(store) -> None:
    """SPEC D-1, the phase's cardinal rule, asserted rather than trusted.

    The probe is fed a handler that RAISES if it is ever awaited. On a schedule this is the
    difference between a test and an incident: an executing probe against a deployment whose guard
    has a hole performs the exfiltration it was checking for, every pass, in production.
    """
    def _handler_must_never_run(*a, **k):
        raise AssertionError("an attack payload was EXECUTED — spec D-1 violated")

    r = _reconciler(store, _Spy(), handler=_handler_must_never_run)
    asyncio.run(r.reconcile_async())  # must not raise


def test_the_run_is_recorded_as_scheduled_not_manual(store) -> None:
    """The trend must be able to separate what a human ran from what the timer ran: a human runs
    suites while debugging, and those runs would otherwise pollute the continuous signal."""


def test_it_drives_through_the_REAL_reconciliation_loop(store) -> None:
    """Slice 11c shipped an async `reconcile` the loop silently mishandled — it awaited a coroutine
    through `asyncio.to_thread`, got a TypeError, and reported an error every pass while the work
    never ran. A stub loop cannot catch that; the real one can."""
    from agentos_controlplane.reconcile import ReconciliationLoop

    r = _reconciler(store, spy := _Spy(), suites=("jailbreak",))
    results = asyncio.run(ReconciliationLoop([r]).run_once())

    assert [x.ok for x in results] == [True]
    assert spy.calls == ["jailbreak"], "the loop must actually have run the work"
```

Fill in `_reconciler`, `_Results`, `_Row` as small local fixtures (mirroring 12a's test module — the
control plane must not import the SDK). The `store` fixture is 12a's.

- [ ] **Step 2: Run → fails.** **Step 3: Implement.** **Step 4: Run → passes** + the WHOLE suite.
- [ ] **Step 5: Commit** `feat(controlplane): scheduled continuous validation against the live decision path (TEST-08)`.

## Self-review

TEST-08 asks for suites re-run against the live agent on a schedule, and all three parts are real:
the suites come from the shipped corpus, `evaluate` is the live pipeline's, and the reconciler runs
under the existing `ReconciliationLoop` — proven by a test that drives the REAL loop rather than a
stub, because Slice 11c shipped an async/sync mismatch that only the real loop exposes.

The phase's cardinal rule is asserted, not assumed: a handler that raises if awaited proves nothing
executed. Failure isolation is tested, because a validation loop that silently stopped running looks
exactly like a guard that is holding. Runs are tagged `scheduled` so a human debugging with the same
suites cannot pollute the continuous signal.

The honest limit is in the module docstring: this detects **regression, not novelty**. A flat green
line means nothing that used to be blocked has stopped being blocked — it is not evidence of security,
and Phase 14's self-play is where new attacks come from.
