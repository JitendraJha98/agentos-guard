"""API-04 — reconciliation loops.

A reconciler is only useful if the loop around it is honest about failure. The
properties tested here are the loop's, not any individual reconciler's:

  * **idempotency** — a converged pass changes nothing (otherwise the loop
    churns and "changed" means nothing);
  * **error isolation** — one throwing reconciler must not stop the others or
    kill the loop, and its failure must be VISIBLE, never swallowed;
  * **independent intervals** — a cheap reconciler must not be dragged to an
    expensive one's cadence;
  * **clean lifecycle** — stop() actually stops.
"""

from __future__ import annotations

import asyncio

import pytest

from agentos_controlplane.reconcile import (
    ReconcilerResult,
    ReconciliationLoop,
    periodic,
)


class _Counter:
    """A reconciler that reports how many items it changed, and can be made to fail."""

    def __init__(self, name: str, *, interval_s: float = 1.0, changes=(1, 0, 0), boom=False):
        self.name = name
        self.interval_s = interval_s
        self._changes = list(changes)
        self._boom = boom
        self.calls = 0

    def reconcile(self) -> int:
        self.calls += 1
        if self._boom:
            raise RuntimeError(f"{self.name} exploded")
        return self._changes.pop(0) if self._changes else 0


# ------------------------------------------------------------------- one pass


def test_run_once_runs_every_reconciler_and_reports_changes():
    a, b = _Counter("a", changes=(3,)), _Counter("b", changes=(0,))
    results = asyncio.run(ReconciliationLoop([a, b]).run_once())

    assert [r.name for r in results] == ["a", "b"]
    assert results[0].changed == 3 and results[0].ok
    assert results[1].changed == 0 and results[1].ok


def test_a_converged_pass_reports_no_changes():
    """Idempotency: reconcile to a fixed point, then stay there."""
    r = _Counter("a", changes=(5, 0, 0))
    loop = ReconciliationLoop([r])

    asyncio.run(loop.run_once())
    second = asyncio.run(loop.run_once())
    third = asyncio.run(loop.run_once())

    assert second[0].changed == 0 and third[0].changed == 0


# -------------------------------------------------------------- error isolation


def test_a_failing_reconciler_does_not_stop_the_others():
    """THE loop property: reconcilers are independent, so one must not take the rest down."""
    boom = _Counter("boom", boom=True)
    fine = _Counter("fine", changes=(2,))

    results = asyncio.run(ReconciliationLoop([boom, fine]).run_once())

    assert not results[0].ok and "exploded" in results[0].error
    assert results[1].ok and results[1].changed == 2, "a sibling failure skipped a healthy reconciler"


def test_a_failure_is_reported_never_swallowed():
    """A silently-failing reconciler is worse than none — derived state rots invisibly."""
    seen: list[ReconcilerResult] = []
    asyncio.run(
        ReconciliationLoop([_Counter("boom", boom=True)], on_result=seen.append).run_once()
    )
    assert len(seen) == 1 and not seen[0].ok


def test_a_throwing_observer_cannot_break_reconciliation():
    """The on_result sink is observability — it must never be able to halt governance state."""
    def hostile(_r):
        raise RuntimeError("sink is down")

    results = asyncio.run(
        ReconciliationLoop([_Counter("a", changes=(1,))], on_result=hostile).run_once()
    )
    assert results[0].ok and results[0].changed == 1


def test_run_once_recovers_after_a_transient_failure():
    class _Flaky:
        name, interval_s = "flaky", 1.0

        def __init__(self):
            self.calls = 0

        def reconcile(self) -> int:
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("transient")
            return 0

    loop = ReconciliationLoop([_Flaky()])
    assert not asyncio.run(loop.run_once())[0].ok
    assert asyncio.run(loop.run_once())[0].ok


# ------------------------------------------------------------------- lifecycle


def test_periodic_respects_each_reconcilers_own_interval():
    """A cheap reconciler must not be dragged to an expensive one's cadence."""
    now = [0.0]
    fast = _Counter("fast", interval_s=1.0, changes=())
    slow = _Counter("slow", interval_s=10.0, changes=())

    due = periodic([fast, slow], last_run={}, now=now[0])
    assert {r.name for r in due} == {"fast", "slow"}, "first pass must run everything"

    last = {"fast": 0.0, "slow": 0.0}
    now[0] = 2.0
    due = periodic([fast, slow], last_run=last, now=now[0])
    assert [r.name for r in due] == ["fast"], "slow reconciler ran early"

    now[0] = 11.0
    due = periodic([fast, slow], last_run=last, now=now[0])
    assert {r.name for r in due} == {"fast", "slow"}


def test_start_then_stop_terminates_cleanly():
    async def drive():
        loop = ReconciliationLoop([_Counter("a", interval_s=0.01, changes=())], tick_s=0.005)
        await loop.start()
        await asyncio.sleep(0.05)
        await loop.stop()
        return loop

    loop = asyncio.run(drive())
    assert not loop.running


def test_the_loop_survives_a_reconciler_that_always_fails():
    """A permanently-broken reconciler must not silently kill the background loop."""
    async def drive():
        boom = _Counter("boom", interval_s=0.01, boom=True)
        loop = ReconciliationLoop([boom], tick_s=0.005)
        await loop.start()
        await asyncio.sleep(0.06)
        running = loop.running
        await loop.stop()
        return running, boom.calls

    running, calls = asyncio.run(drive())
    assert running, "the loop died on a reconciler exception"
    assert calls > 1, "the loop stopped retrying a failing reconciler"
