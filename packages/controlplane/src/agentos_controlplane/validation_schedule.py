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
the breach it detects is the worst outcome this phase could produce. The seam is injected as a bare
callable rather than as an agent object, so there is nothing on this class from which a later edit
could reach an execution path.

WHAT IT DETECTS, STATED HONESTLY. Regression, not novelty. It re-runs a fixed, shipped corpus against
the live decision path, so it answers "did something that used to be blocked stop being blocked?".
It is not a pentest and it discovers nothing new; Phase 14's self-play is where novel attacks come
from. An operator who reads a flat green line as "we are secure" is reading more than it says.
"""

from __future__ import annotations

import logging

from agentos_controlplane.reconcile import DEFAULT_INTERVALS

_log = logging.getLogger(__name__)


class ValidationReconciler:
    """API-04 reconciler that re-runs the red-team suites against the live decision path.

    `run_suite` is INJECTED rather than imported: it lives in `agentos_sdk.redteam` and the control
    plane does not import the SDK (STATE.md records one undeclared edge already; this does not add a
    second). `evaluate` is the live `Pipeline.evaluate`.

    ASYNC on purpose, and it is the loop's `reconcile_async` path — not `reconcile` — because its
    work is awaiting the LIVE pipeline. `ReconciliationLoop` runs the sync shape through
    `asyncio.to_thread`, and a suite driven from a worker thread would have to spin a SECOND event
    loop for a pipeline whose async state belongs to the first: a harder-to-find version of the very
    mismatch the sync/async split exists to prevent.
    """

    name = "validation"

    def __init__(
        self,
        store,  # ValidationStore
        evaluate,  # the LIVE pipeline's evaluate (async)
        run_suite,  # agentos_sdk.redteam.run_suite (async, evaluate-only)
        suites,  # the suite names to run
        *,
        agent_id: str,
        token: str,
        interval_s: float = DEFAULT_INTERVALS["validation"],
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

        Sequential rather than concurrent: this competes with real traffic for the same pipeline,
        and a scheduler that fans the whole corpus at a live PDP is a self-inflicted load spike on
        the hot path it is supposed to be observing.

        A failing suite is isolated rather than fatal, the Phase-7 reconciler lesson: a loop that
        dies on one bad suite stops producing the signal it exists for, and a validation loop that
        silently stopped running is indistinguishable from a guard that is holding. Both halves are
        inside the guard — a probe that raised and a run that could not be persisted are the same
        outage through different doors.
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
                # Logged, never swallowed: a pass that recorded fewer suites than it was asked for
                # leaves an operator reading a partial trend as a complete one.
                _log.warning("scheduled validation of suite %r failed", suite, exc_info=True)
        return recorded
