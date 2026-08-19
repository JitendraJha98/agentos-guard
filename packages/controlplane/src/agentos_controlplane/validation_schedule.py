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

BUT A DECISION IS NOT FREE, AND THAT IS THE SECOND HALF OF D-1. `evaluate` is not read-only: it
appends an audit record, feeds the RUN-06 circuit breaker, and supplies the TRST-03 reputation signal
that `TrustReconciler` persists. A pass is N attacks, all of them denied by a HEALTHY guard — which
is precisely a burst of `deny` records under whatever identity the probe used. Pointed at the
production agent, one pass opens that agent's breaker (default threshold 5) and floors its
reputation, and the timer then does it again forever: the health check causes the outage, and does it
MORE reliably the better the guard is. So the probe identity is a SEPARATE, required principal
(`probe_agent_id`), and pointing it at the validated agent is refused at construction. The deployment
registers that principal with the same trust and posture as the target; the trend is filed under the
TARGET, because "is agent X's guard holding" is the question, and the answer is only as good as that
mirroring. Say so on the dashboard rather than letting a reader assume it was X itself.

IT ALSO COSTS INFERENCE. The interpreter runs on policy `no_match` (POL-04) and carries a
`payload_excerpt` of the action, so against an interpreter-wired pipeline a pass makes real provider
calls with attack text in them — billed, and drawn against the agent's own ECON-02 budget. At the
default interval that is a few hundred calls a day. It is inside D-1 (the interpreter is part of the
PDP, not execution) but it is not free, and an operator choosing the interval should know it.

WHAT IT DETECTS, STATED HONESTLY. Regression, not novelty. It re-runs a fixed, shipped corpus against
the live decision path, so it answers "did something that used to be blocked stop being blocked?".
It is not a pentest and it discovers nothing new; Phase 14's self-play is where novel attacks come
from. An operator who reads a flat green line as "we are secure" is reading more than it says.
"""

from __future__ import annotations

import asyncio
import logging

from agentos_contract import ActionType, AgentAction

from agentos_controlplane.reconcile import DEFAULT_INTERVALS

_log = logging.getLogger(__name__)

# A pass writes to the audit hash chain — one record per probe plus one `validation_run` event — on
# the same serialized write path the hot path uses. `interval_s=0` would run it every loop tick, so
# the interval has a floor rather than only a positivity check: this is the one reconciler whose
# cost is paid in audit appends and (on `no_match`) provider calls.
_MIN_INTERVAL_S = 60.0

# Well under the interval, and it has to be: `run_once` is SEQUENTIAL and `_loop` awaits it, so a
# probe that never returns does not merely lose this pass — it stops constitution, trust, graph,
# cache and budget reconciliation for good, and `stop()` never returns either. The wait is genuinely
# unbounded (the interpreter is a remote call, and a red-team corpus is exactly the `no_match`
# population that reaches it), so it is bounded HERE.
_DEFAULT_SUITE_TIMEOUT_S = 60.0

# Not a corpus target and carries no payload: the control probe must prove the probe identity reaches
# the policy engine WITHOUT being an attack itself, and a distinct target keeps it off the breaker
# window of any real tool.
_CONTROL_TARGET = "validation_control"


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
        agent_id: str,  # the agent whose guard this measures — the TREND key
        probe_agent_id: str,  # who the probes run AS; see the module docstring
        probe_token: str,
        interval_s: float = DEFAULT_INTERVALS["validation"],
        suite_timeout_s: float = _DEFAULT_SUITE_TIMEOUT_S,
    ) -> None:
        suites = tuple(suites)
        if not suites:
            # A reconciler with nothing to run reports a clean converged pass forever, which reads
            # exactly like a guard that is holding. Refuse the configuration instead.
            raise ValueError("suites must not be empty; a validation loop with no suites is silent")
        if probe_agent_id == agent_id:
            # The whole of the second D-1 half, enforced rather than documented: probing as the
            # production agent trips its breaker and floors its reputation every pass.
            raise ValueError(
                f"probe_agent_id must differ from agent_id ({agent_id!r}): scheduled probes are "
                "denied by a healthy guard, and those denials feed the RUN-06 breaker and TRST-03 "
                "reputation of whatever identity they ran as. Register a separate validation "
                "principal mirroring the target's trust and posture."
            )
        if interval_s < _MIN_INTERVAL_S:
            raise ValueError(f"interval_s must be at least {_MIN_INTERVAL_S}s; got {interval_s}")
        if suite_timeout_s <= 0:
            raise ValueError(f"suite_timeout_s must be positive; got {suite_timeout_s}")
        self._store = store
        self._evaluate = evaluate
        self._run_suite = run_suite
        self._suites = suites
        self._agent_id = agent_id
        self._probe_agent_id = probe_agent_id
        self._probe_token = probe_token
        self.interval_s = interval_s
        self._suite_timeout_s = suite_timeout_s

    async def reconcile_async(self) -> int:
        """Run every suite once and record each result. Returns suites RECORDED.

        THIS ONE NEVER CONVERGES, unlike its four siblings. The loop's contract reads `changed == 0`
        as converged and constant churn as a bug; here a healthy pass reports `len(suites)` forever
        and a FALL is the alarm. The number is "suites successfully measured", and it is at its
        maximum when everything is fine — the opposite direction from every other reconciler, so any
        alert built on the loop's own invariant has to be told about this one.

        Sequential rather than concurrent: this competes with real traffic for the same pipeline,
        and a scheduler that fans the whole corpus at a live PDP is a self-inflicted load spike on
        the hot path it is supposed to be observing.

        A failing suite is isolated rather than fatal, the Phase-7 reconciler lesson: a loop that
        dies on one bad suite stops producing the signal it exists for, and a validation loop that
        silently stopped running is indistinguishable from a guard that is holding. Both halves are
        inside the guard — a probe that raised and a run that could not be persisted are the same
        outage through different doors.

        But TOTAL failure is not isolated, and that asymmetry is the point. Partial failure still
        produces a signal; a pass where every suite failed produces none, and reporting that as
        `changed=0` hands the health surface the loop's word for CONVERGED. The two states an
        operator most needs to tell apart would render identically. So it raises, the loop records an
        error result, and the next pass runs regardless.
        """
        await self._assert_the_probe_reaches_policy()
        recorded = 0
        for suite in self._suites:
            try:
                results = await asyncio.wait_for(
                    self._run_suite(
                        self._evaluate,
                        suite,
                        agent_id=self._probe_agent_id,
                        token=self._probe_token,
                    ),
                    timeout=self._suite_timeout_s,
                )
                await self._store.record(self._agent_id, suite, results, source="scheduled")
                recorded += 1
            except Exception:
                # Logged, never swallowed: a pass that recorded fewer suites than it was asked for
                # leaves an operator reading a partial trend as a complete one.
                _log.warning("scheduled validation of suite %r failed", suite, exc_info=True)
        if recorded == 0:
            raise RuntimeError(
                f"every scheduled suite failed ({len(self._suites)} of {len(self._suites)}); "
                "the trend gained no point this pass"
            )
        return recorded

    async def _assert_the_probe_reaches_policy(self) -> None:
        """Refuse the pass unless the probe identity actually reaches the policy engine.

        Without this, the loop's most reassuring output is also its most broken one. If the probe
        token expired, the probe agent was kill-switched, or its breaker opened, EVERY probe
        short-circuits to `deny` before policy runs — and `deny` is a blocking outcome, so the pass
        records 100% blocked, ASR 0.0, "the guard blocked every attack". The operator sees a flat
        green line produced by a policy path that was never exercised at all. That disguise is
        stronger than silence, because it is positive evidence for the wrong conclusion.

        The check asserts the POSITIVE — a decision that reached stage 3 always carries a
        `stage="policy"` reason, either `constitution_principle_fired` or `no_principle_matched` —
        rather than enumerating the short-circuits, which would have to be kept in step with the
        pipeline's stage list from over here. The OUTCOME is deliberately not checked: what is benign
        under one constitution is denied under another, and this asks whether the engine ran, not
        what it said.
        """
        control = AgentAction(
            agent_id=self._probe_agent_id,
            type=ActionType.tool_call,
            target=_CONTROL_TARGET,
            identity_token=self._probe_token,
        )
        decision = await asyncio.wait_for(self._evaluate(control), timeout=self._suite_timeout_s)
        if not any(reason.stage == "policy" for reason in decision.reasons):
            raise RuntimeError(
                f"validation control probe as {self._probe_agent_id!r} never reached the policy "
                f"stage (outcome {getattr(decision.outcome, 'value', decision.outcome)!r}, stages "
                f"{sorted({r.stage for r in decision.reasons})}); every attack would score as "
                "blocked without the guard being exercised"
            )
