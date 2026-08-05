"""Shared enforcement core — the ONE outcome-enforcement map for every PEP form.

PDP decides, PEP blocks: the pipeline returns a Decision and never sleeps;
everything that blocks (approval waits) or escalates (reviews, substitutions,
side-effect dispatch) happens HERE through injected seams, so middleware hooks
and SDK wrappers cannot diverge — they all call `governed_call`.

The outcome-enforcement map (replaces the interim `should_execute`, retired):

    allow, warn                -> execute
    temporary_exception        -> execute (a ratified allow; expiry was checked
                                  at decision time, POL-13)
    governance_review          -> open review via coordinator (non-blocking) + execute
    require_approval           -> park + block-await via coordinator;
                                  no coordinator -> GovernanceDenied (fail-closed)
    sandbox                    -> quarantine via the SandboxRunner seam (RUN-03):
                                  `run` is NEVER awaited -> GovernanceQuarantined;
                                  no runner -> GovernanceDenied (fail-closed)
    require_consensus          -> escalate to the approval path until POL-09
                                  (Slice 9f), audited as `enforcement_substitution`;
                                  no coordinator -> GovernanceDenied
    deny                       -> GovernanceDenied

Resource budgets (RUN-05, Slice 9c) wrap BOTH `await run()` sites through
`_run_within_limits`, so a per-agent wall/memory/network budget applies to a
directly-executable outcome AND to post-approval execution. The guarantees differ
per dimension and are stated honestly on `GovernanceResourceExceeded.preventive`:
network denial is preventive; a wall overrun is cancelled only when the handler is
suspended at an await, and is otherwise DETECTED AFTER COMPLETION (never silently
returned); the memory budget is detected at completion too, and is not evaluated at
all when another governed call overlapped the measurement window.

Circuit-breaker signals (RUN-06, Slice 9d) ride the same two run sites through
`_run_reported`: a governed execution that RAISES is an error the PDP cannot see,
so it is reported to the `CircuitReporter` seam. Governance blocks are explicitly
NOT reported — the PDP's graduated path already counted those, and counting them
here too would trip every breaker at twice the intended rate.

Review obligation survives escalation (D5): the review opens when the outcome is
`governance_review` OR any fired principle's effect was — a risk-escalated floor
keeps its review.

The collaborators are structural Protocols (no control-plane import): the
concrete coordinator is `agentos_controlplane.coordinator.StoreApprovalCoordinator`,
the concrete sandbox runner is `agentos_controlplane.sandbox.QuarantineSandbox`,
the concrete dispatcher arrives with PIPE-09 dispatch.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
import tracemalloc
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Protocol, TypeVar

from agentos_contract import (
    ActionType,
    AgentAction,
    Decision,
    Outcome,
    PipelineProtocol,
    SandboxResult,
)

_T = TypeVar("_T")


def format_reasons(decision: Decision) -> str:
    """A compact, machine-readable summary of the fired reasons (NEVER raw payload)."""
    return "; ".join(f"{r.stage}:{r.code}" for r in decision.reasons)


class ApprovalCoordinator(Protocol):
    """The PEP-side blocking/escalation seam (POL-07 / POL-14).

    `park_and_wait` persists the approval request and blocks on the STORE row
    (D3) until resolved or timed out; True means the action may run. The
    coordinator audits its own lifecycle (resolution/timeout/review/substitution
    events ride the one audit hash chain).
    """

    async def park_and_wait(self, action: AgentAction, decision: Decision) -> bool: ...

    async def open_review(self, action: AgentAction, decision: Decision) -> None: ...

    async def record_substitution(
        self, action: AgentAction, decision: Decision, *, requested: str, substituted: str
    ) -> None: ...


class SandboxRunner(Protocol):
    """RUN-03 seam: run the action in an isolated context with quarantined side effects.

    The concrete runner is `agentos_controlplane.sandbox.QuarantineSandbox`. It is NOT
    given the handler on purpose: quarantine means the real operation never runs, so
    there is nothing to invoke — the runner only observes, persists, and audits.
    """

    async def run(self, action: AgentAction, decision: Decision) -> SandboxResult: ...


class SideEffectDispatcher(Protocol):
    """The PIPE-09 dispatch seam: one audit event per Decision side effect."""

    async def dispatch(self, action: AgentAction, decision: Decision) -> None: ...


@dataclass(frozen=True)
class ResourceLimits:
    """RUN-05 per-agent execution budget. `None` on a field means NO limit for that dimension.

    Read the enforcement guarantees on `GovernanceResourceExceeded` before relying on these: they
    differ per dimension, and only `network` reliably PREVENTS the work — a `wall_s` overrun is
    prevented only when the cancellation can land, and is otherwise merely detected afterwards.
    """

    wall_s: float | None = None
    memory_mb: float | None = None
    network: str = "allow"  # "allow" | "deny"


class ResourceGovernor(Protocol):
    """RUN-05 seam. `limits_for` is called on EVERY executed action, so it MUST be an in-memory
    lookup (no DB read) — the concrete `ResourceGovernorStore` caches the table.
    `record_breach` audits the violation with short identifiers + numbers only.
    """

    def limits_for(self, agent_id: str) -> "ResourceLimits | None": ...

    async def record_breach(
        self, action: AgentAction, decision: Decision, *, limit: str, budget: float, observed: float
    ) -> None: ...


class CircuitReporter(Protocol):
    """RUN-06 seam (PEP side): report a governed EXECUTION failure, which the PDP cannot observe.

    The concrete reporter is `agentos_controlplane.circuit_breaker.CircuitBreakerStore`. Only
    FAILURES are reported here: success is the PDP's job (its graduated path already recorded it),
    and reporting it twice could close a breaker on the strength of one action.

    Note the honest ordering: the PDP records its closing signal for a PERMITTED DECISION, before the
    handler runs. A trial whose decision was permitted but whose execution then fails therefore closes
    the breaker and starts a fresh window from this failure — a repeat pattern still re-trips at the
    threshold, one round later.
    """

    async def record_failure(self, agent_id: str, target: str) -> None: ...


class GovernanceDenied(Exception):
    """Raised when a governed action may not run — the governed exception (D-03).

    Carries the `Decision` so the fired reasons / evidence_ref are available to the caller.

    Base-class guarantee: **the result is always withheld** from the caller. For this class itself and
    for `GovernanceQuarantined`, nothing ran either — no side effect, no egress. The one exception is
    `GovernanceResourceExceeded` with `preventive=False` (a RUN-05 budget detected at completion): the
    handler HAD already run, and its side effect stands. Callers that need to distinguish "nothing
    happened" from "it happened but is over budget" must check `preventive`; callers that simply treat
    every `GovernanceDenied` as "no usable result" stay correct.
    """

    def __init__(self, decision: Decision) -> None:
        self.decision = decision
        super().__init__(f"Blocked by agentos-guard: {format_reasons(decision)}")


class GovernanceQuarantined(GovernanceDenied):
    """A `sandbox` outcome (RUN-03): the action was OBSERVED in quarantine and its real
    side effect never happened.

    Subclasses `GovernanceDenied` deliberately: every existing `except GovernanceDenied`
    site (the LangChain hooks, user code) then treats a quarantine as a non-execution,
    so a caller can NEVER mistake it for a successful result. `sandbox_result` carries
    the observation.
    """

    def __init__(self, decision: Decision, result: SandboxResult) -> None:
        # Bypass GovernanceDenied.__init__ so the surfaced message says QUARANTINED
        # while the exception stays a GovernanceDenied for every catch site.
        Exception.__init__(
            self,
            f"Quarantined by agentos-guard (sandboxed, no real effect): "
            f"{format_reasons(decision)}",
        )
        self.decision = decision
        self.sandbox_result = result


class GovernanceResourceExceeded(GovernanceDenied):
    """RUN-05: the execution violated its per-agent resource budget.

    Subclasses `GovernanceDenied` so every existing catch site treats it as a governed block and the
    result is withheld from the caller. Read `preventive` carefully — it is the HONEST distinction
    between what this stage stops and what it only notices:

    * `network` -> `preventive=True`. The handler is never invoked: no egress, nothing happened.
    * `wall_s` -> `preventive` VARIES per breach, and the flag reports which one happened:
      - `True`  — the cancellation LANDED. That requires the handler to be suspended at an await when
        the expired deadline is processed; the work after that await never runs. Cancellation is NOT
        rollback: whatever the handler had already applied before the cancel point stays applied.
      - `False` — the handler ran to COMPLETION despite the deadline, because it blocked the event
        loop (synchronous CPU-bound work cannot be interrupted in-process) or swallowed its
        `CancelledError`. The overrun is then detected afterwards, with `observed` = the real elapsed
        seconds. The result is still withheld, but nothing was prevented.
      A `TimeoutError` raised by the handler ITSELF (an upstream socket read, say) is never a breach:
      it propagates unchanged, because only an expired deadline is a budget violation.
    * `memory_mb` -> `preventive=False`. The breach is detected at COMPLETION: the handler already
      ran and its side effect already happened. This reports and audits a budget violation and
      withholds the result; it does NOT prevent the allocation. It also measures the PEAK GROWTH in
      Python allocations during the call (`tracemalloc`), not RSS. And because those counters are
      PROCESS-GLOBAL, the budget is only evaluated when no other governed call overlapped this one:
      an overlapped window is logged as unmeasurable and yields NO verdict (no breach, no result
      withheld) rather than billing one agent for another's allocations.

    Kernel-enforced prevention needs a real boundary: the opt-in POSIX `setrlimit` path
    (`agentos_controlplane.posix_limits`), the gateway/sidecar (Phase 10), or K8s (Phase 14).
    """

    def __init__(
        self, decision: Decision, *, limit: str, budget: float, observed: float, preventive: bool
    ) -> None:
        # Bypass GovernanceDenied.__init__ so the surfaced message names the budget and states
        # plainly whether the work was blocked or merely detected afterwards.
        Exception.__init__(
            self,
            f"Resource limit exceeded ({limit}: budget={budget}, observed={observed}) — "
            f"{'blocked' if preventive else 'detected after completion'}: "
            f"{format_reasons(decision)}",
        )
        self.decision = decision
        self.limit = limit
        self.budget = budget
        self.observed = observed
        self.preventive = preventive


# Action types capable of leaving the process (egress), DIRECTLY or BY PROXY. A per-agent
# network="deny" refuses these BEFORE the handler runs.
#   * `delegation` is included: a sub-agent runs under its OWN agent_id, and resource budgets are not
#     among the attributes a delegation inherits (TRST-04 passes down trust, scope and ring), so the
#     child would be unbudgeted — dispatching one must not be a way to buy the egress the parent was
#     denied.
#   * `memory_access` is excluded: it is process-local, so a network budget must not break it.
_EGRESS_TYPES = frozenset(
    {
        ActionType.tool_call,
        ActionType.mcp_call,
        ActionType.model_invocation,
        ActionType.delegation,
    }
)

# Outcomes that run the governed operation directly (no coordinator involvement).
_EXECUTABLE = frozenset(
    {Outcome.allow, Outcome.warn, Outcome.temporary_exception, Outcome.governance_review}
)
# Outcomes whose dedicated enforcement is not realized until POL-09 (Slice 9f):
# substituted with the approval path, audited as such. `sandbox` LEFT this set in
# Slice 9a — RUN-03 containment is real now (see the `Outcome.sandbox` route below).
_SUBSTITUTED_TO_APPROVAL = frozenset({Outcome.require_consensus})


def _review_obliged(decision: Decision) -> bool:
    """POL-14 + D5: review on a governance_review OUTCOME or any fired principle
    whose effect was governance_review (the obligation survives risk escalation)."""
    if decision.outcome is Outcome.governance_review:
        return True
    return any(
        r.code == "constitution_principle_fired"
        and isinstance(r.evidence, dict)
        and r.evidence.get("effect") == Outcome.governance_review.value
        for r in decision.reasons
    )


# `tracemalloc`'s counters are PROCESS-GLOBAL, so a memory verdict is only sound when this execution
# was the ONLY governed execution running for its whole duration. Judging anyway bills one agent for
# another's allocations — a fabricated, hash-chained accusation against an agent that allocated
# nothing — and a concurrent window's `tracemalloc.stop()` can make a still-open one read (0, 0) and
# silently pass a real breach.
#
# EVERY governed execution registers here, not just memory-budgeted ones: an unbudgeted call (or one
# budgeted only on wall/network) allocates just the same, so counting only memory-budgeted windows
# would leave exactly that overlap invisible. `_exec_active` is how many are open right now,
# `_exec_opens` how many have ever opened; together they make any overlap DETECTABLE, and an
# unattributable window declines to judge instead of accusing. The lock keeps that true when governed
# calls run on event loops in different threads.
#
# Honest scope: this bounds FALSE accusations from concurrent GOVERNED work. Arbitrary non-governed
# allocation elsewhere in the process is still invisible to `tracemalloc`'s process-global counters, so
# the in-process memory budget is best-effort by nature — sound, kernel-enforced memory limits are the
# capability-gated `RLIMIT_AS` path (`agentos_controlplane.posix_limits`) and the gateway/K8s layer.
_exec_lock = threading.Lock()
_exec_active = 0
_exec_opens = 0


def _open_exec_window() -> tuple[bool, int]:
    """Register a governed execution; returns (nothing else was open at entry, the open-count now)."""
    global _exec_active, _exec_opens
    with _exec_lock:
        outermost = _exec_active == 0
        _exec_active += 1
        _exec_opens += 1
        return outermost, _exec_opens


def _close_exec_window() -> None:
    global _exec_active
    with _exec_lock:
        _exec_active -= 1


def _exclusive_since(opens_at_entry: int) -> bool:
    """True when NO other governed execution opened since this one began AND none is still open —
    i.e. this window had the process's governed activity to itself, so a peak IS attributable."""
    with _exec_lock:
        return _exec_opens == opens_at_entry and _exec_active == 1


async def _run_within_limits(
    run: Callable[[], Awaitable[_T]],
    action: AgentAction,
    decision: Decision,
    governor: ResourceGovernor | None,
) -> _T:
    """RUN-05: apply the agent's execution budget around `run()`.

    Unwired or unlimited agents take the ZERO-OVERHEAD path — no `tracemalloc`, no timeout, just the
    pre-9c `await run()` plus the overlap bookkeeping every governed execution owes its peers (a lock
    and two integer increments; see `_open_exec_window` for why the unbudgeted path must register too).
    """
    # EVERY execution registers, budgeted or not: `tracemalloc` is process-global, so an unbudgeted
    # (or wall-only) call running concurrently would otherwise be invisible and its allocations would
    # be charged to an innocent memory-budgeted agent.
    outermost, opens_at_entry = _open_exec_window()
    try:
        return await _run_within_limits_inner(
            run, action, decision, governor, outermost, opens_at_entry
        )
    finally:
        _close_exec_window()


async def _run_within_limits_inner(
    run: Callable[[], Awaitable[_T]],
    action: AgentAction,
    decision: Decision,
    governor: ResourceGovernor | None,
    outermost: bool,
    opens_at_entry: int,
) -> _T:
    """The budget logic itself. Split out so the overlap window is opened and closed on EVERY path
    (including the zero-overhead early returns) without duplicating a try/finally per branch."""
    if governor is None:
        return await run()
    limits = governor.limits_for(action.agent_id)
    if limits is None:
        return await run()

    # network: refuse BEFORE invoking the handler. This one is genuinely preventive.
    if limits.network == "deny" and action.type in _EGRESS_TYPES:
        await governor.record_breach(action, decision, limit="network", budget=0.0, observed=1.0)
        raise GovernanceResourceExceeded(
            decision, limit="network", budget=0.0, observed=1.0, preventive=True
        )

    track = limits.memory_mb is not None
    started_tracing = False
    baseline = 0
    if track:
        # An inner window must not touch the tracer at all: `reset_peak()` would clobber the peak the
        # outer window is still charging against, and its verdict is skipped anyway.
        if outermost:
            if not tracemalloc.is_tracing():
                tracemalloc.start()
                started_tracing = True
            # `reset_peak()` sets the peak to the CURRENT traced size, not to zero — so the budget is
            # charged against the GROWTH above this baseline. Measuring the absolute peak instead
            # would bill every call for whatever the process was already holding, and a long-lived
            # agent would start false-breaching on its first governed call after any big allocation.
            tracemalloc.reset_peak()
            baseline = tracemalloc.get_traced_memory()[0]
    measurable = False
    peak_mb = 0.0
    started = time.monotonic()
    deadline: asyncio.Timeout | None = None
    try:
        if limits.wall_s is None:
            result = await run()
        else:
            # `asyncio.timeout` rather than `wait_for` because `expired()` says EXACTLY whether the
            # deadline fired, which is the only thing that makes a TimeoutError a budget breach.
            async with asyncio.timeout(limits.wall_s) as deadline:
                result = await run()
    except (asyncio.TimeoutError, TimeoutError):
        if deadline is None or not deadline.expired():
            # The handler's OWN timeout (an upstream socket read, say). Reclassifying it would audit
            # an evidence-grade breach of a budget that was never violated AND suppress the real
            # failure, so it propagates untouched.
            raise
        await governor.record_breach(
            action, decision, limit="wall_s", budget=limits.wall_s, observed=limits.wall_s
        )
        # preventive=True: the cancellation LANDED at the handler's await point. It is not rollback —
        # anything applied before the cancel point stays applied.
        raise GovernanceResourceExceeded(
            decision,
            limit="wall_s",
            budget=limits.wall_s,
            observed=limits.wall_s,
            preventive=True,
        ) from None
    finally:
        if track:
            # Judge ONLY if this execution had the process's governed activity to itself for its whole
            # duration — nothing else open at entry (`outermost`) and nothing else opened or still open
            # now. Otherwise the peak is unattributable and we decline to judge rather than accuse.
            # (The window itself is closed by the caller's finally, on every unwind path.)
            measurable = outermost and _exclusive_since(opens_at_entry)
            if measurable:
                peak_mb = (tracemalloc.get_traced_memory()[1] - baseline) / (1024 * 1024)
            # Only stop what we started: a caller already profiling keeps its tracer, and a
            # governed process never silently acquires tracemalloc's overhead for good.
            if started_tracing:
                tracemalloc.stop()

    elapsed = time.monotonic() - started
    if limits.wall_s is not None and elapsed > limits.wall_s:
        # The deadline passed yet the handler still completed — it blocked the loop or swallowed its
        # CancelledError. preventive=False: post-hoc detection, the same honest treatment memory gets.
        # Returning the result here would make the wall budget silently escapable.
        await governor.record_breach(
            action, decision, limit="wall_s", budget=limits.wall_s, observed=elapsed
        )
        raise GovernanceResourceExceeded(
            decision, limit="wall_s", budget=limits.wall_s, observed=elapsed, preventive=False
        )
    if track and not measurable:
        # Refuse to judge rather than guess: no breach, no withheld result — but never silent.
        logging.getLogger(__name__).warning(
            "memory budget unmeasurable for agent %s action %s: another governed call overlapped "
            "this one and tracemalloc counters are process-global, so no verdict was reached",
            action.agent_id,
            action.id,
        )
    elif limits.memory_mb is not None and peak_mb > limits.memory_mb:
        await governor.record_breach(
            action, decision, limit="memory_mb", budget=limits.memory_mb, observed=peak_mb
        )
        # preventive=False: the handler ALREADY ran. This reports the violation and withholds the
        # result — it did not stop the allocation or the side effect.
        raise GovernanceResourceExceeded(
            decision,
            limit="memory_mb",
            budget=limits.memory_mb,
            observed=peak_mb,
            preventive=False,
        )
    return result


async def _run_reported(
    run: Callable[[], Awaitable[_T]],
    action: AgentAction,
    decision: Decision,
    governor: ResourceGovernor | None,
    reporter: CircuitReporter | None,
) -> _T:
    """RUN-06: a governed execution that RAISES is an error signal for the breaker. A governance block
    the PDP already counted is NOT an execution error — double-counting it would trip breakers twice as
    fast — but a RUN-05 budget breach is, because the PDP counted a PERMITTED decision for it."""
    try:
        return await _run_within_limits(run, action, decision, governor)
    except GovernanceResourceExceeded:
        # Raised at the EXECUTION site, after the PDP recorded a permitted decision — so nothing has
        # counted this yet. An agent that blows its wall/memory budget on every call must be able to
        # trip a breaker; that runaway is exactly what a breaker exists to contain.
        if reporter is not None:
            await reporter.record_failure(action.agent_id, action.target)
        raise
    except GovernanceDenied:
        # A block raised from INSIDE the run — a NESTED governed_call, say — was already counted by
        # the PDP that produced it. (deny / sandbox are raised at the decision site, never here.)
        raise
    except Exception:
        if reporter is not None:
            await reporter.record_failure(action.agent_id, action.target)
        raise


async def governed_call(
    pipeline: PipelineProtocol,
    action: AgentAction,
    run: Callable[[], Awaitable[_T]],
    *,
    coordinator: ApprovalCoordinator | None = None,
    dispatcher: SideEffectDispatcher | None = None,
    sandbox: SandboxRunner | None = None,
    governor: ResourceGovernor | None = None,
    reporter: CircuitReporter | None = None,
) -> _T:
    """Evaluate `action` and enforce the outcome map; `run` executes only when
    the map says so (after the approval resolves, for blocking outcomes).

    A blocking outcome without a coordinator raises GovernanceDenied BEFORE
    `run()` is awaited — fail-closed, never silent execution (the enforcement
    contract: no side effect / no egress on a block).
    """
    decision = await pipeline.evaluate(action)
    if dispatcher is not None:
        # PIPE-09: side effects ride EVERY decision (a deny can still risk_flag).
        await dispatcher.dispatch(action, decision)
    if _review_obliged(decision):
        if coordinator is not None:
            # POL-14: open the async review — non-blocking; never awaited-on.
            await coordinator.open_review(action, decision)
        else:
            # Execution still proceeds (non-blocking semantics), but a dropped
            # review obligation must never vanish silently.
            logging.getLogger(__name__).warning(
                "governance_review obligation dropped for action %s: "
                "no coordinator wired to open the review",
                action.id,
            )
    outcome = decision.outcome
    if outcome in _EXECUTABLE:
        return await _run_reported(run, action, decision, governor, reporter)
    if outcome is Outcome.deny:
        raise GovernanceDenied(decision)
    if outcome is Outcome.sandbox:
        # RUN-03: real containment. `run` is NEVER awaited on this path — no side
        # effect, no egress. No runner wired -> fail closed, exactly like a blocking
        # outcome without a coordinator.
        if sandbox is None:
            raise GovernanceDenied(decision)
        result = await sandbox.run(action, decision)
        raise GovernanceQuarantined(decision, result)
    # Blocking outcomes from here: require_approval natively; require_consensus
    # escalated onto the same path (audited substitution) until Slice 9f.
    if coordinator is None:
        raise GovernanceDenied(decision)  # fail-closed: nothing can block-await
    if outcome in _SUBSTITUTED_TO_APPROVAL:
        await coordinator.record_substitution(
            action,
            decision,
            requested=outcome.value,
            substituted=Outcome.require_approval.value,
        )
    approved = await coordinator.park_and_wait(action, decision)
    if not approved:
        raise GovernanceDenied(decision)
    # RUN-05 applies to the POST-APPROVAL run site too — otherwise requesting approval would be a
    # trivial way to buy an unbudgeted execution. RUN-06 reporting wraps it for the same reason.
    return await _run_reported(run, action, decision, governor, reporter)
