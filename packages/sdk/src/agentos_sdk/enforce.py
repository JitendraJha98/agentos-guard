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
network denial is preventive, wall cancellation is preventive-but-cooperative (and
is not rollback), and the memory budget is DETECTED AT COMPLETION.

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
    differ per dimension, and only `network` (and `wall_s`, cooperatively) actually PREVENT the work.
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


class GovernanceDenied(Exception):
    """Raised when a governed action may not run — the governed exception (D-03).

    Carries the `Decision` so the fired reasons / evidence_ref are available to the
    caller. The action that triggered it was NOT executed (no side effect / no egress).
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
    * `wall_s` -> `preventive=True`, but COOPERATIVELY. An awaiting handler is cancelled, so the
      work after the await never runs. A synchronous CPU-bound handler that never yields to the
      event loop CANNOT be interrupted in-process, and cancellation is NOT rollback — whatever the
      handler had already applied before the cancel point stays applied.
    * `memory_mb` -> `preventive=False`. The breach is detected at COMPLETION: the handler already
      ran and its side effect already happened. This reports and audits a budget violation and
      withholds the result; it does NOT prevent the allocation. It also measures the PEAK GROWTH in
      Python allocations during the call (`tracemalloc`), not RSS.

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


# Action types capable of leaving the process (egress). A per-agent network="deny" refuses these
# BEFORE the handler runs. A memory access is process-local, so a network budget must not break it.
_EGRESS_TYPES = frozenset({ActionType.tool_call, ActionType.mcp_call, ActionType.model_invocation})

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


async def _run_within_limits(
    run: Callable[[], Awaitable[_T]],
    action: AgentAction,
    decision: Decision,
    governor: ResourceGovernor | None,
) -> _T:
    """RUN-05: apply the agent's execution budget around `run()`.

    Unwired or unlimited agents take the ZERO-OVERHEAD path — no `tracemalloc`, no `wait_for` — so
    the default hot path is byte-for-byte the pre-9c `await run()`.
    """
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
        if not tracemalloc.is_tracing():
            tracemalloc.start()
            started_tracing = True
        # `reset_peak()` sets the peak to the CURRENT traced size, not to zero — so the budget is
        # charged against the GROWTH above this baseline. Measuring the absolute peak instead would
        # bill every call for whatever the process was already holding, and a long-lived agent would
        # start false-breaching on its first governed call after any large allocation.
        tracemalloc.reset_peak()
        baseline = tracemalloc.get_traced_memory()[0]
    peak_mb = 0.0
    try:
        if limits.wall_s is not None:
            result = await asyncio.wait_for(run(), timeout=limits.wall_s)
        else:
            result = await run()
    except (asyncio.TimeoutError, TimeoutError):
        await governor.record_breach(
            action, decision, limit="wall_s", budget=limits.wall_s, observed=limits.wall_s
        )
        # preventive=True but cooperative: the handler was cancelled at its await point, and
        # anything it had already applied is NOT rolled back.
        raise GovernanceResourceExceeded(
            decision,
            limit="wall_s",
            budget=limits.wall_s,
            observed=limits.wall_s,
            preventive=True,
        ) from None
    finally:
        if track:
            peak_mb = (tracemalloc.get_traced_memory()[1] - baseline) / (1024 * 1024)
            # Only stop what we started: a caller already profiling keeps its tracer, and a
            # governed process never silently acquires tracemalloc's overhead for good.
            if started_tracing:
                tracemalloc.stop()

    if limits.memory_mb is not None and peak_mb > limits.memory_mb:
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


async def governed_call(
    pipeline: PipelineProtocol,
    action: AgentAction,
    run: Callable[[], Awaitable[_T]],
    *,
    coordinator: ApprovalCoordinator | None = None,
    dispatcher: SideEffectDispatcher | None = None,
    sandbox: SandboxRunner | None = None,
    governor: ResourceGovernor | None = None,
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
        return await _run_within_limits(run, action, decision, governor)
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
    # trivial way to buy an unbudgeted execution.
    return await _run_within_limits(run, action, decision, governor)
