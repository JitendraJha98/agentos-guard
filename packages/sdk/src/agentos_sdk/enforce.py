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
    sandbox, require_consensus -> escalate to the approval path until RUN-03/POL-09
                                  (Phase 9), audited as `enforcement_substitution`;
                                  no coordinator -> GovernanceDenied
    deny                       -> GovernanceDenied

Review obligation survives escalation (D5): the review opens when the outcome is
`governance_review` OR any fired principle's effect was — a risk-escalated floor
keeps its review.

The collaborators are structural Protocols (no control-plane import): the
concrete coordinator is `agentos_controlplane.coordinator.StoreApprovalCoordinator`,
the concrete dispatcher arrives with PIPE-09 dispatch.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import Protocol, TypeVar

from agentos_contract import AgentAction, Decision, Outcome, PipelineProtocol

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


class SideEffectDispatcher(Protocol):
    """The PIPE-09 dispatch seam: one audit event per Decision side effect."""

    async def dispatch(self, action: AgentAction, decision: Decision) -> None: ...


class GovernanceDenied(Exception):
    """Raised when a governed action may not run — the governed exception (D-03).

    Carries the `Decision` so the fired reasons / evidence_ref are available to the
    caller. The action that triggered it was NOT executed (no side effect / no egress).
    """

    def __init__(self, decision: Decision) -> None:
        self.decision = decision
        super().__init__(f"Blocked by agentos-guard: {format_reasons(decision)}")


# Outcomes that run the governed operation directly (no coordinator involvement).
_EXECUTABLE = frozenset(
    {Outcome.allow, Outcome.warn, Outcome.temporary_exception, Outcome.governance_review}
)
# Outcomes whose dedicated enforcement is not realized until RUN-03/POL-09
# (Phase 9): substituted with the approval path, audited as such.
_SUBSTITUTED_TO_APPROVAL = frozenset({Outcome.sandbox, Outcome.require_consensus})


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


async def governed_call(
    pipeline: PipelineProtocol,
    action: AgentAction,
    run: Callable[[], Awaitable[_T]],
    *,
    coordinator: ApprovalCoordinator | None = None,
    dispatcher: SideEffectDispatcher | None = None,
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
        return await run()
    if outcome is Outcome.deny:
        raise GovernanceDenied(decision)
    # Blocking outcomes from here: require_approval natively; sandbox /
    # require_consensus escalated onto the same path (audited substitution).
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
    return await run()
