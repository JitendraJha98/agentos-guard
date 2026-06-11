"""Shared enforcement core — one allow/deny primitive for every PEP form.

Phase 1 inlined "normalize -> evaluate -> allow runs / deny blocks" inside the tool
middleware. Phase 2 governs five action types across two interception shapes
(LangChain middleware hooks for tool/model; SDK wrappers for memory/MCP/delegation).
To guarantee they never diverge, the decision/enforcement logic lives here ONCE:

  - `format_reasons` — the compact, machine-readable reason summary (NEVER raw payload).
  - `GovernanceDenied` — the governed exception a wrapper raises on `deny`, carrying the
    `Decision` (with fired reasons) so the caller gets an explainable denial, not a
    silent failure. This is the "deny raises a governed exception with the decision
    reasons attached" enforcement contract from docs/architecture/03.
  - `should_execute` — the single shared enforcement posture: which outcomes may run
    the governed operation. Interim Phase-3 posture: outcomes whose enforcement is not
    yet realized BLOCK fail-closed (never silently execute).
  - `governed_call` — evaluate the action through the in-process pipeline (PDP); if
    `should_execute` says no, raise WITHOUT running the action (no side effect / no
    egress); otherwise run the action and return its result.

Every PEP form (middleware hooks AND wrappers) branches on `should_execute`, so the
posture cannot diverge across enforcement sites. The pipeline is typed structurally
(PipelineProtocol), so this package keeps its only internal dependencies on
agentos-contract + agentos-pipeline (no control-plane import).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import TypeVar

from agentos_contract import AgentAction, Decision, Outcome, PipelineProtocol

_T = TypeVar("_T")


def format_reasons(decision: Decision) -> str:
    """A compact, machine-readable summary of the fired reasons (NEVER raw payload)."""
    return "; ".join(f"{r.stage}:{r.code}" for r in decision.reasons)


# Interim Phase-3 posture: outcomes whose enforcement is not yet realized BLOCK
# fail-closed (Slices 6a/6b replace this with approval-blocking + the real outcome
# map). Executable now: allow (run), warn (run; advisory reasons ride on the
# Decision), governance_review (run; async review is non-blocking by definition).
_EXECUTABLE = frozenset({Outcome.allow, Outcome.warn, Outcome.governance_review})


def should_execute(decision: Decision) -> bool:
    """True if this outcome may run the governed operation under the interim posture."""
    return decision.outcome in _EXECUTABLE


class GovernanceDenied(Exception):
    """Raised when the pipeline denies an action — the governed exception (D-03).

    Carries the `Decision` so the fired reasons / evidence_ref are available to the
    caller. The action that triggered it was NOT executed (no side effect / no egress).
    """

    def __init__(self, decision: Decision) -> None:
        self.decision = decision
        super().__init__(f"Blocked by agentos-guard: {format_reasons(decision)}")


async def governed_call(
    pipeline: PipelineProtocol,
    action: AgentAction,
    run: Callable[[], Awaitable[_T]],
) -> _T:
    """Evaluate `action`; raise GovernanceDenied unless executable, else run.

    A non-executable outcome short-circuits BEFORE `run()` is awaited, so the governed
    operation never executes (the enforcement contract — no silent allow, no side
    effect on a block; interim fail-closed posture, see `should_execute`).
    """
    decision = await pipeline.evaluate(action)
    if not should_execute(decision):
        raise GovernanceDenied(decision)
    return await run()
