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
  - `governed_call` — evaluate the action through the in-process pipeline (PDP); on
    `deny`, raise WITHOUT running the action (no side effect / no egress); on any
    non-deny outcome, run the action and return its result.

The pipeline is typed structurally (PipelineProtocol), so this package keeps its only
internal dependencies on agentos-contract + agentos-pipeline (no control-plane import).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import TypeVar

from agentos_contract import AgentAction, Decision, Outcome, PipelineProtocol

_T = TypeVar("_T")


def format_reasons(decision: Decision) -> str:
    """A compact, machine-readable summary of the fired reasons (NEVER raw payload)."""
    return "; ".join(f"{r.stage}:{r.code}" for r in decision.reasons)


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
    """Evaluate `action`; on deny raise GovernanceDenied, else run and return result.

    `deny` short-circuits BEFORE `run()` is awaited, so the governed operation never
    executes (the enforcement contract — no silent allow, no side effect on deny).
    """
    decision = await pipeline.evaluate(action)
    if decision.outcome == Outcome.deny:
        raise GovernanceDenied(decision)
    return await run()
