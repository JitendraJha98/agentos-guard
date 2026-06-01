"""GovernanceMiddleware — the LangChain v1 PEP (INT-01 / SDK-01).

Source: 01-RESEARCH.md § "Interception (INT-01, SDK-01)" (the verified hook signature
and short-circuit code) + 01-AI-SPEC.md §4 "Tool Use"; CONTEXT.md D-01/D-03/D-07.

This is the Policy Enforcement Point. It intercepts every governed tool call BEFORE
it executes, normalizes it into a stable `AgentAction`, asks the in-process pipeline
(the PDP, D-07) for a `Decision`, and enforces it — that is the entire allow/deny
mechanism (D-03):

  - allow -> call `handler(request)` so the tool runs;
  - deny  -> return a `ToolMessage` carrying the fired reasons WITHOUT calling
             `handler`, so the tool never executes (no egress — the enforcement
             contract; threat T-01-19).

Async-hook resolution (Open Q2 / Assumption A3, RESOLVED 2026-06-02): langchain 1.3.2
exposes `awrap_tool_call(self, request, handler)` whose `handler` returns an Awaitable.
We use that async path and `await pipeline.evaluate(action)` directly, so the pipeline
and its async audit write run inside the existing LangGraph event loop. We never spin a
nested event loop inside the hook (no asyncio runner call) — the hook already runs in a
running loop, so doing so would raise RuntimeError (threat T-01-22; AI-SPEC §4b).

This package depends ONLY on agentos-contract + agentos-pipeline. No PEP-specific logic
leaks into the PDP (Anti-Pattern 5) — the pipeline sees only the AgentAction; it owns
the audit writer it was constructed with.
"""

from __future__ import annotations

from langchain.agents.middleware import AgentMiddleware, ToolCallRequest
from langchain.messages import ToolMessage

from agentos_contract import Outcome, PipelineProtocol

from agentos_sdk.normalize import normalize_action


def _format_reasons(decision) -> str:
    """A compact, machine-readable summary of the fired reasons (NEVER raw payload)."""
    return "; ".join(f"{r.stage}:{r.code}" for r in decision.reasons)


class GovernanceMiddleware(AgentMiddleware):
    """The PEP: intercept -> normalize -> evaluate -> enforce (allow runs / deny blocks)."""

    def __init__(self, pipeline: PipelineProtocol, token: str) -> None:
        self._pipeline = pipeline  # the in-process PDP (D-07); satisfies PipelineProtocol
        self._token = token        # the agent's signed JWT (from registration, IDN-01)

    async def awrap_tool_call(self, request: ToolCallRequest, handler):
        """Async PEP hook (langchain 1.3.2). Allow runs the tool; deny blocks egress."""
        action = normalize_action(request, self._token)
        decision = await self._pipeline.evaluate(action)
        if decision.outcome == Outcome.deny:
            # SHORT-CIRCUIT: do NOT call handler() -> the tool never executes (D-03).
            return ToolMessage(
                content=f"Blocked by agentos-guard: {_format_reasons(decision)}",
                tool_call_id=request.tool_call["id"],
            )
        return await handler(request)  # allow -> the tool executes
