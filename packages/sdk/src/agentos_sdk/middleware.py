"""GovernanceMiddleware — the LangChain v1 PEP (INT-01 / SDK-01).

Source: 01-RESEARCH.md § "Interception (INT-01, SDK-01)" (the verified hook signature
and short-circuit code) + 01-AI-SPEC.md §4 "Tool Use"; CONTEXT.md D-01/D-03/D-07.

This is the Policy Enforcement Point. It intercepts every governed tool call BEFORE
it executes, normalizes it into a stable `AgentAction`, asks the in-process pipeline
(the PDP, D-07) for a `Decision`, and enforces it via the single shared posture
(`agentos_sdk.enforce.should_execute`, D-03):

  - executable (allow / warn / governance_review) -> call `handler(request)` so the
    tool runs;
  - anything else (deny, plus outcomes whose enforcement is not yet realized —
    interim fail-closed posture) -> return a `ToolMessage` carrying the fired reasons
    WITHOUT calling `handler`, so the tool never executes (no egress — the
    enforcement contract; threat T-01-19).

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

from langchain.agents.middleware import AgentMiddleware, ModelRequest, ToolCallRequest
from langchain.messages import AIMessage, ToolMessage

from agentos_contract import PipelineProtocol

from agentos_sdk.enforce import format_reasons, should_execute
from agentos_sdk.normalize import normalize_action, normalize_model_call


class GovernanceMiddleware(AgentMiddleware):
    """The PEP: intercept -> normalize -> evaluate -> enforce (executable runs / else blocks).

    Two native LangChain hooks are governed here: tool calls (INT-01) and model
    invocations (INT-02). Memory, MCP, and delegation are not LangChain middleware
    hooks — they are governed by the SDK wrappers in `agentos_sdk.wrappers`, sharing
    the same enforcement core (`agentos_sdk.enforce`).
    """

    def __init__(self, pipeline: PipelineProtocol, token: str) -> None:
        self._pipeline = pipeline  # the in-process PDP (D-07); satisfies PipelineProtocol
        self._token = token        # the agent's signed JWT (from registration, IDN-01)

    async def awrap_tool_call(self, request: ToolCallRequest, handler):
        """Async PEP hook (langchain 1.3.2). Executable runs the tool; else blocks egress."""
        action = normalize_action(request, self._token)
        decision = await self._pipeline.evaluate(action)
        if not should_execute(decision):
            # SHORT-CIRCUIT: do NOT call handler() -> the tool never executes (D-03).
            return ToolMessage(
                content=f"Blocked by agentos-guard: {format_reasons(decision)}",
                tool_call_id=request.tool_call["id"],
            )
        return await handler(request)  # executable -> the tool runs

    async def awrap_model_call(self, request: ModelRequest, handler):
        """Async PEP hook (INT-02). Executable invokes the model; else blocks the call.

        On a block the provider is NEVER called (handler is not awaited) — no prompt
        leaves the process — and an AIMessage carrying the fired reasons is returned in
        place of the model's response, so the agent loop sees an explainable block.
        """
        action = normalize_model_call(request, self._token)
        decision = await self._pipeline.evaluate(action)
        if not should_execute(decision):
            # SHORT-CIRCUIT: the model is never invoked (no prompt egress to the provider).
            return AIMessage(content=f"Blocked by agentos-guard: {format_reasons(decision)}")
        return await handler(request)  # executable -> the model is invoked
