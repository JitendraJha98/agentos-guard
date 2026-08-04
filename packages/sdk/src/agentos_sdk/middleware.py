"""GovernanceMiddleware — the LangChain v1 PEP (INT-01 / INT-02 / SDK-01).

Source: 01-RESEARCH.md § "Interception (INT-01, SDK-01)" (the verified hook signature
and short-circuit code) + 01-AI-SPEC.md §4 "Tool Use"; CONTEXT.md D-01/D-03/D-07.

This is the Policy Enforcement Point. It intercepts every governed tool call BEFORE
it executes, normalizes it into a stable `AgentAction`, and delegates to the ONE
enforcement core (`agentos_sdk.enforce.governed_call`) — the same outcome map the
SDK wrappers use, with the same injected coordinator/dispatcher seams, so the
posture cannot diverge across enforcement sites (Slice 6b unification).

Block surfacing is the only hook-specific part: a wrapper raises GovernanceDenied;
a LangChain hook must NOT raise into the agent loop, so each hook catches the
governed exception and surfaces the block as its native message type (ToolMessage
for tools — with `status="error"`, so a block/quarantine is never structurally a
success — and AIMessage for model calls) carrying the fired reasons. Either way the
governed operation never executed (no egress — the enforcement contract; T-01-19).

Async-hook resolution (Open Q2 / Assumption A3, RESOLVED 2026-06-02): langchain 1.3.2
exposes `awrap_tool_call(self, request, handler)` whose `handler` returns an Awaitable.
We use that async path and await the pipeline directly, so the pipeline and its async
audit write run inside the existing LangGraph event loop. We never spin a nested event
loop inside the hook (no asyncio runner call) — the hook already runs in a running
loop, so doing so would raise RuntimeError (threat T-01-22; AI-SPEC §4b).

This package depends ONLY on agentos-contract + agentos-pipeline. No PEP-specific logic
leaks into the PDP (Anti-Pattern 5) — the pipeline sees only the AgentAction; it owns
the audit writer it was constructed with.
"""

from __future__ import annotations

from langchain.agents.middleware import AgentMiddleware, ModelRequest, ToolCallRequest
from langchain.messages import AIMessage, ToolMessage

from agentos_contract import PipelineProtocol

from agentos_sdk.enforce import (
    ApprovalCoordinator,
    GovernanceDenied,
    SandboxRunner,
    SideEffectDispatcher,
    governed_call,
)
from agentos_sdk.normalize import normalize_action, normalize_model_call


class GovernanceMiddleware(AgentMiddleware):
    """The PEP: intercept -> normalize -> `governed_call` (the one outcome map).

    Two native LangChain hooks are governed here: tool calls (INT-01) and model
    invocations (INT-02). Memory, MCP, and delegation are not LangChain middleware
    hooks — they are governed by the SDK wrappers in `agentos_sdk.wrappers`, sharing
    the same enforcement core. Without a `coordinator`, blocking outcomes
    (require_approval / require_consensus) fail CLOSED; without a `sandbox` runner,
    so does the `sandbox` outcome (RUN-03).
    """

    def __init__(
        self,
        pipeline: PipelineProtocol,
        token: str,
        *,
        coordinator: ApprovalCoordinator | None = None,
        dispatcher: SideEffectDispatcher | None = None,
        sandbox: SandboxRunner | None = None,
    ) -> None:
        self._pipeline = pipeline  # the in-process PDP (D-07); satisfies PipelineProtocol
        self._token = token        # the agent's signed JWT (from registration, IDN-01)
        self._coordinator = coordinator
        self._dispatcher = dispatcher
        self._sandbox = sandbox

    async def awrap_tool_call(self, request: ToolCallRequest, handler):
        """Async PEP hook (langchain 1.3.2). The map decides; a block returns a
        ToolMessage (the tool never executes — D-03, no egress)."""
        action = normalize_action(request, self._token)
        try:
            return await governed_call(
                self._pipeline,
                action,
                lambda: handler(request),
                coordinator=self._coordinator,
                dispatcher=self._dispatcher,
                sandbox=self._sandbox,
            )
        except GovernanceDenied as denied:
            # SHORT-CIRCUIT happened inside the core: handler was never called.
            # `str(denied)` is the governed exception's OWN message, so a
            # GovernanceQuarantined reads as quarantined while a deny is unchanged.
            # `status="error"` is load-bearing, not cosmetic: this is the ONE surface
            # that turns the governed exception back into a normal return value, and
            # ToolMessage defaults to status="success". Without it a consumer that
            # branches on `status` (LangChain's tool-failure convention) reads a
            # contained action as a completed one.
            return ToolMessage(
                content=str(denied),
                tool_call_id=request.tool_call["id"],
                status="error",
            )

    async def awrap_model_call(self, request: ModelRequest, handler):
        """Async PEP hook (INT-02). On a block the provider is NEVER called (no
        prompt egress); an AIMessage carrying the fired reasons stands in for
        the model's response, so the agent loop sees an explainable block."""
        action = normalize_model_call(request, self._token)
        try:
            return await governed_call(
                self._pipeline,
                action,
                lambda: handler(request),
                coordinator=self._coordinator,
                dispatcher=self._dispatcher,
                sandbox=self._sandbox,
            )
        except GovernanceDenied as denied:
            return AIMessage(content=str(denied))
