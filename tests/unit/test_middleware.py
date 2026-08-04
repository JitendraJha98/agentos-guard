"""SDK PEP behavior — INT-01 / SDK-01 (the GovernanceMiddleware enforcement seam).

Async-hook resolution (Open Q2 / Assumption A3): langchain 1.3.2 DOES expose an
async `awrap_tool_call(self, request, handler)` variant (verified at plan time),
so the PEP uses the async path and `await pipeline.evaluate(action)` directly —
the pipeline + audit write stay async. NEVER `asyncio.run()` inside the hook
(it runs inside the LangGraph event loop; that would raise RuntimeError).

Behavior under test (no real LLM / no real network — a fake pipeline returns a
scripted Decision and a spy handler records its call count):
  - normalize: normalize_action(request, token) -> AgentAction(type=tool_call,
    target=="http_get", payload from tc["args"], identity_token=token).
  - allow: a Decision(outcome=allow) calls handler exactly once and returns its result.
  - deny: a Decision(outcome=deny) returns a ToolMessage carrying the fired reasons
    and does NOT call handler (call count 0 — no egress). The ToolMessage's
    tool_call_id == request.tool_call["id"] and its `status` is "error" — a contained
    action must never be structurally indistinguishable from a completed one
    (ToolMessage defaults to status="success", LangChain's tool-failure convention).
  - no nested loop: the hook does not call asyncio.run (proven by source grep below).
"""

import asyncio
import inspect
from pathlib import Path

import pytest
from langchain.agents.middleware import ToolCallRequest
from langchain.messages import ToolMessage

from agentos_contract import ActionType, Decision, Outcome, Reason
from agentos_sdk import GovernanceMiddleware, normalize_action

TOKEN = "test-token-abc"  # an opaque JWT placeholder; the PEP only attaches it.


def _request(
    name: str = "http_get",
    args: dict | None = None,
    call_id: str = "call_123",
) -> ToolCallRequest:
    """Build a minimal LangChain ToolCallRequest (the middleware reads .tool_call)."""
    return ToolCallRequest(
        tool_call={"name": name, "args": args or {"url": "https://api.example.com/x"}, "id": call_id},
        tool=None,
        state=None,
        runtime=None,
    )


class _FakePipeline:
    """A pipeline stub that returns a scripted Decision (no DB, no real stages)."""

    def __init__(self, decision: Decision) -> None:
        self._decision = decision
        self.actions: list = []

    async def evaluate(self, action):  # matches PipelineProtocol (async)
        self.actions.append(action)
        return self._decision


class _SpyHandler:
    """An awaitable spy handler (matches awrap_tool_call's Awaitable-handler shape)."""

    def __init__(self) -> None:
        self.calls = 0

    async def __call__(self, request: ToolCallRequest):
        self.calls += 1
        return ToolMessage(content="tool ran", tool_call_id=request.tool_call["id"])


def _allow_decision() -> Decision:
    from uuid import uuid4

    return Decision(
        action_id=uuid4(),
        outcome=Outcome.allow,
        reasons=[Reason(stage="policy", code="no_principle_matched")],
    )


def _deny_decision() -> Decision:
    from uuid import uuid4

    return Decision(
        action_id=uuid4(),
        outcome=Outcome.deny,
        reasons=[
            Reason(
                stage="policy",
                code="constitution_principle_fired",
                policy_id="constitution.1.1",
                principle_ref="1.1",
                rationale="Egress allowlist",
            )
        ],
    )


def test_normalize_builds_tool_call_agent_action() -> None:
    req = _request(args={"url": "https://api.example.com/data"})
    action = normalize_action(req, TOKEN)
    assert action.type == ActionType.tool_call
    assert action.target == "http_get"
    assert action.payload == {"url": "https://api.example.com/data"}
    assert action.identity_token == TOKEN


def test_allow_calls_handler_exactly_once_and_returns_its_result() -> None:
    mw = GovernanceMiddleware(_FakePipeline(_allow_decision()), TOKEN)
    handler = _SpyHandler()
    req = _request()
    result = asyncio.run(mw.awrap_tool_call(req, handler))
    assert handler.calls == 1
    assert isinstance(result, ToolMessage)
    assert result.content == "tool ran"  # the handler's result is passed through


def test_deny_blocks_handler_and_returns_tool_message() -> None:
    mw = GovernanceMiddleware(_FakePipeline(_deny_decision()), TOKEN)
    handler = _SpyHandler()
    req = _request(call_id="call_deny_42")
    result = asyncio.run(mw.awrap_tool_call(req, handler))
    # No egress: the handler was NEVER called (the tool never executed).
    assert handler.calls == 0
    assert isinstance(result, ToolMessage)
    # The blocking message is correlated back to the originating tool call.
    assert result.tool_call_id == "call_deny_42"
    # The fired reason is surfaced (machine-readable code present in the message).
    assert "constitution_principle_fired" in result.content
    # And the block is structurally a FAILURE, not a success: a consumer branching on
    # ToolMessage.status (which defaults to "success") must read it as non-execution.
    assert result.status == "error"


# --- Outcome map without a coordinator: blocking outcomes fail CLOSED (6b-2) ------
# (The full coordinator-wired map lives in tests/unit/test_outcome_enforcement.py.)


def _outcome_decision(outcome: Outcome) -> Decision:
    from uuid import uuid4

    return Decision(
        action_id=uuid4(),
        outcome=outcome,
        reasons=[Reason(stage="graduated", code=outcome.value)],
    )


def test_sandbox_blocks_tool_fail_closed() -> None:
    # sandbox escalates to the approval path; with NO coordinator the tool must NOT run.
    mw = GovernanceMiddleware(_FakePipeline(_outcome_decision(Outcome.sandbox)), TOKEN)
    handler = _SpyHandler()
    result = asyncio.run(mw.awrap_tool_call(_request(call_id="call_sbx_7"), handler))
    assert handler.calls == 0  # no egress under the interim fail-closed posture
    assert isinstance(result, ToolMessage)
    assert result.tool_call_id == "call_sbx_7"
    assert "Blocked by agentos-guard" in result.content
    assert result.status == "error"


def test_warn_executes_tool() -> None:
    mw = GovernanceMiddleware(_FakePipeline(_outcome_decision(Outcome.warn)), TOKEN)
    handler = _SpyHandler()
    result = asyncio.run(mw.awrap_tool_call(_request(), handler))
    assert handler.calls == 1
    assert result.content == "tool ran"


def test_governance_review_executes_tool() -> None:
    mw = GovernanceMiddleware(
        _FakePipeline(_outcome_decision(Outcome.governance_review)), TOKEN
    )
    handler = _SpyHandler()
    result = asyncio.run(mw.awrap_tool_call(_request(), handler))
    assert handler.calls == 1
    assert result.content == "tool ran"


def test_middleware_does_not_spin_a_nested_event_loop() -> None:
    """Guard against asyncio.run() in the hook (raises in a running loop)."""
    src = Path(GovernanceMiddleware.__module__.replace(".", "/"))
    middleware_py = (
        Path(inspect.getfile(GovernanceMiddleware))
    )
    text = middleware_py.read_text(encoding="utf-8")
    assert "asyncio.run" not in text
