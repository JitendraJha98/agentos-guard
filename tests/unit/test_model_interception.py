"""Model interception (INT-02) — GovernanceMiddleware.awrap_model_call.

allow invokes the model (handler runs once); deny blocks the call — the provider is
NEVER invoked (no prompt egress) and an AIMessage carrying the fired reasons is
returned in place of the model response.
"""

import asyncio
from uuid import uuid4

from langchain.messages import AIMessage

from agentos_contract import Decision, Outcome, Reason
from agentos_sdk import GovernanceMiddleware

TOKEN = "test-token-abc"


class _FakeModel:
    model_name = "claude-opus-4-8"


class _FakeMessage:
    def __init__(self, content: str) -> None:
        self.content = content


class _FakeModelRequest:
    def __init__(self, text: str = "summarize this") -> None:
        self.model = _FakeModel()
        self.messages = [_FakeMessage(text)]


class _FakePipeline:
    def __init__(self, decision: Decision) -> None:
        self._decision = decision
        self.actions: list = []

    async def evaluate(self, action):
        self.actions.append(action)
        return self._decision


class _SpyHandler:
    def __init__(self) -> None:
        self.calls = 0

    async def __call__(self, request):
        self.calls += 1
        return AIMessage(content="model output")


def _decision(outcome: Outcome) -> Decision:
    return Decision(
        action_id=uuid4(),
        outcome=outcome,
        reasons=[Reason(stage="risk", code="prompt_injection", detail="instruction_override")],
    )


def test_allow_invokes_model_once() -> None:
    mw = GovernanceMiddleware(_FakePipeline(_decision(Outcome.allow)), TOKEN)
    handler = _SpyHandler()
    result = asyncio.run(mw.awrap_model_call(_FakeModelRequest(), handler))
    assert handler.calls == 1
    assert isinstance(result, AIMessage)
    assert result.content == "model output"


def test_deny_blocks_model_and_returns_reasons() -> None:
    mw = GovernanceMiddleware(_FakePipeline(_decision(Outcome.deny)), TOKEN)
    handler = _SpyHandler()
    result = asyncio.run(mw.awrap_model_call(_FakeModelRequest(), handler))
    assert handler.calls == 0  # the provider was NEVER called (no prompt egress)
    assert isinstance(result, AIMessage)
    assert "prompt_injection" in result.content


def test_sandbox_blocks_model_fail_closed() -> None:
    # Interim Phase-3 posture (H1): sandbox is not enforceable yet — no prompt egress.
    mw = GovernanceMiddleware(_FakePipeline(_decision(Outcome.sandbox)), TOKEN)
    handler = _SpyHandler()
    result = asyncio.run(mw.awrap_model_call(_FakeModelRequest(), handler))
    assert handler.calls == 0  # the provider was NEVER called
    assert isinstance(result, AIMessage)
    assert "Blocked by agentos-guard" in result.content


def test_model_action_is_normalized() -> None:
    pipeline = _FakePipeline(_decision(Outcome.allow))
    mw = GovernanceMiddleware(pipeline, TOKEN)
    asyncio.run(mw.awrap_model_call(_FakeModelRequest("hello world"), _SpyHandler()))
    action = pipeline.actions[0]
    assert action.type.value == "model_invocation"
    assert action.payload["messages"] == "hello world"
