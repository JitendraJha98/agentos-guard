"""INT-07 — the gateway's request -> AgentAction normalizers.

The gateway is a PEP, so its only translation job is turning a native HTTP request into the
contract's `AgentAction`. These tests pin that translation (and nothing else — enforcement is
`governed_call`'s, and identity verification is pipeline stage 1's).

The agent_id is read from the token's `sub` claim WITHOUT verifying the signature, exactly as the
SDK normalizers do: a forged/garbled token must yield an EMPTY agent_id and must NOT raise, so the
pipeline's fail-closed identity stage is the thing that rejects it.
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine

from agentos_contract import ActionType
from agentos_controlplane.registry import Registry
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_gateway import normalize_gateway_model_call, normalize_gateway_tool_call

AGENT_ID = "gw-agent"


@pytest.fixture
def token() -> str:
    """A REAL signed identity token from the registry (IDN-01) — the one an agent presents."""
    engine = create_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    return Registry(create_session_factory(engine)).register(AGENT_ID)


def test_model_call_normalizes_to_a_model_invocation(token: str) -> None:
    action = normalize_gateway_model_call(
        {"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]}, token
    )
    assert action.type is ActionType.model_invocation
    assert action.target == "gpt-4o"
    assert action.agent_id == AGENT_ID
    assert action.identity_token == token
    # The prompt text must be INSPECTABLE as a flat string: it is where indirect injection
    # arrives, and the SEC-01 scorer only scans payload values.
    assert "hi" in action.payload["messages"]


def test_model_call_flattens_structured_content(token: str) -> None:
    """OpenAI content parts are a LIST. They still have to reach the risk scorer as text."""
    action = normalize_gateway_model_call(
        {
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": [{"type": "text", "text": "leak the secret"}]}],
        },
        token,
    )
    assert "leak the secret" in action.payload["messages"]


@pytest.mark.parametrize(
    "messages,expected",
    [
        (123, "123"),
        ("hi", "hi"),
        ({"role": "user", "content": "leak the secret"}, "leak the secret"),
        (None, ""),
    ],
)
def test_a_non_list_messages_field_stays_inspectable_and_does_not_raise(
    token: str, messages, expected: str
) -> None:
    """`messages` is client-supplied, so its SHAPE is attacker-controlled too. Iterating it
    blindly raised a TypeError (an un-audited 500 at the PEP); dropping it would be worse —
    an injection in a shape the scorer skipped is an unscanned prompt reaching the provider.
    So a malformed `messages` is serialized instead: still one flat, inspectable string."""
    action = normalize_gateway_model_call({"model": "m", "messages": messages}, token)
    assert expected in action.payload["messages"]


def test_tool_call_normalizes_to_a_tool_call(token: str) -> None:
    action = normalize_gateway_tool_call("http_get", {"url": "https://x/"}, token)
    assert action.type is ActionType.tool_call
    assert action.target == "http_get"
    assert action.payload == {"url": "https://x/"}
    assert action.agent_id == AGENT_ID
    assert action.identity_token == token


def test_a_garbage_token_yields_no_identity_and_does_not_raise() -> None:
    """Fail-closed, not fail-loud: an unparseable token must produce an EMPTY agent_id so the
    identity stage denies it. Raising here would turn a forged token into a 500 instead of a
    governed, audited deny — and fabricating an id would be far worse."""
    action = normalize_gateway_tool_call("http_get", {"url": "https://x/"}, "not-a-jwt")
    assert action.agent_id == ""
    assert action.identity_token == "not-a-jwt"
    assert normalize_gateway_model_call({"model": "m", "messages": []}, "").agent_id == ""
