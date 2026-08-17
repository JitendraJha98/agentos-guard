"""INT-07 — normalize an intercepted HTTP request into the contract's AgentAction.

The gateway is a PEP, so it does exactly what every other PEP form does: translate its native
request shape into an `AgentAction` and hand it to the ONE enforcement core. Registering with
`@covers` keeps INT-06 honest — the gateway is a real interception path, and the matrix says so.
"""

from __future__ import annotations

import json
from typing import Any

from agentos_contract import ActionType, AgentAction
from agentos_sdk.coverage import covers

# The SAME unverified `sub`-claim peek the SDK normalizers use (Anti-Pattern 5: the PEP must not
# duplicate PDP logic — stage 1 owns verification). Reusing it rather than writing a second JWT
# parser keeps one definition of "what agent does this token claim to be", so the gateway and the
# SDK can never disagree about an agent's identity for the same token.
from agentos_sdk.normalize import _agent_id_from_token


def _join_messages(messages: list[dict[str, Any]] | None) -> str:
    """Flatten chat messages to one inspectable string so the SEC-01 risk stage can scan them —
    an OpenAI-compatible body is exactly where indirect prompt injection arrives."""
    parts: list[str] = []
    for m in messages or []:
        content = m.get("content") if isinstance(m, dict) else None
        parts.append(content if isinstance(content, str) else json.dumps(content, default=str))
    return "\n".join(parts)


@covers(ActionType.model_invocation)
def normalize_gateway_model_call(body: dict[str, Any], token: str) -> AgentAction:
    """An OpenAI-compatible chat-completions request -> a model_invocation AgentAction."""
    model = str(body.get("model", "unknown"))
    return AgentAction(
        agent_id=_agent_id_from_token(token),
        type=ActionType.model_invocation,
        target=model,
        payload={"model": model, "messages": _join_messages(body.get("messages"))},
        identity_token=token,
    )


@covers(ActionType.tool_call)
def normalize_gateway_tool_call(tool_name: str, body: dict[str, Any], token: str) -> AgentAction:
    """A gateway tool invocation -> a tool_call AgentAction. The JSON body IS the tool args."""
    return AgentAction(
        agent_id=_agent_id_from_token(token),
        type=ActionType.tool_call,
        target=tool_name,
        payload=dict(body),
        identity_token=token,
    )
