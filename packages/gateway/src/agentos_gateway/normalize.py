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


def _join_messages(messages: Any) -> str:
    """Flatten chat messages to one inspectable string so the SEC-01 risk stage can scan them —
    an OpenAI-compatible body is exactly where indirect prompt injection arrives.

    The SHAPE of `messages` is client-supplied too, so a non-list is normalized rather than
    iterated (which raised a TypeError: an un-audited 500 at the PEP) and rather than dropped —
    an injection hiding in a shape the scorer skipped would be an unscanned prompt reaching the
    provider. Serializing it keeps every malformed body scannable.

    Every message is likewise serialized WHOLE rather than reaching in for a string `content`.
    Reaching in was bypassable: a bare-string list item, a `text` key, a nested content list, and
    the spec-valid `{"content": null, "tool_calls": [...]}` shape all carried the injected prompt
    in a field the scan turned into the literal "null", so the payload sailed past SEC-01 and
    reached the provider. The scorer wants inspectable TEXT, not a schema — so the safe direction
    is to include everything the client sent and let the detector decide.
    """
    if not isinstance(messages, list):
        return "" if messages is None else json.dumps(messages, default=str)
    parts: list[str] = []
    for m in messages:
        if isinstance(m, str):
            parts.append(m)
            continue
        if isinstance(m, dict):
            content = m.get("content")
            # Keep plain content readable for the detector, but NEVER drop the rest of the
            # message: role, name, tool_calls.arguments and any vendor extension can all carry
            # the injection.
            if isinstance(content, str):
                parts.append(content)
            rest = {k: v for k, v in m.items() if not (k == "content" and isinstance(v, str))}
            if rest:
                parts.append(json.dumps(rest, default=str, sort_keys=True))
            continue
        parts.append(json.dumps(m, default=str))
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
