"""ToolCallRequest -> AgentAction normalization (INT-01 / SDK-01).

Source: 01-RESEARCH.md § "Interception (INT-01, SDK-01)" (the verified
normalize_action shape) + 01-AI-SPEC.md §4 "Tool Use".

The data plane owns translation from the framework-native call to the normalized,
serializable `AgentAction` the pipeline (PDP) consumes. The PEP attaches the agent's
signed identity token here; stage 1 of the pipeline verifies it and the token's `sub`
claim is the authoritative agent identity. We resolve `agent_id` from the token's
`sub` claim WITHOUT verifying the signature (verification is the pipeline's stage-1
job — Anti-Pattern 5: the PEP must not duplicate PDP logic). If the token is absent or
unparseable, the agent_id is left empty so the pipeline's identity stage denies it
(fail-closed — never silently fabricate an identity).
"""

from __future__ import annotations

from uuid import UUID

from agentos_contract import ActionContext, ActionType, AgentAction

from agentos_sdk.coverage import covers


def _agent_id_from_token(token: str | None) -> str:
    """Read the `sub` claim WITHOUT verifying (the pipeline verifies in stage 1).

    A missing/garbled token yields "" -> the pipeline's identity stage denies it
    (the token still travels on the action and is the authoritative check). We never
    fabricate an identity here.
    """
    if not token:
        return ""
    try:
        import jwt

        # No signature verification on the data plane (PDP stage 1 owns that). We only
        # peek at the claimed subject so the normalized action carries a plausible id.
        claims = jwt.decode(token, options={"verify_signature": False})
        return str(claims.get("sub", ""))
    except Exception:
        return ""


def _context(parent_action_id: UUID | None, conversation_id: str | None) -> ActionContext:
    """Build the lineage-carrying ActionContext (INT-05)."""
    return ActionContext(
        parent_action_id=parent_action_id,
        conversation_id=conversation_id,
    )


@covers(ActionType.tool_call)
def normalize_action(request, token: str) -> AgentAction:
    """Translate a LangChain ToolCallRequest into the normalized AgentAction (PIPE-02)."""
    tc = request.tool_call  # {"name", "args", "id"}
    return AgentAction(
        agent_id=_agent_id_from_token(token),
        type=ActionType.tool_call,
        target=tc["name"],            # e.g. "http_get"
        payload=dict(tc["args"]),     # {"url": "...", "content": "..."}
        identity_token=token,
    )


def _model_name(model: object) -> str:
    """Best-effort model identifier from a LangChain chat model (no provider call)."""
    for attr in ("model_name", "model", "name"):
        value = getattr(model, attr, None)
        if isinstance(value, str) and value:
            return value
    return type(model).__name__


def _join_messages(messages) -> str:
    """Flatten message contents to one inspectable string for the risk stage.

    The risk detector scans payload values for injection (SEC-01); model inputs are
    exactly where indirect-injection lands, so the prompt text must be inspectable.
    """
    parts: list[str] = []
    for m in messages or []:
        content = getattr(m, "content", m)
        parts.append(content if isinstance(content, str) else str(content))
    return "\n".join(parts)


@covers(ActionType.model_invocation)
def normalize_model_call(request, token: str) -> AgentAction:
    """Translate a LangChain ModelRequest into a model_invocation AgentAction (INT-02)."""
    return AgentAction(
        agent_id=_agent_id_from_token(token),
        type=ActionType.model_invocation,
        target=_model_name(request.model),
        payload={"model": _model_name(request.model), "messages": _join_messages(request.messages)},
        identity_token=token,
    )


@covers(ActionType.memory_access)
def normalize_memory_access(
    operation: str,
    key: str,
    value: str,
    token: str,
    *,
    parent_action_id: UUID | None = None,
    conversation_id: str | None = None,
) -> AgentAction:
    """Normalize a memory read/write into a memory_access AgentAction (INT-03)."""
    return AgentAction(
        agent_id=_agent_id_from_token(token),
        type=ActionType.memory_access,
        target=f"memory:{operation}",
        payload={"operation": operation, "key": key, "value": value},
        context=_context(parent_action_id, conversation_id),
        identity_token=token,
    )


@covers(ActionType.mcp_call)
def normalize_mcp_call(
    server: str,
    tool: str,
    args: str,
    token: str,
    *,
    parent_action_id: UUID | None = None,
    conversation_id: str | None = None,
) -> AgentAction:
    """Normalize an MCP-server tool call into an mcp_call AgentAction (INT-04)."""
    return AgentAction(
        agent_id=_agent_id_from_token(token),
        type=ActionType.mcp_call,
        target=f"{server}:{tool}",
        payload={"server": server, "tool": tool, "args": args},
        context=_context(parent_action_id, conversation_id),
        identity_token=token,
    )


@covers(ActionType.delegation)
def normalize_delegation(
    to_agent: str,
    task: str,
    token: str,
    *,
    parent_action_id: UUID,
    conversation_id: str | None = None,
) -> AgentAction:
    """Normalize an agent-to-agent delegation into a delegation AgentAction (INT-05).

    `parent_action_id` is REQUIRED — a delegation always has an originating action, and
    capturing that edge is the whole point (lineage for the Phase-12 evidence graph).
    """
    return AgentAction(
        agent_id=_agent_id_from_token(token),
        type=ActionType.delegation,
        target=to_agent,
        payload={"to_agent": to_agent, "task": task},
        context=_context(parent_action_id, conversation_id),
        identity_token=token,
    )
