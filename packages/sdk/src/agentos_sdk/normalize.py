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

from agentos_contract import ActionType, AgentAction


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
