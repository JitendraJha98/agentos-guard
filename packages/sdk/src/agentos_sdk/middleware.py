"""(RED stub) GovernanceMiddleware — the LangChain v1 PEP (INT-01 / SDK-01)."""

from __future__ import annotations

from langchain.agents.middleware import AgentMiddleware


class GovernanceMiddleware(AgentMiddleware):
    def __init__(self, pipeline, token: str) -> None:
        raise NotImplementedError
