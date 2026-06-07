"""Phase 2 normalizers (INT-02..05) — each action type maps to a correct AgentAction.

The risk stage scans payload values for injection, so model/memory/mcp/delegation
payloads must carry their inspectable text. Delegation must capture parent_action_id
lineage (INT-05). agent_id is resolved from the token's `sub` claim (unverified here;
the pipeline verifies in stage 1).
"""

from uuid import uuid4

import jwt

from agentos_contract import ActionType
from agentos_sdk import (
    normalize_delegation,
    normalize_memory_access,
    normalize_mcp_call,
    normalize_model_call,
)

# An unsigned token whose `sub` the normalizer peeks at (no verification on the PEP).
TOKEN = jwt.encode({"sub": "agent-7"}, "k" * 32, algorithm="HS256")


class _FakeModel:
    model_name = "claude-opus-4-8"


class _FakeMessage:
    def __init__(self, content: str) -> None:
        self.content = content


class _FakeModelRequest:
    def __init__(self, messages) -> None:
        self.model = _FakeModel()
        self.messages = messages


def test_normalize_model_call() -> None:
    req = _FakeModelRequest([_FakeMessage("hello"), _FakeMessage("world")])
    action = normalize_model_call(req, TOKEN)
    assert action.type == ActionType.model_invocation
    assert action.target == "claude-opus-4-8"
    assert action.agent_id == "agent-7"
    assert action.payload["model"] == "claude-opus-4-8"
    assert action.payload["messages"] == "hello\nworld"  # joined for risk inspection
    assert action.identity_token == TOKEN


def test_normalize_memory_access() -> None:
    action = normalize_memory_access("write", "user_pref", "dark_mode", TOKEN)
    assert action.type == ActionType.memory_access
    assert action.target == "memory:write"
    assert action.payload == {"operation": "write", "key": "user_pref", "value": "dark_mode"}


def test_normalize_mcp_call() -> None:
    action = normalize_mcp_call("github", "create_issue", "title=bug", TOKEN)
    assert action.type == ActionType.mcp_call
    assert action.target == "github:create_issue"
    assert action.payload == {"server": "github", "tool": "create_issue", "args": "title=bug"}


def test_normalize_delegation_captures_parent_lineage() -> None:
    parent = uuid4()
    action = normalize_delegation("worker-agent", "summarize doc", TOKEN, parent_action_id=parent)
    assert action.type == ActionType.delegation
    assert action.target == "worker-agent"
    assert action.payload == {"to_agent": "worker-agent", "task": "summarize doc"}
    # INT-05: the originating action id is captured as lineage on the delegated action.
    assert action.context.parent_action_id == parent
