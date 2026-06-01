"""AgentAction — the normalized, serializable event every PEP produces (PIPE-07).

Source: docs/architecture/02-domain-model.md (AgentAction). Pydantic v2,
serializable from day one, with extra="forbid" so the serialization boundary
rejects unknown shapes (threat T-01-01).
"""

from datetime import datetime, timezone
from enum import Enum
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class ActionType(str, Enum):
    tool_call = "tool_call"                # only this is in Phase-1 scope (D-01)
    memory_access = "memory_access"        # Phase 2
    mcp_call = "mcp_call"                  # Phase 2
    model_invocation = "model_invocation"  # Phase 2
    delegation = "delegation"              # Phase 2


class ActionContext(BaseModel):
    conversation_id: str | None = None
    parent_action_id: UUID | None = None   # delegation/lineage (populated in Phase 2)
    trace_id: str | None = None            # OTel correlation (emitted in Phase 6)


class AgentAction(BaseModel):
    model_config = {"extra": "forbid"}     # reject unknown fields -> stable serializable boundary
    id: UUID = Field(default_factory=uuid4)
    agent_id: str
    type: ActionType
    target: str                            # tool name (e.g. "http_get")
    payload: dict = Field(default_factory=dict)  # tool args + fetched content; redacted in logs by policy
    context: ActionContext = Field(default_factory=ActionContext)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    identity_token: str | None = None      # the signed JWT the SDK attaches (verified in stage 1)
