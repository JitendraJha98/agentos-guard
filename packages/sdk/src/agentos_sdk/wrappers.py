"""Governed wrappers for memory, MCP, and delegation (INT-03 / INT-04 / INT-05).

LangChain v1 exposes native middleware hooks only for tool and model calls; memory,
MCP, and delegation boundaries have no middleware hook, so the SDK governs them with
thin async wrappers. Each one normalizes the operation into the same `AgentAction`
and delegates to the ONE enforcement core (`governed_call`) with the same injected
coordinator/dispatcher/sandbox seams as the middleware hooks — the full outcome map
applies: executable outcomes run the wrapped operation, blocking outcomes park-and-await
via the coordinator (fail-closed without one), a `sandbox` outcome quarantines via the
sandbox runner (RUN-03; fail-closed without one), and deny raises `GovernanceDenied`
WITHOUT executing it (no side effect: no memory write, no MCP egress, no sub-agent
dispatch).

These are deliberately minimal helpers, not a framework: each builds the right action
and delegates to `governed_call`, so all five action types share one decision path.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import TypeVar
from uuid import UUID

from agentos_contract import PipelineProtocol

from agentos_sdk.enforce import (
    ApprovalCoordinator,
    SandboxRunner,
    SideEffectDispatcher,
    governed_call,
)
from agentos_sdk.normalize import (
    normalize_delegation,
    normalize_memory_access,
    normalize_mcp_call,
)

_T = TypeVar("_T")


async def governed_memory_access(
    pipeline: PipelineProtocol,
    token: str,
    *,
    operation: str,
    key: str,
    value: str = "",
    run: Callable[[], Awaitable[_T]],
    parent_action_id: UUID | None = None,
    conversation_id: str | None = None,
    coordinator: ApprovalCoordinator | None = None,
    dispatcher: SideEffectDispatcher | None = None,
    sandbox: SandboxRunner | None = None,
) -> _T:
    """Govern a memory read/write (INT-03) through the one outcome map.

    `value` defaults to "" because a READ supplies no value at the access boundary
    (the read result is not known pre-execution); a WRITE passes the value to govern.
    """
    action = normalize_memory_access(
        operation, key, value, token,
        parent_action_id=parent_action_id, conversation_id=conversation_id,
    )
    return await governed_call(
        pipeline, action, run,
        coordinator=coordinator, dispatcher=dispatcher, sandbox=sandbox,
    )


async def governed_mcp_call(
    pipeline: PipelineProtocol,
    token: str,
    *,
    server: str,
    tool: str,
    args: str,
    run: Callable[[], Awaitable[_T]],
    parent_action_id: UUID | None = None,
    conversation_id: str | None = None,
    coordinator: ApprovalCoordinator | None = None,
    dispatcher: SideEffectDispatcher | None = None,
    sandbox: SandboxRunner | None = None,
) -> _T:
    """Govern an MCP-server call (INT-04) through the one outcome map."""
    action = normalize_mcp_call(
        server, tool, args, token,
        parent_action_id=parent_action_id, conversation_id=conversation_id,
    )
    return await governed_call(
        pipeline, action, run,
        coordinator=coordinator, dispatcher=dispatcher, sandbox=sandbox,
    )


async def governed_delegation(
    pipeline: PipelineProtocol,
    token: str,
    *,
    to_agent: str,
    task: str,
    run: Callable[[], Awaitable[_T]],
    parent_action_id: UUID,
    conversation_id: str | None = None,
    coordinator: ApprovalCoordinator | None = None,
    dispatcher: SideEffectDispatcher | None = None,
    sandbox: SandboxRunner | None = None,
) -> _T:
    """Govern an agent-to-agent delegation (INT-05), capturing `parent_action_id`
    lineage. Allow dispatches the sub-agent (`run`); a block never dispatches it."""
    action = normalize_delegation(
        to_agent, task, token,
        parent_action_id=parent_action_id, conversation_id=conversation_id,
    )
    return await governed_call(
        pipeline, action, run,
        coordinator=coordinator, dispatcher=dispatcher, sandbox=sandbox,
    )
