"""Governed wrappers (INT-03/04/05) — memory, MCP, delegation share one enforcement core.

allow runs the wrapped operation and returns its result; deny raises GovernanceDenied
WITHOUT running it (no side effect: no memory write, no MCP egress, no sub-agent dispatch).
Delegation carries parent_action_id lineage onto the evaluated action.
"""

import asyncio
from uuid import uuid4

import pytest

from agentos_contract import Decision, Outcome, Reason
from agentos_sdk import (
    GovernanceDenied,
    governed_delegation,
    governed_memory_access,
    governed_mcp_call,
)

TOKEN = "test-token-abc"


class _FakePipeline:
    def __init__(self, outcome: Outcome) -> None:
        self._outcome = outcome
        self.actions: list = []

    async def evaluate(self, action):
        self.actions.append(action)
        return Decision(
            action_id=action.id,
            outcome=self._outcome,
            reasons=[Reason(stage="policy", code="x")],
        )


class _Op:
    """A spy operation: records whether it actually ran (the governed side effect)."""

    def __init__(self) -> None:
        self.ran = 0

    async def __call__(self):
        self.ran += 1
        return "did-the-thing"


def test_memory_allow_runs_and_deny_blocks() -> None:
    op = _Op()
    result = asyncio.run(
        governed_memory_access(
            _FakePipeline(Outcome.allow), TOKEN,
            operation="write", key="k", value="v", run=op,
        )
    )
    assert op.ran == 1 and result == "did-the-thing"

    op2 = _Op()
    with pytest.raises(GovernanceDenied):
        asyncio.run(
            governed_memory_access(
                _FakePipeline(Outcome.deny), TOKEN,
                operation="write", key="k", value="v", run=op2,
            )
        )
    assert op2.ran == 0  # no memory write happened on deny


def test_mcp_allow_runs_and_deny_blocks() -> None:
    op = _Op()
    asyncio.run(
        governed_mcp_call(
            _FakePipeline(Outcome.allow), TOKEN,
            server="github", tool="create_issue", args="x", run=op,
        )
    )
    assert op.ran == 1

    op2 = _Op()
    with pytest.raises(GovernanceDenied) as exc:
        asyncio.run(
            governed_mcp_call(
                _FakePipeline(Outcome.deny), TOKEN,
                server="github", tool="create_issue", args="x", run=op2,
            )
        )
    assert op2.ran == 0
    assert exc.value.decision.outcome == Outcome.deny  # carries the explainable decision


def test_delegation_allow_runs_and_carries_parent_lineage() -> None:
    parent = uuid4()
    pipeline = _FakePipeline(Outcome.allow)
    op = _Op()
    asyncio.run(
        governed_delegation(
            pipeline, TOKEN,
            to_agent="worker", task="t", run=op, parent_action_id=parent,
        )
    )
    assert op.ran == 1
    assert pipeline.actions[0].context.parent_action_id == parent


def test_delegation_deny_does_not_dispatch_subagent() -> None:
    op = _Op()
    with pytest.raises(GovernanceDenied):
        asyncio.run(
            governed_delegation(
                _FakePipeline(Outcome.deny), TOKEN,
                to_agent="worker", task="t", run=op, parent_action_id=uuid4(),
            )
        )
    assert op.ran == 0  # the sub-agent was never dispatched
