"""Interception-coverage check (INT-06) — all five types hooked, no silent gaps.

Two complementary guarantees:
  - STATIC: every member of ActionType has a registered interception path (importing
    the SDK populates the registry via the @covers decorators). A new action type with
    no PEP would make verify_coverage() raise — the gap cannot pass silently.
  - RUNTIME (bypass attempt): an action that reaches the pipeline without a valid
    identity — the signature of an un-instrumented / forged path — is DENIED by the
    fail-closed identity stage (IDN-02), not silently allowed.
"""

import asyncio

import pytest

from agentos_contract import ActionType, AgentAction, Outcome
import agentos_sdk  # noqa: F401 — import populates the coverage registry
from agentos_sdk import (
    InterceptionGapError,
    covered_types,
    verify_coverage,
)
from agentos_sdk.coverage import _REGISTRY, covers


def test_all_five_action_types_are_covered() -> None:
    assert covered_types() == set(ActionType)
    verify_coverage()  # does not raise


def test_coverage_includes_each_expected_type() -> None:
    for t in (
        ActionType.tool_call,
        ActionType.model_invocation,
        ActionType.memory_access,
        ActionType.mcp_call,
        ActionType.delegation,
    ):
        assert t in covered_types()


def test_a_gap_is_detected_not_silent() -> None:
    """Removing one type's registration makes verify_coverage raise (no silent gap)."""
    saved = dict(_REGISTRY)
    try:
        _REGISTRY.pop(ActionType.delegation)
        with pytest.raises(InterceptionGapError, match="delegation"):
            verify_coverage()
    finally:
        _REGISTRY.clear()
        _REGISTRY.update(saved)


def test_covers_registers_entrypoint() -> None:
    saved = dict(_REGISTRY)
    try:
        @covers(ActionType.tool_call)
        def _probe() -> None: ...

        assert _REGISTRY[ActionType.tool_call].endswith("_probe")
    finally:
        _REGISTRY.clear()
        _REGISTRY.update(saved)


def test_bypass_attempt_with_no_identity_is_denied(pipeline_with_principle) -> None:
    """A direct/un-instrumented model call (no identity token) must NOT be silently allowed."""
    wired = pipeline_with_principle
    rogue = AgentAction(
        agent_id="",                       # no resolvable identity (bypassed the PEP)
        type=ActionType.model_invocation,
        target="claude-opus-4-8",
        payload={"model": "claude-opus-4-8", "messages": "hi"},
        identity_token=None,               # no signed token attached
    )
    decision = asyncio.run(wired.pipeline.evaluate(rogue))
    assert decision.outcome == Outcome.deny
    codes = [r.code for r in decision.reasons]
    assert "forged_or_unknown_identity" in codes
