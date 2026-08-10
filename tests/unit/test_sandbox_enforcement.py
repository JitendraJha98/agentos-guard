"""RUN-03 — the `sandbox` outcome QUARANTINES instead of substituting (Slice 9a).

The load-bearing assertion in every test here is `ran == []`: the real handler is
never awaited on the sandbox path, so no side effect and no egress can occur. The
observation surfaces as `GovernanceQuarantined` — a `GovernanceDenied` SUBCLASS, so
every existing `except GovernanceDenied` site already treats it as a non-execution
and a caller can never mistake a quarantine for a successful result.

Fail-closed is preserved: no runner wired -> plain `GovernanceDenied` with nothing
executed and NO `enforcement_substitution` recorded (Slice 9f retired the substitution
set entirely — `require_consensus`, its last member, now needs a real quorum).
"""

from __future__ import annotations

import asyncio

import pytest

from agentos_contract import ActionType, AgentAction, Decision, Outcome, Reason
from agentos_sdk.enforce import (
    GovernanceDenied,
    GovernanceQuarantined,
    SandboxResult,
    governed_call,
)


def _action() -> AgentAction:
    return AgentAction(
        agent_id="test-agent",
        type=ActionType.tool_call,
        target="http_get",
        payload={"url": "https://api.example.com/x", "content": ""},
        identity_token="tok",
    )


def _sandbox_decision(action: AgentAction) -> Decision:
    return Decision(
        action_id=action.id,
        outcome=Outcome.sandbox,
        reasons=[Reason(stage="graduated", code="sandbox")],
    )


class _Pipeline:
    def __init__(self, decision: Decision) -> None:
        self._decision = decision

    async def evaluate(self, action):
        return self._decision


class _Runner:
    """A stub SandboxRunner. It is NEVER handed the real handler — quarantine means
    there is nothing to invoke."""

    def __init__(self) -> None:
        self.calls: list[tuple] = []

    async def run(self, action, decision) -> SandboxResult:
        self.calls.append((action, decision))
        return SandboxResult(quarantined=True, run_id="r1", detail="d")


class _RaisingRunner:
    async def run(self, action, decision) -> SandboxResult:
        raise RuntimeError("sandbox unavailable")


class _Coordinator:
    """Records every seam call so a sandbox path can be proven NOT to touch it."""

    def __init__(self) -> None:
        self.substitutions: list[dict] = []
        self.parked = 0
        self.reviews = 0

    async def park_and_wait(self, action, decision) -> bool:
        self.parked += 1
        return True

    async def open_review(self, action, decision) -> None:
        self.reviews += 1

    async def record_substitution(self, action, decision, *, requested, substituted) -> None:
        self.substitutions.append({"requested": requested, "substituted": substituted})


def test_sandbox_quarantines_without_ever_running_the_handler() -> None:
    action, ran = _action(), []
    runner = _Runner()

    async def run():
        ran.append("side-effect")
        return "ran"

    with pytest.raises(GovernanceQuarantined) as exc:
        asyncio.run(
            governed_call(
                _Pipeline(_sandbox_decision(action)), action, run, sandbox=runner
            )
        )
    assert ran == []  # THE assertion: the real handler was never awaited
    assert len(runner.calls) == 1 and runner.calls[0][0] is action
    assert exc.value.sandbox_result.run_id == "r1"
    assert exc.value.sandbox_result.quarantined is True
    assert exc.value.decision.outcome is Outcome.sandbox


def test_quarantined_is_a_governance_denied_with_its_own_message() -> None:
    """Every existing `except GovernanceDenied` site must treat a quarantine as a
    non-execution — while the surfaced text says QUARANTINED, not blocked."""
    action, ran = _action(), []

    async def run():
        ran.append("side-effect")

    with pytest.raises(GovernanceDenied) as exc:  # caught as the BASE class
        asyncio.run(
            governed_call(
                _Pipeline(_sandbox_decision(action)), action, run, sandbox=_Runner()
            )
        )
    assert isinstance(exc.value, GovernanceQuarantined)
    assert isinstance(exc.value, GovernanceDenied)
    assert "Quarantined by agentos-guard" in str(exc.value)
    assert "Blocked by agentos-guard" not in str(exc.value)
    assert ran == []


def test_sandbox_without_runner_fails_closed_and_records_no_substitution() -> None:
    """No runner wired -> the containment cannot be enforced -> GovernanceDenied,
    nothing executed, and NO substitution onto the approval path (RUN-03 replaced it)."""
    action, ran = _action(), []
    coord = _Coordinator()

    async def run():
        ran.append("side-effect")

    with pytest.raises(GovernanceDenied) as exc:
        asyncio.run(
            governed_call(
                _Pipeline(_sandbox_decision(action)), action, run, coordinator=coord
            )
        )
    assert ran == []
    assert not isinstance(exc.value, GovernanceQuarantined)  # a plain block
    assert coord.substitutions == []  # never substituted onto the approval path
    assert coord.parked == 0          # and never parked


def test_sandbox_runner_failure_propagates_without_running_the_handler() -> None:
    """A runner that raises must NOT fall through to execution (fail-safe)."""
    action, ran = _action(), []

    async def run():
        ran.append("side-effect")

    with pytest.raises(RuntimeError):
        asyncio.run(
            governed_call(
                _Pipeline(_sandbox_decision(action)), action, run, sandbox=_RaisingRunner()
            )
        )
    assert ran == []


def test_the_substitution_set_is_gone_entirely() -> None:
    """RUN-03 removed `sandbox` from it in 9a; POL-09 removed `require_consensus` — its last
    member — in 9f, so the set itself is retired and NO outcome borrows the approval path."""
    import agentos_sdk.enforce as enforce

    assert not hasattr(enforce, "_SUBSTITUTED_TO_APPROVAL")
