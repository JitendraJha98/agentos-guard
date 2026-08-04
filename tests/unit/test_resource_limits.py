"""Per-agent execution budgets at the PEP (RUN-05, Slice 9c, Task 1).

`_run_within_limits` wraps BOTH `await run()` sites in `governed_call`, so a budget applies to
directly-executable outcomes AND to post-approval execution. The point of these tests is to pin the
HONEST enforcement boundary rather than a marketing claim:

  * `network` -> preventive: the handler is NEVER invoked, and only for egress-capable action types.
  * `wall_s`  -> preventive but COOPERATIVE: an awaiting handler is cancelled (proved by a post-sleep
    flag that never gets set); a sync CPU-bound handler could not be interrupted, and an aborted
    handler is NOT rolled back.
  * `memory_mb` -> DETECTED AT COMPLETION: the handler already ran. `preventive is False` says so.

Every violation is a `GovernanceDenied` subclass, so no existing catch site can mistake a budget
breach for a successful result. An unwired (`governor=None`) or unlimited agent must take the
zero-overhead path: no `tracemalloc`, no `wait_for`.
"""

from __future__ import annotations

import asyncio
import tracemalloc
from uuid import uuid4

import pytest

from agentos_contract import ActionType, AgentAction, Decision, Outcome, Reason
from agentos_sdk.enforce import (
    GovernanceDenied,
    GovernanceResourceExceeded,
    ResourceLimits,
    governed_call,
)


def _action(type_: ActionType = ActionType.tool_call) -> AgentAction:
    payloads = {
        ActionType.tool_call: {"url": "https://api.example.com/x", "content": ""},
        ActionType.memory_access: {"operation": "write", "key": "k", "value": "v"},
        ActionType.mcp_call: {"server": "s", "tool": "t", "args": "{}"},
    }
    return AgentAction(
        agent_id="budget-agent",
        type=type_,
        target="http_get",
        payload=payloads[type_],
        identity_token="tok",
    )


class _AllowPipeline:
    """A stub PDP that always allows — so anything that blocks here is the BUDGET, not policy."""

    async def evaluate(self, action: AgentAction) -> Decision:
        return Decision(
            action_id=action.id,
            outcome=Outcome.allow,
            reasons=[Reason(stage="policy", code="allowlisted")],
            evidence_ref=uuid4(),
        )


class _StubGovernor:
    """The RUN-05 seam under test: in-memory `limits_for`, breach recording into a list."""

    def __init__(self, limits: ResourceLimits | None) -> None:
        self._limits = limits
        self.breaches: list[dict] = []
        self.lookups = 0

    def limits_for(self, agent_id: str) -> ResourceLimits | None:
        self.lookups += 1
        return self._limits

    async def record_breach(self, action, decision, *, limit, budget, observed) -> None:
        self.breaches.append(
            {"agent_id": action.agent_id, "limit": limit, "budget": budget, "observed": observed}
        )


def _call(governor, run, *, action: AgentAction | None = None):
    return asyncio.run(
        governed_call(_AllowPipeline(), action or _action(), run, governor=governor)
    )


# --- the zero-overhead default -----------------------------------------------


def test_no_governor_runs_the_handler_unchanged() -> None:
    """The default hot path: no governor wired -> no tracemalloc, no wait_for, no lookup."""
    ran = []

    async def run():
        ran.append(1)
        return "result"

    assert _call(None, run) == "result"
    assert ran == [1]
    assert not tracemalloc.is_tracing()


def test_a_governor_with_no_limits_for_the_agent_runs_unchanged() -> None:
    """`limits_for` -> None (the common case: most agents have no budget row) is also zero-overhead."""
    governor = _StubGovernor(None)
    ran = []

    async def run():
        ran.append(1)
        return "result"

    assert _call(governor, run) == "result"
    assert ran == [1] and governor.lookups == 1 and governor.breaches == []
    assert not tracemalloc.is_tracing()


def test_an_all_none_budget_permits_execution() -> None:
    """A row exists but every dimension is unset (network allow) -> the handler still runs."""
    governor = _StubGovernor(ResourceLimits())
    ran = []

    async def run():
        ran.append(1)
        return "result"

    assert _call(governor, run) == "result"
    assert ran == [1] and governor.breaches == []
    assert not tracemalloc.is_tracing()


# --- wall_s: preventive, but cooperative -------------------------------------


def test_wall_budget_cancels_an_awaiting_handler() -> None:
    """Preventive: the handler is CANCELLED mid-await, so the work after the sleep never happens.
    The post-sleep flag is the proof — a merely-detected timeout would have set it."""
    governor = _StubGovernor(ResourceLimits(wall_s=0.05))
    completed = []

    async def run():
        await asyncio.sleep(5)
        completed.append("side-effect")  # must NEVER happen
        return "result"

    with pytest.raises(GovernanceResourceExceeded) as exc:
        _call(governor, run)

    assert exc.value.limit == "wall_s"
    assert exc.value.preventive is True
    assert exc.value.budget == 0.05
    assert completed == []  # cancelled, not merely observed
    assert len(governor.breaches) == 1 and governor.breaches[0]["limit"] == "wall_s"
    assert "wall_s" in str(exc.value)


def test_a_handler_inside_its_wall_budget_returns_normally() -> None:
    governor = _StubGovernor(ResourceLimits(wall_s=5.0))

    async def run():
        await asyncio.sleep(0)
        return "result"

    assert _call(governor, run) == "result"
    assert governor.breaches == []


# --- network: preventive, egress types only ----------------------------------


def test_network_deny_never_invokes_an_egress_handler() -> None:
    governor = _StubGovernor(ResourceLimits(network="deny"))
    ran = []

    async def run():
        ran.append(1)
        return "result"

    with pytest.raises(GovernanceResourceExceeded) as exc:
        _call(governor, run)

    assert exc.value.limit == "network"
    assert exc.value.preventive is True
    assert ran == []  # the handler was NEVER invoked — this is real prevention
    assert len(governor.breaches) == 1 and governor.breaches[0]["limit"] == "network"


@pytest.mark.parametrize("type_", [ActionType.tool_call, ActionType.mcp_call])
def test_network_deny_covers_every_egress_capable_type(type_: ActionType) -> None:
    governor = _StubGovernor(ResourceLimits(network="deny"))
    ran = []

    async def run():
        ran.append(1)

    with pytest.raises(GovernanceResourceExceeded):
        _call(governor, run, action=_action(type_))
    assert ran == []


def test_network_deny_does_not_block_a_non_egress_action() -> None:
    """A memory access does not leave the process: a network budget must not silently break it
    (over-blocking is as much a correctness bug as under-blocking)."""
    governor = _StubGovernor(ResourceLimits(network="deny"))
    ran = []

    async def run():
        ran.append(1)
        return "result"

    assert _call(governor, run, action=_action(ActionType.memory_access)) == "result"
    assert ran == [1] and governor.breaches == []


# --- memory_mb: detected at COMPLETION, not prevented ------------------------


def test_memory_budget_is_detected_after_the_handler_already_ran() -> None:
    """The honesty test. `preventive is False` and `ran == [1]` together document that a memory
    breach is POST-HOC: the allocation happened, the side effect happened, and all this does is
    withhold the result and audit the violation. Claiming otherwise would be a lie in the docs."""
    governor = _StubGovernor(ResourceLimits(memory_mb=0.001))
    ran = []

    async def run():
        ran.append(1)
        blob = b"x" * 2_000_000
        return len(blob)

    with pytest.raises(GovernanceResourceExceeded) as exc:
        _call(governor, run)

    assert exc.value.limit == "memory_mb"
    assert exc.value.preventive is False
    assert exc.value.observed > exc.value.budget
    assert ran == [1]  # the handler ALREADY ran — nothing was prevented
    assert len(governor.breaches) == 1 and governor.breaches[0]["limit"] == "memory_mb"
    assert "detected after completion" in str(exc.value)


def test_a_handler_inside_its_memory_budget_returns_normally() -> None:
    governor = _StubGovernor(ResourceLimits(memory_mb=64.0))

    async def run():
        return "result"

    assert _call(governor, run) == "result"
    assert governor.breaches == []


def test_tracemalloc_is_not_left_running() -> None:
    """The helper started tracing, so the helper stops it: a governed process must not silently
    acquire tracemalloc's overhead for the rest of its life."""
    assert not tracemalloc.is_tracing()  # precondition
    governor = _StubGovernor(ResourceLimits(memory_mb=64.0))

    async def run():
        return "result"

    _call(governor, run)
    assert not tracemalloc.is_tracing()

    # ... and also on the breach path, where an exception unwinds through the helper.
    breaching = _StubGovernor(ResourceLimits(memory_mb=0.001))

    async def big():
        return b"x" * 2_000_000

    with pytest.raises(GovernanceResourceExceeded):
        _call(breaching, big)
    assert not tracemalloc.is_tracing()


def test_the_budget_is_charged_per_call_not_process_wide() -> None:
    """A previous large allocation still LIVE in this process must not make the next call breach.

    `tracemalloc.reset_peak()` sets the peak to the CURRENT size rather than zero, so the budget is
    charged against growth above that baseline. Billing the absolute peak instead would make a
    long-lived agent false-breach on its first governed call after any big allocation.
    """
    tracemalloc.start()
    try:
        hog = b"y" * 4_000_000  # noqa: F841 — deliberately kept alive across the governed call
        assert tracemalloc.get_traced_memory()[0] > 3_000_000
        governor = _StubGovernor(ResourceLimits(memory_mb=1.0))

        async def run():
            return len(hog)

        assert _call(governor, run) == 4_000_000  # the call itself allocated ~nothing
        assert governor.breaches == []

        # ... and a call that DOES grow past the budget still breaches from that same baseline.
        async def grow():
            return b"z" * 3_000_000

        with pytest.raises(GovernanceResourceExceeded) as exc:
            _call(governor, grow)
        assert exc.value.limit == "memory_mb" and exc.value.observed > 1.0
    finally:
        tracemalloc.stop()


# --- the subclass contract ---------------------------------------------------


@pytest.mark.parametrize(
    "limits",
    [
        ResourceLimits(network="deny"),
        ResourceLimits(wall_s=0.05),
        ResourceLimits(memory_mb=0.001),
    ],
)
def test_every_breach_is_a_governance_denied(limits: ResourceLimits) -> None:
    """Legacy callers only know `except GovernanceDenied` — a budget breach must land there, so no
    caller can read a withheld result as a success."""
    governor = _StubGovernor(limits)

    async def run():
        await asyncio.sleep(5 if limits.wall_s else 0)
        return b"x" * 2_000_000

    caught = None
    try:
        _call(governor, run)
    except GovernanceDenied as denied:  # the ONLY except-site legacy callers have
        caught = denied
    assert isinstance(caught, GovernanceResourceExceeded)
    assert caught.decision.outcome is Outcome.allow  # policy allowed it; the BUDGET refused


# --- both run sites ----------------------------------------------------------


class _ApprovalPipeline:
    async def evaluate(self, action: AgentAction) -> Decision:
        return Decision(
            action_id=action.id,
            outcome=Outcome.require_approval,
            reasons=[Reason(stage="policy", code="constitution_principle_fired")],
            evidence_ref=uuid4(),
        )


class _Approves:
    """A coordinator that approves, so execution reaches the POST-APPROVAL `run()` site."""

    async def park_and_wait(self, action, decision) -> bool:
        return True

    async def open_review(self, action, decision) -> None: ...

    async def record_substitution(self, action, decision, *, requested, substituted) -> None: ...


def test_the_budget_also_applies_to_post_approval_execution() -> None:
    """The second `await run()` site. If only the `_EXECUTABLE` branch were wrapped, requesting
    approval would be a trivial way to buy an UNLIMITED execution — the budget must survive the
    approval detour."""
    governor = _StubGovernor(ResourceLimits(network="deny"))
    ran = []

    async def run():
        ran.append(1)
        return "result"

    with pytest.raises(GovernanceResourceExceeded) as exc:
        asyncio.run(
            governed_call(
                _ApprovalPipeline(),
                _action(),
                run,
                coordinator=_Approves(),
                governor=governor,
            )
        )
    assert exc.value.limit == "network"
    assert ran == []  # approved by a human, still refused by the budget
    assert exc.value.decision.outcome is Outcome.require_approval


def test_post_approval_execution_within_budget_still_returns() -> None:
    governor = _StubGovernor(ResourceLimits(wall_s=5.0, memory_mb=64.0))

    async def run():
        return "result"

    assert (
        asyncio.run(
            governed_call(
                _ApprovalPipeline(),
                _action(),
                run,
                coordinator=_Approves(),
                governor=governor,
            )
        )
        == "result"
    )
    assert governor.breaches == []
