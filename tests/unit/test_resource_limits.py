"""Per-agent execution budgets at the PEP (RUN-05, Slice 9c, Task 1).

`_run_within_limits` wraps BOTH `await run()` sites in `governed_call`, so a budget applies to
directly-executable outcomes AND to post-approval execution. The point of these tests is to pin the
HONEST enforcement boundary rather than a marketing claim:

  * `network` -> preventive: the handler is NEVER invoked, and only for egress-capable action types
    (including `delegation`, so egress cannot be bought by dispatching a sub-agent).
  * `wall_s`  -> preventive ONLY when the cancellation lands: an awaiting handler is cancelled (proved
    by a post-sleep flag that never gets set), but a blocking or cancel-swallowing handler runs to
    completion and its overrun is then DETECTED AFTERWARDS (`preventive is False`) — never silently
    returned. A handler's OWN `TimeoutError` is not a budget breach at all.
  * `memory_mb` -> DETECTED AT COMPLETION: the handler already ran. `preventive is False` says so.
    The counters are process-global, so an OVERLAPPED window is unmeasurable and gets no verdict.

Every violation is a `GovernanceDenied` subclass, so no existing catch site can mistake a budget
breach for a successful result. An unwired (`governor=None`) or unlimited agent must take the
zero-overhead path: no `tracemalloc`, no `wait_for`.
"""

from __future__ import annotations

import asyncio
import logging
import time
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


def _action(type_: ActionType = ActionType.tool_call, agent_id: str = "budget-agent") -> AgentAction:
    payloads = {
        ActionType.tool_call: {"url": "https://api.example.com/x", "content": ""},
        ActionType.memory_access: {"operation": "write", "key": "k", "value": "v"},
        ActionType.mcp_call: {"server": "s", "tool": "t", "args": "{}"},
        ActionType.model_invocation: {"model": "m", "prompt": "p"},
        ActionType.delegation: {"to_agent": "child-agent", "task": "fetch a url"},
    }
    return AgentAction(
        agent_id=agent_id,
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


def test_a_blocking_overrun_is_DETECTED_after_completion_not_returned() -> None:
    """A sync handler never yields, so the cancellation can never land — but the overrun must not be
    silent either. It is reported post-hoc with the REAL elapsed time, audited, and the result is
    withheld; `preventive is False` says plainly that nothing was stopped."""
    governor = _StubGovernor(ResourceLimits(wall_s=0.05))
    completed = []

    async def run():
        time.sleep(0.3)  # blocking: the event loop cannot interrupt this
        completed.append("side-effect")
        return "result-that-must-not-reach-the-caller"

    with pytest.raises(GovernanceResourceExceeded) as exc:
        _call(governor, run)

    assert exc.value.limit == "wall_s"
    assert exc.value.preventive is False  # it ran to completion: detection, not prevention
    assert exc.value.budget == 0.05 and exc.value.observed > 0.05
    assert completed == ["side-effect"]  # the side effect DID happen — that is why we report it
    assert len(governor.breaches) == 1
    assert governor.breaches[0]["limit"] == "wall_s" and governor.breaches[0]["observed"] > 0.05
    assert "detected after completion" in str(exc.value)


def test_a_cancel_swallowing_handler_cannot_escape_the_wall_budget() -> None:
    """Cooperative cancellation is escapable by design; the post-hoc check is what makes the budget
    unbypassable. A handler that eats its CancelledError still loses its result."""
    governor = _StubGovernor(ResourceLimits(wall_s=0.05))

    async def run():
        try:
            await asyncio.sleep(5)
        except asyncio.CancelledError:
            pass  # swallowed
        return "result-after-swallowed-cancel"

    with pytest.raises(GovernanceResourceExceeded) as exc:
        _call(governor, run)

    assert exc.value.limit == "wall_s" and exc.value.preventive is False
    assert exc.value.observed > 0.05
    assert len(governor.breaches) == 1


# --- a handler's OWN TimeoutError is not a budget breach ----------------------


@pytest.mark.parametrize("limits", [ResourceLimits(memory_mb=64.0), ResourceLimits()])
def test_a_handlers_own_timeout_is_not_a_wall_breach_when_no_wall_budget_is_set(
    limits: ResourceLimits,
) -> None:
    """A budgeted agent with NO wall budget: an upstream `TimeoutError` must propagate UNCHANGED.
    Reclassifying it would fabricate a hash-covered `resource_limit_exceeded` for a budget that was
    never set AND suppress the real failure, leaving the caller unable to recover."""
    governor = _StubGovernor(limits)

    async def run():
        raise TimeoutError("upstream socket read timed out")

    with pytest.raises(TimeoutError) as exc:
        _call(governor, run)

    assert not isinstance(exc.value, GovernanceDenied)  # not a governed block at all
    assert "upstream socket read timed out" in str(exc.value)
    assert governor.breaches == []  # nothing to audit: no budget was violated


def test_a_handlers_own_timeout_inside_its_wall_budget_also_propagates() -> None:
    """Even WITH a wall budget: the deadline is the only thing that makes a TimeoutError a breach, so
    an upstream timeout that fires well inside the budget stays the handler's own failure."""
    governor = _StubGovernor(ResourceLimits(wall_s=5.0))

    async def run():
        raise TimeoutError("upstream socket read timed out")

    with pytest.raises(TimeoutError) as exc:
        _call(governor, run)

    assert not isinstance(exc.value, GovernanceDenied)
    assert "upstream socket read timed out" in str(exc.value)
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


@pytest.mark.parametrize(
    "type_",
    [
        ActionType.tool_call,
        ActionType.mcp_call,
        ActionType.model_invocation,
        ActionType.delegation,
    ],
)
def test_network_deny_covers_every_egress_capable_type(type_: ActionType) -> None:
    governor = _StubGovernor(ResourceLimits(network="deny"))
    ran = []

    async def run():
        ran.append(1)

    with pytest.raises(GovernanceResourceExceeded):
        _call(governor, run, action=_action(type_))
    assert ran == []


def test_network_deny_cannot_be_escaped_by_delegating_to_a_sub_agent() -> None:
    """The proxy escape. Budgets are NOT among the attributes a delegation inherits (TRST-04 passes
    down trust, scope and ring — not resource limits), so a sub-agent would run under its OWN
    unbudgeted `agent_id` and could egress freely. A parent forbidden to egress therefore may not
    dispatch the delegation at all."""
    governor = _StubGovernor(ResourceLimits(network="deny"))
    dispatched = []

    async def run():
        dispatched.append("sub-agent")  # would have made its own tool/mcp/model calls
        return "delegated"

    with pytest.raises(GovernanceResourceExceeded) as exc:
        _call(governor, run, action=_action(ActionType.delegation))

    assert exc.value.limit == "network" and exc.value.preventive is True
    assert dispatched == []  # no child was ever dispatched
    assert len(governor.breaches) == 1 and governor.breaches[0]["limit"] == "network"


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


# --- memory_mb under CONCURRENCY: unmeasurable, never cross-attributed -------


def _overlapping_pair(fat: _StubGovernor, thin: _StubGovernor, *, thin_raises: bool = False):
    """Two governed calls whose measurement windows provably overlap: the fat handler allocates and
    then parks on a gate that the thin handler opens, so the thin call runs entirely INSIDE the fat
    call's window. `tracemalloc` counters are process-global, so nothing can tell them apart."""

    async def main():
        gate = asyncio.Event()

        async def fat_run():
            blob = b"x" * 8_000_000
            await gate.wait()  # hold the window OPEN across the whole thin call
            return len(blob)

        async def thin_run():
            gate.set()
            if thin_raises:
                raise RuntimeError("handler failure")  # the window must still close
            return "thin-result"  # allocates nothing worth measuring

        return await asyncio.gather(
            governed_call(
                _AllowPipeline(), _action(agent_id="fat-agent"), fat_run, governor=fat
            ),
            governed_call(
                _AllowPipeline(), _action(agent_id="thin-agent"), thin_run, governor=thin
            ),
            return_exceptions=thin_raises,
        )

    return asyncio.run(main())


def test_overlapping_calls_never_cross_attribute_memory(caplog) -> None:
    """The verdict is REFUSED rather than guessed. Judging a process-global counter under concurrency
    is wrong in both directions: it bills an innocent agent for another's allocation (a fabricated,
    hash-chained accusation), and once the first window closes the later one reads (0, 0) and silently
    passes a real breach. An overlapped window therefore says `unmeasurable` and audits nothing."""
    fat = _StubGovernor(ResourceLimits(memory_mb=1.0))
    thin = _StubGovernor(ResourceLimits(memory_mb=1.0))

    with caplog.at_level(logging.WARNING):
        results = _overlapping_pair(fat, thin)

    assert results == [8_000_000, "thin-result"]
    assert thin.breaches == []  # the innocent agent is NEVER billed for the other's 8 MB
    assert fat.breaches == []  # and an unmeasurable window is not a breach either
    assert caplog.text.count("unmeasurable") == 2  # both windows said so, out loud
    assert "fat-agent" in caplog.text and "thin-agent" in caplog.text
    assert not tracemalloc.is_tracing()  # only the outermost window started/stopped the tracer


@pytest.mark.parametrize("thin_raises", [False, True])
def test_an_overlap_does_not_disable_the_memory_budget_afterwards(thin_raises: bool) -> None:
    """A leaked window counter would silently disable every LATER memory budget in the process — the
    worst failure mode of the fix. Proved by breaching normally right after an overlap, including one
    whose inner window unwound through an exception."""
    _overlapping_pair(
        _StubGovernor(ResourceLimits(memory_mb=1.0)),
        _StubGovernor(ResourceLimits(memory_mb=1.0)),
        thin_raises=thin_raises,
    )

    solo = _StubGovernor(ResourceLimits(memory_mb=1.0))

    async def run():
        return b"z" * 8_000_000

    with pytest.raises(GovernanceResourceExceeded) as exc:
        _call(solo, run)
    assert exc.value.limit == "memory_mb" and exc.value.observed > 1.0
    assert len(solo.breaches) == 1


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
