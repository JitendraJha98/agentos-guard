"""POL-09 — `require_consensus` needs a QUORUM, not a substitution (Slice 9f).

The load-bearing assertion in every denying test here is `ran == []`: the real handler is
never awaited unless independent voters actually agreed. Fail-closed on every axis —

* no coordinator wired  -> `GovernanceDenied`, `run` never awaited (the seam cannot be
  enforced, so the action does not proceed) and NO substitution onto the approval path;
* quorum not reached    -> `GovernanceDenied`, `run` never awaited;
* a coordinator that RAISES -> propagates, `run` never awaited (an error is not consent).

The interim escalation `require_consensus` rode until this slice (`_SUBSTITUTED_TO_APPROVAL`
+ an audited `enforcement_substitution`) is retired here; the coordinator seam that recorded
it stays, because existing audit chains contain those records.
"""

from __future__ import annotations

import asyncio

import pytest

from agentos_contract import ActionType, AgentAction, Decision, Outcome, Reason
from agentos_sdk.enforce import GovernanceDenied, governed_call


def _action() -> AgentAction:
    return AgentAction(
        agent_id="test-agent",
        type=ActionType.tool_call,
        target="http_post",
        payload={"url": "https://api.example.com/x", "content": ""},
        identity_token="tok",
    )


def _consensus_decision(action: AgentAction) -> Decision:
    return Decision(
        action_id=action.id,
        outcome=Outcome.require_consensus,
        reasons=[Reason(stage="graduated", code="require_consensus")],
    )


class _Pipeline:
    def __init__(self, decision: Decision) -> None:
        self._decision = decision

    async def evaluate(self, action):
        return self._decision


class _Consensus:
    """A stub ConsensusCoordinator returning a fixed verdict."""

    def __init__(self, reached: bool) -> None:
        self._reached = reached
        self.calls: list[tuple] = []

    async def reach_consensus(self, action, decision) -> bool:
        self.calls.append((action, decision))
        return self._reached


class _RaisingConsensus:
    async def reach_consensus(self, action, decision) -> bool:
        raise RuntimeError("voter pool unavailable")


class _TruthyConsensus:
    """A NON-CONFORMING coordinator: returns a truthy non-bool instead of a real quorum.

    The natural implementation bug is `return approvals` instead of `return approvals >= quorum`
    — one approval against a quorum of two returns a truthy `1`.
    """

    def __init__(self, value) -> None:
        self._value = value

    async def reach_consensus(self, action, decision):
        return self._value


class _Coordinator:
    """Records every approval-seam call so a consensus path can be proven NOT to touch it."""

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


def test_quorum_reached_executes_the_handler() -> None:
    action, ran = _action(), []
    consensus = _Consensus(True)

    async def run():
        ran.append("side-effect")
        return "ran"

    result = asyncio.run(
        governed_call(_Pipeline(_consensus_decision(action)), action, run, consensus=consensus)
    )
    assert result == "ran" and ran == ["side-effect"]
    assert len(consensus.calls) == 1 and consensus.calls[0][0] is action


def test_quorum_not_reached_blocks_without_running() -> None:
    action, ran = _action(), []
    consensus = _Consensus(False)

    async def run():
        ran.append("side-effect")
        return "ran"

    with pytest.raises(GovernanceDenied) as exc:
        asyncio.run(
            governed_call(_Pipeline(_consensus_decision(action)), action, run, consensus=consensus)
        )
    assert ran == []  # THE assertion: sub-quorum never executes
    assert exc.value.decision.outcome is Outcome.require_consensus


@pytest.mark.parametrize(
    "verdict", ["yes", 1, object(), [1], 1.0], ids=["str", "int", "object", "list", "float"]
)
def test_a_truthy_non_bool_quorum_is_not_an_approval(verdict) -> None:
    """The GATE applies the same rule as the voter path: only a genuine `True` authorises.

    `ConsensusCoordinator` is a public Protocol for third-party implementations, so the one
    line between a non-conforming coordinator and unauthorised execution must not gate on
    Python truthiness.
    """
    action, ran = _action(), []

    async def run():
        ran.append("side-effect")
        return "ran"

    with pytest.raises(GovernanceDenied):
        asyncio.run(
            governed_call(
                _Pipeline(_consensus_decision(action)), action, run,
                consensus=_TruthyConsensus(verdict),
            )
        )
    assert ran == []  # THE assertion: a truthy non-bool never executes


def test_no_coordinator_fails_closed_and_records_no_substitution() -> None:
    """No consensus coordinator wired -> the outcome CANNOT be enforced -> denied, with the
    handler never awaited and NO escalation onto the human-approval path."""
    action, ran = _action(), []
    coord = _Coordinator()

    async def run():
        ran.append("side-effect")
        return "ran"

    with pytest.raises(GovernanceDenied):
        asyncio.run(
            governed_call(_Pipeline(_consensus_decision(action)), action, run, coordinator=coord)
        )
    assert ran == []
    assert coord.substitutions == []  # the interim substitution is retired
    assert coord.parked == 0          # and the action was never parked for a human


def test_a_raising_coordinator_propagates_without_running_the_handler() -> None:
    """A consensus coordinator that fails must NOT fall through to execution (fail-safe)."""
    action, ran = _action(), []

    async def run():
        ran.append("side-effect")

    with pytest.raises(RuntimeError):
        asyncio.run(
            governed_call(
                _Pipeline(_consensus_decision(action)), action, run, consensus=_RaisingConsensus()
            )
        )
    assert ran == []


def test_consensus_approved_execution_still_flows_through_the_run_helper() -> None:
    """Containment COMPOSES: a consensus-approved run is not a bypass — the RUN-05 budget and
    the RUN-06 breaker reporting still wrap it, exactly as for a directly-executable outcome."""
    from agentos_sdk.enforce import ResourceLimits

    action = _action()

    class _Governor:
        def __init__(self) -> None:
            self.breaches: list[str] = []

        def limits_for(self, agent_id: str):
            return ResourceLimits(network="deny")

        async def record_breach(self, action, decision, *, limit, budget, observed) -> None:
            self.breaches.append(limit)

    class _Reporter:
        def __init__(self) -> None:
            self.failures: list[tuple[str, str]] = []

        async def record_failure(self, agent_id: str, target: str) -> None:
            self.failures.append((agent_id, target))

    governor, reporter, ran = _Governor(), _Reporter(), []

    async def run():
        ran.append("side-effect")

    from agentos_sdk.enforce import GovernanceResourceExceeded

    with pytest.raises(GovernanceResourceExceeded) as exc:
        asyncio.run(
            governed_call(
                _Pipeline(_consensus_decision(action)),
                action,
                run,
                consensus=_Consensus(True),
                governor=governor,
                reporter=reporter,
            )
        )
    assert ran == []                                  # the RUN-05 network denial is preventive
    assert exc.value.limit == "network" and exc.value.preventive is True
    assert governor.breaches == ["network"]           # RUN-05 audited the breach
    assert reporter.failures == [(action.agent_id, action.target)]  # RUN-06 saw the failure


def test_middleware_and_wrappers_forward_the_consensus_seam() -> None:
    """One enforcement core: the seam must reach it from BOTH PEP forms, or the posture
    diverges between the LangChain hook and a governed wrapper."""
    from langchain.agents.middleware import ToolCallRequest
    from langchain.messages import ToolMessage

    from agentos_sdk import GovernanceMiddleware, governed_mcp_call

    action = _action()
    decision = _consensus_decision(action)

    # Wrapper path: quorum reached -> the wrapped operation runs.
    ran: list[str] = []

    async def run():
        ran.append("side-effect")
        return "ran"

    result = asyncio.run(
        governed_mcp_call(
            _Pipeline(decision), "tok", server="github", tool="create_issue",
            args="x", run=run, consensus=_Consensus(True),
        )
    )
    assert result == "ran" and ran == ["side-effect"]

    # Middleware path: quorum NOT reached -> a contained ToolMessage, tool never invoked.
    mw = GovernanceMiddleware(_Pipeline(decision), "tok", consensus=_Consensus(False))
    req = ToolCallRequest(
        tool_call={"name": "http_get", "args": {"url": "https://api.example.com/x"},
                   "id": "call_con_1"},
        tool=None, state=None, runtime=None,
    )
    calls = []

    async def handler(request):
        calls.append(request)
        return ToolMessage(content="tool ran", tool_call_id=request.tool_call["id"])

    surfaced = asyncio.run(mw.awrap_tool_call(req, handler))
    assert calls == []  # the tool NEVER executed
    assert isinstance(surfaced, ToolMessage) and surfaced.status == "error"
    assert "Blocked by agentos-guard" in surfaced.content


def test_the_substitution_machinery_is_retired() -> None:
    """`require_consensus` was its last member, so the set and its branch are GONE — while
    `record_substitution` and the `enforcement_substitution` kind remain valid for the
    historical records already on the chain."""
    import agentos_sdk.enforce as enforce
    from agentos_controlplane.audit import EVENT_KINDS

    assert not hasattr(enforce, "_SUBSTITUTED_TO_APPROVAL")
    assert hasattr(enforce.ApprovalCoordinator, "record_substitution")
    assert "enforcement_substitution" in EVENT_KINDS


def test_the_protocols_are_exported() -> None:
    from agentos_sdk import ConsensusCoordinator, ConsensusVoter

    assert ConsensusVoter is not None and ConsensusCoordinator is not None
