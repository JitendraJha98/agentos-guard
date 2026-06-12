"""The REAL outcome-enforcement map (6b-2) — replaces the interim `should_execute`.

| outcome                    | enforcement                                                |
|----------------------------|------------------------------------------------------------|
| allow, warn                | execute                                                    |
| temporary_exception        | execute (a ratified allow; expiry checked at decision time)|
| governance_review          | open review (non-blocking) + execute                       |
| require_approval           | park + block-await; no coordinator -> GovernanceDenied     |
| sandbox, require_consensus | escalate to the approval path (audited substitution);      |
|                            | no coordinator -> GovernanceDenied                         |
| deny                       | GovernanceDenied                                           |

PDP decides, PEP blocks: the blocking lives HERE (the SDK enforcement core) via
the injected coordinator — the pipeline never sleeps. The coordinator under test
is the REAL StoreApprovalCoordinator over an in-memory SQLite ApprovalStore, so
approve/deny/timeout flows exercise the persisted-row rendezvous (D3).
"""

from __future__ import annotations

import asyncio
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, select

from agentos_contract import ActionType, AgentAction, Decision, Outcome, Reason
from agentos_controlplane.approvals import ApprovalStore
from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.coordinator import StoreApprovalCoordinator
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import ApprovalRequest, AuditRecord, GovernanceReview
from agentos_pipeline.posture import PostureMap
from agentos_sdk.enforce import GovernanceDenied, governed_call


@pytest.fixture
def store():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    return create_session_factory(engine)


@pytest.fixture
def approvals(store) -> ApprovalStore:
    return ApprovalStore(store, AuditWriter(store))


def _coordinator(
    approvals: ApprovalStore, store, *, deadline_s: float = 5.0
) -> StoreApprovalCoordinator:
    return StoreApprovalCoordinator(
        approvals, AuditWriter(store), PostureMap(), deadline_s=deadline_s, poll_s=0.05
    )


def _action() -> AgentAction:
    return AgentAction(
        agent_id="test-agent", type=ActionType.tool_call, target="drop_table",
        payload={"url": "https://api.example.com/x", "content": ""},
        identity_token="tok",
    )


def _decision(action: AgentAction, outcome: Outcome, *, reasons=None) -> Decision:
    return Decision(
        action_id=action.id,
        outcome=outcome,
        reasons=reasons
        if reasons is not None
        else [
            Reason(
                stage="policy", code="constitution_principle_fired",
                principle_ref="2.1", evidence={"effect": outcome.value},
            )
        ],
    )


class _Pipeline:
    def __init__(self, decision: Decision) -> None:
        self._decision = decision

    async def evaluate(self, action):
        return self._decision


class _Op:
    def __init__(self) -> None:
        self.ran = 0

    async def __call__(self):
        self.ran += 1
        return "ran"


def _events(store, kind: str) -> list[dict]:
    with store() as session:
        rows = session.scalars(select(AuditRecord).order_by(AuditRecord.seq))
        return [r.body for r in rows if r.body.get("kind") == kind]


async def _resolve_when_parked(approvals: ApprovalStore, *, approved: bool) -> None:
    while not (pending := approvals.list_pending()):
        await asyncio.sleep(0.02)
    await approvals.resolve(pending[0].id, approved=approved, resolver="op@example.com")


# --- require_approval: park + block-await (POL-07) -----------------------------


def test_approve_flow_parks_blocks_then_executes(approvals, store) -> None:
    action = _action()
    pipeline = _Pipeline(_decision(action, Outcome.require_approval))
    coord = _coordinator(approvals, store)
    op = _Op()

    async def scenario():
        resolver = asyncio.create_task(_resolve_when_parked(approvals, approved=True))
        result = await governed_call(pipeline, action, op, coordinator=coord)
        await resolver
        return result

    result = asyncio.run(scenario())
    assert result == "ran" and op.ran == 1  # executed only AFTER the approve
    rows = approvals.list_requests()
    assert len(rows) == 1 and rows[0].status == "approved"
    events = _events(store, "approval_resolved")
    assert len(events) == 1 and events[0]["approved"] is True


def test_deny_resolution_blocks_without_running(approvals, store) -> None:
    action = _action()
    pipeline = _Pipeline(_decision(action, Outcome.require_approval))
    coord = _coordinator(approvals, store)
    op = _Op()

    async def scenario():
        resolver = asyncio.create_task(_resolve_when_parked(approvals, approved=False))
        try:
            with pytest.raises(GovernanceDenied):
                await governed_call(pipeline, action, op, coordinator=coord)
        finally:
            await resolver

    asyncio.run(scenario())
    assert op.ran == 0
    assert approvals.list_requests()[0].status == "denied"


def test_timeout_fail_closed_class_blocks_and_marks_row(approvals, store) -> None:
    """POL-07 timeout -> the per-action-class posture default: fail-closed ->
    GovernanceDenied with code approval_timeout; the row is timed_out + audited."""
    action = _action()
    pipeline = _Pipeline(_decision(action, Outcome.require_approval))
    coord = _coordinator(approvals, store, deadline_s=0.15)
    op = _Op()

    with pytest.raises(GovernanceDenied) as exc:
        asyncio.run(governed_call(pipeline, action, op, coordinator=coord))
    assert op.ran == 0
    assert any(r.code == "approval_timeout" for r in exc.value.decision.reasons)
    assert approvals.list_requests()[0].status == "timed_out"
    assert len(_events(store, "approval_timed_out")) == 1


def test_no_coordinator_require_approval_fail_closed() -> None:
    """The old interim behavior, now explicit: no coordinator -> the blocking
    outcome CANNOT be enforced -> GovernanceDenied (never silent execution)."""
    action = _action()
    pipeline = _Pipeline(_decision(action, Outcome.require_approval))
    op = _Op()
    with pytest.raises(GovernanceDenied):
        asyncio.run(governed_call(pipeline, action, op))
    assert op.ran == 0


# --- sandbox / require_consensus: substituted escalation (until RUN-03/POL-09) --


@pytest.mark.parametrize("outcome", [Outcome.sandbox, Outcome.require_consensus])
def test_unrealized_outcomes_escalate_to_approval_path(approvals, store, outcome) -> None:
    action = _action()
    pipeline = _Pipeline(_decision(action, outcome))
    coord = _coordinator(approvals, store)
    op = _Op()

    async def scenario():
        resolver = asyncio.create_task(_resolve_when_parked(approvals, approved=True))
        result = await governed_call(pipeline, action, op, coordinator=coord)
        await resolver
        return result

    assert asyncio.run(scenario()) == "ran" and op.ran == 1
    subs = _events(store, "enforcement_substitution")
    assert len(subs) == 1
    assert subs[0]["requested"] == outcome.value
    assert subs[0]["substituted"] == "require_approval"


@pytest.mark.parametrize("outcome", [Outcome.sandbox, Outcome.require_consensus])
def test_unrealized_outcomes_without_coordinator_blocked(outcome) -> None:
    action = _action()
    op = _Op()
    with pytest.raises(GovernanceDenied):
        asyncio.run(governed_call(_Pipeline(_decision(action, outcome)), action, op))
    assert op.ran == 0


# --- governance_review: proceed + async non-blocking review (POL-14) -----------


def test_governance_review_executes_and_opens_review(approvals, store) -> None:
    action = _action()
    pipeline = _Pipeline(_decision(action, Outcome.governance_review))
    coord = _coordinator(approvals, store)
    op = _Op()
    result = asyncio.run(governed_call(pipeline, action, op, coordinator=coord))
    assert result == "ran" and op.ran == 1  # proceeded — NO wait on the review
    with store() as session:
        review = session.scalars(select(GovernanceReview)).one()
        assert review.status == "open" and review.action_id == action.id
    assert len(_events(store, "review_opened")) == 1
    # Non-blocking proof: nothing was parked (no approval row, no wait).
    with store() as session:
        assert session.scalars(select(ApprovalRequest)).first() is None


def test_review_obligation_survives_risk_escalation(approvals, store) -> None:
    """D5: a fired governance_review principle keeps its review even when the
    final outcome was escalated past it (here: require_approval) — the review
    opens AND the approval path still blocks."""
    action = _action()
    decision = _decision(
        action, Outcome.require_approval,
        reasons=[
            Reason(
                stage="policy", code="constitution_principle_fired",
                principle_ref="4.1", evidence={"effect": "governance_review"},
            ),
            Reason(stage="graduated", code="require_approval"),
        ],
    )
    coord = _coordinator(approvals, store)
    op = _Op()

    async def scenario():
        resolver = asyncio.create_task(_resolve_when_parked(approvals, approved=True))
        result = await governed_call(_Pipeline(decision), action, op, coordinator=coord)
        await resolver
        return result

    assert asyncio.run(scenario()) == "ran"
    assert len(_events(store, "review_opened")) == 1  # the obligation survived


# --- the executable outcomes ----------------------------------------------------


@pytest.mark.parametrize(
    "outcome", [Outcome.allow, Outcome.warn, Outcome.temporary_exception]
)
def test_executable_outcomes_run_without_coordinator(outcome) -> None:
    action = _action()
    op = _Op()
    result = asyncio.run(governed_call(_Pipeline(_decision(action, outcome)), action, op))
    assert result == "ran" and op.ran == 1


def test_deny_raises_with_decision_attached() -> None:
    action = _action()
    op = _Op()
    with pytest.raises(GovernanceDenied) as exc:
        asyncio.run(governed_call(_Pipeline(_decision(action, Outcome.deny)), action, op))
    assert op.ran == 0
    assert exc.value.decision.outcome is Outcome.deny


# --- middleware/wrapper parity: ONE enforcement core ----------------------------


def test_middleware_tool_hook_blocks_require_approval_without_coordinator() -> None:
    from langchain.agents.middleware import ToolCallRequest
    from langchain.messages import ToolMessage

    from agentos_sdk import GovernanceMiddleware

    action = _action()
    mw = GovernanceMiddleware(_Pipeline(_decision(action, Outcome.require_approval)), "tok")
    req = ToolCallRequest(
        tool_call={"name": "http_get", "args": {"url": "https://api.example.com/x"},
                   "id": "call_ra_1"},
        tool=None, state=None, runtime=None,
    )
    calls = []

    async def handler(request):
        calls.append(request)
        return ToolMessage(content="tool ran", tool_call_id=request.tool_call["id"])

    result = asyncio.run(mw.awrap_tool_call(req, handler))
    assert calls == []  # the tool NEVER ran
    assert isinstance(result, ToolMessage)
    assert result.tool_call_id == "call_ra_1"
    assert "Blocked by agentos-guard" in result.content


def test_middleware_model_hook_blocks_require_approval_without_coordinator() -> None:
    from langchain.messages import AIMessage

    from agentos_sdk import GovernanceMiddleware

    action = _action()
    mw = GovernanceMiddleware(_Pipeline(_decision(action, Outcome.require_approval)), "tok")

    class _Req:
        model = type("M", (), {"model_name": "test-model"})()
        messages = []

    calls = []

    async def handler(request):
        calls.append(request)
        return AIMessage(content="model ran")

    result = asyncio.run(mw.awrap_model_call(_Req(), handler))
    assert calls == []  # the provider was NEVER invoked
    assert isinstance(result, AIMessage)
    assert "Blocked by agentos-guard" in result.content


def test_parity_tool_hook_vs_wrapper_same_map(approvals, store) -> None:
    """The SAME require_approval decision through the middleware hook and a
    governed wrapper: both park-approve-execute via the one shared core."""
    from langchain.agents.middleware import ToolCallRequest
    from langchain.messages import ToolMessage

    from agentos_sdk import GovernanceMiddleware, governed_mcp_call

    action = _action()
    decision = _decision(action, Outcome.require_approval)
    coord = _coordinator(approvals, store)

    # Wrapper path
    op = _Op()

    async def wrapper_scenario():
        resolver = asyncio.create_task(_resolve_when_parked(approvals, approved=True))
        result = await governed_mcp_call(
            _Pipeline(decision), "tok", server="github", tool="create_issue",
            args="x", run=op, coordinator=coord,
        )
        await resolver
        return result

    assert asyncio.run(wrapper_scenario()) == "ran" and op.ran == 1

    # Middleware path (same coordinator wiring)
    mw = GovernanceMiddleware(_Pipeline(decision), "tok", coordinator=coord)
    req = ToolCallRequest(
        tool_call={"name": "http_get", "args": {"url": "https://api.example.com/x"},
                   "id": "call_par_1"},
        tool=None, state=None, runtime=None,
    )
    handled = []

    async def handler(request):
        handled.append(request)
        return ToolMessage(content="tool ran", tool_call_id=request.tool_call["id"])

    async def middleware_scenario():
        resolver = asyncio.create_task(_resolve_when_parked(approvals, approved=True))
        result = await mw.awrap_tool_call(req, handler)
        await resolver
        return result

    result = asyncio.run(middleware_scenario())
    assert len(handled) == 1 and result.content == "tool ran"
    # Both paths parked one approval each -> two approved rows, one shared map.
    assert [r.status for r in approvals.list_requests()] == ["approved", "approved"]


def test_should_execute_is_retired() -> None:
    """The interim posture primitive is GONE — the outcome map is the only core."""
    import agentos_sdk.enforce as enforce

    assert not hasattr(enforce, "should_execute")
