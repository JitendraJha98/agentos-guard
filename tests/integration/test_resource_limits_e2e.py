"""RUN-05 e2e over the REAL governed stack (Slice 9c, Task 4).

The acceptance proof over ONE shared store and the SAME `ResourceGovernorStore` instance the PEP
reads, so the in-memory budget the hot path consults is the one administration updates:

  - baseline: an unbudgeted agent's benign allowlisted `http_get` EXECUTES (so a later block is
    attributable to the budget, not to policy)
  - `network="deny"`                -> the same call is refused and the handler NEVER runs, audited
                                       as one `resource_limit_exceeded` event
  - through the LangChain middleware -> the block is surfaced as a `ToolMessage` with
                                       `status == "error"` (the 9a contained-outcome convention)
  - `wall_s`                        -> a slow awaiting handler is cancelled
  - a DIFFERENT, unbudgeted agent   -> entirely unaffected (budgets are per agent)
  - the audit chain still verifies with decisions and breaches interleaved on it

The pipeline is the real compiled-constitution engine over a benign allowed action, so the ONLY
thing that can refuse it here is the resource budget.
"""

from __future__ import annotations

import asyncio

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.pool import StaticPool

from agentos_contract import ActionType, AgentAction, Outcome
from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.audit_verify import verify_chain
from agentos_controlplane.registry import Registry
from agentos_controlplane.resource_governor import ResourceGovernorStore
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import AuditRecord
from agentos_pipeline.identity import IdentityStage
from agentos_pipeline.policy import ConstitutionPolicyEngine
from agentos_pipeline.posture import PostureMap
from agentos_pipeline.risk import PromptInjectionScorer
from agentos_pipeline.runner import Pipeline
from agentos_sdk import GovernanceMiddleware
from agentos_sdk.enforce import GovernanceDenied, GovernanceResourceExceeded, governed_call

AGENT_ID = "budgeted-agent"
OTHER_AGENT = "unbudgeted-agent"


class _Wired:
    """Pipeline + ResourceGovernorStore over ONE shared store and the SAME governor instance."""

    def __init__(self, constitution_wasm) -> None:
        engine = create_engine(
            "sqlite+pysqlite:///:memory:",
            poolclass=StaticPool,
            connect_args={"check_same_thread": False},
        )
        create_all(engine)
        self.store = create_session_factory(engine)
        registry = Registry(self.store)
        self.token = registry.register(AGENT_ID)
        self.other_token = registry.register(OTHER_AGENT)
        audit = AuditWriter(self.store)  # ONE writer per store (the chain-head cache)
        self.governor = ResourceGovernorStore(self.store, audit)
        self.pipeline = Pipeline(
            identity=IdentityStage(registry.identity),
            policy=ConstitutionPolicyEngine(
                wasm_path=str(constitution_wasm.wasm_path),
                lists=constitution_wasm.bundle.lists,
                constitution_version=constitution_wasm.bundle.constitution_version,
                principles_meta=constitution_wasm.principles_meta,
            ),
            scorers=[PromptInjectionScorer()],
            audit=audit,
            posture=PostureMap(),
        )

    def action(self, agent_id: str, token: str) -> AgentAction:
        # Benign and allowlisted: only the budget can refuse it.
        return AgentAction(
            agent_id=agent_id,
            type=ActionType.tool_call,
            target="http_get",
            payload={"url": "https://api.example.com/data", "content": ""},
            identity_token=token,
        )

    def call(self, agent_id: str, token: str, run):
        return asyncio.run(
            governed_call(
                self.pipeline, self.action(agent_id, token), run, governor=self.governor
            )
        )

    def events(self, kind: str) -> list[dict]:
        with self.store() as s:
            rows = s.scalars(select(AuditRecord).order_by(AuditRecord.seq))
            return [r.body for r in rows if r.body.get("kind") == kind]


@pytest.fixture
def wired(constitution_wasm) -> _Wired:
    return _Wired(constitution_wasm)


def _tool_request(call_id: str):
    from langchain.agents.middleware import ToolCallRequest

    return ToolCallRequest(
        tool_call={
            "name": "http_get",
            "args": {"url": "https://api.example.com/data"},
            "id": call_id,
        },
        tool=None,
        state=None,
        runtime=None,
    )


# --- baseline ----------------------------------------------------------------


def test_an_unbudgeted_agent_executes_normally(wired: _Wired) -> None:
    """The precondition every block below depends on: with no budget row the action is ALLOWED and
    the handler runs, so a later refusal is the budget rather than policy."""
    ran = []

    async def run():
        ran.append(1)
        return "tool-result"

    assert wired.governor.limits_for(AGENT_ID) is None
    assert wired.call(AGENT_ID, wired.token, run) == "tool-result"
    assert ran == [1]
    assert asyncio.run(wired.pipeline.evaluate(wired.action(AGENT_ID, wired.token))).outcome is (
        Outcome.allow
    )


# --- network: preventive over the real stack ---------------------------------


def test_network_deny_refuses_the_egress_call_without_running_it(wired: _Wired) -> None:
    asyncio.run(wired.governor.set_limits(AGENT_ID, network="deny", set_by="op@x"))
    ran = []

    async def run():
        ran.append(1)
        return "tool-result"

    with pytest.raises(GovernanceResourceExceeded) as exc:
        wired.call(AGENT_ID, wired.token, run)

    assert exc.value.limit == "network"
    assert exc.value.preventive is True
    assert ran == []  # no egress: the handler was never invoked
    assert exc.value.decision.outcome is Outcome.allow  # policy allowed it; the BUDGET refused

    breaches = wired.events("resource_limit_exceeded")
    assert len(breaches) == 1
    assert breaches[0]["agent_id"] == AGENT_ID and breaches[0]["limit"] == "network"
    assert breaches[0]["action_type"] == "tool_call"
    assert verify_chain(wired.store).ok  # decisions + budget events on ONE chain


def test_the_middleware_surfaces_the_block_as_a_failed_tool_message(wired: _Wired) -> None:
    """The 9a contained-outcome convention: a hook must not raise into the agent loop, and the
    stand-in ToolMessage must carry status="error" so a consumer branching on status never reads a
    refused call as a completed one."""
    from langchain.messages import ToolMessage

    asyncio.run(wired.governor.set_limits(AGENT_ID, network="deny", set_by="op@x"))
    mw = GovernanceMiddleware(wired.pipeline, wired.token, governor=wired.governor)
    calls = []

    async def handler(request):
        calls.append(request)
        return ToolMessage(content="tool ran", tool_call_id=request.tool_call["id"])

    result = asyncio.run(mw.awrap_tool_call(_tool_request("call_res_1"), handler))

    assert calls == []  # the tool NEVER executed
    assert isinstance(result, ToolMessage)
    assert result.status == "error"
    assert "Resource limit exceeded" in result.content
    assert "network" in result.content
    assert len(wired.events("resource_limit_exceeded")) == 1


# --- wall_s over the real stack ----------------------------------------------


def test_a_wall_budget_cancels_a_slow_handler(wired: _Wired) -> None:
    asyncio.run(wired.governor.set_limits(AGENT_ID, wall_s=0.05, set_by="op@x"))
    completed = []

    async def run():
        await asyncio.sleep(5)
        completed.append("side-effect")  # must NEVER happen
        return "tool-result"

    with pytest.raises(GovernanceResourceExceeded) as exc:
        wired.call(AGENT_ID, wired.token, run)

    assert exc.value.limit == "wall_s" and exc.value.preventive is True
    assert completed == []
    assert wired.events("resource_limit_exceeded")[0]["limit"] == "wall_s"


# --- isolation + durability --------------------------------------------------


def test_budgets_are_per_agent_over_the_real_stack(wired: _Wired) -> None:
    """Budgeting one agent must not quietly throttle the rest of the fleet."""
    asyncio.run(wired.governor.set_limits(AGENT_ID, network="deny", set_by="op"))
    ran = []

    async def run():
        ran.append(1)
        return "tool-result"

    with pytest.raises(GovernanceResourceExceeded):
        wired.call(AGENT_ID, wired.token, run)
    assert ran == []

    assert wired.call(OTHER_AGENT, wired.other_token, run) == "tool-result"
    assert ran == [1]


def test_a_budget_breach_is_caught_by_existing_governance_denied_handlers(wired: _Wired) -> None:
    """The subclass contract over the real stack: code that only knows `GovernanceDenied` still
    treats a budget refusal as a non-execution."""
    asyncio.run(wired.governor.set_limits(AGENT_ID, network="deny", set_by="op"))
    ran = []

    async def run():
        ran.append(1)

    caught = None
    try:
        wired.call(AGENT_ID, wired.token, run)
    except GovernanceDenied as denied:  # the ONLY except-site legacy callers have
        caught = denied
    assert isinstance(caught, GovernanceResourceExceeded)
    assert ran == []


def test_budgets_survive_a_fresh_store_over_the_same_tables(wired: _Wired) -> None:
    """Durability: a restarted control plane reloads the budget and keeps enforcing it."""
    asyncio.run(wired.governor.set_limits(AGENT_ID, wall_s=1.5, network="deny", set_by="op"))

    fresh = ResourceGovernorStore(wired.store, AuditWriter(wired.store))
    reloaded = fresh.limits_for(AGENT_ID)
    assert reloaded is not None
    assert reloaded.network == "deny" and reloaded.wall_s == 1.5
    assert fresh.limits_for(OTHER_AGENT) is None


def test_administration_and_breaches_share_the_one_verified_chain(wired: _Wired) -> None:
    asyncio.run(wired.governor.set_limits(AGENT_ID, network="deny", set_by="op@x"))

    async def run():
        return "tool-result"

    with pytest.raises(GovernanceResourceExceeded):
        wired.call(AGENT_ID, wired.token, run)

    assigned = wired.events("resource_limit_set")
    assert len(assigned) == 1 and assigned[0]["set_by"] == "op@x"
    assert len(wired.events("resource_limit_exceeded")) == 1
    assert verify_chain(wired.store).ok
