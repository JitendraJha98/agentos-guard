"""POL-09 e2e — `require_consensus` gates execution on a real quorum (Slice 9f).

The full governed stack over ONE shared store: the real compiled-constitution policy engine,
the real risk scorers, the real audit chain, the real `StoreConsensusCoordinator` — and
either enforcement site (`governed_call` directly, or the LangChain middleware hook).

Determinism: the graduated stage never EMITS `require_consensus` (it is a policy floor, not a
risk band), so the probe is graded by a constitution principle whose effect is exactly that
(tests/fixtures/test_constitution_consensus.yaml). Every test asserts the outcome IS
`require_consensus` before asserting the enforcement behavior, so a policy/tuning drift fails
as a wrong-outcome error rather than silently passing for the wrong reason.
"""

from __future__ import annotations

import asyncio

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.pool import StaticPool

from _opa import BuiltPolicy
from agentos_contract import ActionType, AgentAction, Outcome
from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.audit_verify import verify_chain
from agentos_controlplane.consensus import StoreConsensusCoordinator
from agentos_controlplane.registry import Registry
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import AuditRecord, ConsensusRound, ConsensusVote
from agentos_pipeline.identity import IdentityStage
from agentos_pipeline.policy import ConstitutionPolicyEngine
from agentos_pipeline.posture import PostureMap
from agentos_pipeline.risk import PromptInjectionScorer
from agentos_pipeline.runner import Pipeline
from agentos_sdk import GovernanceMiddleware
from agentos_sdk.enforce import GovernanceDenied, governed_call

AGENT_ID = "consensus-agent"
# `consensus_wasm` (the require_consensus constitution, compiled once per session) lives in
# tests/conftest.py — the gateway PEP e2e drives the same outcome through the same fixture.


class _Voter:
    """A real ConsensusVoter: a named, independent agent with a fixed verdict."""

    def __init__(self, name: str, verdict: bool) -> None:
        self.name = name
        self._verdict = verdict
        self.calls = 0

    async def vote(self, action, decision) -> bool:
        self.calls += 1
        return self._verdict


class _Wired:
    """The real governed stack over ONE shared store, graded to `require_consensus`."""

    def __init__(self, consensus_wasm: BuiltPolicy) -> None:
        engine = create_engine(
            "sqlite+pysqlite:///:memory:",
            poolclass=StaticPool,
            connect_args={"check_same_thread": False},
        )
        create_all(engine)
        self.store = create_session_factory(engine)
        registry = Registry(self.store)
        self.token = registry.register(AGENT_ID)
        self.audit = AuditWriter(self.store, signer=registry.identity)
        self.pipeline = Pipeline(
            identity=IdentityStage(registry.identity),
            policy=ConstitutionPolicyEngine(
                wasm_path=str(consensus_wasm.wasm_path),
                lists=consensus_wasm.bundle.lists,
                constitution_version=consensus_wasm.bundle.constitution_version,
                principles_meta=consensus_wasm.principles_meta,
            ),
            scorers=[PromptInjectionScorer()],
            audit=self.audit,
            posture=PostureMap(),
        )

    def coordinator(self, *voters) -> StoreConsensusCoordinator:
        # ONE AuditWriter per store (the chain-head cache): the coordinator shares the
        # pipeline's writer rather than opening a second appender.
        return StoreConsensusCoordinator(self.store, self.audit, voters)

    def action(self) -> AgentAction:
        return AgentAction(
            agent_id=AGENT_ID,
            type=ActionType.tool_call,
            target="http_post",
            payload={"url": "https://api.example.com/data", "content": ""},
            identity_token=self.token,
        )

    def rounds(self) -> list[ConsensusRound]:
        with self.store() as session:
            return list(session.scalars(select(ConsensusRound)))

    def votes(self) -> list[ConsensusVote]:
        with self.store() as session:
            return list(session.scalars(select(ConsensusVote)))

    def events(self, kind: str) -> list[dict]:
        with self.store() as session:
            rows = session.scalars(select(AuditRecord).order_by(AuditRecord.seq))
            return [r.body for r in rows if r.body.get("kind") == kind]


@pytest.fixture
def wired(consensus_wasm) -> _Wired:
    return _Wired(consensus_wasm)


def _tool_request(call_id: str):
    from langchain.agents.middleware import ToolCallRequest

    return ToolCallRequest(
        tool_call={
            "name": "http_post",
            "args": {"url": "https://api.example.com/data"},
            "id": call_id,
        },
        tool=None,
        state=None,
        runtime=None,
    )


def test_pipeline_grades_the_probe_to_require_consensus(wired) -> None:
    """The determinism precondition every test below depends on."""
    decision = asyncio.run(wired.pipeline.evaluate(wired.action()))
    assert decision.outcome is Outcome.require_consensus


def test_two_of_three_quorum_lets_the_action_run(wired) -> None:
    action, ran = wired.action(), []
    coord = wired.coordinator(_Voter("v1", True), _Voter("v2", True), _Voter("v3", False))

    async def run():
        ran.append("side-effect")
        return "ran"

    result = asyncio.run(governed_call(wired.pipeline, action, run, consensus=coord))

    assert result == "ran" and ran == ["side-effect"]
    rows = wired.rounds()
    assert len(rows) == 1 and rows[0].action_id == action.id
    assert rows[0].approvals == 2 and rows[0].quorum == 2 and rows[0].reached is True
    assert len(wired.votes()) == 3
    assert len(wired.events("consensus_vote")) == 3
    assert len(wired.events("consensus_resolved")) == 1
    assert verify_chain(wired.store).ok  # decision + votes + resolution on ONE chain


def test_one_of_three_denies_and_the_handler_never_runs(wired) -> None:
    action, ran = wired.action(), []
    coord = wired.coordinator(_Voter("v1", True), _Voter("v2", False), _Voter("v3", False))

    async def run():
        ran.append("side-effect")
        return "ran"

    with pytest.raises(GovernanceDenied) as exc:
        asyncio.run(governed_call(wired.pipeline, action, run, consensus=coord))

    assert ran == []  # THE assertion: sub-quorum never executes
    assert exc.value.decision.outcome is Outcome.require_consensus
    assert wired.rounds()[0].reached is False
    assert verify_chain(wired.store).ok


def test_middleware_surfaces_a_denied_round_without_running_the_tool(wired) -> None:
    from langchain.messages import ToolMessage

    coord = wired.coordinator(_Voter("v1", False), _Voter("v2", False), _Voter("v3", True))
    mw = GovernanceMiddleware(wired.pipeline, wired.token, consensus=coord)
    calls = []

    async def handler(request):
        calls.append(request)
        return ToolMessage(content="tool ran", tool_call_id=request.tool_call["id"])

    result = asyncio.run(mw.awrap_tool_call(_tool_request("call_con_1"), handler))

    assert calls == []  # the tool NEVER executed
    assert isinstance(result, ToolMessage)
    assert result.content.startswith("Blocked by agentos-guard")
    # A contained action is surfaced as a FAILED tool result, never a successful one.
    assert result.status == "error"
    assert wired.rounds()[0].reached is False


def test_without_a_coordinator_it_fails_closed(wired) -> None:
    """No consensus seam wired: the quorum cannot be collected, so the action is denied —
    with nothing executed, no round recorded, and nothing audited as consensus."""
    action, ran = wired.action(), []

    async def run():
        ran.append("side-effect")
        return "ran"

    with pytest.raises(GovernanceDenied):
        asyncio.run(governed_call(wired.pipeline, action, run))

    assert ran == []
    assert wired.rounds() == []
    assert wired.events("consensus_resolved") == []
    assert wired.events("enforcement_substitution") == []  # and never escalated to a human
