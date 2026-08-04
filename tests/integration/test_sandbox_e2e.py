"""RUN-03 e2e — a `sandbox` outcome quarantines through the REAL pipeline + PEP (Slice 9a).

The full governed stack: the real compiled-constitution policy engine, the real risk
scorers, the real audit chain, the real `QuarantineSandbox` over one shared store — and
either enforcement site (`governed_call` directly, or the LangChain middleware hook).

Determinism: the probe is a benign allowlisted `http_get`, and the pipeline is built with
`GraduatedThresholds(sandbox_at=0.0, deny_at=1.0)` so ANY risk score grades to `sandbox`
without depending on detector tuning. Every test asserts the outcome IS `sandbox` before
asserting the enforcement behavior, so a threshold/tuning drift fails as a wrong-outcome
error rather than silently passing for the wrong reason.
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
from agentos_controlplane.sandbox import QuarantineSandbox
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import AuditRecord, SandboxRun
from agentos_pipeline.graduated import GraduatedThresholds
from agentos_pipeline.identity import IdentityStage
from agentos_pipeline.policy import ConstitutionPolicyEngine
from agentos_pipeline.posture import PostureMap
from agentos_pipeline.risk import PromptInjectionScorer
from agentos_pipeline.runner import Pipeline
from agentos_sdk import GovernanceMiddleware
from agentos_sdk.enforce import GovernanceDenied, GovernanceQuarantined, governed_call

AGENT_ID = "sandbox-agent"


class _Wired:
    """The real governed stack over ONE shared store, graded to `sandbox` by thresholds."""

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
        self.audit = AuditWriter(self.store, signer=registry.identity)
        self.pipeline = Pipeline(
            identity=IdentityStage(registry.identity),
            policy=ConstitutionPolicyEngine(
                wasm_path=str(constitution_wasm.wasm_path),
                lists=constitution_wasm.bundle.lists,
                constitution_version=constitution_wasm.bundle.constitution_version,
                principles_meta=constitution_wasm.principles_meta,
            ),
            scorers=[PromptInjectionScorer()],
            audit=self.audit,
            posture=PostureMap(),
            # POL-06: any risk >= 0.0 grades to sandbox, and nothing reaches deny.
            thresholds=GraduatedThresholds(sandbox_at=0.0, deny_at=1.0),
        )
        # ONE AuditWriter per store (the chain-head cache): the sandbox shares the
        # pipeline's writer rather than opening a second appender.
        self.sandbox = QuarantineSandbox(self.store, self.audit)

    def action(self) -> AgentAction:
        return AgentAction(
            agent_id=AGENT_ID,
            type=ActionType.tool_call,
            target="http_get",
            payload={"url": "https://api.example.com/data", "content": ""},
            identity_token=self.token,
        )

    def rows(self) -> list[SandboxRun]:
        with self.store() as session:
            return list(session.scalars(select(SandboxRun)))

    def events(self, kind: str) -> list[dict]:
        with self.store() as session:
            rows = session.scalars(select(AuditRecord).order_by(AuditRecord.seq))
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


def test_pipeline_grades_the_probe_to_sandbox(wired) -> None:
    """The determinism precondition every test below depends on."""
    decision = asyncio.run(wired.pipeline.evaluate(wired.action()))
    assert decision.outcome is Outcome.sandbox


def test_governed_call_quarantines_persists_and_audits(wired) -> None:
    action, ran = wired.action(), []

    async def run():
        ran.append("side-effect")
        return "ran"

    with pytest.raises(GovernanceQuarantined) as exc:
        asyncio.run(governed_call(wired.pipeline, action, run, sandbox=wired.sandbox))

    assert exc.value.decision.outcome is Outcome.sandbox   # the right reason
    assert ran == []                                       # the handler NEVER ran

    rows = wired.rows()
    assert len(rows) == 1 and rows[0].action_id == action.id
    assert rows[0].quarantined is True
    events = wired.events("sandbox_executed")
    assert len(events) == 1 and events[0]["run_id"] == str(rows[0].id)
    assert exc.value.sandbox_result.run_id == str(rows[0].id)
    assert verify_chain(wired.store).ok  # decision + containment on ONE chain


def test_middleware_tool_hook_surfaces_quarantined_without_running_the_tool(wired) -> None:
    from langchain.messages import ToolMessage

    mw = GovernanceMiddleware(wired.pipeline, wired.token, sandbox=wired.sandbox)
    calls = []

    async def handler(request):
        calls.append(request)
        return ToolMessage(content="tool ran", tool_call_id=request.tool_call["id"])

    result = asyncio.run(mw.awrap_tool_call(_tool_request("call_sbx_1"), handler))

    assert calls == []  # the tool NEVER executed
    assert isinstance(result, ToolMessage)
    assert result.content.startswith("Quarantined by agentos-guard")
    assert len(wired.rows()) == 1 and len(wired.events("sandbox_executed")) == 1


def test_middleware_without_a_runner_fails_closed_as_blocked(wired) -> None:
    """No sandbox runner wired: containment cannot be enforced, so the hook blocks
    (the pre-9a text) — and still never executes the tool."""
    from langchain.messages import ToolMessage

    mw = GovernanceMiddleware(wired.pipeline, wired.token)  # no sandbox=
    calls = []

    async def handler(request):
        calls.append(request)
        return ToolMessage(content="tool ran", tool_call_id=request.tool_call["id"])

    result = asyncio.run(mw.awrap_tool_call(_tool_request("call_sbx_2"), handler))

    assert calls == []  # fail-CLOSED: still no execution
    assert result.content.startswith("Blocked by agentos-guard")
    assert wired.rows() == []                       # nothing observed
    assert wired.events("sandbox_executed") == []   # nothing audited


def test_quarantine_is_caught_by_existing_governance_denied_handlers(wired) -> None:
    """The subclass contract: user code that only knows `GovernanceDenied` still
    treats a quarantine as a non-execution."""
    action, ran = wired.action(), []

    async def run():
        ran.append("side-effect")

    caught = None
    try:
        asyncio.run(governed_call(wired.pipeline, action, run, sandbox=wired.sandbox))
    except GovernanceDenied as denied:  # the ONLY except-site legacy callers have
        caught = denied
    assert isinstance(caught, GovernanceQuarantined)
    assert ran == []
