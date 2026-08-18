"""INT-08 e2e — a REAL `Runner.run` over the REAL governed stack, with no network.

The full stack: the real compiled-constitution policy engine, the real risk scorers, the real
identity stage and audit chain, one shared store — driving a REAL OpenAI-Agents agent loop whose
model is a FAKE `ModelProvider` (so there is no API key, no HTTP, and a deterministic script).

The load-bearing part is the `calls` list on the tool body. "A block never executes the tool"
cannot be proved from the model's transcript — a framework could run the tool, discard the result
and still report an error to the model, and the side effect would already have happened. It is
proved by the body never being ENTERED, so every assertion below is written against `calls`, with
an ALLOWED control so the deny assertion cannot pass vacuously through broken wiring.

API shapes introspected from the INSTALLED openai-agents 0.20.0 (recorded so the next reader does
not repeat it):
* `ModelResponse(output: list[TResponseOutputItem], usage: Usage, response_id: str | None,
  request_id=None, raw_usage=None)` — a pydantic dataclass; the first three are positional-required.
* A function-tool call is `openai.types.responses.ResponseFunctionToolCall(arguments: str (JSON),
  call_id: str, name: str, type="function_call")`; a terminating text turn is
  `ResponseOutputMessage(id, content=[ResponseOutputText(annotations=[], text, type="output_text")],
  role="assistant", status="completed", type="message")`.
* `agents.Model` is abstract on BOTH `get_response` and `stream_response`, so a fake must define
  both even when only one is exercised.
* `ToolInputGuardrailData` carries `.context` (a `ToolContext` with `.tool_name` and a RAW JSON
  STRING `.tool_arguments`) and `.agent` — there is no `.arguments` attribute on the data object.
* `ToolGuardrailFunctionOutput.reject_content(message, output_info=None)` / `.allow(output_info=None)`.
"""

from __future__ import annotations

import asyncio
import json

import pytest
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from agentos_contract import ActionType
from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.registry import Registry
from agentos_controlplane.sandbox import QuarantineSandbox
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_pipeline.graduated import GraduatedThresholds
from agentos_pipeline.identity import IdentityStage
from agentos_pipeline.policy import ConstitutionPolicyEngine
from agentos_pipeline.posture import PostureMap
from agentos_pipeline.risk import PromptInjectionScorer
from agentos_pipeline.runner import Pipeline
from agentos_sdk.coverage import coverage_matrix, verify_coverage

agents = pytest.importorskip("agents", reason="openai-agents (the `adapters` group) is not installed")

from agents import (  # noqa: E402
    Agent,
    Model,
    ModelProvider,
    ModelResponse,
    RunConfig,
    Runner,
    function_tool,
)
from agents.usage import Usage  # noqa: E402
from openai.types.responses import (  # noqa: E402
    ResponseFunctionToolCall,
    ResponseOutputMessage,
    ResponseOutputText,
)

from agentos_sdk.adapters.openai_agents import (  # noqa: E402
    governance_tool_guardrail,
    governed_tool,
)

AGENT_ID = "adapter-agent"
ALLOWED_URL = "https://api.example.com/data"      # in the test constitution's egress_allowlist
EXFIL_URL = "https://evil.example.net/collect"    # NOT allowlisted -> principle 1.1 denies


def _tool_call(name: str, args: dict) -> ResponseFunctionToolCall:
    return ResponseFunctionToolCall(
        arguments=json.dumps(args), call_id="call-1", name=name, type="function_call"
    )


def _text(text: str) -> ResponseOutputMessage:
    return ResponseOutputMessage(
        id="msg-1",
        content=[ResponseOutputText(annotations=[], text=text, type="output_text")],
        role="assistant",
        status="completed",
        type="message",
    )


class _FakeModel(Model):
    """A scripted model: turn 1 calls the tool, turn 2 answers in text so the run terminates.

    No network, no API key, no provider SDK — the agent loop itself is the real one.
    """

    def __init__(self, url: str) -> None:
        self.turns = 0
        self._url = url

    async def get_response(self, *args, **kwargs) -> ModelResponse:
        self.turns += 1
        output = (
            [_tool_call("http_get", {"url": self._url})] if self.turns == 1 else [_text("done")]
        )
        return ModelResponse(output=output, usage=Usage(), response_id=None)

    def stream_response(self, *args, **kwargs):
        # Abstract on `Model`, never reached: `Runner.run` (non-streaming) uses get_response.
        raise NotImplementedError


class _FakeProvider(ModelProvider):
    def __init__(self, model: Model) -> None:
        self._model = model

    def get_model(self, model_name: str | None) -> Model:
        return self._model


class _Stack:
    """The REAL pipeline over one shared in-memory store, plus the agent's registered token."""

    def __init__(self, constitution, *, thresholds: GraduatedThresholds = GraduatedThresholds(),
                 wire_sandbox: bool = False) -> None:
        engine = create_engine(
            "sqlite+pysqlite:///:memory:",
            poolclass=StaticPool,
            connect_args={"check_same_thread": False},
        )
        create_all(engine)
        self.store = create_session_factory(engine)
        registry = Registry(self.store)
        self.token = registry.register(AGENT_ID)
        audit = AuditWriter(self.store, signer=registry.identity)
        self.pipeline = Pipeline(
            identity=IdentityStage(registry.identity),
            policy=ConstitutionPolicyEngine(
                wasm_path=str(constitution.wasm_path),
                lists=constitution.bundle.lists,
                constitution_version=constitution.bundle.constitution_version,
                principles_meta=constitution.principles_meta,
            ),
            scorers=[PromptInjectionScorer()],
            audit=audit,
            posture=PostureMap(),
            thresholds=thresholds,
        )
        self.sandbox = QuarantineSandbox(self.store, audit) if wire_sandbox else None


def _run(agent: Agent, url_model: _FakeModel):
    return asyncio.run(
        Runner.run(
            agent,
            "fetch it",
            run_config=RunConfig(model_provider=_FakeProvider(url_model), tracing_disabled=True),
        )
    )


def _wrapped_agent(stack: _Stack, calls: list) -> Agent:
    """The PRIMARY entry point: the governed CALLABLE, wrapped by `function_tool`."""

    @function_tool
    @governed_tool(stack.pipeline, stack.token, sandbox=stack.sandbox)
    async def http_get(url: str) -> str:
        calls.append(url)
        return "fetched"

    return Agent(name="adapter-agent", tools=[http_get])


def _guardrail_agent(stack: _Stack, calls: list) -> Agent:
    """The framework-native entry point: the SDK's own tool-input guardrail."""

    @function_tool(tool_input_guardrails=[governance_tool_guardrail(stack.pipeline, stack.token)])
    async def http_get(url: str) -> str:
        calls.append(url)
        return "fetched"

    return Agent(name="adapter-agent", tools=[http_get])


def test_a_denied_tool_never_executes_in_a_real_agent_run(constitution_wasm) -> None:
    """THE load-bearing assertion (D-03, no egress): the model asks for an exfiltrating
    `http_get`, the constitution denies it, and the tool body is NEVER entered — through a real
    `Runner.run`, over the real compiled constitution."""
    stack = _Stack(constitution_wasm)
    calls: list = []

    result = _run(_wrapped_agent(stack, calls), _FakeModel(EXFIL_URL))

    assert calls == []  # nothing ran: no request, no exfiltration
    # ...and the model was TOLD, so the agent loop continues instead of dying.
    outputs = [getattr(item, "output", "") for item in result.new_items]
    assert any("Blocked by agentos-guard" in str(o) for o in outputs)


def test_an_allowed_tool_does_execute_in_the_same_real_agent_run(constitution_wasm) -> None:
    """The CONTROL for the test above. Without it, a wrapper that broke the tool wiring
    altogether — or an agent that never dispatched the call — would pass the deny assertion
    while governing nothing."""
    stack = _Stack(constitution_wasm)
    calls: list = []

    result = _run(_wrapped_agent(stack, calls), _FakeModel(ALLOWED_URL))

    assert calls == [ALLOWED_URL]  # the body really ran, exactly once
    assert result.final_output == "done"


def test_the_guardrail_entry_point_also_refuses_the_hostile_call(constitution_wasm) -> None:
    """The framework-native second entry point reaches the SAME decision: a governed block is
    mapped onto the SDK's reject behavior, and the SDK does not invoke a tool whose input
    guardrail rejected — so the body never runs here either."""
    stack = _Stack(constitution_wasm)
    calls: list = []

    result = _run(_guardrail_agent(stack, calls), _FakeModel(EXFIL_URL))

    assert calls == []
    outputs = [str(getattr(item, "output", "")) for item in result.new_items]
    assert any("Blocked by agentos-guard" in o for o in outputs)


def test_the_guardrail_entry_point_lets_an_allowed_call_through(constitution_wasm) -> None:
    """...and its control: the guardrail is a governor, not a wall."""
    stack = _Stack(constitution_wasm)
    calls: list = []

    _run(_guardrail_agent(stack, calls), _FakeModel(ALLOWED_URL))

    assert calls == [ALLOWED_URL]


def test_a_sandbox_outcome_quarantines_the_tool_in_a_real_run(constitution_wasm) -> None:
    """RUN-03 through this PEP form: the `sandbox` outcome is CONTAINMENT, not a plain deny.
    Delete `sandbox=` from the adapter's `governed_call` and this is what fails, instead of the
    suite silently downgrading quarantine to a deny for the OpenAI-Agents path.

    Graded so ANY risk lands on `sandbox` and nothing reaches `deny` (the determinism trick from
    test_sandbox_e2e), with the REAL QuarantineSandbox wired."""
    stack = _Stack(
        constitution_wasm,
        thresholds=GraduatedThresholds(sandbox_at=0.0, deny_at=1.0),
        wire_sandbox=True,
    )
    calls: list = []

    result = _run(_wrapped_agent(stack, calls), _FakeModel(ALLOWED_URL))

    assert calls == []  # quarantine means the real operation never happened
    outputs = [str(getattr(item, "output", "")) for item in result.new_items]
    assert any("Quarantined by agentos-guard" in o for o in outputs)


def test_the_adapter_is_a_registered_interception_path() -> None:
    """INT-06 stays honest: the adapter is a real PEP form, and the coverage matrix records it
    ALONGSIDE the SDK middleware and the gateway rather than replacing them."""
    import agentos_gateway  # noqa: F401 — importing registers the gateway normalizers
    import agentos_sdk  # noqa: F401 — and the LangChain PEP's

    verify_coverage()  # no gaps
    entries = coverage_matrix()[ActionType.tool_call]
    assert any(e.endswith("normalize_action") for e in entries)  # LangChain middleware
    assert any(e.endswith("normalize_gateway_tool_call") for e in entries)  # the gateway
    assert any(e.endswith("normalize_openai_agents_tool_call") for e in entries)  # this adapter
