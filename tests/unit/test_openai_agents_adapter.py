"""INT-08 — the OpenAI Agents SDK adapter.

`agents` lives in the OPTIONAL `adapters` dependency group, so this module skips cleanly when it
is absent (exactly like the redteam extra).

API shapes introspected from the INSTALLED openai-agents 0.20.0 (do not re-derive from docs):
* `function_tool(func=None, *, name_override, description_override, docstring_style,
  use_docstring_info, failure_error_function, strict_mode, is_enabled, needs_approval,
  tool_input_guardrails, tool_output_guardrails, timeout, ...)`
* `agents.tool_guardrails.ToolInputGuardrail(guardrail_function, name=None)`, whose function takes a
  `ToolInputGuardrailData(context: ToolContext, agent: Agent)` and returns a
  `ToolGuardrailFunctionOutput` built via `.allow(output_info=None)` /
  `.reject_content(message, output_info=None)` / `.raise_exception(output_info=None)`.
* `ToolContext.tool_name: str` and `ToolContext.tool_arguments: str` (a RAW JSON string, not a dict).
"""

from __future__ import annotations

import asyncio
import inspect

import pytest

from agentos_contract import ActionType, Decision, Outcome, Reason, SandboxResult
from agentos_sdk.enforce import GovernanceDenied, GovernanceQuarantined

agents = pytest.importorskip("agents", reason="openai-agents (the `adapters` group) is not installed")

from agentos_sdk.adapters.openai_agents import governed_tool  # noqa: E402

EXFIL_URL = "https://evil.example.net/collect"
TOKEN = "tok"


class _Pipeline:
    """A stub PDP with a fixed outcome, keeping every action it was HANDED.

    The kept actions are how the normalization assertions below read what the PEP built — the
    adapter's whole contribution is that translation, so it is asserted on directly.
    """

    def __init__(self, outcome: Outcome) -> None:
        self._outcome = outcome
        self.actions: list = []

    async def evaluate(self, action) -> Decision:
        self.actions.append(action)
        return Decision(
            action_id=action.id,
            outcome=self._outcome,
            reasons=[Reason(stage="policy", code="constitution_principle_fired")],
        )


class _Sandbox:
    """A stub RUN-03 SandboxRunner. It observes; it is never given the handler."""

    def __init__(self) -> None:
        self.runs: list = []

    async def run(self, action, decision) -> SandboxResult:
        self.runs.append(action)
        return SandboxResult(quarantined=True, run_id="run-1", detail="observed")


def _tool(pipeline, ran: list, **seams):
    """The governed `http_get` under test: appending to `ran` is the SIDE EFFECT that must not
    happen on a block."""

    @governed_tool(pipeline, TOKEN, **seams)
    async def http_get(url: str, content: str = "") -> str:
        ran.append(url)
        return "fetched"

    return http_get


def test_a_deny_never_invokes_the_tool_body() -> None:
    """THE load-bearing assertion (D-03): blocking is STRUCTURAL — the body is simply never
    called, so there is no side effect and no egress to undo."""
    pipeline = _Pipeline(Outcome.deny)
    ran: list = []
    tool = _tool(pipeline, ran)

    with pytest.raises(GovernanceDenied):
        asyncio.run(tool(EXFIL_URL))

    assert ran == []


def test_an_allow_runs_the_body_and_returns_its_value() -> None:
    """The control for the test above: without this, a wrapper that blocked EVERYTHING would
    pass the deny assertion while governing nothing."""
    pipeline = _Pipeline(Outcome.allow)
    ran: list = []
    tool = _tool(pipeline, ran)

    assert asyncio.run(tool("https://api.example.com/data")) == "fetched"
    assert ran == ["https://api.example.com/data"]


def test_a_positional_call_is_bound_to_the_tools_parameter_names() -> None:
    """A positional argument must reach the PDP under the NAME the operator wrote principles
    against. `{"0": "..."}` (or an empty payload) would make `when: field: url` unenforceable —
    the constitution would silently match nothing."""
    pipeline = _Pipeline(Outcome.allow)
    asyncio.run(_tool(pipeline, [])(EXFIL_URL))

    action = pipeline.actions[-1]
    assert action.type is ActionType.tool_call
    assert action.target == "http_get"
    assert action.payload == {"url": EXFIL_URL, "content": ""}
    assert action.identity_token == TOKEN


def test_a_sync_tool_body_is_governed_too() -> None:
    """The Agents SDK accepts sync tool functions, so the wrapper must not assume a coroutine —
    an un-awaitable body must run, not return a coroutine object the model would stringify."""
    pipeline = _Pipeline(Outcome.allow)
    ran: list = []

    @governed_tool(pipeline, TOKEN)
    def read_file(path: str) -> str:
        ran.append(path)
        return "contents"

    assert asyncio.run(read_file("/etc/hosts")) == "contents"
    assert ran == ["/etc/hosts"]


def test_the_wrapper_preserves_the_signature_function_tool_introspects() -> None:
    """`function_tool` builds the model-facing JSON schema from the wrapped function's name,
    docstring and signature. Without `update_wrapper` the model would be offered a tool called
    `_governed` taking `(*args, **kwargs)` — unusable, and the schema would stop matching what
    the constitution governs."""
    tool = _tool(_Pipeline(Outcome.allow), [])

    assert tool.__name__ == "http_get"
    assert "url" in inspect.signature(tool).parameters


def test_the_sandbox_seam_is_threaded_so_a_quarantine_stays_a_quarantine() -> None:
    """The Phase-9 seams are PASSED THROUGH, not dropped: delete `sandbox=sandbox` from the
    `governed_call` call and this fails, instead of the suite silently downgrading RUN-03
    containment to a plain deny for this PEP form."""
    pipeline = _Pipeline(Outcome.sandbox)
    sandbox = _Sandbox()
    ran: list = []
    tool = _tool(pipeline, ran, sandbox=sandbox)

    with pytest.raises(GovernanceQuarantined) as excinfo:
        asyncio.run(tool(EXFIL_URL))

    assert excinfo.value.sandbox_result.quarantined is True
    assert len(sandbox.runs) == 1  # the runner really observed it
    assert ran == []  # ...and the real body never ran


def test_an_unwired_sandbox_seam_fails_closed() -> None:
    """The same outcome with NO runner: containment cannot be enforced, so the call is denied —
    never silently executed."""
    pipeline = _Pipeline(Outcome.sandbox)
    ran: list = []

    with pytest.raises(GovernanceDenied):
        asyncio.run(_tool(pipeline, ran)(EXFIL_URL))

    assert ran == []


def test_the_verified_extension_points_still_exist() -> None:
    """The adapter is built on these; if a version bump removes one, fail HERE with a clear
    message rather than somewhere deep inside an agent run."""
    import inspect

    from agents.tool_guardrails import (
        ToolGuardrailFunctionOutput,
        ToolInputGuardrail,
        ToolInputGuardrailData,
    )

    params = inspect.signature(agents.function_tool).parameters
    assert "tool_input_guardrails" in params
    assert hasattr(ToolInputGuardrail, "run")
    for constructor in ("allow", "reject_content"):
        assert hasattr(ToolGuardrailFunctionOutput, constructor)
    # The guardrail reads the call through `data.context`, so those two field names are load-bearing.
    assert "context" in ToolInputGuardrailData.__dataclass_fields__
    tool_context = agents.tool_context.ToolContext
    for field in ("tool_name", "tool_arguments"):
        assert field in tool_context.__dataclass_fields__
    for hook in ("on_tool_start", "on_llm_start"):
        assert hasattr(agents.RunHooks, hook)
