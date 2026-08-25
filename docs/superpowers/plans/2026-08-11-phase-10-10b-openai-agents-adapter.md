# Phase 10 · Slice 10b — OpenAI Agents SDK Adapter (INT-08) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Commits end
> with a second `-m "Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"`. Tests:
> `./.venv/Scripts/python.exe -m pytest`. TDD per task, one commit each. Gates `floor_invariant`
> + `regression_lock` green at every commit. (`-m latency` is wall-clock and marginal on this box
> — if it fails, re-run when idle and compare against a scratch worktree at the Phase-9 base
> `886ad59` before claiming a regression. NEVER loosen the budget.)

**Goal (INT-08):** A second framework adapter — the **OpenAI Agents SDK** — intercepts agent actions
behind the same `evaluate(AgentAction) -> Decision` contract, proving the control plane is not
LangChain-only.

**Architecture:** The adapter contributes **normalization + a framework entry point only**;
enforcement goes through the SAME `agentos_sdk.enforce.governed_call` every other PEP uses, so
Phase-9 containment (sandbox quarantine, consensus quorum, resource budgets, breaker reporting)
applies unchanged. Two entry points, one core:
1. `governed_tool(...)` — wraps the tool **callable** before `function_tool` registers it. Blocking is
   structural: on a governed block the real body is simply never invoked.
2. `governance_tool_guardrail(...)` — builds a framework-native `ToolInputGuardrail` for
   `function_tool(tool_input_guardrails=[...])`, mapping a block onto the SDK's reject/raise behavior.

The callable wrapper is the PRIMARY path deliberately: the SDK documents no general pre-execution
middleware and its hook/guardrail semantics have shifted across versions, so an API change must never
be able to silently disable enforcement.

**Tech Stack:** `openai-agents` (new OPTIONAL dependency group `adapters`), `agentos-sdk`,
`agentos-contract`, pytest.

> First commit in this slice: `docs(phase-10): Slice 10b plan` for this file, then the tasks below.

## Verified API facts (introspected from openai-agents 0.21.1 — do NOT re-derive from docs)
- `function_tool(func=None, *, name_override=None, description_override=None, use_docstring_info=True,
  failure_error_function=..., strict_mode=True, is_enabled=True, needs_approval=False,
  tool_input_guardrails=None, tool_output_guardrails=None, timeout=None, ...)`
- `agents.tool_guardrails` exports `ToolInputGuardrail` (`.run(data: ToolInputGuardrailData) ->
  ToolGuardrailFunctionOutput`), plus `AllowBehavior`, `RejectContentBehavior`, `RaiseExceptionBehavior`.
- `RunHooks` methods: `on_agent_start/end`, `on_tool_start/end`, `on_llm_start/end`, `on_handoff`.
- `Model.get_response(system_instructions, input, model_settings, tools, output_schema, handoffs,
  tracing, *, previous_response_id, conversation_id, prompt) -> ModelResponse`
- `ModelProvider.get_model(model_name) -> Model`
- `RunConfig(...)` fields include `model`, `model_provider`, `tracing_disabled`.
- `Runner.run(starting_agent, input, *, context=None, max_turns=10, hooks=None, run_config=None, ...)`

**Not yet verified — introspect before writing the fake model (Task 3):** the exact construction of
`ModelResponse` and of a function-tool-call output item. Run
`python -c "import agents, inspect; print(inspect.signature(agents.ModelResponse))"` and inspect
`agents.items` / the `openai.types.responses` item classes, then build the fake from what the
installed version actually requires. Do NOT guess these shapes.

## File structure
- Modify root `pyproject.toml` — `[dependency-groups] adapters = ["openai-agents>=0.21,<1"]`.
- Create `packages/sdk/src/agentos_sdk/adapters/__init__.py` — package marker + lazy exports.
- Create `packages/sdk/src/agentos_sdk/adapters/openai_agents.py` — the adapter.
- Tests: `tests/unit/test_openai_agents_adapter.py`,
  `tests/integration/test_openai_agents_e2e.py`.

---

### Task 1: the `adapters` dependency group

**Files:** modify root `pyproject.toml`; test `tests/unit/test_openai_agents_adapter.py` (guard only).

- [ ] Add to the root `pyproject.toml`, alongside the existing `[dependency-groups]` entries
  (`dev`, `redteam`):
```toml
adapters = ["openai-agents>=0.21,<1"]
```
- [ ] Install it WITHOUT pruning the other groups (a bare `uv sync --all-packages` silently removed
  the `redteam` group during Slice 10a):
  `uv sync --all-packages --group dev --group redteam --group adapters`
- [ ] Confirm both extras survive: `./.venv/Scripts/python.exe -c "import agents, garak; print(agents.__version__)"`
  prints a `0.21.x` version and does not raise.
- [ ] Failing test in `tests/unit/test_openai_agents_adapter.py`:
```python
import pytest

agents = pytest.importorskip("agents", reason="openai-agents (the `adapters` group) is not installed")


def test_the_verified_extension_points_still_exist():
    """The adapter is built on these; if a version bump removes one, fail HERE with a clear
    message rather than somewhere deep inside an agent run."""
    import inspect

    from agents.tool_guardrails import ToolInputGuardrail

    params = inspect.signature(agents.function_tool).parameters
    assert "tool_input_guardrails" in params
    assert hasattr(ToolInputGuardrail, "run")
    for hook in ("on_tool_start", "on_llm_start"):
        assert hasattr(agents.RunHooks, hook)
```
  Run → passes once the group is installed (it is a contract lock, not a red-first test; state that
  in the commit body).
- [ ] Commit `build(sdk): optional adapters group with openai-agents + API contract lock (INT-08)`.

---

### Task 2: `governed_tool` — the primary, structurally-blocking PEP

**Files:** create `packages/sdk/src/agentos_sdk/adapters/__init__.py`,
`packages/sdk/src/agentos_sdk/adapters/openai_agents.py`; test `tests/unit/test_openai_agents_adapter.py`.

`adapters/__init__.py`:
```python
"""Framework adapters. Each contributes normalization + a framework entry point ONLY — enforcement
always goes through `agentos_sdk.enforce.governed_call`, so every adapter inherits the same outcome
map and cannot drift. Submodules import their framework lazily so the base SDK never requires it."""
```

`adapters/openai_agents.py`:
```python
"""INT-08 — the OpenAI Agents SDK adapter.

Two entry points onto ONE enforcement core:

* `governed_tool` wraps the tool CALLABLE, so a governed block simply never invokes the body.
  Blocking is structural — no framework hook has to cooperate. This is the primary path.
* `governance_tool_guardrail` builds the framework-native `ToolInputGuardrail` for
  `function_tool(tool_input_guardrails=[...])`, for adopters who prefer the SDK's own mechanism.

Both call `governed_call`, so sandbox quarantine, consensus quorum, resource budgets and breaker
reporting (Phase 9) apply here exactly as they do to the LangChain PEP. The SDK documents no general
pre-execution middleware and its hook semantics have moved between versions, which is precisely why
enforcement does NOT depend on one.
"""
from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from typing import Any

from agentos_contract import ActionType, AgentAction, PipelineProtocol

from agentos_sdk.coverage import covers
from agentos_sdk.enforce import GovernanceDenied, governed_call
from agentos_sdk.normalize import _agent_id_from_token


@covers(ActionType.tool_call)
def normalize_openai_agents_tool_call(tool_name: str, args: dict[str, Any], token: str) -> AgentAction:
    """An OpenAI-Agents function-tool invocation -> the contract's AgentAction."""
    return AgentAction(
        agent_id=_agent_id_from_token(token),
        type=ActionType.tool_call,
        target=tool_name,
        payload=dict(args),
        identity_token=token,
    )


def governed_tool(
    pipeline: PipelineProtocol,
    token: str,
    *,
    name: str | None = None,
    coordinator: Any | None = None,
    dispatcher: Any | None = None,
    sandbox: Any | None = None,
    consensus: Any | None = None,
    governor: Any | None = None,
    reporter: Any | None = None,
) -> Callable[[Callable[..., Awaitable[Any] | Any]], Callable[..., Awaitable[Any]]]:
    """Wrap a tool callable so governance runs BEFORE its body.

    Usage:
        @function_tool
        @governed_tool(pipeline, token)
        async def http_get(url: str) -> str: ...

    A governed block raises `GovernanceDenied` (or a Phase-9 subclass). The Agents SDK turns a tool
    exception into an error result for the model, so the run continues with the model told the call
    was refused — the same shape as the LangChain PEP's ToolMessage block.
    """

    def _decorate(fn: Callable[..., Awaitable[Any] | Any]) -> Callable[..., Awaitable[Any]]:
        tool_name = name or getattr(fn, "__name__", "tool")

        async def _run_body(*args: Any, **kwargs: Any) -> Any:
            result = fn(*args, **kwargs)
            if hasattr(result, "__await__"):
                return await result
            return result

        async def _governed(*args: Any, **kwargs: Any) -> Any:
            action = normalize_openai_agents_tool_call(tool_name, _tool_args(fn, args, kwargs), token)
            return await governed_call(
                pipeline,
                action,
                lambda: _run_body(*args, **kwargs),
                coordinator=coordinator,
                dispatcher=dispatcher,
                sandbox=sandbox,
                consensus=consensus,
                governor=governor,
                reporter=reporter,
            )

        # Preserve the signature/metadata `function_tool` introspects to build the tool schema —
        # without this the wrapped tool would expose (*args, **kwargs) to the model.
        import functools

        functools.update_wrapper(_governed, fn)
        return _governed

    return _decorate


def _tool_args(fn: Callable[..., Any], args: tuple[Any, ...], kwargs: dict[str, Any]) -> dict[str, Any]:
    """Bind the call to the tool's own parameter NAMES so the risk stage and the constitution see
    the same field names an operator wrote principles against (positional args would otherwise be
    invisible to a `when: field: url` principle)."""
    import inspect

    try:
        bound = inspect.signature(fn).bind_partial(*args, **kwargs)
        bound.apply_defaults()
        return {k: v for k, v in bound.arguments.items() if k not in ("self", "ctx", "context")}
    except (TypeError, ValueError):
        return dict(kwargs)
```

**Steps (TDD):**
- [ ] Failing test in `tests/unit/test_openai_agents_adapter.py` (stub pipeline; NO framework import
  needed for these):
  - a `deny` pipeline → calling the wrapped tool raises `GovernanceDenied` and a `ran` list stays
    EMPTY (the load-bearing no-side-effect assertion);
  - an `allow` pipeline → the body runs and its return value comes back;
  - the action handed to the pipeline has `type is ActionType.tool_call`, `target == "http_get"`,
    and `payload == {"url": "https://api.example.com/"}` when called POSITIONALLY
    (`tool("https://api.example.com/")`) — proving `_tool_args` binds parameter names;
  - a sync tool body is supported as well as async;
  - `functools.update_wrapper` kept `__name__` and the signature (assert
    `inspect.signature(wrapped).parameters` still contains `url`);
  - with a stub `sandbox` runner and a `sandbox` decision → `GovernanceQuarantined` and the body
    never ran (proves the Phase-9 seams are threaded, not dropped).
  Run → fails.
- [ ] Implement the adapter. Run → passes.
- [ ] Commit `feat(sdk): OpenAI Agents adapter — governed_tool blocks before the body (INT-08)`.

---

### Task 3: real `Runner.run` e2e with a fake model (no network)

**Files:** create `tests/integration/test_openai_agents_e2e.py`; modify
`packages/sdk/src/agentos_sdk/adapters/openai_agents.py` (add `governance_tool_guardrail`).

Add the framework-native second entry point:
```python
def governance_tool_guardrail(
    pipeline: PipelineProtocol,
    token: str,
    **seams: Any,
):
    """Build a framework-native `ToolInputGuardrail` that consults the SAME enforcement core.

    Returned for `function_tool(tool_input_guardrails=[...])`. A governed block is mapped onto the
    SDK's reject behavior so the model is told the call was refused; the tool body never runs
    because the SDK does not invoke it when an input guardrail rejects.
    """
    from agents.tool_guardrails import ToolInputGuardrail, ToolGuardrailFunctionOutput

    async def _check(data: Any) -> Any:
        tool_name = getattr(getattr(data, "context", None), "tool_name", None) or "tool"
        raw = getattr(data, "arguments", None) or getattr(data, "tool_arguments", None) or {}
        args = raw if isinstance(raw, dict) else _loads(raw)
        action = normalize_openai_agents_tool_call(tool_name, args, token)
        try:
            await governed_call(pipeline, action, _noop, **seams)
        except GovernanceDenied as denied:
            return ToolGuardrailFunctionOutput.reject_content(message=str(denied))
        return ToolGuardrailFunctionOutput.allow()

    return ToolInputGuardrail(guardrail_function=_check, name="agentos_guard")


async def _noop() -> None:
    """The guardrail path only needs the DECISION; the SDK runs the body itself when allowed."""
    return None


def _loads(raw: Any) -> dict[str, Any]:
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {"arguments": parsed}
    except Exception:
        return {"arguments": str(raw)}
```

> The `ToolGuardrailFunctionOutput` constructors and the `ToolInputGuardrailData` attribute names are
> NOT verified. Introspect them first
> (`python -c "import agents.tool_guardrails as t, inspect; print([n for n in dir(t)]); print(inspect.signature(t.ToolGuardrailFunctionOutput))"`)
> and match the installed API; adjust the snippet rather than forcing it.

**Steps (TDD):**
- [ ] Introspect `agents.ModelResponse`, the function-tool-call output item type, and
  `ToolGuardrailFunctionOutput` / `ToolInputGuardrailData`. Record what you found in the test
  module docstring so the next reader does not repeat it.
- [ ] Write `tests/integration/test_openai_agents_e2e.py` with
  `agents = pytest.importorskip("agents", reason="openai-agents (the `adapters` group) is not installed")`
  at module scope, then:
  - a `_FakeModel(agents.Model)` whose `get_response(...)` returns, on the FIRST call, a
    `ModelResponse` containing one function-tool call for `http_get` with
    `{"url": "https://attacker.example/exfil"}`, and on the second call a plain text message (so the
    run terminates);
  - a `_FakeProvider(agents.ModelProvider)` returning it from `get_model`;
  - an `Agent` whose tools are `[function_tool(governed_tool(pipeline, token)(http_get))]` where
    `http_get` appends to a `calls` list;
  - run it: `await Runner.run(agent, "go", run_config=agents.RunConfig(model_provider=_FakeProvider(),
    tracing_disabled=True))`;
  - **assert `calls == []`** — the real tool body never executed, through a REAL agent run, with no
    network;
  - a second case with a benign allowlisted URL asserts `calls == ["ran"]` (so the deny case is not
    vacuously passing because the wiring is broken);
  - a third case wires the tool via `function_tool(..., tool_input_guardrails=[governance_tool_guardrail(...)])`
    instead and asserts the hostile call is likewise refused and the body never ran.
  Use the REAL governed stack (compiled constitution + registry token) as in
  `tests/integration/test_gateway_pep.py`.
- [ ] Run → fails, then passes.
- [ ] Commit `test(adapters): real Runner.run proves the tool never executes on a block (INT-08)`.

---

### Task 4: full gate
- [ ] `pytest -q` green; `-m floor_invariant`, `-m regression_lock` green; `-m latency` (baseline-check
  before attributing a wall-clock failure).
- [ ] Confirm the main suite still passes WITHOUT the adapters group installed — the importorskip
  guards must skip cleanly, exactly like the redteam extra
  (verify by running the two new test files with `-p no:cacheprovider` in a subprocess whose
  `sys.modules` blocks `agents`, or by temporarily uninstalling and reinstalling the group).
- [ ] Confirm `coverage_matrix()[ActionType.tool_call]` now contains the LangChain, gateway AND
  adapter entrypoints, and `verify_coverage()` still passes.
- [ ] Commit only if incidental fixes were needed.

## Self-review
INT-08 is realized: a second framework genuinely intercepts actions, proven by a REAL `Runner.run`
against a fake model provider (no network) in which a denied tool's body provably never executes,
with an allowed-case control so the deny is not vacuous. The adapter contributes normalization + a
framework entry point only — both entry points route through `governed_call`, so Phase-9 containment
applies unchanged and cannot drift, and the primary path blocks structurally rather than depending on
hook semantics that have moved between SDK versions. The framework is an OPTIONAL dependency group
whose absence skips cleanly, so the base install stays lean. INT-06 coverage records the new PEP form
alongside the existing ones.
