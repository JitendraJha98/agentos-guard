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

Only the guardrail touches `agents`, and it imports it INSIDE the function: the base SDK installs
without the optional `adapters` dependency group, and `governed_tool` is a plain decorator that
`function_tool` sees as an ordinary function.

NAMING — keep the two names in sync. `function_tool` is applied ABOVE `governed_tool`, so the
adapter cannot see a `name_override`; it governs the Python function's `__name__` by default. Since
`target` is a first-class policy-input field, a mismatch means every principle written against the
model-facing name SILENTLY NEVER FIRES. If you pass `function_tool(name_override=X)` you MUST pass
`governed_tool(..., name=X)`. The guardrail path has no such coupling — it reads the model-facing
`ToolContext.tool_name` directly.
"""

from __future__ import annotations

import functools
import inspect
import json
from collections.abc import Awaitable, Callable
from typing import Any

from agentos_contract import ActionType, AgentAction, PipelineProtocol

from agentos_sdk.coverage import covers
from agentos_sdk.enforce import (
    ApprovalCoordinator,
    CircuitReporter,
    ConsensusCoordinator,
    GovernanceDenied,
    ResourceGovernor,
    SandboxRunner,
    SideEffectDispatcher,
    governed_call,
)
from agentos_sdk.normalize import _agent_id_from_token


@covers(ActionType.tool_call)
def normalize_openai_agents_tool_call(
    tool_name: str, args: dict[str, Any], token: str
) -> AgentAction:
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
    coordinator: ApprovalCoordinator | None = None,
    dispatcher: SideEffectDispatcher | None = None,
    sandbox: SandboxRunner | None = None,
    consensus: ConsensusCoordinator | None = None,
    governor: ResourceGovernor | None = None,
    reporter: CircuitReporter | None = None,
) -> Callable[[Callable[..., Any]], Callable[..., Awaitable[Any]]]:
    """Wrap a tool callable so governance runs BEFORE its body. The RECOMMENDED entry point: it
    blocks wherever the tool is called from, because it wraps the callable itself.

    Usage:
        @function_tool
        @governed_tool(pipeline, token)
        async def http_get(url: str) -> str: ...

    `name` is the governed `target` the constitution matches on, defaulting to the function's
    `__name__`. It MUST mirror any `function_tool(name_override=...)`, which is applied above this
    decorator and is therefore invisible to it:

        @function_tool(name_override="fetch_url")
        @governed_tool(pipeline, token, name="fetch_url")   # <- keep these two identical
        async def http_get(url: str) -> str: ...

    Let them drift and a principle written `when: {field: target, op: eq, value: fetch_url}` matches
    nothing at all — a silent fail-open for that principle.

    A governed block raises `GovernanceDenied` (or a Phase-9 subclass). The Agents SDK turns a tool
    exception into an error result for the model, so the run continues with the model told the call
    was refused — the same shape as the LangChain PEP's ToolMessage block.
    """

    def _decorate(fn: Callable[..., Any]) -> Callable[..., Awaitable[Any]]:
        tool_name = name or getattr(fn, "__name__", "tool")

        async def _run_body(*args: Any, **kwargs: Any) -> Any:
            # Sync tool bodies are legal in this SDK, so an un-awaitable result is returned as-is
            # rather than handed back as a coroutine object the model would stringify.
            result = fn(*args, **kwargs)
            if inspect.isawaitable(result):
                return await result
            return result

        async def _governed(*args: Any, **kwargs: Any) -> Any:
            action = normalize_openai_agents_tool_call(
                tool_name, _tool_args(fn, args, kwargs), token
            )
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

        # Preserve the name/docstring/signature `function_tool` introspects to build the tool
        # schema — without this the model would be offered `_governed(*args, **kwargs)`.
        functools.update_wrapper(_governed, fn)
        return _governed

    return _decorate


def _is_framework_context(value: Any) -> bool:
    """True when `value` is the SDK's own context object (`RunContextWrapper`, or the `ToolContext`
    subclass a tool actually receives).

    Tested by MRO rather than `isinstance` so this module never imports `agents` eagerly — the base
    SDK installs without the optional `adapters` group.
    """
    return any(
        cls.__module__.split(".")[0] == "agents"
        and cls.__name__ in ("RunContextWrapper", "ToolContext")
        for cls in type(value).__mro__
    )


def _tool_args(
    fn: Callable[..., Any], args: tuple[Any, ...], kwargs: dict[str, Any]
) -> dict[str, Any]:
    """Bind the call to the tool's own parameter NAMES so the risk stage and the constitution see
    the same field names an operator wrote principles against (a positional argument would
    otherwise be invisible to a `when: field: url` principle).

    The framework's own context parameter is dropped — it is agent plumbing, not agent intent, and
    it does not serialize — but by TYPE in FIRST position, never by name. The SDK identifies that
    parameter by its ANNOTATION and position; the name is irrelevant to it. Dropping `ctx` /
    `context` / `self` by name instead was a name-selectable ungoverned channel: an ordinary
    parameter carrying one of those idiomatic names reached the BODY while the constitution, the
    risk scorers and the audit payload never saw it. The inverse failed too — a correctly annotated
    context parameter named anything else survived into the payload and made the tool unusable.

    The invariant this holds: the governed payload is exactly what the body will receive.
    """
    try:
        bound = inspect.signature(fn).bind_partial(*args, **kwargs)
        bound.apply_defaults()
        # `apply_defaults` rebuilds `arguments` in declaration order, so item 0 IS the first
        # parameter — the only position the framework ever passes its context in.
        items = list(bound.arguments.items())
    except (TypeError, ValueError):
        # An un-introspectable callable (a builtin, say) still gets governed — on the keywords
        # alone rather than not at all.
        return dict(kwargs)
    if items and _is_framework_context(items[0][1]):
        items = items[1:]
    return dict(items)


def governance_tool_guardrail(
    pipeline: PipelineProtocol,
    token: str,
    *,
    name: str = "agentos_guard",
    coordinator: ApprovalCoordinator | None = None,
    dispatcher: SideEffectDispatcher | None = None,
    sandbox: SandboxRunner | None = None,
    consensus: ConsensusCoordinator | None = None,
    governor: ResourceGovernor | None = None,
    reporter: CircuitReporter | None = None,
) -> Any:
    """Build a framework-native `ToolInputGuardrail` that consults the SAME enforcement core.

    Returned for `function_tool(tool_input_guardrails=[...])`. A governed block is mapped onto the
    SDK's reject behavior so the model is told the call was refused, and the SDK does not invoke a
    tool whose input guardrail rejected.

    This is the SECONDARY path, and honestly so — on two counts. Prefer `governed_tool`:

    * ENFORCEMENT IS HOST-CONDITIONAL. The guardrail is run by the Runner's tool-execution path, NOT
      by the `FunctionTool` object, so any direct or programmatic `on_invoke_tool` call — a custom
      runner, a replay harness — executes the body with the pipeline never consulted.
      `governed_tool` wraps the CALLABLE: its block is structural, wherever the tool is called from.
    * IT GOVERNS THE DECISION, NOT THE EXECUTION. The SDK runs the body itself when the guardrail
      allows, so the RUN-05 budget and the RUN-06 reporter here wrap only the decision.

    Argument fidelity: the SDK hands the guardrail the model's RAW JSON, then invokes the body with
    the tool's pydantic DEFAULTS applied, so the raw JSON alone is not what the body executes on.
    Top-level defaults are recovered from the tool's own `params_json_schema` (`_with_defaults`);
    defaults nested INSIDE a pydantic model parameter are not, so those remain unseen here.
    `governed_tool` has no such gap — it binds the real call signature.
    """
    from agents.tool_guardrails import ToolGuardrailFunctionOutput, ToolInputGuardrail

    async def _check(data: Any) -> Any:
        context = data.context
        action = normalize_openai_agents_tool_call(
            context.tool_name, _with_defaults(_loads(context.tool_arguments), data), token
        )
        try:
            await governed_call(
                pipeline,
                action,
                _noop,
                coordinator=coordinator,
                dispatcher=dispatcher,
                sandbox=sandbox,
                consensus=consensus,
                governor=governor,
                reporter=reporter,
            )
        except GovernanceDenied as denied:
            return ToolGuardrailFunctionOutput.reject_content(message=str(denied))
        return ToolGuardrailFunctionOutput.allow()

    return ToolInputGuardrail(guardrail_function=_check, name=name)


async def _noop() -> None:
    """The guardrail path only needs the DECISION; the SDK runs the body itself when allowed."""
    return None


def _loads(raw: Any) -> dict[str, Any]:
    """`ToolContext.tool_arguments` is the model's RAW JSON string. A shape that is not a JSON
    object is still governed — on the text the model actually sent — rather than dropped, because
    an unparsed argument is an ungoverned one."""
    if isinstance(raw, dict):
        return raw
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        return {"arguments": str(raw)}
    return parsed if isinstance(parsed, dict) else {"arguments": parsed}


def _with_defaults(args: dict[str, Any], data: Any) -> dict[str, Any]:
    """Fill in the defaults the SDK will apply before it invokes the body, so the constitution sees
    the arguments the tool actually EXECUTES on — not only the ones the model bothered to send.

    The tool's own `params_json_schema` is the source: it is the pydantic schema the SDK validates
    against, and it keeps each parameter's `default` in both strict and non-strict mode. Anything
    unreadable (a dynamic tool list, a renamed tool, a schema shape from a future version) simply
    yields no defaults — governing the raw arguments, exactly as before.
    """
    properties = _params_schema(data).get("properties")
    if not isinstance(properties, dict):
        return args
    filled = dict(args)
    for field, spec in properties.items():
        if field not in filled and isinstance(spec, dict) and "default" in spec:
            filled[field] = spec["default"]
    return filled


def _params_schema(data: Any) -> dict[str, Any]:
    """The called tool's parameter schema, found on the agent by the name the model invoked."""
    name = getattr(data.context, "tool_name", None)
    for tool in getattr(data.agent, "tools", None) or ():
        if getattr(tool, "name", None) == name:
            schema = getattr(tool, "params_json_schema", None)
            return schema if isinstance(schema, dict) else {}
    return {}
