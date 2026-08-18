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
    """Wrap a tool callable so governance runs BEFORE its body.

    Usage:
        @function_tool
        @governed_tool(pipeline, token)
        async def http_get(url: str) -> str: ...

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


def _tool_args(
    fn: Callable[..., Any], args: tuple[Any, ...], kwargs: dict[str, Any]
) -> dict[str, Any]:
    """Bind the call to the tool's own parameter NAMES so the risk stage and the constitution see
    the same field names an operator wrote principles against (a positional argument would
    otherwise be invisible to a `when: field: url` principle).

    The framework's own context parameter is dropped: it is a `RunContextWrapper`, not agent
    intent, and it does not serialize.
    """
    try:
        bound = inspect.signature(fn).bind_partial(*args, **kwargs)
        bound.apply_defaults()
        return {k: v for k, v in bound.arguments.items() if k not in ("self", "ctx", "context")}
    except (TypeError, ValueError):
        # An un-introspectable callable (a builtin, say) still gets governed — on the keywords
        # alone rather than not at all.
        return dict(kwargs)


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
    SDK's reject behavior so the model is told the call was refused; the tool body never runs
    because the SDK does not invoke it when an input guardrail rejects.

    This is the SECONDARY path, and honestly so: the SDK runs the body itself when the guardrail
    allows, so the RUN-05 budget and RUN-06 reporter here wrap only the DECISION, not the real
    execution. `governed_tool` is the path that governs both.
    """
    from agents.tool_guardrails import ToolGuardrailFunctionOutput, ToolInputGuardrail

    async def _check(data: Any) -> Any:
        context = data.context
        action = normalize_openai_agents_tool_call(
            context.tool_name, _loads(context.tool_arguments), token
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
