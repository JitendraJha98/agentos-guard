"""INT-08 — the OpenAI Agents SDK adapter.

`governed_tool` wraps the tool CALLABLE, so a governed block simply never invokes the body.
Blocking is structural — no framework hook has to cooperate.

It calls `governed_call`, so sandbox quarantine, consensus quorum, resource budgets and breaker
reporting (Phase 9) apply here exactly as they do to the LangChain PEP. The SDK documents no general
pre-execution middleware and its hook semantics have moved between versions, which is precisely why
enforcement does NOT depend on one.

Nothing in this module imports `agents`: the wrapper is a plain decorator that the framework's
`function_tool` sees as an ordinary function, so the base SDK never requires the optional
`adapters` dependency group.
"""

from __future__ import annotations

import functools
import inspect
from collections.abc import Awaitable, Callable
from typing import Any, TypeVar

from agentos_contract import ActionType, AgentAction, PipelineProtocol

from agentos_sdk.coverage import covers
from agentos_sdk.enforce import (
    ApprovalCoordinator,
    CircuitReporter,
    ConsensusCoordinator,
    ResourceGovernor,
    SandboxRunner,
    SideEffectDispatcher,
    governed_call,
)
from agentos_sdk.normalize import _agent_id_from_token

_T = TypeVar("_T")


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


def _tool_args(fn: Callable[..., Any], args: tuple[Any, ...], kwargs: dict[str, Any]) -> dict[str, Any]:
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
