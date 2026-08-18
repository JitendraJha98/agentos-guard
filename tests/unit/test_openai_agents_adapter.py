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

import pytest

agents = pytest.importorskip("agents", reason="openai-agents (the `adapters` group) is not installed")


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
