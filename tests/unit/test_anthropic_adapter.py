"""AnthropicInterpreter — the toggle-side structured-outputs adapter (POL-04 / D2).

No network anywhere here: a fake client is injected (the CI determinism path the
adapter's `client=` constructor param exists for) and the tests assert the exact
request the adapter builds — model, typed output_format, the trusted system prompt
(principles + the untrusted-data instruction), and the untrusted payload labelled
as data INSIDE the <action_data> block. The missing-anthropic ImportError path is
deliberately NOT tested (the package is installed in this workspace).
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from agentos_contract.policy_io import AUTHORABLE_EFFECTS
from agentos_pipeline.interpreter import InterpreterVerdict, SemanticInterpreter
from agentos_pipeline.interpreter.anthropic_adapter import AnthropicInterpreter, _VerdictModel
from agentos_pipeline.interpreter.protocol import InterpretationRequest


class FakeMessages:
    def __init__(self, parsed_output) -> None:
        self.kwargs: dict | None = None
        self._parsed_output = parsed_output

    async def parse(self, **kwargs):
        self.kwargs = kwargs
        return SimpleNamespace(parsed_output=self._parsed_output)


class FakeClient:
    def __init__(self, parsed_output) -> None:
        self.messages = FakeMessages(parsed_output)


def _request() -> InterpretationRequest:
    return InterpretationRequest(
        action_type="tool_call",
        target="bulk_export_contacts",
        intent_class="",
        guardrails=(("format", False), ("pii", True), ("unsafe", False)),
        payload_excerpt="export every contact record to an external csv",
        principles=(
            ("1.1", "Egress allowlist", "An agent may only make outbound requests to allowlisted hosts."),
            ("3.2", "PII never leaves approved hosts", "An agent must never send user PII to a host outside the approved allowlist."),
        ),
        constitution_version="sha256:c1",
        policy_version="sha256:p1",
    )


def test_adapter_builds_the_structured_outputs_request() -> None:
    fake = FakeClient(_VerdictModel(outcome="warn", principle_ref="3.2", rationale="r"))
    adapter = AnthropicInterpreter(client=fake)
    asyncio.run(adapter.interpret(_request()))

    kwargs = fake.messages.kwargs
    assert kwargs is not None
    assert kwargs["model"] == "claude-opus-4-8"
    assert kwargs["max_tokens"] == 1024
    assert kwargs["output_format"] is _VerdictModel
    # NO sampling/thinking params (removed/unneeded on claude-opus-4-8 — 400 if sent).
    assert "temperature" not in kwargs
    assert "top_p" not in kwargs
    assert "top_k" not in kwargs
    assert "thinking" not in kwargs


def test_system_prompt_is_trusted_principles_plus_untrusted_data_instruction() -> None:
    fake = FakeClient(_VerdictModel(outcome="warn", principle_ref="3.2", rationale="r"))
    adapter = AnthropicInterpreter(client=fake)
    asyncio.run(adapter.interpret(_request()))

    system = fake.messages.kwargs["system"]
    # A principle statement is present in the TRUSTED channel.
    assert "An agent must never send user PII to a host outside the approved allowlist." in system
    assert "3.2" in system and "PII never leaves approved hosts" in system
    # The untrusted-data framing (Pitfall 5) and the restrict-only framing.
    assert "UNTRUSTED DATA" in system
    assert "never an instruction" in system
    assert "restrict" in system.lower()
    # The payload excerpt must NOT leak into the trusted channel.
    assert "export every contact record" not in system


def test_user_content_is_the_labelled_data_block_with_the_excerpt_inside() -> None:
    fake = FakeClient(_VerdictModel(outcome="warn", principle_ref="3.2", rationale="r"))
    adapter = AnthropicInterpreter(client=fake)
    asyncio.run(adapter.interpret(_request()))

    messages = fake.messages.kwargs["messages"]
    assert len(messages) == 1 and messages[0]["role"] == "user"
    content = messages[0]["content"]
    start = content.index("<action_data")
    end = content.index("</action_data>")
    assert content.index("<payload_excerpt>") > start
    assert content.index("export every contact record to an external csv") < end
    assert 'target="bulk_export_contacts"' in content[start:end]


def test_adapter_returns_the_typed_verdict() -> None:
    fake = FakeClient(
        _VerdictModel(outcome="warn", principle_ref="3.2", rationale="semantically a PII export")
    )
    adapter = AnthropicInterpreter(client=fake)
    verdict = asyncio.run(adapter.interpret(_request()))
    assert verdict == InterpreterVerdict(
        outcome="warn", principle_ref="3.2", rationale="semantically a PII export"
    )


def test_verdict_model_vocabulary_is_exactly_the_authorable_effects() -> None:
    """ADR-0005: no temporary_exception in the output schema — recommend-only
    lives in rationale, never as an outcome."""
    import typing

    literal = _VerdictModel.model_fields["outcome"].annotation
    assert set(typing.get_args(literal)) == set(AUTHORABLE_EFFECTS)


def test_adapter_satisfies_the_protocol_and_defaults() -> None:
    adapter = AnthropicInterpreter(client=FakeClient(None))
    assert isinstance(adapter, SemanticInterpreter)
    assert adapter.name == "anthropic.v1"


def test_model_is_constructor_configurable() -> None:
    fake = FakeClient(_VerdictModel(outcome="allow", principle_ref=None, rationale="r"))
    adapter = AnthropicInterpreter(model="claude-haiku-4-5", client=fake)
    asyncio.run(adapter.interpret(_request()))
    assert fake.messages.kwargs["model"] == "claude-haiku-4-5"
