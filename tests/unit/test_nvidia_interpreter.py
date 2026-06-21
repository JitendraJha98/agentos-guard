import asyncio
from types import SimpleNamespace

import pytest

from agentos_contract.policy_io import AUTHORABLE_EFFECTS
from agentos_pipeline.interpreter import NvidiaInterpreter, SemanticInterpreter
from agentos_pipeline.interpreter.nvidia_adapter import _VERDICT_SCHEMA, InterpreterParseError
from agentos_pipeline.interpreter.protocol import InterpretationRequest

REQ = InterpretationRequest(
    action_type="tool_call", target="bulk_export", intent_class="",
    guardrails=(("pii", False),), payload_excerpt="export all customer rows",
    principles=(("3.2", "Data privacy", "Never send PII to unapproved hosts."),),
    constitution_version="sha256:c", policy_version="sha256:p",
)


class _FakeClient:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    async def _create(self, **kwargs):
        self.calls.append(kwargs)
        content = self._responses.pop(0)
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=content))])


def _interp(responses, **kw):
    return NvidiaInterpreter(client=_FakeClient(responses), **kw)


def test_is_semantic_interpreter():
    assert isinstance(_interp(['{}']), SemanticInterpreter)


def test_schema_is_flat_enum_with_string_principle_ref():
    assert _VERDICT_SCHEMA["additionalProperties"] is False
    assert set(_VERDICT_SCHEMA["properties"]["outcome"]["enum"]) == set(AUTHORABLE_EFFECTS)
    assert _VERDICT_SCHEMA["properties"]["principle_ref"]["type"] == "string"  # not a nullable union


def test_valid_verdict_nvext_mode_and_prompt_shape():
    it = _interp(['{"outcome":"require_approval","principle_ref":"3.2","rationale":"x"}'])
    v = asyncio.run(it.interpret(REQ))
    assert (v.outcome, v.principle_ref, v.rationale) == ("require_approval", "3.2", "x")
    call = it._client.calls[0]
    assert call["extra_body"] == {"nvext": {"guided_json": _VERDICT_SCHEMA}}      # default nvext path
    sys, usr = call["messages"][0]["content"], call["messages"][1]["content"]
    assert "UNTRUSTED DATA" in sys and 'ref="3.2"' in sys and "ONLY a single JSON" in sys
    assert "<payload_excerpt>export all customer rows</payload_excerpt>" in usr


def test_none_sentinel_maps_to_null_ref():
    assert asyncio.run(_interp(['{"outcome":"warn","principle_ref":"none","rationale":"y"}']).interpret(REQ)).principle_ref is None
    assert asyncio.run(_interp(['{"outcome":"warn","principle_ref":"","rationale":"y"}']).interpret(REQ)).principle_ref is None


def test_retry_then_success_counts_two_calls():
    it = _interp(['not json at all', '{"outcome":"deny","principle_ref":"none","rationale":"z"}'])
    assert asyncio.run(it.interpret(REQ)).outcome == "deny"
    assert len(it._client.calls) == 2


def test_exhausted_retries_raise():
    it = _interp(['nope', 'still nope'], max_attempts=2)
    with pytest.raises(InterpreterParseError):
        asyncio.run(it.interpret(REQ))
    assert len(it._client.calls) == 2


def test_out_of_vocab_outcome_is_rejected_then_exhausts():
    it = _interp(['{"outcome":"explode","principle_ref":"none","rationale":"q"}',
                  '{"outcome":"explode","principle_ref":"none","rationale":"q"}'], max_attempts=2)
    with pytest.raises(InterpreterParseError):
        asyncio.run(it.interpret(REQ))


def test_markdown_fenced_json_is_parsed():
    it = _interp(['```json\n{"outcome":"sandbox","principle_ref":"none","rationale":"r"}\n```'])
    assert asyncio.run(it.interpret(REQ)).outcome == "sandbox"


def test_bare_language_hint_prefix_is_parsed():
    it = _interp(['json\n{"outcome":"warn","principle_ref":"none","rationale":"r"}'])
    assert asyncio.run(it.interpret(REQ)).outcome == "warn"


def test_trailing_prose_after_object_is_dropped():
    it = _interp(['{"outcome":"deny","principle_ref":"none","rationale":"r"}\nHere is my verdict.'])
    assert asyncio.run(it.interpret(REQ)).outcome == "deny"


def test_brace_inside_string_does_not_truncate_object():
    it = _interp(['{"outcome":"warn","principle_ref":"none","rationale":"uses a {curly} token"}'])
    assert asyncio.run(it.interpret(REQ)).rationale == "uses a {curly} token"


def test_wire_schema_rationale_bounded():
    assert _VERDICT_SCHEMA["properties"]["rationale"]["maxLength"] == 512


def test_json_schema_mode_uses_response_format_not_nvext():
    it = _interp(['{"outcome":"allow","principle_ref":"none","rationale":"ok"}'], structured_mode="json_schema")
    asyncio.run(it.interpret(REQ))
    call = it._client.calls[0]
    assert "extra_body" not in call and call["response_format"]["type"] == "json_schema"
