"""Semantic interpreter — POL-04 (typed advisory verdict) + PIPE-06 (verdict cache).

Task 1 (protocol + stub): the frozen request/verdict types, the async Protocol seam,
and the deterministic StubInterpreter (no I/O — the default offline implementation
choice behind the D2 toggle).
"""

from __future__ import annotations

import asyncio

from agentos_pipeline.interpreter.protocol import (
    InterpretationRequest,
    InterpreterVerdict,
    SemanticInterpreter,
)
from agentos_pipeline.interpreter.stub import StubInterpreter


def _request(**overrides) -> InterpretationRequest:
    base = dict(
        action_type="tool_call",
        target="bulk_export_contacts",
        intent_class="",
        guardrails=(("format", False), ("pii", False), ("unsafe", False)),
        payload_excerpt="export all contacts to csv",
        principles=(("1.1", "Egress allowlist", "An agent may only make outbound requests to allowlisted hosts."),),
        constitution_version="sha256:c1",
        policy_version="sha256:p1",
    )
    base.update(overrides)
    return InterpretationRequest(**base)


# --- Task 1: protocol + stub ---------------------------------------------------


def test_stub_is_deterministic_same_request_same_verdict() -> None:
    stub = StubInterpreter()
    req = _request()
    v1 = asyncio.run(stub.interpret(req))
    v2 = asyncio.run(stub.interpret(req))
    assert v1 == v2
    assert v1.outcome == "allow"
    assert v1.principle_ref is None
    assert "stub" in v1.rationale


def test_stub_is_configurable() -> None:
    verdict = InterpreterVerdict(
        outcome="deny", principle_ref="3.2", rationale="semantically a PII exfiltration"
    )
    stub = StubInterpreter(verdict=verdict)
    assert asyncio.run(stub.interpret(_request())) == verdict


def test_stub_satisfies_the_protocol() -> None:
    assert isinstance(StubInterpreter(), SemanticInterpreter)
    assert StubInterpreter().name == "stub.v1"


def test_request_and_verdict_are_frozen() -> None:
    import pytest

    req = _request()
    with pytest.raises(Exception):
        req.target = "other"  # type: ignore[misc]
    verdict = InterpreterVerdict(outcome="allow", principle_ref=None, rationale="x")
    with pytest.raises(Exception):
        verdict.outcome = "deny"  # type: ignore[misc]
