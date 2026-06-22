"""Deterministic stub interpreter — the default offline implementation choice (D2).

No I/O, no network: same request -> same verdict, so the no_match advisory path is
testable (and deployable) without any model dependency."""

from __future__ import annotations

from agentos_pipeline.interpreter.protocol import InterpretationRequest, InterpreterVerdict

_DEFAULT_VERDICT = InterpreterVerdict(
    outcome="allow",
    principle_ref=None,
    rationale="stub interpreter: deterministic default (offline)",
)


class StubInterpreter:
    name = "stub.v1"

    def __init__(self, verdict: InterpreterVerdict | None = None) -> None:
        self._verdict = verdict if verdict is not None else _DEFAULT_VERDICT

    async def interpret(self, request: InterpretationRequest) -> InterpreterVerdict:
        return self._verdict
