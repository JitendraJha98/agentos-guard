"""POL-04/POL-05 — the advisory semantic-interpreter seam (mirrors the PolicyEngine toggle).
The interpreter runs ONLY on no_match ambiguity; its verdict may RESTRICT the class-posture
floor, never relax it (clamped in the runner via OUTCOME_RESTRICTIVENESS)."""

from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@dataclass(frozen=True)
class InterpretationRequest:
    action_type: str
    target: str
    intent_class: str            # "" when untagged
    guardrails: tuple[tuple[str, bool], ...]   # sorted (name, flag) pairs
    payload_excerpt: str         # capped, UNTRUSTED — labelled as data in prompts
    principles: tuple[tuple[str, str, str], ...]   # (ref, title, statement)
    constitution_version: str
    policy_version: str


@dataclass(frozen=True)
class InterpreterVerdict:
    outcome: str                 # one of AUTHORABLE_EFFECTS (validated by the runner clamp)
    principle_ref: str | None
    rationale: str               # bounded by the runner before it enters a Reason


@runtime_checkable
class SemanticInterpreter(Protocol):
    name: str

    async def interpret(self, request: InterpretationRequest) -> InterpreterVerdict: ...
