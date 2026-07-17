"""RiskFinding + RiskScorer — the typed guardrail evidence and SEC-03 scorer
contract.

Source: 01-AI-SPEC.md §3 (RiskScorer Protocol) and §4b (frozen RiskFinding with
the _no_raw_payload validator). RiskFinding flows into Decision.reasons and the
un-redactable, hash-covered audit log, so `matched` must carry pattern IDs only,
never raw attacker payload (threat T-01-02). The scorer *implementation* lives in
the pipeline package; only this Protocol is part of the stable boundary.
"""

from typing import TYPE_CHECKING, Literal, Protocol

from pydantic import BaseModel, Field, field_validator

if TYPE_CHECKING:
    from agentos_contract.action import AgentAction


class RiskFinding(BaseModel):
    """Typed, serializable guardrail finding. Validated on construction; flows into the audit chain."""
    model_config = {"frozen": True, "extra": "forbid"}   # immutable + reject unknown keys

    scorer: str                                           # "prompt_injection.v1"
    category: Literal[
        "prompt_injection", "egress_exfil", "secret_leak", "intent",
        "pii", "unsafe_content", "format_violation",
        # Phase-8 detector categories (SEC-11 / SEC-09).
        "code_execution", "memory_poisoning",
    ]
    risk_score: float = Field(ge=0.0, le=1.0)             # normalized 0–1; enforced by validator
    matched: list[str] = Field(default_factory=list)      # pattern IDs only — NEVER raw payload
    detail: str = Field(default="", max_length=512)
    inline: bool = True                                   # provenance: was this on the hot path?

    @field_validator("matched")
    @classmethod
    def _no_raw_payload(cls, v: list[str]) -> list[str]:
        # Guardrail-specific: matched holds rule IDs, not attacker text, so findings are safe
        # to write into the (un-redactable, hash-covered) audit log. Reject anything URL-like.
        if any("http" in m or len(m) > 64 for m in v):
            raise ValueError("matched must contain pattern IDs, not raw/long payload strings")
        return v


class RiskScorer(Protocol):
    """SEC-03 pluggable-scorer contract. inline=True scorers run unconditionally on the hot path."""
    name: str
    inline: bool                                  # True = sub-ms, deterministic, always runs

    def score(self, action: "AgentAction") -> RiskFinding: ...
