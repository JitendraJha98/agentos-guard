"""Decision — the single output of the pipeline (PIPE-02 explainability).

Source: docs/architecture/02-domain-model.md (Decision). Pydantic v2,
extra="forbid"; scores bounded to [0, 1] (threat T-01-03).
"""

import json
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from uuid import UUID

from pydantic import BaseModel, Field, field_validator


class Outcome(str, Enum):
    allow = "allow"
    warn = "warn"            # vocabulary present; realized Phase 3
    sandbox = "sandbox"      # vocabulary present; realized Phase 3
    require_consensus = "require_consensus"
    require_approval = "require_approval"
    temporary_exception = "temporary_exception"   # POL-13 — human-ratified, time-boxed allow
    governance_review = "governance_review"        # POL-14 — proceed + async non-blocking review
    deny = "deny"


class SideEffect(str, Enum):
    """Composable, outcome-orthogonal escalations (PIPE-09). A Decision may carry any subset."""
    notify = "notify"
    additional_monitoring = "additional_monitoring"
    risk_flag = "risk_flag"
    create_incident = "create_incident"


@dataclass(frozen=True)
class SandboxResult:
    """RUN-03 — what a quarantined (sandboxed) run OBSERVED.

    Deliberately NOT an imitation of the real handler's return value: the real handler
    was never invoked, so there is no result to imitate. `detail` is a short, redacted
    summary — never raw payload.

    It lives in the contract (not the SDK) because both sides of the seam need it: the
    SDK's enforcement core raises it and the control plane's concrete runner returns it,
    and `agentos-sdk` already depends on `agentos-controlplane` — so the reverse import
    would be a package cycle. `agentos_sdk.enforce` re-exports it.
    """

    quarantined: bool
    run_id: str
    detail: str = ""


def _evidence_strings(node):
    """Yield every string in an evidence tree (keys AND values, nested)."""
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for key, val in node.items():
            if isinstance(key, str):
                yield key
            yield from _evidence_strings(val)
    elif isinstance(node, (list, tuple)):
        for item in node:
            yield from _evidence_strings(item)


class Reason(BaseModel):
    """Machine-readable explainability — PIPE-02. Each stage appends one or more."""
    model_config = {"extra": "forbid"}

    stage: str                       # "identity" | "policy" | "risk" | "graduated" | "pipeline"
    code: str                        # e.g. "constitution_principle_fired", "forged_identity"
    detail: str = Field(default="", max_length=512)      # short human string; NEVER raw attacker payload
    policy_id: str | None = None     # fired principle / policy id (Phase 1: the egress rule id)
    principle_ref: str | None = Field(default=None, max_length=64)   # constitution principle id (e.g. "3.2") — PIPE-08
    rationale: str = Field(default="", max_length=512)   # short human rationale — PIPE-08 (NEVER raw payload)
    evidence: dict | None = None       # small structured evidence — PIPE-08

    @field_validator("evidence")
    @classmethod
    def _bounded_evidence(cls, v: dict | None) -> dict | None:
        # Reasons flow into the un-redactable, hash-covered audit log (threat T-01-02):
        # evidence must stay small and structured — never a raw-payload carrier.
        if v is None:
            return v
        try:
            # Strict (no default=str): a non-JSON-native value would validate here
            # yet crash the audit writer's canonical_json at hash time.
            serialized = json.dumps(v)
        except TypeError:
            raise ValueError(
                "evidence must be JSON-native (str/int/float/bool/None/list/dict)"
            ) from None
        if len(serialized) > 1024:
            raise ValueError("evidence must serialize to <= 1024 chars (audit-bound, T-01-02)")
        for key, val in v.items():
            if (isinstance(key, str) and len(key) > 256) or (isinstance(val, str) and len(val) > 256):
                raise ValueError("evidence string keys/values must be <= 256 chars (audit-bound, T-01-02)")
        for s in _evidence_strings(v):
            if "://" in s:
                # Full URLs carry query-string secrets; host-only is the audit convention.
                raise ValueError("evidence strings must not contain URLs (host-only, audit-bound)")
        return v


class Decision(BaseModel):
    model_config = {"extra": "forbid"}
    action_id: UUID
    outcome: Outcome
    risk_score: float = Field(ge=0.0, le=1.0, default=0.0)
    trust_score: float = Field(ge=0.0, le=1.0, default=0.0)
    reasons: list[Reason] = Field(default_factory=list)
    side_effects: list[SideEffect] = Field(default_factory=list)   # PIPE-09
    inferred_intent: str | None = Field(default=None, max_length=64)   # SEC-12 coarse intent class
    remediation: list[str] = Field(default_factory=list)           # PIPE-08 next steps
    constitution_version: str | None = None                        # POL-08 (populated Slice 3)
    policy_version: str | None = None                              # POL-08 (populated Slice 3)
    expires_at: datetime | None = None                             # POL-13 temporary_exception expiry
    evidence_ref: UUID | None = None   # the AuditRecord id, set after the audit write

    @field_validator("remediation")
    @classmethod
    def _bounded_remediation(cls, v: list[str]) -> list[str]:
        # Audit-bound (T-01-02): keep remediation small and structured.
        if len(v) > 10:
            raise ValueError("remediation must have <= 10 items (audit-bound, T-01-02)")
        for item in v:
            if len(item) > 256:
                raise ValueError("remediation items must be <= 256 chars (audit-bound, T-01-02)")
        return v

    @field_validator("expires_at")
    @classmethod
    def _tz_aware_expires_at(cls, v: datetime | None) -> datetime | None:
        # A naive expiry is ambiguous across timezones — require tz-aware (POL-13).
        if v is not None and v.tzinfo is None:
            raise ValueError("expires_at must be timezone-aware")
        return v
