"""Decision — the single output of the pipeline (PIPE-02 explainability).

Source: docs/architecture/02-domain-model.md (Decision). Pydantic v2,
extra="forbid"; scores bounded to [0, 1] (threat T-01-03).
"""

import json
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


class Reason(BaseModel):
    """Machine-readable explainability — PIPE-02. Each stage appends one or more."""
    model_config = {"extra": "forbid"}

    stage: str                       # "identity" | "policy" | "risk" | "graduated"
    code: str                        # e.g. "egress_allowlist_violation", "forged_identity"
    detail: str = ""                 # short human string; NEVER raw attacker payload
    policy_id: str | None = None     # fired principle / policy id (Phase 1: the egress rule id)
    principle_ref: str | None = None   # constitution principle id (e.g. "3.2") — PIPE-08
    rationale: str = Field(default="", max_length=512)   # short human rationale — PIPE-08 (NEVER raw payload)
    evidence: dict | None = None       # small structured evidence — PIPE-08

    @field_validator("evidence")
    @classmethod
    def _bounded_evidence(cls, v: dict | None) -> dict | None:
        # Reasons flow into the un-redactable, hash-covered audit log (threat T-01-02):
        # evidence must stay small and structured — never a raw-payload carrier.
        if v is None:
            return v
        if len(json.dumps(v, default=str)) > 1024:
            raise ValueError("evidence must serialize to <= 1024 chars (audit-bound, T-01-02)")
        for key, val in v.items():
            if (isinstance(key, str) and len(key) > 256) or (isinstance(val, str) and len(val) > 256):
                raise ValueError("evidence string keys/values must be <= 256 chars (audit-bound, T-01-02)")
        return v


class Decision(BaseModel):
    model_config = {"extra": "forbid"}
    action_id: UUID
    outcome: Outcome
    risk_score: float = Field(ge=0.0, le=1.0, default=0.0)
    trust_score: float = Field(ge=0.0, le=1.0, default=0.0)
    reasons: list[Reason] = Field(default_factory=list)
    side_effects: list[SideEffect] = Field(default_factory=list)   # PIPE-09
    inferred_intent: str | None = None                             # SEC-12 coarse intent class
    remediation: list[str] = Field(default_factory=list)           # PIPE-08 next steps
    constitution_version: str | None = None                        # POL-08 (populated Slice 3)
    policy_version: str | None = None                              # POL-08 (populated Slice 3)
    expires_at: datetime | None = None                             # POL-13 temporary_exception expiry
    evidence_ref: UUID | None = None   # the AuditRecord id, set after the audit write
