"""Decision — the single output of the pipeline (PIPE-02 explainability).

Source: docs/architecture/02-domain-model.md (Decision). Pydantic v2,
extra="forbid"; scores bounded to [0, 1] (threat T-01-03).
"""

from enum import Enum
from uuid import UUID

from pydantic import BaseModel, Field


class Outcome(str, Enum):
    allow = "allow"
    warn = "warn"            # vocabulary present; realized Phase 3
    sandbox = "sandbox"      # vocabulary present; realized Phase 3
    require_consensus = "require_consensus"
    require_approval = "require_approval"
    deny = "deny"


class Reason(BaseModel):
    """Machine-readable explainability — PIPE-02. Each stage appends one or more."""
    stage: str                       # "identity" | "policy" | "risk" | "graduated"
    code: str                        # e.g. "egress_allowlist_violation", "forged_identity"
    detail: str = ""                 # short human string; NEVER raw attacker payload
    policy_id: str | None = None     # fired principle / policy id (Phase 1: the egress rule id)


class Decision(BaseModel):
    model_config = {"extra": "forbid"}
    action_id: UUID
    outcome: Outcome
    risk_score: float = Field(ge=0.0, le=1.0, default=0.0)
    trust_score: float = Field(ge=0.0, le=1.0, default=0.0)
    reasons: list[Reason] = Field(default_factory=list)
    evidence_ref: UUID | None = None   # the AuditRecord id, set after the audit write
