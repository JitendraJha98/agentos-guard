"""SQLAlchemy 2.0 declarative models — Agent registry + append-only audit_record.

Source: 01-RESEARCH.md § Audit (hash chain) schema; D-14/D-15.

No-Docker deviation (CONTEXT.md D-14): these models are authored against
PostgreSQL as the production target but use SQLAlchemy **dialect-agnostic
generic types** (`JSON` not `JSONB`, `Uuid`, `DateTime(timezone=True)`,
`String`/`Text`) so the very same models run on the Phase-1 **SQLite** backend
AND map to Postgres types as the production target — a backend swap, not a
rewrite. The Alembic migration (production target) and the SQLite Store share
this metadata.
"""

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    DateTime,
    Float,
    String,
    Text,
    Uuid,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Declarative base shared by the registry + audit tables."""


class Agent(Base):
    """Agent registry row (IDN-01) carrying the TRST-01 seed trust score."""

    __tablename__ = "agent"

    # agent_id is the natural PK the identity token's `sub` claim references.
    agent_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    # Identity metadata: the agent's public key (PEM). Phase-1 issuance uses a
    # single control-plane keypair, but the column models the per-agent key the
    # X.509 upgrade (IDN-03, Phase 7) will populate.
    public_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    # TRST-01 seed: a single 0-1 score consumed by the graduated-response stage.
    trust_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.5)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class AuditRecord(Base):
    """Append-only, hash-chained audit record (AUD-01).

    `seq` is strictly monotonic and is COVERED by `record_hash` (Pitfall 8) —
    ordering derives from `seq`, never from `created_at`. `prev_hash` is NULL
    only for the genesis record. `policy_version` lives nullable inside `body`,
    NOT as a column (populated from Phase 3 Slice 3).
    """

    __tablename__ = "audit_record"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    seq: Mapped[int] = mapped_column(BigInteger, nullable=False, unique=True)
    prev_hash: Mapped[str | None] = mapped_column(Text, nullable=True)
    record_hash: Mapped[str] = mapped_column(Text, nullable=False)
    # AUD-08: detached per-record EdDSA signature over SIG_DOMAIN + canonical_json(body),
    # and a short fingerprint of the signing public key. Nullable: a writer without a signer
    # produces unsigned records (backward compat); the production path always signs.
    signature: Mapped[str | None] = mapped_column(Text, nullable=True)        # 64-byte sig, hex
    signing_key_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Generic JSON (NOT JSONB) so the column maps to SQLite TEXT-JSON now and to
    # Postgres JSONB at the production target.
    body: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class ApprovalRequest(Base):
    """A parked `require_approval` action awaiting human resolution (POL-07).

    `context` is the action payload REDACTED through the audit redactor BEFORE
    the row is created (fail-closed: unclassifiable payload -> no row). `status`
    transitions (pending -> approved | denied | timed_out) are constrained at
    the ApprovalStore layer — the single writer — not by a DB CHECK, so the
    column stays a plain string on every backend (D-14).

    Datetimes are stored UTC-naive (SQLite drops tz offsets); the ApprovalStore
    normalizes on write and re-attaches UTC on read.
    """

    __tablename__ = "approval_request"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    action_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    agent_id: Mapped[str] = mapped_column(String(255), nullable=False)
    action_type: Mapped[str] = mapped_column(String(64), nullable=False)
    target: Mapped[str] = mapped_column(Text, nullable=False)
    context: Mapped[dict] = mapped_column(JSON, nullable=False)   # REDACTED payload
    reasons: Mapped[list] = mapped_column(JSON, nullable=False)   # Decision.reasons dump
    risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    trust_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    deadline_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    resolver: Mapped[str | None] = mapped_column(String(255), nullable=True)
    resolution_note: Mapped[str | None] = mapped_column(Text, nullable=True)


class TemporaryException(Base):
    """A human-ratified, time-boxed allow scoped to (agent_id, principle_ref) — POL-13.

    Granted ONLY via human approval resolution (never authorable, never
    interpreter-grantable). Auto-revoke is a READ-TIME expiry check
    (`expires_at > now()` in the lookup query) — no background job; `revoked`
    is the explicit kill switch.
    """

    __tablename__ = "temporary_exception"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    agent_id: Mapped[str] = mapped_column(String(255), nullable=False)
    principle_ref: Mapped[str] = mapped_column(String(64), nullable=False)
    granted_by: Mapped[str] = mapped_column(String(255), nullable=False)
    approval_id: Mapped[UUID | None] = mapped_column(Uuid, nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class GovernanceReview(Base):
    """An async, NON-blocking review of an executed action (POL-14).

    Opened when the outcome is `governance_review` (or any fired principle's
    effect was — the obligation survives risk escalation); the action proceeds
    without waiting. `status` is open|closed, constrained at the store layer.
    """

    __tablename__ = "governance_review"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    action_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    agent_id: Mapped[str] = mapped_column(String(255), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="open")
    opened_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    closed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
