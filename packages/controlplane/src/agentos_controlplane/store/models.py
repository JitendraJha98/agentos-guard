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

from datetime import datetime, timezone
from uuid import UUID, uuid4

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    DateTime,
    Float,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
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
    # IDN-03: the AGENT's own Ed25519 public key (PEM) — the key its certificate
    # binds this agent_id to. Through Phase 6 this column held the CONTROL PLANE's
    # key (every row identical, certifying nothing); Phase 7 populates it as the
    # column was always documented to mean. The matching private key is returned to
    # the agent at registration and never stored here.
    public_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    # IDN-03: the CA-issued X.509 certificate (PEM) attesting agent_id <-> public_key,
    # and its serial as a DECIMAL STRING — X.509 serials are up to 20 bytes and do
    # not fit BIGINT on any backend.
    certificate: Mapped[str | None] = mapped_column(Text, nullable=True)
    cert_serial: Mapped[str | None] = mapped_column(String(64), nullable=True)
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


class KillSwitch(Base):
    """RUN-01/02 — CURRENT kill-switch state (immutable history lives in the audit chain).

    `target` is an `agent_id`, or "*" for the whole fleet. This row is the durable
    backing for the in-memory `KillSwitchStore` (the hot-path lookup); the operator
    free-text `reason` lives HERE only, never in the audit-event body (so the 4d
    secret-gate on `append_event` can never block an emergency kill).
    """

    __tablename__ = "kill_switch"

    target: Mapped[str] = mapped_column(String(255), primary_key=True)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    set_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class SandboxRun(Base):
    """RUN-03 — one quarantined (sandboxed) execution.

    The REAL handler never ran; this row IS the observation record. `detail` is a short,
    REDACTED summary — never the raw payload. It lives HERE and not in the audit-event
    body (which carries short identifiers only) so the AUD-04 secret gate on
    `append_event` can never refuse — and thereby block — a containment event, exactly
    the discipline `KillSwitch.reason` follows.
    """

    __tablename__ = "sandbox_run"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    action_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    agent_id: Mapped[str] = mapped_column(String(255), nullable=False)
    action_type: Mapped[str] = mapped_column(String(64), nullable=False)
    target: Mapped[str] = mapped_column(Text, nullable=False)
    quarantined: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    detail: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class ChainCheckpoint(Base):
    """AUD-05 — an external anchor binding the chain head {seq, record_hash} to an unforgeable proof.

    Checkpointing is operator-/schedule-driven (NOT on the per-action hot path). The CI verifier
    re-derives the head hash at `seq` and proves it still matches `record_hash` (no rewrite of
    checkpointed history) and that the chain is no shorter than a checkpointed seq (no truncation).
    """

    __tablename__ = "chain_checkpoint"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    seq: Mapped[int] = mapped_column(BigInteger, nullable=False)          # the head seq anchored
    record_hash: Mapped[str] = mapped_column(Text, nullable=False)       # the head record_hash anchored
    anchor_kind: Mapped[str] = mapped_column(String(32), nullable=False)  # local_ed25519_v1 | rfc3161_v1
    proof: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)     # opaque per kind (sig | DER TimeStampResp)
    tsa_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class TrustProfile(Base):
    """Declarative TrustProfile resource (API-01). The current trust posture for an agent,
    versioned for optimistic concurrency. `band` is an optional graduated-response band config.
    Keyed by agent_id (one current profile per agent); the Agent row keeps the seed trust_score.

    `version` is SQLAlchemy's `version_id_col`: every UPDATE is emitted as
    `... WHERE agent_id = :id AND version = :current`, the new version is computed by the ORM,
    and a row already advanced by a concurrent writer makes the UPDATE match zero rows ->
    StaleDataError. This is an atomic SQL-level guard that survives the Postgres target
    (distinct connections, READ COMMITTED), not a non-atomic Python read-then-compare."""

    __tablename__ = "trust_profile"

    agent_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    trust_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.5)
    band: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # TRST-04: the agent's own capability scope — a JSON list of capability strings,
    # `["*"]` for the wildcard. NULL means "unset", which the ScopeLookup reads as the
    # wildcard so an agent without an authored scope keeps its pre-Phase-7 behavior;
    # a delegation still narrows it to the delegator's scope by intersection.
    scope: Mapped[list | None] = mapped_column(JSON, nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __mapper_args__ = {"version_id_col": version}


class RevokedCertificate(Base):
    """IDN-03 — the certificate revocation list. One row per revoked serial.

    Presence IS revocation (no status column): a revocation must never be
    reversible by flipping a flag, and re-issuing is the intended path back. The
    serial is a decimal string, matching `Agent.cert_serial` (20-byte X.509 serials
    do not fit BIGINT).
    """

    __tablename__ = "revoked_certificate"

    serial: Mapped[str] = mapped_column(String(64), primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(255), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    revoked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class ConstitutionResource(Base):
    """Declarative Constitution resource (API-01/02). One row per applied version; `version` is the
    content-hash constitution_version (idempotent apply). `source` is the authored document (JSON).

    Class name is ConstitutionResource (NOT Constitution) so it never collides with the Pydantic
    `agentos_constitution.Constitution` the compiler validates; the table is `constitution`."""

    __tablename__ = "constitution"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)  # constitution_version
    source: Mapped[dict] = mapped_column(JSON, nullable=False)  # the authored document, verbatim
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class PolicyResource(Base):
    """The compile-on-write output for a Constitution version (API-02). Stores the Rego + the
    reviewable YAML middle layer + graduated/lists/sequences metadata the engine consumes.

    Persisted in the SAME transaction as its ConstitutionResource; keyed (unique) by
    constitution_version so apply stays idempotent on the content-hash version."""

    __tablename__ = "policy"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    constitution_version: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    yaml_policy: Mapped[str] = mapped_column(Text, nullable=False)
    rego: Mapped[str] = mapped_column(Text, nullable=False)
    graduated_config: Mapped[dict] = mapped_column(JSON, nullable=False)
    lists: Mapped[dict] = mapped_column(JSON, nullable=False)
    sequences: Mapped[list] = mapped_column(JSON, nullable=False)
    # Python-side default for MICROSECOND resolution. `server_default=func.now()` alone
    # resolves to CURRENT_TIMESTAMP — whole SECONDS on SQLite — so two constitutions
    # applied in the same second tied, and `get_latest_policy()` (ORDER BY created_at
    # DESC) could return the OLDER policy: a stale answer from GET /policies/latest and
    # a cache reconciler warming to the wrong constitution. The server_default is kept
    # for rows inserted outside the ORM.
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
    )


class Abom(Base):
    """Declarative Agent Bill of Materials resource (API-01 / ABOM-01 seed). Phase 5 only
    validates/versions/stores it; provenance + vuln-impact analysis are Phase 8/14. Keyed by
    agent_id (current ABOM per agent), version-incremented for optimistic concurrency.

    `version` is the `version_id_col` (see TrustProfile): the atomic SQL-level optimistic guard
    SQLAlchemy enforces on every UPDATE, raising StaleDataError on a concurrent stale write."""

    __tablename__ = "abom"

    agent_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    components: Mapped[dict] = mapped_column(JSON, nullable=False)  # {models,prompts,tools,mcp:[...]}
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __mapper_args__ = {"version_id_col": version}


class InventoryComponent(Base):
    """DISC-01/02 — an authoritative inventory row: one component (a tool/prompt/memory/etc.) tied to
    an agent. `source` is 'declared' (registration manifest, authoritative) or 'observed' (reconciled
    from activity). Unique on (agent_id, kind, name) so declare+observe of the same component
    reconcile into ONE row."""

    __tablename__ = "inventory_component"
    __table_args__ = (UniqueConstraint("agent_id", "kind", "name", name="uq_inventory_component"),)

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    agent_id: Mapped[str] = mapped_column(String(255), nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)   # tool|prompt|memory|model|mcp|delegation
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    source: Mapped[str] = mapped_column(String(16), nullable=False)  # declared|observed
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class AgentPrivilege(Base):
    """RUN-04 — the capability tier (privilege ring) an agent HOLDS. Higher = more privileged;
    absent means ring 0 (least privileged)."""

    __tablename__ = "agent_privilege"

    agent_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    ring: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    set_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class TargetPrivilege(Base):
    """RUN-04 — the ring a sensitive TARGET (tool / memory key / MCP tool / model) REQUIRES.

    Registered-sensitivity model: only rows present here are gated. An unregistered target is
    ring 0 (ungated by this stage) and remains governed by the constitution floor — so adding this
    stage cannot silently break an existing deployment.
    """

    __tablename__ = "target_privilege"

    target: Mapped[str] = mapped_column(String(255), primary_key=True)
    required_ring: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    set_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
