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
    an agent. `source` is 'declared' (registration manifest, authoritative), 'observed' (this exact
    component was used) or 'observed_class' (the class-level placeholder `enrich_from_audit` writes,
    where name == kind, because the audit body omits the per-action target). Unique on (agent_id,
    kind, name) so declare+observe of the same component reconcile into ONE row."""

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


class ResourceLimit(Base):
    """RUN-05 — the per-agent execution budget enforced at the PEP. NULL on a numeric column means
    NO limit for that dimension; an absent row means the agent is unbudgeted (the zero-overhead
    default path in `agentos_sdk.enforce._run_within_limits`).

    What each dimension actually guarantees differs, and the SDK's `GovernanceResourceExceeded`
    documents it: `network` prevents (the handler never runs), `wall_s` cancels cooperatively, and
    `memory_mb` is detected at COMPLETION. This table stores the budget, not a promise of kernel
    enforcement — that is the opt-in `posix_limits` path and the Phase-10/14 boundaries.
    """

    __tablename__ = "resource_limit"

    agent_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    wall_s: Mapped[float | None] = mapped_column(Float, nullable=True)
    memory_mb: Mapped[float | None] = mapped_column(Float, nullable=True)
    network: Mapped[str] = mapped_column(String(16), nullable=False, default="allow")
    set_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )


class CircuitBreakerState(Base):
    """RUN-06 — the DURABLE state of one breaker, identified by the COMPOSITE PK
    (scope, agent_id, target); `target` is "" for the agent scope.

    Three columns rather than one concatenated `"agent_id|target"` key: both parts are free-form (an
    agent registers its own id, a target is arbitrary) and may contain the separator, so a
    single-string key let an attacker's breaker ALIAS a victim's — the tool pair (`a`, `http_get`)
    and an agent literally named `a|http_get` collapsed onto the same row.

    Only TRANSITIONS are persisted; the rolling-window counters live in memory because a window is a
    recent-history view, not durable state. `opened_at` is epoch SECONDS (a float) rather than a
    DateTime: cooldown arithmetic is the only thing it is used for, and a plain epoch avoids
    naive/aware conversion bugs across the SQLite dev / Postgres target split. Human-readable history
    lives on the audit chain.
    """

    __tablename__ = "circuit_breaker_state"

    scope: Mapped[str] = mapped_column(String(16), primary_key=True)  # "agent" | "tool"
    agent_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    target: Mapped[str] = mapped_column(String(255), primary_key=True, default="")
    state: Mapped[str] = mapped_column(String(16), nullable=False)  # "open" | "half_open" | "closed"
    opened_at: Mapped[float | None] = mapped_column(Float, nullable=True)
    trip_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )


class EmergencyShutdown(Base):
    """RUN-07 — an append-only record of one fleet-wide emergency stop.

    The `kill_switch` table holds only CURRENT state (it is upserted), so incident HISTORY lives
    here: who declared the stop, when, why, and when it was resumed. The free-text `justification`
    lives in this table ONLY — the audit event carries short identifiers + this row's id, so a
    secret-bearing justification can never trip the AUD-04 gate and block an emergency stop.
    """

    __tablename__ = "emergency_shutdown"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    justification: Mapped[str] = mapped_column(Text, nullable=False)
    declared_by: Mapped[str] = mapped_column(String(255), nullable=False)
    declared_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    resumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resumed_by: Mapped[str | None] = mapped_column(String(255), nullable=True)


class ConsensusRound(Base):
    """POL-09 — one consensus round for one action: how many voters were asked, how many
    approved, the quorum required, and whether it was reached.

    Counts, not opinions: the round is the durable answer to "was this action allowed to
    proceed, and on whose agreement" — the per-voter verdicts hang off it in
    `consensus_vote`. `reached` is the enforcement-relevant bit; a round short of quorum
    means the action was denied.
    """

    __tablename__ = "consensus_round"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    action_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    agent_id: Mapped[str] = mapped_column(String(255), nullable=False)
    voters: Mapped[int] = mapped_column(Integer, nullable=False)
    approvals: Mapped[int] = mapped_column(Integer, nullable=False)
    quorum: Mapped[int] = mapped_column(Integer, nullable=False)
    reached: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class ConsensusVote(Base):
    """POL-09 — one voter's verdict in a round.

    `error` records a voter that RAISED or TIMED OUT, which counts as a NO-VOTE
    (fail-closed): `approved` is False and the exception type / "timeout" is kept here so a
    silent quorum failure is distinguishable from a deliberate rejection. It is a short
    type name, never the voter's message — the free text would be attacker-influenceable
    and the audit event body carries identifiers + counts only.
    """

    __tablename__ = "consensus_vote"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    round_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    voter: Mapped[str] = mapped_column(String(255), nullable=False)
    approved: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    error: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class DiscoveredFramework(Base):
    """DISC-03 — an agent framework observed in this deployment, by ONE observing instance.

    `name` is the catalogue key (stable), `distribution` the PyPI name actually found, and
    `version` what was installed at detection time — bounded + charset-restricted at the detector,
    since METADATA is supply-chain input and the column widths here are enforced on Postgres.

    Keyed by (observer, name): the CURRENT observation per framework PER scanning instance, with
    first/last-seen bracketing it. The observer dimension is load-bearing — keyed by `name` alone,
    two replicas that disagree about a version overwrite each other on every pass and emit an
    unbounded stream of `framework_discovered` events for an unchanged fleet. The audit chain
    carries the immutable history.
    """

    __tablename__ = "discovered_framework"

    observer: Mapped[str] = mapped_column(String(128), primary_key=True)
    name: Mapped[str] = mapped_column(String(64), primary_key=True)
    distribution: Mapped[str] = mapped_column(String(128), nullable=False)
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )


class ShadowAgent(Base):
    """DISC-04 — an actor that ACTED without being registered.

    `claimed_agent_id` is ATTACKER-CONTROLLED: it is whatever an unverified caller put in its
    token, so it is bounded to 255 chars and sanitized before it ever reaches this row. It is
    stored to give an operator something to recognise, never trusted — the action itself was
    already denied at stage 1 (IDN-02), and this row exists so a flood of such denies reads as one
    incident instead of vanishing into routine noise.

    The KEY is `claimed_id_digest` (sha256 of the FULL raw id), not that display text: sanitizing
    is lossy — every disallowed character maps to `?` and anything past 255 chars is dropped — so
    keying by it would merge distinct attackers into one row. The store also uses the key for its
    `<overflow>` bucket, which no real digest can collide with.
    """

    __tablename__ = "shadow_agent"

    claimed_id_digest: Mapped[str] = mapped_column(String(64), primary_key=True)
    claimed_agent_id: Mapped[str] = mapped_column(String(255), nullable=False)
    action_type: Mapped[str] = mapped_column(String(64), nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )


class RogueFinding(Base):
    """DISC-05 — a REGISTERED agent used a component it never declared.

    Advisory evidence, not a verdict: the manifest may simply be stale, so this records a
    divergence for an operator to judge and adds no deny path. `resolved` lets that operator
    acknowledge a finding without deleting the history the audit chain already carries.

    UNIQUE on (agent_id, kind, name) so a scheduled sweep of an unchanged fleet writes nothing —
    the idempotence that keeps a repeat scan from bloating the table or the hash chain is enforced
    by the schema, not only by the detector's read-before-write.

    An agent names its own components, so `agent_id`/`kind`/`name` are caller text: the detector
    bounds and sanitizes them to these widths BEFORE they reach the row (SQLite does not enforce
    String(n), and on Postgres an over-long value would fail the INSERT and abort the sweep), and a
    value it had to alter carries a digest of the original so two components cannot merge into one
    finding.
    """

    __tablename__ = "rogue_finding"
    __table_args__ = (UniqueConstraint("agent_id", "kind", "name", name="uq_rogue_finding"),)

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    agent_id: Mapped[str] = mapped_column(String(255), nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)  # tool|memory|mcp|model|...
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    resolved: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class GraphNode(Base):
    """DISC-06 — one node in the live agent graph: an agent, or a component an agent uses.

    UNIQUE on (kind, name) so a repeated materialization pass converges on the same row rather
    than growing a second copy of the graph on every sweep.

    `kind`/`name` are CALLER text — an agent names itself in the audit body it caused — so the
    store bounds and sanitizes them to these widths before the row (SQLite does not enforce
    String(n); on Postgres an over-long value fails the INSERT and aborts the whole sweep), and
    caps how many distinct agent nodes exist at all.

    `source` records the FIDELITY of the row the way `inventory_component.source` does — 'declared'
    (the registration manifest), 'observed' (this exact agent really acted) or 'observed_class'
    (the class-level placeholder named after its own class, because the audit body omits the
    per-action target). Without it a placeholder is byte-identical to a genuine component that
    happens to be named 'tool'.
    """

    __tablename__ = "graph_node"
    __table_args__ = (UniqueConstraint("kind", "name", name="uq_graph_node"),)

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    # agent | tool | model | mcp | memory | delegation | prompt
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    source: Mapped[str] = mapped_column(
        String(16), nullable=False, default="observed"
    )  # declared|observed|observed_class
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )


class GraphEdge(Base):
    """DISC-06 — a directed edge in the live agent graph.

    `uses` is agent -> component; `delegates` is agent -> agent, its lineage derived from the audit
    body's `parent_action_id` by resolving which agent performed the parent action.

    `observations` counts ACTIONS — one per audit record consumed for this edge, exactly once,
    because the materialization pass is incremental (each record is read once, past a persisted
    watermark). It does NOT count sweeps: a sweep-counter would rank a one-off agent above a hot
    path purely for having existed longer. A DECLARED edge starts at 0, so "declared but never
    exercised" stays distinguishable from "used once". BigInteger because a hot edge on a busy
    fleet outgrows int4.

    `source` mirrors `graph_node.source` (declared > observed > observed_class), so a Phase-13
    transitive walk can tell a class-level placeholder from real evidence.

    UNIQUE on the (src, dst, relation) 5-tuple for the same reason `graph_node` is unique on
    (kind, name): a scheduled sweep must converge, not accumulate.
    """

    __tablename__ = "graph_edge"
    __table_args__ = (
        UniqueConstraint(
            "src_kind", "src_name", "dst_kind", "dst_name", "relation", name="uq_graph_edge"
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    src_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    src_name: Mapped[str] = mapped_column(String(255), nullable=False)
    dst_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    dst_name: Mapped[str] = mapped_column(String(255), nullable=False)
    relation: Mapped[str] = mapped_column(String(32), nullable=False)  # uses | delegates
    observations: Mapped[int] = mapped_column(BigInteger, nullable=False, default=1)
    source: Mapped[str] = mapped_column(
        String(16), nullable=False, default="observed"
    )  # declared|observed|observed_class
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )


class GraphWatermark(Base):
    """DISC-06 — how far the graph materialization has consumed the audit chain.

    One row, keyed by a constant. It is what makes the pass INCREMENTAL: without it every sweep
    re-read the whole audit log and re-issued a statement per record, so the cost grew with the log
    forever and the long write transaction blocked the AuditWriter appending to the SAME database —
    a stalled append drives the pipeline's fail-safe, i.e. observation degrading enforcement.
    Persisted rather than in-process so a restart does not pay for all of history again.
    """

    __tablename__ = "graph_watermark"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)  # constant — one row
    seq: Mapped[int] = mapped_column(BigInteger, nullable=False)  # last AuditRecord.seq consumed
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )


class MerkleRoot(Base):
    """AUD-06 — a sealed epoch: the Merkle root over a contiguous audit `seq` range.

    Epochs are contiguous and non-overlapping by construction (`seq_start` is the previous epoch's
    `seq_end + 1`), so no record can slip between two epochs and escape coverage — a record in no
    epoch could never be proven to an auditor at all.

    A separate table rather than a reuse of `ChainCheckpoint`: that row binds {seq, record_hash},
    and stuffing a root into `record_hash` would make the column mean two different things
    depending on the row. It also has to be self-contained for export (CMP-06) — root, range and
    anchor travelling together is exactly what a disclosure bundle serializes.

    The anchor columns are nullable and filled by a SEPARATE operator step: sealing is cheap and
    local, anchoring costs a network round-trip to a TSA. Making them one operation would mean a
    TSA outage stops the log from being sealed at all.
    """

    __tablename__ = "merkle_root"

    epoch: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    seq_start: Mapped[int] = mapped_column(BigInteger, nullable=False)
    seq_end: Mapped[int] = mapped_column(BigInteger, nullable=False)
    root: Mapped[str] = mapped_column(String(64), nullable=False)  # sha256 hex
    leaf_count: Mapped[int] = mapped_column(BigInteger, nullable=False)
    # AUD-05 reuse: the SAME anchor kinds and the SAME verify dispatch as ChainCheckpoint.
    anchor_kind: Mapped[str | None] = mapped_column(String(32), nullable=True)
    proof: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    tsa_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class CostRecord(Base):
    """ECON-01 — what one action actually cost, attributed to one agent.

    Money is INTEGER micro-USD, not a float. Floating-point money accumulates representation error
    across a sum, and a budget decision (Slice 11c) made on a drifting total is a decision the
    operator cannot reproduce. Integers also mean the same value round-trips identically through
    SQLite and Postgres, which a NUMERIC would not.

    `cost_micro_usd` is NULLABLE and stays null when the model is unpriced: tokens are a fact we
    observed, dollars are a conversion we can only do with a rate the operator gave us. Writing a
    zero there would read as 'this action was free'.

    `price_book_version` pins WHICH rates produced the figure, so a bill can be re-derived — and so
    a rate correction does not silently rewrite history.

    ECON-03 widens the same row rather than adding a second table: downstream API spend and GPU time
    are what an action cost, and splitting them off would let two tables disagree about one action.
    """

    __tablename__ = "cost_record"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    action_id: Mapped[UUID] = mapped_column(Uuid, nullable=False, index=True)
    agent_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    action_type: Mapped[str] = mapped_column(String(32), nullable=False)
    model: Mapped[str | None] = mapped_column(String(128), nullable=True)
    input_tokens: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    output_tokens: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    cost_micro_usd: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    price_book_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # ECON-03 — downstream (non-model) consumption. `provider` is the action's own target, a FACT
    # the PEP already normalized; it is never an inferred vendor name. Inferring "this target is
    # really AWS" would put a guess into a cost report an operator reconciles against a real invoice.
    provider: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # ECON-03 — GPU, recorded only when something actually reported it, never zero-filled.
    gpu_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)
    gpu_memory_mib: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    # WHICH THING WAS MEASURED, stored beside the number because a figure that loses its qualifier
    # becomes a bill nobody can challenge. 'process' = attributable to THIS process;
    # 'device_shared' = a device-wide counter that cannot be honestly divided among concurrent
    # agents, so it is explicitly NOT a per-agent bill and no roll-up may total it as one.
    gpu_attribution: Mapped[str | None] = mapped_column(String(16), nullable=True)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )


class AgentBudget(Base):
    """ECON-02 — an operator-set spending limit for one agent.

    `period` is the window the limit applies over ('day' | 'month' | 'total'); spend is summed from
    `cost_record` inside the current window. Micro-USD integers for the same reason CostRecord uses
    them: a budget DECISION must be reproducible, and float money is not.

    A MISSING ROW MEANS NO BUDGET CONFIGURED, which is not the same as a budget of zero. The ledger
    reports a used-ratio of 0.0 for an unconfigured agent, so an operator who has set no budgets
    cannot have their whole fleet deadlocked by the mere presence of this feature — absence of a
    budget is not evidence of a breach.

    `version` counts assignments so an operator can see a limit was RAISED between two decisions:
    raising a budget is how an over-budget agent is unblocked, and a limit that changes with no
    trace is the one an incident review cannot reconstruct. It is SQLAlchemy's `version_id_col`, so
    that trace is also a guard: every UPDATE is emitted as `... WHERE agent_id = :id AND
    version = :current`, and a row already advanced by a concurrent writer matches zero rows ->
    StaleDataError. Same reasoning as TrustProfile — an atomic SQL-level guard that survives the
    Postgres target (distinct connections, READ COMMITTED), not a non-atomic Python read-then-write
    in which one of two concurrent raises silently vanishes.
    """

    __tablename__ = "agent_budget"

    agent_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    period: Mapped[str] = mapped_column(String(16), nullable=False, default="day")
    limit_micro_usd: Mapped[int] = mapped_column(BigInteger, nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )

    __mapper_args__ = {"version_id_col": version}
