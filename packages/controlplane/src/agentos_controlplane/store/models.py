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
    only for the genesis record. `policy_version` is deferred to Phase 4
    (AUD-03): it lives nullable inside `body`, NOT as a column.
    """

    __tablename__ = "audit_record"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    seq: Mapped[int] = mapped_column(BigInteger, nullable=False, unique=True)
    prev_hash: Mapped[str | None] = mapped_column(Text, nullable=True)
    record_hash: Mapped[str] = mapped_column(Text, nullable=False)
    # Generic JSON (NOT JSONB) so the column maps to SQLite TEXT-JSON now and to
    # Postgres JSONB at the production target.
    body: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
