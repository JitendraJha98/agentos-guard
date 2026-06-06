"""initial — agent registry + append-only hash-chained audit_record

Revision ID: 0001_initial
Revises:
Create Date: 2026-06-01

Authored against PostgreSQL as the production target (D-14). Uses
dialect-agnostic generic types so the same DDL applies on SQLite, but the
append-only UPDATE/DELETE trigger is Postgres-specific (Open Q3 hardening) and
is therefore guarded by a dialect check — on SQLite, append-only is enforced at
the application layer (the Store rejects UPDATE/DELETE). The real-Postgres
trigger is validated in Phase 4 per the Deviation Log.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Postgres-only trigger blocking UPDATE/DELETE on audit_record (Open Q3).
_AUDIT_APPEND_ONLY_FN = """
CREATE OR REPLACE FUNCTION audit_record_append_only()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_record is append-only: % is not permitted', TG_OP;
END;
$$ LANGUAGE plpgsql;
"""

_AUDIT_APPEND_ONLY_TRIGGER = """
CREATE TRIGGER audit_record_no_update_delete
BEFORE UPDATE OR DELETE ON audit_record
FOR EACH ROW EXECUTE FUNCTION audit_record_append_only();
"""


def upgrade() -> None:
    op.create_table(
        "agent",
        sa.Column("agent_id", sa.String(length=255), primary_key=True),
        sa.Column("public_key", sa.Text(), nullable=True),
        sa.Column("trust_score", sa.Float(), nullable=False, server_default="0.5"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )

    op.create_table(
        "audit_record",
        sa.Column("id", sa.Uuid(), primary_key=True),
        # seq is strictly monotonic and hash-covered (Pitfall 8); ordering
        # derives from seq, NOT created_at.
        sa.Column("seq", sa.BigInteger(), nullable=False),
        # prev_hash is NULL only for the genesis record.
        sa.Column("prev_hash", sa.Text(), nullable=True),
        sa.Column("record_hash", sa.Text(), nullable=False),
        # Generic JSON (not JSONB) -> maps to Postgres JSONB at the production
        # target and to SQLite TEXT-JSON for the Phase-1 backend.
        sa.Column("body", sa.JSON(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.UniqueConstraint("seq", name="uq_audit_record_seq"),
    )

    # Postgres-only append-only hardening; SQLite enforces this at the app layer.
    if op.get_bind().dialect.name == "postgresql":
        op.execute(_AUDIT_APPEND_ONLY_FN)
        op.execute(_AUDIT_APPEND_ONLY_TRIGGER)


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute("DROP TRIGGER IF EXISTS audit_record_no_update_delete ON audit_record")
        op.execute("DROP FUNCTION IF EXISTS audit_record_append_only()")
    op.drop_table("audit_record")
    op.drop_table("agent")
