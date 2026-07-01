"""chain_checkpoint — external anchor binding the chain head {seq, record_hash} (AUD-05)

Revision ID: 0004_chain_checkpoint
Revises: 0003_audit_signatures
Create Date: 2026-06-12

Slice 4c: a checkpoint binds the audit-chain head {seq, record_hash} to an external,
unforgeable proof (RFC-3161 trusted timestamp, or a durability-only Ed25519 anchor for
tests). The CI verifier then proves no already-checkpointed history was rewritten and the
chain was not truncated below a checkpointed seq. Authored against PostgreSQL as the
production target (D-14) with dialect-agnostic generic types so the same DDL applies on
SQLite (LargeBinary -> BLOB on SQLite, BYTEA on Postgres).
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0004_chain_checkpoint"
down_revision: Union[str, None] = "0003_audit_signatures"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "chain_checkpoint",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("seq", sa.BigInteger(), nullable=False),
        sa.Column("record_hash", sa.Text(), nullable=False),
        sa.Column("anchor_kind", sa.String(length=32), nullable=False),
        sa.Column("proof", sa.LargeBinary(), nullable=False),
        sa.Column("tsa_url", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )


def downgrade() -> None:
    op.drop_table("chain_checkpoint")
