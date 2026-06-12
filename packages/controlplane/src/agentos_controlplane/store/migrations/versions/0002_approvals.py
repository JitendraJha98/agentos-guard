"""approvals — approval_request + temporary_exception + governance_review

Revision ID: 0002_approvals
Revises: 0001_initial
Create Date: 2026-06-12

The Slice-6 lifecycle tables (POL-07 / POL-13 / POL-14). Authored against
PostgreSQL as the production target (D-14) with dialect-agnostic generic types
so the same DDL applies on SQLite. Status transitions are constrained at the
ApprovalStore layer (the single writer), NOT by DB CHECK constraints.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0002_approvals"
down_revision: Union[str, None] = "0001_initial"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "approval_request",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("action_id", sa.Uuid(), nullable=False),
        sa.Column("agent_id", sa.String(length=255), nullable=False),
        sa.Column("action_type", sa.String(length=64), nullable=False),
        sa.Column("target", sa.Text(), nullable=False),
        # The action payload REDACTED through the audit redactor (fail-closed).
        sa.Column("context", sa.JSON(), nullable=False),
        sa.Column("reasons", sa.JSON(), nullable=False),
        sa.Column("risk_score", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("trust_score", sa.Float(), nullable=False, server_default="0.0"),
        # pending | approved | denied | timed_out — store-layer constrained.
        sa.Column("status", sa.String(length=32), nullable=False, server_default="pending"),
        sa.Column("deadline_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolver", sa.String(length=255), nullable=True),
        sa.Column("resolution_note", sa.Text(), nullable=True),
    )

    op.create_table(
        "temporary_exception",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("agent_id", sa.String(length=255), nullable=False),
        sa.Column("principle_ref", sa.String(length=64), nullable=False),
        sa.Column("granted_by", sa.String(length=255), nullable=False),
        sa.Column("approval_id", sa.Uuid(), nullable=True),
        # Auto-revoke is a READ-TIME expiry check (expires_at > now()) — POL-13.
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )

    op.create_table(
        "governance_review",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("action_id", sa.Uuid(), nullable=False),
        sa.Column("agent_id", sa.String(length=255), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False, server_default=""),
        # open | closed — store-layer constrained.
        sa.Column("status", sa.String(length=32), nullable=False, server_default="open"),
        sa.Column(
            "opened_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("governance_review")
    op.drop_table("temporary_exception")
    op.drop_table("approval_request")
