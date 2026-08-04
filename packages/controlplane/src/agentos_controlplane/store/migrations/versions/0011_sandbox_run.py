"""sandbox_run — quarantined sandboxed executions (RUN-03)

Revision ID: 0011_sandbox_run
Revises: 0010_agent_certificates
Create Date: 2026-08-04

Slice 9a: a `sandbox` outcome no longer borrows the human-approval path — it routes to
the SandboxRunner seam, which quarantines the action (the real handler is never invoked)
and records the observation HERE.

`detail` is a short, redacted summary and lives in this table rather than in the
`sandbox_executed` audit-event body (short identifiers only), so the AUD-04 secret gate
on `append_event` can never refuse — and thereby block — a containment event. Same
discipline as `kill_switch.reason` (0005).

Authored against PostgreSQL as the production target (D-14) with dialect-agnostic
generic types so the same DDL applies on SQLite; the SQLite Store bootstraps the
equivalent schema via create_all.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0011_sandbox_run"
down_revision: Union[str, None] = "0010_agent_certificates"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "sandbox_run",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("action_id", sa.Uuid(), nullable=False),
        sa.Column("agent_id", sa.String(length=255), nullable=False),
        sa.Column("action_type", sa.String(length=64), nullable=False),
        sa.Column("target", sa.Text(), nullable=False),
        sa.Column("quarantined", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("detail", sa.Text(), nullable=False, server_default=""),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )


def downgrade() -> None:
    op.drop_table("sandbox_run")
