"""resource_limit — per-agent execution budgets (RUN-05)

Revision ID: 0013_resource_limits
Revises: 0012_privilege_rings
Create Date: 2026-08-04

Slice 9c: the wall-clock / memory / network budget the PEP enforces around a governed execution.
NULL on a numeric column means NO limit for that dimension; an ABSENT ROW means the agent is
unbudgeted, which is what lets the SDK take a zero-overhead path for the common case.

The administrative assignment history lives on the audit chain (`resource_limit_set`) and each
violation as `resource_limit_exceeded` — short identifiers + numbers only, never the target or the
payload.

Authored against PostgreSQL as the production target (D-14) with dialect-agnostic generic types so
the same DDL applies on SQLite; the SQLite Store bootstraps the equivalent schema via create_all.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0013_resource_limits"
down_revision: Union[str, None] = "0012_privilege_rings"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "resource_limit",
        sa.Column("agent_id", sa.String(length=255), primary_key=True),
        sa.Column("wall_s", sa.Float(), nullable=True),
        sa.Column("memory_mb", sa.Float(), nullable=True),
        sa.Column("network", sa.String(length=16), nullable=False, server_default="allow"),
        sa.Column("set_by", sa.String(length=255), nullable=True),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )


def downgrade() -> None:
    op.drop_table("resource_limit")
