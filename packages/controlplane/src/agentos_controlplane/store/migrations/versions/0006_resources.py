"""resources — declarative TrustProfile + Abom resource tables (API-01)

Revision ID: 0006_resources
Revises: 0005_kill_switch
Create Date: 2026-06-27

Slice 5a: the declarative-resource layer of the control-plane API. Both tables are keyed
by agent_id (the current profile / ABOM per agent) and carry a monotonic `version` for
optimistic concurrency (a stale-version update -> VersionConflict -> 409). Authored against
PostgreSQL as the production target (D-14) with dialect-agnostic generic types so the same
DDL applies on SQLite; the SQLite Store bootstraps the equivalent schema via create_all.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0006_resources"
down_revision: Union[str, None] = "0005_kill_switch"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "trust_profile",
        sa.Column("agent_id", sa.String(length=255), primary_key=True),
        sa.Column("trust_score", sa.Float(), nullable=False, server_default="0.5"),
        sa.Column("band", sa.JSON(), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_table(
        "abom",
        sa.Column("agent_id", sa.String(length=255), primary_key=True),
        sa.Column("components", sa.JSON(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )


def downgrade() -> None:
    op.drop_table("abom")
    op.drop_table("trust_profile")
