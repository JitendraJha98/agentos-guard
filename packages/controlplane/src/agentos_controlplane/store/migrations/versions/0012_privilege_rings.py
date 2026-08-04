"""agent_privilege + target_privilege — privilege rings (RUN-04)

Revision ID: 0012_privilege_rings
Revises: 0011_sandbox_run
Create Date: 2026-08-04

Slice 9b: sensitive targets require a capability tier and an agent holding a lower ring is denied
at pipeline stage 1e. `agent_privilege` records the ring an agent HOLDS; `target_privilege` records
the ring a target REQUIRES.

Registered-sensitivity model: only rows in `target_privilege` are gated — an unregistered target is
ring 0 and stays governed by the constitution floor, which is what makes the stage additive.

The administrative assignment history lives on the audit chain (`privilege_ring_set`, short
identifiers only); the per-action deny is audited as a DECISION record.

Authored against PostgreSQL as the production target (D-14) with dialect-agnostic generic types so
the same DDL applies on SQLite; the SQLite Store bootstraps the equivalent schema via create_all.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0012_privilege_rings"
down_revision: Union[str, None] = "0011_sandbox_run"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "agent_privilege",
        sa.Column("agent_id", sa.String(length=255), primary_key=True),
        sa.Column("ring", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("set_by", sa.String(length=255), nullable=True),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_table(
        "target_privilege",
        sa.Column("target", sa.String(length=255), primary_key=True),
        sa.Column("required_ring", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("set_by", sa.String(length=255), nullable=True),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )


def downgrade() -> None:
    op.drop_table("target_privilege")
    op.drop_table("agent_privilege")
