"""inventory — authoritative agent inventory component table (DISC-01/02)

Revision ID: 0008_inventory
Revises: 0007_constitution_policy
Create Date: 2026-06-27

Slice 5c: a single `inventory_component` table tracks an agent's tools/prompts/memories (+ observed
capability classes). UNIQUE (agent_id, kind, name) so a declared row (registration manifest,
authoritative) and an observed row (reconciled from activity) for the SAME component reconcile into
ONE row. Authored against PostgreSQL as the production target (D-14) with dialect-agnostic generic
types so the same DDL applies on SQLite; the SQLite Store bootstraps the equivalent schema via
create_all.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0008_inventory"
down_revision: Union[str, None] = "0007_constitution_policy"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "inventory_component",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("agent_id", sa.String(length=255), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("source", sa.String(length=16), nullable=False),
        sa.Column(
            "first_seen_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "last_seen_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.UniqueConstraint("agent_id", "kind", "name", name="uq_inventory_component"),
    )


def downgrade() -> None:
    op.drop_table("inventory_component")
