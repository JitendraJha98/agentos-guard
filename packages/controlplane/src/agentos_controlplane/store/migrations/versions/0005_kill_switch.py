"""kill_switch — CURRENT operator kill-switch state (RUN-01/02)

Revision ID: 0005_kill_switch
Revises: 0004_chain_checkpoint
Create Date: 2026-06-12

Slice 4e: an operator can kill-switch a single agent (RUN-01) or the entire fleet
(target "*", RUN-02). This table holds the durable CURRENT state backing the in-memory
`KillSwitchStore` (the hot-path lookup); the immutable history of toggles lives on the
audit hash chain (`kill_switch_set` / `kill_switch_cleared` events). The operator
free-text `reason` lives in this table only. Authored against PostgreSQL as the
production target (D-14) with dialect-agnostic generic types so the same DDL applies on
SQLite.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0005_kill_switch"
down_revision: Union[str, None] = "0004_chain_checkpoint"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "kill_switch",
        sa.Column("target", sa.String(length=255), primary_key=True),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("set_by", sa.String(length=255), nullable=True),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )


def downgrade() -> None:
    op.drop_table("kill_switch")
