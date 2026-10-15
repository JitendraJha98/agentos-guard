"""correlation_event + delegation_authority — SEC-13 and TRST-04 state shared across instances

Both lived in process memory, so a multi-instance deployment could be evaded by splitting a
sequence across replicas (SEC-13), and denied legitimate delegations whose parent was resolved on
another replica (TRST-04). Additive and empty: no backfill question.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0032_shared_lineage"
down_revision: Union[str, None] = "0031_control_state_version"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "correlation_event",
        sa.Column(
            "id",
            sa.BigInteger().with_variant(sa.Integer(), "sqlite"),
            primary_key=True,
            autoincrement=True,
        ),
        sa.Column("key", sa.String(length=255), nullable=False),
        sa.Column("intent_class", sa.String(length=128), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
    )
    op.create_index("ix_correlation_event_key", "correlation_event", ["key"])
    op.create_table(
        "delegation_authority",
        sa.Column("action_id", sa.String(length=64), primary_key=True),
        sa.Column("agent_id", sa.String(length=255), nullable=False),
        sa.Column("trust", sa.Float(), nullable=False),
        sa.Column("scope", sa.JSON(), nullable=False),
        sa.Column("depth", sa.Integer(), nullable=False),
        sa.Column("ring", sa.Integer(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
    )
    op.create_index(
        "ix_delegation_authority_created_at", "delegation_authority", ["created_at"]
    )


def downgrade() -> None:
    op.drop_index("ix_delegation_authority_created_at", table_name="delegation_authority")
    op.drop_table("delegation_authority")
    op.drop_index("ix_correlation_event_key", table_name="correlation_event")
    op.drop_table("correlation_event")
