"""graph_node + graph_edge — the live agent graph (DISC-06)

Revision ID: 0021_agent_graph
Revises: 0020_observed_class_source
Create Date: 2026-08-11

Slice 10f: agents and the components they use become first-class NODES, and the delegation lineage
the audit body already carries (`parent_action_id`) becomes agent -> agent EDGES. This is the
"what talks to what" map the Phase-13 permission calculus walks.

Both tables are keyed by their identity — a node by (kind, name), an edge by the (src, dst,
relation) 5-tuple — because materialization is a BATCH reconciler pass that reruns on a schedule.
Without those constraints every sweep would append a fresh copy of the whole graph; with them the
pass converges and `observations` records repetition instead.

Authored against PostgreSQL as the production target (D-14) with dialect-agnostic generic types so
the same DDL applies on SQLite; the SQLite Store bootstraps the equivalent schema via create_all.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0021_agent_graph"
down_revision: Union[str, None] = "0020_observed_class_source"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "graph_node",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
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
        sa.UniqueConstraint("kind", "name", name="uq_graph_node"),
    )
    op.create_table(
        "graph_edge",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("src_kind", sa.String(length=32), nullable=False),
        sa.Column("src_name", sa.String(length=255), nullable=False),
        sa.Column("dst_kind", sa.String(length=32), nullable=False),
        sa.Column("dst_name", sa.String(length=255), nullable=False),
        sa.Column("relation", sa.String(length=32), nullable=False),
        sa.Column("observations", sa.Integer(), nullable=False, server_default="1"),
        sa.Column(
            "last_seen_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.UniqueConstraint(
            "src_kind", "src_name", "dst_kind", "dst_name", "relation", name="uq_graph_edge"
        ),
    )


def downgrade() -> None:
    op.drop_table("graph_edge")
    op.drop_table("graph_node")
