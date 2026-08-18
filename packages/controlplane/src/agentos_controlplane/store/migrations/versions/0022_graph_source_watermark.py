"""graph fidelity + the incremental watermark (DISC-06 review)

Revision ID: 0022_graph_source_watermark
Revises: 0021_agent_graph
Create Date: 2026-08-18

Three corrections to the graph tables 0021 created.

`source` on both tables. Audit-derived capability-class rows are named after their own class
('tool','tool'), which is byte-identical to a genuine component literally named 'tool' — the exact
collapse that made DISC-05 flag every declaring agent in the fleet (migration 0020). The column
carries `inventory_component`'s vocabulary and precedence (declared > observed > observed_class) so
a placeholder can never be mistaken for evidence. Existing rows backfill to 'observed_class', the
LOWEST fidelity: the writer that produced them recorded no distinction, so claiming more than the
weakest reading would be inventing it, and the store never downgrades a row it re-sees.

`graph_watermark` — one row, how far materialization has consumed the audit chain. Without it every
sweep re-read the whole audit log inside ONE long write transaction against the database the
AuditWriter appends to, so a sweep stalled and then failed audit appends, which drives the
pipeline's fail-safe.

`graph_edge.observations` widens to BIGINT: it now counts ACTIONS (one per audit record, consumed
once), and a hot edge on a busy fleet outgrows int4.

Authored against PostgreSQL as the production target (D-14); `batch_alter_table` keeps the same
migration applicable to the SQLite bootstrap, which cannot ALTER a column type in place.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0022_graph_source_watermark"
down_revision: Union[str, None] = "0021_agent_graph"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    for table in ("graph_node", "graph_edge"):
        op.add_column(
            table,
            sa.Column(
                "source",
                sa.String(length=16),
                nullable=False,
                server_default="observed_class",
            ),
        )
    with op.batch_alter_table("graph_edge") as batch:
        batch.alter_column(
            "observations",
            existing_type=sa.Integer(),
            type_=sa.BigInteger(),
            existing_nullable=False,
            existing_server_default="1",
        )
    op.create_table(
        "graph_watermark",
        sa.Column("id", sa.String(length=32), primary_key=True),
        sa.Column("seq", sa.BigInteger(), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )


def downgrade() -> None:
    op.drop_table("graph_watermark")
    with op.batch_alter_table("graph_edge") as batch:
        batch.alter_column(
            "observations",
            existing_type=sa.BigInteger(),
            type_=sa.Integer(),
            existing_nullable=False,
            existing_server_default="1",
        )
    for table in ("graph_edge", "graph_node"):
        op.drop_column(table, "source")
