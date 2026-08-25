"""cost_record — what one action cost, attributed to one agent (ECON-01)

Money is INTEGER micro-USD, never a float or a NUMERIC. Float money drifts across a sum and Slice
11c makes budget DECISIONS on that sum, so an operator could not reproduce the number that blocked
their agent; integers also round-trip identically through SQLite and Postgres.

`cost_micro_usd` is nullable and stays null when the model is unpriced. Tokens are a fact the
provider reported; dollars are a conversion we can only do with a rate the operator supplied.
A zero there would read as "this action was free", which is a different claim from "we do not know".

The indexes are on the columns the 11c ledger and the read API actually filter by — an unindexed
scan of this table on a read path is the slow query that eventually gets blamed on the pipeline.

Authored against PostgreSQL as the production target (D-14); the column types are the same ones
the SQLite bootstrap already carries elsewhere in this schema.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0024_cost_record"
down_revision: Union[str, None] = "0023_merkle_root"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "cost_record",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("action_id", sa.Uuid(), nullable=False),
        sa.Column("agent_id", sa.String(length=255), nullable=False),
        sa.Column("action_type", sa.String(length=32), nullable=False),
        sa.Column("model", sa.String(length=128), nullable=True),
        sa.Column("input_tokens", sa.BigInteger(), nullable=True),
        sa.Column("output_tokens", sa.BigInteger(), nullable=True),
        sa.Column("cost_micro_usd", sa.BigInteger(), nullable=True),
        sa.Column("price_book_version", sa.String(length=32), nullable=True),
        sa.Column(
            "recorded_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index("ix_cost_record_action_id", "cost_record", ["action_id"])
    op.create_index("ix_cost_record_agent_id", "cost_record", ["agent_id"])
    op.create_index("ix_cost_record_recorded_at", "cost_record", ["recorded_at"])


def downgrade() -> None:
    op.drop_index("ix_cost_record_recorded_at", table_name="cost_record")
    op.drop_index("ix_cost_record_agent_id", table_name="cost_record")
    op.drop_index("ix_cost_record_action_id", table_name="cost_record")
    op.drop_table("cost_record")
