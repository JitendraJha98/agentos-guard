"""agent_budget — an operator-set spending limit for one agent (ECON-02)

Money is INTEGER micro-USD, matching `cost_record`. The two are compared on every governed action to
produce a used-ratio the constitution conditions on, so they must be the same representation: a float
limit compared against an integer sum is a budget boundary that moves depending on which side
rounded, and an operator cannot reproduce the number that blocked their agent.

An ABSENT ROW MEANS "no budget configured", never "a budget of zero". That is why the limit is not
defaulted to 0 for every registered agent: the ledger reads a missing row as a used-ratio of 0.0, so
a deployment that never opted into budgets is not denied by the mere presence of this table.

`period` is the window the limit applies over ('day' | 'month' | 'total'); the ledger sums
`cost_record` inside that window rather than storing a running total here, so a corrected or deleted
cost row is reflected on the next reconcile instead of being baked into a counter forever.

Authored against PostgreSQL as the production target (D-14); the column types are the same generic
ones the rest of this schema already carries.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0025_agent_budget"
down_revision: Union[str, None] = "0024_cost_record"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "agent_budget",
        sa.Column("agent_id", sa.String(length=255), primary_key=True),
        sa.Column("period", sa.String(length=16), nullable=False, server_default="day"),
        sa.Column("limit_micro_usd", sa.BigInteger(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )


def downgrade() -> None:
    op.drop_table("agent_budget")
