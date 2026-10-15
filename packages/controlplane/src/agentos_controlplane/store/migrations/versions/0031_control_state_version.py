"""control_state_version — cross-instance invalidation of the hot-path caches (Phase 15)

The kill switch, circuit breakers, privilege rings, resource limits, identity cache and budget
ledger all answer the hot path from memory. With more than one control-plane instance, a change
made through one instance was invisible to the others until they restarted. Each write now bumps a
per-topic version in the same transaction, and every instance polls this one small table.

Additive and empty: no backfill question. Topics are seeded lazily by the bus.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0031_control_state_version"
down_revision: Union[str, None] = "0030_policy_seq"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "control_state_version",
        sa.Column("topic", sa.String(length=64), primary_key=True),
        sa.Column("version", sa.BigInteger(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("control_state_version")
