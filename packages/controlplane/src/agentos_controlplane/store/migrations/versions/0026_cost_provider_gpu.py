"""cost_record gains downstream provider + GPU attribution (ECON-03)

Revision ID: 0026_cost_provider_gpu
Revises: 0025_agent_budget
Create Date: 2026-08-19

ECON-01 recorded what a HOSTED MODEL cost. ECON-03 covers the other two ways an agent spends: a
third-party API it calls, and GPU time on hardware the operator owns. Both widen the existing row
rather than opening a second table — they are what the SAME action cost, and two tables keyed on one
action_id is two numbers that can disagree about it.

`provider` is the action's own `target`, which the PEP already normalized. Nothing here infers a
vendor from a hostname: a guessed vendor lands in a cost report an operator reconciles line-by-line
against a real invoice, and a wrong line there is worse than a missing one.

`gpu_attribution` exists because NVML reports per DEVICE. A control plane governing several agents in
one process cannot divide a device-wide counter among them, so the label says which thing was
measured — 'process', or 'device_shared' which is explicitly NOT a per-agent bill. Phase 9's Slice 9c
shipped a draft that attributed process-wide tracemalloc deltas to individual actions and the review
killed it for fabricating audit accusations; this column is how the same trap is walked around
instead of into.

ALL FOUR NULLABLE, AND EXISTING ROWS ARE NOT BACKFILLED. An action recorded before this migration
genuinely has no provider and no GPU reading. Defaulting them to 0 / '' would convert "we did not
measure" into "we measured nothing", which is a claim about an agent that no one ever observed.

Authored against PostgreSQL as the production target (D-14); `batch_alter_table` keeps the same
migration applicable to the SQLite bootstrap, whose ALTER support is limited (the pattern 0022 used).
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0026_cost_provider_gpu"
down_revision: Union[str, None] = "0025_agent_budget"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("cost_record") as batch:
        batch.add_column(sa.Column("provider", sa.String(length=128), nullable=True))
        batch.add_column(sa.Column("gpu_seconds", sa.Float(), nullable=True))
        batch.add_column(sa.Column("gpu_memory_mib", sa.BigInteger(), nullable=True))
        batch.add_column(sa.Column("gpu_attribution", sa.String(length=16), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("cost_record") as batch:
        for column in ("gpu_attribution", "gpu_memory_mib", "gpu_seconds", "provider"):
            batch.drop_column(column)
