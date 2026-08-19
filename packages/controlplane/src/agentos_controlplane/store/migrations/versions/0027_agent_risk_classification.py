"""agent gains the operator-declared EU AI Act risk classification (CMP-04)

Revision ID: 0027_agent_risk_classification
Revises: 0026_cost_provider_gpu
Create Date: 2026-08-19

Whether a deployment is high-risk under Art. 6 / Annex III of Regulation (EU) 2024/1689 depends on
its USE CASE, which nothing in this control plane can observe. So the column holds what an OPERATOR
declared and nothing else.

NULLABLE, WITH NO SERVER DEFAULT AND NO BACKFILL, and that is the whole point of the column. Every
agent registered before this migration genuinely has no declaration on file. A default of
'minimal_risk' would tell a deployer they may skip obligations they in fact have; a default of
'high_risk' would burden them with obligations they do not. NULL means undeclared, the export
reports it as undeclared, and the operator is the one who resolves it.

Authored against PostgreSQL as the production target (D-14); `batch_alter_table` keeps the same
migration applicable to the SQLite bootstrap, whose ALTER support is limited (the pattern 0022/0026
used).
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0027_agent_risk_classification"
down_revision: Union[str, None] = "0026_cost_provider_gpu"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("agent") as batch:
        batch.add_column(sa.Column("risk_classification", sa.String(length=32), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("agent") as batch:
        batch.drop_column("risk_classification")
