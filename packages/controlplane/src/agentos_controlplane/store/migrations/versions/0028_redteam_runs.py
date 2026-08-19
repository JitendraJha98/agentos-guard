"""redteam_run + redteam_result — attack-success-rate over time (TEST-07)

Revision ID: 0028_redteam_runs
Revises: 0027_agent_risk_classification
Create Date: 2026-08-19

COUNTS, NOT A RATE. `total` and `blocked` are stored and the rate is derived, because a rate is a
lossy summary of two numbers and the one it loses is the one that says whether to believe it: one
attack slipped out of two and two hundred and fifty out of five hundred are both "50%" and land on
the same point of a trend chart. Storing the counts also means a later window or a coarser grouping
is re-derivable without re-running anything, which a stored rate cannot give back.

`suite` IS A GROUP BY KEY, and that is why it is a bounded vocabulary (`agentos_sdk.redteam.suites()`)
rather than free text. Phase 6's Slice 6b review found a metric-cardinality DoS in exactly this
shape — per-agent x per-class x per-window — and ECON-03 found the other half of the same hazard:
clipping a grouping key silently MERGES two distinct things into one row. The writer refuses an
over-long suite rather than truncating it, so two attack classes can never sum into one reassuring
number.

Two tables rather than one: the run is what a trend point aggregates, and the per-attack rows are
what make a regression diagnosable — a moving trend says something broke, and only the attack id
says what.

Authored against PostgreSQL as the production target (D-14) with dialect-agnostic generic types, so
the same migration runs on the SQLite bootstrap. Both tables are NEW and empty, so there is no
backfill question to get wrong.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0028_redteam_runs"
down_revision: Union[str, None] = "0027_agent_risk_classification"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "redteam_run",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("agent_id", sa.String(length=255), nullable=False),
        sa.Column("suite", sa.String(length=64), nullable=False),
        sa.Column("total", sa.Integer(), nullable=False),
        sa.Column("blocked", sa.Integer(), nullable=False),
        sa.Column("source", sa.String(length=32), nullable=False, server_default="manual"),
        sa.Column(
            "ran_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
    )
    # The trend query groups on (agent_id, suite) and windows on ran_at — these three indexes are
    # exactly the read this table exists to serve, not speculative coverage.
    op.create_index("ix_redteam_run_agent_id", "redteam_run", ["agent_id"])
    op.create_index("ix_redteam_run_suite", "redteam_run", ["suite"])
    op.create_index("ix_redteam_run_ran_at", "redteam_run", ["ran_at"])

    op.create_table(
        "redteam_result",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.Column("attack_id", sa.String(length=64), nullable=False),
        sa.Column("outcome", sa.String(length=32), nullable=False),
        sa.Column("blocked", sa.Boolean(), nullable=False),
    )
    op.create_index("ix_redteam_result_run_id", "redteam_result", ["run_id"])


def downgrade() -> None:
    op.drop_index("ix_redteam_result_run_id", table_name="redteam_result")
    op.drop_table("redteam_result")
    op.drop_index("ix_redteam_run_ran_at", table_name="redteam_run")
    op.drop_index("ix_redteam_run_suite", table_name="redteam_run")
    op.drop_index("ix_redteam_run_agent_id", table_name="redteam_run")
    op.drop_table("redteam_run")
