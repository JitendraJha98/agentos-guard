"""consensus_round + consensus_vote — 2-of-3 multi-agent consensus (POL-09)

Revision ID: 0016_consensus
Revises: 0015_emergency_shutdown
Create Date: 2026-08-04

Slice 9f: a `require_consensus` outcome no longer borrows the human-approval path — it is
resolved by independent voters, and THIS is the durable record of that resolution. The round
row holds the counts that decided it (voters asked, approvals received, quorum required,
whether it was reached); one vote row per voter holds the individual verdict.

`consensus_vote.error` is what makes the fail-closed rule auditable: a voter that raised or
timed out is stored with `approved = false` and a short error tag, so "nobody objected" can
never be mistaken for "everybody agreed". It is a short type name / "timeout", never a
voter-supplied message — the audit event bodies carry identifiers + counts only, so a
secret-bearing or hostile rationale can never trip the AUD-04 gate and thereby BLOCK the
recording of a consensus decision.

Authored against PostgreSQL as the production target (D-14) with dialect-agnostic generic
types so the same DDL applies on SQLite; the SQLite Store bootstraps the equivalent schema
via create_all.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0016_consensus"
down_revision: Union[str, None] = "0015_emergency_shutdown"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "consensus_round",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("action_id", sa.Uuid(), nullable=False),
        sa.Column("agent_id", sa.String(length=255), nullable=False),
        sa.Column("voters", sa.Integer(), nullable=False),
        sa.Column("approvals", sa.Integer(), nullable=False),
        sa.Column("quorum", sa.Integer(), nullable=False),
        sa.Column("reached", sa.Boolean(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_table(
        "consensus_vote",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("round_id", sa.Uuid(), nullable=False),
        sa.Column("voter", sa.String(length=255), nullable=False),
        sa.Column("approved", sa.Boolean(), nullable=False),
        sa.Column("error", sa.String(length=255), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )


def downgrade() -> None:
    op.drop_table("consensus_vote")
    op.drop_table("consensus_round")
