"""emergency_shutdown — append-only fleet emergency-stop incidents (RUN-07)

Revision ID: 0015_emergency_shutdown
Revises: 0014_circuit_breakers
Create Date: 2026-08-04

Slice 9e: emergency shutdown EXTENDS the RUN-01/02 kill switch (it sets the same fleet flag, so the
pipeline's stage-0 check halts every agent with no new hot-path code). What it adds durably is
INCIDENT HISTORY, which the `kill_switch` table cannot hold: that row is upserted and carries only
CURRENT state, so a resumed incident would leave no trace of who stopped the fleet, when, or why.

`justification` is NOT NULL because an unexplained fleet stop is not an auditable control, and the
free text lives HERE ONLY — the audit event body carries short identifiers + this row's id, so a
hostile or secret-bearing justification can never trip the AUD-04 secret gate on `append_event` and
thereby BLOCK an emergency stop. `resumed_at`/`resumed_by` stay NULL while the incident is open (the
open row is also what a restart reads to reload the halt's `emergency` scope).

Authored against PostgreSQL as the production target (D-14) with dialect-agnostic generic types so
the same DDL applies on SQLite; the SQLite Store bootstraps the equivalent schema via create_all.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0015_emergency_shutdown"
down_revision: Union[str, None] = "0014_circuit_breakers"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "emergency_shutdown",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("justification", sa.Text(), nullable=False),
        sa.Column("declared_by", sa.String(length=255), nullable=False),
        sa.Column(
            "declared_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("resumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resumed_by", sa.String(length=255), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("emergency_shutdown")
