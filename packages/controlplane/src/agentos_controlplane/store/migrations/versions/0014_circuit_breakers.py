"""circuit_breaker_state — durable breaker transitions (RUN-06)

Revision ID: 0014_circuit_breakers
Revises: 0013_resource_limits
Create Date: 2026-08-04

Slice 9d: the breaker state the pipeline's stage-1f gate reads. A breaker is identified by the
COMPOSITE PK (scope, agent_id, target), with target="" for the agent scope — never a concatenated
"agent_id|target" key, because both parts are free-form and may contain the separator, which let one
breaker alias another's row. Only TRANSITIONS are persisted — the rolling-window failure counters
live in memory, because a window is a recent-history view, not durable state; only the tripped state
must survive a restart, so a restart cannot silently un-trip a breaker.

`opened_at` is epoch SECONDS (a float): cooldown arithmetic is its only use, and a plain epoch avoids
naive/aware conversion bugs across the SQLite dev / Postgres target split.

The transition history lives on the audit chain (`circuit_tripped` / `circuit_reset`) — short
identifiers + counts only, never the target payload. The per-action deny is audited as a DECISION
record, not as a duplicate per-action event.

Authored against PostgreSQL as the production target (D-14) with dialect-agnostic generic types so
the same DDL applies on SQLite; the SQLite Store bootstraps the equivalent schema via create_all.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0014_circuit_breakers"
down_revision: Union[str, None] = "0013_resource_limits"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "circuit_breaker_state",
        sa.Column("scope", sa.String(length=16), primary_key=True),
        sa.Column("agent_id", sa.String(length=255), primary_key=True),
        sa.Column("target", sa.String(length=255), primary_key=True),
        sa.Column("state", sa.String(length=16), nullable=False),
        sa.Column("opened_at", sa.Float(), nullable=True),
        sa.Column("trip_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )


def downgrade() -> None:
    op.drop_table("circuit_breaker_state")
