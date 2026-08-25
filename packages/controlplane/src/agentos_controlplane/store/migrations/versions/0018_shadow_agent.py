"""shadow_agent — actors seen acting WITHOUT being registered (DISC-04)

Revision ID: 0018_shadow_agent
Revises: 0017_discovered_framework
Create Date: 2026-08-11

Slice 10d: the pipeline already denies an unregistered actor at stage 1 (IDN-02); this table makes
it visible. One row per claimed id, bracketed by first/last-seen with an attempt counter, so a
hundred probes from one id read as ONE incident rather than a hundred denies lost among thousands.

`claimed_agent_id` is ATTACKER-CONTROLLED — it is whatever an unverified caller put in its token.
The store bounds it to 255 chars and sanitizes it BEFORE it reaches this row, so the width here is
enforced at the source and not merely by Postgres: SQLite does not enforce VARCHAR length, and a
10 MB claimed id must not become a 10 MB row on either backend. Only the FIRST sighting of an id
appends to the audit chain, so a flood cannot grow the chain at will, and the store caps how many
DISTINCT ids get their own row (the rest fold into one `<overflow>` bucket), so rotating the id
cannot grow the table or the chain either.

The PRIMARY KEY is `claimed_id_digest` — sha256 of the FULL raw id — and not the sanitized display
text, which is lossy in two directions (truncation past 255 chars, and every disallowed character
mapping to the same `?`). Keyed by that text, two different attackers would share one row.

Authored against PostgreSQL as the production target (D-14) with dialect-agnostic generic types so
the same DDL applies on SQLite; the SQLite Store bootstraps the equivalent schema via create_all.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0018_shadow_agent"
down_revision: Union[str, None] = "0017_discovered_framework"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "shadow_agent",
        sa.Column("claimed_id_digest", sa.String(length=64), primary_key=True),
        sa.Column("claimed_agent_id", sa.String(length=255), nullable=False),
        sa.Column("action_type", sa.String(length=64), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="1"),
        sa.Column(
            "first_seen_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "last_seen_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )


def downgrade() -> None:
    op.drop_table("shadow_agent")
