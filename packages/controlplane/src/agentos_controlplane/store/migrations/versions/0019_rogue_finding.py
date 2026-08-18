"""rogue_finding — a registered agent used a component it never declared (DISC-05)

Revision ID: 0019_rogue_finding
Revises: 0018_shadow_agent
Create Date: 2026-08-11

Slice 10e: 10d's `shadow_agent` answers "who is acting without being registered"; this answers "who
is registered but is not doing what they said". Phase 5's `inventory_component` already stores both
halves of the comparison — `source='declared'` (the registration manifest, authoritative) and
`source='observed'` (what actually happened), with declared winning the upsert — so a row still
marked observed is precisely a component the agent never declared. This table records that
divergence.

ADVISORY: there is no deny path. A declaration gap is evidence, not proof — a manifest goes stale —
so `resolved` lets an operator acknowledge a finding while the audit chain keeps the sighting.

UNIQUE on (agent_id, kind, name) so a repeat sweep of an unchanged fleet inserts nothing: the
idempotence that keeps a scheduled scan from bloating the table lives in the schema, not only in
the detector.

Authored against PostgreSQL as the production target (D-14) with dialect-agnostic generic types so
the same DDL applies on SQLite; the SQLite Store bootstraps the equivalent schema via create_all.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0019_rogue_finding"
down_revision: Union[str, None] = "0018_shadow_agent"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "rogue_finding",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("agent_id", sa.String(length=255), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("resolved", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column(
            "first_seen_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.UniqueConstraint("agent_id", "kind", "name", name="uq_rogue_finding"),
    )


def downgrade() -> None:
    op.drop_table("rogue_finding")
