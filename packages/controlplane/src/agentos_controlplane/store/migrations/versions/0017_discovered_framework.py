"""discovered_framework — the agent frameworks actually present in this deployment (DISC-03)

Revision ID: 0017_discovered_framework
Revises: 0016_consensus
Create Date: 2026-08-11

Slice 10c: you cannot govern what you cannot see. This table records which agent frameworks
(LangChain/LangGraph, CrewAI, AutoGen, the OpenAI Agents SDK, MCP) are genuinely installed, with
the distribution that evidenced each and the version found at detection time.

Keyed by (`observer`, `name`): the row is the CURRENT observation per framework PER scanning
instance, upserted by each scan and bracketed by first/last-seen. The observer dimension is what
bounds the chain in a multi-replica deployment — keyed by `name` alone, two control planes that
disagree about a version overwrite each other on every pass and emit an event every time.

The immutable history lives on the audit chain, where a newly-observed framework (or a version
change) appends one `framework_discovered` event carrying short identifiers plus a sha256 digest of
the version — never the version text, which is supply-chain input. A repeat scan over an unchanged
environment appends nothing, so a scheduled pass cannot bloat the chain.

Column widths are enforced here (Postgres) and not on SQLite, so the detector bounds `version` and
`distribution` to exactly these widths before persisting — same row on both backends.

Authored against PostgreSQL as the production target (D-14) with dialect-agnostic generic types so
the same DDL applies on SQLite; the SQLite Store bootstraps the equivalent schema via create_all.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0017_discovered_framework"
down_revision: Union[str, None] = "0016_consensus"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "discovered_framework",
        sa.Column("observer", sa.String(length=128), primary_key=True),
        sa.Column("name", sa.String(length=64), primary_key=True),
        sa.Column("distribution", sa.String(length=128), nullable=False),
        sa.Column("version", sa.String(length=64), nullable=False),
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
    op.drop_table("discovered_framework")
