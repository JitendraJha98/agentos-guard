"""trust_profile.scope — the agent's own capability scope (TRST-04)

Revision ID: 0009_trust_scope
Revises: 0008_inventory
Create Date: 2026-07-17

Slice 7b: delegated scope is enforced as an INTERSECTION of the delegator's and the
delegate's scope (never a union), so each agent needs an authored scope of its own.
It lands on `trust_profile` — the existing per-agent governance-posture resource that
already carries `trust_score` and the graduated `band` — rather than a new table.

NULLABLE with no server default, deliberately: NULL reads as "unset", which the
ScopeLookup resolves to the wildcard. Existing agents therefore keep their exact
pre-Phase-7 authority on upgrade (no silent capability loss on a live fleet), while a
delegation still narrows them by intersection with the delegator. Backfilling `["*"]`
would be equivalent today but would bake a wildcard into rows an operator never
authored, which is worse to inherit later.

Authored against PostgreSQL as the production target (D-14) with dialect-agnostic
generic types so the same DDL applies on SQLite; the SQLite Store bootstraps the
equivalent schema via create_all.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0009_trust_scope"
down_revision: Union[str, None] = "0008_inventory"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("trust_profile", sa.Column("scope", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("trust_profile", "scope")
