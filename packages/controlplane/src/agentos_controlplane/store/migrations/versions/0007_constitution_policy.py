"""constitution + policy — compile-on-write Constitution/Policy resource tables (API-02)

Revision ID: 0007_constitution_policy
Revises: 0006_resources
Create Date: 2026-06-27

Slice 5b: compile-on-write. Applying a Constitution validates + compiles + persists the
Constitution version (`constitution`) AND its derived Policy (`policy`) in ONE transaction.
`constitution.version` / `policy.constitution_version` are the content-hash constitution_version
and are UNIQUE so apply is idempotent. Authored against PostgreSQL as the production target
(D-14) with dialect-agnostic generic types so the same DDL applies on SQLite; the SQLite Store
bootstraps the equivalent schema via create_all.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0007_constitution_policy"
down_revision: Union[str, None] = "0006_resources"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "constitution",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("version", sa.String(length=128), nullable=False, unique=True),
        sa.Column("source", sa.JSON(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_table(
        "policy",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("constitution_version", sa.String(length=128), nullable=False, unique=True),
        sa.Column("yaml_policy", sa.Text(), nullable=False),
        sa.Column("rego", sa.Text(), nullable=False),
        sa.Column("graduated_config", sa.JSON(), nullable=False),
        sa.Column("lists", sa.JSON(), nullable=False),
        sa.Column("sequences", sa.JSON(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )


def downgrade() -> None:
    op.drop_table("policy")
    op.drop_table("constitution")
