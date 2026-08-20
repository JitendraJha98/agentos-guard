"""amendment — the Constitution's own change log (POL-10)

Until now the constitution was versioned but its changes were not attributable: `constitution` is
already append-only with a unique content-hash `version`, so the old text survives, but nothing
recorded WHO asked for a change, who agreed to it, or why. "Versioned like a legal document" is
mostly about that second half — a document whose history you can read but whose authority you cannot
is a log, not a record.

`source` holds the whole proposed constitution rather than a diff. A diff would have to be applied to
whatever the constitution said at ratification time, which may differ from what it said when the
proposal was written, so what a human ratified would not be what took effect.

`ratified_by` and `constitution_version` are nullable because a proposal is INERT: a row in
`proposed` has produced no version and has no ratifier, and defaulting either would make a pending
amendment indistinguishable from a ratified one at the schema level.

A NEW, empty table, so there is no backfill question to get wrong.

Authored against PostgreSQL as the production target (D-14); every column type here is one the SQLite
bootstrap already carries elsewhere in this schema.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0029_amendment"
down_revision: Union[str, None] = "0028_redteam_runs"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "amendment",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("proposed_by", sa.String(length=255), nullable=False),
        sa.Column("source", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="proposed"),
        sa.Column("ratified_by", sa.String(length=128), nullable=True),
        sa.Column("resolution_note", sa.Text(), nullable=True),
        sa.Column("constitution_version", sa.String(length=128), nullable=True),
        sa.Column(
            "proposed_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
    )
    # The operator read is "what is waiting for me", so status is the index that matters. Both
    # remaining reads (history by version, and one amendment by id) are already served by the PK and
    # by the constitution table's own unique version.
    op.create_index("ix_amendment_status", "amendment", ["status"])


def downgrade() -> None:
    op.drop_index("ix_amendment_status", table_name="amendment")
    op.drop_table("amendment")
