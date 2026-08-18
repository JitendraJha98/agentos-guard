"""merkle_root — sealed audit epochs with inclusion proofs (AUD-06)

The hash chain proves the log was not rewritten, but only to a holder of the whole log. This table
lets an operator prove ONE record to an auditor: a root over a contiguous seq range, against which
a sibling path verifies a single disclosed record while revealing nothing about the others.

Anchor columns are nullable and filled by a separate step — sealing is local and cheap, anchoring
needs a TSA round-trip, and a TSA outage must not stop the log being sealed.

Authored against PostgreSQL as the production target (D-14); the column types are the same ones
the SQLite bootstrap already carries elsewhere in this schema.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0023_merkle_root"
down_revision: Union[str, None] = "0022_graph_source_watermark"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "merkle_root",
        sa.Column("epoch", sa.BigInteger(), primary_key=True),
        sa.Column("seq_start", sa.BigInteger(), nullable=False),
        sa.Column("seq_end", sa.BigInteger(), nullable=False),
        sa.Column("root", sa.String(length=64), nullable=False),
        sa.Column("leaf_count", sa.BigInteger(), nullable=False),
        sa.Column("anchor_kind", sa.String(length=32), nullable=True),
        sa.Column("proof", sa.LargeBinary(), nullable=True),
        sa.Column("tsa_url", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )


def downgrade() -> None:
    op.drop_table("merkle_root")
