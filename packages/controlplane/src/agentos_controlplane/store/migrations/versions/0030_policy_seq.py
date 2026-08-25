"""policy.seq — order the policy history by insertion, not by the wall clock

`get_latest_policy()` ordered by `created_at DESC` with no tiebreaker. `created_at` was given a
Python-side default precisely to avoid ties, but a Python default carries only the PLATFORM CLOCK'S
resolution: microseconds on Linux, but ~15.6ms on Windows. Two constitutions applied inside one tick
therefore still tied, and the row the database happened to return first won — which could be the
OLDER policy. The consequences are the ones the regression test names: a stale `GET /policies/latest`,
and the API-04 CacheReconciler warming the hot path to the WRONG constitution.

This is the same problem `AuditRecord` already solved, so it takes the same answer: a strictly
monotonic `seq` assigned by the single writer, with ordering derived from it and never from a
timestamp. UNIQUE is what makes it trustworthy — two applies that compute the same number cannot
both commit, so the loser retries instead of silently sharing an ordering key.

BACKFILL: existing rows are numbered by `created_at`, then by `id` to break the very ties this
column exists to eliminate. That ordering is arbitrary for rows already tied — it cannot be
reconstructed after the fact — but it is STABLE from here on, which is the property that was
missing. Numbering starts at 1 so `max(seq)` on an empty table reads as 0 and the first insert
takes 1.

Authored against PostgreSQL as the production target (D-14); `batch_alter_table` keeps the SQLite
bootstrap working, where ALTER is emulated by table rebuild.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0030_policy_seq"
down_revision: Union[str, None] = "0029_amendment"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1) Add it nullable: an existing table has rows that have no number yet.
    with op.batch_alter_table("policy") as batch:
        batch.add_column(sa.Column("seq", sa.BigInteger(), nullable=True))

    # 2) Backfill in a deterministic order. Portable to both backends: a correlated COUNT rather
    # than a window function, since the table holds one row per constitution version — tens of
    # rows in any real deployment, not a volume where the O(n^2) shape matters.
    policy = sa.table(
        "policy",
        sa.column("id", sa.Uuid()),
        sa.column("seq", sa.BigInteger()),
        sa.column("created_at", sa.DateTime(timezone=True)),
    )
    inner = policy.alias("earlier")
    op.execute(
        policy.update().values(
            seq=(
                sa.select(sa.func.count())
                .select_from(inner)
                .where(
                    sa.tuple_(inner.c.created_at, inner.c.id)
                    <= sa.tuple_(policy.c.created_at, policy.c.id)
                )
                .scalar_subquery()
            )
        )
    )

    # 3) Now that every row is numbered, enforce what the column promises.
    with op.batch_alter_table("policy") as batch:
        batch.alter_column("seq", existing_type=sa.BigInteger(), nullable=False)
        batch.create_unique_constraint("uq_policy_seq", ["seq"])


def downgrade() -> None:
    with op.batch_alter_table("policy") as batch:
        batch.drop_constraint("uq_policy_seq", type_="unique")
        batch.drop_column("seq")
