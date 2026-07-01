"""audit_signatures — per-record EdDSA signature + signing_key_id (AUD-08)

Revision ID: 0003_audit_signatures
Revises: 0002_approvals
Create Date: 2026-06-12

Slice 4a: each audit_record gains a detached Ed25519 signature over
SIG_DOMAIN + canonical_json(body) plus a short fingerprint of the signing
public key. Both columns are nullable — a writer without a signer produces
unsigned records (backward compat); the production path always signs. Authored
against PostgreSQL as the production target (D-14) with dialect-agnostic generic
types so the same DDL applies on SQLite.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0003_audit_signatures"
down_revision: Union[str, None] = "0002_approvals"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("audit_record", sa.Column("signature", sa.Text(), nullable=True))
    op.add_column(
        "audit_record", sa.Column("signing_key_id", sa.String(length=64), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("audit_record", "signing_key_id")
    op.drop_column("audit_record", "signature")
