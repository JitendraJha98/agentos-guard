"""agent certificates + revocation list (IDN-03)

Revision ID: 0010_agent_certificates
Revises: 0009_trust_scope
Create Date: 2026-07-17

Slice 7c: each agent gets its own Ed25519 keypair and a CA-issued X.509 certificate
binding `agent_id <-> public_key`. `agent.certificate` holds the PEM and
`agent.cert_serial` its serial; `revoked_certificate` is the CRL.

Serials are DECIMAL STRINGS, not integers: X.509 serials are up to 20 bytes and
overflow BIGINT on every backend.

`agent.public_key` is NOT altered here, but its MEANING changes with this revision:
through 0009 it stored the control plane's shared key (identical in every row,
certifying nothing); from Phase 7 registration writes the agent's own key, as the
column was always documented to mean. Existing rows keep the old value until the
agent re-registers — harmless, since nothing read the column before this slice, and
a stale row simply has no certificate to verify against.

Authored against PostgreSQL as the production target (D-14) with dialect-agnostic
generic types so the same DDL applies on SQLite; the SQLite Store bootstraps the
equivalent schema via create_all.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0010_agent_certificates"
down_revision: Union[str, None] = "0009_trust_scope"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("agent", sa.Column("certificate", sa.Text(), nullable=True))
    op.add_column("agent", sa.Column("cert_serial", sa.String(length=64), nullable=True))
    op.create_table(
        "revoked_certificate",
        sa.Column("serial", sa.String(length=64), primary_key=True),
        sa.Column("agent_id", sa.String(length=255), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False, server_default=""),
        sa.Column(
            "revoked_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )


def downgrade() -> None:
    op.drop_table("revoked_certificate")
    op.drop_column("agent", "cert_serial")
    op.drop_column("agent", "certificate")
