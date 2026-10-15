"""mcp_quarantine — the SEC-07 quarantine, durable and shared across instances (Phase 17)

The gateway's quarantine lived only in process memory, so a restart released every quarantined
MCP tool and a second instance never saw the first one's quarantine. Additive and empty.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0034_mcp_quarantine"
down_revision: Union[str, None] = "0033_api_principal"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "mcp_quarantine",
        sa.Column("server", sa.String(length=255), primary_key=True),
        sa.Column("tool", sa.String(length=255), primary_key=True),
        sa.Column("findings", sa.JSON(), nullable=False),
        sa.Column(
            "quarantined_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )


def downgrade() -> None:
    op.drop_table("mcp_quarantine")
