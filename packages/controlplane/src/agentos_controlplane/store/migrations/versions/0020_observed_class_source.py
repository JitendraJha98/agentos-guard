"""inventory_component — relabel the CLASS-LEVEL observations `observed_class` (DISC-05 review)

Revision ID: 0020_observed_class_source
Revises: 0019_rogue_finding
Create Date: 2026-08-11

`InventoryStore.enrich_from_audit` (driven by API-04's GraphReconciler) is the only production
writer of observed rows, and the audit body omits the per-action target — so what it records is a
CLASS-level placeholder named after its own class: ('tool','tool'), ('memory','memory'). A manifest
declares per-tool names ('tool','http_get'), so the two keys can never reconcile, and DISC-05
comparing them flagged every manifest-declaring agent in the fleet for doing exactly what it
declared. The writer now marks that fidelity difference with its own `source`, and the detector
compares only full-fidelity `observed` rows.

This backfills the rows already written under the old label, so a deployment that has been running
the reconciler does not carry the false positive forward. The predicate is exactly the placeholder
the writer emitted (`name = kind`); no full-fidelity writer exists yet (Slice 5d), so no genuine
observation can be caught by it. A DATA migration only — the column and its width are unchanged.

Authored against PostgreSQL as the production target (D-14) with dialect-agnostic SQL so the same
statement applies on SQLite.
"""

from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0020_observed_class_source"
down_revision: Union[str, None] = "0019_rogue_finding"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        "UPDATE inventory_component SET source = 'observed_class' "
        "WHERE source = 'observed' AND name = kind"
    )


def downgrade() -> None:
    op.execute("UPDATE inventory_component SET source = 'observed' WHERE source = 'observed_class'")
