"""InventoryStore + InventoryComponent model (DISC-01/02).

Authoritative agent inventory over a function-scoped in-memory SQLite store (D-14: no Docker).
A single `inventory_component` table is UNIQUE on (agent_id, kind, name) so a declared row and an
observed row for the SAME component reconcile into ONE row (declared is authoritative). Audit-derived
observation is capability-class level by design (the audit body omits per-action target).
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.pool import StaticPool

from agentos_controlplane.store.engine import create_all, create_session_factory


@pytest.fixture
def store():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    create_all(engine)
    return create_session_factory(engine)


def test_inventory_component_unique_round_trip(store) -> None:
    """The model persists and reads back; a duplicate (agent_id, kind, name) raises IntegrityError."""
    from agentos_controlplane.store.models import InventoryComponent

    with store() as s:
        s.add(InventoryComponent(agent_id="a", kind="tool", name="http_get", source="declared"))
        s.add(InventoryComponent(agent_id="a", kind="memory", name="m1", source="declared"))
        s.commit()
    with store() as s:
        rows = s.query(InventoryComponent).all()
        assert len(rows) == 2
        assert {(r.kind, r.name) for r in rows} == {("tool", "http_get"), ("memory", "m1")}

    # Duplicate key (same agent_id/kind/name) violates the named unique constraint.
    with store() as s:
        s.add(InventoryComponent(agent_id="a", kind="tool", name="http_get", source="observed"))
        with pytest.raises(IntegrityError):
            s.commit()
