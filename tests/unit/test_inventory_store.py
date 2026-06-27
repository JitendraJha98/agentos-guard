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


def test_declare_then_observe_reconciles_to_one_row(store) -> None:
    """A declared manifest writes authoritative rows; observing the SAME component reconciles into
    ONE row (declared wins, never downgraded); observing a NEW component adds an observed row."""
    from agentos_controlplane.inventory import InventoryStore

    inv = InventoryStore(store)
    inv.declare("a", tools=["http_get"], prompts=["sys"], memories=["m1"])

    rows = inv.get_inventory("a")
    assert {(r.kind, r.name, r.source) for r in rows} == {
        ("tool", "http_get", "declared"),
        ("prompt", "sys", "declared"),
        ("memory", "m1", "declared"),
    }

    # Observing the declared component reconciles into the SAME row — still declared, not duplicated.
    inv.observe("a", "tool", "http_get")
    tools = [r for r in inv.get_inventory("a") if r.kind == "tool"]
    assert len(tools) == 1 and tools[0].source == "declared"

    # Observing a brand-new component creates an observed row.
    inv.observe("a", "tool", "other")
    tools = sorted((r.name, r.source) for r in inv.get_inventory("a") if r.kind == "tool")
    assert tools == [("http_get", "declared"), ("other", "observed")]


def test_list_and_get_shapes_and_ordering(store) -> None:
    """list_inventory spans agents (sorted agent_id, kind, name); get_inventory filters one agent."""
    from agentos_controlplane.inventory import InventoryStore

    inv = InventoryStore(store)
    inv.declare("b", tools=["z_tool"])
    inv.declare("a", tools=["a_tool"], memories=["m"])

    listed = inv.list_inventory()
    assert [(d.agent_id, d.kind, d.name) for d in listed] == [
        ("a", "memory", "m"),
        ("a", "tool", "a_tool"),
        ("b", "tool", "z_tool"),
    ]
    # Shape: ComponentData carries source + ISO timestamps.
    first = listed[0]
    assert first.source == "declared"
    assert first.first_seen_at is not None and first.last_seen_at is not None

    only_a = inv.get_inventory("a")
    assert {d.name for d in only_a} == {"m", "a_tool"}


def test_enrich_from_audit_observes_class_level_and_skips_events(store) -> None:
    """enrich_from_audit maps each decision record's action_type -> capability class and records an
    observed (agent, class) row. Event records (body carries 'kind') are skipped — class-level by
    design (the audit body omits per-action target)."""
    from agentos_controlplane.inventory import InventoryStore
    from agentos_controlplane.store.models import AuditRecord

    # Two decision records (a tool_call + a delegation) and one event record (has "kind").
    with store() as s:
        s.add(AuditRecord(
            seq=0, prev_hash=None, record_hash="h0",
            body={"seq": 0, "agent_id": "a", "action_type": "tool_call"},
        ))
        s.add(AuditRecord(
            seq=1, prev_hash="h0", record_hash="h1",
            body={"seq": 1, "agent_id": "a", "action_type": "delegation"},
        ))
        s.add(AuditRecord(
            seq=2, prev_hash="h1", record_hash="h2",
            body={"seq": 2, "kind": "side_effect", "agent_id": "a"},
        ))
        s.commit()

    inv = InventoryStore(store)
    applied = inv.enrich_from_audit()
    assert applied == 2  # the event record was skipped

    rows = {(r.kind, r.name, r.source) for r in inv.get_inventory("a")}
    assert rows == {("tool", "tool", "observed"), ("delegation", "delegation", "observed")}
