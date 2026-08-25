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
    design (the audit body omits per-action target).

    The source is `observed_class`, NOT `observed`: the row's name is a placeholder for the CLASS
    (`name == kind`), so it can never reconcile with a manifest's per-tool name. Marking it as a
    full-fidelity observation made DISC-05 flag every declaring agent in the fleet."""
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
    assert rows == {
        ("tool", "tool", "observed_class"),
        ("delegation", "delegation", "observed_class"),
    }

    # Idempotent: a second reconcile pass re-upserts the same rows, it does not relabel them.
    inv.enrich_from_audit()
    assert {r.source for r in inv.get_inventory("a")} == {"observed_class"}


def test_repeated_activity_of_one_class_is_still_one_row(store) -> None:
    """The reconciler sees one audit record per ACTION but the (agent, class) ROW is the same one:
    an agent that made two tool calls must not try to insert its class-level row twice."""
    from agentos_controlplane.inventory import InventoryStore
    from agentos_controlplane.store.models import AuditRecord

    with store() as s:
        for i in range(3):
            s.add(AuditRecord(
                seq=i, prev_hash=None, record_hash=f"h{i}",
                body={"seq": i, "agent_id": "a", "action_type": "tool_call"},
            ))
        s.commit()

    inv = InventoryStore(store)
    assert inv.enrich_from_audit() == 3  # observations applied, one per record
    assert [(r.kind, r.name) for r in inv.get_inventory("a")] == [("tool", "tool")]


def test_source_precedence_never_downgrades_a_row(store) -> None:
    """declared (the manifest) > observed (this exact component was used) > observed_class (the
    class-level placeholder). Without the promotion half, a class-level row would permanently mask
    a genuine, undeclared component that happens to be named after its own class."""
    from agentos_controlplane.inventory import InventoryStore
    from agentos_controlplane.store.models import AuditRecord

    with store() as s:
        s.add(AuditRecord(
            seq=0, prev_hash=None, record_hash="h0",
            body={"seq": 0, "agent_id": "a", "action_type": "tool_call"},
        ))
        s.commit()

    inv = InventoryStore(store)
    inv.enrich_from_audit()
    assert [r.source for r in inv.get_inventory("a")] == ["observed_class"]

    inv.observe("a", "tool", "tool")  # a real, full-fidelity sighting of a tool named "tool"
    assert [r.source for r in inv.get_inventory("a")] == ["observed"]

    inv.declare("a", tools=["tool"])
    assert [r.source for r in inv.get_inventory("a")] == ["declared"]
    inv.observe("a", "tool", "tool")
    assert [r.source for r in inv.get_inventory("a")] == ["declared"]  # declared still wins


def test_register_with_manifest_writes_declared_inventory(store) -> None:
    """A registration manifest declares authoritative inventory rows (DISC-01)."""
    from agentos_controlplane.inventory import InventoryStore
    from agentos_controlplane.registry import Registry

    inv = InventoryStore(store)
    token = Registry(store, inventory=inv).register(
        "a", manifest={"tools": ["http_get"], "memories": ["m1"]}
    )
    assert token  # a valid issued identity token

    rows = {(r.kind, r.name, r.source) for r in inv.get_inventory("a")}
    assert rows == {("tool", "http_get", "declared"), ("memory", "m1", "declared")}


def test_register_backward_compatible_no_inventory_no_manifest(store) -> None:
    """register(agent_id) with no inventory/manifest still issues a token and writes no components."""
    from agentos_controlplane.inventory import InventoryStore
    from agentos_controlplane.registry import Registry

    token = Registry(store).register("b")
    assert token

    # Even register(agent_id, trust_score) stays unchanged (no manifest arg required).
    token2 = Registry(store).register("c", 0.9)
    assert token2

    assert InventoryStore(store).list_inventory() == []
