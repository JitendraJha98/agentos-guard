"""Agent-inventory read API + auth gate (DISC-01/02).

GET /inventory and GET /inventory/{agent_id} read the InventoryStore behind the shared-token gate
(no/wrong Bearer -> 401). create_app without an inventory_store wires no routes (GET /inventory ->
404), keeping every existing caller working.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from agentos_controlplane.api import create_app
from agentos_controlplane.approvals import ApprovalStore
from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.inventory import InventoryStore
from agentos_controlplane.store.engine import create_all, create_session_factory

TOKEN = "test-token"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


@pytest.fixture
def store():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    create_all(engine)
    return create_session_factory(engine)


@pytest.fixture
def client(store) -> TestClient:
    inv = InventoryStore(store)
    inv.declare("a", tools=["http_get"], memories=["m1"])
    inv.declare("b", tools=["z_tool"])
    app = create_app(
        ApprovalStore(store, AuditWriter(store)),
        inventory_store=inv,
        api_token=TOKEN,
    )
    c = TestClient(app)
    c.headers.update(AUTH)
    return c


def test_list_inventory_200(client) -> None:
    r = client.get("/inventory")
    assert r.status_code == 200
    rows = r.json()
    assert {(d["agent_id"], d["kind"], d["name"], d["source"]) for d in rows} == {
        ("a", "memory", "m1", "declared"),
        ("a", "tool", "http_get", "declared"),
        ("b", "tool", "z_tool", "declared"),
    }


def test_get_inventory_filtered_200(client) -> None:
    r = client.get("/inventory/a")
    assert r.status_code == 200
    rows = r.json()
    assert {d["name"] for d in rows} == {"http_get", "m1"}
    assert all(d["agent_id"] == "a" for d in rows)


def test_no_auth_header_is_401_on_inventory_route(store) -> None:
    inv = InventoryStore(store)
    app = create_app(
        ApprovalStore(store, AuditWriter(store)),
        inventory_store=inv,
        api_token=TOKEN,
    )
    client = TestClient(app)  # no default auth header
    assert client.get("/inventory").status_code == 401
    assert client.get("/inventory/a").status_code == 401


def test_create_app_without_inventory_store_has_no_routes(store) -> None:
    """Backward compat: create_app with no inventory_store wires no /inventory routes -> 404."""
    app = create_app(ApprovalStore(store, AuditWriter(store)), api_token=TOKEN)
    client = TestClient(app)
    client.headers.update(AUTH)
    assert client.get("/inventory").status_code == 404
