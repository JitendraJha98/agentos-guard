"""Framework-discovery read API + auth gate (DISC-03).

GET /discovery/frameworks reads the FrameworkDetector's inventory behind the SAME shared-token gate
as the DISC-01/02 inventory routes (no/wrong Bearer -> 401) — discovery rides the existing gated
surface rather than opening a second one. create_app without a framework_detector wires no route
(GET /discovery/frameworks -> 404) while the inventory routes keep working, so every existing
caller is unchanged.
"""

from __future__ import annotations

import asyncio

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from agentos_controlplane.api import create_app
from agentos_controlplane.approvals import ApprovalStore
from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.framework_discovery import FrameworkDetector
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
def detector(store) -> FrameworkDetector:
    return FrameworkDetector(store, AuditWriter(store))


@pytest.fixture
def client(store, detector) -> TestClient:
    inv = InventoryStore(store)
    inv.declare("a", tools=["http_get"])
    app = create_app(
        ApprovalStore(store, AuditWriter(store)),
        inventory_store=inv,
        framework_detector=detector,
        api_token=TOKEN,
    )
    c = TestClient(app)
    c.headers.update(AUTH)
    return c


def test_list_frameworks_200_after_scan(client, detector) -> None:
    """The route reports what the scan actually found — langchain is a real dependency here."""
    asyncio.run(detector.scan())

    r = client.get("/discovery/frameworks")
    assert r.status_code == 200
    rows = r.json()
    names = {d["name"] for d in rows}
    assert "langchain" in names
    assert "langgraph" in names
    entry = next(d for d in rows if d["name"] == "langchain")
    assert entry["distribution"] == "langchain"
    assert entry["version"] and entry["first_seen_at"] and entry["last_seen_at"]


def test_list_frameworks_before_any_scan_is_empty(client) -> None:
    """Nothing observed yet is an empty inventory, not an invented one."""
    r = client.get("/discovery/frameworks")
    assert r.status_code == 200
    assert r.json() == []


def test_no_auth_header_is_401_on_discovery_route(store, detector) -> None:
    app = create_app(
        ApprovalStore(store, AuditWriter(store)),
        inventory_store=InventoryStore(store),
        framework_detector=detector,
        api_token=TOKEN,
    )
    client = TestClient(app)  # no default auth header
    assert client.get("/discovery/frameworks").status_code == 401


def test_create_app_without_detector_has_no_discovery_route(store) -> None:
    """Backward compat: no framework_detector -> 404, and the inventory routes still work."""
    inv = InventoryStore(store)
    inv.declare("a", tools=["http_get"])
    app = create_app(
        ApprovalStore(store, AuditWriter(store)),
        inventory_store=inv,
        api_token=TOKEN,
    )
    client = TestClient(app)
    client.headers.update(AUTH)
    assert client.get("/discovery/frameworks").status_code == 404
    assert client.get("/inventory").status_code == 200


def test_create_app_without_inventory_store_wires_no_discovery_route(store, detector) -> None:
    """Discovery rides the INVENTORY router: absent an inventory_store there is no gated surface
    for it, so the route is simply not there (404) — never an ungated one."""
    app = create_app(
        ApprovalStore(store, AuditWriter(store)),
        framework_detector=detector,
        api_token=TOKEN,
    )
    client = TestClient(app)
    client.headers.update(AUTH)
    assert client.get("/discovery/frameworks").status_code == 404
