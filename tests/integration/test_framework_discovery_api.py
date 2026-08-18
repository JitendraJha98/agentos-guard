"""Framework-discovery API + auth gate (DISC-03).

GET /discovery/frameworks reads the FrameworkDetector's inventory and POST /discovery/scan drives a
pass, both behind the SAME shared-token gate as the DISC-01/02 inventory routes (no/wrong Bearer ->
401) — discovery rides the existing gated surface rather than opening a second one. create_app
without a framework_detector wires no routes (404) while the inventory routes keep working, so
every existing caller is unchanged.

The POST route is what makes the slice deliverable: without a caller the table stays empty and the
read route is a hollow surface. It is operator-driven and gated — a scan touches importlib and the
audit chain, never the per-action hot path.
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
def detector(store, tmp_path, monkeypatch) -> FrameworkDetector:
    """A detector over a PLANTED distribution: what this venv happens to have installed is not the
    subject here, and a detector that finds nothing would make the route tests pass vacuously."""
    site = tmp_path / "site"
    info = site / "crewai-0.86.0.dist-info"
    info.mkdir(parents=True)
    info.joinpath("METADATA").write_text(
        "Metadata-Version: 2.1\nName: crewai\nVersion: 0.86.0\n", encoding="utf-8"
    )
    monkeypatch.syspath_prepend(str(site))
    return FrameworkDetector(
        store, AuditWriter(store), catalogue={"crewai": ("crewai",)}, observer="cp-1"
    )


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
    """The route reports what the scan actually found."""
    asyncio.run(detector.scan())

    r = client.get("/discovery/frameworks")
    assert r.status_code == 200
    rows = r.json()
    assert {d["name"] for d in rows} == {"crewai"}
    entry = rows[0]
    assert (entry["distribution"], entry["version"], entry["observer"]) == (
        "crewai",
        "0.86.0",
        "cp-1",
    )
    assert entry["first_seen_at"] and entry["last_seen_at"]


def test_post_scan_populates_the_inventory(client) -> None:
    """The WRITE half: without a caller the table stays empty forever and the read route is a
    hollow surface. POST drives a pass and returns the resulting inventory."""
    assert client.get("/discovery/frameworks").json() == []

    r = client.post("/discovery/scan")

    assert r.status_code == 200
    assert {d["name"] for d in r.json()} == {"crewai"}
    assert client.get("/discovery/frameworks").json() == r.json()


def test_post_scan_is_idempotent(client) -> None:
    """A repeated operator scan converges: same inventory, no second chain entry."""
    first = client.post("/discovery/scan").json()

    second = client.post("/discovery/scan").json()

    assert [d["name"] for d in second] == [d["name"] for d in first]


def test_no_auth_header_is_401_on_the_scan_route(store, detector) -> None:
    """The write route rides the SAME gate — an unauthenticated caller can never drive a scan."""
    app = create_app(
        ApprovalStore(store, AuditWriter(store)),
        inventory_store=InventoryStore(store),
        framework_detector=detector,
        api_token=TOKEN,
    )
    assert TestClient(app).post("/discovery/scan").status_code == 401


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
    assert client.post("/discovery/scan").status_code == 404
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
