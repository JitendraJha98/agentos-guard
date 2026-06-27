"""Gated self-registration API (SDK-02 server side).

POST /agents/{agent_id}/register rides the shared-token gate (no/wrong Bearer -> 401), persists the
Agent via the Registry, returns the per-agent EdDSA identity token, and — with a manifest — declares
the agent's components into the inventory (DISC-01). trust_score is bounded (Pydantic -> 422).
create_app without a registry wires no /agents routes (POST -> 404), keeping existing callers working.
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
from agentos_controlplane.registry import Registry
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
    registry = Registry(store, inventory=inv)
    app = create_app(
        ApprovalStore(store, AuditWriter(store)),
        inventory_store=inv,
        registry=registry,
        api_token=TOKEN,
    )
    c = TestClient(app)
    c.headers.update(AUTH)
    return c


def test_register_returns_token_and_persists_agent(client, store) -> None:
    r = client.post("/agents/a/register", json={"manifest": {"tools": ["http_get"]}})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["agent_id"] == "a"
    assert body["token"]  # non-empty identity token
    # the agent is now registered (a fresh Registry over the same store sees it)
    assert Registry(store).is_registered("a") is True


def test_register_declares_manifest_into_inventory(client) -> None:
    client.post("/agents/a/register", json={"manifest": {"tools": ["http_get"], "memories": ["m1"]}})
    rows = client.get("/inventory/a").json()
    assert {(d["kind"], d["name"], d["source"]) for d in rows} == {
        ("tool", "http_get", "declared"),
        ("memory", "m1", "declared"),
    }


def test_register_accepts_trust_score(client, store) -> None:
    r = client.post("/agents/a/register", json={"trust_score": 0.9})
    assert r.status_code == 200, r.text
    assert Registry(store).load_trust("a") == 0.9


def test_register_trust_score_out_of_bounds_is_422(client) -> None:
    assert client.post("/agents/a/register", json={"trust_score": 2.0}).status_code == 422


def test_register_without_manifest_ok(client, store) -> None:
    r = client.post("/agents/a/register", json={})
    assert r.status_code == 200, r.text
    assert Registry(store).is_registered("a") is True


def test_no_auth_header_is_401_on_register(store) -> None:
    inv = InventoryStore(store)
    app = create_app(
        ApprovalStore(store, AuditWriter(store)),
        inventory_store=inv,
        registry=Registry(store, inventory=inv),
        api_token=TOKEN,
    )
    client = TestClient(app)  # no default auth header
    assert client.post("/agents/a/register", json={}).status_code == 401


def test_create_app_without_registry_has_no_route(store) -> None:
    """Backward compat: create_app with no registry wires no /agents routes -> 404."""
    app = create_app(ApprovalStore(store, AuditWriter(store)), api_token=TOKEN)
    client = TestClient(app)
    client.headers.update(AUTH)
    assert client.post("/agents/a/register", json={}).status_code == 404
