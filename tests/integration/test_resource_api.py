"""Declarative resource API + auth gate (API-01).

PUT validates (Pydantic bounds -> 422) and versions (optimistic-concurrency -> 409); GET reads
(missing -> 404). The shared-token gate enforces `Authorization: Bearer` on the resource router
AND the retrofitted approval router (no/wrong token -> 401).
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from agentos_controlplane.api import create_app
from agentos_controlplane.approvals import ApprovalStore
from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.resources import ResourceStore
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
    app = create_app(
        ApprovalStore(store, AuditWriter(store)),
        resource_store=ResourceStore(store),
        api_token=TOKEN,
    )
    c = TestClient(app)
    c.headers.update(AUTH)
    return c


# ---- TrustProfile ----
def test_trust_profile_create_update_conflict(client) -> None:
    r = client.put("/trust-profiles/a", json={"trust_score": 0.7})
    assert r.status_code == 200 and r.json()["version"] == 1 and r.json()["trust_score"] == 0.7

    r = client.put("/trust-profiles/a", json={"trust_score": 0.8, "version": 1})
    assert r.status_code == 200 and r.json()["version"] == 2

    # stale version -> 409
    r = client.put("/trust-profiles/a", json={"trust_score": 0.9, "version": 1})
    assert r.status_code == 409


def test_trust_profile_get_and_missing(client) -> None:
    client.put("/trust-profiles/a", json={"trust_score": 0.5})
    assert client.get("/trust-profiles/a").status_code == 200
    assert client.get("/trust-profiles/missing").status_code == 404
    listed = client.get("/trust-profiles")
    assert listed.status_code == 200 and listed.json()[0]["agent_id"] == "a"


def test_trust_score_bounds_422(client) -> None:
    assert client.put("/trust-profiles/a", json={"trust_score": 2.0}).status_code == 422
    assert client.put("/trust-profiles/a", json={"trust_score": -0.1}).status_code == 422


# ---- Abom ----
def test_abom_create_update_conflict(client) -> None:
    r = client.put("/aboms/a", json={"components": {"tools": ["http_get"]}})
    assert r.status_code == 200 and r.json()["version"] == 1

    r = client.put("/aboms/a", json={"components": {"tools": ["drop_table"]}, "version": 1})
    assert r.status_code == 200 and r.json()["version"] == 2

    r = client.put("/aboms/a", json={"components": {}, "version": 1})
    assert r.status_code == 409


def test_abom_get_and_missing(client) -> None:
    client.put("/aboms/a", json={"components": {"models": ["m1"]}})
    assert client.get("/aboms/a").status_code == 200
    assert client.get("/aboms/missing").status_code == 404


# ---- Auth gate on ALL routers ----
def test_no_auth_header_is_401_on_resource_route(store) -> None:
    app = create_app(
        ApprovalStore(store, AuditWriter(store)),
        resource_store=ResourceStore(store),
        api_token=TOKEN,
    )
    client = TestClient(app)  # no default auth header
    assert client.get("/trust-profiles").status_code == 401
    assert client.put("/trust-profiles/a", json={"trust_score": 0.5}).status_code == 401


def test_no_auth_header_is_401_on_approvals_route(store) -> None:
    app = create_app(
        ApprovalStore(store, AuditWriter(store)),
        resource_store=ResourceStore(store),
        api_token=TOKEN,
    )
    client = TestClient(app)  # no default auth header
    assert client.get("/approvals").status_code == 401


def test_wrong_token_is_401(client) -> None:
    bad = {"Authorization": "Bearer nope"}
    assert client.get("/trust-profiles", headers=bad).status_code == 401
    assert client.get("/approvals", headers=bad).status_code == 401
