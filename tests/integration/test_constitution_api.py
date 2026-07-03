"""Compile-on-write Constitution / Policy API (API-02).

POST /constitutions validates (Pydantic) + compiles + persists the Constitution version AND its
derived Policy in ONE transaction (malformed -> 422 with NOTHING written); apply is idempotent on
the content-hash version. The compiled Policy (Rego text + reviewable YAML + metadata) is retrievable
via /policies/latest and /policies/{version}. Routes ride the existing auth-gated resource router
(no Bearer -> 401).
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
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
_FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "test_constitution.yaml"


@pytest.fixture
def src() -> dict:
    return yaml.safe_load(_FIXTURE.read_text(encoding="utf-8"))


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


def test_apply_compiles_and_policy_retrievable(client, src) -> None:
    r = client.post("/constitutions", json={"name": "t", "source": src})
    assert r.status_code == 200, r.text
    body = r.json()
    version = body["constitution"]["version"]
    assert body["policy_version"] == version

    # the compiled policy (Rego text) is retrievable for the engine
    latest = client.get("/policies/latest")
    assert latest.status_code == 200
    assert "package agentos.constitution" in latest.json()["rego"]
    assert latest.json()["constitution_version"] == version

    # version-keyed reads
    assert client.get(f"/constitutions/{version}").status_code == 200
    assert client.get(f"/policies/{version}").status_code == 200
    assert client.get("/policies/unknown").status_code == 404
    assert client.get("/constitutions/unknown").status_code == 404


def test_malformed_constitution_is_422_writes_nothing(client, src) -> None:
    bad = {**src, "bogus_top_level": 1}  # extra=forbid -> compile-on-write rejects it
    r = client.post("/constitutions", json={"name": "t", "source": bad})
    assert r.status_code == 422

    # fail-closed: nothing persisted
    assert client.get("/constitutions").json() == []
    assert client.get("/policies/latest").status_code == 404


def test_apply_is_idempotent(client, src) -> None:
    r1 = client.post("/constitutions", json={"name": "t", "source": src})
    r2 = client.post("/constitutions", json={"name": "t", "source": src})
    assert r1.status_code == 200 and r2.status_code == 200
    assert r1.json()["policy_version"] == r2.json()["policy_version"]
    assert len(client.get("/constitutions").json()) == 1  # no duplicate row


def test_no_auth_header_is_401(store, src) -> None:
    app = create_app(
        ApprovalStore(store, AuditWriter(store)),
        resource_store=ResourceStore(store),
        api_token=TOKEN,
    )
    client = TestClient(app)  # no default auth header
    assert client.post("/constitutions", json={"name": "t", "source": src}).status_code == 401
    assert client.get("/constitutions").status_code == 401
    assert client.get("/policies/latest").status_code == 401
