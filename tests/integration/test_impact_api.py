"""ABOM-03 — the gated vulnerability-impact route.

The gate is load-bearing rather than merely consistent: this answer is a list of exactly where a
fleet is exploitable, which is the single most useful document an attacker could be handed.

And the counts that qualify the answer have to survive the hop to JSON, because the wire is where an
incident responder reads them.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from agentos_controlplane.api import create_app
from agentos_controlplane.approvals import ApprovalStore
from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.impact import ImpactAnalyzer
from agentos_controlplane.inventory import InventoryStore
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
def resources(store) -> ResourceStore:
    return ResourceStore(store)


def _app(store, resources, *, wired=True):
    audit = AuditWriter(store)
    inv = InventoryStore(store)
    inv.declare("a1", tools=["http_get"])
    return create_app(
        ApprovalStore(store, audit),
        inventory_store=inv,
        api_token=TOKEN,
        impact=ImpactAnalyzer(resources, store) if wired else None,
    )


@pytest.fixture
def seeded(resources):
    resources.declare_abom("a1", declaration={"tools": ["backdoored"]}, expected_version=None)
    resources.declare_abom("a2", declaration={"tools": ["fine"]}, expected_version=None)
    return resources


@pytest.fixture
def client(store, resources, seeded) -> TestClient:
    c = TestClient(_app(store, resources))
    c.headers.update(AUTH)
    return c


def test_the_route_answers_who_uses_a_component(client) -> None:
    body = client.get("/impact?name=backdoored").json()

    assert body["affected_agents"] == ["a1"]
    assert body["matches"][0]["matched_on"] == "name"


def test_the_qualifying_counts_survive_the_wire(client) -> None:
    """A responder reading "1 affected" needs to know it came from searching the whole fleet. These
    three counts are what separate a blast radius from a sample."""
    body = client.get("/impact?name=backdoored").json()

    for key in ("agents_searched", "agents_total", "agents_without_components", "truncated"):
        assert key in body, f"{key} must reach the wire"


def test_a_query_with_no_criteria_is_422_not_the_whole_fleet(client) -> None:
    """Answering it would let a typo read as "everything is compromised"."""
    assert client.get("/impact").status_code == 422


def test_an_unaffected_query_is_an_empty_list_not_a_404(client) -> None:
    """During an incident "nobody is affected" is an answer; a 404 reads as "the tool is broken"."""
    resp = client.get("/impact?digest=" + "de" * 32)

    assert resp.status_code == 200 and resp.json()["affected_agents"] == []


def test_the_route_is_gated(store, resources, seeded) -> None:
    anon = TestClient(_app(store, resources))

    assert anon.get("/impact?name=backdoored").status_code == 401


def test_an_app_without_impact_404s_and_keeps_the_other_routes(store, resources, seeded) -> None:
    c = TestClient(_app(store, resources, wired=False))
    c.headers.update(AUTH)

    assert c.get("/impact?name=x").status_code == 404
    assert c.get("/inventory").status_code == 200
