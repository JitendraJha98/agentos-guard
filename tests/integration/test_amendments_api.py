"""POL-10 — the gated amendment and constitution-history API.

Two properties have to survive the hop to HTTP. Proposing is AGENT-usable (that is the half of POL-10
an agent is meant to do) while ratifying is a separate route, because a system that could ratify its
own amendments could rewrite the rules governing it. And a proposal is INERT: the propose route must
change no constitution.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.pool import StaticPool

from agentos_controlplane.amendments import AmendmentStore
from agentos_controlplane.api import create_app
from agentos_controlplane.approvals import ApprovalStore
from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.inventory import InventoryStore
from agentos_controlplane.resources import ResourceStore
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import ConstitutionResource

TOKEN = "test-token"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


def _constitution(host: str = "api.example.com") -> dict:
    return {
        "schema_version": 1,
        "name": "test",
        "lists": {"egress_allowlist": [host]},
        "principles": [
            {
                "id": "1.1",
                "title": "Egress allowlist",
                "statement": "An agent may only call allowlisted hosts.",
                "applies_to": ["tool_call"],
                "effect": "deny",
                "when": {"field": "egress.host", "op": "not_in", "list_ref": "egress_allowlist"},
            }
        ],
    }


@pytest.fixture
def store():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    create_all(engine)
    return create_session_factory(engine)


def _app(store, *, wired=True):
    audit = AuditWriter(store)
    inv = InventoryStore(store)
    inv.declare("a1", tools=["http_get"])
    amendments = (
        AmendmentStore(store, audit, ResourceStore(store)) if wired else None
    )
    return create_app(
        ApprovalStore(store, audit),
        inventory_store=inv,
        api_token=TOKEN,
        amendments=amendments,
    )


@pytest.fixture
def client(store) -> TestClient:
    c = TestClient(_app(store))
    c.headers.update(AUTH)
    return c


def test_an_agent_can_propose_over_http(client) -> None:
    """Proposing is the AGENT-usable half of POL-10."""
    resp = client.post(
        "/amendments",
        json={"title": "widen egress", "rationale": "need it", "proposed_by": "agent-1",
              "source": _constitution("b.test")},
    )

    assert resp.status_code == 200 and resp.json()["status"] == "proposed"
    assert client.get("/amendments?status=proposed").json()[0]["proposed_by"] == "agent-1"


def test_proposing_changes_no_constitution(client, store) -> None:
    """THE property, over HTTP: a proposal is inert. If the propose route applied the constitution,
    an agent could rewrite the rules governing it with one request."""
    client.post(
        "/amendments",
        json={"title": "permissive", "rationale": "r", "proposed_by": "agent-1",
              "source": _constitution("evil.test")},
    )

    with store() as s:
        assert s.scalars(select(ConstitutionResource)).all() == []


def test_ratifying_is_a_separate_route_and_produces_a_version(client) -> None:
    aid = client.post(
        "/amendments",
        json={"title": "v2", "rationale": "r", "proposed_by": "agent-1",
              "source": _constitution("c.test")},
    ).json()["id"]

    resp = client.post(f"/amendments/{aid}/ratify", json={"ratified_by": "operator-jane"})

    assert resp.status_code == 200
    assert resp.json()["constitution_version"]


def test_ratifying_without_a_ratifier_is_422(client) -> None:
    """"human-ratified" is the entire claim this transition makes."""
    aid = client.post(
        "/amendments",
        json={"title": "t", "rationale": "r", "proposed_by": "agent-1",
              "source": _constitution("d.test")},
    ).json()["id"]

    assert client.post(f"/amendments/{aid}/ratify", json={"ratified_by": ""}).status_code == 422


def test_ratifying_twice_is_409(client) -> None:
    aid = client.post(
        "/amendments",
        json={"title": "t", "rationale": "r", "proposed_by": "agent-1",
              "source": _constitution("e.test")},
    ).json()["id"]
    client.post(f"/amendments/{aid}/ratify", json={"ratified_by": "operator-jane"})

    second = client.post(f"/amendments/{aid}/ratify", json={"ratified_by": "operator-bob"})

    assert second.status_code == 409


def test_an_uncompilable_proposal_is_422_not_500(client) -> None:
    """The proposer gets a usable error rather than a traceback."""
    resp = client.post(
        "/amendments",
        json={"title": "bad", "rationale": "r", "proposed_by": "agent-1",
              "source": {"nonsense": True}},
    )

    assert resp.status_code == 422


def test_an_unknown_amendment_is_404(client) -> None:
    from uuid import uuid4

    resp = client.post(f"/amendments/{uuid4()}/ratify", json={"ratified_by": "operator-jane"})

    assert resp.status_code == 404


def test_rejecting_leaves_the_constitution_untouched(client, store) -> None:
    aid = client.post(
        "/amendments",
        json={"title": "no", "rationale": "r", "proposed_by": "agent-1",
              "source": _constitution("f.test")},
    ).json()["id"]

    resp = client.post(
        f"/amendments/{aid}/resolve",
        json={"status": "rejected", "resolved_by": "operator-jane"},
    )

    assert resp.status_code == 200
    with store() as s:
        assert s.scalars(select(ConstitutionResource)).all() == []


def test_the_resolve_route_cannot_be_used_to_ratify(client) -> None:
    """`ratify` is the only path to RATIFIED, and the schema refuses the alternative rather than
    relying on the store to catch it."""
    aid = client.post(
        "/amendments",
        json={"title": "t", "rationale": "r", "proposed_by": "agent-1",
              "source": _constitution("g.test")},
    ).json()["id"]

    resp = client.post(
        f"/amendments/{aid}/resolve",
        json={"status": "ratified", "resolved_by": "operator-jane"},
    )

    assert resp.status_code == 422


def test_history_names_the_authority_behind_a_version(client) -> None:
    aid = client.post(
        "/amendments",
        json={"title": "v2", "rationale": "r", "proposed_by": "agent-1",
              "source": _constitution("h.test")},
    ).json()["id"]
    version = client.post(
        f"/amendments/{aid}/ratify", json={"ratified_by": "operator-jane"}
    ).json()["constitution_version"]

    entry = next(e for e in client.get("/constitution/history").json() if e["version"] == version)

    assert entry["amendment"]["ratified_by"] == "operator-jane"
    assert entry["amendment"]["proposed_by"] == "agent-1"


def test_an_over_long_title_is_422_at_the_boundary(client) -> None:
    resp = client.post(
        "/amendments",
        json={"title": "x" * 300, "rationale": "r", "proposed_by": "agent-1",
              "source": _constitution()},
    )

    assert resp.status_code == 422


def test_the_routes_are_gated(store) -> None:
    """Amending the Constitution is the most privileged write in the product."""
    anon = TestClient(_app(store))

    assert anon.get("/amendments").status_code == 401
    assert anon.post("/amendments", json={}).status_code == 401
    assert anon.get("/constitution/history").status_code == 401


def test_an_app_without_amendments_404s_and_keeps_the_other_routes(store) -> None:
    c = TestClient(_app(store, wired=False))
    c.headers.update(AUTH)

    assert c.get("/amendments").status_code == 404
    assert c.get("/constitution/history").status_code == 404
    assert c.get("/inventory").status_code == 200
