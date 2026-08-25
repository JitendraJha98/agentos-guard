"""AUD-09 / OBS-05 — the gated evidence-graph and conversation-tracing routes.

The gate is load-bearing rather than merely consistent: a causal chain says which agent set which
other agent in motion, and a conversation reconstruction is the most revealing read in the product.
An app built without an EvidenceGraph answers 404 rather than opening an ungated one.

The property this slice exists to protect has to survive the hop to JSON, because the wire is where
an investigator reads it: `lineage` must cross it. A route that returned only `records` would strip
exactly the field separating "here is what happened" from "here is what the fleet said happened".
"""

from __future__ import annotations

import asyncio
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from agentos_contract import ActionContext, ActionType, AgentAction, Decision, Outcome, Reason
from agentos_controlplane.api import create_app
from agentos_controlplane.approvals import ApprovalStore
from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.forensics import EvidenceGraph
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
def audit(store) -> AuditWriter:
    return AuditWriter(store)


def _act(audit, agent_id="a1", *, parent=None, conversation=None, action_type=ActionType.tool_call):
    payload = {
        ActionType.tool_call: {"url": "https://api.example.com/x", "content": ""},
        ActionType.delegation: {"to_agent": "b", "task": "t"},
    }[action_type]
    action = AgentAction(
        agent_id=agent_id,
        type=action_type,
        target="http_get",
        payload=payload,
        context=ActionContext(parent_action_id=parent, conversation_id=conversation),
    )
    asyncio.run(
        audit.append(
            action,
            Decision(
                action_id=action.id,
                outcome=Outcome.allow,
                reasons=[Reason(stage="policy", code="no_match_posture", detail="ok")],
            ),
        )
    )
    return action


def _app(store, audit, forensics):
    inv = InventoryStore(store)
    inv.declare("a1", tools=["http_get"])
    return create_app(
        ApprovalStore(store, audit),
        inventory_store=inv,
        api_token=TOKEN,
        forensics=forensics,
    )


@pytest.fixture
def seeded(store, audit):
    """A -> B -> C, plus a conversation spanning a tool call and a delegation."""
    a = _act(audit, "a1")
    b = _act(audit, "a2", parent=a.id)
    c = _act(audit, "a3", parent=b.id)
    _act(audit, "a1", conversation="conv-1")
    _act(audit, "a2", conversation="conv-1", action_type=ActionType.delegation)
    return c


@pytest.fixture
def client(store, audit, seeded) -> TestClient:
    c = TestClient(_app(store, audit, EvidenceGraph(store)))
    c.headers.update(AUTH)
    return c


@pytest.fixture
def client_no_token(store, audit, seeded) -> TestClient:
    return TestClient(_app(store, audit, EvidenceGraph(store)))


@pytest.fixture
def client_no_forensics(store, audit, seeded) -> TestClient:
    c = TestClient(_app(store, audit, None))
    c.headers.update(AUTH)
    return c


def test_the_chain_route_returns_the_causal_path(client, seeded) -> None:
    body = client.get(f"/forensics/chain/{seeded.id}").json()

    assert [r["agent_id"] for r in body["records"]] == ["a3", "a2", "a1"]
    assert body["truncated"] is False


def test_the_route_does_not_strip_the_lineage_qualifier(client, seeded) -> None:
    """The field an investigator most needs is the one a serializer is most likely to drop: it is
    prose in a payload of ids. Without it the response reads as proven causation, and blame gets
    attributed on the strength of a field the accused agent's own caller supplied."""
    body = client.get(f"/forensics/chain/{seeded.id}").json()

    assert "CLAIMED, not proven" in body["lineage"]
    assert "TRST-04" in body["lineage"]


def test_the_conversation_route_spans_tools_and_delegations(client) -> None:
    body = client.get("/forensics/conversation/conv-1").json()

    assert {r["action_type"] for r in body["records"]} == {"tool_call", "delegation"}
    assert "lineage" in body


def test_an_unknown_id_is_an_empty_chain_not_a_404(client) -> None:
    """During an incident "nothing matched" is an answer; a 404 reads as "this route is wrong" and
    sends the responder debugging the tool instead of the incident."""
    chain = client.get(f"/forensics/chain/{uuid4()}")
    convo = client.get("/forensics/conversation/no-such-conversation")

    assert chain.status_code == 200 and chain.json()["records"] == []
    assert convo.status_code == 200 and convo.json()["records"] == []


def test_the_routes_are_gated(client_no_token, seeded) -> None:
    assert client_no_token.get(f"/forensics/chain/{seeded.id}").status_code == 401
    assert client_no_token.get("/forensics/conversation/conv-1").status_code == 401


def test_an_app_without_the_graph_404s_and_keeps_the_other_routes(client_no_forensics, seeded) -> None:
    assert client_no_forensics.get(f"/forensics/chain/{seeded.id}").status_code == 404
    assert client_no_forensics.get("/inventory").status_code == 200
