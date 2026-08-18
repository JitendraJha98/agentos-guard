"""ECON-01 — the gated cost read API: what did this agent cost, and on which actions?

The routes ride the SAME shared-token gate as the DISC-01..06 inventory surface and the AUD-06
disclosure surface. What an agent costs is commercial information — spend per agent maps directly
onto which workloads a deployment is running and how heavily — so it is never a public endpoint,
and an app built without a recorder answers 404 rather than opening an ungated one.
"""

from __future__ import annotations

import asyncio

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from agentos_contract import ActionType, AgentAction, Decision, Outcome, Reason, Usage
from agentos_controlplane.api import create_app
from agentos_controlplane.approvals import ApprovalStore
from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.economics import CostRecorder, PriceBook
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
    """ONE writer over the store — a second instance caches a stale chain head."""
    return AuditWriter(store)


def _action(agent: str, model: str) -> AgentAction:
    return AgentAction(
        agent_id=agent, type=ActionType.model_invocation, target="chat", payload={"model": model}
    )


@pytest.fixture
def cost(store, audit) -> CostRecorder:
    """Two priced actions for a1 and one UNPRICED one, so the roll-up has something to be honest
    about rather than a total that happens to be complete."""
    rec = CostRecorder(store, audit, PriceBook({"gpt-4o": (2.5, 10.0)}, version="2026-08"))
    for agent, model, usage in (
        ("a1", "gpt-4o", Usage(1000, 500, "gpt-4o")),
        ("a1", "mystery", Usage(10, 10, "mystery")),
        ("a2", "gpt-4o", Usage(100, 100, "gpt-4o")),
    ):
        action = _action(agent, model)
        decision = Decision(
            action_id=action.id, outcome=Outcome.allow, reasons=[Reason(stage="policy", code="ok")]
        )
        asyncio.run(rec.record(action, decision, usage))
    return rec


def _app(store, audit, cost):
    inv = InventoryStore(store)
    inv.declare("a1", tools=["http_get"])
    return create_app(
        ApprovalStore(store, audit), inventory_store=inv, api_token=TOKEN, cost=cost
    )


@pytest.fixture
def client(store, audit, cost) -> TestClient:
    c = TestClient(_app(store, audit, cost))
    c.headers.update(AUTH)
    return c


@pytest.fixture
def client_no_token(store, audit, cost) -> TestClient:
    return TestClient(_app(store, audit, cost))  # no default auth header


@pytest.fixture
def client_no_cost(store, audit) -> TestClient:
    c = TestClient(_app(store, audit, None))
    c.headers.update(AUTH)
    return c


def test_the_roll_up_reports_spend_per_agent(client) -> None:
    rows = {r["agent_id"]: r for r in client.get("/economics/costs").json()}

    assert rows["a1"]["input_tokens"] == 1010
    assert rows["a1"]["cost_micro_usd"] == 7_500_000
    assert rows["a2"]["cost_micro_usd"] == 1_250_000


def test_the_roll_up_shows_how_much_of_the_bill_is_actually_priced(client) -> None:
    """A dollar total covering 1 of 2 actions is a number an operator reads as the whole bill unless
    the response says otherwise — so it says otherwise."""
    a1 = {r["agent_id"]: r for r in client.get("/economics/costs").json()}["a1"]

    assert (a1["actions"], a1["priced_actions"], a1["unpriced_actions"]) == (2, 1, 1)


def test_the_per_agent_route_lists_the_actions_behind_the_total(client) -> None:
    """ECON-01 asks for cost per agent AND per action; this is the per-action half."""
    rows = client.get("/economics/costs/a1").json()

    assert len(rows) == 2
    assert {r["model"] for r in rows} == {"gpt-4o", "mystery"}
    unpriced = next(r for r in rows if r["model"] == "mystery")
    assert unpriced["cost_micro_usd"] is None and unpriced["price_book_version"] is None
    assert unpriced["input_tokens"] == 10, "an unpriced action still reports the tokens it used"


def test_an_agent_with_no_recorded_cost_is_an_empty_list_not_an_error(client) -> None:
    assert client.get("/economics/costs/never-ran").json() == []


def test_the_per_agent_route_can_be_paged_so_the_two_routes_cannot_disagree(client) -> None:
    """The detail read is capped — the table grows with every governed action. Without a way past
    the cap an operator reconciling a busy agent against an invoice silently reads less money here
    than the roll-up reports, with nothing in the response to explain the difference."""
    first = client.get("/economics/costs/a1", params={"limit": 1}).json()
    second = client.get("/economics/costs/a1", params={"limit": 1, "offset": 1}).json()

    assert len(first) == len(second) == 1
    assert {r["action_id"] for r in first + second} == {
        r["action_id"] for r in client.get("/economics/costs/a1").json()
    }


def test_the_routes_are_gated(client_no_token) -> None:
    assert client_no_token.get("/economics/costs").status_code == 401
    assert client_no_token.get("/economics/costs/a1").status_code == 401


def test_an_app_built_without_a_recorder_404s_and_keeps_the_other_routes(client_no_cost) -> None:
    assert client_no_cost.get("/economics/costs").status_code == 404
    assert client_no_cost.get("/economics/costs/a1").status_code == 404
    assert client_no_cost.get("/inventory").status_code == 200
