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
from sqlalchemy.orm.exc import StaleDataError
from sqlalchemy.pool import StaticPool

from agentos_contract import ActionType, AgentAction, Decision, Outcome, Reason, Usage
from agentos_controlplane.api import create_app
from agentos_controlplane.approvals import ApprovalStore
from agentos_controlplane.budget import BudgetLedger
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


@pytest.fixture
def budget(store) -> BudgetLedger:
    return BudgetLedger(store)


def _app(store, audit, cost, budget=None):
    inv = InventoryStore(store)
    inv.declare("a1", tools=["http_get"])
    return create_app(
        ApprovalStore(store, audit),
        inventory_store=inv,
        api_token=TOKEN,
        cost=cost,
        budget=budget,
    )


@pytest.fixture
def client(store, audit, cost, budget) -> TestClient:
    c = TestClient(_app(store, audit, cost, budget))
    c.headers.update(AUTH)
    return c


@pytest.fixture
def client_no_token(store, audit, cost, budget) -> TestClient:
    return TestClient(_app(store, audit, cost, budget))  # no default auth header


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


# ---------------------------------------------------------------- ECON-02: the budget routes


def test_setting_a_budget_makes_it_readable_with_the_spend_against_it(client) -> None:
    """One route sets the limit and one shows what has been spent against it — an operator deciding
    whether to raise a budget needs both numbers in the same place."""
    assert client.put("/economics/budgets/a1", json={"limit_micro_usd": 10_000_000}).status_code == 200

    rows = client.get("/economics/budgets").json()

    assert len(rows) == 1
    assert (rows[0]["agent_id"], rows[0]["limit_micro_usd"], rows[0]["period"]) == (
        "a1",
        10_000_000,
        "day",
    )


def test_the_read_route_reports_the_ratio_the_constitution_will_see(client, budget) -> None:
    """The number on the route and the number in the decision are the SAME reading — an operator who
    cannot see what the principle will compare against cannot explain a budget block.

    The $7.50 the `cost` fixture already COMMITTED for a1 is part of that reading. It used to read
    as $0.00 here, because the ledger only ever held what this process had noted: /economics/costs
    and /economics/budgets reported different money for the same agent with nothing to explain the
    gap, and the decision path — reading the same empty cache — allowed for the same reason.
    """
    client.put("/economics/budgets/a1", json={"limit_micro_usd": 4_000_000})
    budget.note_spend("a1", 3_000_000)

    row = client.get("/economics/budgets").json()[0]

    assert row["spend_usd"] == 10.5  # $7.50 committed to cost_record + $3.00 noted in this process
    assert row["budget_used_ratio"] == pytest.approx(2.625)
    assert row["budget_used_ratio"] == budget.posture_for("a1").budget_used_ratio


def test_a_budget_write_that_lost_a_race_is_a_conflict_and_not_a_500(
    client, budget, monkeypatch
) -> None:
    """`AgentBudget.version` is a `version_id_col`, so a raise that lost a race raises rather than
    silently vanishing. The route has to turn that into the answer an operator can act on: 409 says
    "re-read and retry", a 500 says "the control plane is broken" and invites neither."""

    def _lost_the_race(*args, **kwargs):
        raise StaleDataError("UPDATE expected to update 1 row(s); 0 were matched.")

    monkeypatch.setattr(budget, "set_budget", _lost_the_race)

    resp = client.put("/economics/budgets/a1", json={"limit_micro_usd": 9_000_000})

    assert resp.status_code == 409
    assert "retry" in resp.json()["detail"]


def test_raising_a_budget_bumps_the_version(client) -> None:
    """Raising a limit is how an over-budget agent is unblocked. That is a privileged act, so it
    leaves a trace an incident review can read."""
    client.put("/economics/budgets/a1", json={"limit_micro_usd": 1_000_000})
    client.put("/economics/budgets/a1", json={"limit_micro_usd": 8_000_000})

    assert client.get("/economics/budgets").json()[0]["version"] == 2


def test_a_malformed_or_impossible_budget_is_refused(client) -> None:
    """A negative limit or an unknown period is a typo, and a typo must not become a silently
    disabled spend control."""
    assert client.put("/economics/budgets/a1", json={}).status_code == 422
    assert client.put("/economics/budgets/a1", json={"limit_micro_usd": "lots"}).status_code == 422
    assert client.put("/economics/budgets/a1", json={"limit_micro_usd": -1}).status_code == 422
    assert (
        client.put("/economics/budgets/a1", json={"limit_micro_usd": 1, "period": "fortnight"}).status_code
        == 422
    )
    assert client.get("/economics/budgets").json() == []


def test_the_budget_routes_are_gated(client_no_token) -> None:
    """Raising a spending limit from an unauthenticated request is a governance bypass, not a
    convenience: an agent that can raise its own budget has no budget."""
    assert client_no_token.get("/economics/budgets").status_code == 401
    assert (
        client_no_token.put("/economics/budgets/a1", json={"limit_micro_usd": 1}).status_code == 401
    )


def test_an_app_built_without_a_ledger_404s(client_no_cost) -> None:
    assert client_no_cost.get("/economics/budgets").status_code == 404
    assert client_no_cost.put("/economics/budgets/a1", json={"limit_micro_usd": 1}).status_code == 404


def test_the_roll_up_read_is_bounded_and_pageable(client) -> None:
    """The 11b review left this open: the roll-up grouped over the WHOLE cost table on a gated read
    route, so its cost grew with every governed action the fleet ever took. It is capped now, and
    pageable so the cap cannot make it silently disagree with the per-agent detail."""
    first = client.get("/economics/costs", params={"limit": 1}).json()
    second = client.get("/economics/costs", params={"limit": 1, "offset": 1}).json()

    assert [r["agent_id"] for r in first] == ["a1"]
    assert [r["agent_id"] for r in second] == ["a2"]
