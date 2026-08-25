"""OBS-04 — the gated agent-health read route.

It rides the SAME shared-token gate as the DISC-01..06 inventory surface, and the gate is
load-bearing rather than merely consistent: which agents are quiet, which are being blocked and
which are held by a breaker is a map of where a fleet is weakest right now. An app built without a
HealthStore answers 404 rather than opening an ungated one.

The two properties this slice exists to protect have to survive the hop to JSON, because the wire is
where a dashboard reads them: no verdict key crosses it, and three denials do not arrive as a 75%
error rate.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, update
from sqlalchemy.pool import StaticPool

from agentos_contract import ActionType, AgentAction, Decision, Outcome, Reason
from agentos_controlplane.api import create_app
from agentos_controlplane.approvals import ApprovalStore
from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.health import HealthStore
from agentos_controlplane.inventory import InventoryStore
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import AuditRecord

TOKEN = "test-token"
AUTH = {"Authorization": f"Bearer {TOKEN}"}

VERIFIED = [Reason(stage="identity", code="identity_verified", detail="ok")]


class _Breakers:
    """The `CircuitBreakerStore.list_open()` slice the health read uses."""

    def __init__(self, rows=()) -> None:
        self._rows = list(rows)

    def list_open(self) -> list[dict]:
        return list(self._rows)


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


def _act(audit: AuditWriter, agent_id: str, outcome: Outcome) -> None:
    action = AgentAction(
        agent_id=agent_id,
        type=ActionType.tool_call,
        target="http_get",
        payload={"url": "https://x.example.com/", "content": ""},
    )
    asyncio.run(
        audit.append(
            action,
            Decision(
                action_id=action.id,
                outcome=outcome,
                risk_score=0.0,
                trust_score=0.5,
                reasons=list(VERIFIED),
            ),
        )
    )


@pytest.fixture
def seeded(audit) -> None:
    """`a1` is a well-governed agent: one action ran, three were correctly blocked. That is the
    shape a naive error rate renders as 75% broken."""
    for outcome in (Outcome.allow, Outcome.deny, Outcome.deny, Outcome.deny):
        _act(audit, "a1", outcome)
    _act(audit, "a2", Outcome.allow)


def _app(store, audit, health=None):
    inv = InventoryStore(store)
    inv.declare("a1", tools=["http_get"])
    return create_app(
        ApprovalStore(store, audit),
        inventory_store=inv,
        api_token=TOKEN,
        health=health,
    )


@pytest.fixture
def client(store, audit, seeded) -> TestClient:
    breakers = _Breakers(
        [{"scope": "agent", "agent_id": "a2", "target": "", "state": "open", "opened_at": 1.0}]
    )
    return TestClient(_app(store, audit, HealthStore(store, breakers=breakers)))


def test_the_route_reports_liveness_error_counts_and_breaker_state(client) -> None:
    """OBS-04 names three things, and all three have to reach the operator."""
    rows = {r["agent_id"]: r for r in client.get("/health/agents", headers=AUTH).json()}

    assert rows["a1"]["last_seen_at"] is not None
    assert rows["a1"]["executed"] == 1 and rows["a1"]["blocked"] == 3
    assert rows["a2"]["breakers_open"] == 1


def test_no_verdict_key_crosses_the_wire(client) -> None:
    """SPEC D-5, at the surface a dashboard actually reads. An idle agent and a dead one look
    identical from here, so nothing on this route may claim to tell them apart."""
    for row in client.get("/health/agents", headers=AUTH).json():
        assert not any(k in row for k in ("status", "alive", "healthy", "up", "down", "state"))


def test_three_denials_do_not_arrive_as_a_seventy_five_percent_error_rate(client) -> None:
    """SPEC D-6. a1 is the best-governed agent here; a rate that counted its denials would make it
    the sickest thing on the page, and the fix an operator reaches for is to loosen the guard."""
    a1 = next(r for r in client.get("/health/agents", headers=AUTH).json() if r["agent_id"] == "a1")

    assert a1["execution_failure_rate"] != 0.75
    assert a1["execution_failure_rate"] is None
    # The counts behind the rate travel with it, so a reader can never plot one without the other.
    assert a1["executed"] == 1 and a1["blocked"] == 3 and a1["execution_failures"] is None


def test_containment_crosses_the_wire_by_STATE_not_as_one_number(store, audit, seeded) -> None:
    """The dashboard downstream reads these two fields. An open breaker refuses; a half-open one is
    serving a cooldown between single trials — summing them would tell an operator that a recovering
    agent is cut off, and dropping the half-open one would say nothing is holding back an agent
    throttled to one action per cooldown."""
    breakers = _Breakers(
        [
            {"scope": "agent", "agent_id": "a1", "target": "", "state": "open", "opened_at": 1.0},
            {"scope": "tool", "agent_id": "a2", "target": "http_get", "state": "half_open",
             "opened_at": 1.0},
        ]
    )
    client = TestClient(_app(store, audit, HealthStore(store, breakers=breakers)))

    rows = {r["agent_id"]: r for r in client.get("/health/agents", headers=AUTH).json()}

    assert (rows["a1"]["breakers_open"], rows["a1"]["breakers_half_open"]) == (1, 0)
    assert (rows["a2"]["breakers_open"], rows["a2"]["breakers_half_open"]) == (0, 1)


def test_the_window_narrows_the_read(client, store) -> None:
    """`hours` has to actually reach the query. A window accepted and ignored shows an operator last
    quarter's activity as if it were this morning's."""
    assert client.get("/health/agents", params={"hours": 1}, headers=AUTH).json() != []

    with store() as s:
        s.execute(
            update(AuditRecord).values(
                created_at=datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=30)
            )
        )
        s.commit()

    narrow = client.get("/health/agents", params={"hours": 1}, headers=AUTH).json()
    wide = client.get("/health/agents", params={"hours": 24 * 90}, headers=AUTH).json()

    # a2 keeps a row because its breaker is open — containment is exactly what makes an agent quiet.
    assert {r["agent_id"] for r in narrow} == {"a2"}
    assert next(r for r in narrow if r["agent_id"] == "a2")["last_seen_at"] is None
    assert {r["agent_id"] for r in wide} == {"a1", "a2"}


def test_the_window_travels_in_the_response(client) -> None:
    """A null `last_seen_at` only means something once the reader knows how far back we looked."""
    rows = client.get("/health/agents", params={"hours": 6}, headers=AUTH).json()

    assert all(r["window_hours"] == pytest.approx(6.0) for r in rows)


def test_a_negative_window_is_refused_rather_than_meaning_something_else(client) -> None:
    """`hours=-1` puts the window's start in the FUTURE and would answer 200 with an empty fleet —
    indistinguishable from "every agent is silent", which is the one conclusion this surface must
    never invent."""
    assert client.get("/health/agents", params={"hours": -1}, headers=AUTH).status_code == 422
    assert client.get("/health/agents", params={"hours": 0}, headers=AUTH).status_code == 422


def test_an_absurd_window_is_refused_rather_than_crashing(client) -> None:
    """Not a tidiness bound: an unbounded `hours` builds a timedelta that raises OverflowError out
    of the route, which is a 500 on a gated operator surface reachable with one query parameter."""
    assert (
        client.get("/health/agents", params={"hours": 999_999_999}, headers=AUTH).status_code == 422
    )


def test_the_route_is_gated(client) -> None:
    """Which agents are quiet, which are being blocked and which are contained is a map of where a
    fleet is weakest right now."""
    assert client.get("/health/agents").status_code == 401


def test_an_app_without_health_answers_404_and_leaves_the_rest_of_the_router_working(
    store, audit
) -> None:
    """A deployment that never wired health must not get an ungated surface, and must not lose the
    inventory routes that share the router either."""
    client = TestClient(_app(store, audit, health=None))

    assert client.get("/health/agents", headers=AUTH).status_code == 404
    assert client.get("/inventory", headers=AUTH).status_code == 200
