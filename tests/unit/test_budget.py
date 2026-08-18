"""ECON-02 — budget as policy: the ledger the decision path reads, and what it refuses to invent."""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import AgentBudget


@pytest.fixture
def store():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    create_all(engine)
    return create_session_factory(engine)


def test_a_budget_row_round_trips(store) -> None:
    """Money is integer micro-USD here for the same reason it is on CostRecord: a budget DECISION
    must be reproducible, and a float total is not."""
    with store() as s:
        s.add(AgentBudget(agent_id="a1", period="day", limit_micro_usd=5_000_000))
        s.commit()

    with store() as s:
        row = s.get(AgentBudget, "a1")
        assert (row.period, row.limit_micro_usd, row.version) == ("day", 5_000_000, 1)
