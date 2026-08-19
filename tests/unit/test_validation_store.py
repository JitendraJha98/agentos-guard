"""TEST-07 — attack-success-rate over time, per agent and per attack class."""

from __future__ import annotations

import asyncio
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.pool import StaticPool

from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import RedTeamResult, RedTeamRun


@pytest.fixture
def store():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    create_all(engine)
    return create_session_factory(engine)


def test_a_run_and_its_results_round_trip(store) -> None:
    run_id = uuid4()
    with store() as s:
        s.add(RedTeamRun(id=run_id, agent_id="a1", suite="jailbreak", total=2, blocked=2))
        s.add(RedTeamResult(run_id=run_id, attack_id="jb_dev_mode", outcome="deny", blocked=True))
        s.commit()
    with store() as s:
        run = s.scalars(select(RedTeamRun)).one()
        result = s.scalars(select(RedTeamResult)).one()

    assert (run.total, run.blocked, run.source) == (2, 2, "manual")
    assert result.attack_id == "jb_dev_mode" and result.blocked is True


def test_the_validation_event_kind_is_accepted_and_unknown_kinds_are_not(store) -> None:
    audit = AuditWriter(store)

    asyncio.run(
        audit.append_event(
            "validation_run", {"agent": "a1", "suite": "jailbreak", "total": 2, "blocked": 2}
        )
    )

    with pytest.raises(ValueError):
        asyncio.run(audit.append_event("validation_definitely_not_a_kind", {}))
