"""TEST-08 — the scheduler against the REAL corpus runner.

`tests/unit/test_validation_schedule.py` drives a faithful miniature of `run_suite`, because the
control plane may not import `agentos_sdk` and the reconciler takes the seam injected. But a
miniature cannot fail when the real one changes: a renamed kwarg, or an execution path added to
`run_suite`, would leave every unit test green while the scheduled pass either breaks in production
or — the cardinal rule — starts performing the attacks it is meant to only ask about.

Tests may import both packages (five files here already do), so the cardinal rule is pinned HERE, on
the real corpus runner, with the real store underneath it.
"""

from __future__ import annotations

import asyncio

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.pool import StaticPool

from agentos_contract import Decision, Outcome, Reason
from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.reconcile import ReconciliationLoop
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import RedTeamResult, RedTeamRun
from agentos_controlplane.validation import ValidationStore
from agentos_controlplane.validation_schedule import ValidationReconciler
from agentos_sdk.redteam import SUITES, run_suite


@pytest.fixture
def sessions():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    create_all(engine)
    return create_session_factory(engine)


class _GovernedAgent:
    """A PDP that decides, and a handler that must never be reached (spec D-1).

    The decision carries a `policy` reason because the real deployment's would: the scheduler
    refuses a pass whose control probe never reached the policy engine, since every probe would then
    short-circuit to `deny` and score a perfect guard that was never exercised.
    """

    def __init__(self) -> None:
        self.actions: list[object] = []

    async def evaluate(self, action):
        self.actions.append(action)
        return Decision(
            action_id=action.id,
            outcome=Outcome.deny,
            reasons=[Reason(stage="policy", code="constitution_principle_fired")],
        )

    async def execute(self, action):  # pragma: no cover - failing it is the assertion
        raise AssertionError("an attack payload was EXECUTED — spec D-1 violated")


def test_the_real_corpus_runner_drives_the_scheduler_without_executing_anything(sessions) -> None:
    """The real `run_suite`, the real `ValidationStore`, the real `ReconciliationLoop`.

    Pins three things a stand-in cannot: that the injected-callable contract still matches
    `run_suite`'s signature, that the scheduler's own probes reach the PDP and nothing else, and
    that the whole corpus lands in the trend under the agent being measured.
    """
    agent = _GovernedAgent()
    store = ValidationStore(sessions, AuditWriter(sessions))
    suites = ("exfiltration", "jailbreak")

    r = ValidationReconciler(
        store,
        agent.evaluate,
        run_suite,
        suites,
        agent_id="prod-agent",
        probe_agent_id="prod-agent#validation",
        probe_token="probe-tok",
    )
    results = asyncio.run(ReconciliationLoop([r]).run_once())

    assert [(x.name, x.changed, x.error) for x in results] == [("validation", 2, None)]

    # Every attack in the real corpus went through `evaluate`, plus the one control probe — and
    # `execute` raising means none of them went anywhere else.
    expected_probes = sum(len(SUITES[s]) for s in suites)
    assert len(agent.actions) == expected_probes + 1
    assert {a.agent_id for a in agent.actions} == {"prod-agent#validation"}

    with sessions() as s:
        runs = list(s.scalars(select(RedTeamRun)).all())
        rows = list(s.scalars(select(RedTeamResult)).all())
    assert {(run.agent_id, run.suite, run.source) for run in runs} == {
        ("prod-agent", s_, "scheduled") for s_ in suites
    }
    assert len(rows) == expected_probes
    assert all(row.blocked for row in rows)


def test_a_suite_name_the_real_runner_rejects_fails_the_pass_loudly(sessions) -> None:
    """The real `run_suite` raises `KeyError` for an unknown suite, and a typo in a configured suite
    list is forever — it cannot heal. Isolated per suite it would be one WARNING every fifteen
    minutes and an absent trend line, which reads as "validation is running and finding nothing"
    rather than "validation was never configured". A pass that measures NOTHING is an error result.
    """
    agent = _GovernedAgent()
    store = ValidationStore(sessions, AuditWriter(sessions))

    r = ValidationReconciler(
        store,
        agent.evaluate,
        run_suite,
        ("jailbrake",),  # sic
        agent_id="prod-agent",
        probe_agent_id="prod-agent#validation",
        probe_token="probe-tok",
    )
    results = asyncio.run(ReconciliationLoop([r]).run_once())

    assert results[0].error is not None
    assert "every scheduled suite failed" in results[0].error
    with sessions() as s:
        assert s.scalars(select(RedTeamRun)).all() == []
