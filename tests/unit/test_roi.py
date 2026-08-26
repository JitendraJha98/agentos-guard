"""ECON-04 — ROI analytics, and the value proxy that must not exist.

The load-bearing test is negative: there is NO path from observable data to a value number. The
obvious proxy — counting permitted actions — rises when the guard permits more, so it would make the
cheapest route to a better ROI dashboard "loosen your constitution". A metric that rewards weakening
the control plane has no business inside it.
"""

from __future__ import annotations

import asyncio

import pytest
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from agentos_contract import ActionType, AgentAction, Decision, Outcome, Reason, Usage
from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.economics import CostRecorder, PriceBook
from agentos_controlplane.roi import RoiAnalyzer
from agentos_controlplane.store.engine import create_all, create_session_factory


@pytest.fixture
def store():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    create_all(engine)
    return create_session_factory(engine)


def _action(agent="a1", model="gpt-4o") -> AgentAction:
    return AgentAction(
        agent_id=agent,
        type=ActionType.model_invocation,
        target="chat",
        payload={"model": model, "messages": [{"role": "user", "content": "hi"}]},
    )


def _decision(action, outcome=Outcome.allow) -> Decision:
    return Decision(
        action_id=action.id,
        outcome=outcome,
        reasons=[Reason(stage="policy", code="c", detail="d")],
    )


@pytest.fixture
def cost(store) -> CostRecorder:
    recorder = CostRecorder(
        store, AuditWriter(store), PriceBook({"gpt-4o": (2.5, 10.0)}, version="v")
    )
    action = _action("a1")
    asyncio.run(recorder.record(action, _decision(action), Usage(1000, 500, "gpt-4o")))
    return recorder


# --- the join ------------------------------------------------------------------


def test_roi_is_declared_value_over_measured_cost(cost) -> None:
    analyzer = RoiAnalyzer(cost)
    analyzer.declare_value("a1", 15_000_000)  # $15 declared against $7.50 measured

    row = analyzer.report()["rows"][0]

    assert row["cost_micro_usd"] == 7_500_000
    assert row["roi"] == pytest.approx(2.0)


def test_both_inputs_are_shown_beside_the_ratio(cost) -> None:
    """A ratio nobody can argue with is a ratio nobody should act on."""
    analyzer = RoiAnalyzer(cost)
    analyzer.declare_value("a1", 15_000_000)

    row = analyzer.report()["rows"][0]

    assert row["cost_micro_usd"] and row["declared_value_micro_usd"]


def test_an_agent_with_no_declared_value_has_NULL_roi_not_zero(cost) -> None:
    """Zero asserts the agent produced nothing — a claim about the agent. Null is a claim about what
    we were told, which is the true one."""
    row = RoiAnalyzer(cost).report()["rows"][0]

    assert row["declared_value_micro_usd"] is None
    assert row["roi"] is None


def test_positive_value_at_zero_measured_cost_is_null_not_infinite(store) -> None:
    """An unpriced fleet is not an infinite return. Reporting inf would sort a meaningless row to the
    top of a budget review."""
    recorder = CostRecorder(store, AuditWriter(store), PriceBook({}, version="v"))
    action = _action("a1", model="unpriced")
    asyncio.run(recorder.record(action, _decision(action), Usage(10, 10, "unpriced")))
    analyzer = RoiAnalyzer(recorder)
    analyzer.declare_value("a1", 5_000_000)

    row = analyzer.report()["rows"][0]

    assert row["cost_micro_usd"] == 0 and row["roi"] is None


def test_a_negative_declared_value_is_refused(cost) -> None:
    """It would invert the ratio's sign and render a net-harmful agent as profitable on a sorted
    table. If an agent is net-harmful that is a governance finding, not an ROI figure."""
    with pytest.raises(ValueError, match="negative"):
        RoiAnalyzer(cost).declare_value("a1", -1)


# --- the proxy that must not exist ---------------------------------------------


def test_there_is_no_inferred_value_path(cost) -> None:
    """THE property of this slice, asserted structurally.

    The tempting proxy is "count allowed actions". It rises when the guard permits more, so an agent
    whose denials were CORRECT scores worse than one running unchecked, and the cheapest way to
    improve a team's ROI dashboard becomes loosening their constitution.
    """
    import inspect

    import agentos_controlplane.roi as mod

    source = inspect.getsource(mod)
    # No outcome inspection anywhere: value must never be derived from what the pipeline decided.
    assert "Outcome" not in source
    assert "allow" not in source.replace("allowed", "").replace("allows", "")


def test_value_never_appears_without_being_declared(cost) -> None:
    """Non-vacuity for the structural check: with nothing declared, no row carries a value."""
    report = RoiAnalyzer(cost).report()

    assert all(r["declared_value_micro_usd"] is None for r in report["rows"])
    assert report["agents_with_declared_value"] == 0


# --- the caveats that travel with the number -----------------------------------


def test_every_row_carries_the_value_source_caveat(cost) -> None:
    """Per row, not once per response: a consumer rendering one agent must not be able to drop the
    caveat by rendering a subset."""
    analyzer = RoiAnalyzer(cost)
    analyzer.declare_value("a1", 1_000_000)

    row = analyzer.report()["rows"][0]

    assert "operator-declared" in row["value_source"].lower()
    assert "never inferred" in row["value_source"].lower()


def test_the_report_states_that_cost_includes_blocked_actions(cost) -> None:
    """A well-governed agent under attack looks expensive here, because blocked actions still burned
    tokens reaching the decision and the value of a block is invisible. That has to travel with the
    ratio, since the number outlives the context it was read in."""
    report = RoiAnalyzer(cost).report()

    assert "blocked" in report["cost_basis"].lower()
    assert "question, not a verdict" in report["cost_basis"].lower()


def test_the_report_says_how_many_agents_it_covered(cost) -> None:
    """An ROI table covering three of two hundred agents is a sample, and a reader sorting by ratio
    cannot see that from the rows alone."""
    report = RoiAnalyzer(cost).report()

    assert report["agents_reported"] == len(report["rows"])
    assert "agents_with_declared_value" in report


def test_the_report_is_bounded(store) -> None:
    """The aggregation reads the whole cost table, which grows with every governed action."""
    recorder = CostRecorder(
        store, AuditWriter(store), PriceBook({"gpt-4o": (2.5, 10.0)}, version="v")
    )
    for i in range(8):
        action = _action(f"agent-{i}")
        asyncio.run(recorder.record(action, _decision(action), Usage(10, 10, "gpt-4o")))

    assert len(RoiAnalyzer(recorder).report(limit=3)["rows"]) == 3
