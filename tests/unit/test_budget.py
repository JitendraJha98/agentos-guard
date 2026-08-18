"""ECON-02 — budget as policy: the ledger the decision path reads, and what it refuses to invent."""

from __future__ import annotations

import asyncio
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from agentos_contract import ActionType, AgentAction, Decision, Outcome, Reason, Usage
from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.budget import BudgetLedger, BudgetReconciler
from agentos_controlplane.economics import CostRecorder, PriceBook
from agentos_controlplane.reconcile import Reconciler
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import AgentBudget, CostRecord


@pytest.fixture
def store():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    create_all(engine)
    return create_session_factory(engine)


def _seed_cost(store, agent: str, micro: int | None) -> None:
    """A cost row as the recorder would have written it — `micro=None` is the unpriced case."""
    with store() as s:
        s.add(
            CostRecord(
                action_id=uuid4(),
                agent_id=agent,
                action_type="model_invocation",
                model="gpt-4o",
                input_tokens=1,
                output_tokens=1,
                cost_micro_usd=micro,
            )
        )
        s.commit()


def _action(agent: str = "a1") -> AgentAction:
    return AgentAction(
        agent_id=agent,
        type=ActionType.model_invocation,
        target="chat",
        payload={"model": "gpt-4o"},
    )


def _decision(action: AgentAction) -> Decision:
    return Decision(
        action_id=action.id, outcome=Outcome.allow, reasons=[Reason(stage="policy", code="ok")]
    )


def test_a_budget_row_round_trips(store) -> None:
    """Money is integer micro-USD here for the same reason it is on CostRecord: a budget DECISION
    must be reproducible, and a float total is not."""
    with store() as s:
        s.add(AgentBudget(agent_id="a1", period="day", limit_micro_usd=5_000_000))
        s.commit()

    with store() as s:
        row = s.get(AgentBudget, "a1")
        assert (row.period, row.limit_micro_usd, row.version) == ("day", 5_000_000, 1)


def test_an_agent_with_no_budget_is_not_over_budget(store) -> None:
    """The whole-fleet-outage guard. A feature nobody configured must not deny anything."""
    ledger = BudgetLedger(store)
    ledger.reload()

    posture = ledger.posture_for("never-configured")

    assert posture.budget_used_ratio == 0.0 and posture.spend_usd == 0.0


def test_spend_accumulates_against_the_configured_limit(store) -> None:
    ledger = BudgetLedger(store)
    ledger.set_budget("a1", limit_micro_usd=10_000_000)  # $10
    ledger.note_spend("a1", 2_500_000)  # $2.50

    posture = ledger.posture_for("a1")

    assert posture.spend_usd == 2.5 and posture.budget_used_ratio == 0.25


def test_unpriced_spend_moves_nothing(store) -> None:
    """An unpriced action consumed tokens we cannot convert. Inventing a figure to keep the budget
    moving is the fabrication ECON-01 exists to refuse."""
    ledger = BudgetLedger(store)
    ledger.set_budget("a1", limit_micro_usd=1_000_000)

    ledger.note_spend("a1", None)

    assert ledger.posture_for("a1").budget_used_ratio == 0.0


def test_a_budget_of_zero_is_a_limit_not_an_absent_row(store) -> None:
    """An operator who writes a limit of zero means "spend nothing", which is a DIFFERENT statement
    from having written no budget at all. Collapsing the two would make the one budget an operator
    can set to stop an agent outright the one budget that is silently ignored."""
    ledger = BudgetLedger(store)
    ledger.set_budget("a1", limit_micro_usd=0)

    assert ledger.posture_for("a1").budget_used_ratio == 0.0  # nothing spent yet
    ledger.note_spend("a1", 1)
    assert ledger.posture_for("a1").budget_used_ratio == 1.0


def test_posture_for_touches_no_database(store) -> None:
    """PIPE-04: this runs on EVERY action. A DB round-trip here would put a query on the hot path of
    every governed call in the fleet — the most reliable way to make operators disable governance."""
    ledger = BudgetLedger(store)
    ledger.set_budget("a1", limit_micro_usd=1_000_000)
    ledger.note_spend("a1", 500_000)

    def explode(*a, **k):
        raise AssertionError("posture_for must not open a session")

    ledger._sf = explode  # deliberate: the only way to prove the absence of I/O is to make it fatal

    assert ledger.posture_for("a1").budget_used_ratio == 0.5
    assert ledger.posture_for("never-configured").budget_used_ratio == 0.0


def test_reload_converges_from_the_cost_table_and_reports_zero_when_settled(store) -> None:
    """API-04 semantics: a reconciler that always reports work makes a converged system
    indistinguishable from a broken one."""
    ledger = BudgetLedger(store)
    ledger.set_budget("a1", limit_micro_usd=10_000_000)
    _seed_cost(store, "a1", 3_000_000)

    assert ledger.reload() >= 1
    assert ledger.posture_for("a1").spend_usd == 3.0
    assert ledger.reload() == 0


def test_reload_ignores_unpriced_rows_rather_than_counting_them_as_zero_or_guessing(store) -> None:
    """The table half of the same refusal `note_spend` makes: a null cost is "we do not know what
    this cost", and a SUM that skipped it must not be presented as a complete bill."""
    ledger = BudgetLedger(store)
    ledger.set_budget("a1", limit_micro_usd=10_000_000)
    _seed_cost(store, "a1", None)
    ledger.reload()

    assert ledger.posture_for("a1").spend_usd == 0.0


def test_reload_picks_up_a_budget_an_operator_set_in_another_process(store) -> None:
    """The reconciler's real job: this process never called set_budget, so without the reload the
    limit exists in the table and nowhere the decision path can see it."""
    with store() as s:
        s.add(AgentBudget(agent_id="a1", period="day", limit_micro_usd=4_000_000))
        s.commit()
    _seed_cost(store, "a1", 4_000_000)
    ledger = BudgetLedger(store)

    ledger.reload()

    assert ledger.posture_for("a1").budget_used_ratio == 1.0


def test_setting_a_budget_bumps_the_version_so_a_raise_is_visible(store) -> None:
    """Raising a limit is how an over-budget agent is unblocked. A limit that changes with no trace
    is the one an incident review cannot reconstruct."""
    ledger = BudgetLedger(store)
    ledger.set_budget("a1", limit_micro_usd=1_000_000)
    ledger.set_budget("a1", limit_micro_usd=9_000_000)

    row = ledger.list_budgets()[0]

    assert (row["limit_micro_usd"], row["version"]) == (9_000_000, 2)


def test_the_recorder_moves_the_ledger(store) -> None:
    """The feed: a metered action is what advances the budget, on the one execution seam."""
    ledger = BudgetLedger(store)
    ledger.set_budget("a1", limit_micro_usd=10_000_000)
    recorder = CostRecorder(
        store,
        AuditWriter(store),
        PriceBook({"gpt-4o": (2.5, 10.0)}, version="v1"),
        ledger=ledger,
    )
    action = _action()

    asyncio.run(recorder.record(action, _decision(action), Usage(1000, 500, "gpt-4o")))

    assert ledger.posture_for("a1").spend_usd == 7.5


def test_the_recorder_without_a_ledger_still_records(store) -> None:
    """The ledger is optional wiring; an ECON-01 deployment that never opted into budgets must keep
    attributing cost exactly as before."""
    recorder = CostRecorder(store, AuditWriter(store), PriceBook({"gpt-4o": (2.5, 10.0)}, version="v1"))
    action = _action()

    asyncio.run(recorder.record(action, _decision(action), Usage(1000, 500, "gpt-4o")))

    assert recorder.totals()[0]["cost_micro_usd"] == 7_500_000


def test_the_reconciler_is_the_shape_the_loop_runs(store) -> None:
    """The API-04 loop calls `reconcile()` through `asyncio.to_thread` and does `int(changed)` on the
    result. An async `reconcile` would hand it a coroutine, which the loop catches and reports as an
    error forever — a budget that silently never converges."""
    reconciler = BudgetReconciler(BudgetLedger(store))

    assert isinstance(reconciler, Reconciler)
    assert reconciler.name == "budget" and reconciler.interval_s > 0
    assert reconciler.reconcile() == 0  # nothing configured, nothing spent — converged
