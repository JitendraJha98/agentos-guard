"""ECON-02 — budget as policy: the ledger the decision path reads, and what it refuses to invent."""

from __future__ import annotations

import asyncio
import sys
import threading
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm.exc import StaleDataError
from sqlalchemy.pool import StaticPool

from agentos_contract import ActionType, AgentAction, Decision, Outcome, Reason, Usage
from agentos_controlplane import budget as budget_module
from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.budget import (
    BudgetLedger,
    BudgetReconciler,
    CostPosture,
    _utcnow,
    _window_start,
)
from agentos_controlplane.economics import CostRecorder, PriceBook
from agentos_controlplane.reconcile import Reconciler
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import AgentBudget, CostRecord

_MICRO_USD = 1_000_000


@pytest.fixture
def store():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    create_all(engine)
    return create_session_factory(engine)


def _seed_cost(store, agent: str, micro: int | None, when: datetime | None = None) -> None:
    """A cost row as the recorder would have written it — `micro=None` is the unpriced case.

    `when` stamps `recorded_at` explicitly so a window boundary can be asserted rather than waited
    for: the server default only ever produces 'now', which cannot discriminate a window that is
    24h wide from one that is all of history.
    """
    with store() as s:
        row = CostRecord(
            action_id=uuid4(),
            agent_id=agent,
            action_type="model_invocation",
            model="gpt-4o",
            input_tokens=1,
            output_tokens=1,
            cost_micro_usd=micro,
        )
        if when is not None:
            row.recorded_at = when
        s.add(row)
        s.commit()


def _set_limit(store, agent: str, micro: int, period: str = "day") -> None:
    """A budget row written STRAIGHT to the table — i.e. by another process, which is the case the
    in-memory ledger cannot see without loading."""
    with store() as s:
        s.add(AgentBudget(agent_id=agent, period=period, limit_micro_usd=micro))
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


# ------------------------------------------------------------------- the ledger comes up loaded


def test_a_fresh_ledger_enforces_the_budgets_already_in_the_table(store) -> None:
    """A restart must not fail open. The ledger is a cache over two tables; a process that comes up
    with empty dicts reports a used-ratio of 0.0 for an agent FIFTY TIMES over its limit, and every
    configured budget silently stops enforcing until something calls `reload()` — which nothing in a
    default deployment does (no composition root builds a `ReconciliationLoop`). Same shape and the
    same fix as `KillSwitchStore._load` and `PrivilegeRingStore._load`."""
    _set_limit(store, "a1", 1_000_000)  # $1.00/day
    _seed_cost(store, "a1", 50_000_000)  # $50.00 already committed against it

    posture = BudgetLedger(store).posture_for("a1")  # NO explicit reload

    assert posture.spend_usd == 50.0 and posture.budget_used_ratio == 50.0


# ----------------------------------------------------------------------- what `period` means


def test_the_window_bounds_are_the_ones_each_period_names() -> None:
    """`period` is a stored, operator-settable column and this function is the whole of its meaning.
    Unpinned, a day window that never turns over (all history), one that opens 24h early, and a
    month window that has quietly collapsed to a day are all indistinguishable — each is wrong by a
    factor an operator reads as real spend."""
    now = datetime(2026, 8, 19, 13, 45, 30, 123456)

    assert _window_start("day", now) == datetime(2026, 8, 19, 0, 0, 0, 0)
    assert _window_start("month", now) == datetime(2026, 8, 1, 0, 0, 0, 0)
    assert _window_start("total", now) is None


def test_the_window_clock_is_utc_and_not_the_servers_local_zone() -> None:
    """`recorded_at` is stamped in UTC, so resolving the boundary against a server's local zone
    makes the same daily budget reset at a different moment in each region of a fleet — silently
    wrong for exactly the offset, every day. (This assertion can only discriminate on a host whose
    local zone is NOT UTC; it is the half of the property that is checkable in-process.)"""
    assert abs(_utcnow() - datetime.now(timezone.utc).replace(tzinfo=None)) < timedelta(seconds=1)


def test_a_daily_budget_counts_this_windows_spend_and_not_the_last_ones(store) -> None:
    """The boundary asserted against real rows, not just against the pure function: an agent that
    spent its daily budget yesterday must start today at zero, or `period` promises a reset the
    ledger never performs and the agent needs human approval forever."""
    start = _window_start("day", _utcnow())
    _seed_cost(store, "a1", 5_000_000, when=start - timedelta(seconds=1))  # the previous window
    _seed_cost(store, "a1", 1_000_000, when=start + timedelta(seconds=1))  # this one
    _set_limit(store, "a1", 2_000_000)

    assert BudgetLedger(store).posture_for("a1").spend_usd == 1.0


def test_the_window_rolls_over_in_memory_without_waiting_for_a_reconciler(store, monkeypatch) -> None:
    """`note_spend` only ever adds, so without this the cached total from a closed window is the
    number the constitution keeps comparing against — an agent that spent its budget on Monday is
    still over budget on Friday. The reconciler converges a FLEET; it must not be the only thing
    that makes a single process' own clock advance."""
    ledger = BudgetLedger(store)
    ledger.set_budget("a1", limit_micro_usd=1_000_000, period="day")
    monkeypatch.setattr(budget_module, "_utcnow", lambda: _utcnow() - timedelta(days=1))
    ledger.note_spend("a1", 5_000_000)
    assert ledger.posture_for("a1").budget_used_ratio == 5.0  # over budget, in yesterday's window

    monkeypatch.undo()  # the day turns over; nothing else happens

    assert ledger.posture_for("a1").budget_used_ratio == 0.0
    # ...and the NEXT spend must start from zero, not re-admit yesterday. `note_spend` carries its
    # own half of the rollover, and reading it through `posture_for` alone left that half untested:
    # a mutant that dropped the window check there reported 5.1 instead of 0.1 here, so the agent
    # would be over budget again on its second action of the day, every day.
    ledger.note_spend("a1", 100_000)

    assert ledger.posture_for("a1").budget_used_ratio == 0.1


# --------------------------------------------------------- what the ledger refuses to carry


def test_the_ledger_tracks_only_the_agents_an_operator_budgeted(store) -> None:
    """Two costs in one. `CostRecorder` notifies for EVERY agent, so `_spend` grew one entry per
    agent in the fleet; and `reload` aggregated `cost_record` fleet-wide on a 30-second timer —
    a full GROUP BY against the same database the AuditWriter appends to, computing a figure whose
    ratio is 0.0 either way. An unbudgeted agent's spend changes no decision, so it is not carried."""
    ledger = BudgetLedger(store)
    # One budgeted agent ALONGSIDE the unbudgeted crowd. With no budgets at all the reload runs no
    # query, so the `IN (budgeted)` restriction it is supposed to pin is never reached — the test
    # passed with that clause deleted. A guard needs the shape a real deployment has: some budgets,
    # a much larger fleet.
    ledger.set_budget("budgeted", limit_micro_usd=10_000_000, period="day")
    _seed_cost(store, "budgeted", 3_000_000)
    for i in range(50):
        _seed_cost(store, f"unbudgeted-{i}", 1_000_000)
        ledger.note_spend(f"unbudgeted-{i}", 1_000_000)

    ledger.reload()

    assert set(ledger._spend) == {"budgeted"}, "reload must aggregate only the budgeted agents"
    assert ledger.posture_for("budgeted").spend_usd == 3.0
    assert ledger.posture_for("unbudgeted-0") == CostPosture(spend_usd=0.0, budget_used_ratio=0.0)


def test_reload_does_not_aggregate_the_cost_table_when_nothing_is_budgeted(store) -> None:
    """A deployment that never opted into budgets must not pay a repeating fleet-wide scan for the
    privilege. `cost_record` grows with every governed action; the long read is what stalls the
    AuditWriter's append, and a stalled append drives the pipeline's fail-safe."""
    _seed_cost(store, "a1", 1_000_000)
    statements: list[str] = []
    event.listen(
        store.kw["bind"],
        "before_cursor_execute",
        lambda conn, cursor, statement, *rest: statements.append(statement),
    )

    BudgetLedger(store).reload()

    assert statements  # the budget table WAS read...
    assert not any("cost_record" in s for s in statements)  # ...and the cost table was not


def test_note_spend_refuses_an_amount_that_would_move_the_budget_backwards(store) -> None:
    """11b hardened `Usage.reported` against negative and boolean counts because a forged figure
    could move a priced ledger row. This is the OTHER entrance to the same ledger: a negative
    micro-USD is a refund an agent could spend its way back under its limit with, and `True` is an
    int that is not a dollar figure."""
    ledger = BudgetLedger(store)
    ledger.set_budget("a1", limit_micro_usd=10_000_000)
    ledger.note_spend("a1", 9_000_000)

    ledger.note_spend("a1", -8_000_000)  # a plausible in-range "refund"
    ledger.note_spend("a1", True)

    assert ledger.posture_for("a1").spend_usd == 9.0


# ------------------------------------------------------------------ administering a budget


def test_concurrent_recorders_cannot_lose_an_increment(store) -> None:
    """`total = total + cost` is several bytecodes, and every loss favours the agent — spend that
    was really incurred simply does not reach the number the constitution compares against. One
    event loop cannot interleave it, but the SDK already reaches for a `threading.Lock` to host a
    PEP in threads, and a governance figure must not depend on which host it was wired into."""
    ledger = BudgetLedger(store)
    ledger.set_budget("a1", limit_micro_usd=10_000_000)
    interval = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)  # force the interpreter to preempt mid-increment
    try:
        threads = [
            threading.Thread(target=lambda: [ledger.note_spend("a1", 1) for _ in range(2_000)])
            for _ in range(16)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    finally:
        sys.setswitchinterval(interval)

    assert ledger.posture_for("a1").spend_usd == 32_000 / _MICRO_USD


def test_set_budget_refuses_a_period_it_cannot_window(store) -> None:
    """The HTTP route validates this, but the STORE is the boundary: a 'week' row from a direct
    call, an operator's SQL or a future importer falls through to an all-history sum, which
    over-counts every agent it touches and denies on a number no window explains."""
    ledger = BudgetLedger(store)

    with pytest.raises(ValueError, match="period"):
        ledger.set_budget("a1", limit_micro_usd=1_000_000, period="week")

    assert ledger.list_budgets() == []


def test_changing_the_period_re_derives_the_spend_for_the_new_window(store) -> None:
    """A limit and the window it is measured over change together. Leaving the total computed for
    the OLD window in place measures a day's spend against a month's limit (under-denies) or a
    month's against a day's (over-denies), until a reload nobody scheduled arrives."""
    _seed_cost(store, "a1", 5_000_000, when=_utcnow() - timedelta(days=40))  # long closed
    _seed_cost(store, "a1", 1_000_000, when=_utcnow())
    ledger = BudgetLedger(store)

    ledger.set_budget("a1", limit_micro_usd=10_000_000, period="day")
    assert ledger.posture_for("a1").spend_usd == 1.0

    ledger.set_budget("a1", limit_micro_usd=10_000_000, period="total")
    assert ledger.posture_for("a1").spend_usd == 6.0


def test_a_budget_write_that_lost_a_race_is_refused_rather_than_silently_dropped(store) -> None:
    """Raising a limit is how an over-budget agent is unblocked — the privileged write on this whole
    feature. A read-modify-write with no SQL-level guard lets one of two concurrent assignments
    vanish with no trace, which is exactly what `AgentBudget.version` claims to make impossible.
    `version_id_col` is the atomic guard that survives the Postgres target (distinct connections,
    READ COMMITTED), not a non-atomic Python read-then-compare."""
    ledger = BudgetLedger(store)
    ledger.set_budget("a1", limit_micro_usd=1_000_000)

    with store() as stale:
        row = stale.get(AgentBudget, "a1")  # version 1 in hand
        with store() as winner:
            winner.get(AgentBudget, "a1").limit_micro_usd = 5_000_000
            winner.commit()  # another operator's raise lands first
        row.limit_micro_usd = 2_000_000
        with pytest.raises(StaleDataError):
            stale.commit()

    with store() as s:
        assert s.get(AgentBudget, "a1").limit_micro_usd == 5_000_000
