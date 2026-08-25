"""ECON-02 — the budget ledger: accumulated spend, ready for the decision path.

WHY IT IS A CACHE. `posture_for` is called on EVERY action, inside the decision pipeline, under the
PIPE-04 latency budget (p95 < 10 ms). A SQL SUM per action would put a database round-trip on the
hot path of every governed call in the fleet — the single most reliable way to turn a governance
control plane into the thing operators disable. So the ledger holds per-agent totals in memory,
`CostRecorder` increments them as costs land, and `BudgetReconciler` converges them from the table
(the API-04 pattern already used for trust and resources).

WHY IT LOADS AT CONSTRUCTION. A cache that starts empty reports a used-ratio of 0.0 for an agent
already fifty times over its limit, which is indistinguishable from an agent nobody budgeted — so a
restart would come up "budgets configured, nothing enforced", and nothing in a default deployment
calls `reload` (the reconciler is operator-wired, like every other one here). `__init__` therefore
loads, exactly as `KillSwitchStore` and `PrivilegeRingStore` do for the same reason. That makes the
reconciler an optimization for fleet-wide convergence rather than the only thing standing between
this feature and a silent no-op.

WHY ONLY BUDGETED AGENTS ARE CARRIED. `CostRecorder` reports every agent's cost, budgeted or not, and
an unbudgeted agent's spend changes no decision (its ratio is 0.0 either way — see below). Carrying
them anyway cost one dict entry per agent in the fleet and a fleet-wide `GROUP BY` over `cost_record`
on a 30-second timer, against the same database the `AuditWriter` appends to. That long read is what
stalls an append, and a stalled append drives the pipeline's fail-safe: observation degrading
enforcement. So the ledger's working set is the `agent_budget` table — one row per agent an operator
explicitly budgeted, which does not grow with fleet activity. `cost.spend_usd` is consequently
"spend inside this agent's budget window", and 0.0 for an agent with no budget.

HOW THE WINDOW TURNS OVER. `period` names a window and the spend compared against a limit is the
spend INSIDE it. `note_spend` only ever adds, so each cached total is stamped with the window it
covers and is read as zero once that window closes — otherwise an agent that spent its daily budget
on Monday needs human approval every day after, which is the false positive that gets a control
switched off. The window is resolved against UTC, not the server's local zone: `recorded_at` is
stored in UTC, and a local boundary makes the same daily budget reset at a different moment in each
region of a fleet.

WHAT THE CACHE COSTS, STATED HONESTLY. Between reconciles, a multi-process deployment sees only the
spend recorded in ITS process, so the fleet-wide figure can lag. The reconcile interval is the
operator's dial for it. It is a lag, never a miss: the cost table is the source of truth and `reload`
re-derives the whole window from it, so spend that a reload raced past is counted by the next one.

WHY THE GATE READS ACCUMULATED SPEND, AND WHAT THAT BOUNDS. A call's cost is knowable only after it
returns, so the pre-call gate conditions on what has ALREADY been spent, and the overshoot is
whatever was in flight when the line was crossed: an agent that fans out N parallel calls has N of
them gated on the same pre-crossing reading, plus the reconcile lag above in a multi-process fleet.
It is NOT capped at one action — that tighter bound reads better and an `asyncio.gather` walks
straight through it. Estimating the pending call's tokens would tighten the window while introducing
a provider-specific number the operator cannot verify and an agent can shape its prompt to evade; a
stated bound beats a fragile one. An operator who needs a hard cap sets the limit below the exposure
they will accept.

WHAT IS NOT CAPPED ACROSS A DELEGATION. A sub-agent runs under its OWN agent_id and budgets are not
among the attributes a delegation inherits (TRST-04 passes down trust, scope and ring; RUN-05 states
the same gap for resource limits). An over-budget agent can therefore delegate and keep spending on
the delegate's budget. Budgeting the delegates is the operator's answer today.

WHY AN UNCONFIGURED AGENT IS NOT OVER BUDGET. No budget row means no limit was set. Reporting a
used-ratio of 1.0 there would deny every action in a deployment that never opted into budgets —
turning a feature nobody configured into a fleet-wide outage. Absence of a budget is not evidence of
a breach. An explicit limit of ZERO is the opposite statement and is honored as one.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import func, select

from agentos_controlplane.reconcile import DEFAULT_INTERVALS
from agentos_controlplane.store.models import AgentBudget, CostRecord

_MICRO = 1_000_000
PERIODS = ("day", "month", "total")


@dataclass(frozen=True)
class CostPosture:
    """What the decision path needs to know about an agent's spend."""

    spend_usd: float
    budget_used_ratio: float  # 0.0 when no budget is configured — see the module docstring


# The reading for an agent nobody budgeted, allocated once: in a fleet that has not opted into
# budgets this is the answer for every action, so it is the hot path's common case.
_UNBUDGETED = CostPosture(spend_usd=0.0, budget_used_ratio=0.0)


def _utcnow() -> datetime:
    """Naive UTC. `recorded_at` lands as SQLite's UTC CURRENT_TIMESTAMP and as a Postgres
    timestamptz, and a tz-AWARE bound would not compare against the former.

    On Postgres the naive bound is cast using the session TimeZone, so a server not set to UTC opens
    the window at its own midnight — the house idiom for every naive bound in this codebase, and the
    one place it compares MONEY. Run the database in UTC.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _window_start(period: str, now: datetime) -> datetime | None:
    """The inclusive lower bound of the current window; None for 'total' (all history).

    An unrecognized period also sums all history — over-counting, so it fails toward denying rather
    than toward letting spend through. `set_budget` refuses one up front so the only way to store one
    is to write the row by hand.
    """
    if period == "day":
        return now.replace(hour=0, minute=0, second=0, microsecond=0)
    if period == "month":
        return now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    return None


class BudgetLedger:
    """In-memory per-agent spend, converged from the cost table."""

    def __init__(self, session_factory) -> None:
        self._sf = session_factory
        # Guards the three dicts together. `posture_for` reads them WITHOUT it — a governance
        # decision must never queue behind an administrative write — so a racing reader can see a
        # total one increment behind, which is the lag the module docstring already owns.
        self._lock = threading.Lock()
        self._spend: dict[str, int] = {}  # agent -> micro-USD in the window below
        self._windows: dict[str, datetime | None] = {}  # agent -> the window that total covers
        self._budgets: dict[str, tuple[str, int]] = {}  # agent -> (period, limit_micro_usd)
        self.reload()

    # ---- hot path (in-memory only) ----
    def posture_for(self, agent_id: str) -> CostPosture:
        """Dict reads only — no DB, no I/O, no raise. A ledger failure must not be able to take down
        the decision pipeline that consults it on every action."""
        budget = self._budgets.get(agent_id)
        if budget is None:
            # No row: no limit was set, so there is no ratio to report. Not a breach.
            return _UNBUDGETED
        period, limit = budget
        spend = self._spend.get(agent_id, 0)
        if spend and self._windows.get(agent_id) != _window_start(period, _utcnow()):
            # The total was accumulated in a window that has since closed. Spending it again is the
            # operator's stated intent in choosing a period; keeping it is a budget that never
            # resets. (Only reached for an agent with a nonzero total, so the clock read costs
            # nothing in a fleet that has not opted into budgets.)
            spend = 0
        if limit <= 0:
            # An explicit zero says "spend nothing" — a real limit, not an absent one. Any spend
            # against it is over; none is not. (A zero ratio here would make the one budget that
            # stops an agent outright the one budget that is silently ignored.)
            ratio = 1.0 if spend > 0 else 0.0
        else:
            ratio = spend / limit
        return CostPosture(spend_usd=spend / _MICRO, budget_used_ratio=ratio)

    def note_spend(self, agent_id: str, micro_usd: int | None) -> None:
        """Increment the in-memory total as a cost lands.

        None (unpriced) adds nothing — an unpriced action consumed tokens we cannot convert to
        dollars, and inventing a figure to keep the budget moving would be exactly the fabrication
        ECON-01 refuses. A NEGATIVE amount adds nothing either: it is a refund that would let an
        agent spend its way back under its limit, the same class of forged figure `Usage.reported`
        refuses one layer up. So is `True`, which is an int and is not a dollar figure.
        """
        budget = self._budgets.get(agent_id)
        if budget is None:
            return  # unbudgeted: this total would change no decision — see the module docstring
        if type(micro_usd) is not int or micro_usd <= 0:
            return
        start = _window_start(budget[0], _utcnow())
        with self._lock:
            # A total stamped with a closed window starts over rather than being added to.
            base = self._spend.get(agent_id, 0) if self._windows.get(agent_id) == start else 0
            self._spend[agent_id] = base + micro_usd
            self._windows[agent_id] = start

    # ---- convergence + administration (DB) ----
    def reload(self) -> int:
        """Converge the cache from the tables. Returns the number of agents whose posture CHANGED
        (API-04: zero means converged)."""
        now = _utcnow()
        with self._sf() as s:
            budgets = {
                b.agent_id: (b.period, b.limit_micro_usd)
                for b in s.scalars(select(AgentBudget)).all()
            }
            spend, windows = self._sum_windows(s, budgets, now)
        changed = sum(
            1
            for agent in set(spend) | set(self._spend) | set(budgets) | set(self._budgets)
            if spend.get(agent, 0) != self._spend.get(agent, 0)
            or budgets.get(agent) != self._budgets.get(agent)
        )
        with self._lock:
            # Windows BEFORE spend, and the order is the point: `posture_for` reads the pair without
            # the lock, so a reader can land between the two stores. New-window/old-spend reports a
            # total that may be one window stale (over-reports, fails toward the gate); the reverse
            # would zero a fresh total against a closed window and let one action through.
            self._windows, self._spend, self._budgets = windows, spend, budgets
        return changed

    def _sum_windows(
        self, s, budgets: dict[str, tuple[str, int]], now: datetime
    ) -> tuple[dict[str, int], dict[str, datetime | None]]:
        """Sum each budgeted agent's spend inside its own window.

        One grouped query per distinct period, not one per agent: there are three periods and there
        can be thousands of agents. Every query is restricted to the agents actually budgeted, so
        the cost of a pass tracks the operator's configuration and not the fleet's traffic — with no
        budgets configured, `cost_record` is not touched at all. That restriction is what keeps
        `total` affordable: it has no lower bound, so each pass re-sums those agents' whole history
        (over the `agent_id` index), which is bounded by how many agents an operator budgeted rather
        than by how long the fleet has been running.
        """
        by_period: dict[str, list[str]] = {}
        for agent_id, (period, _) in budgets.items():
            by_period.setdefault(period, []).append(agent_id)
        spend: dict[str, int] = {}
        windows: dict[str, datetime | None] = {}
        for period, agents in by_period.items():
            start = _window_start(period, now)
            query = (
                select(CostRecord.agent_id, func.sum(CostRecord.cost_micro_usd))
                .where(CostRecord.agent_id.in_(agents))
                .group_by(CostRecord.agent_id)
            )
            if start is not None:
                query = query.where(CostRecord.recorded_at >= start)
            for agent_id, total in s.execute(query).all():
                # SUM over an all-null column is NULL, not 0: an agent whose actions were all
                # unpriced has spent an amount we cannot state, which moves no budget.
                spend[agent_id] = int(total or 0)
            windows.update(dict.fromkeys(agents, start))
        return spend, windows

    def set_budget(self, agent_id: str, *, limit_micro_usd: int, period: str = "day") -> None:
        """Assign a limit. Durable FIRST, then the cache — a failed persist must never leave the hot
        path enforcing a limit the table does not record.

        The period is validated HERE and not only at the HTTP route: the store is the boundary, and
        a period this ledger cannot window is a spend control that looks configured and sums the
        wrong thing. Concurrency is `AgentBudget.version_id_col`'s job — a raise that lost a race
        raises `StaleDataError` rather than vanishing, because raising a limit is how an over-budget
        agent is unblocked and a lost one is the write an incident review cannot reconstruct.
        """
        if period not in PERIODS:
            raise ValueError(f"period must be one of {PERIODS}; got {period!r}")
        with self._sf() as s:
            row = s.get(AgentBudget, agent_id)
            if row is None:
                s.add(
                    AgentBudget(agent_id=agent_id, period=period, limit_micro_usd=limit_micro_usd)
                )
            else:
                row.period, row.limit_micro_usd = period, limit_micro_usd
            s.commit()
            # The new limit is measured over a window the cached total may not cover — switching
            # day->month would otherwise weigh a day's spend against a month's limit — and an agent
            # budgeted for the first time would read as having spent nothing until a reload arrived.
            budget = {agent_id: (period, limit_micro_usd)}
            spend, windows = self._sum_windows(s, budget, _utcnow())
        with self._lock:
            self._budgets[agent_id] = (period, limit_micro_usd)
            self._spend[agent_id] = spend.get(agent_id, 0)
            self._windows[agent_id] = windows[agent_id]

    def list_budgets(self) -> list[dict]:
        """Every configured budget with its current posture. Bounded by construction: this table has
        one row per agent an operator explicitly budgeted, not one per action."""
        with self._sf() as s:
            rows = s.scalars(select(AgentBudget).order_by(AgentBudget.agent_id)).all()
        out = []
        for row in rows:
            # The SAME reading the decision path gets: an operator who cannot see the number the
            # principle will compare against cannot explain, or unblock, a budget escalation.
            posture = self.posture_for(row.agent_id)
            out.append(
                {
                    "agent_id": row.agent_id,
                    "period": row.period,
                    "limit_micro_usd": row.limit_micro_usd,
                    "spend_usd": posture.spend_usd,
                    "budget_used_ratio": posture.budget_used_ratio,
                    "version": row.version,
                }
            )
        return out


class BudgetReconciler:
    """API-04 reconciler over the ledger. Reports agents CHANGED (zero == converged).

    What it is FOR, now that the ledger loads at construction and turns its own window over: the
    fleet. Each process only sees the spend it recorded itself, so this is what makes one process'
    figure include another's — and what picks up a budget an operator set on the API process.

    SYNCHRONOUS on purpose: `ReconciliationLoop` runs reconcilers through `asyncio.to_thread` and
    calls `int()` on what comes back. An async `reconcile` would hand it a coroutine, the loop would
    catch the TypeError and report an error every pass, and the budget cache would silently never
    converge — the failure mode that looks exactly like a working reconciler nobody reads.
    """

    name = "budget"

    def __init__(self, ledger: BudgetLedger, *, interval_s: float = DEFAULT_INTERVALS["budget"]) -> None:
        self._ledger = ledger
        self.interval_s = interval_s

    def reconcile(self) -> int:
        return self._ledger.reload()
