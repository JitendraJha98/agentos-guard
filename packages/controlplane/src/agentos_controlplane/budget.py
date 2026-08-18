"""ECON-02 — the budget ledger: accumulated spend, ready for the decision path.

WHY IT IS A CACHE. `posture_for` is called on EVERY action, inside the decision pipeline, under the
PIPE-04 latency budget (p95 < 10 ms). A SQL SUM per action would put a database round-trip on the
hot path of every governed call in the fleet — the single most reliable way to turn a governance
control plane into the thing operators disable. So the ledger holds per-agent totals in memory,
`CostRecorder` increments them as costs land, and `BudgetReconciler` converges them from the table
(the API-04 pattern already used for trust and resources).

WHAT THE CACHE COSTS, STATED HONESTLY. Between reconciles, a multi-process deployment sees only the
spend recorded in ITS process, so the fleet-wide figure can lag. That widens the overshoot window
beyond the single-action bound below; the reconcile interval is the operator's dial for it. It is a
lag, never a miss: the cost table is the source of truth and `reload` re-derives the whole window
from it, so spend that a reload raced past is counted by the next one.

WHY THE GATE READS ACCUMULATED SPEND. A call's cost is knowable only after it returns, so the
pre-call gate conditions on what has ALREADY been spent. The bound that follows is stated plainly
and tested: an agent can exceed its budget by at most the cost of the single action that crossed the
line. Estimating the pending call's tokens would tighten that slightly while introducing a
provider-specific number the operator cannot verify and an agent can shape its prompt to evade — a
verifiable bound beats a fragile tighter one.

WHY AN UNCONFIGURED AGENT IS NOT OVER BUDGET. No budget row means no limit was set. Reporting a
used-ratio of 1.0 there would deny every action in a deployment that never opted into budgets —
turning a feature nobody configured into a fleet-wide outage. Absence of a budget is not evidence of
a breach. An explicit limit of ZERO is the opposite statement and is honored as one.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import func, select

from agentos_controlplane.reconcile import DEFAULT_INTERVALS
from agentos_controlplane.store.models import AgentBudget, CostRecord

_MICRO = 1_000_000


@dataclass(frozen=True)
class CostPosture:
    """What the decision path needs to know about an agent's spend."""

    spend_usd: float
    budget_used_ratio: float  # 0.0 when no budget is configured — see the module docstring


def _window_start(period: str, now: datetime) -> datetime | None:
    """The inclusive lower bound of the current window; None for 'total' (all history).

    The window turns over at UTC midnight, not the operator's local midnight — `recorded_at` is
    stored in UTC, and resolving the boundary against a server's local zone would make the same
    daily budget reset at a different moment in each region of a fleet.
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
        self._spend: dict[str, int] = {}  # agent -> micro-USD in the current window
        self._budgets: dict[str, tuple[str, int]] = {}  # agent -> (period, limit_micro_usd)

    # ---- hot path (in-memory only) ----
    def posture_for(self, agent_id: str) -> CostPosture:
        """Dict reads only — no DB, no I/O, no raise. A ledger failure must not be able to take down
        the decision pipeline that consults it on every action."""
        spend = self._spend.get(agent_id, 0)
        budget = self._budgets.get(agent_id)
        if budget is None:
            # No row: no limit was set, so there is no ratio to report. Not a breach.
            return CostPosture(spend_usd=spend / _MICRO, budget_used_ratio=0.0)
        limit = budget[1]
        if limit <= 0:
            # An explicit zero says "spend nothing" — a real limit, not an absent one. Any spend
            # against it is over; none is not. (A zero ratio here would make the one budget that
            # stops an agent outright the one budget that is silently ignored.)
            ratio = 1.0 if spend > 0 else 0.0
        else:
            ratio = spend / limit
        return CostPosture(spend_usd=spend / _MICRO, budget_used_ratio=ratio)

    def note_spend(self, agent_id: str, micro_usd: int | None) -> None:
        """Increment the in-memory total as a cost lands. None (unpriced) adds nothing — an unpriced
        action consumed tokens we cannot convert to dollars, and inventing a figure to keep the
        budget moving would be exactly the fabrication ECON-01 refuses."""
        if micro_usd:
            self._spend[agent_id] = self._spend.get(agent_id, 0) + micro_usd

    # ---- convergence + administration (DB) ----
    def reload(self) -> int:
        """Converge the cache from the tables. Returns the number of agents whose posture CHANGED
        (API-04: zero means converged)."""
        # Naive UTC: `recorded_at` lands as SQLite's UTC CURRENT_TIMESTAMP and as a Postgres
        # timestamptz, and a tz-aware bound would not compare against the former.
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        with self._sf() as s:
            budgets = {
                b.agent_id: (b.period, b.limit_micro_usd)
                for b in s.scalars(select(AgentBudget)).all()
            }
            spend: dict[str, int] = {}
            # One grouped query per distinct period, not one per agent: there are three periods and
            # there can be thousands of agents. "day" is always queried so an agent with no budget
            # row still gets a truthful spend figure (its ratio stays 0.0 — see posture_for).
            for period in {p for p, _ in budgets.values()} | {"day"}:
                start = _window_start(period, now)
                query = select(
                    CostRecord.agent_id, func.sum(CostRecord.cost_micro_usd)
                ).group_by(CostRecord.agent_id)
                if start is not None:
                    query = query.where(CostRecord.recorded_at >= start)
                for agent_id, total in s.execute(query).all():
                    # SUM over an all-null column is NULL, not 0: an agent whose actions were all
                    # unpriced has spent an amount we cannot state, which moves no budget.
                    if budgets.get(agent_id, ("day", 0))[0] == period:
                        spend[agent_id] = int(total or 0)
        changed = sum(
            1
            for agent in set(spend) | set(self._spend) | set(budgets) | set(self._budgets)
            if spend.get(agent, 0) != self._spend.get(agent, 0)
            or budgets.get(agent) != self._budgets.get(agent)
        )
        self._spend, self._budgets = spend, budgets
        return changed

    def set_budget(self, agent_id: str, *, limit_micro_usd: int, period: str = "day") -> None:
        """Assign a limit. Durable FIRST, then the cache — a failed persist must never leave the hot
        path enforcing a limit the table does not record."""
        with self._sf() as s:
            row = s.get(AgentBudget, agent_id)
            if row is None:
                s.add(
                    AgentBudget(agent_id=agent_id, period=period, limit_micro_usd=limit_micro_usd)
                )
            else:
                row.period, row.limit_micro_usd = period, limit_micro_usd
                row.version += 1
            s.commit()
        self._budgets[agent_id] = (period, limit_micro_usd)

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
