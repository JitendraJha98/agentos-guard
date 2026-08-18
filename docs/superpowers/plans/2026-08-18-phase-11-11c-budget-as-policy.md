# Phase 11 · Slice 11c — Budget as Policy (ECON-02) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Commits end
> with a second `-m "Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"`. Tests:
> `./.venv/Scripts/python.exe -m pytest`. TDD per task, one commit each. Gates `floor_invariant`
> + `regression_lock` green at every commit. **`-m latency` is a first-class gate for this slice** —
> it adds a lookup to the per-action decision path. Re-run when idle before claiming a regression;
> NEVER loosen the budget.

**Goal (ECON-02):** Express token/budget limits as **policy**, so an over-budget action is denied or
escalated by the graduated-response engine — not by a parallel budget enforcer bolted alongside it.

**Architecture:** Spend enters the decision as **policy-input fields** (`cost.spend_usd`,
`cost.budget_used_ratio`); a principle in the constitution conditions on them; the existing floor +
graduated machinery produces the outcome. That is the whole design, and its point is that a budget
breach becomes explainable, auditable and overridable by exactly the same mechanisms as every other
governance decision — with the same floor invariant (a policy deny is terminal; risk and trust may
only restrict further).

The gate reads **accumulated fact, not a predicted cost** (spec D-4). Spend is knowable only after a
call returns, so the honest bound is stated plainly and tested: **overshoot is capped at one action's
cost.** The rejected alternative — estimating the pending call's tokens — is a provider-specific
number the operator cannot verify and an agent can shape its prompt to evade.

`enrich()` is pure-CPU and stateless by contract, so budget state does **not** enter through it. The
`BudgetLedger` is an in-memory cached lookup consulted in the runner and passed into
`build_policy_input` — exactly how the stateful `SequenceCorrelator` already enters (runner.py:653),
and exactly the caching discipline `ResourceGovernor.limits_for` already requires.

**Tech Stack:** SQLAlchemy 2.0 + Alembic, the existing constitution compiler + opa-wasmtime, pytest.

## Note for the implementer: `gte`/`lte` have never run against a real field

`agentos_contract.policy_io.POLICY_INPUT_FIELDS` currently declares only `str`, `bool` and `list`
fields, yet `schema.py:50-57` validates `gte`/`lte` against `ftype in (int, float)` and
`compiler.py:77-86` emits `input.{f} >= {v}`. **The numeric comparison path therefore has no live
consumer today.** `cost.*` will be the first. Do not assume it works — prove it end-to-end
(YAML → compile → WASM → `evaluate`) in Task 3, including the negated-leaf inversion at
`compiler.py:86` (`gte`→`lt`, `lte`→`gt`) under a `not:` node, which is the part most likely to be
wrong precisely because nothing has ever exercised it.

> First commit in this slice: `docs(phase-11): Slice 11c plan` for this file, then the tasks below.

## File structure
- Modify `.../store/models.py` — `AgentBudget`.
- Create `.../store/migrations/versions/0025_agent_budget.py` (down_revision `0024_cost_record`).
- Create `.../agentos_controlplane/budget.py` — `BudgetLedger` + `BudgetReconciler`.
- Modify `.../economics.py` — `CostRecorder` notifies the ledger.
- Modify `packages/contract/src/agentos_contract/policy_io.py` — the two `cost.*` fields.
- Modify `packages/pipeline/src/agentos_pipeline/policy_input.py` — emit the `cost` doc.
- Modify `packages/pipeline/src/agentos_pipeline/runner.py` — the `budget` collaborator.
- Modify `policies/constitution.yaml` — the shipped budget principle.
- Modify `.../api.py` — read + set routes.
- Tests: `tests/unit/test_budget.py`, `tests/integration/test_budget_policy.py`.

---

### Task 1: `AgentBudget` table + migration 0025

**Files:** modify `.../store/models.py`; create the migration; test `tests/unit/test_budget.py`.

```python
class AgentBudget(Base):
    """ECON-02 — an operator-set spending limit for one agent.

    `period` is the window the limit applies over ('day' | 'month' | 'total'); spend is summed from
    `cost_record` inside the current window. Micro-USD integers for the same reason CostRecord uses
    them: a budget DECISION must be reproducible, and float money is not.

    A missing row means NO BUDGET CONFIGURED, which is not the same as a budget of zero. The ledger
    reports a used-ratio of 0.0 for an unconfigured agent, so an operator who has set no budgets
    cannot have their whole fleet deadlocked by the mere presence of this feature.
    """

    __tablename__ = "agent_budget"

    agent_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    period: Mapped[str] = mapped_column(String(16), nullable=False, default="day")
    limit_micro_usd: Mapped[int] = mapped_column(BigInteger, nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )
```

Migration `0025_agent_budget.py` (`revision = "0025_agent_budget"`,
`down_revision = "0024_cost_record"`), house-style docstring covering why micro-USD and why an absent
row means "unconfigured" rather than "zero".

- [ ] **Step 1: Failing test** — insert an `AgentBudget(agent_id="a1", period="day",
  limit_micro_usd=5_000_000)`, read it back, assert the fields and `version == 1`.
- [ ] **Step 2: Run → fails** (`ImportError: cannot import name 'AgentBudget'`).
- [ ] **Step 3: Add the model + migration.**
- [ ] **Step 4: Run → passes;** alembic single head `['0025_agent_budget']`.
- [ ] **Step 5: Commit** `feat(controlplane): agent_budget table + migration 0025 (ECON-02)`.

---

### Task 2: `BudgetLedger` — the cached hot-path lookup

**Files:** create `.../agentos_controlplane/budget.py`; modify `.../economics.py`; test
`tests/unit/test_budget.py`.

```python
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
lag, never a miss: reconciliation is additive and monotonic within a window.

WHY THE GATE READS ACCUMULATED SPEND. A call's cost is knowable only after it returns, so the
pre-call gate conditions on what has ALREADY been spent. The bound that follows is stated plainly
and tested: an agent can exceed its budget by at most the cost of the single action that crossed the
line. Estimating the pending call's tokens would tighten that slightly while introducing a
provider-specific number the operator cannot verify and an agent can shape its prompt to evade — a
verifiable bound beats a fragile tighter one.

WHY AN UNCONFIGURED AGENT IS NOT OVER BUDGET. No budget row means no limit was set. Reporting a
used-ratio of 1.0 there would deny every action in a deployment that never opted into budgets —
turning a feature nobody configured into a fleet-wide outage. Absence of a budget is not evidence of
a breach.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select

from agentos_controlplane.store.models import AgentBudget, CostRecord

_MICRO = 1_000_000


@dataclass(frozen=True)
class CostPosture:
    """What the decision path needs to know about an agent's spend."""

    spend_usd: float
    budget_used_ratio: float  # 0.0 when no budget is configured — see the module docstring


def _window_start(period: str, now: datetime) -> datetime | None:
    """The inclusive lower bound of the current window; None for 'total' (all history)."""
    if period == "day":
        return now.replace(hour=0, minute=0, second=0, microsecond=0)
    if period == "month":
        return now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    return None


class BudgetLedger:
    """In-memory per-agent spend, converged from the cost table."""

    def __init__(self, session_factory) -> None:
        self._sf = session_factory
        self._spend: dict[str, int] = {}          # agent -> micro-USD in the current window
        self._budgets: dict[str, tuple[str, int]] = {}  # agent -> (period, limit_micro_usd)

    def posture_for(self, agent_id: str) -> CostPosture:
        """Hot path. Dict reads only — no DB, no I/O. Never raises: a ledger failure must not be
        able to take down the decision pipeline that consults it."""
        spend = self._spend.get(agent_id, 0)
        budget = self._budgets.get(agent_id)
        limit = budget[1] if budget else 0
        return CostPosture(
            spend_usd=spend / _MICRO,
            budget_used_ratio=(spend / limit) if limit > 0 else 0.0,
        )

    def note_spend(self, agent_id: str, micro_usd: int | None) -> None:
        """Increment the in-memory total as a cost lands. None (unpriced) adds nothing — an unpriced
        action consumed tokens we cannot convert to dollars, and inventing a figure to keep the
        budget moving would be exactly the fabrication ECON-01 refuses."""
        if micro_usd:
            self._spend[agent_id] = self._spend.get(agent_id, 0) + micro_usd

    def reload(self) -> int:
        """Converge cache from the tables. Returns the number of agents whose posture CHANGED
        (API-04: zero means converged)."""
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        with self._sf() as s:
            budgets = {b.agent_id: (b.period, b.limit_micro_usd) for b in s.scalars(select(AgentBudget)).all()}
            spend: dict[str, int] = {}
            # One grouped query per distinct period, not one per agent: the number of periods is 3.
            for period in {p for p, _ in budgets.values()} | {"day"}:
                start = _window_start(period, now)
                q = select(CostRecord.agent_id, func.sum(CostRecord.cost_micro_usd)).group_by(
                    CostRecord.agent_id
                )
                if start is not None:
                    q = q.where(CostRecord.recorded_at >= start)
                for agent_id, total in s.execute(q).all():
                    if budgets.get(agent_id, ("day", 0))[0] == period:
                        spend[agent_id] = int(total or 0)
        changed = sum(
            1
            for a in set(spend) | set(self._spend) | set(budgets) | set(self._budgets)
            if spend.get(a, 0) != self._spend.get(a, 0) or budgets.get(a) != self._budgets.get(a)
        )
        self._spend, self._budgets = spend, budgets
        return changed

    def set_budget(self, agent_id: str, *, limit_micro_usd: int, period: str = "day") -> None:
        with self._sf() as s:
            row = s.get(AgentBudget, agent_id)
            if row is None:
                s.add(AgentBudget(agent_id=agent_id, period=period, limit_micro_usd=limit_micro_usd))
            else:
                row.period, row.limit_micro_usd, row.version = period, limit_micro_usd, row.version + 1
            s.commit()
        self._budgets[agent_id] = (period, limit_micro_usd)

    def list_budgets(self) -> list[dict]:
        with self._sf() as s:
            rows = s.scalars(select(AgentBudget).order_by(AgentBudget.agent_id)).all()
            out = []
            for r in rows:
                p = self.posture_for(r.agent_id)
                out.append(
                    {
                        "agent_id": r.agent_id,
                        "period": r.period,
                        "limit_micro_usd": r.limit_micro_usd,
                        "spend_usd": p.spend_usd,
                        "budget_used_ratio": p.budget_used_ratio,
                        "version": r.version,
                    }
                )
            return out


class BudgetReconciler:
    """API-04 reconciler over the ledger. Reports items CHANGED (zero == converged)."""

    name = "budget"

    def __init__(self, ledger: BudgetLedger) -> None:
        self._ledger = ledger

    async def reconcile(self) -> int:
        import asyncio

        # Blocking DB I/O — off the loop, exactly like the Phase-7 reconcilers.
        return await asyncio.to_thread(self._ledger.reload)
```

`CostRecorder.__init__` gains `ledger: BudgetLedger | None = None`; after the commit in `record()`:
```python
        if self._ledger is not None:
            self._ledger.note_spend(action.agent_id, cost)
```

- [ ] **Step 1: Write the failing tests**

```python
def test_an_agent_with_no_budget_is_not_over_budget(store) -> None:
    """The whole-fleet-outage guard. A feature nobody configured must not deny anything."""
    ledger = BudgetLedger(store)
    ledger.reload()
    p = ledger.posture_for("never-configured")
    assert p.budget_used_ratio == 0.0 and p.spend_usd == 0.0


def test_spend_accumulates_against_the_configured_limit(store) -> None:
    ledger = BudgetLedger(store)
    ledger.set_budget("a1", limit_micro_usd=10_000_000)   # $10
    ledger.note_spend("a1", 2_500_000)                     # $2.50
    p = ledger.posture_for("a1")
    assert p.spend_usd == 2.5 and p.budget_used_ratio == 0.25


def test_unpriced_spend_moves_nothing(store) -> None:
    """An unpriced action consumed tokens we cannot convert. Inventing a figure to keep the budget
    moving is the fabrication ECON-01 exists to refuse."""
    ledger = BudgetLedger(store)
    ledger.set_budget("a1", limit_micro_usd=1_000_000)
    ledger.note_spend("a1", None)
    assert ledger.posture_for("a1").budget_used_ratio == 0.0


def test_posture_for_touches_no_database(store) -> None:
    """PIPE-04: this runs on EVERY action. A DB round-trip here would put a query on the hot path of
    every governed call in the fleet."""
    ledger = BudgetLedger(store)
    ledger.set_budget("a1", limit_micro_usd=1_000_000)
    ledger.note_spend("a1", 500_000)

    def explode(*a, **k):
        raise AssertionError("posture_for must not open a session")

    ledger._sf = explode
    assert ledger.posture_for("a1").budget_used_ratio == 0.5


def test_reload_converges_from_the_cost_table_and_reports_zero_when_settled(store) -> None:
    """API-04 semantics: a reconciler that always reports work makes a converged system
    indistinguishable from a broken one."""
    ledger = BudgetLedger(store)
    ledger.set_budget("a1", limit_micro_usd=10_000_000)
    _seed_cost(store, "a1", 3_000_000)
    assert ledger.reload() >= 1
    assert ledger.posture_for("a1").spend_usd == 3.0
    assert ledger.reload() == 0


@pytest.mark.asyncio
async def test_the_recorder_moves_the_ledger(store) -> None:
    ledger = BudgetLedger(store)
    ledger.set_budget("a1", limit_micro_usd=10_000_000)
    rec = CostRecorder(store, AuditWriter(store), PriceBook({"gpt-4o": (2.5, 10.0)}, version="v"), ledger=ledger)
    await rec.record(_action(), _decision(), Usage(1000, 500, "gpt-4o"))
    assert ledger.posture_for("a1").spend_usd == 7.5
```

Write `_seed_cost(store, agent, micro)` inserting a `CostRecord` directly.

- [ ] **Step 2: Run → fails.** **Step 3: Implement.** **Step 4: Run → passes.**
- [ ] **Step 5: Commit** `feat(controlplane): BudgetLedger + reconciler — cached spend off the hot path (ECON-02)`.

---

### Task 3: the policy-input fields and the numeric operator path

**Files:** modify `packages/contract/src/agentos_contract/policy_io.py`,
`packages/pipeline/src/agentos_pipeline/policy_input.py`,
`packages/pipeline/src/agentos_pipeline/runner.py`; test `tests/unit/test_budget.py`,
`tests/integration/test_budget_policy.py`.

In `POLICY_INPUT_FIELDS`, added in the file's existing lockstep style:
```python
    # ECON-02 economics fields — the FIRST numeric fields in this registry, so they are also the
    # first live consumers of the gte/lte operators. Added in lockstep with the builder below
    # (drift-locked by test_builder_emits_exactly_the_registry_fields_for_every_type).
    "cost.spend_usd": (float, "all"),           # accumulated spend in the agent's budget window
    "cost.budget_used_ratio": (float, "all"),   # 0.0 when NO budget is configured (not a breach)
```

In `build_policy_input`, add the parameter and the doc section:
```python
def build_policy_input(
    action: AgentAction,
    enrichment: Enrichment,
    sequence_matched_refs: tuple[str, ...] = (),
    cost: "CostPostureLike | None" = None,
) -> dict:
    ...
        # ECON-02: accumulated spend, so a principle can gate on budget through the SAME floor
        # machinery as everything else. Absent ledger -> zeros, which is "no budget configured",
        # never "over budget": a deployment that has not opted into budgets must not be denied by
        # the mere presence of the fields.
        "cost": {
            "spend_usd": float(getattr(cost, "spend_usd", 0.0)),
            "budget_used_ratio": float(getattr(cost, "budget_used_ratio", 0.0)),
        },
```

In `runner.py`, a `budget` collaborator (structural, None-default, appended last in `__init__`), and
at the stage-3 call site (runner.py:659-662):
```python
        # ECON-02: accumulated spend enters as policy input, so a budget breach is a policy floor
        # like any other — explainable, auditable, and subject to the same floor invariant. NOT a
        # parallel enforcer. The lookup is an in-memory dict read (BudgetLedger.posture_for).
        cost_posture = self._budget.posture_for(action.agent_id) if self._budget is not None else None
        res = self._policy.evaluate(
            build_policy_input(action, enrichment, sequence_matched_refs=sequence_refs, cost=cost_posture)
        )
```

- [ ] **Step 1: Write the failing tests**

```python
def test_the_numeric_operator_path_works_end_to_end(tmp_path) -> None:
    """gte/lte have existed in the schema and compiler since Phase 3 with NO numeric field to act
    on, so this is their first real exercise. Compile a real constitution and evaluate it."""
    yaml_text = """
schema_version: 1
name: budget-probe
principles:
  - id: "9.1"
    title: Over budget
    statement: An agent that has spent its budget may not act.
    effect: deny
    when: {field: cost.budget_used_ratio, op: gte, value: 1.0}
"""
    engine = _compile(yaml_text, tmp_path)     # mirror tests/integration/test_policy_engine*.py
    over = _policy_input(cost_ratio=1.0)
    under = _policy_input(cost_ratio=0.99)
    assert select_floor(engine.evaluate(over).matched) is Outcome.deny
    assert engine.evaluate(under).matched == ()


def test_the_negated_numeric_leaf_inverts_correctly(tmp_path) -> None:
    """compiler.py:86 maps gte->lt and lte->gt under a not: node. Nothing has ever exercised it, and
    an inverted comparison would deny exactly the actions it should permit."""
    yaml_text = """
schema_version: 1
name: budget-probe-negated
principles:
  - id: "9.2"
    title: Under budget proceeds
    statement: An agent below its budget proceeds.
    effect: warn
    when: {not: {field: cost.budget_used_ratio, op: gte, value: 1.0}}
"""
    engine = _compile(yaml_text, tmp_path)
    assert select_floor(engine.evaluate(_policy_input(cost_ratio=0.5)).matched) is Outcome.warn
    assert engine.evaluate(_policy_input(cost_ratio=1.0)).matched == ()


def test_the_builder_emits_cost_for_every_action_type() -> None:
    """The registry/builder lockstep the existing drift test enforces."""
    for t in ActionType:
        doc = build_policy_input(_action_of(t), _empty_enrichment())
        assert doc["cost"] == {"spend_usd": 0.0, "budget_used_ratio": 0.0}


def test_an_absent_ledger_reads_as_no_budget_not_as_over_budget() -> None:
    doc = build_policy_input(_action_of(ActionType.tool_call), _empty_enrichment(), cost=None)
    assert doc["cost"]["budget_used_ratio"] == 0.0
```

Run the existing drift-lock test explicitly — it is the thing that catches a registry/builder
mismatch: `./.venv/Scripts/python.exe -m pytest -q -k builder_emits_exactly_the_registry_fields`.

- [ ] **Step 2: Run → fails.** **Step 3: Implement.** **Step 4: Run → passes** + `-m latency`.
- [ ] **Step 5: Commit** `feat(pipeline): cost.* policy-input fields — budget enters the decision (ECON-02)`.

---

### Task 4: the shipped principle, the regression lock, the API, and the full gate

**Files:** modify `policies/constitution.yaml`, `.../api.py`; test
`tests/integration/test_budget_policy.py`.

Add to `policies/constitution.yaml`, in the file's existing voice:
```yaml
  - id: "5.1"
    title: Spending beyond budget requires approval
    statement: An agent that has consumed its budget may not continue spending without human approval.
    effect: require_approval
    when: {field: cost.budget_used_ratio, op: gte, value: 1.0}
    remediation:
      - Raise the agent's budget, or approve this action explicitly.
      - Investigate why the agent consumed its budget — a runaway loop spends faster than a task.
  - id: "5.2"
    title: Approaching budget proceeds under governance review
    statement: An agent that has consumed most of its budget proceeds, but is opened for asynchronous governance review.
    effect: governance_review
    when: {field: cost.budget_used_ratio, op: gte, value: 0.8}
```

**Why `require_approval` and not `deny` for 5.1:** a hard deny on a budget boundary strands work that
may be one call from completing, with no path forward but an operator editing policy. Approval keeps
a human in the loop and produces an audit trail of who authorized the overspend. An operator who
wants a hard stop changes one word — which is the point of expressing this as policy.

- [ ] **Step 1: Write the failing tests** (`tests/integration/test_budget_policy.py`)

```python
@pytest.mark.regression_lock
@pytest.mark.asyncio
async def test_an_over_budget_action_is_escalated_by_the_graduated_engine(pipeline_with_budget) -> None:
    """ECON-02's core claim. Note WHAT is asserted: the outcome carries a POLICY reason naming the
    principle — proving the constitution did this, not a budget enforcer running beside it."""
    pipeline, ledger = pipeline_with_budget
    ledger.set_budget("a1", limit_micro_usd=1_000_000)
    ledger.note_spend("a1", 1_200_000)
    decision = await pipeline.evaluate(_action("a1"))
    assert decision.outcome is Outcome.require_approval
    assert any(r.stage == "policy" and "5.1" in (r.detail or "") for r in decision.reasons)


@pytest.mark.regression_lock
@pytest.mark.asyncio
async def test_removing_the_principle_flips_the_over_budget_action_to_allow(pipeline_no_budget_principle) -> None:
    """The D-04-style CI lock: if the constitution is what enforces the budget, deleting the
    principle must let the over-budget action through. If it still blocks, something ELSE is
    enforcing — a parallel enforcer is exactly what ECON-02 forbids."""
    pipeline, ledger = pipeline_no_budget_principle
    ledger.set_budget("a1", limit_micro_usd=1_000_000)
    ledger.note_spend("a1", 5_000_000)
    assert (await pipeline.evaluate(_action("a1"))).outcome is Outcome.allow


@pytest.mark.asyncio
async def test_an_agent_with_no_budget_configured_is_unaffected(pipeline_with_budget) -> None:
    pipeline, _ = pipeline_with_budget
    assert (await pipeline.evaluate(_action("never-configured"))).outcome is Outcome.allow


@pytest.mark.asyncio
async def test_overshoot_is_bounded_to_one_action(pipeline_with_budget, store) -> None:
    """The honest bound from the design, asserted rather than asserted-in-prose: the action that
    CROSSES the line completes, and the next one is stopped."""
    pipeline, ledger = pipeline_with_budget
    ledger.set_budget("a1", limit_micro_usd=1_000_000)
    ledger.note_spend("a1", 999_999)
    assert (await pipeline.evaluate(_action("a1"))).outcome is Outcome.allow   # crosses
    ledger.note_spend("a1", 500_000)
    assert (await pipeline.evaluate(_action("a1"))).outcome is Outcome.require_approval  # stopped


@pytest.mark.floor_invariant
@pytest.mark.asyncio
async def test_the_budget_floor_is_never_relaxed_by_trust(pipeline_with_budget) -> None:
    """POL-05/TRST-02: a policy floor is terminal. A highly trusted agent must not spend past its
    budget just because it is trusted."""
    pipeline, ledger = pipeline_with_budget
    ledger.set_budget("a1", limit_micro_usd=1_000_000)
    ledger.note_spend("a1", 9_000_000)
    decision = await pipeline.evaluate(_action("a1", trust=0.99))
    assert decision.outcome is Outcome.require_approval
```

Build the fixtures by mirroring the existing constitution-driven integration tests
(`tests/integration/test_policy_engine*.py`, and the D-04 lock in the Phase-1 tests for the
delete-the-principle shape). Reuse those fixtures; do not invent a new harness.

**API.** Append `budget: "BudgetLedger | None" = None` LAST to `build_inventory_router` and
`create_app`:
```python
    @router.get("/economics/budgets")
    def list_budgets() -> list[dict]:
        if budget is None:
            raise HTTPException(status_code=404, detail="budgets are not wired")
        return budget.list_budgets()

    @router.put("/economics/budgets/{agent_id}")
    def set_budget(agent_id: str, body: dict) -> dict:
        """ECON-02 — set an agent's spending limit. Gated: raising a budget is a privileged act."""
        if budget is None:
            raise HTTPException(status_code=404, detail="budgets are not wired")
        try:
            limit = int(body["limit_micro_usd"])
            period = str(body.get("period", "day"))
        except (KeyError, TypeError, ValueError) as exc:
            raise HTTPException(status_code=422, detail="limit_micro_usd (int) is required") from exc
        if limit < 0 or period not in {"day", "month", "total"}:
            raise HTTPException(status_code=422, detail="invalid limit or period")
        budget.set_budget(agent_id, limit_micro_usd=limit, period=period)
        return {"agent_id": agent_id, "limit_micro_usd": limit, "period": period}
```

- [ ] **Step 2: Run → fails.** **Step 3: Implement.**
- [ ] **Step 4: Run → passes**, then the FULL gate: `pytest -q`, `-m floor_invariant`,
  `-m regression_lock`, `-m latency`, the coverage check, the alembic single-head check.
- [ ] **Step 5: Commit** `feat(controlplane): budget principle + gated budget API (ECON-02)`.

## Self-review

ECON-02 asks for two things and both are asserted, not assumed. **"Expressed as policy"** — the
fields go through `POLICY_INPUT_FIELDS`, a principle in the shipped constitution conditions on them,
and the regression lock proves it by *deleting the principle and requiring the block to disappear*.
If anything else were enforcing the budget, that test would fail, which is exactly how a parallel
enforcer would be caught. **"Denied/escalated by the graduated-response engine"** — the outcome
carries a `policy`-stage reason naming principle 5.1, and a floor-invariant test proves high trust
cannot relax it.

The hot-path risk is handled by construction and tested directly: `posture_for` is a dict read, and a
test replaces the session factory with a function that raises to prove no session is opened.

Three honest limits are documented in the module docstring rather than glossed: overshoot is bounded
by one action's cost (asserted by a test, not just prose); a multi-process deployment's fleet-wide
figure lags between reconciles, widening that window with the reconcile interval as the operator's
dial; and unpriced spend moves the ledger by nothing, because inventing a dollar figure to keep the
budget advancing is the same fabrication ECON-01 refuses.
