# Phase 11 · Slice 11b — Cost Attribution (ECON-01) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Commits end
> with a second `-m "Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"`. Tests:
> `./.venv/Scripts/python.exe -m pytest`. TDD per task, one commit each. Gates `floor_invariant`
> + `regression_lock` green at every commit. `-m latency` matters here — this slice adds work to the
> execution path. Re-run when idle before claiming a regression; NEVER loosen the budget.

**Goal (ECON-01):** Attribute token/API cost to each agent and each action, from what the provider
actually reported — so an operator can answer "what did this agent cost me, and on which actions?"
with evidence rather than an estimate.

**Architecture:** A `CostMeter` seam injected into `governed_call` alongside `governor`/`reporter`,
applied at `_run_reported` — **the one site every PEP form already funnels through**. A second
recording path would let the gateway and the SDK disagree about what an agent spent. `UsageExtractor`
reads usage off the returned object and returns `None` when the shape is unrecognized (spec D-7:
never fabricate a number). `PriceBook` is operator-supplied and versioned; an unpriced model records
**tokens with no dollar figure**, never a guessed rate. Money is stored as integer **micro-USD**.

**Tech Stack:** SQLAlchemy 2.0 + Alembic, FastAPI, pytest. No new dependency.

## Verified external facts (introspected 2026-08-18 against the installed packages, not docs)

- `langchain_core.messages.AIMessage.usage_metadata` is a **dict** with required int keys
  `input_tokens`, `output_tokens`, `total_tokens` (plus optional `*_token_details`). It is `None`
  when the provider reported nothing.
- `agents.usage.Usage` (openai-agents 0.20.0) is a **dataclass** with `input_tokens`,
  `output_tokens`, `total_tokens`, `requests`.
- The two agree on the field NAMES, which is why one extractor handles both by duck-typing
  (mapping key first, then attribute) instead of two provider-specific branches.

> First commit in this slice: `docs(phase-11): Slice 11b plan` for this file, then the tasks below.

## File structure
- Create `.../agentos_controlplane/economics.py` — `UsageExtractor`, `PriceBook`, `CostRecorder`.
- Modify `.../store/models.py` — `CostRecord`.
- Create `.../store/migrations/versions/0024_cost_record.py` (down_revision `0023_merkle_root`).
- Modify `.../audit.py` — `EVENT_KINDS += "cost_recorded"`.
- Modify `packages/sdk/src/agentos_sdk/enforce.py` — the `CostMeter` Protocol + `meter=` kwarg.
- Modify `.../sdk/middleware.py`, `.../sdk/wrappers.py`, `.../sdk/adapters/openai_agents.py`,
  `packages/gateway/src/agentos_gateway/app.py` — thread `meter` through every PEP form.
- Modify `.../api.py` — read routes on the gated inventory router.
- Tests: `tests/unit/test_economics.py`, `tests/integration/test_economics_api.py`.

---

### Task 1: `CostRecord` table + migration 0024 + event kind

**Files:** modify `.../store/models.py`, `.../audit.py`; create the migration; test
`tests/unit/test_economics.py` (round-trip portion).

```python
class CostRecord(Base):
    """ECON-01 — what one action actually cost, attributed to one agent.

    Money is INTEGER micro-USD, not a float. Floating-point money accumulates representation error
    across a sum, and a budget decision (Slice 11c) made on a drifting total is a decision the
    operator cannot reproduce. Integers also mean the same value round-trips identically through
    SQLite and Postgres, which a NUMERIC would not.

    `cost_micro_usd` is NULLABLE and stays null when the model is unpriced: tokens are a fact we
    observed, dollars are a conversion we can only do with a rate the operator gave us. Writing a
    zero there would read as 'this action was free'.

    `price_book_version` pins WHICH rates produced the figure, so a bill can be re-derived — and so
    a rate correction does not silently rewrite history.
    """

    __tablename__ = "cost_record"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    action_id: Mapped[UUID] = mapped_column(Uuid, nullable=False, index=True)
    agent_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    action_type: Mapped[str] = mapped_column(String(32), nullable=False)
    model: Mapped[str | None] = mapped_column(String(128), nullable=True)
    input_tokens: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    output_tokens: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    cost_micro_usd: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    price_book_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )
```

`audit.py`, inside `EVENT_KINDS`, in the file's comment style:
```python
        # ECON-01 (Slice 11b): what an action cost. Short identifiers + numbers only — never the
        # prompt that produced the tokens.
        "cost_recorded",
```

Migration `0024_cost_record.py` (`revision = "0024_cost_record"`, `down_revision = "0023_merkle_root"`),
house-style docstring explaining WHY integer micro-USD and why the nullable cost. Columns exactly as
the model; indexes on `action_id`, `agent_id`, `recorded_at` (the 11c ledger sums by agent over a
time window, and an unindexed scan of the cost table on the read path would be the slow query that
eventually gets blamed on the pipeline). `downgrade` drops the table.

- [ ] **Step 1: Write the failing test**

```python
"""ECON-01 — cost attribution: what an action cost, attributed to an agent."""
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.pool import StaticPool

from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.store.engine import create_session_factory
from agentos_controlplane.store.models import Base, CostRecord


@pytest.fixture()
def store():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return create_session_factory(engine)


def test_cost_record_round_trips_with_an_unpriced_model(store) -> None:
    """The unpriced case is the DEFAULT, not an edge case: an operator who has not supplied rates
    must still get token attribution, and must not be shown a fabricated dollar figure."""
    from uuid import uuid4

    with store() as s:
        s.add(
            CostRecord(
                action_id=uuid4(),
                agent_id="a1",
                action_type="model_invocation",
                model="some-unpriced-model",
                input_tokens=100,
                output_tokens=20,
            )
        )
        s.commit()
    with store() as s:
        row = s.scalars(select(CostRecord)).one()
    assert (row.input_tokens, row.output_tokens) == (100, 20)
    assert row.cost_micro_usd is None and row.price_book_version is None


@pytest.mark.asyncio
async def test_the_cost_event_kind_is_accepted_and_unknown_kinds_are_not(store) -> None:
    audit = AuditWriter(store)
    await audit.append_event("cost_recorded", {"agent": "a1", "input_tokens": 1, "output_tokens": 1})
    with pytest.raises(Exception):
        await audit.append_event("cost_definitely_not_a_kind", {})
```

- [ ] **Step 2: Run to verify it fails**

Run: `./.venv/Scripts/python.exe -m pytest tests/unit/test_economics.py -q`
Expected: FAIL — `ImportError: cannot import name 'CostRecord'`.

- [ ] **Step 3: Add the model, event kind, and migration** (above).

- [ ] **Step 4: Run to verify it passes + single head**

Run: `./.venv/Scripts/python.exe -m pytest tests/unit/test_economics.py -q`
Expected: PASS.
Run the alembic head one-liner from the 11a plan. Expected: `['0024_cost_record']`.

- [ ] **Step 5: Commit**

```bash
git add packages/controlplane/src/agentos_controlplane/store/models.py packages/controlplane/src/agentos_controlplane/audit.py packages/controlplane/src/agentos_controlplane/store/migrations/versions/0024_cost_record.py tests/unit/test_economics.py
git commit -m "feat(controlplane): cost_record table + event kind + migration 0024 (ECON-01)" -m "Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: `UsageExtractor` + `PriceBook` + `CostRecorder`

**Files:** create `.../agentos_controlplane/economics.py`; test `tests/unit/test_economics.py`.

```python
"""ECON-01 — cost attribution. What did this agent cost, on which actions?

WHY IT IS SHAPED THIS WAY.

Usage is REPORTED, never inferred. `UsageExtractor` reads what the provider actually returned and
gives back None when it recognizes nothing. The tempting alternative — estimate tokens by counting
characters — produces a number that looks authoritative, is provider-specific, and is wrong in ways
the operator cannot see. An absent figure is a fact ('we do not know'); a fabricated one is a lie
that will eventually appear on a budget decision or a compliance export.

Dollars are a CONVERSION, not an observation. Tokens we saw; the rate is something the operator
tells us. So the PriceBook is supplied and versioned, an unpriced model records tokens with a null
cost, and every priced record pins the rate version that produced it — a later rate correction must
not silently rewrite what an old action reportedly cost.

Money is integer micro-USD. Float money drifts across a sum, and Slice 11c makes budget DECISIONS on
that sum.
"""
from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import func, select

from agentos_contract import AgentAction, Decision
from agentos_controlplane.store.models import CostRecord

_MICRO = 1_000_000


@dataclass(frozen=True)
class Usage:
    """What the provider reported for one call."""

    input_tokens: int
    output_tokens: int
    model: str | None = None


def _field(obj: object, name: str) -> object | None:
    """Read `name` from a mapping key or an attribute.

    LangChain reports usage as a dict (`AIMessage.usage_metadata`) and the OpenAI Agents SDK as a
    dataclass (`agents.usage.Usage`); both use the same field names. One duck-typed reader beats two
    provider-specific branches that drift apart the first time a third framework lands.
    """
    if isinstance(obj, dict):
        return obj.get(name)
    return getattr(obj, name, None)


def extract_usage(result: object) -> Usage | None:
    """Pull reported usage off a returned object, or None when nothing recognizable is there.

    Returning None is the load-bearing behavior: a caller must be able to tell 'no usage reported'
    from 'zero tokens used', because only one of those means the action was free.
    """
    for holder in (
        _field(result, "usage_metadata"),   # LangChain AIMessage
        _field(result, "usage"),            # OpenAI Agents RunResult / raw response
        result,                             # a Usage-shaped object passed directly
    ):
        if holder is None:
            continue
        inp, out = _field(holder, "input_tokens"), _field(holder, "output_tokens")
        if isinstance(inp, int) and isinstance(out, int):
            meta = _field(result, "response_metadata")
            model = _field(meta, "model_name") or _field(meta, "model") if meta else None
            return Usage(input_tokens=inp, output_tokens=out, model=model if isinstance(model, str) else None)
    return None


class PriceBook:
    """Operator-supplied token rates, versioned. `rates` maps model name -> (usd_per_1k_input,
    usd_per_1k_output). A model that is not in the book is UNPRICED — tokens only."""

    def __init__(self, rates: dict[str, tuple[float, float]] | None = None, *, version: str = "unset") -> None:
        self._rates = dict(rates or {})
        self.version = version

    def cost_micro_usd(self, model: str | None, input_tokens: int, output_tokens: int) -> int | None:
        """Micro-USD for this usage, or None when the model is unpriced."""
        rate = self._rates.get(model or "")
        if rate is None:
            return None
        usd = (input_tokens / 1000.0) * rate[0] + (output_tokens / 1000.0) * rate[1]
        return round(usd * _MICRO)


class CostRecorder:
    """The concrete `CostMeter` (the SDK-side Protocol). Persists + audits one action's cost."""

    def __init__(self, session_factory, audit, price_book: PriceBook | None = None) -> None:
        self._sf = session_factory
        self._audit = audit
        self._prices = price_book or PriceBook()

    async def record(self, action: AgentAction, decision: Decision, usage: Usage) -> None:
        """Attribute `usage` to `action.agent_id`. Called only after a SUCCESSFUL run."""
        model = usage.model or str((action.payload or {}).get("model") or "") or None
        cost = self._prices.cost_micro_usd(model, usage.input_tokens, usage.output_tokens)
        with self._sf() as s:
            s.add(
                CostRecord(
                    action_id=action.id,
                    agent_id=action.agent_id,
                    action_type=action.type.value,
                    model=model,
                    input_tokens=usage.input_tokens,
                    output_tokens=usage.output_tokens,
                    cost_micro_usd=cost,
                    price_book_version=self._prices.version if cost is not None else None,
                )
            )
            s.commit()
        await self._audit.append_event(
            "cost_recorded",
            {
                "action_id": str(action.id),
                "agent": action.agent_id,
                "model": model,
                "input_tokens": usage.input_tokens,
                "output_tokens": usage.output_tokens,
                "cost_micro_usd": cost,
            },
        )

    def totals(self) -> list[dict]:
        """Per-agent roll-up. Tokens and dollars are summed SEPARATELY and dollars may cover fewer
        actions than tokens — an operator reading a total must be able to see that some actions were
        unpriced rather than assume the dollar figure is complete."""
        with self._sf() as s:
            rows = s.execute(
                select(
                    CostRecord.agent_id,
                    func.count().label("actions"),
                    func.sum(CostRecord.input_tokens),
                    func.sum(CostRecord.output_tokens),
                    func.sum(CostRecord.cost_micro_usd),
                    func.count(CostRecord.cost_micro_usd).label("priced_actions"),
                )
                .group_by(CostRecord.agent_id)
                .order_by(CostRecord.agent_id)
            ).all()
        return [
            {
                "agent_id": r[0],
                "actions": r[1],
                "input_tokens": int(r[2] or 0),
                "output_tokens": int(r[3] or 0),
                "cost_micro_usd": int(r[4] or 0),
                "priced_actions": r[5],
                "unpriced_actions": r[1] - r[5],
            }
            for r in rows
        ]

    def for_agent(self, agent_id: str, limit: int = 200) -> list[dict]:
        with self._sf() as s:
            rows = s.scalars(
                select(CostRecord)
                .where(CostRecord.agent_id == agent_id)
                .order_by(CostRecord.recorded_at.desc())
                .limit(limit)
            ).all()
            return [
                {
                    "action_id": str(r.action_id),
                    "action_type": r.action_type,
                    "model": r.model,
                    "input_tokens": r.input_tokens,
                    "output_tokens": r.output_tokens,
                    "cost_micro_usd": r.cost_micro_usd,
                    "price_book_version": r.price_book_version,
                    "recorded_at": r.recorded_at.isoformat() if r.recorded_at else None,
                }
                for r in rows
            ]
```

- [ ] **Step 1: Write the failing tests**

```python
from agentos_contract import ActionType, AgentAction
from agentos_controlplane.economics import CostRecorder, PriceBook, Usage, extract_usage


def _action(agent="a1", model="gpt-4o"):
    return AgentAction(
        agent_id=agent, type=ActionType.model_invocation, target="chat",
        payload={"model": model, "messages": [{"role": "user", "content": "hi"}]},
    )


def test_usage_is_extracted_from_a_langchain_message() -> None:
    from langchain_core.messages import AIMessage

    msg = AIMessage(content="ok", usage_metadata={"input_tokens": 11, "output_tokens": 4, "total_tokens": 15})
    assert extract_usage(msg) == Usage(input_tokens=11, output_tokens=4, model=None)


def test_usage_is_extracted_from_an_openai_agents_usage_object() -> None:
    """Same extractor, no provider branch — the two SDKs agree on the field names."""
    from agents.usage import Usage as AgentsUsage

    holder = type("R", (), {"usage": AgentsUsage(requests=1, input_tokens=7, output_tokens=3, total_tokens=10)})()
    got = extract_usage(holder)
    assert (got.input_tokens, got.output_tokens) == (7, 3)


def test_an_unrecognized_result_yields_None_not_zero() -> None:
    """THE property that keeps the ledger honest. Zero means 'this was free'; None means 'we do not
    know'. Collapsing them would put fabricated free actions into a budget decision and a
    compliance export."""
    assert extract_usage("just a string") is None
    assert extract_usage({"nothing": "useful"}) is None
    assert extract_usage(None) is None
    assert extract_usage(type("R", (), {"usage_metadata": {"input_tokens": "eleven"}})()) is None


def test_pricing_is_exact_in_integer_micro_usd() -> None:
    book = PriceBook({"gpt-4o": (2.50, 10.00)}, version="2026-08")
    # 1000 in @ $2.50/1k + 500 out @ $10.00/1k = $2.50 + $5.00 = $7.50
    assert book.cost_micro_usd("gpt-4o", 1000, 500) == 7_500_000


def test_an_unpriced_model_costs_None_not_zero() -> None:
    book = PriceBook({"gpt-4o": (2.5, 10.0)}, version="2026-08")
    assert book.cost_micro_usd("some-other-model", 1000, 500) is None
    assert book.cost_micro_usd(None, 1000, 500) is None


@pytest.mark.asyncio
async def test_recording_attributes_cost_to_the_agent_and_the_action(store) -> None:
    audit = AuditWriter(store)
    rec = CostRecorder(store, audit, PriceBook({"gpt-4o": (2.5, 10.0)}, version="2026-08"))
    action = _action()
    await rec.record(action, _decision(), Usage(input_tokens=1000, output_tokens=500, model="gpt-4o"))
    with store() as s:
        row = s.scalars(select(CostRecord)).one()
    assert row.agent_id == "a1" and row.action_id == action.id
    assert row.cost_micro_usd == 7_500_000 and row.price_book_version == "2026-08"


@pytest.mark.asyncio
async def test_an_unpriced_record_keeps_tokens_and_pins_no_rate_version(store) -> None:
    audit = AuditWriter(store)
    rec = CostRecorder(store, audit, PriceBook({}, version="2026-08"))
    await rec.record(_action(model="mystery"), _decision(), Usage(input_tokens=9, output_tokens=1, model="mystery"))
    with store() as s:
        row = s.scalars(select(CostRecord)).one()
    assert (row.input_tokens, row.output_tokens) == (9, 1)
    assert row.cost_micro_usd is None
    assert row.price_book_version is None, "a rate version on an unpriced row would imply a rate was applied"


@pytest.mark.asyncio
async def test_the_audit_body_carries_no_prompt_text(store) -> None:
    """AUD-04: identifiers and numbers only. The prompt is the thing most worth leaking and it is
    exactly what a cost event does not need."""
    audit = AuditWriter(store)
    rec = CostRecorder(store, audit, PriceBook({"gpt-4o": (2.5, 10.0)}, version="v"))
    action = _action()
    action.payload["messages"] = [{"role": "user", "content": "SECRET-CANARY-TEXT"}]
    await rec.record(action, _decision(), Usage(input_tokens=1, output_tokens=1, model="gpt-4o"))
    from agentos_controlplane.store.models import AuditRecord

    with store() as s:
        blob = json.dumps([r.body for r in s.scalars(select(AuditRecord)).all()])
    assert "SECRET-CANARY-TEXT" not in blob


@pytest.mark.asyncio
async def test_totals_separate_priced_from_unpriced_actions(store) -> None:
    """A dollar total that silently covers only half the actions is a number an operator will
    misread as the whole bill."""
    audit = AuditWriter(store)
    rec = CostRecorder(store, audit, PriceBook({"gpt-4o": (2.5, 10.0)}, version="v"))
    await rec.record(_action(), _decision(), Usage(1000, 500, "gpt-4o"))
    await rec.record(_action(model="mystery"), _decision(), Usage(10, 10, "mystery"))
    t = rec.totals()[0]
    assert t["actions"] == 2 and t["priced_actions"] == 1 and t["unpriced_actions"] == 1
    assert t["input_tokens"] == 1010 and t["cost_micro_usd"] == 7_500_000
```

Add a `_decision()` helper in the test module building a minimal allowed `Decision` (mirror how
`tests/unit/test_circuit_breaker.py` or `tests/unit/test_resource_governor.py` builds one — reuse the
existing pattern, do not invent a new shape), plus `import json`.

- [ ] **Step 2: Run to verify it fails.** Expected: `ModuleNotFoundError: agentos_controlplane.economics`.

- [ ] **Step 3: Implement `economics.py`** (code above).

- [ ] **Step 4: Run to verify it passes.**

- [ ] **Step 5: Commit**

```bash
git add packages/controlplane/src/agentos_controlplane/economics.py tests/unit/test_economics.py
git commit -m "feat(controlplane): UsageExtractor, versioned PriceBook, CostRecorder (ECON-01)" -m "Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: wire the meter into the ONE enforcement seam

**Files:** modify `packages/sdk/src/agentos_sdk/enforce.py`, `middleware.py`, `wrappers.py`,
`adapters/openai_agents.py`, `packages/gateway/src/agentos_gateway/app.py`; test
`tests/unit/test_economics.py`.

In `enforce.py`, next to the other PEP-side seams:

```python
class CostMeter(Protocol):
    """ECON-01 seam (PEP side): attribute what an executed action cost.

    Concrete implementation: `agentos_controlplane.economics.CostRecorder`. Applied at the ONE
    execution site, so every PEP form — LangChain middleware, the async wrappers, the OpenAI Agents
    adapter, the network gateway — attributes cost identically. A second recording path would let
    two PEPs disagree about what the same agent spent, and the disagreement would surface as a
    budget decision nobody can explain.
    """

    async def record(self, action: AgentAction, decision: Decision, usage: "Usage") -> None: ...
```

In `_run_reported`, meter **only a successful run**:

```python
async def _run_reported(run, action, decision, governor, reporter, meter=None):
    try:
        result = await _run_within_limits(run, action, decision, governor)
    except GovernanceResourceExceeded:
        ...unchanged...
    except GovernanceDenied:
        raise
    except Exception:
        ...unchanged...
    if meter is not None:
        # ECON-01: attribute AFTER a successful run and never let metering break the call. A
        # bookkeeping failure must not turn a completed action into an exception the agent sees —
        # the action already happened, and raising here would report a false failure to the RUN-06
        # breaker as well.
        try:
            usage = extract_usage(result)
            if usage is not None:
                await meter.record(action, decision, usage)
        except Exception:
            logging.getLogger(__name__).warning(
                "cost metering failed for action %s", action.id, exc_info=True
            )
    return result
```

**Where `Usage` and `extract_usage` live — resolved, do not re-litigate.** The workspace edges were
read at plan time (`packages/*/pyproject.toml`): `agentos-sdk` depends on `agentos-controlplane`, but
`agentos-controlplane` depends on **`agentos-contract` only**. So the control plane cannot import
from the SDK. The split follows each package's stated purpose:

- **`packages/contract/src/agentos_contract/usage.py`** — the `Usage` value type. Contract is the
  stable serializable boundary both sides already depend on, and a shared value type is exactly what
  belongs there. Export it from `agentos_contract/__init__.py` alongside the other types.
- **`packages/sdk/src/agentos_sdk/usage.py`** — `extract_usage`. Reading a framework's return value
  is PEP-side work by definition (it sits beside `normalize.py`, which does the same job on the way
  in), and it keeps framework-shape knowledge out of the control plane.

Adjust Task 2 accordingly: `economics.py` does `from agentos_contract import Usage` and **never**
imports `extract_usage`; `enforce.py` imports it from `agentos_sdk.usage`. Move the two Task-2 tests
that exercise `extract_usage` into the SDK-facing test module.

Thread `meter` through, appended LAST in each signature so no positional caller shifts:
`GovernanceMiddleware.__init__(..., meter: CostMeter | None = None)` → passed to both
`governed_call` sites; the three `wrappers.py` call sites; the OpenAI Agents adapter;
`agentos_gateway.app` (its governed-call construction).

- [ ] **Step 1: Write the failing tests**

```python
@pytest.mark.asyncio
async def test_an_allowed_action_is_metered_through_governed_call(store) -> None:
    from langchain_core.messages import AIMessage

    from agentos_sdk.enforce import governed_call

    audit = AuditWriter(store)
    rec = CostRecorder(store, audit, PriceBook({"gpt-4o": (2.5, 10.0)}, version="v"))
    msg = AIMessage(content="ok", usage_metadata={"input_tokens": 1000, "output_tokens": 500, "total_tokens": 1500})
    await governed_call(_allow_pipeline(), _action(), lambda: _async(msg), meter=rec)
    with store() as s:
        assert s.scalars(select(CostRecord)).one().cost_micro_usd == 7_500_000


@pytest.mark.asyncio
async def test_a_DENIED_action_is_never_metered(store) -> None:
    """A blocked action ran nothing, so it cost nothing. Metering it would bill an agent for work
    the control plane prevented — and would inflate the very budget that caused the block."""
    from agentos_sdk.enforce import GovernanceDenied, governed_call

    rec = CostRecorder(store, AuditWriter(store), PriceBook({"gpt-4o": (2.5, 10.0)}, version="v"))
    with pytest.raises(GovernanceDenied):
        await governed_call(_deny_pipeline(), _action(), lambda: _async("never"), meter=rec)
    with store() as s:
        assert s.scalars(select(CostRecord)).all() == []


@pytest.mark.asyncio
async def test_a_metering_failure_does_not_break_the_agents_call(store) -> None:
    """The action already succeeded. Raising here would hand the agent a false failure AND report a
    phantom execution error to the RUN-06 breaker."""
    from langchain_core.messages import AIMessage

    from agentos_sdk.enforce import governed_call

    class Broken:
        async def record(self, action, decision, usage):
            raise RuntimeError("ledger down")

    msg = AIMessage(content="ok", usage_metadata={"input_tokens": 1, "output_tokens": 1, "total_tokens": 2})
    assert await governed_call(_allow_pipeline(), _action(), lambda: _async(msg), meter=Broken()) is msg


@pytest.mark.asyncio
async def test_a_result_with_no_usage_records_nothing(store) -> None:
    from agentos_sdk.enforce import governed_call

    rec = CostRecorder(store, AuditWriter(store), PriceBook({}, version="v"))
    await governed_call(_allow_pipeline(), _action(), lambda: _async("plain string"), meter=rec)
    with store() as s:
        assert s.scalars(select(CostRecord)).all() == []
```

Build `_allow_pipeline()` / `_deny_pipeline()` as tiny stubs satisfying `PipelineProtocol` (an
`evaluate` returning an allow/deny `Decision`) — mirror the stubs already used in
`tests/unit/test_enforce*.py`; reuse, do not reinvent. `_async(v)` is
`async def _async(v): return v` adapted to a zero-arg callable.

- [ ] **Step 2: Run to verify it fails.** Expected: `TypeError: governed_call() got an unexpected
  keyword argument 'meter'`.

- [ ] **Step 3: Implement the seam + thread it through all five PEP forms.**

- [ ] **Step 4: Run to verify it passes**, plus `-m latency` (this touched the execution path) and
  the INT-06 coverage check.

- [ ] **Step 5: Commit**

```bash
git add packages/sdk packages/gateway packages/controlplane tests/unit/test_economics.py
git commit -m "feat(sdk): CostMeter seam on the one execution site, threaded through every PEP (ECON-01)" -m "Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: read API + full gate

**Files:** modify `.../api.py`; test `tests/integration/test_economics_api.py`.

Append `cost: "CostRecorder | None" = None` LAST to `build_inventory_router` and `create_app`
(matching DISC-03..06 and 11a), and add:

```python
    @router.get("/economics/costs")
    def cost_totals() -> list[dict]:
        """ECON-01 — per-agent cost roll-up. Gated: what an agent costs is commercial information."""
        if cost is None:
            raise HTTPException(status_code=404, detail="cost attribution is not wired")
        return cost.totals()

    @router.get("/economics/costs/{agent_id}")
    def cost_for_agent(agent_id: str) -> list[dict]:
        if cost is None:
            raise HTTPException(status_code=404, detail="cost attribution is not wired")
        return cost.for_agent(agent_id)
```

- [ ] **Step 1: Failing test** — with a token: `GET /economics/costs` → 200 with the seeded agent's
  roll-up; `GET /economics/costs/a1` → 200 listing its actions; without a token → 401; an app built
  with no `cost` → 404 while `GET /inventory` still returns 200 (backward compat).
- [ ] **Step 2: Run → fails.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run → passes**, then the FULL gate: `pytest -q`, `-m floor_invariant`,
  `-m regression_lock`, `-m latency`, the coverage check, the alembic single-head check.
- [ ] **Step 5: Commit** `feat(controlplane): cost read API (ECON-01)`.

## Self-review

ECON-01 asks for cost attributed to each agent AND each action; `CostRecord` carries both
`agent_id` and `action_id`, and the read API exposes the roll-up and the per-agent detail.

The design's honesty properties each have a test that fails without them: unrecognized usage yields
`None` rather than zero (so 'free' and 'unknown' never collapse), an unpriced model records tokens
with a null cost and NO rate version, totals separate priced from unpriced actions so a partial
dollar figure cannot be misread as the whole bill, and the audit body carries no prompt text.

Metering hangs off `_run_reported` — the single execution site — so all five PEP forms attribute
identically; a denied action is never metered (it ran nothing, and billing it would inflate the very
budget that blocked it); and a metering failure is logged, never raised, because the action already
happened and a raise would both lie to the agent and feed a phantom failure to the RUN-06 breaker.

Package boundaries hold: the workspace edges were read at plan time, so `Usage` lands in
`agentos-contract` (the seam both sides already depend on) and `extract_usage` in the SDK beside
`normalize.py`, which keeps framework-shape knowledge out of the control plane and adds no
dependency in either direction.
