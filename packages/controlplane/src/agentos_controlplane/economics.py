"""ECON-01 — cost attribution. What did this agent cost, on which actions?

WHY IT IS SHAPED THIS WAY.

Usage is REPORTED, never inferred. The PEP-side `agentos_sdk.usage.extract_usage` reads what the
provider actually returned and hands back None when it recognizes nothing; this module never sees an
estimate. An absent figure is a fact ('we do not know'); a fabricated one is a lie that will
eventually appear on a budget decision or a compliance export.

Dollars are a CONVERSION, not an observation. Tokens we saw; the rate is something the operator
tells us. So the PriceBook is supplied and versioned, an unpriced model records tokens with a null
cost, and every priced record pins the rate version that produced it — a later rate correction must
not silently rewrite what an old action reportedly cost.

Money is integer micro-USD. Float money drifts across a sum, and Slice 11c makes budget DECISIONS on
that sum.

ECON-03 adds the two kinds of spend that are not hosted-model tokens: a third-party API the agent
called, and GPU time on the operator's own hardware. Both live on this same row — they are what the
SAME action cost — and both obey the rule above. The provider is the action's own target rather than
an inferred vendor, and a GPU figure never travels without the label saying what it measured.
"""

from __future__ import annotations

from decimal import ROUND_HALF_UP, Decimal

from sqlalchemy import case, func, select

from agentos_contract import ActionType, AgentAction, Decision, Usage
from agentos_controlplane.gpu import (
    DEVICE_SHARED,
    PROCESS,
    GpuReading,
    gpu_metering_available,
    read_gpu,
)
from agentos_controlplane.store.models import CostRecord

# Rates are quoted per 1k tokens; the ledger is in micro-USD. 1e6 / 1e3 = 1e3.
_MICRO_PER_1K_TOKEN_USD = 1000
# `model` is String(128) in the ledger. A name longer than that is already pathological (no provider
# publishes one), but on Postgres — the production target — an over-long value makes the INSERT raise
# and the PEP's metering swallow drops the row entirely. Truncating keeps the row: a clipped name
# will simply not match the price book, so the action records as unpriced rather than not at all.
_MODEL_MAX = 128
# `price_book_version` is String(32). Unlike `model` this is OPERATOR config, not provider data, so
# an over-long value is a typo to reject up front rather than something to quietly truncate.
_VERSION_MAX = 32
# ECON-03: the action types whose `target` IS the downstream service being consumed. A model
# invocation's target is 'chat', not a vendor — writing that into `provider` would invent a service
# that was never called and put the same spend under two headings on one report.
_DOWNSTREAM_TYPES = frozenset({ActionType.tool_call, ActionType.mcp_call})
# `provider` is String(128) and a target can be an arbitrarily long URL. Truncated for the same
# reason `model` is: on Postgres an over-long value makes the INSERT raise into the PEP's swallow and
# the whole cost row disappears. A clipped hostname is a display defect; a missing row is missing money.
_PROVIDER_MAX = 128


class PriceBook:
    """Operator-supplied token rates, versioned. `rates` maps model name -> (usd_per_1k_input,
    usd_per_1k_output). A model that is not in the book is UNPRICED — tokens only.

    Shipping a hardcoded rate table was the rejected alternative: prices change, and a stale
    built-in rate misbills silently while looking exactly as authoritative as a correct one.
    """

    def __init__(
        self, rates: dict[str, tuple[float, float]] | None = None, *, version: str | None = None
    ) -> None:
        if rates and version is None:
            # Rates without a version defeat the pin: every row would carry the same placeholder,
            # so two different rate tables would be indistinguishable on the record and a bill
            # could not be re-derived. An EMPTY book prices nothing, so it needs no version.
            raise ValueError("a PriceBook with rates must name the version those rates come from")
        if version is not None and len(version) > _VERSION_MAX:
            # Refused at CONSTRUCTION, not at the insert. `price_book_version` is String(32): on
            # Postgres an over-long value makes every metered INSERT raise, the PEP swallows each
            # one, and the operator gets a permanently empty ledger with no failed request to
            # explain it. Failing at startup is the difference between a typo and a silent outage.
            raise ValueError(
                f"price book version must be at most {_VERSION_MAX} characters; got {len(version)}"
            )
        for model, rate in (rates or {}).items():
            if rate[0] < 0 or rate[1] < 0:
                # A negative rate is a typo with a governance consequence, not just a wrong bill:
                # ECON-02's ledger sums these, so every priced action would REFUND budget and an
                # agent would spend its way back under its limit. Refused at construction for the
                # same reason as an over-long version — a startup error beats a silent one.
                raise ValueError(f"price book rates must not be negative; {model!r} has {rate}")
        self._rates = dict(rates or {})
        self.version = version or "unset"

    def cost_micro_usd(self, model: str | None, input_tokens: int, output_tokens: int) -> int | None:
        """Micro-USD for this usage, or None when the model is unpriced OR the true cost is too
        small to represent.

        Decimal, not float: `Decimal(str(rate))` prices the number the operator actually wrote, so
        the figure an operator reconciles against an invoice is the one their own rate table
        implies. ROUND_HALF_UP rather than `round()`, whose banker's rule makes 2.5 -> 2 while
        3.5 -> 4 — non-monotonic in the eye of anyone checking the ledger by hand.

        A cost that is genuinely zero (no tokens, or a zero rate) records as 0 and pins its rate
        version. A cost that is NONZERO but under half a micro-USD records as UNPRICED instead:
        cheap-model actions are exactly the ones that arrive in millions, and quantising each one
        to a *priced* 0 would assert "these rates priced this action, and it was free" — the
        fabrication this module exists to refuse. Unpriced says "we cannot represent this", which
        is what `unpriced_actions` then shows the operator.
        """
        rate = self._rates.get(model or "")
        if rate is None:
            return None
        micro = (
            Decimal(input_tokens) * Decimal(str(rate[0]))
            + Decimal(output_tokens) * Decimal(str(rate[1]))
        ) * _MICRO_PER_1K_TOKEN_USD
        if micro == 0:
            return 0
        return int(micro.to_integral_value(rounding=ROUND_HALF_UP)) or None


class CostRecorder:
    """The concrete `CostMeter` (the SDK-side Protocol). Persists + audits one action's cost."""

    def __init__(
        self, session_factory, audit, price_book: PriceBook | None = None, ledger=None
    ) -> None:
        self._sf = session_factory
        self._audit = audit
        self._prices = price_book or PriceBook()
        # ECON-02: the in-memory BudgetLedger, notified as each cost lands so the decision path's
        # spend figure moves without a per-action SQL SUM. None (the ECON-01 deployment that never
        # opted into budgets) means nothing is notified and this class behaves exactly as before.
        self._ledger = ledger
        # ECON-03: resolved ONCE, here, and never per action. Python does not cache a FAILED import,
        # so asking per call would re-walk the entire import path on every governed action in
        # precisely the deployments — the large majority — that own no GPU to meter.
        self._gpu_available = gpu_metering_available()

    def _model_for(self, action: AgentAction, usage: Usage) -> str | None:
        """Which model this action is billed against.

        What the provider SERVED wins over what the action REQUESTED: an alias resolves to a dated
        snapshot that can be priced differently, and the served name is what the bill says.

        The requested-model fallback applies ONLY to a model invocation. `normalize_action` puts a
        tool's own arguments at the top of the payload, so a `tool_call` carrying an argument named
        `model` was being priced at that model's rate — an `http_get` billed $2.50 because the
        attacker named an argument well. A tool call has no model to fall back to; None is correct.
        """
        served = usage.model
        if served is None and action.type is ActionType.model_invocation:
            requested = (action.payload or {}).get("model")
            served = requested if isinstance(requested, str) and requested else None
        return served[:_MODEL_MAX] if served else None

    async def record(
        self, action: AgentAction, decision: Decision, usage: Usage, *, gpu: GpuReading | None = None
    ) -> None:
        """Attribute `usage` to `action.agent_id`. Called only after a SUCCESSFUL run.

        The audit event is appended BEFORE the row is committed, and that order is the point. This
        is two stores, not one transaction, so one of them can fail after the other succeeded — and
        the two failures are not symmetric. An event with no row is a visible reconciliation gap the
        AUD-06 chain can be read against; a committed row with no event is a money figure with no
        evidence behind it, which is precisely what the audit chain exists to make impossible.

        (`decision` is unused, and Slice 11c did NOT turn out to need it either — the budget ledger
        keys on agent and dollars alone, which is the whole of what a spending limit is about. It
        stays in the `CostMeter` Protocol because the seam is where the decision is in hand and an
        operator's own meter may legitimately bill by outcome; dropping a Protocol parameter would
        break those implementers to delete one unused name here.)

        `gpu` is ECON-03's reading, taken here rather than at the `_run_reported` seam. The seam
        would have had to hand it through the `CostMeter` Protocol, breaking every implementer of a
        three-argument `record` to gain nothing: this method is already called exactly once per
        action, immediately after it returned, which is the same moment and the same frequency.
        Callers who genuinely know a figure we cannot measure — a sandbox runner, a cluster
        scheduler that reports real GPU-seconds — pass it explicitly and it wins over the probe.
        """
        model = self._model_for(action, usage)
        cost = self._prices.cost_micro_usd(model, usage.input_tokens, usage.output_tokens)
        # ECON-03: the downstream service consumed is the action's own target, a fact the PEP
        # already normalized — never a vendor inferred from it.
        provider = action.target[:_PROVIDER_MAX] if action.type in _DOWNSTREAM_TYPES else None
        if gpu is None and self._gpu_available:
            gpu = read_gpu()
        body = {
            "action_id": str(action.id),
            "agent": action.agent_id,
            "model": model,
            "provider": provider,
            "input_tokens": usage.input_tokens,
            "output_tokens": usage.output_tokens,
            "cost_micro_usd": cost,
        }
        if gpu is not None:
            # The label goes into the body in the SAME statement as the numbers, so no later edit
            # can ship a device-wide figure into the hash chain without the qualifier that says it
            # is not a per-agent bill. The chain is the one copy nobody can go back and annotate.
            body.update(
                {
                    "gpu_seconds": gpu.gpu_seconds,
                    "gpu_memory_mib": gpu.gpu_memory_mib,
                    "gpu_attribution": gpu.attribution,
                }
            )
        await self._audit.append_event("cost_recorded", body)
        with self._sf() as s:
            s.add(
                CostRecord(
                    action_id=action.id,
                    agent_id=action.agent_id,
                    action_type=action.type.value,
                    model=model,
                    provider=provider,
                    input_tokens=usage.input_tokens,
                    output_tokens=usage.output_tokens,
                    cost_micro_usd=cost,
                    # Pinned only when a rate was actually applied — a version beside a null cost
                    # would read as 'these rates priced this action', which is the opposite of true.
                    price_book_version=self._prices.version if cost is not None else None,
                    # Absent when nothing measured a GPU. NULL, never 0: a zero claims this agent
                    # used no GPU, where the truth is that we did not look.
                    gpu_seconds=gpu.gpu_seconds if gpu else None,
                    gpu_memory_mib=gpu.gpu_memory_mib if gpu else None,
                    gpu_attribution=gpu.attribution if gpu else None,
                )
            )
            s.commit()
        # ECON-02, AFTER the commit: the ledger is a cache over this table, so it must never lead
        # the durable record. A notified-then-failed insert would leave the decision path enforcing
        # spend the table cannot account for — a budget nobody can reconcile against the ledger.
        if self._ledger is not None:
            self._ledger.note_spend(action.agent_id, cost)

    def totals(self, limit: int = 200, offset: int = 0) -> list[dict]:
        """Per-agent roll-up. Tokens and dollars are summed SEPARATELY and dollars may cover fewer
        actions than tokens — an operator reading a total must be able to see that some actions were
        unpriced rather than assume the dollar figure is complete.

        Bounded and pageable, for the reason `for_agent` is: the aggregation reads the WHOLE cost
        table, which grows with every governed action the fleet ever takes, and this is reachable
        from a gated read route. Paging over the GROUPED rows (agents), not the raw rows, so a page
        is always a complete set of per-agent totals rather than a partial sum of somebody's spend.

        `cost_micro_usd` is None, not 0, for an agent whose actions are ALL unpriced. SQL `SUM` over
        an all-null column returns NULL and coercing that to zero invents "this agent spent $0.00" —
        on the operator-facing route, for the default deployment that supplied no price book at all.
        `priced_actions: 0` sits beside it, but a dashboard rendering agent-and-dollars shows a free
        agent, and Slice 11c reading the same field would decide a budget on it.

        THE GPU LABEL IS IN THE FIELD NAME, deliberately. A per-agent roll-up is the hop where a
        qualifier is likeliest to be dropped, and dropping it is exactly how a device-wide 8 GiB
        becomes "agent a1 used 8 GiB". So only `process`-attributed readings produce a number here,
        and `device_shared` readings produce a COUNT — visible, so an absent number is not misread
        as "no GPU was seen", and never a quantity attributed to one agent.

        Even the process figure is an upper bound, not a division: a process may host several
        agents, so this is the largest process-level reading observed while this agent was acting.
        Memory is a MAX rather than a SUM because it is a level, not a quantity that accumulates —
        summing snapshots would multiply one 8 GiB allocation by the action count into nonsense.
        """
        is_process = CostRecord.gpu_attribution == PROCESS
        with self._sf() as s:
            rows = s.execute(
                select(
                    CostRecord.agent_id,
                    func.count().label("actions"),
                    func.sum(CostRecord.input_tokens),
                    func.sum(CostRecord.output_tokens),
                    func.sum(CostRecord.cost_micro_usd),
                    # COUNT over a nullable column counts only the NON-null rows — which is exactly
                    # how many actions the dollar sum above actually covers.
                    func.count(CostRecord.cost_micro_usd).label("priced_actions"),
                    func.sum(case((is_process, CostRecord.gpu_seconds))),
                    func.max(case((is_process, CostRecord.gpu_memory_mib))),
                    func.count(case((CostRecord.gpu_attribution == DEVICE_SHARED, 1))),
                )
                .group_by(CostRecord.agent_id)
                .order_by(CostRecord.agent_id)
                .limit(limit)
                .offset(offset)
            ).all()
        return [
            {
                "agent_id": r[0],
                "actions": r[1],
                "input_tokens": int(r[2] or 0),
                "output_tokens": int(r[3] or 0),
                "cost_micro_usd": int(r[4]) if r[5] else None,
                "priced_actions": r[5],
                "unpriced_actions": r[1] - r[5],
                "gpu_process_seconds": float(r[6]) if r[6] is not None else None,
                "gpu_process_memory_mib_max": int(r[7]) if r[7] is not None else None,
                "gpu_device_shared_actions": r[8],
            }
            for r in rows
        ]

    def by_provider(self, limit: int = 200, offset: int = 0) -> list[dict]:
        """ECON-03 — downstream (non-model) consumption per (agent, provider).

        The provider is the action's own target, so this answers "which third-party services is this
        agent actually consuming, and how much has that cost" from facts the PEP recorded rather
        than from anything inferred about a hostname.

        `cost_micro_usd` is None, not 0, when no call in the group was priced — the same refusal
        `totals()` makes, and it matters more here: a downstream provider named in a report reads
        as a vendor line, and "$0.00 with Stripe" is a claim about a bill nobody checked.

        Paged like `totals()`, and for the same reason: the aggregation reads the whole cost table,
        which grows with every governed action, and a bounded scan on a gated route is still a scan.
        """
        with self._sf() as s:
            rows = s.execute(
                select(
                    CostRecord.agent_id,
                    CostRecord.provider,
                    func.count().label("calls"),
                    func.sum(CostRecord.cost_micro_usd),
                    func.count(CostRecord.cost_micro_usd).label("priced_calls"),
                )
                .where(CostRecord.provider.is_not(None))
                .group_by(CostRecord.agent_id, CostRecord.provider)
                .order_by(CostRecord.agent_id, CostRecord.provider)
                .limit(limit)
                .offset(offset)
            ).all()
        return [
            {
                "agent_id": r[0],
                "provider": r[1],
                "calls": r[2],
                "cost_micro_usd": int(r[3]) if r[4] else None,
                "priced_calls": r[4],
            }
            for r in rows
        ]

    def for_agent(self, agent_id: str, limit: int = 200, offset: int = 0) -> list[dict]:
        """The actions behind one agent's total, newest first. Bounded: the table grows with every
        governed action, and an unbounded read on a gated route is still a read of everything.

        `offset` exists because the bound alone made the two routes DISAGREE: 500 recorded actions
        answered $500 here and $1,250 on the roll-up, with nothing to say the detail was clipped.
        An operator reconciling against an invoice has to be able to walk the whole ledger, so the
        cap stays and paging is how you get past it.

        The id breaks ties on `recorded_at`. SQLite's `CURRENT_TIMESTAMP` has one-second resolution,
        so at real metering rates ties are the NORM — and without a tiebreaker a page boundary
        returns an arbitrary subset of the tied second, which is how a paging reader silently skips
        or repeats rows. It orders nothing meaningful; it just makes the order stable.
        """
        with self._sf() as s:
            rows = s.scalars(
                select(CostRecord)
                .where(CostRecord.agent_id == agent_id)
                .order_by(CostRecord.recorded_at.desc(), CostRecord.id.desc())
                .limit(limit)
                .offset(offset)
            ).all()
            return [
                {
                    "action_id": str(r.action_id),
                    "action_type": r.action_type,
                    "model": r.model,
                    "provider": r.provider,
                    "input_tokens": r.input_tokens,
                    "output_tokens": r.output_tokens,
                    "cost_micro_usd": r.cost_micro_usd,
                    "price_book_version": r.price_book_version,
                    # ECON-03: the label ships with the numbers on the route an operator reconciles
                    # line-by-line against an invoice — the place a bare GPU figure would do most
                    # damage. All three are None together when nothing measured a GPU.
                    "gpu_seconds": r.gpu_seconds,
                    "gpu_memory_mib": r.gpu_memory_mib,
                    "gpu_attribution": r.gpu_attribution,
                    "recorded_at": r.recorded_at.isoformat() if r.recorded_at else None,
                }
                for r in rows
            ]
