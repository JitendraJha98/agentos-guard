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
"""

from __future__ import annotations

from sqlalchemy import func, select

from agentos_contract import AgentAction, Decision, Usage
from agentos_controlplane.store.models import CostRecord

_MICRO = 1_000_000


class PriceBook:
    """Operator-supplied token rates, versioned. `rates` maps model name -> (usd_per_1k_input,
    usd_per_1k_output). A model that is not in the book is UNPRICED — tokens only.

    Shipping a hardcoded rate table was the rejected alternative: prices change, and a stale
    built-in rate misbills silently while looking exactly as authoritative as a correct one.
    """

    def __init__(
        self, rates: dict[str, tuple[float, float]] | None = None, *, version: str = "unset"
    ) -> None:
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
        # What the provider SERVED wins over what the action REQUESTED: an alias resolves to a
        # dated snapshot that can be priced differently, and the served name is what the bill says.
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
                    # Pinned only when a rate was actually applied — a version beside a null cost
                    # would read as 'these rates priced this action', which is the opposite of true.
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
                    # COUNT over a nullable column counts only the NON-null rows — which is exactly
                    # how many actions the dollar sum above actually covers.
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
        """The actions behind one agent's total, newest first. Bounded: the table grows with every
        governed action, and an unbounded read on a gated route is still a read of everything."""
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
