"""ECON-04 — ROI analytics: value against cost, per agent.

COST IS MEASURED. VALUE IS NOT, AND CANNOT BE. ECON-01/03 attribute real dollars to real actions, so
the cost half of this is evidence. The value half is not observable by a control plane at all: an
action that completed may have produced something worthless, and one that was denied may have
prevented a catastrophe worth more than the whole fleet's annual spend. Nothing in an audit log
distinguishes those.

SO VALUE IS OPERATOR-SUPPLIED, AND THE ALTERNATIVE IS WORSE THAN IT SOUNDS. The obvious proxy is
"count the actions that were allowed" — and on a governance product that number is actively harmful.
It rises when the guard permits more, so an agent whose denials were correct scores WORSE than one
running unchecked, and the cheapest way to improve a team's ROI dashboard becomes loosening their
constitution. A metric that rewards weakening the control plane has no business inside the control
plane. There is no inferred-value path here, and a test asserts its absence.

WHAT THIS THEREFORE IS. A join: measured cost, operator-declared value, and the ratio — with BOTH
inputs shown beside it so the ratio can be argued with. An agent with no declared value has no ROI,
reported as null rather than zero: zero is the claim "this agent produced nothing", which is a
statement about the agent, while null is a statement about our knowledge.

THE DENIED-ACTION CAVEAT TRAVELS WITH THE NUMBER. Cost includes actions the control plane blocked
(they still burned tokens getting to the decision), while the value of a block is exactly what this
module cannot see. So a well-governed agent under attack looks expensive here. That is stated in the
payload, not just in this docstring, because the ratio is what an operator screenshots into a budget
review.
"""

from __future__ import annotations

from dataclasses import dataclass

_MAX_ROWS = 500
_MICRO = 1_000_000

# The caveat that has to travel with any ratio computed here. In the payload rather than the docs
# because the number outlives the context it was read in.
COST_BASIS_NOTE = (
    "Cost is measured and includes actions the control plane BLOCKED — they still consumed tokens "
    "reaching the decision. The value of a block is not observable here, so an agent that is "
    "attracting and correctly refusing attacks will look expensive on this page. Read a low ratio "
    "as a question, not a verdict."
)
VALUE_SOURCE_NOTE = (
    "Value is OPERATOR-DECLARED, never inferred. A control plane cannot tell a valuable outcome "
    "from a worthless one, and the obvious proxy — counting permitted actions — would reward "
    "loosening the guard, so it is not computed here at any confidence."
)


@dataclass(frozen=True)
class RoiRow:
    """One agent's value-against-cost, with both inputs visible.

    `roi` is None when no value was declared. Not 0.0: zero asserts the agent produced nothing,
    which is a claim about the agent rather than about what we were told.
    """

    agent_id: str
    cost_micro_usd: int
    declared_value_micro_usd: int | None
    actions: int
    priced_actions: int
    unpriced_actions: int

    @property
    def roi(self) -> float | None:
        if self.declared_value_micro_usd is None:
            return None
        if self.cost_micro_usd <= 0:
            # A positive value at zero measured cost is not an infinite return, it is an unpriced
            # fleet. Reporting `inf` would put a meaningless number at the top of a sorted table.
            return None
        return self.declared_value_micro_usd / self.cost_micro_usd

    def as_dict(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "cost_micro_usd": self.cost_micro_usd,
            "declared_value_micro_usd": self.declared_value_micro_usd,
            "roi": self.roi,
            "actions": self.actions,
            "priced_actions": self.priced_actions,
            "unpriced_actions": self.unpriced_actions,
            # Carried per row, not once per response: a consumer that renders one agent must not be
            # able to drop the caveat by rendering a subset.
            "value_source": VALUE_SOURCE_NOTE,
        }


class RoiAnalyzer:
    """ECON-04 — joins ECON-01/03 measured cost to operator-declared value.

    `cost` is the shipped `CostRecorder`; `values` is a mapping of agent_id -> declared value in
    micro-USD, supplied by the operator. Deliberately a plain mapping rather than a table: the
    declaration is an operator's business input, it changes on their cadence rather than the fleet's,
    and giving it a schema here would imply this module owns a fact it merely receives.
    """

    def __init__(self, cost, values=None) -> None:
        self._cost = cost
        self._values = dict(values or {})

    def declare_value(self, agent_id: str, value_micro_usd: int) -> None:
        """Record what an operator says an agent is worth over the reporting period."""
        value = int(value_micro_usd)
        if value < 0:
            # A negative declared value would invert the ratio's sign and read as a profitable
            # agent on a sorted table. If an agent is net-harmful that is a governance finding, not
            # an ROI figure.
            raise ValueError("declared value cannot be negative")
        self._values[str(agent_id)] = value

    def report(self, *, limit: int = _MAX_ROWS, offset: int = 0) -> dict:
        """Per-agent ROI over the measured cost table.

        Bounded and pageable for the reason `CostRecorder.totals` is: the aggregation reads the whole
        cost table, which grows with every governed action the fleet ever takes.
        """
        bound = max(1, min(int(limit), _MAX_ROWS))
        totals = self._cost.totals(limit=bound, offset=max(0, int(offset)))
        rows = [
            RoiRow(
                agent_id=t["agent_id"],
                cost_micro_usd=int(t.get("cost_micro_usd") or 0),
                declared_value_micro_usd=self._values.get(t["agent_id"]),
                actions=int(t.get("actions") or 0),
                priced_actions=int(t.get("priced_actions") or 0),
                unpriced_actions=int(t.get("unpriced_actions") or 0),
            )
            for t in totals
        ]
        with_value = [r for r in rows if r.declared_value_micro_usd is not None]
        return {
            "rows": [r.as_dict() for r in rows],
            # The two counts that stop a partial picture reading as the whole one: an ROI table
            # covering three of two hundred agents is a sample, and a reader sorting by ratio has no
            # way to see that from the rows alone.
            "agents_reported": len(rows),
            "agents_with_declared_value": len(with_value),
            "cost_basis": COST_BASIS_NOTE,
            "value_source": VALUE_SOURCE_NOTE,
        }
