"""OBS-04 — agent health: liveness, error rate and circuit-breaker state, per agent.

A READ, NOT A SUBSYSTEM. Every fact here is already recorded for another reason — the audit log
knows when an agent last acted and how its actions resolved, and `CircuitBreakerStore` knows which
breakers are open. A health WRITER would be a second source of the same facts, and the moment it
disagreed with the audit log the disagreement would be discovered while diagnosing an incident. So
nothing in this module writes, and a test asserts that structurally.

IDLE IS NOT DEAD (spec D-5). `last_seen_at` is reported as a fact and never as a verdict: this
module emits no `status`, `alive`, `healthy`, `up` or `down` field, because an agent with nothing to
do is byte-identical in the log to one that crashed and only the operator knows which they have. A
nightly batch agent and a request handler have opposite expectations; a module that asserted "down"
would page someone at 3am about a healthy nightly job, and the lesson learned would be to ignore
this page. A null `last_seen_at` means "not within the window we examined" — which is why the window
travels beside it as `window_hours`, and why widening it is the lever that tells "idle for a week"
apart from "never seen at all".

A DENY IS NOT AN ERROR (spec D-6). `deny`, `sandbox`, `require_approval` and `require_consensus` are
the system WORKING. Folding them into an error rate would make the best-governed agent in a fleet —
the one attracting the most correctly-blocked attempts — look like the sickest, and the fix an
operator reaches for to make that chart green is to LOOSEN THE GUARD. So the denominator is EXECUTED
actions, the numerator is EXECUTION failures, and both counts travel with the rate rather than being
left for a reader to assume.

## Why `execution_failures` is null, and why the field exists anyway

The audit chain records DECISIONS, not execution OUTCOMES. A governed tool that simply raised is
reported to the RUN-06 breaker in memory (`CircuitBreakerStore.record_failure`, from the PEP's
`CircuitReporter`) and audited nowhere; the only breaker events on the chain are `circuit_tripped` /
`circuit_reset`, and the breaker's own failure signal is fed mostly by GOVERNANCE BLOCKS
(`runner._BREAKER_FAILURES`), so a trip count is not an execution-failure count either — reading one
as the other would re-commit the exact D-6 inversion above. No total is therefore recoverable, and
this reports `None`.

The field stays, rather than being dropped, precisely BECAUSE it is null: a health surface with no
error field at all invites the dashboard downstream to plot the denial count in its place. `None`
says "we do not know", which is the one statement that cannot be misread as "everything ran fine".

`resource_limit_breaches` is the one execution-failure class the chain does carry (RUN-05
`resource_limit_exceeded`, raised at the execution site after a PERMITTED decision). It is counted
under its own name and never promoted to `execution_failures`: a lower bound presented as a total is
the same lie as calling denials errors, one field across.

## Only VERIFIED identity moves an agent's numbers

`agent_id` is client-settable, and the pipeline's identity short-circuit audits an unknown caller's
action VERBATIM before denying it. Taken as fact, a prober naming a dead agent would keep that
agent's `last_seen_at` moving and suppress the one signal D-5 leaves the operator. So a decision
record counts only when the identity stage itself vouched for it — the same filter the DISC-06 graph
applies, for the same reason.

The cost is stated rather than hidden: an agent whose OWN credentials broke (revoked certificate,
expired token) shows here as ZERO activity rather than as errors. That reads correctly — it is not
acting — and the DISC-04 shadow surface says why.

## Bounded, because a gated route is still a route

Phase 6's Slice 6b review found a metric-cardinality DoS in exactly this per-agent shape. The
DISTINCT-agent dimension is capped like the DISC-04 shadow store and the DISC-06 graph: past
`max_agents` the remainder folds into the single `<overflow>` bucket, so the counts stay whole and
the page SAYS there is more instead of truncating silently. The scan itself is bounded by the window
and streamed in chunks — a memory bound, not a result bound, so no count is ever clipped.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from agentos_controlplane.shadow import OVERFLOW_ID
from agentos_controlplane.store.models import AuditRecord

# How many DISTINCT agents one read may return before the rest fold into `<overflow>`. Sized like
# `ShadowAgentStore._max_rows` and `AgentGraphStore._max_nodes`.
_MAX_AGENTS = 500
# Rows per round trip while streaming the window — a memory bound, not a result bound (no count is
# clipped), exactly as `compliance._SCAN_CHUNK`.
_SCAN_CHUNK = 1000
_DEFAULT_WINDOW = timedelta(hours=24)

# Outcomes where the action was PERMITTED to run. The error rate's denominator is these, because an
# action the control plane refused never reached the code that could fail.
_EXECUTED_OUTCOMES = frozenset({"allow", "warn", "governance_review", "temporary_exception"})
# Outcomes where the control plane STOPPED the action. Counted and reported separately — they are
# governance working, and folding them into an error rate inverts what the number means.
_BLOCKED_OUTCOMES = frozenset({"deny", "sandbox", "require_approval", "require_consensus"})
# RUN-05: the only EXECUTION failure the chain carries (see the module docstring).
_BREACH_EVENT = "resource_limit_exceeded"


def _as_utc_naive(moment: datetime) -> datetime:
    """A window bound in the form `audit_record.created_at` stores.

    The column is filled by the server's `now()` and reads back UTC-naive on the SQLite backend,
    while SQLAlchemy's SQLite DATETIME binding DROPS a tzinfo rather than converting it. An aware
    bound passed straight through would therefore become a different instant — an operator in
    UTC+05:30 asking for "the last hour" would get a window five and a half hours in the future,
    see nothing, and read it as a silent fleet. Same conversion as `compliance._as_utc_naive`.
    """
    return moment if moment.tzinfo is None else moment.astimezone(timezone.utc).replace(tzinfo=None)


def _identity_verified(body: dict) -> bool:
    """Did the identity stage itself vouch for this record's `agent_id`?

    The pipeline appends this reason once identity has verified and BEFORE any later stage can deny,
    so it means "this caller is who it says", not "this action was allowed". Duplicated from the
    DISC-06 graph's private check rather than imported across modules; the rationale is in the
    module docstring above and the two must stay in agreement.
    """
    reasons = body.get("reasons")
    if not isinstance(reasons, list):
        return False
    return any(
        isinstance(r, dict) and r.get("stage") == "identity" and r.get("code") == "identity_verified"
        for r in reasons
    )


@dataclass
class _Counts:
    """Mutable accumulator for one agent while the window is streamed."""

    last_seen_at: datetime | None = None
    actions: int = 0
    executed: int = 0
    blocked: int = 0
    breaches: int = 0


@dataclass(frozen=True)
class AgentHealth:
    """One agent's health over one window. `as_dict` is the ONLY serializer, so a rate can never
    reach a caller without the two counts that produced it."""

    agent_id: str
    window_hours: float
    last_seen_at: datetime | None      # a FACT. Never a verdict — see the module docstring.
    actions: int
    executed: int
    blocked: int
    resource_limit_breaches: int
    breakers_open: int
    execution_failures: int | None = None

    @property
    def execution_failure_rate(self) -> float | None:
        """Failures per EXECUTED action — None when the count is unknown, and None when nothing
        executed.

        None rather than 0.0 on the same reasoning ECON-01 uses for an unpriced model: 0.0 is the
        claim "everything that ran, ran fine", and an agent that ran nothing has not made it.
        """
        if self.execution_failures is None or not self.executed:
            return None
        return self.execution_failures / self.executed

    def as_dict(self) -> dict:
        return {
            "agent_id": self.agent_id,
            # Beside the timestamp, always: a null `last_seen_at` only means something once the
            # reader knows how far back we looked.
            "window_hours": self.window_hours,
            "last_seen_at": (
                self.last_seen_at.replace(tzinfo=timezone.utc).isoformat()
                if self.last_seen_at is not None
                else None
            ),
            "actions": self.actions,
            "executed": self.executed,
            "blocked": self.blocked,
            "resource_limit_breaches": self.resource_limit_breaches,
            "breakers_open": self.breakers_open,
            "execution_failures": self.execution_failures,
            "execution_failure_rate": self.execution_failure_rate,
        }


class HealthStore:
    """Answers OBS-04 by reading the audit log and the live breaker state. It writes nothing."""

    def __init__(self, session_factory, breakers=None, *, max_agents: int = _MAX_AGENTS) -> None:
        self._sf = session_factory
        # Duck-typed: anything exposing `list_open()` (the `CircuitBreakerStore` slice this needs).
        self._breakers = breakers
        self._max_agents = max(1, min(int(max_agents), _MAX_AGENTS))

    def for_agent(self, agent_id: str, *, window: timedelta = _DEFAULT_WINDOW) -> dict:
        """One agent's health. An agent with no records answers with zeros and a null
        `last_seen_at` — never an invented timestamp and never a verdict."""
        counts = self._scan(window, only=agent_id).get(agent_id) or _Counts()
        return self._row(agent_id, counts, window, self._open_breakers()).as_dict()

    def fleet(self, *, window: timedelta = _DEFAULT_WINDOW, limit: int = _MAX_AGENTS) -> list[dict]:
        """Every agent seen acting in the window, plus every agent currently held by a breaker.

        The contained ones matter most and are the easiest to lose: an OPEN breaker DENIES, so
        containment itself makes an agent quiet, and a read of the audit log alone would drop
        exactly the row the operator opened this page for.

        Busiest first, so a truncated read keeps the rows worth looking at.

        `limit` is the budget of NAMED agents, applied while the window is streamed. It is not a
        slice of the answer afterwards: trimming rows off the end would throw away the counts they
        carried, which is the silent truncation the `<overflow>` bucket exists to avoid. The bucket
        therefore rides ALONGSIDE the budget rather than inside it.
        """
        budget = max(1, min(int(limit), self._max_agents))
        counts = self._scan(window, budget=budget)
        breakers = self._open_breakers()
        rows = [self._row(agent_id, c, window, breakers) for agent_id, c in counts.items()]
        for agent_id in sorted(breakers):
            if agent_id not in counts and len(rows) <= budget:
                rows.append(self._row(agent_id, _Counts(), window, breakers))
        rows.sort(key=lambda r: (-r.actions, r.agent_id))
        return [r.as_dict() for r in rows]

    # ------------------------------------------------------------------------------ internals

    def _open_breakers(self) -> dict[str, int]:
        """agent_id -> how many of its breakers are open. Both scopes count: an agent-scope breaker
        contains it everywhere and a tool-scope one contains it on that tool, and an operator
        reading a health page wants to know that anything is holding it back."""
        if self._breakers is None:
            return {}
        counts: dict[str, int] = {}
        for row in self._breakers.list_open():
            agent_id = row.get("agent_id")
            if agent_id:
                counts[agent_id] = counts.get(agent_id, 0) + 1
        return counts

    def _row(
        self, agent_id: str, counts: _Counts, window: timedelta, breakers: dict[str, int]
    ) -> AgentHealth:
        return AgentHealth(
            agent_id=agent_id,
            window_hours=window.total_seconds() / 3600,
            last_seen_at=counts.last_seen_at,
            actions=counts.actions,
            executed=counts.executed,
            blocked=counts.blocked,
            resource_limit_breaches=counts.breaches,
            breakers_open=breakers.get(agent_id, 0),
            # Not recoverable from the chain — see the module docstring. Null, deliberately, so
            # nothing downstream substitutes the denial count for it.
            execution_failures=None,
        )

    def _scan(
        self, window: timedelta, only: str | None = None, budget: int | None = None
    ) -> dict[str, _Counts]:
        """Stream the window once and accumulate per agent.

        One pass over both record shapes: DECISION records (which carry an `outcome`) give the
        activity counts and the liveness fact, and the RUN-05 `resource_limit_exceeded` EVENTS give
        the one audited execution-failure class. An outcome this module does not know is counted in
        `actions` and in neither half, which is the honest reading of a record written by a version
        that knew something we do not.
        """
        if window <= timedelta(0):
            raise ValueError(
                "window must be positive; a window ending before it starts answers 'no activity', "
                "which is indistinguishable from a silent fleet"
            )
        since = _as_utc_naive(datetime.now(timezone.utc) - window)
        acc: dict[str, _Counts] = {}
        stmt = (
            select(AuditRecord.body, AuditRecord.created_at)
            .where(AuditRecord.created_at >= since)
            .order_by(AuditRecord.seq)
        )
        with self._sf() as s:
            for body, created_at in s.execute(stmt, execution_options={"yield_per": _SCAN_CHUNK}):
                body = body or {}
                agent_id = body.get("agent_id")
                if not agent_id or (only is not None and agent_id != only):
                    continue
                kind = body.get("kind")
                if kind is not None:
                    # An event record is not an action. Only the RUN-05 breach is health evidence,
                    # and it needs no identity filter: it is raised at the execution site, after a
                    # PERMITTED decision, so identity has already been verified for it.
                    if kind == _BREACH_EVENT:
                        _bucket(acc, agent_id, budget).breaches += 1
                    continue
                outcome = body.get("outcome")
                if outcome is None or not _identity_verified(body):
                    continue
                counts = _bucket(acc, agent_id, budget)
                counts.actions += 1
                if outcome in _EXECUTED_OUTCOMES:
                    counts.executed += 1
                elif outcome in _BLOCKED_OUTCOMES:
                    counts.blocked += 1
                if counts.last_seen_at is None or created_at > counts.last_seen_at:
                    counts.last_seen_at = created_at
        return acc


def _bucket(acc: dict[str, _Counts], agent_id: str, budget: int | None) -> _Counts:
    """The accumulator for `agent_id`, or the shared `<overflow>` one once the budget is spent.

    The cap is applied DURING the scan — that is what makes the read bounded against an id-rotating
    prober rather than merely trimming the answer afterwards, and folding into one bucket keeps the
    counts whole where a trim would silently drop them. A single-agent scan passes no budget: it can
    only ever fill one bucket.
    """
    if budget is not None and agent_id not in acc and len(acc) >= budget:
        agent_id = OVERFLOW_ID
    return acc.setdefault(agent_id, _Counts())
