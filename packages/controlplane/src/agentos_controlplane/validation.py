"""TEST-07 — attack-success-rate over time. Is the guard STILL holding?

Phase 6 proved it holds once, in CI, against a fixed corpus. That is a claim about a moment. This
module makes it a claim about a trend, which is the form an operator can actually act on: a single
green run says nothing about whether last week's green run tested the same thing.

WHAT THIS RECORDS, AND WHAT IT DOES NOT. It records the verdict of the DECISION path — what the
pipeline said it *would* do about an attack — because that is what `agentos_sdk.redteam.run_suite`
produces, and nothing anywhere in this phase executes an attack payload (spec D-1). So a rising
success rate here means the GUARD changed, not that an agent was compromised. Recording is the whole
of this module's job: it never runs anything itself, which is why it takes a results object rather
than an evaluate seam.

WHY COUNTS RATHER THAN A RATE. A rate is a lossy summary of two numbers and the lost one is the one
that says whether to believe it: 1-of-2 and 250-of-500 are both "50%" and land on the same point of a
chart. So `blocked` and `total` are what get stored, the rate is derived, and `n` travels with every
rate this module returns — enforced by the return shape (`TrendPoint`, one serializer) rather than by
every caller remembering.

WHY IT DOES NOT IMPORT THE SDK. `results` is duck-typed: anything exposing `.results` of rows with
`.attack_id` / `.outcome` / `.blocked`. STATE.md already records one undeclared controlplane -> SDK
import as a blocker and this module does not add a second one.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import UUID, uuid4

from sqlalchemy import func, select

from agentos_controlplane.store.models import RedTeamResult, RedTeamRun

# The trend groups by (agent, suite). Both key spaces are bounded — `suite` to the shipped
# vocabulary, `agent` to registered ids — but the READ is capped anyway: Phase 6's Slice 6b review
# found a metric-cardinality DoS in this exact per-agent x per-class x per-window shape, and a gated
# route is still a route. The cap is applied INSIDE, so a caller cannot ask past it.
_MAX_ROWS = 500
# The two GROUP BY keys, at their column widths. Over-long values are REFUSED rather than truncated:
# a clip on a grouping key silently merges two distinct things into one row, which is precisely the
# defect ECON-03 shipped when it clipped `provider` and summed two downstream services onto one
# billing line. Here the merge would average a healthy attack class together with a broken one.
_SUITE_MAX = 64
_AGENT_MAX = 255
# `attack_id` is CLIPPED, not refused, and the difference is deliberate. It is a display label rather
# than a grouping key, so a clip costs a suffix — whereas refusing (or letting Postgres refuse the
# INSERT) throws away the entire run, and a lost run is a lost measurement on a safety trend. Same
# split ECON-01 draws between `model`, which it clips, and `price_book_version`, which it refuses.
_ATTACK_ID_MAX = 64


def _as_utc_naive(moment: datetime | None) -> datetime | None:
    """A window bound in the form `ran_at` stores.

    `ran_at` is filled by the server's `now()` and reads back UTC-naive on the SQLite backend, while
    SQLAlchemy's SQLite DATETIME binding DROPS a tzinfo rather than converting it. An aware bound
    passed straight through therefore becomes a different instant: an operator in UTC+05:30 asking
    for "the last hour" gets a window five and a half hours in the future, sees an empty trend, and
    reads it as "validation has stopped" while validation is running fine. A naive bound is taken as
    already-UTC, for the same reason `compliance._as_utc_naive` does.
    """
    if moment is None or moment.tzinfo is None:
        return moment
    return moment.astimezone(timezone.utc).replace(tzinfo=None)


def _grouping_key(name: str, value: str, limit: int) -> str:
    """Refuse an over-long GROUP BY key. See `_SUITE_MAX` for why this refuses instead of clipping."""
    if not value:
        raise ValueError(f"{name} must not be empty; it is a grouping key on the trend")
    if len(value) > limit:
        raise ValueError(
            f"{name} must be at most {limit} characters; got {len(value)}. It is a GROUP BY key on "
            "the attack-success trend and truncating it would merge two distinct rows into one."
        )
    return value


@dataclass(frozen=True)
class TrendPoint:
    """One (agent, suite) aggregate. `n` is not decoration — see the module docstring.

    The rate is a PROPERTY, not a field, and that is the enforcement: there is no attribute a caller
    could set to carry a rate without the counts that produced it, and `as_dict` — the single
    serializer both read methods go through — emits the rate and the counts in one statement.
    """

    agent_id: str
    suite: str
    runs: int
    total: int
    blocked: int
    last_run_at: datetime | None = None

    @property
    def attack_success_rate(self) -> float | None:
        """Fraction NOT blocked. 0.0 means the guard blocked every attack in the window.

        None — not 0.0 — when nothing was tested. A run that yielded no attacks (an empty corpus, a
        misconfigured schedule) reporting 0.0 would assert "the guard blocked everything", which is
        the same lie an empty trend reporting 0.0 would tell, one layer down. ECON-01's
        absent-is-not-zero discipline applied to a safety number.
        """
        if not self.total:
            return None
        return (self.total - self.blocked) / self.total

    def as_dict(self) -> dict:
        """The rate and its sample size, always in one object. The ONLY place a rate is serialized."""
        return {
            "agent_id": self.agent_id,
            "suite": self.suite,
            "runs": self.runs,
            "total": self.total,
            "blocked": self.blocked,
            "attack_success_rate": self.attack_success_rate,
            # WHEN it was measured, beside WHAT was measured: a 0.0 from last quarter renders
            # identically to a 0.0 from an hour ago, and only one of them is evidence about today.
            "last_run_at": self.last_run_at.isoformat() if self.last_run_at else None,
        }


class ValidationStore:
    """Persists red-team runs and answers the trend query."""

    def __init__(self, session_factory, audit) -> None:
        self._sf = session_factory
        self._audit = audit

    async def record(self, agent_id: str, suite: str, results, *, source: str = "manual") -> UUID:
        """Persist one run of `suite` against `agent_id`. `results` is an
        `agentos_sdk.redteam.Results` (or anything with the same `.results` of attack rows).

        Only the three fields the trend and the diagnosis view need are read off each row —
        `attack_id`, `outcome`, `blocked` — so nothing this module cannot name can reach the
        database, and the attack TEXT that produced the verdict is left where it came from.

        Audited AFTER the commit, which is the opposite order from `CostRecorder.record` and
        deliberately so. There the event is the evidence for a money figure, so a committed row with
        no event is a bill with nothing behind it. Here the row IS the measurement and the trend is
        derived from rows: an append that failed first would drop the run entirely and quietly
        thin out the safety signal, which is the failure mode 12b's scheduler is built to avoid.
        The reverse leaves a recorded run with no chain event — visible, and reconcilable against
        the AUD-06 chain.

        The audit body carries identifiers and counts only. The payloads are our own corpus rather
        than a secret, but an audit body is not a place to put text engineered to be interpreted as
        an instruction: it is read back by tools, by operators, and eventually by a model.
        """
        # Validated BEFORE anything is written, so a refused run leaves neither half of a
        # half-record — no row for the trend to count, no event claiming a run that never landed.
        agent_id = _grouping_key("agent_id", agent_id, _AGENT_MAX)
        suite = _grouping_key("suite", suite, _SUITE_MAX)

        rows = tuple(results.results)
        total = len(rows)
        blocked = sum(1 for r in rows if r.blocked)
        run_id = uuid4()
        with self._sf() as s:
            s.add(
                RedTeamRun(
                    id=run_id,
                    agent_id=agent_id,
                    suite=suite,
                    total=total,
                    blocked=blocked,
                    source=source,
                )
            )
            s.add_all(
                [
                    RedTeamResult(
                        run_id=run_id,
                        attack_id=str(r.attack_id)[:_ATTACK_ID_MAX],
                        outcome=str(r.outcome),
                        blocked=bool(r.blocked),
                    )
                    for r in rows
                ]
            )
            s.commit()
        await self._audit.append_event(
            "validation_run",
            {
                "run_id": str(run_id),
                "agent": agent_id,
                "suite": suite,
                "total": total,
                "blocked": blocked,
                "source": source,
            },
        )
        return run_id

    def trend(
        self,
        *,
        agent_id: str | None = None,
        since: datetime | None = None,
        limit: int = _MAX_ROWS,
    ) -> list[dict]:
        """ASR per (agent, suite) over the window, most recently exercised first.

        `n` (as `total`, and `runs`) is returned alongside the rate in every row, deliberately: a
        caller that wants to plot the rate cannot accidentally plot it without the sample size.

        The two keys are grouped SEPARATELY rather than averaged, which is the requirement's "per
        agent/attack class" doing real work: a guard that still blocks jailbreaks while it has
        started letting exfiltration through shows two rows, one of them alarming, instead of one
        reassuring number in the middle.

        An empty history returns an empty list, never a 0.0 row — 0.0 is the claim "every attack was
        blocked", and no data is not that claim.
        """
        limit = max(1, min(int(limit), _MAX_ROWS))
        last_run_at = func.max(RedTeamRun.ran_at).label("last_run_at")
        stmt = (
            select(
                RedTeamRun.agent_id,
                RedTeamRun.suite,
                func.count().label("runs"),
                func.sum(RedTeamRun.total),
                func.sum(RedTeamRun.blocked),
                last_run_at,
            )
            .group_by(RedTeamRun.agent_id, RedTeamRun.suite)
            # The keys break the tie on the timestamp. SQLite's `CURRENT_TIMESTAMP` has one-second
            # resolution, so a fleet validated in one scheduler pass ties on `last_run_at` — and
            # without a tiebreaker the `limit` above would return an arbitrary subset of the tied
            # groups, differently on each call.
            .order_by(last_run_at.desc(), RedTeamRun.agent_id, RedTeamRun.suite)
            .limit(limit)
        )
        if agent_id is not None:
            stmt = stmt.where(RedTeamRun.agent_id == agent_id)
        if since is not None:
            stmt = stmt.where(RedTeamRun.ran_at >= _as_utc_naive(since))
        with self._sf() as s:
            rows = s.execute(stmt).all()
        return [
            TrendPoint(r[0], r[1], r[2], int(r[3] or 0), int(r[4] or 0), r[5]).as_dict()
            for r in rows
        ]

    def runs_for(self, agent_id: str, *, limit: int = 100) -> list[dict]:
        """The individual runs behind a trend point, newest first — the diagnosis view. A trend that
        moves says something broke; only the run and its attack ids say what.

        `slipped` names the attacks the guard did NOT block, which is the answer an operator is
        actually after: the trend moved, and this is the probe that stopped being stopped. Fetched
        in one further query over the page of runs rather than per run.

        Capped like the trend, and this is the read that genuinely accumulates: the trend is bounded
        by its key space, while this table grows by one row per suite per scheduled pass forever.
        """
        limit = max(1, min(int(limit), _MAX_ROWS))
        with self._sf() as s:
            runs = s.scalars(
                select(RedTeamRun)
                .where(RedTeamRun.agent_id == agent_id)
                # The id breaks the tie for the same reason the trend's keys do — one scheduler pass
                # writes several runs inside SQLite's one-second `ran_at` resolution.
                .order_by(RedTeamRun.ran_at.desc(), RedTeamRun.id.desc())
                .limit(limit)
            ).all()
            slipped: dict[UUID, list[str]] = {}
            if runs:
                for run_id, attack_id in s.execute(
                    select(RedTeamResult.run_id, RedTeamResult.attack_id)
                    .where(
                        RedTeamResult.run_id.in_([r.id for r in runs]),
                        RedTeamResult.blocked.is_(False),
                    )
                    .order_by(RedTeamResult.attack_id)
                ):
                    slipped.setdefault(run_id, []).append(attack_id)
        return [
            # Through the SAME TrendPoint serializer as the trend, so this route cannot drift into
            # reporting a rate without its sample size. One run is a one-run aggregate.
            dict(
                TrendPoint(r.agent_id, r.suite, 1, r.total, r.blocked, r.ran_at).as_dict(),
                run_id=str(r.id),
                source=r.source,
                slipped=slipped.get(r.id, []),
            )
            for r in runs
        ]
