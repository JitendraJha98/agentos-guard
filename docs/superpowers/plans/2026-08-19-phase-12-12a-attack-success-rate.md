# Phase 12 · Slice 12a — Attack-Success-Rate Over Time (TEST-07) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Commits end
> with a second `-m "Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"`. Tests:
> `./.venv/Scripts/python.exe -m pytest`. TDD per task, one commit each. Gates `floor_invariant`
> + `regression_lock` green at every commit. Nothing here touches the per-action path.

**Goal (TEST-07):** Track attack-success-rate **over time, per agent and per attack class**, so an
operator can answer "is the guard still holding?" with a trend rather than a single green CI run.

**Architecture:** A `ValidationStore` persisting one row per red-team **run** and one per **attack
result**, plus trend queries that aggregate by (agent, suite, window). The store keeps **counts**; the
rate is derived and always reported beside its sample size `n` (spec D-4). Nothing here executes an
attack — it records what `agentos_sdk.redteam.run_suite` already produced by asking the PDP.

**Tech Stack:** SQLAlchemy 2.0 + Alembic, pytest. No new dependency.

> First commit in this slice: `docs(phase-12): Slice 12a plan` for this file, then the tasks below.

## Why counts, not a stored rate

A rate is a lossy summary of two numbers, and the lost number is the one that says whether to believe
it. Two attacks, one slipped, is 50%; five hundred attacks, two hundred and fifty slipped, is also
50%. On a trend chart they are the same dot. Storing `blocked` and `total` keeps both, makes the rate
derivable at any grouping, and means a later window can be re-aggregated without re-running anything.

## File structure
- Modify `.../store/models.py` — `RedTeamRun`, `RedTeamResult`.
- Create `.../store/migrations/versions/0028_redteam_runs.py` (down_revision `0027_agent_risk_classification`).
- Modify `.../audit.py` — `EVENT_KINDS += "validation_run"`.
- Create `.../agentos_controlplane/validation.py` — `ValidationStore`.
- Modify `.../api.py` — gated read routes.
- Tests: `tests/unit/test_validation_store.py`, `tests/integration/test_validation_api.py`.

---

### Task 1: tables + migration 0028 + event kind

**Files:** modify `.../store/models.py`, `.../audit.py`; create the migration; test
`tests/unit/test_validation_store.py` (round-trip portion).

```python
class RedTeamRun(Base):
    """TEST-07 — one execution of one red-team suite against one agent's DECISION path.

    A run is the unit a trend is built from, and it stores COUNTS rather than a rate: the rate is a
    lossy summary of `blocked` and `total`, and the number it loses is the one that says whether to
    trust it. Two attacks with one slipped and five hundred with two hundred and fifty slipped are
    both "50%" on a chart.

    `suite` is the attack CLASS the requirement asks to break the rate down by. It is a bounded
    vocabulary (`agentos_sdk.redteam.suites()`), NOT free text — this column is a GROUP BY key on an
    operator-facing trend, and Phase 6's Slice 6b review already found a metric-cardinality DoS in
    exactly this shape.
    """

    __tablename__ = "redteam_run"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    agent_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    suite: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    total: Mapped[int] = mapped_column(Integer, nullable=False)
    blocked: Mapped[int] = mapped_column(Integer, nullable=False)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="manual")  # manual | scheduled
    ran_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )


class RedTeamResult(Base):
    """TEST-07 — one attack within a run.

    The per-attack rows are what make a regression DIAGNOSABLE rather than merely visible: a trend
    that moves tells an operator something broke, and only the attack id tells them what.
    """

    __tablename__ = "redteam_result"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    run_id: Mapped[UUID] = mapped_column(Uuid, nullable=False, index=True)
    attack_id: Mapped[str] = mapped_column(String(64), nullable=False)
    outcome: Mapped[str] = mapped_column(String(32), nullable=False)
    blocked: Mapped[bool] = mapped_column(Boolean, nullable=False)
```

`audit.py`, inside `EVENT_KINDS`, in the file's comment style:
```python
        # TEST-07 (Slice 12a): a red-team suite was run against an agent's decision path. Short
        # identifiers and counts only — never an attack payload.
        "validation_run",
```

Migration `0028_redteam_runs.py` (`revision = "0028_redteam_runs"`,
`down_revision = "0027_agent_risk_classification"`), house-style docstring explaining why counts
rather than a rate, and why `suite` is a bounded vocabulary. Indexes on `agent_id`, `suite`, `ran_at`
(the trend query groups and windows on exactly these) and on `redteam_result.run_id`.

**Also add a case to `tests/integration/test_migrations.py`** — that file now exists (Slice 11d) and
0028 adds tables rather than widening a populated one, so assert upgrade/downgrade/re-upgrade is
clean and the single head is `0028_redteam_runs`.

- [ ] **Step 1: Write the failing test**

```python
"""TEST-07 — attack-success-rate over time, per agent and per attack class."""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.pool import StaticPool

from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import RedTeamResult, RedTeamRun


@pytest.fixture
def store():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    create_all(engine)
    return create_session_factory(engine)


def test_a_run_and_its_results_round_trip(store) -> None:
    run_id = uuid4()
    with store() as s:
        s.add(RedTeamRun(id=run_id, agent_id="a1", suite="jailbreak", total=2, blocked=2))
        s.add(RedTeamResult(run_id=run_id, attack_id="jb_dev_mode", outcome="deny", blocked=True))
        s.commit()
    with store() as s:
        run = s.scalars(select(RedTeamRun)).one()
        result = s.scalars(select(RedTeamResult)).one()

    assert (run.total, run.blocked, run.source) == (2, 2, "manual")
    assert result.attack_id == "jb_dev_mode" and result.blocked is True


def test_the_validation_event_kind_is_accepted_and_unknown_kinds_are_not(store) -> None:
    audit = AuditWriter(store)

    asyncio.run(audit.append_event("validation_run", {"agent": "a1", "suite": "jailbreak",
                                                      "total": 2, "blocked": 2}))

    with pytest.raises(ValueError):
        asyncio.run(audit.append_event("validation_definitely_not_a_kind", {}))
```

- [ ] **Step 2: Run to verify it fails.** Expected: `ImportError: cannot import name 'RedTeamRun'`.
- [ ] **Step 3: Add the models, the event kind, and the migration.**
- [ ] **Step 4: Run to verify it passes**, plus the alembic single-head check
  (`['0028_redteam_runs']`) and the new migration test.
- [ ] **Step 5: Commit** `feat(controlplane): redteam_run + redteam_result tables, migration 0028 (TEST-07)`.

---

### Task 2: `ValidationStore` — record a run, derive the trend

**Files:** create `.../agentos_controlplane/validation.py`; test `tests/unit/test_validation_store.py`.

```python
"""TEST-07 — attack-success-rate over time. Is the guard STILL holding?

Phase 6 proved it holds once, in CI, against a fixed corpus. That is a claim about a moment. This
module makes it a claim about a trend, which is the form an operator can actually act on: a single
green run says nothing about whether last week's green run tested the same thing.

WHAT THIS RECORDS, AND WHAT IT DOES NOT. It records the verdict of the DECISION path — what the
pipeline said it would do about an attack — because that is what `agentos_sdk.redteam.run_suite`
produces and nothing here executes an attack payload (spec D-1). So a rising success rate means the
GUARD changed, not that an agent was compromised.

WHY COUNTS RATHER THAN A RATE. A rate is a lossy summary of two numbers and the lost one is the one
that says whether to believe it: 1-of-2 and 250-of-500 are both "50%" and land on the same point of a
chart. `n` therefore travels with every rate this module returns, and a caller cannot get one without
the other.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import func, select

from agentos_controlplane.store.models import RedTeamResult, RedTeamRun

# The trend groups by (agent, suite). Both are bounded — `suite` to the shipped vocabulary, `agent`
# to registered ids — but the READ is still capped: Phase 6's Slice 6b review found a
# metric-cardinality DoS in this exact shape, and a gated route is still a route.
_MAX_ROWS = 500
_SUITE_MAX = 64


@dataclass(frozen=True)
class TrendPoint:
    """One (agent, suite) aggregate. `n` is not decoration — see the module docstring."""

    agent_id: str
    suite: str
    runs: int
    total: int
    blocked: int

    @property
    def attack_success_rate(self) -> float:
        """Fraction NOT blocked. 0.0 means the guard blocked every attack in the window."""
        return 0.0 if not self.total else (self.total - self.blocked) / self.total


class ValidationStore:
    """Persists red-team runs and answers the trend query."""

    def __init__(self, session_factory, audit) -> None:
        self._sf = session_factory
        self._audit = audit

    async def record(self, agent_id: str, suite: str, results, *, source: str = "manual") -> UUID:
        """Persist one run of `suite` against `agent_id`. `results` is an
        `agentos_sdk.redteam.Results` (or anything with the same `.results` of attack rows).

        Audited AFTER the commit, with identifiers and counts only — never an attack payload. The
        payloads are our own corpus rather than a secret, but an audit body is not a place to put
        text engineered to be interpreted as an instruction: it is read back by tools, and by
        operators, and eventually by a model.
        """
```

The rest of `record` inserts the `RedTeamRun` with `total`/`blocked` computed from `results`, one
`RedTeamResult` per attack, commits, then appends the `validation_run` event.

```python
    def trend(self, *, agent_id: str | None = None, since: datetime | None = None,
              limit: int = _MAX_ROWS) -> list[dict]:
        """ASR per (agent, suite) over the window, newest activity first.

        `n` (as `total`, and `runs`) is returned alongside the rate in every row, deliberately: a
        caller that wants to plot the rate cannot accidentally plot it without the sample size.
        """
```

```python
    def runs_for(self, agent_id: str, *, limit: int = 100) -> list[dict]:
        """The individual runs behind a trend point, newest first — the diagnosis view. A trend that
        moves says something broke; only the run and its attack ids say what."""
```

- [ ] **Step 1: Write the failing tests**

```python
from agentos_controlplane.validation import ValidationStore


class _Res:
    """Minimal stand-in for agentos_sdk.redteam.Results (the control plane must not import the SDK
    — see the STATE.md blocker about the existing undeclared edge; do not add another)."""

    def __init__(self, rows):
        self.results = tuple(rows)


class _Row:
    def __init__(self, attack_id, suite, outcome, blocked):
        self.attack_id, self.suite, self.outcome, self.blocked = attack_id, suite, outcome, blocked


def _results(blocked_flags, suite="jailbreak"):
    return _Res([_Row(f"atk{i}", suite, "deny" if b else "allow", b)
                 for i, b in enumerate(blocked_flags)])


def test_a_recorded_run_stores_counts_not_a_rate(store) -> None:
    """The rate is derivable from the counts; the counts are NOT derivable from the rate."""
    v = ValidationStore(store, AuditWriter(store))

    asyncio.run(v.record("a1", "jailbreak", _results([True, True, False])))

    with store() as s:
        run = s.scalars(select(RedTeamRun)).one()
    assert (run.total, run.blocked) == (3, 2)


def test_the_trend_reports_the_rate_WITH_its_sample_size(store) -> None:
    """THE property of this slice. 1-of-2 and 250-of-500 are both 50% and must not be presentable as
    the same claim — so a caller cannot obtain the rate without `n` beside it."""
    v = ValidationStore(store, AuditWriter(store))
    asyncio.run(v.record("a1", "jailbreak", _results([True, False])))

    point = v.trend()[0]

    assert point["attack_success_rate"] == pytest.approx(0.5)
    assert point["total"] == 2 and point["runs"] == 1


def test_the_trend_aggregates_runs_within_a_group(store) -> None:
    v = ValidationStore(store, AuditWriter(store))
    asyncio.run(v.record("a1", "jailbreak", _results([True, True])))
    asyncio.run(v.record("a1", "jailbreak", _results([True, False])))

    point = v.trend()[0]

    assert point["runs"] == 2 and point["total"] == 4 and point["blocked"] == 3
    assert point["attack_success_rate"] == pytest.approx(0.25)


def test_the_trend_separates_attack_classes(store) -> None:
    """TEST-07 says "per agent/attack class". A guard that still blocks jailbreaks but has started
    letting exfiltration through must not average into one reassuring number."""
    v = ValidationStore(store, AuditWriter(store))
    asyncio.run(v.record("a1", "jailbreak", _results([True, True], "jailbreak")))
    asyncio.run(v.record("a1", "exfiltration", _results([False, False], "exfiltration")))

    by_suite = {p["suite"]: p["attack_success_rate"] for p in v.trend()}

    assert by_suite["jailbreak"] == pytest.approx(0.0)
    assert by_suite["exfiltration"] == pytest.approx(1.0)


def test_the_window_filters(store) -> None:
    """A trend whose `since` is ignored shows an operator last quarter's health as if it were today's."""
    v = ValidationStore(store, AuditWriter(store))
    asyncio.run(v.record("a1", "jailbreak", _results([False])))
    with store() as s:  # age it out of the window
        s.execute(update(RedTeamRun).values(ran_at=datetime.now(timezone.utc).replace(tzinfo=None)
                                            - timedelta(days=30)))
        s.commit()

    assert v.trend(since=datetime.now(timezone.utc) - timedelta(days=1)) == []
    assert v.trend() != []


def test_an_empty_history_is_an_empty_trend_not_a_zero_rate(store) -> None:
    """0.0 means "every attack was blocked", which is a claim. No data is not that claim."""
    assert ValidationStore(store, AuditWriter(store)).trend() == []


def test_the_audit_body_carries_no_attack_payload(store) -> None:
    """Identifiers and counts only. An audit body is read back by tools, by operators, and
    eventually by a model; it is not a place to store text engineered to be read as an instruction."""
    v = ValidationStore(store, AuditWriter(store))
    asyncio.run(v.record("a1", "jailbreak", _results([True])))

    from agentos_controlplane.store.models import AuditRecord

    with store() as s:
        blob = json.dumps([r.body for r in s.scalars(select(AuditRecord)).all()])
    assert "ignore all previous instructions" not in blob.lower()


def test_a_suite_name_longer_than_the_column_is_refused_not_truncated(store) -> None:
    """`suite` is a GROUP BY key on an operator-facing trend. Truncating it merges two attack
    classes into one row — the same defect ECON-03's provider clipping had, where a clip on a
    grouping key silently sums two things into one line."""
    v = ValidationStore(store, AuditWriter(store))

    with pytest.raises(ValueError):
        asyncio.run(v.record("a1", "x" * 200, _results([True])))


def test_the_trend_read_is_bounded(store) -> None:
    """Phase 6's 6b review found a metric-cardinality DoS in exactly this shape."""
    v = ValidationStore(store, AuditWriter(store))
    for i in range(30):
        asyncio.run(v.record(f"agent-{i}", "jailbreak", _results([True])))

    assert len(v.trend(limit=10)) == 10
```

Add `import json` and `from sqlalchemy import update` to the test module.

- [ ] **Step 2: Run to verify it fails.** **Step 3: Implement `validation.py`.** **Step 4: Run to
  verify it passes.**
- [ ] **Step 5: Commit** `feat(controlplane): ValidationStore — ASR trends that carry their sample size (TEST-07)`.

---

### Task 3: read API + full gate

**Files:** modify `.../api.py`; test `tests/integration/test_validation_api.py`.

Append `validation: "ValidationStore | None" = None` LAST to `build_inventory_router` and
`create_app` (matching how DISC-03..06 and the Phase-11 collaborators were wired), and add:

```python
    @router.get("/validation/trend")
    def validation_trend(agent_id: str | None = None, days: int | None = None) -> list[dict]:
        """TEST-07 — attack-success-rate per agent and attack class. Gated: how well an agent's
        guard is holding is a map of where to attack it."""
        if validation is None:
            raise HTTPException(status_code=404, detail="validation tracking is not wired")
        since = None if days is None else datetime.now(timezone.utc) - timedelta(days=days)
        return validation.trend(agent_id=agent_id, since=since)

    @router.get("/validation/runs/{agent_id}")
    def validation_runs(agent_id: str) -> list[dict]:
        if validation is None:
            raise HTTPException(status_code=404, detail="validation tracking is not wired")
        return validation.runs_for(agent_id)
```

`days` must be validated (positive, bounded) — a negative or absurd value must be a 422 rather than
silently producing a window that means something else.

- [ ] **Step 1: Failing tests** — with a token: `GET /validation/trend` → 200 with the seeded point
  including `total`/`runs`; `?days=1` filters; `?days=-5` → 422; `GET /validation/runs/a1` → 200;
  without a token → 401; an app built with no `validation` → 404 while `GET /inventory` still 200.
- [ ] **Step 2: Run → fails.** **Step 3: Implement.**
- [ ] **Step 4: Run → passes**, then the FULL gate: `pytest -q` (the WHOLE suite — this phase has
  already been bitten by an ordering interaction), `-m floor_invariant`, `-m regression_lock`,
  `-m latency`, the coverage check, the alembic single-head check.
- [ ] **Step 5: Commit** `feat(controlplane): validation trend read API (TEST-07)`.

## Self-review

TEST-07 asks for ASR tracked over time **per agent/attack class**, and all three axes are real: the
trend groups by both keys with a window that genuinely filters, proven by a test that ages a run out
and by one asserting two suites do not average into a single reassuring number.

The design's central honesty property — a rate never travels without its sample size — is enforced by
the return shape rather than by convention, so a caller cannot plot the rate without `n`. Counts are
stored rather than a rate so any later grouping is re-derivable, and an empty history returns an empty
trend rather than 0.0, because 0.0 is the claim "every attack was blocked".

Nothing executes an attack: this slice records what the evaluate-only Phase-6 harness produced. The
audit body carries identifiers and counts only, and the `suite` grouping key is refused rather than
truncated — a clip on a GROUP BY key silently merges two attack classes, which is ECON-03's provider
defect in a new place.
