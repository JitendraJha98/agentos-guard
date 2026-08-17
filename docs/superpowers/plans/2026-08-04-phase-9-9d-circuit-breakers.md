# Phase 9 · Slice 9d — Circuit Breakers (RUN-06) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Commits end
> with a second `-m "Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"`. Tests:
> `./.venv/Scripts/python.exe -m pytest`. TDD per task, one commit each. Gates `floor_invariant`
> + `regression_lock` green at every commit. (`-m latency` is wall-clock and noisy under machine load
> — if it fails, verify against a clean baseline via `git stash` before attributing it.)

**Goal (RUN-06):** A breaker auto-trips an agent (or an agent+tool pair) after a threshold of
violations or errors inside a rolling window; while OPEN, that agent's actions are denied; after a
cooldown it admits trials and closes on success. Every transition is audited and survives a restart.

**Architecture:** `CircuitBreakerStore` (control plane) keeps **rolling-window counters in memory**
(ephemeral by design — a window is a recent-history view, not durable state) and persists only **state
transitions**, which are audited (`circuit_tripped` / `circuit_reset`) and reloaded at construction so a
restart cannot silently un-trip a breaker. The pipeline gains **Stage 1f** (right after 9b's privilege
gate) as a deterministic deny, and feeds the breaker from the **graduated path only**; the PEP feeds
execution errors through a `CircuitReporter` seam.

**Two correctness traps this design closes explicitly:**
1. **Feedback loop.** If breaker-caused denials counted as violations, an OPEN breaker would feed
   itself and never close. Only decisions that reach the **graduated stage** are recorded — every
   short-circuit deny (kill switch, identity, delegation, MCP, privilege, breaker) is excluded.
2. **Cross-agent DoS.** Counting *unverified* actions would let an attacker trip another agent's
   breaker by forging its id. Recording happens only after identity verification (the same lesson as
   the 6b metric-cardinality fix), which the graduated-path-only rule guarantees.

**Precedence:** kill switch (stage 0, *operator intent*) is checked before the breaker (stage 1f,
*automatic*), and each denies with its own distinct reason code so forensics can tell them apart.

**Tech Stack:** stdlib `collections.deque` + injectable clock, SQLAlchemy 2.0 + Alembic, pytest.

> First commit in this slice: `docs(phase-9): Slice 9d plan` for this file, then the tasks below.

## File structure
- Modify `.../store/models.py` — `CircuitBreakerState` table.
- Create `.../store/migrations/versions/0014_circuit_breakers.py` (down_revision `0013_resource_limits`).
- Modify `.../audit.py` — `EVENT_KINDS += "circuit_tripped"`, `"circuit_reset"`.
- Create `.../agentos_controlplane/circuit_breaker.py` — `BreakerVerdict`, `CircuitBreakerStore`.
- Modify `packages/pipeline/src/agentos_pipeline/runner.py` — `BreakerVerdictProtocol`,
  `CircuitBreakerLookup`, ctor seam, Stage 1f, graduated-path recording.
- Modify `packages/sdk/src/agentos_sdk/enforce.py` (+ `middleware.py`, `wrappers.py`, `__init__.py`) —
  `CircuitReporter` seam + error/success reporting around the run sites.
- Tests: `tests/unit/test_circuit_breaker_store.py`, `tests/unit/test_circuit_breaker_pipeline.py`,
  `tests/integration/test_circuit_breaker_e2e.py`.

---

### Task 1: `CircuitBreakerState` table + migration 0014 + event kinds

**Files:** modify `.../store/models.py`, `.../audit.py`; create `.../versions/0014_circuit_breakers.py`;
test `tests/unit/test_circuit_breaker_store.py` (round-trip + event-kind portion).

```python
class CircuitBreakerState(Base):
    """RUN-06 — the DURABLE state of one breaker (`key` is an agent_id, or "agent_id|target").

    Only TRANSITIONS are persisted; the rolling-window counters live in memory because a window is a
    recent-history view, not durable state. `opened_at` is epoch SECONDS (a float) rather than a
    DateTime: cooldown arithmetic is the only thing it is used for, and a plain epoch avoids
    naive/aware conversion bugs across the SQLite dev / Postgres target split. Human-readable history
    lives on the audit chain.
    """

    __tablename__ = "circuit_breaker_state"

    key: Mapped[str] = mapped_column(String(511), primary_key=True)
    scope: Mapped[str] = mapped_column(String(16), nullable=False)  # "agent" | "tool"
    state: Mapped[str] = mapped_column(String(16), nullable=False)  # "open" | "half_open" | "closed"
    opened_at: Mapped[float | None] = mapped_column(Float, nullable=True)
    trip_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )
```

`audit.py`:

```python
        # RUN-06 (Slice 9d): automatic breaker transitions. Short identifiers + counts only.
        "circuit_tripped",
        "circuit_reset",
```

Migration `0014_circuit_breakers.py` (`revision = "0014_circuit_breakers"`,
`down_revision = "0013_resource_limits"`): create `circuit_breaker_state` with the columns above
(`sa.String(511)` pk, `sa.String(16)` scope/state, `sa.Float()` nullable `opened_at`, `sa.Integer()`
`trip_count` server_default `"0"`, `sa.DateTime(timezone=True)` `updated_at` server_default
`sa.func.now()`); `downgrade` drops it.

**Steps:**
- [ ] Failing test: in-memory store; insert a `CircuitBreakerState(key="a|http_get", scope="tool",
  state="open", opened_at=1000.0, trip_count=1)`, read it back; assert `append_event("circuit_tripped",
  {...})` and `append_event("circuit_reset", {...})` are accepted and an unknown kind still raises.
  Run → fails.
- [ ] Add model + event kinds + migration; verify a SINGLE head (expected `['0014_circuit_breakers']`)
  with the heads one-liner used in the 9b/9c plans. Run → passes.
- [ ] Commit `feat(controlplane): circuit_breaker_state table + event kinds + migration 0014 (RUN-06)`.

---

### Task 2: `CircuitBreakerStore` — window counters + state machine

**Files:** create `packages/controlplane/src/agentos_controlplane/circuit_breaker.py`;
test `tests/unit/test_circuit_breaker_store.py`.

```python
"""RUN-06 — circuit breakers. A breaker trips an agent (or an agent+tool pair) after a threshold of
violations or errors inside a rolling window, denies while OPEN, admits trials after a cooldown, and
closes on a successful trial.

Shape mirrors the other Phase-9 containment stores: the per-action lookup is IN-MEMORY (no DB read on
the hot path), transitions are persisted + audited, and state reloads at construction so a restart
cannot silently un-trip a breaker. Counters are deliberately NOT persisted — a rolling window is a
recent-history view; only the tripped state is durable.

`now` is injectable for deterministic tests. It is WALL clock (not monotonic) because a reloaded OPEN
breaker must be able to compute how long it has been open across a process restart.

HALF_OPEN semantics (documented simplification): the state admits trial traffic rather than exactly one
request; the first violation re-opens it and the first success closes it. Strict single-trial admission
would need cross-process coordination, which is Phase-7 reconciler territory.
"""
from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass
from typing import Callable

from sqlalchemy import select

from agentos_controlplane.store.models import CircuitBreakerState

_AGENT, _TOOL = "agent", "tool"


@dataclass(frozen=True)
class BreakerVerdict:
    """Returned ONLY when the breaker refuses the action."""

    key: str
    scope: str   # "agent" | "tool"
    state: str   # "open"


class CircuitBreakerStore:
    def __init__(
        self,
        session_factory,
        audit,
        *,
        failure_threshold: int = 5,
        window_s: float = 60.0,
        cooldown_s: float = 30.0,
        now: Callable[[], float] = time.time,
    ) -> None:
        if failure_threshold < 1:
            raise ValueError("failure_threshold must be >= 1")
        self._sf = session_factory
        self._audit = audit
        self._threshold = failure_threshold
        self._window_s = window_s
        self._cooldown_s = cooldown_s
        self._now = now
        self._fails: dict[str, deque[float]] = {}   # key -> failure timestamps (rolling window)
        self._state: dict[str, tuple[str, float | None]] = {}  # key -> (state, opened_at)
        self._load()

    def _load(self) -> None:
        with self._sf() as s:
            for row in s.scalars(select(CircuitBreakerState)).all():
                if row.state != "closed":
                    self._state[row.key] = (row.state, row.opened_at)

    # ---- keys ----
    @staticmethod
    def _agent_key(agent_id: str) -> str:
        return agent_id

    @staticmethod
    def _tool_key(agent_id: str, target: str) -> str:
        return f"{agent_id}|{target}"

    # ---- hot path (in-memory only) ----
    def status(self, agent_id: str, target: str) -> BreakerVerdict | None:
        """None == permitted. A verdict == refused. Checks the agent breaker first (broader), then
        the agent+tool pair. An OPEN breaker whose cooldown has elapsed becomes HALF_OPEN and permits."""
        for key, scope in ((self._agent_key(agent_id), _AGENT), (self._tool_key(agent_id, target), _TOOL)):
            entry = self._state.get(key)
            if entry is None:
                continue
            state, opened_at = entry
            if state == "open":
                if opened_at is not None and (self._now() - opened_at) >= self._cooldown_s:
                    self._state[key] = ("half_open", opened_at)  # cooldown elapsed -> admit trials
                    continue
                return BreakerVerdict(key=key, scope=scope, state="open")
        return None

    # ---- signals ----
    async def record_failure(self, agent_id: str, target: str) -> None:
        """RUN-06 — one violation OR execution error. Trips either breaker that crosses the threshold,
        and immediately re-opens a HALF_OPEN breaker (a failed trial)."""
        t = self._now()
        for key, scope in ((self._agent_key(agent_id), _AGENT), (self._tool_key(agent_id, target), _TOOL)):
            window = self._fails.setdefault(key, deque())
            window.append(t)
            cutoff = t - self._window_s
            while window and window[0] < cutoff:
                window.popleft()
            state = (self._state.get(key) or ("closed", None))[0]
            if state == "half_open" or len(window) >= self._threshold:
                if state != "open":
                    await self._trip(key, scope, len(window))

    async def record_success(self, agent_id: str, target: str) -> None:
        """A successful execution closes a HALF_OPEN breaker (and clears its window)."""
        for key, scope in ((self._agent_key(agent_id), _AGENT), (self._tool_key(agent_id, target), _TOOL)):
            if (self._state.get(key) or ("closed", None))[0] == "half_open":
                await self._close(key, scope, reason="trial_succeeded")

    async def reset(self, key: str, *, set_by: str) -> None:
        """Explicit operator reset."""
        scope = _TOOL if "|" in key else _AGENT
        await self._close(key, scope, reason="operator_reset", set_by=set_by)

    def list_open(self) -> list[dict]:
        return [
            {"key": k, "state": st, "opened_at": oa}
            for k, (st, oa) in sorted(self._state.items())
            if st != "closed"
        ]

    # ---- transitions (durable + audited) ----
    async def _trip(self, key: str, scope: str, observed: int) -> None:
        opened_at = self._now()
        with self._sf() as s:
            row = s.get(CircuitBreakerState, key)
            if row is None:
                s.add(
                    CircuitBreakerState(
                        key=key, scope=scope, state="open", opened_at=opened_at, trip_count=1
                    )
                )
            else:
                row.state, row.opened_at, row.trip_count = "open", opened_at, (row.trip_count or 0) + 1
            s.commit()
        self._state[key] = ("open", opened_at)  # cache AFTER the commit (no divergence)
        await self._audit.append_event(
            "circuit_tripped",
            {"key": key, "scope": scope, "observed": observed, "threshold": self._threshold},
        )

    async def _close(self, key: str, scope: str, *, reason: str, set_by: str = "system") -> None:
        with self._sf() as s:
            row = s.get(CircuitBreakerState, key)
            if row is not None:
                row.state, row.opened_at = "closed", None
                s.commit()
        await self._audit.append_event(
            "circuit_reset", {"key": key, "scope": scope, "reason": reason, "set_by": set_by}
        )
        # Un-contain the hot path only AFTER the durable steps succeed (fail-toward-contained).
        self._state.pop(key, None)
        self._fails.pop(key, None)
```

**Steps (TDD):**
- [ ] Failing tests over a shared in-memory store + real `AuditWriter`, with an injectable fake clock
  (`clock = [1000.0]`, `now=lambda: clock[0]`):
  - below threshold → `status("a", "t") is None`;
  - `failure_threshold=3`: three `record_failure("a","t")` → `status` returns a verdict (`state ==
    "open"`), one `circuit_tripped` event per tripped scope, and the durable row says `open`;
  - a DIFFERENT agent is unaffected (per-agent isolation);
  - rolling window: two failures, advance the clock past `window_s`, one more failure → still permitted
    (the stale two aged out);
  - cooldown: after tripping, advance past `cooldown_s` → `status` permits (HALF_OPEN);
  - failed trial: while HALF_OPEN, one `record_failure` re-opens immediately (a second
    `circuit_tripped` event, `trip_count == 2`);
  - successful trial: while HALF_OPEN, `record_success` closes it (`circuit_reset` with
    `reason="trial_succeeded"`) and `status` permits;
  - `await reset("a", set_by="op")` closes an OPEN breaker with `reason="operator_reset"`;
  - tool scoping: trip `"a|http_get"` only (threshold failures on that target with a HIGH agent
    threshold, or assert the verdict scope) → a different target for the same agent still permitted;
  - a fresh store over the same tables reloads the OPEN state (a restart must not un-trip);
  - `failure_threshold=0` raises `ValueError`;
  - `verify_chain(sf).ok` holds; no audit body contains a payload.
  Run → fails.
- [ ] Implement `circuit_breaker.py`. Run → passes.
- [ ] Commit `feat(controlplane): CircuitBreakerStore — rolling-window trip, cooldown, audited (RUN-06)`.

---

### Task 3: pipeline Stage 1f gate + graduated-path recording

**Files:** modify `packages/pipeline/src/agentos_pipeline/runner.py`;
test `tests/unit/test_circuit_breaker_pipeline.py`.

Add Protocols beside 9b's `PrivilegeLookup`:

```python
class BreakerVerdictProtocol(Protocol):
    """RUN-06: what a refusing breaker reports."""

    key: str
    scope: str
    state: str


class CircuitBreakerLookup(Protocol):
    """RUN-06 seam. `status` MUST be in-memory (per-action hot path); `record_failure` /
    `record_success` feed the rolling window."""

    def status(self, agent_id: str, target: str) -> "BreakerVerdictProtocol | None": ...

    async def record_failure(self, agent_id: str, target: str) -> None: ...

    async def record_success(self, agent_id: str, target: str) -> None: ...
```

`Pipeline.__init__` gains `breaker: CircuitBreakerLookup | None = None` → `self._breaker`
(`None` default → the stage never runs, behavior unchanged).

**Stage 1f** — insert immediately AFTER 9b's Stage 1e privilege block, BEFORE `# Stage 2 — Enrichment`:

```python
        # Stage 1f — Circuit breaker (RUN-06): an agent (or agent+tool pair) that crossed its
        # violation/error threshold is denied while OPEN. Placed AFTER identity so the breaker keys on
        # a VERIFIED agent — counting unverified actions would let an attacker trip someone else's
        # breaker by forging their id. The kill switch (stage 0, OPERATOR intent) is deliberately
        # checked earlier than this AUTOMATIC trip, and each uses a distinct reason code so audit
        # forensics can tell them apart. Lookup is in-memory (no per-action DB read).
        if self._breaker is not None:
            bv = self._breaker.status(action.agent_id, action.target)
            if bv is not None:
                floor_box[0] = Outcome.deny  # an open breaker may NEVER relax
                reasons.append(
                    Reason(
                        stage="circuit_breaker",
                        code="circuit_open",
                        detail=f"{bv.scope} breaker {bv.key} is {bv.state}",
                    )
                )
                decision = Decision(
                    action_id=action.id,
                    outcome=Outcome.deny,
                    trust_score=trust,
                    reasons=reasons,
                    constitution_version=self._policy.constitution_version,
                    policy_version=self._policy.policy_version,
                )
                await self._append_with_redaction_fallback(action, decision)
                return decision  # TERMINAL
```

**Graduated-path recording** — at the END of `_evaluate`, immediately before the final graduated
`Decision` is returned (i.e. on the ONE path that ran policy+risk+graduated), record the outcome:

```python
        # RUN-06: feed the breaker from the GRADUATED path only. Every short-circuit deny above
        # (kill switch, identity, delegation, inter-agent auth, MCP quarantine, privilege, breaker) is
        # deliberately EXCLUDED: counting the breaker's own denials would make an open breaker feed
        # itself and never close, and counting pre-identity denials would let a forged id trip another
        # agent's breaker.
        if self._breaker is not None:
            if decision.outcome is Outcome.allow:
                await self._breaker.record_success(action.agent_id, action.target)
            else:
                await self._breaker.record_failure(action.agent_id, action.target)
```

**Steps (TDD):**
- [ ] Failing test (stub pipeline wiring like `tests/unit/test_kill_switch_pipeline.py`, plus a stub
  breaker recording calls): OPEN breaker → `Outcome.deny` with a `circuit_breaker`/`circuit_open`
  reason, policy+risk never ran (`pol.calls == 0`, `scorer.calls == 0`), audited (`evidence_ref` set);
  permitted (`status` → None) → normal evaluation and exactly ONE record call afterwards
  (`record_success` on allow, `record_failure` on a policy deny); **no recording on a short-circuit** —
  assert a forged-identity action records NOTHING and an OPEN-breaker deny records NOTHING (the
  feedback-loop guard); `breaker=None` → unchanged; the breaker is consulted only after identity (a
  forged action never reaches `status`). Run → fails.
- [ ] Implement the Protocols + ctor seam + Stage 1f + graduated recording. Run → passes.
- [ ] Commit `feat(pipeline): stage-1f breaker gate + graduated-path signal recording (RUN-06)`.

---

### Task 4: PEP error reporting

**Files:** modify `packages/sdk/src/agentos_sdk/enforce.py`, `middleware.py`, `wrappers.py`,
`__init__.py`; test `tests/unit/test_circuit_breaker_pipeline.py` (PEP portion).

RUN-06 counts violations **or errors**; a governed execution that raises is an error signal the
pipeline cannot see. Add the seam and report around the run sites:

```python
class CircuitReporter(Protocol):
    """RUN-06 seam (PEP side): report a governed EXECUTION failure, which the PDP cannot observe."""

    async def record_failure(self, agent_id: str, target: str) -> None: ...
```

`governed_call` gains `reporter: CircuitReporter | None = None`, and each `_run_within_limits(...)`
call site becomes:

```python
        return await _run_reported(run, action, decision, governor, reporter)
```

with:

```python
async def _run_reported(
    run: Callable[[], Awaitable[_T]],
    action: AgentAction,
    decision: Decision,
    governor: ResourceGovernor | None,
    reporter: CircuitReporter | None,
) -> _T:
    """RUN-06: a governed execution that RAISES is an error signal for the breaker. Governance blocks
    (GovernanceDenied and its subclasses) are NOT execution errors — they are already counted by the
    PDP's graduated-path recording, so double-counting them would trip breakers twice as fast."""
    try:
        return await _run_within_limits(run, action, decision, governor)
    except GovernanceDenied:
        raise
    except Exception:
        if reporter is not None:
            await reporter.record_failure(action.agent_id, action.target)
        raise
```

`middleware.py` / `wrappers.py` accept and forward `reporter`; export `CircuitReporter`.

**Steps (TDD):**
- [ ] Failing test: a handler raising `RuntimeError` under `governed_call(..., reporter=stub)` → the
  error propagates AND exactly one `record_failure` was reported; a handler raising
  `GovernanceDenied`-family (e.g. the sandbox `GovernanceQuarantined`) reports NOTHING (no
  double-count); a successful handler reports nothing here (success is the PDP's job); `reporter=None`
  → unchanged. Run → fails.
- [ ] Implement. Run → full suite green.
- [ ] Commit `feat(sdk): report governed execution failures to the breaker (RUN-06)`.

---

### Task 5: e2e + full gate

**Files:** test `tests/integration/test_circuit_breaker_e2e.py`.

**Steps (TDD):**
- [ ] Failing e2e over the REAL governed stack sharing ONE store and the SAME `CircuitBreakerStore`
  instance (`failure_threshold=2`, injectable clock):
  - baseline: a benign allowlisted `http_get` is `allow` (attributable baseline);
  - two exfil actions to a non-allowlisted host (real policy-floor denies) → the breaker trips;
  - the SAME agent's previously-benign action is now denied with `circuit_open` (containment beyond
    the original violation);
  - a DIFFERENT agent is unaffected;
  - advance the clock past the cooldown → the benign action is permitted again (HALF_OPEN), and a
    success closes the breaker (`circuit_reset`);
  - both transitions are on the audit chain and `verify_chain` reports ok;
  - kill-switch precedence: with BOTH a fleet kill and an open breaker, the reason code is the kill
    switch's (`fleet_killed`), proving operator intent is evaluated before the automatic trip.
- [ ] Run → fails, then passes.
- [ ] `pytest -q` green; `-m floor_invariant`, `-m regression_lock` green; `-m latency` (baseline-check
  a wall-clock failure before attributing it).
- [ ] Commit `test(breaker): e2e — violations trip, cooldown recovers, kill switch wins (RUN-06)`.

## Self-review
RUN-06 is realized: rolling-window violation/error counters trip per-agent and per-(agent,target)
breakers, an OPEN breaker denies at Stage 1f with `circuit_open`, a cooldown admits trials and a success
closes, and an operator can reset. The two traps are closed by construction and asserted: recording
happens on the **graduated path only** (so the breaker never feeds itself, and never counts an
unverified/forged id), and PEP-side error reporting explicitly skips `GovernanceDenied`-family blocks to
avoid double-counting. Counters are in-memory (no hot-path DB read); transitions are commit-then-cache
(no divergence) and reload on restart so containment survives a restart. Kill-switch-before-breaker
precedence is asserted with distinct reason codes. Migration 0014 single-head; `None` defaults keep every
existing deployment and test unchanged.
