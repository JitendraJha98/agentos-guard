# Phase 9 · Slice 9f — 2-of-3 Multi-Agent Consensus (POL-09) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Commits end
> with a second `-m "Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"`. Tests:
> `./.venv/Scripts/python.exe -m pytest`. TDD per task, one commit each. Gates `floor_invariant`
> + `regression_lock` green at every commit. (`-m latency` is wall-clock and noisy under machine load
> — if it fails, verify against a clean baseline via `git stash` before attributing it.)

**Goal (POL-09):** A `require_consensus` outcome requires **2-of-3 agent agreement** before the action
proceeds — the last outcome still riding the interim approval substitution.

**Architecture:** This closes the Phase-9 arc opened in 9a. `enforce.py` currently escalates
`require_consensus` onto the human-approval path with an audited `enforcement_substitution`; this slice
routes it to a `ConsensusCoordinator` seam (structural Protocol, SDK-side) that collects votes from
independent `ConsensusVoter`s, requires a quorum, persists a round + per-vote rows, and audits each vote
plus the resolution. Application-level voting, exactly as the roadmap scopes it — BFT is POL-12
(Phase 13).

**Fail-closed everywhere** (the Phase-9 invariant): no coordinator wired → `GovernanceDenied` before
`run()`; a voter that raises or times out counts as **no-vote**; anything short of quorum denies.

**Tech Stack:** stdlib `asyncio` (concurrent voting with per-voter timeout), SQLAlchemy 2.0 + Alembic,
pytest.

> First commit in this slice: `docs(phase-9): Slice 9f plan` for this file, then the tasks below.

## Retiring the substitution (deliberate cleanup)
`require_consensus` is the last member of `_SUBSTITUTED_TO_APPROVAL`, so after this slice the set is
empty and its branch in `governed_call` is unreachable. **Remove the empty set and its branch** (code
this slice orphaned). **Keep** `ApprovalCoordinator.record_substitution` and the
`enforcement_substitution` audit-event kind: existing audit chains contain those records and the event
kind must stay valid for the verifier, and the coordinator method remains a supported seam. Update the
tests that assert substitution-for-`require_consensus` to the new semantics rather than deleting them.

## File structure
- Modify `.../store/models.py` — `ConsensusRound`, `ConsensusVote`.
- Create `.../store/migrations/versions/00NN_consensus.py` (chain from the CURRENT head).
- Modify `.../audit.py` — `EVENT_KINDS += "consensus_vote"`, `"consensus_resolved"`.
- Create `.../agentos_controlplane/consensus.py` — `StoreConsensusCoordinator`.
- Modify `packages/sdk/src/agentos_sdk/enforce.py` — `ConsensusVoter`, `ConsensusCoordinator`,
  the `require_consensus` route, substitution removal.
- Modify `.../middleware.py`, `.../wrappers.py`, `.../__init__.py` — forward + export.
- Tests: `tests/unit/test_consensus_enforcement.py`, `tests/unit/test_consensus_coordinator.py`,
  `tests/integration/test_consensus_e2e.py`; UPDATE `tests/unit/test_outcome_enforcement.py`.

---

### Task 1: models + migration + event kinds

**Files:** modify `.../store/models.py`, `.../audit.py`; create `.../versions/00NN_consensus.py`;
test `tests/unit/test_consensus_coordinator.py` (round-trip + event-kind portion).

```python
class ConsensusRound(Base):
    """POL-09 — one consensus round for one action: how many voters were asked, how many approved,
    the quorum required, and whether it was reached."""

    __tablename__ = "consensus_round"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    action_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    agent_id: Mapped[str] = mapped_column(String(255), nullable=False)
    voters: Mapped[int] = mapped_column(Integer, nullable=False)
    approvals: Mapped[int] = mapped_column(Integer, nullable=False)
    quorum: Mapped[int] = mapped_column(Integer, nullable=False)
    reached: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class ConsensusVote(Base):
    """POL-09 — one voter's verdict in a round. `error` records a voter that raised or timed out,
    which counts as a NO-VOTE (fail-closed)."""

    __tablename__ = "consensus_vote"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    round_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    voter: Mapped[str] = mapped_column(String(255), nullable=False)
    approved: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    error: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
```

`audit.py`:

```python
        # POL-09 (Slice 9f): per-voter verdicts + the round resolution. Short identifiers + counts
        # only — voter rationale (if any) stays in the consensus_vote TABLE.
        "consensus_vote",
        "consensus_resolved",
```

Migration: `revision = "00NN_consensus"`; **`down_revision` = the CURRENT head** — determine it with
the heads one-liner (expected `['0015_emergency_shutdown']` if 9e landed first) and number this file one
higher. Create both tables; `downgrade` drops `consensus_vote` then `consensus_round`.

**Steps:**
- [ ] Failing test: in-memory store; insert a `ConsensusRound` + two `ConsensusVote` rows, read back;
  assert both new event kinds are accepted and an unknown kind still raises. Run → fails.
- [ ] Add models + event kinds + migration; verify a SINGLE head. Run → passes.
- [ ] Commit `feat(controlplane): consensus round/vote tables + event kinds + migration (POL-09)`.

---

### Task 2: the enforcement seam + `require_consensus` route

**Files:** modify `packages/sdk/src/agentos_sdk/enforce.py`, `middleware.py`, `wrappers.py`,
`__init__.py`; test `tests/unit/test_consensus_enforcement.py`; UPDATE
`tests/unit/test_outcome_enforcement.py`.

```python
class ConsensusVoter(Protocol):
    """POL-09 — one independent voter. `name` identifies it in the audit trail. A voter that raises or
    times out counts as a NO-VOTE (fail-closed) — it never counts as approval."""

    name: str

    async def vote(self, action: AgentAction, decision: Decision) -> bool: ...


class ConsensusCoordinator(Protocol):
    """POL-09 seam: collect votes and report whether quorum was reached. The concrete coordinator is
    `agentos_controlplane.consensus.StoreConsensusCoordinator`, which persists the round + votes and
    audits each vote plus the resolution."""

    async def reach_consensus(self, action: AgentAction, decision: Decision) -> bool: ...
```

In `governed_call`, add `consensus: ConsensusCoordinator | None = None`, and route
`require_consensus` **before** the remaining blocking-outcome block (mirroring 9a's `sandbox` route):

```python
    if outcome is Outcome.require_consensus:
        # POL-09: 2-of-3 agent agreement. No coordinator wired -> fail closed, exactly like a
        # blocking outcome without an approval coordinator: `run` is never awaited.
        if consensus is None:
            raise GovernanceDenied(decision)
        if not await consensus.reach_consensus(action, decision):
            raise GovernanceDenied(decision)  # quorum not reached
        return await _run_reported(run, action, decision, governor, reporter)
```

> Use whatever the current post-9d execution helper is named at the run sites (`_run_reported` after
> Slice 9d, `_run_within_limits` before it) — read the file and match, so consensus-approved execution
> still gets RUN-05 budgets and RUN-06 error reporting.

Then delete the now-unreachable `_SUBSTITUTED_TO_APPROVAL` set and its `if outcome in
_SUBSTITUTED_TO_APPROVAL:` block, and update the module docstring's outcome table so
`require_consensus` reads "2-of-3 consensus via the ConsensusCoordinator seam (POL-09)".
`middleware.py` / `wrappers.py` accept and forward `consensus`; export the two new Protocols.

**Steps (TDD):**
- [ ] Failing test with a stub pipeline returning `require_consensus`, a `ran` list, and a stub
  coordinator: quorum reached → handler runs, result returned; quorum NOT reached →
  `GovernanceDenied` and `ran == []`; `consensus=None` → `GovernanceDenied`, `ran == []`, and NO
  substitution recorded on a passed approval-coordinator stub; a coordinator that raises propagates
  with `ran == []`. Run → fails.
- [ ] Implement the seam + route + substitution removal. Run → passes.
- [ ] Update `tests/unit/test_outcome_enforcement.py`: the two tests still parametrized over
  `[Outcome.require_consensus]` (narrowed in 9a) now assert the CONSENSUS semantics — no
  `enforcement_substitution` event, and fail-closed without a coordinator — and the docstring table is
  updated. Assert `_SUBSTITUTED_TO_APPROVAL` no longer exists (e.g. `not hasattr(enforce,
  "_SUBSTITUTED_TO_APPROVAL")`), mirroring the existing `test_should_execute_is_retired` convention.
  Run the file → passes.
- [ ] Run the FULL suite → green. Commit
  `feat(sdk): ConsensusCoordinator seam — require_consensus needs quorum, not substitution (POL-09)`.

---

### Task 3: `StoreConsensusCoordinator`

**Files:** create `packages/controlplane/src/agentos_controlplane/consensus.py`;
test `tests/unit/test_consensus_coordinator.py`.

```python
"""POL-09 — application-level 2-of-3 consensus.

Voters are asked CONCURRENTLY with a per-voter timeout; a voter that raises or times out counts as a
NO-VOTE, never as approval (fail-closed). The round and every vote are persisted, and each vote plus the
resolution is audited with short identifiers + counts only. Protocol-level BFT is POL-12 (Phase 13).
"""
from __future__ import annotations

import asyncio
from uuid import uuid4

from agentos_contract import AgentAction, Decision

from agentos_controlplane.store.models import ConsensusRound, ConsensusVote


class StoreConsensusCoordinator:
    """Satisfies the SDK's `ConsensusCoordinator` Protocol structurally."""

    def __init__(self, session_factory, audit, voters, *, quorum: int = 2, timeout_s: float = 10.0) -> None:
        if not voters:
            raise ValueError("consensus requires at least one voter")
        if quorum < 1 or quorum > len(voters):
            raise ValueError(f"quorum must be between 1 and {len(voters)}")
        self._sf = session_factory
        self._audit = audit
        self._voters = list(voters)
        self._quorum = quorum
        self._timeout_s = timeout_s

    async def _one_vote(self, voter, action, decision) -> tuple[str, bool, str | None]:
        try:
            approved = await asyncio.wait_for(voter.vote(action, decision), timeout=self._timeout_s)
            return (voter.name, bool(approved), None)
        except (asyncio.TimeoutError, TimeoutError):
            return (voter.name, False, "timeout")  # a timeout is a NO-VOTE, never an approval
        except Exception as exc:
            return (voter.name, False, type(exc).__name__)

    async def reach_consensus(self, action: AgentAction, decision: Decision) -> bool:
        round_id = uuid4()
        results = await asyncio.gather(
            *(self._one_vote(v, action, decision) for v in self._voters)
        )
        approvals = sum(1 for _, approved, _ in results if approved)
        reached = approvals >= self._quorum
        with self._sf() as s:
            s.add(
                ConsensusRound(
                    id=round_id,
                    action_id=action.id,
                    agent_id=action.agent_id,
                    voters=len(self._voters),
                    approvals=approvals,
                    quorum=self._quorum,
                    reached=reached,
                )
            )
            for name, approved, error in results:
                s.add(
                    ConsensusVote(round_id=round_id, voter=name, approved=approved, error=error)
                )
            s.commit()
        for name, approved, error in results:
            await self._audit.append_event(
                "consensus_vote",
                {
                    "round_id": str(round_id),
                    "action_id": str(action.id),
                    "voter": name,
                    "approved": approved,
                    "error": error or "",
                },
            )
        await self._audit.append_event(
            "consensus_resolved",
            {
                "round_id": str(round_id),
                "action_id": str(action.id),
                "agent_id": action.agent_id,
                "approvals": approvals,
                "voters": len(self._voters),
                "quorum": self._quorum,
                "reached": reached,
            },
        )
        return reached
```

**Steps (TDD):**
- [ ] Failing test over a shared in-memory store + real `AuditWriter`, with stub voters
  (`name`, configurable verdict/delay/exception):
  - 2 of 3 approve → `reach_consensus` True; the round row has `approvals == 2, quorum == 2,
    reached True`; three `consensus_vote` events + one `consensus_resolved`;
  - 1 of 3 → False, `reached False`;
  - 3 of 3 → True;
  - a voter that RAISES counts as a no-vote: 2 approve + 1 raising → True; 1 approve + 2 raising →
    False, and the raising voters' rows carry `error` set;
  - a voter that HANGS past `timeout_s=0.05` counts as a no-vote (and the call still returns promptly);
  - construction validation: empty voters → `ValueError`; `quorum=0` and `quorum=4` (with 3 voters) →
    `ValueError`;
  - a voter payload canary: build the action with `payload={"content": "SECRET-CANARY"}` and assert the
    canary appears in NO audit event body;
  - `verify_chain(sf).ok` holds.
  Run → fails.
- [ ] Implement `consensus.py`. Run → passes.
- [ ] Commit `feat(controlplane): StoreConsensusCoordinator — concurrent voting, fail-closed (POL-09)`.

---

### Task 4: e2e + full gate

**Files:** test `tests/integration/test_consensus_e2e.py`.

**Steps (TDD):**
- [ ] Failing e2e over the REAL governed stack sharing ONE store: build a pipeline whose decision for
  the probe action is `require_consensus` deterministically — construct the `Pipeline` with
  `thresholds=GraduatedThresholds(...)` tuned so the probe grades there, OR (simpler and preferred) use
  a constitution principle whose effect is `require_consensus` from `tests/fixtures/`; **assert the
  decision outcome IS `Outcome.require_consensus` first** so the enforcement assertions are meaningful.
  Then:
  - with 2-of-3 approving voters → the handler RUNS (result returned), the round row says reached, and
    the chain verifies;
  - with 1-of-3 → `GovernanceDenied`, handler never ran;
  - through `GovernanceMiddleware(..., consensus=coordinator)` the denied case returns a `ToolMessage`
    with `status == "error"` (the 9a contained-outcome convention) and the handler never ran;
  - without a coordinator → denied, handler never ran (fail-closed).
- [ ] Run → fails, then passes.
- [ ] `pytest -q` green; `-m floor_invariant`, `-m regression_lock` green; `-m latency` (baseline-check a
  wall-clock failure before attributing it).
- [ ] Commit `test(consensus): e2e — 2-of-3 quorum gates execution (POL-09)`.

## Self-review
POL-09 is realized: `require_consensus` no longer borrows the human-approval path — it routes to a
`ConsensusCoordinator` that asks independent voters concurrently, requires a 2-of-3 quorum, persists the
round + per-vote verdicts, and audits every vote plus the resolution (short identifiers + counts only,
canary-tested). Fail-closed on every axis: no coordinator, a raising voter, a hanging voter, or any
sub-quorum tally all deny with the handler never awaited. Consensus-approved execution still flows
through the RUN-05 budget / RUN-06 reporting helper, so containment composes rather than being bypassed.
The interim substitution machinery this slice orphaned is removed while the `record_substitution` seam
and its event kind are retained for historical audit records; the narrowed tests are updated rather than
deleted. This is the last outcome in the graduated spectrum to get real enforcement — the Phase-9 arc
that 9a opened is now closed.
