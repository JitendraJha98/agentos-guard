# Phase 10 · Slice 10d — Shadow-Agent Detection (DISC-04) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Commits end
> with a second `-m "Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"`. Tests:
> `./.venv/Scripts/python.exe -m pytest`. TDD per task, one commit each. Gates `floor_invariant`
> + `regression_lock` green at every commit. (`-m latency` is wall-clock and marginal on this box —
> re-run when idle and compare against a scratch worktree at `886ad59` before claiming a regression.
> NEVER loosen the budget.)

**Goal (DISC-04):** Flag agents **acting without registration**. The pipeline already denies them at
stage 1 (IDN-02) — this slice makes them **visible**, so an operator learns that an unregistered actor
is probing the fleet instead of it being one deny among thousands.

**Architecture:** A `ShadowAgentStore` records `{claimed_agent_id, action_type, attempts, first_seen,
last_seen}` and audits `shadow_agent_detected` the FIRST time a claimed id is seen. It is fed from the
pipeline's existing identity short-circuit through an optional `ShadowReporter` seam — **observation
only, no new deny path** (the deny already happened; adding a second one would change behaviour, not
visibility).

**The claimed id is attacker-controlled.** That drives three rules, all enforced here:
1. It is **bounded and sanitized** before storage (a 10 MB id must not become a 10 MB row).
2. It is **never a metric label** (the Phase-6 cardinality lesson: an unbounded label set is a DoS).
3. It is **never placed raw in a hash-covered audit body** — the event carries a bounded, sanitized
   identifier plus a digest, so a hostile id cannot trip the AUD-04 secret gate and block the record.

**Tech Stack:** SQLAlchemy 2.0 + Alembic, FastAPI, pytest.

> First commit in this slice: `docs(phase-10): Slice 10d plan` for this file, then the tasks below.

## File structure
- Modify `.../store/models.py` — `ShadowAgent`.
- Create `.../store/migrations/versions/0018_shadow_agent.py` (down_revision `0017_discovered_framework`).
- Modify `.../audit.py` — `EVENT_KINDS += "shadow_agent_detected"`.
- Create `.../agentos_controlplane/shadow.py` — `ShadowAgentStore`.
- Modify `packages/pipeline/src/agentos_pipeline/runner.py` — `ShadowReporter` Protocol + a report at
  the identity short-circuit.
- Modify `.../api.py` — a read route.
- Tests: `tests/unit/test_shadow_agents.py`, `tests/unit/test_shadow_pipeline.py`,
  `tests/integration/test_shadow_agents_api.py`.

---

### Task 1: model + migration 0018 + event kind

**Files:** modify `.../store/models.py`, `.../audit.py`; create the migration; test
`tests/unit/test_shadow_agents.py` (round-trip portion).

```python
class ShadowAgent(Base):
    """DISC-04 — an actor that ACTED without being registered.

    `claimed_agent_id` is ATTACKER-CONTROLLED: it is whatever an unverified caller put in its token,
    so it is bounded to 255 chars and sanitized before it ever reaches this row. It is stored to give
    an operator something to recognise, never trusted — the action itself was already denied at
    stage 1 (IDN-02).
    """

    __tablename__ = "shadow_agent"

    claimed_agent_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    action_type: Mapped[str] = mapped_column(String(64), nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )
```

`audit.py`:
```python
        # DISC-04 (Slice 10d): an unregistered actor was seen acting. The claimed id is
        # attacker-controlled, so the body carries a BOUNDED, sanitized identifier + a digest —
        # never the raw string, which could otherwise trip the AUD-04 gate and block the record.
        "shadow_agent_detected",
```

Migration `0018_shadow_agent.py` (`revision = "0018_shadow_agent"`,
`down_revision = "0017_discovered_framework"`): create `shadow_agent` with those columns
(`sa.String(255)` pk, `sa.String(64)`, `sa.Integer()` server_default `"1"`, two timestamps);
`downgrade` drops it.

**Steps:**
- [ ] Failing test: in-memory store; insert a `ShadowAgent(claimed_agent_id="ghost",
  action_type="tool_call")`, read back with `attempts == 1`; assert
  `append_event("shadow_agent_detected", {...})` is accepted and an unknown kind still raises.
  Run → fails.
- [ ] Add model + event kind + migration. Run → passes; verify a SINGLE head
  (`['0018_shadow_agent']`).
- [ ] Commit `feat(controlplane): shadow_agent table + event kind + migration 0018 (DISC-04)`.

---

### Task 2: `ShadowAgentStore` — bounded, sanitized, first-sighting audited

**Files:** create `.../agentos_controlplane/shadow.py`; test `tests/unit/test_shadow_agents.py`.

```python
"""DISC-04 — shadow-agent detection: who is acting without being registered.

The pipeline already DENIES these (IDN-02); this store makes them VISIBLE, because a hundred denies
from one unregistered id is an incident and a single deny is noise. Recording only — no new deny path.

Everything here treats `claimed_agent_id` as hostile input: bounded, sanitized, never a metric label
(Phase-6 cardinality lesson), and never raw inside a hash-covered audit body (AUD-04 gate).
"""
from __future__ import annotations

import hashlib
import re

from sqlalchemy import select

from agentos_controlplane.store.models import ShadowAgent

_MAX_ID = 255
# Control characters and anything exotic are replaced rather than stored: an operator reads these in
# a dashboard and a log, and a claimed id is a place to hide terminal escapes or a payload.
_SAFE = re.compile(r"[^A-Za-z0-9._:@-]")


def sanitize_claimed_id(raw: str) -> str:
    """Bound and flatten an attacker-controlled identifier. Empty input becomes a stable
    placeholder so anonymous probes still aggregate into one row instead of vanishing."""
    text = _SAFE.sub("?", (raw or "")[:_MAX_ID])
    return text or "<empty>"


def claimed_id_digest(raw: str) -> str:
    """A short digest of the FULL raw id, so truncation cannot make two different attackers look
    like one in the evidence chain."""
    return hashlib.sha256((raw or "").encode("utf-8", "replace")).hexdigest()[:16]


class ShadowAgentStore:
    def __init__(self, session_factory, audit) -> None:
        self._sf = session_factory
        self._audit = audit

    async def record(self, claimed_agent_id: str, action_type: str) -> bool:
        """Record one sighting. Returns True if this was the FIRST time this id was seen.

        Only a first sighting is audited: a flood of attempts from one id is a single incident, and
        appending an event per attempt would let an unregistered caller grow the hash chain at will.
        """
        safe = sanitize_claimed_id(claimed_agent_id)
        with self._sf() as s:
            row = s.get(ShadowAgent, safe)
            first = row is None
            if row is None:
                s.add(ShadowAgent(claimed_agent_id=safe, action_type=action_type, attempts=1))
            else:
                row.attempts += 1
                row.action_type = action_type
            s.commit()
        if first:
            await self._audit.append_event(
                "shadow_agent_detected",
                {
                    "claimed_agent_id": safe,
                    "claimed_id_digest": claimed_id_digest(claimed_agent_id),
                    "action_type": action_type,
                },
            )
        return first

    def list_shadow_agents(self) -> list[dict]:
        with self._sf() as s:
            rows = s.scalars(
                select(ShadowAgent).order_by(ShadowAgent.last_seen_at.desc())
            ).all()
            return [
                {
                    "claimed_agent_id": r.claimed_agent_id,
                    "action_type": r.action_type,
                    "attempts": r.attempts,
                    "first_seen_at": r.first_seen_at.isoformat() if r.first_seen_at else None,
                    "last_seen_at": r.last_seen_at.isoformat() if r.last_seen_at else None,
                }
                for r in rows
            ]
```

**Steps (TDD):**
- [ ] Failing tests over a shared in-memory store + real `AuditWriter`:
  - first `record("ghost", "tool_call")` → returns True, one row with `attempts == 1`, one
    `shadow_agent_detected` event;
  - a SECOND record of the same id → returns False, `attempts == 2`, and **still only one event**
    (an unregistered caller must not be able to grow the hash chain at will);
  - a 10 000-char id is stored bounded to 255 and does not raise;
  - control characters / ANSI escapes / newlines in the id are replaced (assert the stored value
    matches `^[A-Za-z0-9._:@?-]+$`);
  - an empty id becomes `<empty>` and still aggregates;
  - two DIFFERENT long ids sharing the first 255 chars produce DIFFERENT `claimed_id_digest`
    values in their events (truncation must not merge two attackers);
  - a secret-bearing id (an `AKIA...`-style canary) still records successfully and `verify_chain(sf)`
    stays ok — the record can never be blocked by its own hostile input;
  - `list_shadow_agents()` shape + ordering.
  Run → fails.
- [ ] Implement `shadow.py`. Run → passes.
- [ ] Commit `feat(controlplane): ShadowAgentStore — bounded, sanitized, first-sighting audited (DISC-04)`.

---

### Task 3: wire the pipeline's identity short-circuit

**Files:** modify `packages/pipeline/src/agentos_pipeline/runner.py`; test
`tests/unit/test_shadow_pipeline.py`.

Add a Protocol beside the existing seams:

```python
class ShadowReporter(Protocol):
    """DISC-04 seam: report an actor that acted WITHOUT being registered. Observation only — the
    identity stage has already denied the action; this exists so the attempt is visible."""

    async def record(self, claimed_agent_id: str, action_type: str) -> bool: ...
```

`Pipeline.__init__` gains `shadow: ShadowReporter | None = None` → `self._shadow`
(`None` default → nothing changes).

In `_evaluate`, inside the EXISTING stage-1 identity short-circuit block (where `ident.ok` is false),
AFTER the decision is built and audited and BEFORE it is returned:

```python
            # DISC-04: the deny already happened; record the sighting so an unregistered actor is
            # VISIBLE rather than being one deny among thousands. Observation only — never a second
            # deny path, and never allowed to break governance: a failure here must not turn a clean
            # deny into a fail-safe.
            if self._shadow is not None:
                try:
                    await self._shadow.record(action.agent_id, action.type.value)
                except Exception:
                    logging.getLogger(__name__).warning(
                        "shadow-agent sighting not recorded for action %s", action.id
                    )
```

**Steps (TDD):**
- [ ] Failing test (stub pipeline wiring like `tests/unit/test_kill_switch_pipeline.py`, plus a stub
  shadow reporter):
  - a forged/unknown identity → outcome is still `deny` with `forged_or_unknown_identity` AND the
    reporter received `(claimed_agent_id, action_type)`;
  - a VERIFIED agent → the reporter is never called (`calls == []`);
  - `shadow=None` → behaviour unchanged (backward compat);
  - a reporter that RAISES → the decision is STILL the clean identity deny (not a fail-safe
    `control_plane_failure` outcome) — observation must never degrade enforcement;
  - the reason list is unchanged by the reporting (no extra reason appended).
  Run → fails.
- [ ] Implement the Protocol + ctor seam + the report. Run → passes.
- [ ] Commit `feat(pipeline): report unregistered actors to the shadow store (DISC-04)`.

---

### Task 4: read API + e2e + full gate

**Files:** modify `.../api.py`; test `tests/integration/test_shadow_agents_api.py`.

Add to `build_inventory_router` (extend its signature with
`shadow: "ShadowAgentStore | None" = None`, and thread `shadow_store` through `create_app`, both
defaulting to `None`):

```python
    @router.get("/discovery/shadow-agents")
    def list_shadow_agents() -> list[dict]:
        """DISC-04 — actors seen acting without registration."""
        if shadow is None:
            raise HTTPException(status_code=404, detail="shadow detection is not wired")
        return shadow.list_shadow_agents()
```

**Steps (TDD):**
- [ ] Failing e2e over the REAL stack sharing ONE store (mirror `tests/integration/test_gateway_pep.py`
  or `test_inventory_api.py`): build a real pipeline with `shadow=ShadowAgentStore(sf, audit)` and the
  app with the same store instance. Assert:
  - an action carrying an UNREGISTERED agent's token (or no token) is denied AND
    `GET /discovery/shadow-agents` then lists that claimed id with `attempts == 1`;
  - a second such action → `attempts == 2` and still one audit event;
  - a REGISTERED agent's benign action does NOT appear in the list;
  - no token → 401 on the route; app built without a shadow store → 404;
  - `verify_chain` still ok.
- [ ] Run → fails, then passes.
- [ ] `pytest -q` green; `-m floor_invariant`, `-m regression_lock` green; `-m latency` (baseline-check
  before attributing a wall-clock failure — the reporter only runs on the identity-deny path, never on
  the allowed hot path).
- [ ] Commit `feat(controlplane): shadow-agent read API + e2e (DISC-04)`.

## Self-review
DISC-04 is realized: an actor acting without registration is denied as before AND now recorded, so an
operator sees the probe rather than losing it among routine denies. Every rule that follows from the
claimed id being attacker-controlled is enforced and tested — bounded, sanitized, digested so
truncation cannot merge two attackers, never a metric label, and never raw in a hash-covered body, so a
hostile id can neither block its own record nor grow the chain (only first sightings are audited).
Observation never degrades enforcement: a reporter that raises still yields the clean identity deny,
asserted directly. `shadow=None` and the `None`-defaulted API parameters keep every existing caller
unchanged; migration 0018 single-head; nothing added to the allowed-path hot path.
