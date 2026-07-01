# Phase 4 · Slice 4e — Operator Kill Switch (RUN-01/02) — Implementation Plan

> REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Commits end with a second
> `-m "Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"`. Tests:
> `./.venv/Scripts/python.exe -m pytest`. TDD per task. Gates `floor_invariant` (430) +
> `regression_lock` (10) green at every commit.

**Goal:** An operator can kill-switch a single agent (RUN-01) or the entire fleet (RUN-02); the
targeted agents' actions **halt immediately**. A pre-policy **stage 0** in the pipeline denies a
killed agent's every subsequent action before any other stage runs; the operator toggles via the
resolve API; every toggle is an `AuditRecord` on the hash chain.

**Honest scope (document):** at the SDK-interception layer "halt immediately" = every *subsequent*
action is denied the instant the switch flips (an in-memory flag checked per action, so the hot
path stays fast). An action already mid-flight in the agent isn't force-terminated — true in-flight
kill is the gateway/sandbox layer (Phase 9/10). Fleet kill denies all agents; per-agent kill denies
one.

**Design:** kill state is kept **in-memory** in `KillSwitchStore` (a set of killed agent ids + a
fleet flag), persisted to a `kill_switch` table for durability and loaded at construction — so the
hot-path check is an in-memory lookup (no per-action DB read; mirrors the PIPE-06 own-cache
pattern), while the immutable history lives in the audit chain. The operator-supplied free-text
`reason` is stored in the TABLE only, NOT in the audit-event body (the event body carries
short identifiers — target/scope/set_by — so the 4d secret-gate on `append_event` can never block
an emergency kill).

> First commit: `docs(phase-4): Slice 4e plan` for this file, then the tasks.

## File structure
- Modify `store/models.py` — `KillSwitch` table (+ `Boolean` import); migration `0005_kill_switch.py`.
- Modify `audit.py` — `EVENT_KINDS += {"kill_switch_set", "kill_switch_cleared"}`.
- Create `killswitch.py` — `KillStatus`, `KillSwitchStore`.
- Modify `runner.py` — `kill_switch: KillSwitchLookup | None = None`; stage-0 kill check.
- Modify `api.py` — `build_kill_router` + `create_app(store, kill_store=None)`.
- Tests: `tests/unit/test_kill_switch_store.py`, `test_kill_switch_pipeline.py`,
  `tests/integration/test_kill_switch_api.py`.

---

### Task 1: model + migration + event kinds
- `store/models.py` (+ `Boolean` to the sqlalchemy import):
```python
class KillSwitch(Base):
    """RUN-01/02 — CURRENT kill-switch state (immutable history lives in the audit chain).
    target = an agent_id, or "*" for the whole fleet."""
    __tablename__ = "kill_switch"
    target: Mapped[str] = mapped_column(String(255), primary_key=True)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    set_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
```
- Migration `0005_kill_switch.py` mirrors `0004` (down_revision = `0004`'s revision); creates the
  table; downgrade drops it.
- `audit.py`: add `"kill_switch_set"`, `"kill_switch_cleared"` to `EVENT_KINDS`.
- Tests: row round-trips; the two new event kinds are accepted by `append_event` and an unknown
  kind still raises.
Commit `feat(controlplane): kill_switch table + event kinds + migration 0005 (RUN-01/02)`.

### Task 2: `KillSwitchStore`
`killswitch.py`:
```python
"""RUN-01/02 — operator kill switch. In-memory current state (fast hot-path lookup) backed by the
kill_switch table (durability) + the audit chain (immutable history). Single-process Phase-4 model;
distributed invalidation is Phase-7 reconciler territory."""
from __future__ import annotations
from dataclasses import dataclass
from sqlalchemy import select
from agentos_controlplane.store.models import KillSwitch

_FLEET = "*"

@dataclass(frozen=True)
class KillStatus:
    scope: str   # "agent" | "fleet"
    reason: str

class KillSwitchStore:
    def __init__(self, session_factory, audit) -> None:
        self._sf = session_factory
        self._audit = audit
        self._killed: dict[str, str] = {}   # active target -> reason (in-memory hot-path cache)
        self._load()

    def _load(self) -> None:
        with self._sf() as s:
            for row in s.scalars(select(KillSwitch).where(KillSwitch.active.is_(True))).all():
                self._killed[row.target] = row.reason or ""

    def status(self, agent_id: str) -> KillStatus | None:
        if _FLEET in self._killed:
            return KillStatus("fleet", self._killed[_FLEET])
        if agent_id in self._killed:
            return KillStatus("agent", self._killed[agent_id])
        return None

    async def kill(self, agent_id: str, *, set_by: str, reason: str = "") -> None:
        await self._set(agent_id, "agent", set_by, reason)

    async def kill_fleet(self, *, set_by: str, reason: str = "") -> None:
        await self._set(_FLEET, "fleet", set_by, reason)

    async def clear(self, agent_id: str, *, set_by: str) -> None:
        await self._clear(agent_id, "agent", set_by)

    async def clear_fleet(self, *, set_by: str) -> None:
        await self._clear(_FLEET, "fleet", set_by)

    def list_active(self) -> list[dict]:
        return [{"target": t, "scope": "fleet" if t == _FLEET else "agent", "reason": r}
                for t, r in sorted(self._killed.items())]

    async def _set(self, target, scope, set_by, reason):
        self._killed[target] = reason                                   # in-memory first (hot path)
        with self._sf() as s:                                          # upsert current state
            row = s.get(KillSwitch, target)
            if row is None:
                s.add(KillSwitch(target=target, active=True, reason=reason, set_by=set_by))
            else:
                row.active, row.reason, row.set_by = True, reason, set_by
            s.commit()
        # audit event body = short identifiers only (no free-text reason -> the 4d secret-gate on
        # append_event can never block an emergency kill).
        await self._audit.append_event("kill_switch_set", {"target": target, "scope": scope, "set_by": set_by})

    async def _clear(self, target, scope, set_by):
        self._killed.pop(target, None)
        with self._sf() as s:
            row = s.get(KillSwitch, target)
            if row is not None:
                row.active, row.set_by = False, set_by
                s.commit()
        await self._audit.append_event("kill_switch_cleared", {"target": target, "scope": scope, "set_by": set_by})
```
- Tests: kill agent → `status("a").scope == "agent"`; clear → None; `kill_fleet` → ANY agent_id
  status is "fleet"; `clear_fleet` → None; reason surfaced in status; state persists to the table
  AND a fresh `KillSwitchStore` over the same factory reloads active kills (`_load`); each
  kill/clear writes a `kill_switch_set`/`kill_switch_cleared` audit event (verify via the chain /
  `verify_chain` stays ok); the event body contains target/scope/set_by but NOT the free-text reason.
Commit `feat(controlplane): KillSwitchStore — in-memory state, persistence, audited toggles (RUN-01/02)`.

### Task 3: pipeline stage-0 kill check
`runner.py`:
- Add Protocols (structural, like `ExceptionLookup`):
```python
class KillVerdict(Protocol):
    scope: str
    reason: str

class KillSwitchLookup(Protocol):
    def status(self, agent_id: str) -> "KillVerdict | None": ...
```
- `Pipeline.__init__` gains `kill_switch: KillSwitchLookup | None = None` → `self._kill_switch`.
- In `_evaluate`, as **stage 0 (BEFORE identity)**:
```python
        # Stage 0 — Kill switch (RUN-01/02): an operator halt denies this agent's actions
        # immediately, before any other stage. Fleet kill denies everyone. Audited like the
        # identity short-circuit (evidence the action was blocked); no engine ran -> versions null.
        if self._kill_switch is not None:
            kv = self._kill_switch.status(action.agent_id)
            if kv is not None:
                reasons.append(Reason(stage="killswitch", code=f"{kv.scope}_killed", detail=kv.reason[:512]))
                decision = Decision(action_id=action.id, outcome=Outcome.deny, reasons=reasons)
                floor_box[0] = Outcome.deny
                decision.evidence_ref = await self._append_with_redaction_fallback(action, decision)
                return decision  # TERMINAL — identity/policy/risk never run
```
  (Reuse the existing `_append_with_redaction_fallback` helper. Placing kill BEFORE identity means a
  killed agent is denied even with a valid token — the strongest halt; a forged token claiming a
  non-killed id is still caught by identity afterward.)
- Tests (async, build a Pipeline with a stub `kill_switch`): killed agent → outcome deny + a
  `killswitch`/`agent_killed` reason + NO policy/risk/identity reasons (later stages skipped) +
  audited (evidence_ref set); fleet kill → any agent denied with `fleet_killed`; not-killed agent →
  normal evaluation proceeds; **kill is checked before identity** (a killed agent WITH a valid token
  still denies with `agent_killed`, not `identity_verified`); `kill_switch=None` → behavior
  unchanged (backward compat); the check is in-memory (no DB read on the hot path — assert the stub
  isn't given a session). Run `-m latency` — in-memory check, budget held.
Commit `feat(pipeline): stage-0 kill-switch check halts killed agents immediately (RUN-01/02)`.

### Task 4: resolve-API kill endpoints + e2e
`api.py`:
- Pydantic `KillRequest {set_by: str (max_length 128), reason: str | None (max_length 512) = None}`
  and `ClearRequest {set_by: str (max_length 128)}`.
- `build_kill_router(kill_store) -> APIRouter`: `GET /kill` (list_active); `POST /kill/agents/{agent_id}`
  (kill); `POST /kill/agents/{agent_id}/clear` (clear); `POST /kill/fleet` (kill_fleet);
  `POST /kill/fleet/clear` (clear_fleet). (POST for clear — avoids DELETE-with-body.)
- `create_app(store, kill_store=None)`: include `build_kill_router(kill_store)` when provided
  (keep existing `create_app(store)` callers working — kill_store optional).
- Tests (TestClient + a real pipeline e2e, file or in-memory store shared between the API and the
  pipeline's KillSwitchStore — same session_factory + the SAME KillSwitchStore instance so the
  in-memory flag is shared): `POST /kill/agents/{id}` → that agent's next `pipeline.evaluate` is
  denied (`agent_killed`); `POST .../clear` → the agent's action is allowed again; `POST /kill/fleet`
  → a different agent is denied (`fleet_killed`); `GET /kill` lists active; bounds enforced (200-char
  set_by → 422). This is the RUN-01/02 acceptance proof.
Commit `feat(controlplane): kill-switch resolve API + e2e halt/restore proof (RUN-01/02, API-03)`.

### Task 5: full gate
`pytest -q` green; `-m floor_invariant` 430; `-m regression_lock` 10; `-m latency` healthy (stage 0
is an in-memory dict check). Commit only if incidental fixes were needed.

## Self-review
RUN-01 (per-agent) + RUN-02 (fleet) — stage-0 in-memory check halts subsequent actions immediately,
audited, before identity; operator toggles via the API; each toggle on the hash chain
(short-identifier event body, secret-gate-safe); honest in-flight scope documented; backward
compatible (kill_switch None default); hot path stays in-memory (no per-action DB read). Gates green.
