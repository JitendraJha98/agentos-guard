# Phase 9 · Slice 9e — Emergency Shutdown (RUN-07) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Commits end
> with a second `-m "Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"`. Tests:
> `./.venv/Scripts/python.exe -m pytest`. TDD per task, one commit each. Gates `floor_invariant`
> + `regression_lock` green at every commit. (`-m latency` is wall-clock and noisy under machine load
> — if it fails, verify against a clean baseline via `git stash` before attributing it.)

**Goal (RUN-07):** An operator can stop the entire fleet with a **mandatory, audit-logged
justification**, and resume it explicitly.

**Architecture:** Emergency shutdown *extends* the existing RUN-01/02 kill switch rather than adding a
second halt mechanism — it sets the same fleet flag, so the pipeline's stage-0 check already halts
every agent with **zero new hot-path code**. What shutdown adds: a required justification, a durable
per-incident record (the `kill_switch` table only holds current state, so an append-only
`emergency_shutdown` table preserves incident history), an explicit resume, and a distinguishable
`emergency` scope so forensics can tell an emergency halt from a routine fleet kill.

**Justification handling** follows the established containment convention: the free-text justification
lives in the **table**, and the audit event carries **short identifiers + the incident id** only — so a
hostile or secret-bearing string can never trip the AUD-04 secret gate and block an emergency stop.

**Tech Stack:** SQLAlchemy 2.0 (sync) + Alembic, FastAPI + Pydantic v2, Jinja2/HTMX dashboard, pytest.

> First commit in this slice: `docs(phase-9): Slice 9e plan` for this file, then the tasks below.

## File structure
- Modify `packages/controlplane/src/agentos_controlplane/store/models.py` — `EmergencyShutdown` table.
- Create `.../store/migrations/versions/00NN_emergency_shutdown.py` (chain from the CURRENT head).
- Modify `.../audit.py` — `EVENT_KINDS += "emergency_shutdown"`, `"emergency_resume"`.
- Modify `.../killswitch.py` — `emergency_shutdown()`, `resume_fleet()`, `_emergency` flag,
  `status()` scope, `active_incident()`.
- Modify `.../api.py` — `EmergencyShutdownRequest`, two routes on the existing kill router.
- Modify `.../dashboard.py` + `.../templates/kill.html` — shutdown + resume controls.
- Tests: `tests/unit/test_emergency_shutdown.py`, `tests/integration/test_emergency_shutdown_e2e.py`.

---

### Task 1: `EmergencyShutdown` table + migration + event kinds

**Files:**
- Modify: `.../store/models.py`, `.../audit.py`
- Create: `.../store/migrations/versions/00NN_emergency_shutdown.py`
- Test: `tests/unit/test_emergency_shutdown.py` (round-trip + event-kind portion)

```python
class EmergencyShutdown(Base):
    """RUN-07 — an append-only record of one fleet-wide emergency stop.

    The `kill_switch` table holds only CURRENT state (it is upserted), so incident HISTORY lives here:
    who declared the stop, when, why, and when it was resumed. The free-text `justification` lives in
    this table ONLY — the audit event carries short identifiers + this row's id, so a secret-bearing
    justification can never trip the AUD-04 gate and block an emergency stop.
    """

    __tablename__ = "emergency_shutdown"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    justification: Mapped[str] = mapped_column(Text, nullable=False)
    declared_by: Mapped[str] = mapped_column(String(255), nullable=False)
    declared_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    resumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resumed_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
```

`audit.py` — add both kinds in the file's comment style:

```python
        # RUN-07 (Slice 9e): fleet-wide emergency stop + explicit resume. Short identifiers + the
        # incident id only — the free-text justification stays in the emergency_shutdown TABLE.
        "emergency_shutdown",
        "emergency_resume",
```

Migration: `revision = "00NN_emergency_shutdown"`; **`down_revision` = the CURRENT migration head** —
determine it, do not guess:
`./.venv/Scripts/python.exe -c "from alembic.config import Config; from alembic.script import ScriptDirectory; import agentos_controlplane.store as s, os; d=os.path.dirname(s.__file__); c=Config(); c.set_main_option('script_location', os.path.join(d,'migrations')); print(ScriptDirectory.from_config(c).get_heads())"`
(expected `['0014_circuit_breakers']` if Slice 9d landed first; number this file one higher than that).

```python
def upgrade() -> None:
    op.create_table(
        "emergency_shutdown",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("justification", sa.Text(), nullable=False),
        sa.Column("declared_by", sa.String(length=255), nullable=False),
        sa.Column("declared_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("resumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resumed_by", sa.String(length=255), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("emergency_shutdown")
```

**Steps:**
- [ ] Failing test: in-memory store; insert an `EmergencyShutdown(justification="prompt-injection
  incident", declared_by="op")`, read it back, assert `resumed_at is None`; assert
  `append_event("emergency_shutdown", {...})` and `append_event("emergency_resume", {...})` are
  accepted and an unknown kind still raises. Run → fails.
- [ ] Add the model + event kinds + migration. Run → passes; verify a SINGLE head.
- [ ] Commit `feat(controlplane): emergency_shutdown table + event kinds + migration (RUN-07)`.

---

### Task 2: `KillSwitchStore.emergency_shutdown()` / `resume_fleet()`

**Files:**
- Modify: `packages/controlplane/src/agentos_controlplane/killswitch.py`
- Test: `tests/unit/test_emergency_shutdown.py`

Extend the store. Reuse `_set`/`_clear` for the fleet flag so the halt mechanism (and its
fail-toward-contained ordering) is not duplicated:

```python
    async def emergency_shutdown(self, *, justification: str, set_by: str) -> str:
        """RUN-07 — stop the WHOLE fleet with a mandatory justification. Returns the incident id.

        Reuses the RUN-02 fleet flag, so the pipeline's stage-0 check halts every agent with no new
        hot-path code. The justification is REQUIRED: an empty/whitespace one is rejected and nothing
        is halted (an unexplained fleet stop is not an auditable control).
        """
        text = (justification or "").strip()
        if not text:
            raise ValueError("emergency shutdown requires a non-empty justification")
        incident_id = uuid4()
        # Durable incident record FIRST: the justification must survive even if a later step fails.
        with self._sf() as s:
            s.add(EmergencyShutdown(id=incident_id, justification=text, declared_by=set_by))
            s.commit()
        self._emergency = True  # distinguishes an emergency stop from a routine fleet kill
        # The fleet flag itself (in-memory first, then durable, then audited) — the RUN-02 path.
        await self._set(_FLEET, "emergency", set_by, text)
        # Short identifiers + the incident id only; the justification text stays in the table.
        await self._audit.append_event(
            "emergency_shutdown",
            {"incident_id": str(incident_id), "scope": "fleet", "set_by": set_by},
        )
        return str(incident_id)

    async def resume_fleet(self, *, set_by: str) -> None:
        """RUN-07 — explicit operator resume: close the open incident and clear the fleet halt."""
        with self._sf() as s:
            row = s.scalar(
                select(EmergencyShutdown)
                .where(EmergencyShutdown.resumed_at.is_(None))
                .order_by(EmergencyShutdown.declared_at.desc())
                .limit(1)
            )
            incident_id = str(row.id) if row is not None else None
            if row is not None:
                row.resumed_at, row.resumed_by = datetime.now(timezone.utc).replace(tzinfo=None), set_by
                s.commit()
        await self._audit.append_event(
            "emergency_resume",
            {"incident_id": incident_id or "", "scope": "fleet", "set_by": set_by},
        )
        await self._clear(_FLEET, "emergency", set_by)  # durable-first un-halt (existing path)
        self._emergency = False

    def active_incident(self) -> str | None:
        """The open incident id, or None. Read from the table (operator-facing, not the hot path)."""
        with self._sf() as s:
            row = s.scalar(
                select(EmergencyShutdown)
                .where(EmergencyShutdown.resumed_at.is_(None))
                .order_by(EmergencyShutdown.declared_at.desc())
                .limit(1)
            )
            return str(row.id) if row is not None else None
```

`__init__` gains `self._emergency = False` **before** `self._load()`, and `_load` sets it from an open
incident so a restart does not downgrade an emergency stop to a routine kill:

```python
            self._emergency = (
                s.scalar(
                    select(EmergencyShutdown).where(EmergencyShutdown.resumed_at.is_(None)).limit(1)
                )
                is not None
            )
```

`status()` reports the distinguishable scope (so the pipeline's existing
`Reason(code=f"{kv.scope}_killed")` yields `emergency_killed` vs `fleet_killed` with **no pipeline
change**):

```python
        if _FLEET in self._killed:
            return KillStatus("emergency" if self._emergency else "fleet", self._killed[_FLEET])
```

Add the imports this needs: `from datetime import datetime, timezone`, `from uuid import uuid4`, and
`EmergencyShutdown` to the models import.

**Steps (TDD):**
- [ ] Failing tests over a shared in-memory store + real `AuditWriter`:
  - `await emergency_shutdown(justification="incident 42", set_by="op")` returns an id; `status("any-
    agent-never-seen")` is not None with `scope == "emergency"`; one `emergency_shutdown` event exists
    whose body contains the incident id and **not** the justification text; the row holds the
    justification; `active_incident()` returns the id;
  - empty and whitespace-only justifications raise `ValueError`, **nothing is halted**
    (`status("a") is None`), no row, no event;
  - `await resume_fleet(set_by="op")` → `status("a") is None`, the row has `resumed_at`/`resumed_by`
    set, one `emergency_resume` event exists;
  - a routine `await kill_fleet(set_by="op")` still reports `scope == "fleet"` (regression guard on the
    existing RUN-02 behavior);
  - a fresh `KillSwitchStore` over the same tables during an open incident reloads BOTH the halt and
    `scope == "emergency"` (a restart must not downgrade it);
  - `verify_chain(sf).ok` holds throughout;
  - a secret-bearing justification (`"leaked AKIA..." style canary`) still shuts down successfully and
    the canary appears in NO audit event body (the whole point of table-only free text).
  Run → fails.
- [ ] Implement. Run → passes; run the FULL suite (existing kill-switch tests must stay green).
- [ ] Commit `feat(controlplane): emergency shutdown + explicit resume on the kill switch (RUN-07)`.

---

### Task 3: API + dashboard controls

**Files:**
- Modify: `packages/controlplane/src/agentos_controlplane/api.py`, `.../dashboard.py`,
  `.../templates/kill.html`
- Test: `tests/integration/test_emergency_shutdown_e2e.py`

`api.py` — add the request model next to `KillRequest`, and two routes inside `build_kill_router`:

```python
class EmergencyShutdownRequest(BaseModel):
    model_config = {"extra": "forbid"}

    set_by: str = Field(max_length=128)
    justification: str = Field(min_length=1, max_length=2000)  # REQUIRED (RUN-07) -> empty is a 422
```

```python
    @router.post("/kill/emergency-shutdown")
    async def emergency_shutdown(body: EmergencyShutdownRequest) -> dict:
        try:
            incident_id = await kill_store.emergency_shutdown(
                justification=body.justification, set_by=body.set_by
            )
        except ValueError as exc:  # whitespace-only survives min_length -> still a 422
            raise HTTPException(status_code=422, detail=str(exc)) from None
        return {"incident_id": incident_id, "scope": "fleet", "active": True}

    @router.post("/kill/emergency-resume")
    async def emergency_resume(body: ClearRequest) -> dict:
        await kill_store.resume_fleet(set_by=body.set_by)
        return {"scope": "fleet", "active": False}
```

`dashboard.py` — add two cookie-gated POST actions mirroring the existing kill actions
(`Form(...)` fields `justification` + `set_by`, redirect back to `/dashboard/kill`), and pass
`active_incident=kill_store.active_incident()` into the `kill.html` context. `kill.html` gains an
emergency-shutdown form (a required `justification` textarea) and a resume button, plus a banner when
`active_incident` is set.

**Steps (TDD):**
- [ ] Failing e2e over ONE shared store with the SAME `KillSwitchStore` instance behind both the API
  and a real pipeline (mirror `tests/integration/test_kill_switch_api.py`):
  - baseline: a benign action for `AGENT_ID` is `allow`;
  - `POST /kill/emergency-shutdown {"set_by": "op", "justification": "incident 42"}` → 200 with an
    `incident_id`; the SAME pipeline now denies BOTH `AGENT_ID` and a never-before-seen agent with
    reason code `emergency_killed`;
  - `POST /kill/emergency-shutdown {"set_by": "op", "justification": ""}` → 422 and nothing halted;
    `"   "` (whitespace) → 422 as well;
  - `POST /kill/emergency-resume {"set_by": "op"}` → 200 and both agents evaluate to `allow` again;
  - the audited events are `emergency_shutdown` + `emergency_resume` and neither body carries the
    justification text; `verify_chain` still ok;
  - dashboard: logged-in `POST /dashboard/kill/emergency-shutdown` with a justification halts the fleet
    (assert via `kill_store.status`), an UNAUTHENTICATED post redirects to login and halts nothing, and
    `GET /dashboard/kill` shows the incident banner.
- [ ] Run → fails, then passes.
- [ ] Commit `feat(controlplane): emergency-shutdown API + dashboard controls (RUN-07)`.

---

### Task 4: full gate
- [ ] `pytest -q` green; `-m floor_invariant`, `-m regression_lock` green; run `-m latency` and, if a
  wall-clock benchmark fails, confirm against a clean baseline before attributing it.
- [ ] Commit only if incidental fixes were needed.

## Self-review
RUN-07 is realized by *extending* the proven RUN-01/02 halt rather than duplicating it: shutdown sets
the same fleet flag (so stage-0 halts every agent, including agents never seen before, with no new
hot-path code), but adds a **mandatory** justification (empty/whitespace rejected, nothing halted — at
both the Pydantic boundary and the store), an append-only incident record preserving history that the
upserted `kill_switch` table cannot, an explicit operator resume that closes the incident, and an
`emergency` scope so decisions read `emergency_killed` rather than `fleet_killed` — forensics can tell
an emergency stop from a routine fleet kill, with zero pipeline changes. Free text stays table-only so a
hostile justification can never trip the AUD-04 gate and block the stop (canary-tested); a restart
during an open incident reloads the halt AND its emergency scope. Operator surfaces (gated API +
cookie-gated dashboard) both exercised e2e against a real pipeline.
