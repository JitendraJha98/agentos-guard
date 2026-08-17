# Phase 9 · Slice 9b — Privilege Rings (RUN-04) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Commits end
> with a second `-m "Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"`. Tests:
> `./.venv/Scripts/python.exe -m pytest`. TDD per task, one commit each. Gates `floor_invariant`
> + `regression_lock` + `latency` green at every commit.

**Goal (RUN-04):** Sensitive tools are gated behind higher capability tiers per agent — an agent whose
privilege ring is below a target's required ring is denied before the action runs.

**Architecture:** A `PrivilegeRingStore` (control plane) holds per-agent rings and per-target required
rings, with an **in-memory lookup** backed by tables and audited administrative changes — the proven
`KillSwitchStore` shape (hot-path lookup, durable table, fail-toward-contained ordering). The pipeline
gains **Stage 1e**, a deterministic deny gate placed *after* identity (it needs a verified agent) and
alongside the existing post-identity gates (1b delegation, 1c inter-agent auth, 1d MCP quarantine).
**Registered-sensitivity model:** only explicitly registered targets carry a required ring; anything
unregistered is ring 0 and stays governed by the constitution floor — so every existing pipeline and
test keeps working and the gate is `None`-default optional.

**Tech Stack:** SQLAlchemy 2.0 (sync) + Alembic, Pydantic-free plain dataclasses, pytest.

> First commit in this slice: `docs(phase-9): Slice 9b plan` for this file, then the tasks below.

## Deviation from the phase spec (deliberate, documented)
The phase spec listed a `privilege_denied` **audit event kind**. Following this codebase's actual
convention — every post-identity deny gate (1b/1c/1d) is audited as a **decision record** carrying its
`Reason`, not as a duplicate event — this slice does NOT add a per-action `privilege_denied` event.
Instead it adds `privilege_ring_set`, which audits the *administrative* ring assignment (mirroring
`kill_switch_set`) — genuinely not captured anywhere else. Net: no audit coverage is lost and none is
duplicated.

## File structure
- Modify `packages/controlplane/src/agentos_controlplane/store/models.py` — `AgentPrivilege`,
  `TargetPrivilege`.
- Create `.../store/migrations/versions/0012_privilege_rings.py`.
- Modify `packages/controlplane/src/agentos_controlplane/audit.py` — `EVENT_KINDS += "privilege_ring_set"`.
- Create `packages/controlplane/src/agentos_controlplane/privilege.py` — `PrivilegeVerdict`,
  `PrivilegeRingStore`.
- Modify `packages/pipeline/src/agentos_pipeline/runner.py` — `PrivilegeVerdictProtocol`,
  `PrivilegeLookup`, ctor seam, Stage 1e.
- Tests: `tests/unit/test_privilege_rings.py`, `tests/unit/test_privilege_pipeline.py`,
  `tests/integration/test_privilege_e2e.py`.

---

### Task 1: models + migration 0012 + event kind

**Files:**
- Modify: `packages/controlplane/src/agentos_controlplane/store/models.py`
- Create: `.../store/migrations/versions/0012_privilege_rings.py`
- Modify: `packages/controlplane/src/agentos_controlplane/audit.py`
- Test: `tests/unit/test_privilege_rings.py` (round-trip + event-kind portion)

Add to `models.py` (all types already imported; `Integer` was added in Phase 5):

```python
class AgentPrivilege(Base):
    """RUN-04 — the capability tier (privilege ring) an agent HOLDS. Higher = more privileged;
    absent means ring 0 (least privileged)."""

    __tablename__ = "agent_privilege"

    agent_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    ring: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    set_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class TargetPrivilege(Base):
    """RUN-04 — the ring a sensitive TARGET (tool / memory key / MCP tool / model) REQUIRES.

    Registered-sensitivity model: only rows present here are gated. An unregistered target is
    ring 0 (ungated by this stage) and remains governed by the constitution floor — so adding this
    stage cannot silently break an existing deployment.
    """

    __tablename__ = "target_privilege"

    target: Mapped[str] = mapped_column(String(255), primary_key=True)
    required_ring: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    set_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
```

`audit.py` — extend `EVENT_KINDS` in the file's comment style:

```python
        # RUN-04 (Slice 9b): an administrative privilege-ring assignment (agent tier or target
        # requirement). Short identifiers only; the per-action deny is audited as a DECISION record.
        "privilege_ring_set",
```

Migration `0012_privilege_rings.py` (`revision = "0012_privilege_rings"`,
`down_revision = "0011_sandbox_run"`):

```python
def upgrade() -> None:
    op.create_table(
        "agent_privilege",
        sa.Column("agent_id", sa.String(length=255), primary_key=True),
        sa.Column("ring", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("set_by", sa.String(length=255), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_table(
        "target_privilege",
        sa.Column("target", sa.String(length=255), primary_key=True),
        sa.Column("required_ring", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("set_by", sa.String(length=255), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("target_privilege")
    op.drop_table("agent_privilege")
```

**Steps:**
- [ ] Failing test: in-memory store (`create_engine("sqlite+pysqlite:///:memory:")` → `create_all` →
  `create_session_factory`); insert an `AgentPrivilege(agent_id="a", ring=2)` and a
  `TargetPrivilege(target="db_drop", required_ring=3)`, read both back; assert
  `append_event("privilege_ring_set", {...})` is accepted and an unknown kind still raises. Run → fails.
- [ ] Add the models + event kind + migration. Run → passes.
- [ ] Verify a single migration head:
  `./.venv/Scripts/python.exe -c "from alembic.config import Config; from alembic.script import ScriptDirectory; import agentos_controlplane.store as s, os; d=os.path.dirname(s.__file__); c=Config(); c.set_main_option('script_location', os.path.join(d,'migrations')); print(ScriptDirectory.from_config(c).get_heads())"`
  Expected: exactly `['0012_privilege_rings']`.
- [ ] Commit `feat(controlplane): privilege-ring tables + event kind + migration 0012 (RUN-04)`.

---

### Task 2: `PrivilegeRingStore`

**Files:**
- Create: `packages/controlplane/src/agentos_controlplane/privilege.py`
- Test: `tests/unit/test_privilege_rings.py`

```python
"""RUN-04 — privilege rings. Sensitive targets require a capability tier; an agent holding a lower
ring is denied before the action runs.

Hot-path shape mirrors RUN-01/02's KillSwitchStore: the per-action lookup is IN-MEMORY (no DB read),
backed by tables for durability and reloaded at construction. Administrative changes are audited
(`privilege_ring_set`, short identifiers only). Writes are DURABLE-FIRST so a failed persist can
never leave a target quietly LESS restricted than the operator believes (fail-toward-contained, the
Slice-4e lesson).

Registered-sensitivity model: only registered targets are gated; an unregistered target is ring 0 and
remains governed by the constitution floor. That keeps this stage additive — wiring it cannot break an
existing deployment.
"""
from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select

from agentos_controlplane.store.models import AgentPrivilege, TargetPrivilege


@dataclass(frozen=True)
class PrivilegeVerdict:
    """Returned ONLY when the action is refused: the agent holds less than the target requires."""

    target: str
    required: int
    held: int


class PrivilegeRingStore:
    def __init__(self, session_factory, audit) -> None:
        self._sf = session_factory
        self._audit = audit
        self._agent_rings: dict[str, int] = {}
        self._target_rings: dict[str, int] = {}
        self._load()

    def _load(self) -> None:
        with self._sf() as s:
            for row in s.scalars(select(AgentPrivilege)).all():
                self._agent_rings[row.agent_id] = row.ring
            for row in s.scalars(select(TargetPrivilege)).all():
                self._target_rings[row.target] = row.required_ring

    # ---- hot path (in-memory only) ----
    def ring_for(self, agent_id: str) -> int:
        return self._agent_rings.get(agent_id, 0)

    def required_ring(self, target: str) -> int:
        return self._target_rings.get(target, 0)

    def check(self, agent_id: str, target: str) -> PrivilegeVerdict | None:
        """None == permitted. A verdict == refused (agent ring < target requirement)."""
        required = self._target_rings.get(target, 0)
        if required <= 0:
            return None  # unregistered / ungated target
        held = self._agent_rings.get(agent_id, 0)
        if held >= required:
            return None
        return PrivilegeVerdict(target=target, required=required, held=held)

    # ---- administration (audited) ----
    async def set_agent_ring(self, agent_id: str, ring: int, *, set_by: str) -> None:
        await self._set("agent", agent_id, ring, set_by)

    async def set_target_ring(self, target: str, required_ring: int, *, set_by: str) -> None:
        await self._set("target", target, required_ring, set_by)

    async def _set(self, kind: str, key: str, ring: int, set_by: str) -> None:
        if ring < 0:
            raise ValueError("privilege ring must be >= 0")
        # DURABLE FIRST, then the in-memory cache: a failed persist must never leave the hot path
        # believing a LOWER requirement (or a HIGHER agent tier) than the table records.
        with self._sf() as s:
            if kind == "agent":
                row = s.get(AgentPrivilege, key)
                if row is None:
                    s.add(AgentPrivilege(agent_id=key, ring=ring, set_by=set_by))
                else:
                    row.ring, row.set_by = ring, set_by
            else:
                row = s.get(TargetPrivilege, key)
                if row is None:
                    s.add(TargetPrivilege(target=key, required_ring=ring, set_by=set_by))
                else:
                    row.required_ring, row.set_by = ring, set_by
            s.commit()
        await self._audit.append_event(
            "privilege_ring_set", {"kind": kind, "key": key, "ring": ring, "set_by": set_by}
        )
        if kind == "agent":
            self._agent_rings[key] = ring
        else:
            self._target_rings[key] = ring

    def list_rings(self) -> dict[str, dict[str, int]]:
        return {
            "agents": dict(sorted(self._agent_rings.items())),
            "targets": dict(sorted(self._target_rings.items())),
        }
```

**Steps (TDD):**
- [ ] Failing test: over a shared in-memory store with a real `AuditWriter` —
  (a) unregistered target → `check("a", "http_get") is None`;
  (b) `await set_target_ring("db_drop", 3, set_by="op")` then `check("a", "db_drop")` returns a
  verdict with `required == 3, held == 0`;
  (c) `await set_agent_ring("a", 3, set_by="op")` → `check("a", "db_drop") is None` (equal ring
  passes); ring 4 also passes; ring 2 refuses;
  (d) a fresh `PrivilegeRingStore` over the same factory reloads both maps (`_load`);
  (e) each admin call wrote one `privilege_ring_set` event and `verify_chain(sf).ok` still holds;
  (f) `set_agent_ring("a", -1, set_by="op")` raises `ValueError` and changes nothing;
  (g) durable-first ordering: with a session whose `commit()` raises, the admin call fails AND the
  in-memory map is unchanged (the hot path never diverges from the table).
  Run → fails.
- [ ] Implement `privilege.py`. Run → passes.
- [ ] Commit `feat(controlplane): PrivilegeRingStore — in-memory tiers, durable-first, audited (RUN-04)`.

---

### Task 3: pipeline Stage 1e gate

**Files:**
- Modify: `packages/pipeline/src/agentos_pipeline/runner.py`
- Test: `tests/unit/test_privilege_pipeline.py`

Add Protocols next to `KillSwitchLookup`/`McpQuarantineLookup`:

```python
class PrivilegeVerdictProtocol(Protocol):
    """RUN-04: what a refused privilege check reports."""

    target: str
    required: int
    held: int


class PrivilegeLookup(Protocol):
    """RUN-04 seam. `check` returns None when permitted, a verdict when refused. MUST be
    in-memory (called per action on the hot path)."""

    def check(self, agent_id: str, target: str) -> "PrivilegeVerdictProtocol | None": ...
```

`Pipeline.__init__` gains `privilege: PrivilegeLookup | None = None` → `self._privilege` (documented
`None` default: the stage never runs, behavior unchanged).

Insert **Stage 1e** in `_evaluate` immediately AFTER the Stage-1d MCP block and BEFORE
`# Stage 2 — Enrichment` (mirror 1d's terminal-deny shape exactly):

```python
        # Stage 1e — Privilege rings (RUN-04): a sensitive target requires a capability tier; an
        # agent holding a lower ring is denied before the action runs. Placed AFTER identity so the
        # ring is keyed on a VERIFIED agent_id (an unverified caller never consumes ring state), and
        # alongside the other post-identity gates. The lookup is in-memory (no per-action DB read).
        # None default: unwired deployments skip the check. Only REGISTERED targets are gated, so an
        # unregistered tool is unaffected and still governed by the constitution floor.
        if self._privilege is not None:
            pv = self._privilege.check(action.agent_id, action.target)
            if pv is not None:
                floor_box[0] = Outcome.deny  # insufficient privilege may NEVER relax
                reasons.append(
                    Reason(
                        stage="privilege",
                        code="insufficient_ring",
                        detail=(
                            f"target {pv.target} requires privilege ring {pv.required}; "
                            f"agent holds {pv.held}"
                        ),
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

**Steps (TDD):**
- [ ] Failing test (async, build a `Pipeline` with stub identity/policy/audit like
  `tests/unit/test_kill_switch_pipeline.py`, plus a stub `privilege` whose `check` returns a verdict
  or None): under-privileged → `Outcome.deny` with a `privilege`/`insufficient_ring` reason, and the
  policy + risk stages never ran (`pol.calls == 0`, `scorer.calls == 0`); permitted (`check` → None) →
  normal evaluation proceeds; `privilege=None` → behavior unchanged (backward compat); the deny is
  audited (`evidence_ref` set); the check is keyed on the verified agent (assert the stub is called
  AFTER identity — e.g. a forged-identity action denies with `forged_or_unknown_identity` and the
  privilege stub is never called); the lookup gets no session (in-memory). Run → fails.
- [ ] Implement the Protocols + ctor seam + Stage 1e. Run → passes.
- [ ] Commit `feat(pipeline): stage-1e privilege-ring gate denies under-privileged actions (RUN-04)`.

---

### Task 4: e2e over the real stack + full gate

**Files:**
- Test: `tests/integration/test_privilege_e2e.py`

**Steps (TDD):**
- [ ] Failing test wiring the REAL governed stack over ONE shared store (mirror
  `tests/integration/test_kill_switch_api.py`'s `Wired` class): a real compiled-constitution pipeline
  plus the SAME `PrivilegeRingStore` instance passed as `privilege=`. Assert:
  - baseline: a benign allowlisted `http_get` is `allow` (so a later deny is attributable to the ring);
  - `await rings.set_target_ring("http_get", 2, set_by="op")` → the same action now denies with
    `insufficient_ring`;
  - `await rings.set_agent_ring(AGENT_ID, 2, set_by="op")` → allowed again;
  - a DIFFERENT agent (ring 0) is still denied for that target (per-agent tiering);
  - both admin toggles landed as `privilege_ring_set` events and `verify_chain` still reports ok.
- [ ] Run → fails, then passes with Tasks 1–3.
- [ ] `pytest -q` green; `-m floor_invariant`, `-m regression_lock`, `-m latency` green (the gate is one
  in-memory dict lookup per action — confirm the budget holds).
- [ ] Commit `test(privilege): e2e — ring gate denies then permits over the real pipeline (RUN-04)`.

## Self-review
RUN-04 is realized: sensitive (registered) targets require a capability tier, and an agent holding a
lower ring is denied at Stage 1e — after identity so the ring keys on a VERIFIED agent, before
enrichment/policy, terminal and audited as a decision record carrying `privilege`/`insufficient_ring`.
The floor invariant holds trivially (the stage only ever restricts). Hot path is one in-memory dict
lookup (no DB read); `None` default keeps every existing deployment and test unchanged; unregistered
targets stay ungated by design (documented) so the stage is additive. Administration is durable-first
and audited (`privilege_ring_set`); a fresh store reloads state. Migration 0012 single-head. Gates green.
