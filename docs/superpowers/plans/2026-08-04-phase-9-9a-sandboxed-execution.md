# Phase 9 · Slice 9a — Sandboxed Execution + Quarantined Side Effects (RUN-03) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Commits end
> with a second `-m "Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"`. Tests:
> `./.venv/Scripts/python.exe -m pytest`. TDD per task, one commit each. Gates `floor_invariant`
> + `regression_lock` + `latency` green at every commit.

**Goal (RUN-03):** A `sandbox` outcome runs the action in an isolated context with **quarantined**
side effects — the real handler is never invoked, the observation is persisted and audited, and the
caller can never mistake the quarantine for a successful execution.

**Architecture:** `enforce.py::governed_call` is the ONE outcome map every PEP form shares. Today it
*substitutes* `sandbox` onto the human-approval path (audited `enforcement_substitution`) with the
comment "until RUN-03/POL-09 (Phase 9)". This slice adds a `SandboxRunner` seam (structural Protocol,
no control-plane import), routes `sandbox` to it, and raises `GovernanceQuarantined` — a **subclass of
`GovernanceDenied`** so every existing `except GovernanceDenied` site already treats a quarantine as a
non-execution. The concrete `QuarantineSandbox` (control plane) persists a `SandboxRun` row and audits
`sandbox_executed`. `require_consensus` keeps its substitution until Slice 9f.

**Tech Stack:** Python 3.12, Pydantic v2 contract types, SQLAlchemy 2.0 (sync) + Alembic, pytest.

> First commit in this slice: `docs(phase-9): Slice 9a plan` for this file, then the tasks below.

## File structure
- Modify `packages/sdk/src/agentos_sdk/enforce.py` — `SandboxResult`, `SandboxRunner`,
  `GovernanceQuarantined`, the `sandbox` route, `_SUBSTITUTED_TO_APPROVAL` narrowed.
- Modify `packages/sdk/src/agentos_sdk/middleware.py` — accept/forward `sandbox`; surface the
  governed exception's own message.
- Modify `packages/sdk/src/agentos_sdk/wrappers.py` — accept/forward `sandbox` (enforcement parity).
- Modify `packages/sdk/src/agentos_sdk/__init__.py` — export the new symbols.
- Modify `packages/controlplane/src/agentos_controlplane/store/models.py` — `SandboxRun` table.
- Create `.../store/migrations/versions/0011_sandbox_run.py`.
- Modify `packages/controlplane/src/agentos_controlplane/audit.py` — `EVENT_KINDS += "sandbox_executed"`.
- Create `packages/controlplane/src/agentos_controlplane/sandbox.py` — `QuarantineSandbox`.
- Tests: `tests/unit/test_sandbox_enforcement.py`, `tests/unit/test_quarantine_sandbox.py`,
  `tests/integration/test_sandbox_e2e.py`; UPDATE `tests/unit/test_outcome_enforcement.py`.

---

### Task 1: the enforcement seam — `SandboxRunner` + `GovernanceQuarantined`

**Files:**
- Modify: `packages/sdk/src/agentos_sdk/enforce.py`
- Modify: `packages/sdk/src/agentos_sdk/middleware.py`, `.../wrappers.py`, `.../__init__.py`
- Test: `tests/unit/test_sandbox_enforcement.py`
- Update: `tests/unit/test_outcome_enforcement.py`

Add to `enforce.py` (it already imports `Protocol`; add `from dataclasses import dataclass`):

```python
@dataclass(frozen=True)
class SandboxResult:
    """What a quarantined (sandboxed) run OBSERVED. This is deliberately NOT an imitation of the
    real handler's return value — the real handler was never invoked."""

    quarantined: bool
    run_id: str
    detail: str = ""


class SandboxRunner(Protocol):
    """RUN-03 seam: run the action in an isolated context with quarantined side effects.

    The concrete runner is `agentos_controlplane.sandbox.QuarantineSandbox`. It is NOT given the
    handler on purpose: quarantine means the real operation never runs, so there is nothing to
    invoke — the runner only observes, persists, and audits.
    """

    async def run(self, action: AgentAction, decision: Decision) -> SandboxResult: ...


class GovernanceQuarantined(GovernanceDenied):
    """A `sandbox` outcome (RUN-03): the action was observed in quarantine and its REAL side effect
    never happened.

    Subclasses `GovernanceDenied` deliberately: every existing `except GovernanceDenied` site (the
    LangChain hooks, user code) then treats a quarantine as a non-execution, so a caller can NEVER
    mistake it for a successful result. `sandbox_result` carries the observation.
    """

    def __init__(self, decision: Decision, result: SandboxResult) -> None:
        # Bypass GovernanceDenied.__init__ so the surfaced message says QUARANTINED while the
        # exception stays a GovernanceDenied for every catch site.
        Exception.__init__(
            self,
            f"Quarantined by agentos-guard (sandboxed, no real effect): {format_reasons(decision)}",
        )
        self.decision = decision
        self.sandbox_result = result
```

Narrow the substitution set and document it:

```python
# Outcomes whose dedicated enforcement is not realized until POL-09 (Slice 9f): substituted with
# the approval path, audited as such. `sandbox` left this set in Slice 9a (RUN-03 is real now).
_SUBSTITUTED_TO_APPROVAL = frozenset({Outcome.require_consensus})
```

`governed_call` gains a `sandbox` seam and the `sandbox` route (insert immediately AFTER the
`Outcome.deny` check, BEFORE the coordinator block):

```python
async def governed_call(
    pipeline: PipelineProtocol,
    action: AgentAction,
    run: Callable[[], Awaitable[_T]],
    *,
    coordinator: ApprovalCoordinator | None = None,
    dispatcher: SideEffectDispatcher | None = None,
    sandbox: SandboxRunner | None = None,
) -> _T:
```

```python
    if outcome is Outcome.sandbox:
        # RUN-03: real containment. `run` is NEVER awaited on this path — no side effect, no egress.
        # No runner wired -> fail closed, exactly like a blocking outcome without a coordinator.
        if sandbox is None:
            raise GovernanceDenied(decision)
        result = await sandbox.run(action, decision)
        raise GovernanceQuarantined(decision, result)
```

`middleware.py`: add `sandbox: SandboxRunner | None = None` to `__init__` (store as `self._sandbox`),
pass `sandbox=self._sandbox` in BOTH `governed_call` calls, and surface the exception's own message so
a quarantine reads as quarantined (deny text is unchanged, since `GovernanceDenied.__init__` already
builds `"Blocked by agentos-guard: ..."`):

```python
        except GovernanceDenied as denied:
            return ToolMessage(content=str(denied), tool_call_id=request.tool_call["id"])
```
```python
        except GovernanceDenied as denied:
            return AIMessage(content=str(denied))
```

`wrappers.py`: add `sandbox: SandboxRunner | None = None` to `governed_memory_access`,
`governed_mcp_call`, `governed_delegation` and forward it to `governed_call` (keeps the
tool-hook-vs-wrapper parity test honest). Export `SandboxResult`, `SandboxRunner`,
`GovernanceQuarantined` from `agentos_sdk/__init__.py`.

**Steps (TDD):**
- [ ] Write `tests/unit/test_sandbox_enforcement.py` with a stub pipeline returning a `sandbox`
  Decision, a `run` that flips a `ran = []` list (must stay empty), and a stub runner returning
  `SandboxResult(True, "r1", "d")`. Assert: (a) `governed_call(..., sandbox=stub)` raises
  `GovernanceQuarantined`, `ran == []` (the load-bearing no-side-effect assertion), and the exception
  carries `.sandbox_result.run_id == "r1"` and `.decision`; (b) `GovernanceQuarantined` IS a
  `GovernanceDenied` (`isinstance`) and its message contains `"Quarantined by agentos-guard"`;
  (c) with `sandbox=None` → plain `GovernanceDenied`, `ran == []`, and NO substitution recorded on a
  passed coordinator stub; (d) a runner that raises propagates and `ran == []` (fail-safe). Run → fails.
- [ ] Implement the `enforce.py` changes. Run → passes.
- [ ] Update `tests/unit/test_outcome_enforcement.py`: the two tests parametrized over
  `[Outcome.sandbox, Outcome.require_consensus]`
  (`test_unrealized_outcomes_escalate_to_approval_path`,
  `test_unrealized_outcomes_without_coordinator_blocked`) must now parametrize over
  `[Outcome.require_consensus]` only, and the module docstring table updated so `sandbox` reads
  "quarantined via SandboxRunner (RUN-03)". Add a sandbox case asserting it does NOT record an
  `enforcement_substitution` event. Run the file → passes.
- [ ] Implement the `middleware.py` / `wrappers.py` / `__init__.py` changes; run the full suite →
  green (existing "Blocked by agentos-guard" assertions must still pass unchanged).
- [ ] Commit `feat(sdk): SandboxRunner seam — sandbox quarantines instead of substituting (RUN-03)`.

---

### Task 2: `SandboxRun` table + migration 0011 + audit event kind

**Files:**
- Modify: `packages/controlplane/src/agentos_controlplane/store/models.py`
- Create: `.../store/migrations/versions/0011_sandbox_run.py`
- Modify: `packages/controlplane/src/agentos_controlplane/audit.py`
- Test: `tests/unit/test_quarantine_sandbox.py` (model round-trip + event-kind portion)

Add to `models.py` (all needed types are already imported):

```python
class SandboxRun(Base):
    """RUN-03 — one quarantined (sandboxed) execution. The REAL handler never ran; this row IS the
    observation record. `detail` is a short, redacted summary — never raw payload (the audit event
    carries short identifiers only, so the AUD-04 secret gate can never block containment)."""

    __tablename__ = "sandbox_run"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    action_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    agent_id: Mapped[str] = mapped_column(String(255), nullable=False)
    action_type: Mapped[str] = mapped_column(String(64), nullable=False)
    target: Mapped[str] = mapped_column(Text, nullable=False)
    quarantined: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    detail: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
```

`audit.py` — extend `EVENT_KINDS` (currently at ~line 99) with a comment matching the file's style:

```python
        # RUN-03 (Slice 9a): a quarantined sandbox run. Short identifiers only — the redacted
        # detail lives in the sandbox_run TABLE.
        "sandbox_executed",
```

Migration `0011_sandbox_run.py` — mirror `0010_agent_certificates.py`'s structure:

```python
revision: str = "0011_sandbox_run"
down_revision: Union[str, None] = "0010_agent_certificates"  # verify against 0010's `revision`


def upgrade() -> None:
    op.create_table(
        "sandbox_run",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("action_id", sa.Uuid(), nullable=False),
        sa.Column("agent_id", sa.String(length=255), nullable=False),
        sa.Column("action_type", sa.String(length=64), nullable=False),
        sa.Column("target", sa.Text(), nullable=False),
        sa.Column("quarantined", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("detail", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("sandbox_run")
```

**Steps:**
- [ ] Open `0010_agent_certificates.py` and copy its `revision` string into this migration's
  `down_revision` (do not guess).
- [ ] Write the failing test: build an in-memory store (`create_engine("sqlite+pysqlite:///:memory:")`
  → `create_all` → `create_session_factory`), insert a `SandboxRun`, read it back; and assert
  `append_event("sandbox_executed", {...})` is accepted while an unknown kind still raises. Run → fails.
- [ ] Add the model + event kind + migration. Run → passes.
- [ ] Verify a single migration head:
  `./.venv/Scripts/python.exe -c "from alembic.config import Config; from alembic.script import ScriptDirectory; import agentos_controlplane.store as s, os; d=os.path.dirname(s.__file__); c=Config(); c.set_main_option('script_location', os.path.join(d,'migrations')); print(ScriptDirectory.from_config(c).get_heads())"`
  Expected: exactly `['0011_sandbox_run']`.
- [ ] Commit `feat(controlplane): sandbox_run table + sandbox_executed event + migration 0011 (RUN-03)`.

---

### Task 3: `QuarantineSandbox` — the concrete runner

**Files:**
- Create: `packages/controlplane/src/agentos_controlplane/sandbox.py`
- Test: `tests/unit/test_quarantine_sandbox.py`

```python
"""RUN-03 — the concrete SandboxRunner: QUARANTINE.

`governed_call` routes a `sandbox` outcome here INSTEAD of the real handler, so by construction no
side effect and no egress occur — there is nothing to stub, because nothing runs. This runner records
the observation (`sandbox_run` row) and audits `sandbox_executed`, then returns a `SandboxResult` the
enforcement core raises as `GovernanceQuarantined`.

Honest scope: this is PEP-level quarantine (see docs/architecture/05 — "the SDK shim can intercept
and stub side-effectful tools"). Kernel/network isolation is the gateway/sidecar (Phase 10) and K8s
(Phase 14) layer.
"""
from __future__ import annotations

from uuid import uuid4

from agentos_contract import AgentAction, Decision
from agentos_sdk.enforce import SandboxResult

from agentos_controlplane.store.models import SandboxRun


class QuarantineSandbox:
    """Satisfies the SDK's `SandboxRunner` Protocol structurally (no inheritance)."""

    def __init__(self, session_factory, audit) -> None:
        self._sf = session_factory
        self._audit = audit

    async def run(self, action: AgentAction, decision: Decision) -> SandboxResult:
        run_id = uuid4()
        # A short, redacted summary only — the payload itself is NEVER copied here.
        detail = (
            f"quarantined {action.type.value} on {action.target}; "
            f"{len(action.payload)} payload field(s); handler not invoked"
        )
        with self._sf() as s:
            s.add(
                SandboxRun(
                    id=run_id,
                    action_id=action.id,
                    agent_id=action.agent_id,
                    action_type=action.type.value,
                    target=action.target,
                    quarantined=True,
                    detail=detail,
                )
            )
            s.commit()
        # Short identifiers only (AUD-04 secret-gate safety); the detail stays in the table.
        await self._audit.append_event(
            "sandbox_executed",
            {
                "action_id": str(action.id),
                "agent_id": action.agent_id,
                "action_type": action.type.value,
                "run_id": str(run_id),
                "outcome": decision.outcome.value,
            },
        )
        return SandboxResult(
            quarantined=True,
            run_id=str(run_id),
            detail="side effects quarantined; handler not invoked",
        )
```

> Note the dependency direction: the control plane may import the SDK's `SandboxResult` (the control
> plane already imports contract types); the SDK must NOT import the control plane. If a lint/import
> rule forbids `agentos_controlplane -> agentos_sdk`, move `SandboxResult` into `agentos_contract`
> instead and re-export it from `agentos_sdk.enforce` — record which option you took.

**Steps (TDD):**
- [ ] Failing test: over a shared in-memory store with a real `AuditWriter`, call
  `await QuarantineSandbox(sf, audit).run(action, decision)`; assert the returned `SandboxResult` has
  `quarantined is True` and a non-empty `run_id`; exactly one `sandbox_run` row exists whose
  `action_id`/`agent_id`/`target` match and whose `detail` does NOT contain the payload's secret value
  (build the action with `payload={"url": ..., "content": "SECRET-CANARY"}` and assert
  `"SECRET-CANARY" not in row.detail`); exactly one `sandbox_executed` audit event exists whose body
  has no `target` and no payload; and `verify_chain(sf)` still reports `ok`. Run → fails.
- [ ] Implement `sandbox.py`. Run → passes.
- [ ] Commit `feat(controlplane): QuarantineSandbox — observe + persist + audit, no side effect (RUN-03)`.

---

### Task 4: end-to-end through the real pipeline + PEP

**Files:**
- Test: `tests/integration/test_sandbox_e2e.py`

**Steps (TDD):**
- [ ] Failing test wiring the REAL governed stack (mirror `tests/integration/test_kill_switch_api.py`
  for the shared-store wiring and `tests/integration/test_real_agent_governance.py` for the
  middleware/fake-model wiring):
  - Build a pipeline over the compiled test constitution whose decision for the probe action is
    `sandbox`. Get there deterministically WITHOUT depending on detector tuning: construct the
    `Pipeline` with `thresholds=GraduatedThresholds(sandbox_at=0.0, deny_at=1.0)` so a benign
    allowlisted `http_get` grades to `sandbox` (risk ≥ 0.0), and assert the decision outcome IS
    `Outcome.sandbox` before asserting the enforcement behavior.
  - Through `governed_call` with `sandbox=QuarantineSandbox(sf, audit)`: the handler is never invoked,
    `GovernanceQuarantined` is raised, one `sandbox_run` row + one `sandbox_executed` event exist, and
    the chain still verifies.
  - Through `GovernanceMiddleware(pipeline, token, sandbox=QuarantineSandbox(...))`
    `awrap_tool_call`: the returned `ToolMessage.content` starts with `"Quarantined by agentos-guard"`
    and the real handler was never called (assert a handler that appends to a list left it empty).
  - Without a sandbox runner wired, the same middleware call returns a `ToolMessage` whose content
    starts with `"Blocked by agentos-guard"` (fail-closed) and the handler still never ran.
- [ ] Run → fails, then passes with the code from Tasks 1–3.
- [ ] Commit `test(sandbox): e2e — sandbox quarantines through pipeline + PEP, no side effect (RUN-03)`.

---

### Task 5: full gate
- [ ] `./.venv/Scripts/python.exe -m pytest -q` green; `-m floor_invariant`, `-m regression_lock`,
  `-m latency` all green (this slice adds nothing to the per-action hot path — the seam runs only on a
  `sandbox` outcome, at enforcement time).
- [ ] Report the counts and whether `SandboxResult` stayed in the SDK or moved to the contract.
- [ ] Commit only if incidental fixes were needed.

## Self-review
RUN-03 is realized: a `sandbox` outcome routes to the `SandboxRunner` seam instead of the approval
substitution; the real handler is never awaited (asserted directly), the observation is persisted
(`sandbox_run`) and audited (`sandbox_executed`, short identifiers only, chain still verifies), and the
result surfaces as `GovernanceQuarantined` — a `GovernanceDenied` subclass, so no existing catch site
or caller can mistake quarantine for success. Fail-closed preserved: no runner wired → `GovernanceDenied`
with nothing executed. `require_consensus` keeps its audited substitution until 9f (its parametrized
tests narrowed, not deleted). Migration 0011 single-head. Honest scope (PEP-level quarantine, not
kernel isolation) documented in the module. Hot path untouched; gates green.
