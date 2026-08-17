# Phase 9 · Slice 9c — Resource Isolation (RUN-05) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Commits end
> with a second `-m "Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"`. Tests:
> `./.venv/Scripts/python.exe -m pytest`. TDD per task, one commit each. Gates `floor_invariant`
> + `regression_lock` green at every commit. (`-m latency` is wall-clock and currently noisy under
> machine load — if it fails, verify against a clean baseline via `git stash` before attributing it.)

**Goal (RUN-05):** Enforce CPU/wall, memory, and network limits per agent execution at the PEP, with an
opt-in hard OS path where the platform supports it — and be precise about what is *prevented* versus
merely *detected*.

**Architecture:** Limits are applied where execution actually happens: `enforce.py::governed_call`
wraps **both** `await run()` sites (the `_EXECUTABLE` branch and the post-approval branch) in a
`_run_within_limits` helper. A `ResourceGovernor` seam (structural Protocol, SDK-side) supplies
per-agent `ResourceLimits` from an in-memory cache and records breaches; the concrete
`ResourceGovernorStore` (control plane) persists limits and audits. A separate, capability-gated
`posix_limits` module provides real `setrlimit` enforcement in a subprocess where `resource` is
importable.

**Honest enforcement boundaries — state these in code, do not overclaim:**
| Limit | Mechanism | Guarantee |
|---|---|---|
| `wall_s` | `asyncio.wait_for` → cancel | **Preventive but cooperative.** A handler that awaits is cancelled; a CPU-bound *sync* handler that never yields cannot be interrupted in-process. Abort is **not** rollback — a partially applied side effect stays applied. |
| `memory_mb` | `tracemalloc` peak, reset per call | **Detect-at-completion (post-hoc).** The handler already ran; the breach is audited and the result withheld from the caller. It measures Python allocations in this process, not RSS. |
| `network` | PEP refusal for egress-capable action types | **Preventive.** The handler is never invoked. |
| hard CPU/AS | POSIX `setrlimit` in a subprocess | **Preventive and kernel-enforced**, but only where `resource` imports (skipped on Windows). |

Kernel-level confinement of arbitrary code remains the gateway/sidecar (Phase 10) and K8s (Phase 14)
layer, per `docs/architecture/05`.

**Tech Stack:** stdlib `asyncio` + `tracemalloc` + `resource` (POSIX-gated), SQLAlchemy 2.0 + Alembic,
pytest.

> First commit in this slice: `docs(phase-9): Slice 9c plan` for this file, then the tasks below.

## File structure
- Modify `packages/sdk/src/agentos_sdk/enforce.py` — `ResourceLimits`, `ResourceGovernor`,
  `GovernanceResourceExceeded`, `_run_within_limits`, wire both `run()` sites + the `governor` kwarg.
- Modify `packages/sdk/src/agentos_sdk/middleware.py`, `.../wrappers.py`, `.../__init__.py` — forward
  and export.
- Modify `packages/controlplane/src/agentos_controlplane/store/models.py` — `ResourceLimit` table.
- Create `.../store/migrations/versions/0013_resource_limits.py`.
- Modify `packages/controlplane/src/agentos_controlplane/audit.py` — `EVENT_KINDS +=
  "resource_limit_set"`, `"resource_limit_exceeded"`.
- Create `packages/controlplane/src/agentos_controlplane/resource_governor.py` — `ResourceGovernorStore`.
- Create `packages/controlplane/src/agentos_controlplane/posix_limits.py` — capability-gated hard path.
- Tests: `tests/unit/test_resource_limits.py`, `tests/unit/test_resource_governor_store.py`,
  `tests/integration/test_resource_limits_e2e.py`, `tests/integration/test_posix_hard_limits.py`.

---

### Task 1: the limits seam + `_run_within_limits`

**Files:**
- Modify: `packages/sdk/src/agentos_sdk/enforce.py`, `middleware.py`, `wrappers.py`, `__init__.py`
- Test: `tests/unit/test_resource_limits.py`

Add to `enforce.py` (`dataclass` is already imported from 9a; add `import asyncio`, `import tracemalloc`,
and `ActionType` to the `agentos_contract` import):

```python
# Action types capable of leaving the process (egress). A per-agent network=deny refuses these
# BEFORE the handler runs.
_EGRESS_TYPES = frozenset({ActionType.tool_call, ActionType.mcp_call, ActionType.model_invocation})


@dataclass(frozen=True)
class ResourceLimits:
    """RUN-05 per-agent execution budget. None on a field means "no limit for that dimension"."""

    wall_s: float | None = None
    memory_mb: float | None = None
    network: str = "allow"  # "allow" | "deny"


class ResourceGovernor(Protocol):
    """RUN-05 seam. `limits_for` MUST be in-memory (called per executed action);
    `record_breach` audits the violation."""

    def limits_for(self, agent_id: str) -> "ResourceLimits | None": ...

    async def record_breach(
        self, action: AgentAction, decision: Decision, *, limit: str, budget: float, observed: float
    ) -> None: ...


class GovernanceResourceExceeded(GovernanceDenied):
    """RUN-05: the execution violated its resource budget.

    Subclasses `GovernanceDenied` so every existing catch site treats it as a governed block and the
    result is withheld from the caller. Read `preventive` carefully — it is the HONEST distinction:

    * `network` / `wall_s` -> `preventive=True`: the handler was never invoked, or was cancelled.
      (Cancellation is cooperative: a sync CPU-bound handler that never awaits cannot be interrupted,
      and an aborted handler is NOT rolled back.)
    * `memory_mb` -> `preventive=False`: the breach is detected at COMPLETION, so the side effect
      already happened; this reports and audits a budget violation, it does not prevent it.
    """

    def __init__(
        self, decision: Decision, *, limit: str, budget: float, observed: float, preventive: bool
    ) -> None:
        Exception.__init__(
            self,
            f"Resource limit exceeded ({limit}: budget={budget}, observed={observed}) — "
            f"{'blocked' if preventive else 'detected after completion'}: "
            f"{format_reasons(decision)}",
        )
        self.decision = decision
        self.limit = limit
        self.budget = budget
        self.observed = observed
        self.preventive = preventive
```

The wrapper (place directly above `governed_call`):

```python
async def _run_within_limits(
    run: Callable[[], Awaitable[_T]],
    action: AgentAction,
    decision: Decision,
    governor: ResourceGovernor | None,
) -> _T:
    """RUN-05: apply the agent's execution budget around `run()`. Unwired or unlimited agents take
    the zero-overhead path (no tracemalloc, no wait_for) so the default hot path is unchanged."""
    if governor is None:
        return await run()
    limits = governor.limits_for(action.agent_id)
    if limits is None:
        return await run()

    # network: refuse BEFORE invoking the handler (preventive).
    if limits.network == "deny" and action.type in _EGRESS_TYPES:
        await governor.record_breach(action, decision, limit="network", budget=0.0, observed=1.0)
        raise GovernanceResourceExceeded(
            decision, limit="network", budget=0.0, observed=1.0, preventive=True
        )

    track = limits.memory_mb is not None
    started_tracing = False
    if track:
        if not tracemalloc.is_tracing():
            tracemalloc.start()
            started_tracing = True
        tracemalloc.reset_peak()  # peak must reflect THIS call, not the process history
    peak_mb = 0.0
    try:
        if limits.wall_s is not None:
            result = await asyncio.wait_for(run(), timeout=limits.wall_s)
        else:
            result = await run()
    except (asyncio.TimeoutError, TimeoutError):
        await governor.record_breach(
            action, decision, limit="wall_s", budget=limits.wall_s, observed=limits.wall_s
        )
        raise GovernanceResourceExceeded(
            decision,
            limit="wall_s",
            budget=limits.wall_s,
            observed=limits.wall_s,
            preventive=True,
        ) from None
    finally:
        if track:
            peak_mb = tracemalloc.get_traced_memory()[1] / (1024 * 1024)
            if started_tracing:
                tracemalloc.stop()

    if limits.memory_mb is not None and peak_mb > limits.memory_mb:
        await governor.record_breach(
            action, decision, limit="memory_mb", budget=limits.memory_mb, observed=peak_mb
        )
        # preventive=False: the handler ALREADY ran — this reports the violation, it did not stop it.
        raise GovernanceResourceExceeded(
            decision,
            limit="memory_mb",
            budget=limits.memory_mb,
            observed=peak_mb,
            preventive=False,
        )
    return result
```

`governed_call` gains `governor: ResourceGovernor | None = None` and **both** run sites become:

```python
    if outcome in _EXECUTABLE:
        return await _run_within_limits(run, action, decision, governor)
```
```python
    return await _run_within_limits(run, action, decision, governor)
```

`middleware.py` (`__init__` + both hooks) and the three `wrappers.py` functions gain
`governor: ResourceGovernor | None = None` and forward it. Export `ResourceLimits`,
`ResourceGovernor`, `GovernanceResourceExceeded` from `agentos_sdk/__init__.py`.

**Steps (TDD):**
- [ ] Failing test with a stub governor (`limits_for` returns a configured `ResourceLimits`;
  `record_breach` appends to a list) and a stub pipeline returning `allow`:
  - `governor=None` → handler runs, result returned (zero-overhead path);
  - `ResourceLimits()` (all None, network allow) → handler runs;
  - `wall_s=0.05` with a handler doing `await asyncio.sleep(1)` → `GovernanceResourceExceeded` with
    `limit == "wall_s"`, `preventive is True`, one recorded breach, and the sleep did NOT complete
    (assert a post-sleep flag was never set);
  - `network="deny"` on a `tool_call` → raised with `limit == "network"`, `preventive is True`, and
    the handler was NEVER invoked (`ran == []`);
  - `network="deny"` on a `memory_access` action → allowed to run (not an egress type);
  - `memory_mb=0.001` with a handler allocating ~2 MB (`b"x" * 2_000_000`) → raised with
    `limit == "memory_mb"` and `preventive is False`, and the handler DID run (documents the honest
    post-hoc semantics);
  - `isinstance(exc, GovernanceDenied)` holds for every case;
  - `tracemalloc.is_tracing()` is False again afterwards when the helper started it (no leak).
  Run → fails.
- [ ] Implement the seam + wrapper + both run sites. Run → passes.
- [ ] Wire + export in `middleware.py` / `wrappers.py` / `__init__.py`; run the FULL suite → green.
- [ ] Commit `feat(sdk): per-agent execution budgets — wall/memory/network at both run sites (RUN-05)`.

---

### Task 2: `ResourceLimit` table + migration 0013 + `ResourceGovernorStore`

**Files:**
- Modify: `.../store/models.py`, `.../audit.py`
- Create: `.../store/migrations/versions/0013_resource_limits.py`,
  `.../agentos_controlplane/resource_governor.py`
- Test: `tests/unit/test_resource_governor_store.py`

`models.py`:

```python
class ResourceLimit(Base):
    """RUN-05 — the per-agent execution budget. NULL on a numeric column means "no limit"."""

    __tablename__ = "resource_limit"

    agent_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    wall_s: Mapped[float | None] = mapped_column(Float, nullable=True)
    memory_mb: Mapped[float | None] = mapped_column(Float, nullable=True)
    network: Mapped[str] = mapped_column(String(16), nullable=False, default="allow")
    set_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )
```

`audit.py` — add both kinds with a comment in the file's style:

```python
        # RUN-05 (Slice 9c): the administrative budget assignment, and a per-execution budget
        # breach. Short identifiers + numbers only.
        "resource_limit_set",
        "resource_limit_exceeded",
```

Migration `0013_resource_limits.py` (`revision = "0013_resource_limits"`,
`down_revision = "0012_privilege_rings"`): create `resource_limit` with the columns above
(`sa.Float()` nullable for the two numerics, `sa.String(16)` server_default `"allow"` for network);
`downgrade` drops it.

`resource_governor.py`:

```python
"""RUN-05 — the concrete ResourceGovernor: per-agent execution budgets.

Hot-path lookup is IN-MEMORY (KillSwitchStore shape); the table is durability and reloads at
construction. Administration commits FIRST, then updates the cache, then audits — so a failed persist
never leaves the hot path believing a MORE generous budget than the table records (the 9b review
lesson: cache and table must not diverge after a successful commit).
"""
from __future__ import annotations

from sqlalchemy import select

from agentos_contract import AgentAction, Decision
from agentos_sdk.enforce import ResourceLimits

from agentos_controlplane.store.models import ResourceLimit

_NETWORK_MODES = frozenset({"allow", "deny"})


class ResourceGovernorStore:
    """Satisfies the SDK's `ResourceGovernor` Protocol structurally."""

    def __init__(self, session_factory, audit) -> None:
        self._sf = session_factory
        self._audit = audit
        self._limits: dict[str, ResourceLimits] = {}
        self._load()

    def _load(self) -> None:
        with self._sf() as s:
            for row in s.scalars(select(ResourceLimit)).all():
                self._limits[row.agent_id] = ResourceLimits(
                    wall_s=row.wall_s, memory_mb=row.memory_mb, network=row.network
                )

    def limits_for(self, agent_id: str) -> ResourceLimits | None:
        return self._limits.get(agent_id)

    async def set_limits(
        self,
        agent_id: str,
        *,
        wall_s: float | None = None,
        memory_mb: float | None = None,
        network: str = "allow",
        set_by: str,
    ) -> None:
        if network not in _NETWORK_MODES:
            raise ValueError(f"network must be one of {sorted(_NETWORK_MODES)}, got {network!r}")
        if wall_s is not None and wall_s <= 0:
            raise ValueError("wall_s must be > 0 when set")
        if memory_mb is not None and memory_mb <= 0:
            raise ValueError("memory_mb must be > 0 when set")
        with self._sf() as s:
            row = s.get(ResourceLimit, agent_id)
            if row is None:
                s.add(
                    ResourceLimit(
                        agent_id=agent_id, wall_s=wall_s, memory_mb=memory_mb,
                        network=network, set_by=set_by,
                    )
                )
            else:
                row.wall_s, row.memory_mb, row.network, row.set_by = (
                    wall_s, memory_mb, network, set_by,
                )
            s.commit()
        self._limits[agent_id] = ResourceLimits(
            wall_s=wall_s, memory_mb=memory_mb, network=network
        )
        await self._audit.append_event(
            "resource_limit_set",
            {
                "agent_id": agent_id, "wall_s": wall_s, "memory_mb": memory_mb,
                "network": network, "set_by": set_by,
            },
        )

    async def record_breach(
        self, action: AgentAction, decision: Decision, *, limit: str, budget: float, observed: float
    ) -> None:
        # Short identifiers + numbers only — no payload, no target (AUD-04 secret-gate safety).
        await self._audit.append_event(
            "resource_limit_exceeded",
            {
                "action_id": str(action.id),
                "agent_id": action.agent_id,
                "action_type": action.type.value,
                "limit": limit,
                "budget": budget,
                "observed": round(float(observed), 4),
            },
        )
```

**Steps (TDD):**
- [ ] Failing test over a shared in-memory store + real `AuditWriter`: `limits_for("a") is None`
  initially; `await set_limits("a", wall_s=1.5, memory_mb=64, network="deny", set_by="op")` →
  `limits_for("a")` returns those values and one `resource_limit_set` event exists; a fresh store over
  the same factory reloads them; `network="bogus"` / `wall_s=0` / `memory_mb=-1` each raise
  `ValueError` and change nothing; `await record_breach(action, decision, limit="wall_s", budget=1.5,
  observed=1.5)` writes one `resource_limit_exceeded` event whose body has NO `target` and NO payload
  (build the action with `payload={"content": "SECRET-CANARY"}` and assert the canary appears nowhere
  in the event body); `verify_chain(sf).ok` still holds; a commit-raising session leaves the cache
  unchanged. Run → fails.
- [ ] Add the model, both event kinds, migration 0013, and `resource_governor.py`. Run → passes.
- [ ] Verify a single migration head (expected `['0013_resource_limits']`) with the one-liner used in
  the 9b plan.
- [ ] Commit `feat(controlplane): resource_limit table + ResourceGovernorStore + migration 0013 (RUN-05)`.

---

### Task 3: capability-gated POSIX hard limits

**Files:**
- Create: `packages/controlplane/src/agentos_controlplane/posix_limits.py`
- Test: `tests/integration/test_posix_hard_limits.py`

```python
"""RUN-05 (opt-in hard path) — REAL kernel-enforced limits via POSIX setrlimit, for deployments on a
POSIX host. Capability-gated: `resource` does not exist on Windows, where this module reports
unavailable and callers fall back to the portable PEP budgets in `agentos_sdk.enforce`.

This is deliberately a small, honest capability rather than a full sandbox framework: it runs a child
process under RLIMIT_CPU / RLIMIT_AS so a runaway allocation or spin is killed by the KERNEL, not by
cooperative cancellation. Full confinement of hostile code stays the gateway/sidecar (Phase 10) and
K8s (Phase 14) layer.
"""
from __future__ import annotations

import subprocess
import sys

try:  # pragma: no cover - platform-gated
    import resource as _resource
except ImportError:  # Windows
    _resource = None


def hard_limits_available() -> bool:
    """True when POSIX rlimits can actually be applied on this platform."""
    return _resource is not None


def _preexec(cpu_s: int | None, address_space_mb: int | None):  # pragma: no cover - child process
    def apply() -> None:
        if cpu_s is not None:
            _resource.setrlimit(_resource.RLIMIT_CPU, (cpu_s, cpu_s))
        if address_space_mb is not None:
            nbytes = int(address_space_mb) * 1024 * 1024
            _resource.setrlimit(_resource.RLIMIT_AS, (nbytes, nbytes))
    return apply


def run_python_limited(
    code: str, *, cpu_s: int | None = None, address_space_mb: int | None = None, timeout_s: float = 30.0
) -> subprocess.CompletedProcess:
    """Run `code` in a child Python under kernel rlimits. Raises RuntimeError where unavailable."""
    if not hard_limits_available():
        raise RuntimeError("POSIX rlimits are unavailable on this platform")
    return subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        timeout=timeout_s,
        preexec_fn=_preexec(cpu_s, address_space_mb),
    )
```

**Steps (TDD):**
- [ ] Test with `pytest.mark.skipif(not hard_limits_available(), reason="POSIX rlimits unavailable")`:
  a child running `b"x" * (200 * 1024 * 1024)` under `address_space_mb=64` does NOT exit 0 (killed or
  `MemoryError`), while `print("ok")` under the same limit exits 0 with `"ok"` — proving the limit is
  real and not blanket-failing. Add one ALWAYS-RUNNING test asserting
  `hard_limits_available() is (sys.platform != "win32")` and that `run_python_limited` raises
  `RuntimeError` when unavailable, so Windows still exercises the capability contract.
- [ ] Implement `posix_limits.py`. Run → the gated test passes on POSIX / skips on Windows; the
  contract test passes everywhere.
- [ ] Commit `feat(controlplane): capability-gated POSIX rlimit hard-limit path (RUN-05)`.

---

### Task 4: e2e + full gate

**Files:**
- Test: `tests/integration/test_resource_limits_e2e.py`

**Steps (TDD):**
- [ ] Failing test over the REAL governed stack sharing ONE store (mirror the 9b e2e `Wired` shape):
  a real compiled-constitution pipeline plus the SAME `ResourceGovernorStore` passed as `governor=`.
  Assert:
  - baseline (no limits set for the agent) → a benign allowlisted `http_get` executes and the handler
    ran (so later blocks are attributable to the limit);
  - `await governor.set_limits(AGENT_ID, network="deny", set_by="op")` → the same call raises
    `GovernanceResourceExceeded` with `limit == "network"`, the handler never ran, and one
    `resource_limit_exceeded` event exists;
  - through `GovernanceMiddleware(..., governor=governor)` `awrap_tool_call` the same case returns a
    `ToolMessage` whose content mentions the resource limit and whose `status == "error"` (the 9a
    contained-outcome convention), with the handler never invoked;
  - `await governor.set_limits(AGENT_ID, wall_s=0.05, set_by="op")` with a slow awaiting handler →
    raises with `limit == "wall_s"`; a DIFFERENT agent with no limits is unaffected;
  - `verify_chain` still reports ok.
- [ ] Run → fails, then passes with Tasks 1–3.
- [ ] `pytest -q` green; `-m floor_invariant`, `-m regression_lock` green; run `-m latency` and, if a
  wall-clock benchmark fails, confirm against a clean baseline (`git stash`) before attributing it.
- [ ] Commit `test(resources): e2e — per-agent budgets block egress and slow calls (RUN-05)`.

## Self-review
RUN-05 is enforced where execution happens: both `await run()` sites are wrapped, so limits apply to
directly-executable outcomes AND to post-approval execution. Network denial is preventive (handler
never invoked); the wall budget cancels (cooperative, abort-not-rollback); the memory budget is
detect-at-completion — each distinction is encoded in `GovernanceResourceExceeded.preventive` and
documented rather than overclaimed, and a capability-gated POSIX `setrlimit` path provides genuine
kernel enforcement where the platform allows. Breaches are audited with short identifiers + numbers
only (canary-tested), administration is commit-then-cache-then-audit (no divergence after a successful
commit), and unwired/unlimited agents take a zero-overhead path so the default hot path is unchanged.
Migration 0013 single-head; `GovernanceResourceExceeded` subclasses `GovernanceDenied` so no caller can
mistake a budget violation for success.
