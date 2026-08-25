# Phase 11 · Slice 11d — GPU & Downstream API Attribution (ECON-03) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Commits end
> with a second `-m "Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"`. Tests:
> `./.venv/Scripts/python.exe -m pytest`. TDD per task, one commit each. Gates `floor_invariant`
> + `regression_lock` + `latency` green at every commit. NEVER loosen the latency budget.

**Goal (ECON-03):** Attribute **GPU usage** and **downstream API consumption** per agent — so the
economics picture covers self-hosted compute and third-party API spend, not only hosted-model tokens.

**Architecture:** Extends Slice 11b rather than forking it. Downstream consumption reuses the
existing `cost_record` table with a `provider` column, keyed by the action's own `target` — a fact we
already have, never an inferred vendor. GPU is a **capability-gated probe** following the exact
precedent set by RUN-05's POSIX path (`posix_limits.py`): if NVML is not importable or no device is
present, `gpu_metering_available()` is False and the meter records nothing. **This box has no GPU and
no NVML**, so the NVML path ships unexercised locally and says so.

**The attribution honesty rule (spec D-9).** Every GPU record carries `attribution` ∈
{`process`, `device_shared`}. Device-wide counters in a process running several agents concurrently
**cannot** be honestly divided among them, so `device_shared` is explicitly not a per-agent bill.
Phase 9's Slice 9c review killed a design that cross-attributed process-wide `tracemalloc` deltas
into per-action audit accusations; this is the same trap wearing different hardware, and the label is
how we walk around it instead of into it.

**Tech Stack:** optional `nvidia-ml-py` (lazily imported, never a hard dependency — most deployments
have no GPU and should not pay for one), SQLAlchemy 2.0 + Alembic, pytest.

## Verified at plan time (2026-08-18, this machine)
- `pynvml` / `nvidia_ml_py`: **not importable**. `nvidia-smi`: **not on PATH**. There is no GPU here.
- Precedent to copy: `packages/controlplane/src/agentos_controlplane/posix_limits.py` —
  *"A capability that lies about being available is worse than an absent one."* Same posture here.

> First commit in this slice: `docs(phase-11): Slice 11d plan` for this file, then the tasks below.

## File structure
- Create `.../store/migrations/versions/0026_cost_provider_gpu.py` (down_revision `0025_agent_budget`).
- Modify `.../store/models.py` — `CostRecord.provider`, `.gpu_seconds`, `.gpu_memory_mib`,
  `.gpu_attribution`.
- Create `.../agentos_controlplane/gpu.py` — the capability probe + `NvmlGpuMeter`.
- Modify `.../economics.py` — downstream recording + GPU fields on the record path.
- Modify `.../api.py` — the roll-up gains provider + GPU columns.
- Tests: `tests/unit/test_gpu.py`, extend `tests/unit/test_economics.py`.

---

### Task 1: widen `cost_record` for provider + GPU (migration 0026)

**Files:** modify `.../store/models.py`; create the migration; test `tests/unit/test_economics.py`.

Four new nullable columns on `CostRecord`:

```python
    # ECON-03 — downstream (non-model) consumption. `provider` is the action's own target, a FACT we
    # already hold; it is never an inferred vendor name. Inferring "this target is really AWS" would
    # put a guess into a cost report that an operator reconciles against a real invoice.
    provider: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # ECON-03 — GPU, recorded only when something actually reported it (never zero-filled).
    gpu_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)
    gpu_memory_mib: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    # 'process' = measured for THIS process. 'device_shared' = a device-wide counter that cannot be
    # honestly divided among concurrent agents, so it is explicitly NOT a per-agent bill.
    gpu_attribution: Mapped[str | None] = mapped_column(String(16), nullable=True)
```

Migration `0026_cost_provider_gpu.py` (`revision = "0026_cost_provider_gpu"`,
`down_revision = "0025_agent_budget"`) adds the four columns with `batch_alter_table` (SQLite cannot
add columns to a table with constraints in place otherwise — the same pattern migration 0022 used),
and drops them on downgrade. All four nullable, so existing rows need no backfill: an old row genuinely
has no provider and no GPU reading, and inventing one would be worse than the null.

- [ ] **Step 1: Failing test** — insert a `CostRecord` with `provider="api.stripe.com"` and
  `gpu_seconds=None`; read back; assert the provider round-trips and every GPU column is None.
- [ ] **Step 2: Run → fails.** **Step 3: Add columns + migration.** **Step 4: Run → passes;**
  alembic single head `['0026_cost_provider_gpu']`.
- [ ] **Step 5: Commit** `feat(controlplane): cost_record provider + GPU columns, migration 0026 (ECON-03)`.

---

### Task 2: the GPU capability probe

**Files:** create `.../agentos_controlplane/gpu.py`; test `tests/unit/test_gpu.py`.

```python
"""ECON-03 (GPU half) — attribute GPU usage per agent, honestly or not at all.

CAPABILITY-GATED, like RUN-05's POSIX path. NVML is not a dependency of this project: most
deployments run against hosted model APIs and have no GPU, and making them install an NVIDIA library
to use a governance control plane would be an absurd tax. If `nvidia-ml-py` is absent, or importable
but finding no device, `gpu_metering_available()` is False and the meter records NOTHING — not zero.
A zero would read as 'this agent used no GPU', which is a claim; absence reads as 'we did not
measure', which is the truth.

WHAT CANNOT BE MEASURED HONESTLY. NVML reports utilization per DEVICE. A control plane governing
several agents inside one process cannot divide a device-wide number among them — any split would be
invented. So a reading is labelled:

    process        - per-process memory attributable to THIS process (nvmlDeviceGetComputeRunningProcesses)
    device_shared  - a device-wide counter; NOT a per-agent bill, and must never be presented as one

This distinction is the whole design. Phase 9's Slice 9c shipped a first draft that attributed
process-wide tracemalloc deltas to individual actions, and the review killed it because it fabricated
audit accusations against whichever agent happened to be running. GPU telemetry offers the identical
trap.

NOT EXERCISED LOCALLY. The machine this was written on has no GPU and no NVML, so the NVML branch is
covered by tests against a fake NVML module rather than real hardware. Said plainly here so nobody
reads green tests as proof the vendor path works on a real device.
"""
from __future__ import annotations

from dataclasses import dataclass

PROCESS = "process"
DEVICE_SHARED = "device_shared"


@dataclass(frozen=True)
class GpuReading:
    gpu_memory_mib: int
    attribution: str
    gpu_seconds: float | None = None


def _nvml():
    """Import NVML lazily, or return None. Never raises — an absent GPU library is a normal
    deployment, not an error condition."""
    try:
        import pynvml  # type: ignore

        return pynvml
    except Exception:
        return None


def gpu_metering_available() -> bool:
    """True only when NVML imports AND initializes AND reports at least one device."""
    nvml = _nvml()
    if nvml is None:
        return False
    try:
        nvml.nvmlInit()
        return nvml.nvmlDeviceGetCount() > 0
    except Exception:
        return False


def read_gpu(pid: int | None = None) -> GpuReading | None:
    """The current GPU reading for this process, or None when nothing can be measured.

    Prefers the per-process figure. Falls back to the device-wide one ONLY with the
    `device_shared` label attached, so a consumer can never mistake it for a per-agent bill.
    """
    import os

    nvml = _nvml()
    if nvml is None:
        return None
    pid = os.getpid() if pid is None else pid
    try:
        nvml.nvmlInit()
        for i in range(nvml.nvmlDeviceGetCount()):
            handle = nvml.nvmlDeviceGetHandleByIndex(i)
            for proc in nvml.nvmlDeviceGetComputeRunningProcesses(handle):
                if getattr(proc, "pid", None) == pid:
                    used = getattr(proc, "usedGpuMemory", None)
                    if used:
                        return GpuReading(gpu_memory_mib=int(used) // (1024 * 1024), attribution=PROCESS)
            info = nvml.nvmlDeviceGetMemoryInfo(handle)
            return GpuReading(gpu_memory_mib=int(info.used) // (1024 * 1024), attribution=DEVICE_SHARED)
    except Exception:
        return None
    return None
```

- [ ] **Step 1: Write the failing tests**

```python
"""ECON-03 GPU probe. No GPU exists on the machine this was written on, so the NVML branch is
exercised against a fake module injected into sys.modules — and the tests say so, because green
tests here are NOT evidence the vendor path works on real hardware."""
import sys
import types

import pytest

from agentos_controlplane.gpu import DEVICE_SHARED, PROCESS, gpu_metering_available, read_gpu


def test_without_nvml_nothing_is_available_and_nothing_is_recorded(monkeypatch) -> None:
    """The default deployment. Absence must be silent and safe, never an error and never a zero."""
    monkeypatch.setitem(sys.modules, "pynvml", None)
    assert gpu_metering_available() is False
    assert read_gpu() is None


def _fake_nvml(*, process_pid=None, used_bytes=2 * 1024**3, device_used=8 * 1024**3, count=1):
    m = types.ModuleType("pynvml")
    m.nvmlInit = lambda: None
    m.nvmlDeviceGetCount = lambda: count
    m.nvmlDeviceGetHandleByIndex = lambda i: object()
    proc = types.SimpleNamespace(pid=process_pid, usedGpuMemory=used_bytes)
    m.nvmlDeviceGetComputeRunningProcesses = lambda h: ([proc] if process_pid is not None else [])
    m.nvmlDeviceGetMemoryInfo = lambda h: types.SimpleNamespace(used=device_used)
    return m


def test_a_per_process_reading_is_labelled_process(monkeypatch) -> None:
    import os

    monkeypatch.setitem(sys.modules, "pynvml", _fake_nvml(process_pid=os.getpid()))
    r = read_gpu()
    assert r.attribution == PROCESS and r.gpu_memory_mib == 2048


def test_a_device_wide_reading_is_labelled_device_shared(monkeypatch) -> None:
    """THE finding this design exists to avoid. A device-wide number attributed to one agent is a
    fabricated bill — the same defect Slice 9c's review caught with tracemalloc. The label is what
    keeps a consumer from presenting it as per-agent."""
    monkeypatch.setitem(sys.modules, "pynvml", _fake_nvml(process_pid=None))
    r = read_gpu()
    assert r.attribution == DEVICE_SHARED and r.gpu_memory_mib == 8192


def test_a_broken_nvml_degrades_to_None_rather_than_raising(monkeypatch) -> None:
    """A telemetry library that throws must not take down a governed call. Metering is bookkeeping;
    the action already happened."""
    m = types.ModuleType("pynvml")

    def boom(*a, **k):
        raise RuntimeError("driver mismatch")

    m.nvmlInit = boom
    monkeypatch.setitem(sys.modules, "pynvml", m)
    assert gpu_metering_available() is False
    assert read_gpu() is None


def test_no_device_means_unavailable(monkeypatch) -> None:
    monkeypatch.setitem(sys.modules, "pynvml", _fake_nvml(count=0))
    assert gpu_metering_available() is False
```

> Implementer note: `monkeypatch.setitem(sys.modules, "pynvml", None)` makes `import pynvml` raise
> `ImportError`, which is what the first test wants. Verify that behavior holds on this Python
> version; if not, use a `monkeypatch.setattr(builtins, "__import__", ...)` shim or delete the key
> and block the finder. The assertion must genuinely exercise the absent-library path.

- [ ] **Step 2: Run → fails.** **Step 3: Implement `gpu.py`.** **Step 4: Run → passes.**
- [ ] **Step 5: Commit** `feat(controlplane): capability-gated GPU probe with honest attribution labels (ECON-03)`.

---

### Task 3: downstream attribution + GPU on the record path + roll-up

**Files:** modify `.../economics.py`, `.../api.py`; test `tests/unit/test_economics.py`.

`CostRecorder.record` gains the provider and the optional GPU reading:

```python
    async def record(self, action, decision, usage, *, gpu: "GpuReading | None" = None) -> None:
        ...
        provider = action.target if action.type in _DOWNSTREAM_TYPES else None
```
where
```python
# ECON-03: non-model action types whose target IS the downstream service being consumed. The target
# is a fact the PEP already normalized; no vendor is inferred from it.
_DOWNSTREAM_TYPES = frozenset({ActionType.tool_call, ActionType.mcp_call})
```

and the GPU fields flow onto the row (`gpu_seconds`, `gpu_memory_mib`, `gpu_attribution` — all None
when `gpu is None`). The audit body gains `provider` and, when present, the GPU numbers plus the
attribution label. **The label must travel with the number everywhere it goes** — an audit event
carrying a device-wide figure without its label is the same fabricated bill, one hop downstream.

`totals()` gains `gpu_seconds` / `gpu_memory_mib_max`, and a new `by_provider()` roll-up:

```python
    def by_provider(self) -> list[dict]:
        """ECON-03 — downstream consumption per (agent, provider)."""
        with self._sf() as s:
            rows = s.execute(
                select(
                    CostRecord.agent_id,
                    CostRecord.provider,
                    func.count().label("calls"),
                    func.sum(CostRecord.cost_micro_usd),
                )
                .where(CostRecord.provider.is_not(None))
                .group_by(CostRecord.agent_id, CostRecord.provider)
                .order_by(CostRecord.agent_id, CostRecord.provider)
            ).all()
        return [
            {"agent_id": r[0], "provider": r[1], "calls": r[2], "cost_micro_usd": int(r[3] or 0)}
            for r in rows
        ]
```

Wire `meter` at the execution site to pass a GPU reading when available. Read it **once per action,
not per level of the call stack**, and only when `gpu_metering_available()` — the probe must not add
an NVML call to every governed action in a deployment that has no GPU.

API: add `GET /economics/providers` on the gated router returning `by_provider()`.

- [ ] **Step 1: Write the failing tests**

```python
@pytest.mark.asyncio
async def test_a_tool_call_attributes_its_provider_from_the_target(store) -> None:
    """The target is a fact the PEP normalized. Nothing is inferred about which vendor it 'really'
    is, because a guessed vendor lands in a cost report an operator reconciles against an invoice."""
    rec = CostRecorder(store, AuditWriter(store), PriceBook({}, version="v"))
    await rec.record(_tool_action("a1", target="api.stripe.com"), _decision(), Usage(0, 0, None))
    with store() as s:
        assert s.scalars(select(CostRecord)).one().provider == "api.stripe.com"


@pytest.mark.asyncio
async def test_a_model_invocation_has_no_provider(store) -> None:
    rec = CostRecorder(store, AuditWriter(store), PriceBook({}, version="v"))
    await rec.record(_action(), _decision(), Usage(1, 1, "gpt-4o"))
    with store() as s:
        assert s.scalars(select(CostRecord)).one().provider is None


@pytest.mark.asyncio
async def test_a_device_shared_gpu_reading_keeps_its_label_into_the_audit_body(store) -> None:
    """The label must travel with the number. A device-wide figure logged WITHOUT its label is a
    fabricated per-agent bill one hop downstream — the whole failure this design avoids."""
    from agentos_controlplane.gpu import DEVICE_SHARED, GpuReading

    rec = CostRecorder(store, AuditWriter(store), PriceBook({}, version="v"))
    await rec.record(
        _action(), _decision(), Usage(1, 1, "gpt-4o"),
        gpu=GpuReading(gpu_memory_mib=8192, attribution=DEVICE_SHARED),
    )
    with store() as s:
        row = s.scalars(select(CostRecord)).one()
        bodies = json.dumps([r.body for r in s.scalars(select(AuditRecord)).all()])
    assert row.gpu_attribution == DEVICE_SHARED and row.gpu_memory_mib == 8192
    assert DEVICE_SHARED in bodies


@pytest.mark.asyncio
async def test_no_gpu_reading_leaves_the_columns_null_not_zero(store) -> None:
    rec = CostRecorder(store, AuditWriter(store), PriceBook({}, version="v"))
    await rec.record(_action(), _decision(), Usage(1, 1, "gpt-4o"))
    with store() as s:
        row = s.scalars(select(CostRecord)).one()
    assert row.gpu_seconds is None and row.gpu_memory_mib is None and row.gpu_attribution is None


@pytest.mark.asyncio
async def test_provider_rollup_groups_by_agent_and_provider(store) -> None:
    rec = CostRecorder(store, AuditWriter(store), PriceBook({}, version="v"))
    for target in ("api.stripe.com", "api.stripe.com", "api.twilio.com"):
        await rec.record(_tool_action("a1", target=target), _decision(), Usage(0, 0, None))
    rollup = {r["provider"]: r["calls"] for r in rec.by_provider()}
    assert rollup == {"api.stripe.com": 2, "api.twilio.com": 1}
```

- [ ] **Step 2: Run → fails.** **Step 3: Implement.**
- [ ] **Step 4: Run → passes**, then the FULL gate: `pytest -q`, `-m floor_invariant`,
  `-m regression_lock`, `-m latency`, coverage check, alembic single-head check.
- [ ] **Step 5: Commit** `feat(controlplane): downstream provider + GPU attribution on the cost path (ECON-03)`.

## Self-review

ECON-03 names two things and both land: **GPU usage** through a capability-gated probe, and
**downstream API consumption** through a `provider` attribution keyed by the action's own target with
a per-(agent, provider) roll-up.

The design's central risk is answered by construction, not by promise. GPU numbers carry an
`attribution` label; a device-wide figure is explicitly not a per-agent bill; and a test asserts the
label survives into the audit body, because a number that loses its qualifier one hop downstream is
exactly how a fabricated bill gets created. This is the Slice 9c `tracemalloc` finding generalized,
and it is cited in the module docstring so the next person to touch it knows why the label exists.

Absence is preserved as absence throughout: no NVML means no record (not zero), an unpriced
downstream call keeps its token/call facts with a null cost, and old rows are not backfilled with
invented values.

The honest limit is stated in the module docstring and repeated here: **this machine has no GPU and
no NVML**, so the vendor branch is tested against a fake NVML module. Those green tests prove the
logic and the labelling; they are not evidence that the NVML calls behave as expected on real
hardware, and nobody should read them that way.
