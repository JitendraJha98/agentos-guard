"""ECON-03 (GPU half) — the capability probe and its attribution labels.

THE MACHINE THIS WAS WRITTEN ON HAS NO GPU AND NO NVML. Every branch below that touches a vendor
call is exercised against a FAKE module injected into `sys.modules`, so green here proves the logic
and the labelling and nothing at all about how NVML behaves on real hardware. Said plainly so nobody
reads this file as evidence the vendor path works on a device.
"""

from __future__ import annotations

import math
import os
import sys
import types

import pytest

from agentos_controlplane.gpu import (
    DEVICE_SHARED,
    PROCESS,
    GpuReading,
    gpu_metering_available,
    read_gpu,
)


def _fake_nvml(
    *,
    process_pid: int | None = None,
    used_bytes: int = 2 * 1024**3,
    device_used: int | list[int] = 8 * 1024**3,
    count: int = 1,
    process_on_device: int = 0,
) -> types.ModuleType:
    """A stand-in for `pynvml`. The handle IS the device index, so a test can put the running
    process on a device other than the first one; `device_used` may be a per-device list. Every
    memory query is recorded on `m.seen`, because "which devices did it actually ask about" is a
    claim this module's docstring makes and a `for` loop can silently stop making."""
    m = types.ModuleType("pynvml")
    m.nvmlInit = lambda: None
    m.nvmlDeviceGetCount = lambda: count
    m.nvmlDeviceGetHandleByIndex = lambda i: i
    proc = types.SimpleNamespace(pid=process_pid, usedGpuMemory=used_bytes)
    m.nvmlDeviceGetComputeRunningProcesses = (
        lambda h: [proc] if (process_pid is not None and h == process_on_device) else []
    )
    m.seen = []

    def memory_info(h):
        m.seen.append(h)
        used = device_used[h] if isinstance(device_used, list) else device_used
        return types.SimpleNamespace(used=used)

    m.nvmlDeviceGetMemoryInfo = memory_info
    return m


def test_without_nvml_nothing_is_available_and_nothing_is_recorded(monkeypatch) -> None:
    """The DEFAULT deployment, not an edge case: most fleets run against hosted model APIs and own
    no GPU. Absence must be silent and safe — never an error, and never a zero, because a zero
    reads as 'this agent used no GPU' where the truth is 'we did not measure'."""
    monkeypatch.setitem(sys.modules, "pynvml", None)  # makes `import pynvml` raise ImportError

    assert gpu_metering_available() is False
    assert read_gpu() is None


def test_a_per_process_reading_is_labelled_process(monkeypatch) -> None:
    monkeypatch.setitem(sys.modules, "pynvml", _fake_nvml(process_pid=os.getpid()))

    reading = read_gpu()

    assert reading == GpuReading(gpu_memory_mib=2048, attribution=PROCESS)


def test_a_device_wide_reading_is_labelled_device_shared(monkeypatch) -> None:
    """THE finding this design exists to avoid. A device-wide number handed to one agent is a
    fabricated bill — the same defect Slice 9c's review caught with process-wide tracemalloc deltas.
    The label is the only thing stopping a consumer from presenting it as per-agent."""
    monkeypatch.setitem(sys.modules, "pynvml", _fake_nvml(process_pid=None))

    reading = read_gpu()

    assert reading.attribution == DEVICE_SHARED
    assert reading.gpu_memory_mib == 8192


def test_the_process_is_found_on_a_LATER_device_before_falling_back_to_device_wide(
    monkeypatch,
) -> None:
    """Multi-GPU is the normal shape of a self-hosted box. Answering `device_shared` off device 0
    while this process's own figure sat on device 1 would downgrade an honestly attributable
    reading to the one that must never be billed — the weaker claim winning by loop order."""
    monkeypatch.setitem(
        sys.modules, "pynvml", _fake_nvml(process_pid=os.getpid(), count=2, process_on_device=1)
    )

    assert read_gpu().attribution == PROCESS


def test_a_broken_nvml_degrades_to_None_rather_than_raising(monkeypatch) -> None:
    """A telemetry library that throws must not take down a governed call. Metering is bookkeeping
    and the action already happened; a driver/library version mismatch is a routine condition on a
    GPU box, not a reason to fail the agent."""
    m = types.ModuleType("pynvml")

    def boom(*a, **k):
        raise RuntimeError("driver/library version mismatch")

    m.nvmlInit = boom
    monkeypatch.setitem(sys.modules, "pynvml", m)

    assert gpu_metering_available() is False
    assert read_gpu() is None


def test_nvml_that_reports_no_device_is_not_an_available_capability(monkeypatch) -> None:
    """An importable library is not a GPU. A capability that lies about being available is worse
    than an absent one (the RUN-05 rule), and here the lie would be a metering path that runs on
    every action and records nothing."""
    monkeypatch.setitem(sys.modules, "pynvml", _fake_nvml(count=0))

    assert gpu_metering_available() is False
    assert read_gpu() is None


def test_a_process_that_reports_no_memory_is_not_recorded_as_zero(monkeypatch) -> None:
    """NVML returns no per-process figure at all when it cannot attribute one (MIG, permissions).
    Recording that as 0 MiB would assert this process held no GPU memory. It falls back to the
    device-wide reading, which at least carries a label saying what it is."""
    nvml = _fake_nvml(process_pid=os.getpid(), used_bytes=None)
    monkeypatch.setitem(sys.modules, "pynvml", nvml)

    assert read_gpu().attribution == DEVICE_SHARED


def test_the_probe_never_invents_gpu_seconds(monkeypatch) -> None:
    """NVML reports instantaneous utilization PERCENT, not seconds. Multiplying a sample by a wall
    interval to produce 'GPU-seconds' would be a manufactured number on a cost report, so the probe
    leaves the field None and lets a source that genuinely knows it supply it."""
    monkeypatch.setitem(sys.modules, "pynvml", _fake_nvml(process_pid=os.getpid()))

    assert read_gpu().gpu_seconds is None


def test_a_sub_mib_process_allocation_is_not_floored_into_a_process_level_zero(monkeypatch) -> None:
    """The branch two lines up refuses a missing per-process figure because 0 MiB would assert this
    process held no GPU memory — and then integer division wrote that same lie for anything under a
    MiB, under `process`, the ONE label a roll-up is allowed to turn into a per-agent number."""
    monkeypatch.setitem(
        sys.modules, "pynvml", _fake_nvml(process_pid=os.getpid(), used_bytes=500_000)
    )

    reading = read_gpu()

    assert reading.attribution == PROCESS
    assert reading.gpu_memory_mib == 1, "a real allocation must never be recorded as no allocation"


def test_the_device_wide_fallback_covers_EVERY_device_not_just_the_first(monkeypatch) -> None:
    """The fallback was a `for` loop that returned on iteration 1, so an 8-GPU box reported one
    arbitrary device's memory as 'the device-wide reading' while reading like a scan — a workload
    sitting on device 3 surfaced as device 0's idle figure, with nothing on the row saying which
    device it came from."""
    nvml = _fake_nvml(
        process_pid=None, count=4, device_used=[1 * 1024**3, 2 * 1024**3, 0, 5 * 1024**3]
    )
    monkeypatch.setitem(sys.modules, "pynvml", nvml)

    reading = read_gpu()

    assert nvml.seen == [0, 1, 2, 3], "a device never queried is a device silently left out"
    assert reading == GpuReading(gpu_memory_mib=8192, attribution=DEVICE_SHARED)


@pytest.mark.parametrize(
    "broken",
    ["nvmlDeviceGetHandleByIndex", "nvmlDeviceGetComputeRunningProcesses", "nvmlDeviceGetMemoryInfo"],
)
def test_nvml_that_can_never_produce_a_READING_is_not_an_available_capability(
    monkeypatch, broken: str
) -> None:
    """Init-plus-device-count is not a capability. A MIG or permission-restricted container is the
    ordinary case where those two succeed and everything after them raises, and calling that
    'available' latched True for the process lifetime: every governed action then paid a full NVML
    init and enumeration and recorded nothing. That is the capability lying about being available,
    which this module's RUN-05 precedent calls worse than an absent one."""

    def boom(*a, **k):
        raise RuntimeError("Insufficient Permissions")

    nvml = _fake_nvml(process_pid=None)  # nothing attributable to us — the MIG/container case
    setattr(nvml, broken, boom)
    monkeypatch.setitem(sys.modules, "pynvml", nvml)

    assert read_gpu() is None
    assert gpu_metering_available() is False


# --- a reading is validated where it is BORN, on the `Usage.reported` precedent ----------------


def test_an_unknown_attribution_label_is_refused_at_construction() -> None:
    """`totals()` buckets on the two known labels, so a third one matches NEITHER: a row holding
    8192 MiB would report `gpu_process_memory_mib_max: None` AND `gpu_device_shared_actions: 0` —
    'no GPU was seen', the exact misreading the device-shared count exists to prevent. The column
    is String(16) besides, so a long label raises on the Postgres INSERT into the PEP's metering
    swallow and drops the whole cost row."""
    with pytest.raises(ValueError) as exc:
        GpuReading(gpu_memory_mib=8192, attribution="estimated")

    assert "attribution" in str(exc.value) and "'estimated'" in str(exc.value)


def test_a_negative_gpu_figure_is_refused_the_way_a_negative_token_count_is() -> None:
    """Slice 11b hardened `Usage.reported` against negatives because ECON-02 sums them. This is the
    same shape of input from the same class of supplier — a scheduler, a sandbox runner — landing in
    the same roll-up, and leaving one side unguarded is precisely how 11b's hole happened."""
    with pytest.raises(ValueError) as memory:
        GpuReading(gpu_memory_mib=-999_999, attribution=PROCESS)
    with pytest.raises(ValueError) as seconds:
        GpuReading(gpu_memory_mib=8192, attribution=PROCESS, gpu_seconds=-5.0)

    assert "gpu_memory_mib" in str(memory.value)
    assert "gpu_seconds" in str(seconds.value)


def test_a_gpu_figure_that_overflows_the_ledger_column_is_refused_before_the_insert() -> None:
    """The 11b lesson on a second field: a BigInteger overflow makes the INSERT raise, the PEP's
    metering swallow eats it, and the entire cost row — money, not just a GPU number — vanishes."""
    with pytest.raises(ValueError) as exc:
        GpuReading(gpu_memory_mib=2**63, attribution=PROCESS)

    assert "ledger column" in str(exc.value)


def test_a_non_finite_gpu_seconds_is_refused_before_it_can_poison_a_roll_up() -> None:
    """SQL SUM over a column holding one NaN answers NaN, so a single bad reading turns an agent's
    whole GPU total into a non-number on the operator-facing route."""
    for bad in (math.nan, math.inf):
        with pytest.raises(ValueError) as exc:
            GpuReading(gpu_memory_mib=8192, attribution=PROCESS, gpu_seconds=bad)
        assert "finite" in str(exc.value)
