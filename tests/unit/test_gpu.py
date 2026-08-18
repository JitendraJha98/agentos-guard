"""ECON-03 (GPU half) — the capability probe and its attribution labels.

THE MACHINE THIS WAS WRITTEN ON HAS NO GPU AND NO NVML. Every branch below that touches a vendor
call is exercised against a FAKE module injected into `sys.modules`, so green here proves the logic
and the labelling and nothing at all about how NVML behaves on real hardware. Said plainly so nobody
reads this file as evidence the vendor path works on a device.
"""

from __future__ import annotations

import os
import sys
import types

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
    device_used: int = 8 * 1024**3,
    count: int = 1,
    process_on_device: int = 0,
) -> types.ModuleType:
    """A stand-in for `pynvml`. The handle IS the device index, so a test can put the running
    process on a device other than the first one."""
    m = types.ModuleType("pynvml")
    m.nvmlInit = lambda: None
    m.nvmlDeviceGetCount = lambda: count
    m.nvmlDeviceGetHandleByIndex = lambda i: i
    proc = types.SimpleNamespace(pid=process_pid, usedGpuMemory=used_bytes)
    m.nvmlDeviceGetComputeRunningProcesses = (
        lambda h: [proc] if (process_pid is not None and h == process_on_device) else []
    )
    m.nvmlDeviceGetMemoryInfo = lambda h: types.SimpleNamespace(used=device_used)
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
