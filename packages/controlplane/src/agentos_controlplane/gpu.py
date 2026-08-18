"""ECON-03 (GPU half) — attribute GPU usage per agent, honestly or not at all.

CAPABILITY-GATED, on the RUN-05 precedent in `posix_limits.py` and for the same stated reason: a
capability that lies about being available is worse than an absent one. NVML is NOT a dependency of
this project — most deployments run against hosted model APIs and own no GPU, and making them
install an NVIDIA library to use a governance control plane would be an absurd tax. When
`nvidia-ml-py` is absent, or importable but finding no device, `gpu_metering_available()` is False
and the meter records NOTHING. Not zero: a zero reads as "this agent used no GPU", which is a claim,
where absence reads as "we did not measure", which is the truth (spec D-7).

WHAT CANNOT BE MEASURED HONESTLY. NVML reports utilization and memory per DEVICE. A control plane
governing several agents inside one process cannot divide a device-wide number among them — every
split would be invented. So a reading says which thing it measured:

    process        - memory NVML attributes to THIS process (nvmlDeviceGetComputeRunningProcesses)
    device_shared  - a device-wide counter; NOT a per-agent bill, and never to be presented as one

That distinction is the whole design. Phase 9's Slice 9c shipped a first draft that attributed
process-wide `tracemalloc` deltas to individual actions, and the review killed it because it
fabricated audit accusations against whichever agent happened to be running. GPU telemetry offers
the identical trap wearing different hardware, so the label travels with the number into the ledger
row and into the audit body rather than being dropped at the first hop.

`gpu_seconds` is left to a source that genuinely knows it (a scheduler, a sandbox runner). NVML
reports an instantaneous utilization PERCENT, and turning a sample into seconds by multiplying
through a wall interval would manufacture the one figure on this record that looks most like a bill.

NOT EXERCISED LOCALLY. The machine this was written on has no GPU and no NVML, so the vendor branch
is covered by tests against a fake NVML module. Green tests there prove the logic and the labelling;
they are not evidence that these calls behave as expected on a real device.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

PROCESS = "process"
DEVICE_SHARED = "device_shared"

_MIB = 1024 * 1024


@dataclass(frozen=True)
class GpuReading:
    """One GPU observation and, inseparably, what it is an observation OF."""

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
    """True only when NVML imports AND initializes AND reports at least one device.

    Callers cache this rather than re-asking: a failed `import` is not cached by Python, so probing
    per action would re-walk the whole import path on every governed call in exactly the deployments
    that have no GPU to meter.
    """
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

    Every device is searched for THIS process before any device-wide figure is considered. Answering
    `device_shared` off device 0 while the process's own attributable figure sat on device 1 would
    let loop order downgrade an honest reading to the one that must never be billed — and multi-GPU
    is the normal shape of a self-hosted box.

    Returns None rather than raising on any NVML fault. Metering is bookkeeping; the action it
    describes has already happened, and a driver/library version mismatch is a routine condition on
    a GPU host, not a reason to fail a governed call.
    """
    nvml = _nvml()
    if nvml is None:
        return None
    pid = os.getpid() if pid is None else pid
    try:
        # Re-initialized here rather than assumed: NVML's init is reference-counted and cheap after
        # the first call, and every other NVML entry point raises `Uninitialized` without it — which
        # this function would swallow into a None, turning "nobody called init" into "no GPU".
        nvml.nvmlInit()
        handles = [nvml.nvmlDeviceGetHandleByIndex(i) for i in range(nvml.nvmlDeviceGetCount())]
        for handle in handles:
            for proc in nvml.nvmlDeviceGetComputeRunningProcesses(handle):
                # NVML omits `usedGpuMemory` when it cannot attribute one (MIG, permissions).
                # Recording that as 0 MiB would assert this process held no GPU memory, so the
                # device-wide reading — which at least says what it is — is the better answer.
                used = getattr(proc, "usedGpuMemory", None)
                if getattr(proc, "pid", None) == pid and used:
                    return GpuReading(gpu_memory_mib=int(used) // _MIB, attribution=PROCESS)
        for handle in handles:
            info = nvml.nvmlDeviceGetMemoryInfo(handle)
            return GpuReading(gpu_memory_mib=int(info.used) // _MIB, attribution=DEVICE_SHARED)
    except Exception:
        return None
    return None
