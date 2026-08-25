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
    device_shared  - a host-wide counter; NOT a per-agent bill, and never to be presented as one

Those two strings are the whole vocabulary, and `GpuReading` refuses anything else. A third label
would be invisible to both roll-up buckets in `economics.totals()`, so a reading of 8 GiB carrying
`attribution='estimated'` would be reported as "no GPU was seen" — the exact misreading the
device-shared COUNT was added to prevent.

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

import math
import os
from dataclasses import dataclass

PROCESS = "process"
DEVICE_SHARED = "device_shared"
_ATTRIBUTIONS = frozenset({PROCESS, DEVICE_SHARED})

_MIB = 1024 * 1024
# `gpu_memory_mib` is BigInteger in the ledger. The bound is the 11b lesson applied to a second
# field: a value that overflows the column makes the INSERT raise, the PEP's metering swallow eats
# it, and the whole cost row — money, not just a GPU number — disappears.
_MAX_MIB = 2**63 - 1


@dataclass(frozen=True)
class GpuReading:
    """One GPU observation and, inseparably, what it is an observation OF.

    `gpu_seconds` is the GPU time THIS ONE ACTION consumed — a delta. It is explicitly NOT a
    cumulative process or job counter, which is the shape the NVML family and every batch scheduler
    actually report, because `economics.totals()` SUMs this field: a caller passing a running total
    would have it multiplied by the action count on the one figure here that looks like a bill.
    (Memory is the opposite and is MAXed there — it is a level, not a quantity that accumulates.)
    """

    gpu_memory_mib: int
    attribution: str
    gpu_seconds: float | None = None

    def __post_init__(self) -> None:
        """Validated on the `Usage.reported` precedent and for its reason: the documented supplier
        of this object is a scheduler or sandbox runner nobody here controls, and 11b's hole was
        exactly this asymmetry — one metered input hardened, its neighbour not. A negative figure
        reaches `totals()` and subtracts from a fleet report; an unknown label matches neither
        bucket there, so 8 GiB is reported as "no GPU was seen"; and an over-16-character label
        raises on the Postgres INSERT into the PEP's swallow, dropping the entire cost row.
        """
        if self.attribution not in _ATTRIBUTIONS:
            raise ValueError(
                f"GpuReading.attribution must be one of {sorted(_ATTRIBUTIONS)}; "
                f"got {self.attribution!r}"
            )
        if type(self.gpu_memory_mib) is not int or not 0 <= self.gpu_memory_mib <= _MAX_MIB:
            raise ValueError(
                "GpuReading.gpu_memory_mib must be a non-negative int within the ledger column "
                f"(0..{_MAX_MIB}); got {self.gpu_memory_mib!r}"
            )
        if self.gpu_seconds is not None and (
            not math.isfinite(self.gpu_seconds) or self.gpu_seconds < 0
        ):
            # NaN is the sharp one: SQL SUM over a column holding a single NaN answers NaN, so one
            # bad reading turns an agent's entire GPU roll-up into a non-number.
            raise ValueError(
                "GpuReading.gpu_seconds must be a finite non-negative number of seconds consumed "
                f"by this action; got {self.gpu_seconds!r}"
            )


def _nvml():
    """Import NVML lazily, or return None. Never raises — an absent GPU library is a normal
    deployment, not an error condition."""
    try:
        import pynvml  # type: ignore

        return pynvml
    except Exception:
        return None


def gpu_metering_available() -> bool:
    """True only when NVML imports, initializes, reports a device, AND actually yields a reading.

    THE READING IS THE POINT. Stopping at init-plus-device-count declared the capability available
    on a box where every subsequent call raised — a MIG or permission-restricted container is the
    ordinary case, not an exotic one — so the meter paid a full NVML init and enumeration on every
    governed action forever and recorded nothing. That is a capability lying about being available,
    which is the one thing this module's RUN-05 precedent says is worse than an absent one.

    Callers cache this rather than re-asking: a failed `import` is not cached by Python, so probing
    per action would re-walk the whole import path on every governed call in exactly the deployments
    that have no GPU to meter. Note it leaves NVML INITIALIZED — the init is reference-counted and
    nothing here shuts it down, deliberate on a host that is about to meter every action, but it is
    a side effect the name does not advertise.
    """
    nvml = _nvml()
    if nvml is None:
        return False
    try:
        nvml.nvmlInit()
        if nvml.nvmlDeviceGetCount() <= 0:
            return False
    except Exception:
        return False
    return read_gpu() is not None


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
                    # Floored at 1 MiB rather than truncated toward it. This branch exists because a
                    # 0 would assert this process held no GPU memory, and integer division of a
                    # sub-MiB allocation writes that same lie under the `process` label — the one
                    # label a roll-up is allowed to turn into a per-agent number.
                    return GpuReading(gpu_memory_mib=max(1, int(used) // _MIB), attribution=PROCESS)
        if handles:
            # EVERY device, summed. The previous shape was a `for` loop that returned on its first
            # iteration: an 8-GPU box reported one arbitrary device's memory as "the device-wide
            # reading" while reading like a scan, so a workload sitting on device 3 surfaced as
            # device 0's idle figure. A host-wide total is still indivisible among concurrent
            # agents — hence the label, and hence `totals()` never sums it into a bill — but it is
            # at least the whole box rather than whichever device NVML happened to enumerate first.
            used = sum(int(nvml.nvmlDeviceGetMemoryInfo(h).used) for h in handles)
            return GpuReading(gpu_memory_mib=used // _MIB, attribution=DEVICE_SHARED)
    except Exception:
        return None
    return None
