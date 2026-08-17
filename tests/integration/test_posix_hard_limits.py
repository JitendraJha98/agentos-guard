"""The opt-in HARD limit path: real kernel enforcement via POSIX setrlimit (RUN-05, 9c/3).

Everything in `agentos_sdk.enforce` is a cooperative, in-process budget. This module is the one place
where a limit is enforced by the KERNEL — a child process under RLIMIT_CPU / RLIMIT_AS is killed
whether or not it cooperates. It exists only where `resource` imports, so the real-kill proof is
platform-gated.

The gate is paired with an ALWAYS-RUNNING contract test, so Windows still verifies the capability
reports itself honestly (`hard_limits_available()` matches the platform) and refuses loudly rather
than silently pretending to apply a limit it cannot apply. A capability that lies about being
available is worse than one that is absent.
"""

from __future__ import annotations

import sys

import pytest

from agentos_controlplane.posix_limits import hard_limits_available, run_python_limited

posix_only = pytest.mark.skipif(
    not hard_limits_available(), reason="POSIX rlimits unavailable on this platform"
)


# --- the always-running capability contract ----------------------------------


def test_availability_matches_the_platform() -> None:
    """Honest self-report: `resource` exists on POSIX and not on Windows."""
    assert hard_limits_available() is (sys.platform != "win32")


def test_run_python_limited_refuses_loudly_when_unavailable() -> None:
    """Where the capability is absent it must RAISE, never silently run the child unlimited — a
    caller that asked for a kernel limit and got none must find out."""
    if hard_limits_available():
        pytest.skip("capability present; the refusal path is exercised on Windows")
    with pytest.raises(RuntimeError, match="unavailable"):
        run_python_limited("print('x')", address_space_mb=64)


# --- the real-kill proof (POSIX only) ----------------------------------------


# RLIMIT_AS is applied BEFORE exec, so the interpreter itself boots under it — the cap must leave
# room for CPython's own address space (VSZ, not RSS) or the control test below would fail for the
# wrong reason. 256 MB is comfortable headroom while still far below the 1 GB the runaway asks for.
_AS_MB = 256


@posix_only
def test_an_address_space_limit_actually_kills_a_runaway_allocation() -> None:
    """Genuinely preventive, unlike the in-process memory budget: the child cannot complete the
    allocation at all."""
    done = run_python_limited(
        "b = b'x' * (1024 * 1024 * 1024); print(len(b))", address_space_mb=_AS_MB
    )
    assert done.returncode != 0  # killed by the kernel, or MemoryError
    assert "1073741824" not in done.stdout  # the allocation never completed


@posix_only
def test_the_same_limit_lets_a_well_behaved_child_finish() -> None:
    """The control: proves the limit is selective, not a blanket failure to launch children."""
    done = run_python_limited("print('ok')", address_space_mb=_AS_MB)
    assert done.returncode == 0
    assert done.stdout.strip() == "ok"


@posix_only
def test_a_cpu_limit_kills_a_spinning_child() -> None:
    """The dimension the in-process wall budget CANNOT enforce: a sync CPU-bound loop that never
    yields. Cooperative cancellation cannot touch it; RLIMIT_CPU can."""
    done = run_python_limited("while True: pass", cpu_s=1, timeout_s=30.0)
    assert done.returncode != 0
