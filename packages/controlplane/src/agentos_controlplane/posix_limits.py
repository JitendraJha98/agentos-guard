"""RUN-05 (opt-in HARD path) — real kernel-enforced limits via POSIX setrlimit.

Everything in `agentos_sdk.enforce` is a cooperative, in-process budget: the wall limit cancels an
awaiting handler, and the memory limit only notices a breach after the fact. This module is the one
place in RUN-05 where the KERNEL does the enforcing — a child process under RLIMIT_CPU / RLIMIT_AS is
killed whether or not it cooperates, so a runaway allocation or a synchronous spin loop (exactly the
cases in-process cancellation cannot touch) is genuinely stopped.

Capability-gated: `resource` does not exist on Windows, where `hard_limits_available()` reports False
and `run_python_limited` RAISES rather than silently running an unlimited child. Callers fall back to
the portable PEP budgets. A capability that lies about being available is worse than an absent one.

Deliberately a small, honest capability rather than a sandbox framework: it runs a child Python under
rlimits and nothing more. Full confinement of hostile code stays the gateway/sidecar (Phase 10) and
K8s (Phase 14) layer, per `docs/architecture/05`.
"""

from __future__ import annotations

import subprocess
import sys

try:  # pragma: no cover - platform-gated
    import resource as _resource
except ImportError:  # Windows has no `resource` module
    _resource = None


def hard_limits_available() -> bool:
    """True when POSIX rlimits can actually be applied on this platform."""
    return _resource is not None


def _preexec(cpu_s: int | None, address_space_mb: int | None):  # pragma: no cover - child process
    """Build the child-side hook that lowers its own rlimits before exec."""

    def apply() -> None:
        if cpu_s is not None:
            _resource.setrlimit(_resource.RLIMIT_CPU, (cpu_s, cpu_s))
        if address_space_mb is not None:
            nbytes = int(address_space_mb) * 1024 * 1024
            _resource.setrlimit(_resource.RLIMIT_AS, (nbytes, nbytes))

    return apply


def run_python_limited(
    code: str,
    *,
    cpu_s: int | None = None,
    address_space_mb: int | None = None,
    timeout_s: float = 30.0,
) -> subprocess.CompletedProcess:
    """Run `code` in a child Python under kernel rlimits.

    Raises RuntimeError where the capability is unavailable — never degrades to an unlimited run.
    """
    if not hard_limits_available():
        raise RuntimeError("POSIX rlimits are unavailable on this platform")
    return subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        timeout=timeout_s,
        preexec_fn=_preexec(cpu_s, address_space_mb),
    )
