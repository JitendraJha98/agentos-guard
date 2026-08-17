"""Interception-coverage registry (INT-06) — no silent gaps.

The Phase-2 goal is that ALL FIVE action types are governed, not just tool calls,
and that there is *no silently un-instrumented path*. This module is the teeth
behind that guarantee: every normalizer that defines an interception path registers
the `ActionType` it covers via the `@covers(...)` decorator at import time, so the
registry reflects reality — a type is "covered" iff something actually registered a
PEP entrypoint for it. `verify_coverage()` then fails loudly if any member of
`ActionType` is missing (a coverage gap), and the coverage test in CI asserts the
full matrix is green.

This catches the *static* gap (a new action type added to the contract with no PEP).
The *runtime* bypass — an action that reaches the pipeline without a valid identity —
is caught by the pipeline's fail-closed identity stage (IDN-02): an un-instrumented or
forged actor is denied, never silently allowed. The coverage test exercises both.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TypeVar

from agentos_contract import ActionType

# ActionType -> the fully-qualified entrypoints that intercept/normalize it. A SET, not a single
# string: from Phase 10 an action type legitimately has SEVERAL PEP forms (SDK middleware, SDK
# wrappers, the network gateway), and overwriting would hide all but the last one registered.
_REGISTRY: dict[ActionType, set[str]] = {}

_F = TypeVar("_F", bound=Callable[..., object])


class InterceptionGapError(RuntimeError):
    """Raised when one or more action types have no registered interception path."""


def covers(action_type: ActionType) -> Callable[[_F], _F]:
    """Register `fn` as AN interception/normalization path for `action_type` (several may exist)."""

    def _register(fn: _F) -> _F:
        _REGISTRY.setdefault(action_type, set()).add(f"{fn.__module__}.{fn.__qualname__}")
        return fn

    return _register


def covered_types() -> set[ActionType]:
    """The set of action types that currently have at least one registered PEP path.

    A key with an EMPTY set is a gap, not coverage — the type is listed but nothing intercepts it.
    """
    return {t for t, entries in _REGISTRY.items() if entries}


def coverage_matrix() -> dict[ActionType, set[str]]:
    """A copy of the full {action_type -> {entrypoints}} map (for inspection/reporting)."""
    return {t: set(entries) for t, entries in _REGISTRY.items()}


def verify_coverage() -> None:
    """Raise InterceptionGapError if any ActionType lacks an interception path."""
    missing = set(ActionType) - covered_types()
    if missing:
        names = ", ".join(sorted(t.value for t in missing))
        raise InterceptionGapError(f"un-instrumented action type(s): {names}")
