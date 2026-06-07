"""Policy stage (POL-03 / D-05) — the deterministic OPA WASM floor.

The egress-allowlist principle (policies/egress.rego) is compiled to a WASM
bundle by the pinned OPA CLI (`opa build -t wasm -e 'agentos/egress/allow'`,
extract policy.wasm -> policies/build/egress.wasm). `WasmPolicyEngine` loads that
bundle ONCE at construction (Pitfall 2 — never per request) and evaluates each
action in-process via opa-wasmtime, with no network and no per-request compile.

OPA stays behind the `PolicyEngine` Protocol so an OPA-server deployment is a
future toggle (one-file swap), not a rewrite (D-05).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from opa_wasmtime import OPAPolicy

from agentos_contract import Outcome


@dataclass(frozen=True)
class PolicyResult:
    """The policy stage's verdict for one action.

    `outcome` is the deterministic floor; `code` is the machine-readable reason
    the pipeline copies into Decision.reasons (PIPE-02); `policy_id` is the fired
    principle; `detail` is a short human string that NEVER carries raw payload.
    """

    outcome: Outcome
    code: str
    policy_id: str
    detail: str = ""


@runtime_checkable
class PolicyEngine(Protocol):
    """The toggle seam (POL-03). OPA-server later swaps in behind this."""

    def evaluate(self, input: dict) -> PolicyResult: ...


def _extract_bool(result: object) -> bool:
    """Pull the allow boolean out of the OPA WASM result set.

    opa-wasmtime's OPAPolicy.evaluate() returns the OPA result set as a list with
    one entry per entrypoint result: ``[{"result": <bool>}]`` for the single
    `agentos/egress/allow` entrypoint (index 0, recorded at the 01-04 Task-1
    human-verify checkpoint). Anything unexpected fails closed (deny) — never
    silently fail-open (Pitfall 3).
    """
    if isinstance(result, list) and result and isinstance(result[0], dict):
        return bool(result[0].get("result"))
    return False


class WasmPolicyEngine:
    """In-process OPA WASM floor. The bundle is loaded ONCE at construction."""

    def __init__(self, wasm_path: str, allowlist: list[str]) -> None:
        # Load once, reuse for every request (Pitfall 2). Do NOT construct
        # OPAPolicy or read the .wasm inside evaluate().
        self._policy = OPAPolicy(wasm_path)
        # Supply the concrete hosts as a Rego `data` document (the principle
        # itself stays in Rego; the allowlist is configuration — D-05 note).
        # Canonicalize each entry to a stripped, lowercased host so both sides
        # of the Rego membership test match: `_host` (urlsplit.hostname) always
        # lowercases, so an uppercase/mixed-case allowlist entry would otherwise
        # silently fail-deny. Host comparison on a security floor must be
        # normalized in code, not left to caller discipline.
        self._policy.set_data({"allowlist": [h.strip().lower() for h in allowlist]})

    def evaluate(self, input: dict) -> PolicyResult:
        allowed = _extract_bool(self._policy.evaluate(input))
        # The egress principle governs OUTBOUND TOOL egress only (Phase 2, INT-02..05).
        # For other action types the WASM floor returns allow (the principle does not
        # apply); report a type-appropriate reason rather than the egress-allowlist one,
        # so the Decision never claims an egress check it did not perform. Phase 3 adds
        # the deterministic per-type policies for these action classes.
        if input.get("type") != "tool_call":
            return PolicyResult(
                outcome=Outcome.allow if allowed else Outcome.deny,
                code="no_egress_policy_applicable",
                policy_id="egress.allow",
                detail=f"egress principle does not govern action type {input.get('type')!r}",
            )
        if allowed:
            return PolicyResult(
                outcome=Outcome.allow,
                code="egress_allowlisted",
                policy_id="egress.allow",
            )
        return PolicyResult(
            outcome=Outcome.deny,
            code="egress_allowlist_violation",
            policy_id="egress.allow",
            detail="host not in allowlist",
        )
