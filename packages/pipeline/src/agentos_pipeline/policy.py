"""Policy stage (POL-03 / D-05) — the compiled-constitution WASM floor (Slice 3).

The constitution compiler (POL-02) lowers the operator Constitution to Rego with
one entrypoint, `agentos/constitution/result` -> {"matched": [...], "no_match":
bool}; the vendored/pinned OPA CLI builds that to a WASM bundle. The engine here
evaluates it in-process via opa-wasmtime — no network, no per-request compile.

OPA stays behind the `PolicyEngine` Protocol so an OPA-server deployment is a
future toggle (one-file swap), not a rewrite (D-05).

Caching discipline (PIPE-06): the loaded WASM bundle IS the compiled-policy
cache — loaded ONCE at construction (Pitfall 2, never per request), invalidated
only via `reload()` on a constitution/policy version change. There is NO
whole-Decision cache by design: trust drifts between calls and every action
must produce its own audit record.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Protocol, runtime_checkable

from opa_wasmtime import OPAPolicy

from agentos_contract.policy_io import ConstitutionResult, MatchedPrinciple


class PolicyEvaluationError(RuntimeError):
    """Engine could not produce a structured result — the runner applies the
    per-action-class posture (PIPE-05); NEVER silently allow."""


@runtime_checkable
class PolicyEngine(Protocol):
    """The toggle seam (POL-03). OPA-server later swaps in behind this."""

    def evaluate(self, input: dict) -> ConstitutionResult: ...


class ConstitutionPolicyEngine:
    """Compiled-constitution floor. The WASM bundle is the compiled-policy CACHE:
    loaded ONCE here (Pitfall 2), invalidated only via reload() on version change
    (PIPE-06). No whole-Decision cache by design (trust drift / per-action audit)."""

    def __init__(
        self,
        *,
        wasm_path: str,
        lists: dict[str, list[str]],
        constitution_version: str,
        principles_meta: dict[str, dict],
    ) -> None:
        self._load(
            wasm_path=wasm_path,
            lists=lists,
            constitution_version=constitution_version,
            principles_meta=principles_meta,
        )

    def _load(
        self,
        *,
        wasm_path: str,
        lists: dict[str, list[str]],
        constitution_version: str,
        principles_meta: dict[str, dict],
    ) -> None:
        self._policy = OPAPolicy(wasm_path)
        # Named lists are runtime configuration, not compiled policy (D-05).
        self._policy.set_data({"lists": lists})
        self.constitution_version = constitution_version
        # POL-08: the policy version is the hash of the exact compiled artifact.
        self.policy_version = (
            "sha256:" + hashlib.sha256(Path(wasm_path).read_bytes()).hexdigest()
        )
        # {ref: {title, statement, effect, side_effects}} — Reason rationale source.
        self.principles_meta = principles_meta

    def reload(
        self,
        *,
        wasm_path: str,
        lists: dict[str, list[str]],
        constitution_version: str,
        principles_meta: dict[str, dict],
    ) -> None:
        """Swap in a recompiled constitution — the PIPE-06 cache invalidation."""
        self._load(
            wasm_path=wasm_path,
            lists=lists,
            constitution_version=constitution_version,
            principles_meta=principles_meta,
        )

    def evaluate(self, input: dict) -> ConstitutionResult:
        """Evaluate one D4 policy-input document against the compiled constitution.

        The entrypoint result MUST be {"matched": [...], "no_match": bool} —
        anything else raises PolicyEvaluationError (fail closed; the runner
        applies the per-action-class posture, PIPE-05).
        """
        raw = self._policy.evaluate(input)
        if not (isinstance(raw, list) and raw and isinstance(raw[0], dict)):
            raise PolicyEvaluationError(f"unexpected OPA result set shape: {type(raw).__name__}")
        result = raw[0].get("result")
        if (
            not isinstance(result, dict)
            or not isinstance(result.get("matched"), list)
            or not isinstance(result.get("no_match"), bool)
        ):
            raise PolicyEvaluationError("malformed constitution result document")
        matched: list[MatchedPrinciple] = []
        for m in result["matched"]:
            if (
                not isinstance(m, dict)
                or not isinstance(m.get("principle_ref"), str)
                or not isinstance(m.get("effect"), str)
            ):
                raise PolicyEvaluationError("malformed matched-principle entry")
            matched.append(
                MatchedPrinciple(
                    principle_ref=m["principle_ref"],
                    effect=m["effect"],
                    evidence=m.get("evidence"),
                )
            )
        return ConstitutionResult(matched=tuple(matched), no_match=result["no_match"])
