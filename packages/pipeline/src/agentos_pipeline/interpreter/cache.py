"""PIPE-06 — bounded FIFO interpreter-verdict cache, keyed by action SHAPE.

The key is the sha256 of the canonical JSON of the request WITHOUT
`payload_excerpt` (Pitfall-1: payload values are deliberately excluded) and
WITHOUT `principles` (constitution_version + policy_version stand in for the
principle set). Documented tradeoff: a poisoned verdict can at most affect its
own shape and only ever RESTRICT or be neutral — the runner clamp means it can
never relax anything. Errors are never cached; `invalidate()` empties the cache
(the PIPE-06 invalidation hook for a constitution/policy reload)."""

from __future__ import annotations

import hashlib
import json
from collections import OrderedDict

from agentos_pipeline.interpreter.protocol import InterpretationRequest, InterpreterVerdict


def _key(request: InterpretationRequest) -> str:
    canonical = json.dumps(
        {
            "action_type": request.action_type,
            "target": request.target,
            "intent_class": request.intent_class,
            "guardrails": sorted(request.guardrails),
            "constitution_version": request.constitution_version,
            "policy_version": request.policy_version,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class CachedInterpreter:
    """Wraps any SemanticInterpreter with a bounded shape-keyed FIFO cache."""

    def __init__(self, inner, max_entries: int = 512) -> None:
        self.name = f"cached({inner.name})"
        self._inner = inner
        self._max_entries = max_entries
        self._entries: OrderedDict[str, InterpreterVerdict] = OrderedDict()

    async def interpret(self, request: InterpretationRequest) -> InterpreterVerdict:
        key = _key(request)
        hit = self._entries.get(key)
        if hit is not None:
            return hit
        verdict = await self._inner.interpret(request)  # exceptions propagate, uncached
        self._entries[key] = verdict
        if len(self._entries) > self._max_entries:
            self._entries.popitem(last=False)  # FIFO evict the oldest insertion
        return verdict

    def invalidate(self) -> None:
        self._entries.clear()
