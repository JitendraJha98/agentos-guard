"""Identity stage (pipeline stage 1) — IDN-02 / TRST-01.

Source: 01-RESEARCH.md § "Pipeline Composition" (the identity stage + short-circuit)
and § "Identity"; CONTEXT.md D-10/D-11.

`IdentityStage` is the thin pipeline-stage wrapper over the control plane's EdDSA
identity engine: it extracts `identity_token` and `agent_id` from the AgentAction
and delegates to `engine.verify(token, agent_id)`. The pipeline stage therefore sees
only the normalized AgentAction (Anti-Pattern 5: no PEP/registry detail leaks into
the PDP), and the verification result carries the 0–1 `trust_score` that feeds the
graduated stage (TRST-01).

The engine is injected and typed structurally (a `Protocol`), so this package keeps
its single internal dependency on `agentos-contract` and never imports the control
plane — the same toggle-seam discipline used for the PolicyEngine. The concrete
engine is `agentos_controlplane.identity_engine.IdentityEngine`; its result type
(`IdentityResult`) is duck-typed here via `IdentityVerdict`.
"""

from __future__ import annotations

import time
from typing import Callable, Protocol, runtime_checkable

from agentos_contract import AgentAction


@runtime_checkable
class IdentityVerdict(Protocol):
    """The shape stage 1 consumes from the engine (IdentityResult duck type)."""

    ok: bool
    detail: str
    trust_score: float


class IdentityEngineProtocol(Protocol):
    """The injected verification seam (the control-plane IdentityEngine satisfies it)."""

    def verify(self, token: str | None, claimed_agent_id: str) -> IdentityVerdict: ...


class IdentityStage:
    """Stage 1: verify the action's identity token and load its trust score."""

    def __init__(self, engine: IdentityEngineProtocol) -> None:
        self._engine = engine

    def verify(self, action: AgentAction) -> IdentityVerdict:
        """Delegate to the engine using the action's own token + claimed agent_id."""
        return self._engine.verify(action.identity_token, action.agent_id)


class CachingIdentityStage:
    """The PIPE-06 identity-verification cache: a bounded TTL dict over a wrapped
    `IdentityStage` (same `verify(action)` shape, so `Pipeline` accepts it
    transparently — wire it explicitly, never by default).

    Rules:
      - only SUCCESSFUL verdicts are cached; a failed verdict (forged/unknown
        token) is always re-verified — caching denials would let an attacker
        probe freely, and caching nothing on failure keeps the deny path exact;
      - entries expire after `ttl_seconds` (injectable `clock` for tests);
      - the dict is bounded at `max_entries` with FIFO eviction (dict order);
      - `invalidate()` clears everything; `invalidate(agent_id)` evicts one agent.

    STALENESS WINDOW: a cached verdict embeds the `trust_score` as of the LAST
    uncached verify — a trust demotion or agent deregistration is INVISIBLE to
    this cache for up to `ttl_seconds`. Deployments MUST call `invalidate()` (or
    `invalidate(agent_id)`) on trust mutations, deregistration, and every
    policy/constitution version change; the TTL alone only bounds the window.

    Whole-Decision caching is deliberately REJECTED (trust drifts between calls
    and every action must produce its own audit record); only the verification
    verdict — pure identity, no decision state — is cached here.
    """

    def __init__(
        self,
        stage: IdentityStage,
        *,
        ttl_seconds: float = 60.0,
        max_entries: int = 1024,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._stage = stage
        self._ttl = ttl_seconds
        self._max = max_entries
        self._clock = clock
        self._cache: dict[tuple[str | None, str], tuple[IdentityVerdict, float]] = {}

    def verify(self, action: AgentAction) -> IdentityVerdict:
        key = (action.identity_token, action.agent_id)
        now = self._clock()
        hit = self._cache.get(key)
        if hit is not None and hit[1] > now:
            return hit[0]
        verdict = self._stage.verify(action)
        if verdict.ok:
            if key not in self._cache and len(self._cache) >= self._max:
                self._cache.pop(next(iter(self._cache)))  # FIFO: evict oldest
            self._cache[key] = (verdict, now + self._ttl)
        else:
            self._cache.pop(key, None)  # never serve a stale ok after a failure
        return verdict

    def invalidate(self, agent_id: str | None = None) -> None:
        """Drop cached verdicts: ALL when `agent_id` is None (the policy/constitution
        version-change hook), else only that agent's entries (the trust-mutation /
        deregistration hook)."""
        if agent_id is None:
            self._cache.clear()
            return
        for key in [k for k in self._cache if k[1] == agent_id]:
            del self._cache[key]
