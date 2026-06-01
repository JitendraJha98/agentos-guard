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

from typing import Protocol, runtime_checkable

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
