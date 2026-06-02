"""PipelineProtocol — the one stable PEP<->PDP seam (PIPE-07 / D-08).

Source: docs/architecture/03 + ARCHITECTURE.md Pattern 1. Defining
evaluate(AgentAction) -> Decision once is what makes the Phase-10 gateway and
Phase-14 sidecar additive rather than rewrites. Protocol only — no implementation.
"""

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from agentos_contract.action import AgentAction
    from agentos_contract.decision import Decision


class PipelineProtocol(Protocol):
    def evaluate(self, action: "AgentAction") -> "Decision": ...
