"""StoreApprovalCoordinator — the concrete SDK ApprovalCoordinator (POL-07/POL-14).

Parks the redacted approval request, block-awaits the PERSISTED row via
`ApprovalStore.wait_resolved` (D3 — never an in-process future; see the
approvals module docstring for why), opens non-blocking reviews, and writes
`enforcement_substitution` events for outcomes escalated onto the approval path.

Timeout semantics (POL-07): an unresolved deadline resolves to the per-action-
class posture default — fail-closed classes deny (`approval_timeout` reason on
the surfaced decision); an explicitly fail-open class proceeds. The store marks
the row `timed_out` and audits `approval_timed_out` either way.

`posture` is typed structurally (`fail_posture(action_type) -> {value: str}`)
so this package needs no agentos-pipeline import — the same structural-seam
discipline as the pipeline's injected collaborators.
"""

from __future__ import annotations

from typing import Protocol

from agentos_contract import ActionType, AgentAction, Decision, Reason

from agentos_controlplane.approvals import ApprovalStore
from agentos_controlplane.audit import AuditWriter


class _Posture(Protocol):
    """Structurally the pipeline's PostureMap (fail_posture -> FailPosture)."""

    def fail_posture(self, t: ActionType) -> object: ...


class StoreApprovalCoordinator:
    """Implements the SDK's ApprovalCoordinator Protocol over the ApprovalStore."""

    def __init__(
        self,
        store: ApprovalStore,
        audit: AuditWriter,
        posture: _Posture,
        *,
        deadline_s: float = 300.0,
        poll_s: float = 0.2,
    ) -> None:
        self._store = store
        self._audit = audit
        self._posture = posture
        self._deadline_s = deadline_s
        self._poll_s = poll_s

    async def park_and_wait(self, action: AgentAction, decision: Decision) -> bool:
        """Park (context redacted fail-closed) + block on the persisted row.

        Returns True iff the action may run: an operator approved, or the
        deadline passed on an explicitly fail-OPEN class.
        """
        approval_id = self._store.create(action, decision, deadline_s=self._deadline_s)
        row = await self._store.wait_resolved(
            approval_id, self._deadline_s, poll_s=self._poll_s
        )
        if row is None:  # timed out (row marked + audited by the store)
            decision.reasons.append(Reason(stage="enforcement", code="approval_timeout"))
            return getattr(self._posture.fail_posture(action.type), "value", "") == "open"
        return row.status == "approved"

    async def open_review(self, action: AgentAction, decision: Decision) -> None:
        """Open the async NON-blocking review row (+ `review_opened` event)."""
        await self._store.open_review(
            action.id,
            action.agent_id,
            summary=f"{action.type.value}:{action.target}"[:200],
        )

    async def record_substitution(
        self, action: AgentAction, decision: Decision, *, requested: str, substituted: str
    ) -> None:
        """Audit an outcome whose enforcement was escalated onto the approval path."""
        await self._audit.append_event(
            "enforcement_substitution",
            {
                "action_id": str(action.id),
                "agent_id": action.agent_id,
                "requested": requested,
                "substituted": substituted,
            },
        )
