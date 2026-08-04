"""RUN-03 — the concrete SandboxRunner: QUARANTINE.

`governed_call` routes a `sandbox` outcome HERE instead of the real handler, so by
construction no side effect and no egress occur — there is nothing to stub, because
nothing runs. This runner records the observation (a `sandbox_run` row) and audits
`sandbox_executed`, then returns the `SandboxResult` the enforcement core raises as
`GovernanceQuarantined`.

`SandboxResult` comes from `agentos_contract`, not the SDK: `agentos-sdk` already
depends on `agentos-controlplane`, so importing the SDK here would be a package cycle.

Honest scope: this is PEP-level quarantine (see docs/architecture/05 — "the SDK shim can
intercept and stub side-effectful tools"). Kernel/network isolation is the gateway/sidecar
(Phase 10) and K8s (Phase 14) layer.
"""

from __future__ import annotations

from uuid import uuid4

from agentos_contract import AgentAction, Decision, SandboxResult

from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.store.models import SandboxRun


class QuarantineSandbox:
    """Satisfies the SDK's `SandboxRunner` Protocol structurally (no inheritance)."""

    def __init__(self, session_factory, audit: AuditWriter) -> None:
        self._session_factory = session_factory
        self._audit = audit

    async def run(self, action: AgentAction, decision: Decision) -> SandboxResult:
        run_id = uuid4()
        # A short, redacted summary only — the payload VALUES are never copied here.
        detail = (
            f"quarantined {action.type.value} on {action.target}; "
            f"{len(action.payload)} payload field(s); handler not invoked"
        )
        with self._session_factory() as session:
            session.add(
                SandboxRun(
                    id=run_id,
                    action_id=action.id,
                    agent_id=action.agent_id,
                    action_type=action.type.value,
                    target=action.target,
                    quarantined=True,
                    detail=detail,
                )
            )
            session.commit()
        # Short identifiers only (AUD-04 secret-gate safety): the free-text detail stays
        # in the table, so the gate can never refuse — and thereby block — containment.
        await self._audit.append_event(
            "sandbox_executed",
            {
                "action_id": str(action.id),
                "agent_id": action.agent_id,
                "action_type": action.type.value,
                "run_id": str(run_id),
                "outcome": decision.outcome.value,
            },
        )
        return SandboxResult(
            quarantined=True,
            run_id=str(run_id),
            detail="side effects quarantined; handler not invoked",
        )
