# agentos-sdk

The data-plane Policy Enforcement Point (PEP) for `agentos-guard` (INT-01 / SDK-01).

`GovernanceMiddleware` is a LangChain v1 `AgentMiddleware` that intercepts every
governed tool call before it executes, normalizes it into a stable `AgentAction`,
asks the in-process pipeline (the PDP) for a `Decision`, and enforces it:

- **allow** → calls `handler(request)` so the tool runs;
- **deny** → returns a `ToolMessage` carrying the fired reasons **without** calling
  `handler`, so the tool never executes (no egress — the enforcement contract, D-03);
- **sandbox** → hands the action to the `SandboxRunner` seam, which **quarantines** it
  (RUN-03): `handler` is never called, the containment is recorded, and the hook returns
  the quarantine notice.

Every contained outcome is returned with `status="error"` on the `ToolMessage`, so a
consumer branching on LangChain's tool-failure convention can never read a block or a
quarantine as a completed call.

## Wiring the enforcement seams

The blocking/containment collaborators are structural Protocols the PEP is *given* — the
concrete implementations live in the control plane and are injected, so the SDK core still
depends only on `agentos-contract` + `agentos-pipeline` (PEP logic never leaks into the
PDP, Anti-Pattern 5; the pipeline owns the audit writer it was constructed with).

```python
from agentos_controlplane.coordinator import StoreApprovalCoordinator
from agentos_controlplane.sandbox import QuarantineSandbox
from agentos_sdk import GovernanceMiddleware

middleware = GovernanceMiddleware(
    pipeline,
    token,
    coordinator=StoreApprovalCoordinator(approvals, audit, posture),  # require_approval
    sandbox=QuarantineSandbox(session_factory, audit),                # sandbox (RUN-03)
)
```

**Both seams are required, not optional polish.** Unwired, their outcomes fail CLOSED:
without a `coordinator` an approval-needing action is denied instead of parked, and
without a `sandbox` runner every **mid-risk** action (`sandbox` is the default band above
`sandbox_at=0.4`, and low trust hardens `allow` into it) becomes a hard
`Blocked by agentos-guard` with no approval request and no containment record.

See `agentos_sdk.quickstart` for the runnable end-to-end wiring.
