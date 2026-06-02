# agentos-sdk

The data-plane Policy Enforcement Point (PEP) for `agentos-guard` (INT-01 / SDK-01).

`GovernanceMiddleware` is a LangChain v1 `AgentMiddleware` that intercepts every
governed tool call before it executes, normalizes it into a stable `AgentAction`,
asks the in-process pipeline (the PDP) for a `Decision`, and enforces it:

- **allow** → calls `handler(request)` so the tool runs;
- **deny** → returns a `ToolMessage` carrying the fired reasons **without** calling
  `handler`, so the tool never executes (no egress — the enforcement contract, D-03).

It depends ONLY on `agentos-contract` and `agentos-pipeline`; PEP logic never leaks
into the PDP (Anti-Pattern 5). The pipeline owns the audit writer it was constructed
with — the SDK does not touch the control plane.
