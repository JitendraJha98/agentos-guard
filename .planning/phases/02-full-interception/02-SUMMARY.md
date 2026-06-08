# Phase 2 — Full Interception Coverage — SUMMARY

**Status:** Complete (2026-06-07)
**Requirements:** INT-02, INT-03, INT-04, INT-05, INT-06 (all P0)
**Depends on:** Phase 1 (Walking Skeleton)

## Goal

Thicken the Phase-1 loop so all five action types are governed — not just tool calls —
and prove there are no silently un-instrumented paths. The same stable contract
(`evaluate(AgentAction) -> Decision`) and the same 4-stage pipeline govern every type.

## What shipped

### INT-02 — Model invocation interception
- `GovernanceMiddleware.awrap_model_call` (LangChain v1 native hook) normalizes a
  `ModelRequest` into `AgentAction(type=model_invocation)`, evaluates it, and enforces:
  **allow** invokes the model; **deny** short-circuits — the provider is never called
  (no prompt egress) and an `AIMessage` carrying the fired reasons is returned.
- The prompt text is flattened into `payload["messages"]` so the SEC-01 risk stage
  scans model inputs for injection — proven by a test where injection in a model prompt
  is risk-scored and denied.

### INT-03/04/05 — Memory, MCP, delegation
- LangChain v1 has no middleware hooks for these boundaries, so the SDK governs them
  with thin async wrappers (`governed_memory_access`, `governed_mcp_call`,
  `governed_delegation`) in `agentos_sdk/wrappers.py`.
- All five interception forms share ONE enforcement core (`agentos_sdk/enforce.py`):
  `governed_call` evaluates the action and, on **deny**, raises `GovernanceDenied`
  (the governed exception carrying the `Decision`) WITHOUT running the operation — no
  memory write, no MCP egress, no sub-agent dispatch.
- **INT-05 lineage:** `normalize_delegation` requires `parent_action_id`; it is carried
  on `ActionContext` and persisted in the audit body alongside `conversation_id`
  (seed for the Phase-12 AUD-09 evidence graph).

### INT-06 — Interception-coverage check (no silent gaps)
- `agentos_sdk/coverage.py`: every normalizer registers the `ActionType` it covers via
  `@covers(...)` at import time, so the registry reflects reality. `verify_coverage()`
  raises `InterceptionGapError` if any `ActionType` lacks a path (static gap detection).
- **Bypass attempt (runtime):** an action reaching the pipeline with no valid identity
  (the signature of an un-instrumented / forged path) is denied by the fail-closed
  identity stage (IDN-02), not silently allowed — proven by `test_coverage.py`.

## Cross-cutting plumbing (required for "flows through the same pipeline")

- **Policy floor scoped to egress.** `policies/egress.rego` now states the egress
  principle governs `tool_call` egress only; model/memory/mcp/delegation pass this floor
  (their deterministic policies arrive in Phase 3). `tool_call` stays deny-by-default, so
  the Phase-1 D-04 red-team gate is unchanged. WASM rebuilt; `WasmPolicyEngine` reports a
  type-appropriate reason (`no_egress_policy_applicable`) instead of an egress claim it
  did not check. New `egress_test.rego` cases lock the non-tool behavior.
- **Audit redactor extended (AUD-04 / D-15 stays fail-closed).** Classifies each new
  payload shape: short identifiers kept verbatim, free-text/secret-bearing fields
  (`messages`, `value`, `args`, `task`) reduced to a length+SHA-256 digest. Unknown keys
  still fail closed (no record written).

## Verification

- Full suite: **150 passed, 2 xfailed** (the 2 are honest out-of-scope evasion xfails).
- Regression-lock gate: **10 passed** (Phase-1 red-team gate intact).
- Detector determinism (100×): **2700 passed** (non-flaky).
- Floor invariant: **46 passed** (risk/trust never relax the policy floor).
- New tests: `test_normalize_phase2`, `test_model_interception`, `test_governed_wrappers`,
  `test_coverage`, `test_audit_phase2_payloads`, `test_all_action_types_e2e` (all five
  types share one continuous hash chain; delegation lineage persisted).

## Notes / deferred (correctly out of Phase 2 scope)

- Real per-type **policies** for model/memory/mcp/delegation → Phase 3 (Constitution).
- `sandbox`/`warn`/approval **enforcement** of graduated outcomes → Phase 3.
- Production framework attach via `create_agent(..., middleware=[GovernanceMiddleware])`
  is the documented integration point; the wrappers are the decorator surface for the
  three non-native boundaries.
