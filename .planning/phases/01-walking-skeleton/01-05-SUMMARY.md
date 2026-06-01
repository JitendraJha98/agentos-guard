---
phase: 01-walking-skeleton
plan: 05
subsystem: pipeline
tags: [pipeline, runner, identity-stage, graduated-response, floor-invariant, short-circuit, pipe-01, pipe-02, pipe-03, idn-02, trst-01, pol-06]

# Dependency graph
requires:
  - phase: 01-01
    provides: "agentos_contract (AgentAction, Decision, Outcome, Reason, RiskFinding, RiskScorer, PipelineProtocol) + the uv workspace + tests/conftest scaffold"
  - phase: 01-02
    provides: "agentos_controlplane IdentityEngine/IdentityResult (EdDSA verify + trust) and AuditWriter.append (hash-chained, fail-closed) — injected into the runner"
  - phase: 01-03
    provides: "agentos_pipeline.risk.assess_risk + PromptInjectionScorer (SEC-01 inline detector) — stage 3"
  - phase: 01-04
    provides: "agentos_pipeline.policy WasmPolicyEngine + PolicyResult (deterministic OPA WASM floor) — stage 2"
provides:
  - "agentos_pipeline.graduated.graduated_response(policy_outcome, risk_score, trust) -> Outcome — the floor-respecting stage-4 map (POL-06); deny is terminal (POL-05/TRST-02 invariant)"
  - "agentos_pipeline.identity.IdentityStage — stage-1 wrapper over the EdDSA engine (verify token + load trust), structurally typed so the pipeline keeps its single contract dependency (IDN-02/TRST-01)"
  - "agentos_pipeline.runner.Pipeline.evaluate(action) -> Decision — the async 4-stage PDP (PIPE-01/02/03); orders the stages, accumulates per-stage reasons, short-circuits on forged identity, awaits the audit write and sets evidence_ref before returning"
affects: [sdk-middleware, red-team-gate, e2e-vertical-slice]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Policy is the floor; risk/trust may only RESTRICT (graduated_response returns deny first on a policy deny — Pattern 2)"
    - "Stage-1 short-circuit: forged/unknown identity returns a terminal, audited deny WITHOUT running policy/risk/graduated (PIPE-03)"
    - "Async runner, sync CPU stages: only the audit write is awaited; no nested event loop (AI-SPEC §4b)"
    - "Structural-typing seam: identity engine, policy engine, and audit writer are injected via Protocols so agentos-pipeline never imports agentos-controlplane (same toggle discipline as PolicyEngine)"
    - "Every stage that runs contributes a machine-readable Reason — including identity on the success path (PIPE-02)"

key-files:
  created:
    - "packages/pipeline/src/agentos_pipeline/graduated.py"
    - "packages/pipeline/src/agentos_pipeline/identity.py"
    - "packages/pipeline/src/agentos_pipeline/runner.py"
    - "tests/unit/test_graduated.py"
    - "tests/unit/test_identity_shortcircuit.py"
    - "tests/unit/test_pipeline.py"
  modified: []

key-decisions:
  - "Added an identity Reason on the SUCCESS path (code 'identity_verified'), not only on the short-circuit — the plan's PIPE-02 acceptance criterion requires a stage entry for identity, policy, risk AND graduated on a valid action; the RESEARCH snippet only showed the short-circuit reason (deviation Rule 2)"
  - "IdentityStage delegates to an injected engine typed via a structural Protocol (IdentityEngineProtocol + IdentityVerdict duck type) so agentos-pipeline keeps its single internal dependency on agentos-contract and never imports the control plane"
  - "_host(action) uses urlsplit(...).hostname; a missing/unparseable URL yields an empty host -> the deny-by-default egress policy denies it (fail-closed, never silent allow)"
  - "Tests drive the async runner with asyncio.run(...) in sync test functions, matching the established convention in tests/integration/test_audit_chain.py (no pytest-asyncio in the env; anyio present but unused here)"

patterns-established:
  - "graduated_response: policy deny is terminal; on an allowed floor, risk>=0.7 -> deny, >=0.4 -> sandbox, else allow (POL-06; sandbox is vocabulary, D-13)"
  - "Pipeline short-circuit + audit-before-return on BOTH paths (evidence exists before enforcement)"
  - "Floor invariant proven by a parametrized (risk x trust) sweep marked @pytest.mark.floor_invariant"

requirements-completed: [PIPE-01, PIPE-02, PIPE-03, IDN-02, TRST-01, POL-06]

# Metrics
duration: 5min
completed: 2026-06-02
---

# Phase 1 Plan 05: The 4-Stage Decision Pipeline Summary

**The PDP assembled: `Pipeline.evaluate(action)` runs identity/trust → policy → risk → graduated synchronously into one `Decision` with per-stage machine-readable reasons, short-circuits a forged identity to a terminal audited deny, and `graduated_response` enforces the floor invariant — a policy `deny` is terminal and no (risk, trust) can ever upgrade it.**

## Performance

- **Duration:** ~5 min wall-clock
- **Completed:** 2026-06-02
- **Tasks:** 2 of 2 (both TDD: RED → GREEN, no refactor commit needed)
- **Files created:** 6 (3 source modules + 3 unit test files)

## Accomplishments

- **Task 1 — identity stage + floor-respecting graduated_response (POL-06/IDN-02/TRST-01):**
  - `graduated.py`: `graduated_response(policy_outcome, risk_score, trust)` returns `Outcome.deny` immediately if the policy denied (the FLOOR — nothing below upgrades it); on an allowed floor, `risk >= 0.7 → deny`, `>= 0.4 → sandbox`, else `allow`. `sandbox` is vocabulary only this phase (D-13).
  - `identity.py`: `IdentityStage.verify(action)` extracts `identity_token` + `agent_id` from the action and delegates to the injected EdDSA engine, surfacing the loaded `trust_score` (TRST-01). The engine and its result are typed via structural Protocols so the pipeline package never imports the control plane.
  - Tests: `test_graduated.py` (floor case + a 45-point `risk × trust` property sweep, all `@pytest.mark.floor_invariant`, plus the restrict/band/pass cases) and `test_identity_shortcircuit.py` (valid/forged/missing/mismatch/unregistered).
- **Task 2 — the 4-stage runner (PIPE-01/02/03):**
  - `runner.py`: `Pipeline` satisfies `PipelineProtocol` with `async def evaluate`. Stage 1 verifies identity → on `not ok` appends the identity Reason, builds a terminal `Decision(deny)`, `await`s the audit append to set `evidence_ref`, and RETURNS (no later stages). Else loads trust and records an `identity_verified` Reason. Stage 2 calls `policy.evaluate({"host","method","type"})`. Stage 3 calls `assess_risk(action, scorers)` (plain, CPU-bound). Stage 4 applies `graduated_response(pol.outcome, risk_score, trust)`. Builds the `Decision`, `await`s `audit.append`, sets `evidence_ref`, returns.
  - `_host(action)` parses the host from the `http_get` URL; missing/unparseable → empty host → deny-by-default (fail-closed).
  - Tests: `test_pipeline.py` proves ordering, per-stage reasons, the forged-identity short-circuit (policy + risk **call counts 0** via spies), `evidence_ref` set on **both** paths, the policy-deny floor end-to-end, high-risk restriction, and that trust feeds graduated and is stamped on the Decision.
- **Verification — all green:**
  - `pytest tests/unit/test_pipeline.py -x` → **8 passed**
  - `pytest tests/unit/test_identity_shortcircuit.py -x` → **5 passed**
  - `pytest tests/unit/test_graduated.py -m floor_invariant -x` → **46 passed, 3 deselected**
  - `grep -c "asyncio.run" runner.py` → **0**; `grep -v '^#' graduated.py | grep -c "Outcome.deny"` → **3** (first branch denies on a policy deny)
  - Full suite: **112 passed, 2 xfailed**, no regressions.

## Task Commits

1. **Task 1: identity stage + graduated_response (TDD)** — `4e01296` (test, RED) → `4ec43f9` (feat, GREEN)
2. **Task 2: the 4-stage pipeline runner (TDD)** — `8af7105` (test, RED) → `d1ebc86` (feat, GREEN)

**Plan metadata:** committed separately (docs: complete plan).

_Both TDD tasks produced the expected `test → feat` gate sequence; no refactor commit was needed (each GREEN implementation was already minimal)._

## Files Created

- `packages/pipeline/src/agentos_pipeline/graduated.py` — stage 4: the floor-respecting `{policy, risk, trust} → outcome` map (POL-06).
- `packages/pipeline/src/agentos_pipeline/identity.py` — stage 1: `IdentityStage` wrapper over the injected EdDSA engine, structurally typed (IDN-02/TRST-01).
- `packages/pipeline/src/agentos_pipeline/runner.py` — `Pipeline.evaluate`, the async 4-stage PDP (PIPE-01/02/03) with short-circuit + audit-before-return.
- `tests/unit/test_graduated.py` — floor invariant + property sweep (`floor_invariant`) + restrict/band/pass cases.
- `tests/unit/test_identity_shortcircuit.py` — IdentityStage verify behavior via the real EdDSA engine + in-memory SQLite registry.
- `tests/unit/test_pipeline.py` — the runner behavior cases using fakes/spies for the policy engine, scorer, and audit writer (no DB).

## Decisions Made

- **Identity Reason on the success path (deviation Rule 2 — see below).** The plan's PIPE-02 acceptance criterion requires the reasons of a valid action to include a stage entry for **identity, policy, risk, and graduated**. The RESEARCH composition snippet only appended an identity Reason on the short-circuit, so the success path would have been missing it. Added `Reason(stage="identity", code="identity_verified")` after a successful verify. This is placed AFTER the short-circuit return, so the forged-identity deny still produces exactly one (identity) reason.
- **Structural-typing seam, no control-plane import.** `IdentityStage` and `Pipeline` accept their collaborators (identity engine, policy engine, audit writer) injected and typed via `Protocol`s. `agentos-pipeline` keeps its single internal dependency on `agentos-contract` — the same toggle discipline already used for `PolicyEngine` in 01-04.
- **`_host` fail-closed.** A missing/unparseable URL yields `""`, which the deny-by-default egress policy denies — never a silent fail-open (Pitfall 3).
- **`asyncio.run` in sync tests.** Matches the established convention in `tests/integration/test_audit_chain.py`; no `pytest-asyncio` is installed and the runner is `async` only because the audit write is.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing critical functionality] Identity Reason added on the success path**
- **Found during:** Task 2 (the `test_valid_action_runs_all_four_stages_in_order` assertion that `reasons` covers all four stages).
- **Issue:** The RESEARCH `evaluate` snippet only appended an identity `Reason` on the forged-identity short-circuit, so a valid action's `Decision.reasons` omitted the `identity` stage — violating the plan's PIPE-02 behavior ("at least one Reason per stage that ran") and its acceptance criterion #3.
- **Fix:** After a successful `identity.verify`, append `Reason(stage="identity", code="identity_verified", detail=ident.detail)`. Placed after the short-circuit return so the deny path is unaffected (still exactly one identity reason).
- **Files modified:** `packages/pipeline/src/agentos_pipeline/runner.py`
- **Verification:** `test_pipeline.py` stages-set assertion `== {"identity","policy","risk","graduated"}` passes; the short-circuit test `[r.stage ...] == ["identity"]` still passes.
- **Committed in:** `d1ebc86` (Task 2 GREEN commit)

---

**Total deviations:** 1 auto-fixed (Rule 2). **Impact:** brings the success-path reasons into line with the plan's explicit PIPE-02 contract; no scope creep, no architectural change.

## Issues Encountered

- `opa-wasmtime` emits an `atexit` benchmark hook that raises a harmless `ValueError: min() iterable argument is empty` to stderr at interpreter shutdown when its evaluate path was never exercised in a run. It does **not** affect test results (all suites pass) and is unrelated to this plan's code — logged to `deferred-items.md` as a dependency-side quirk for the 01-04 policy owner / CI noise-filtering, not fixed here (out of scope).

## User Setup Required

None new this plan. The runner is wired entirely from already-installed workspace packages; the only external artifact it transitively relies on (`policies/build/egress.wasm`) is the 01-04 CI/build artifact, present locally and regenerated in CI.

## Next Phase Readiness

- **Ready for the red-team gate (01-06, D-04):** `Pipeline.evaluate` is the PDP the gate drives end-to-end. The egress allowlist is mutable via the policy engine's `set_data` without recompiling, so the `pipeline_without_principle` fixture can flip the exfil probe from deny→allow (the proof-of-life the CI gate asserts). The floor invariant is already locked by the `floor_invariant`-marked sweep.
- **Ready for the SDK PEP (SDK-01):** `evaluate` satisfies `PipelineProtocol`; `GovernanceMiddleware.wrap_tool_call` can construct one `Pipeline` (identity stage + WasmPolicyEngine + [PromptInjectionScorer] + AuditWriter) once at startup and `await` it inside the LangGraph loop, then enforce allow (run handler) / deny (return a blocking ToolMessage).
- **Construction recipe for the e2e slice:** `Pipeline(identity=IdentityStage(registry.identity), policy=WasmPolicyEngine(wasm_path, allowlist), scorers=[PromptInjectionScorer()], audit=AuditWriter(session_factory))`.

## Self-Check: PASSED

All six created files exist on disk (`graduated.py`, `identity.py`, `runner.py`, `test_graduated.py`, `test_identity_shortcircuit.py`, `test_pipeline.py`) and all four task commits exist in git (`4e01296`, `4ec43f9`, `8af7105`, `d1ebc86`).

---
*Phase: 01-walking-skeleton*
*Completed: 2026-06-02*
