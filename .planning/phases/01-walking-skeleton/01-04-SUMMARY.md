---
phase: 01-walking-skeleton
plan: 04
subsystem: policy
tags: [opa, rego, wasm, opa-wasmtime, wasmtime, policy-engine, egress-allowlist]

# Dependency graph
requires:
  - phase: 01-01
    provides: "agentos_contract (Outcome enum) + the uv workspace + pipeline package + tests/conftest scaffold"
provides:
  - "policies/egress.rego — the single Phase-1 Constitution principle (egress allowlist, deny-by-default), authored directly as Rego (D-02)"
  - "policies/egress_test.rego — deterministic opa-test coverage (allowlisted allowed, attacker denied)"
  - "agentos_pipeline.policy: PolicyEngine Protocol + PolicyResult + WasmPolicyEngine (in-process OPA WASM floor, loaded once at construction)"
  - "Locked opa-wasmtime>=0.1.1,<0.2 + wasmtime>=27 (human-verified; no wasmer in the resolution)"
  - "policies/build/egress.wasm build recipe: opa build -t wasm -e 'agentos/egress/allow' policies/egress.rego (CI/build artifact, D-06)"
affects: [pipeline-runner, sdk-middleware, red-team-gate, ci-wasm-build]

# Tech tracking
tech-stack:
  added: ["opa-wasmtime 0.1.1", "wasmtime 45.0.0", "OPA CLI v1.17.0 (pinned binary, gitignored)"]
  patterns:
    - "PolicyEngine Protocol as the toggle seam — OPA-server is a future one-file swap, not a rewrite (D-05)"
    - "Compile-on-build WASM + load-once at construction (Pitfall 2): OPAPolicy constructed exactly once in __init__, never per request"
    - "Principle stays in Rego; concrete hosts injected as a Rego `data` document via set_data (allowlist is configuration)"
    - "Policy fails closed: an unexpected OPA result shape maps to deny, never silent allow (Pitfall 3)"

key-files:
  created:
    - "policies/egress.rego"
    - "policies/egress_test.rego"
    - "policies/build/.gitkeep"
    - "packages/pipeline/src/agentos_pipeline/policy.py"
    - "tests/unit/test_policy_engine.py"
  modified:
    - "packages/pipeline/pyproject.toml"
    - "uv.lock"
    - ".gitignore"

key-decisions:
  - "opa-wasmtime locked after human-verify (the locked opa-wasm is Python-3.12-incompatible via its stale wasmer dep); <0.2 cap given the package's youth"
  - "evaluate() returns the OPA result set as [{'result': <bool>}]; the engine extracts result[0]['result'] (the agentos/egress/allow entrypoint is index 0)"
  - "Compiled egress.wasm is a gitignored CI/build artifact (D-06); only the Rego sources + build/.gitkeep are committed"
  - "Allowlist supplied as a Rego data document (set_data) so the red-team test can mutate hosts without recompiling the WASM"

patterns-established:
  - "PolicyEngine Protocol (runtime_checkable) as the deterministic-floor seam (POL-03/D-05)"
  - "Load-once OPA WASM construction (Pitfall 2) asserted by a load-count probe test"
  - "Fail-closed policy mapping (unexpected result -> deny)"

requirements-completed: [POL-03]

# Metrics
duration: 18min
completed: 2026-06-02
---

# Phase 1 Plan 04: Deterministic OPA WASM Policy Floor Summary

**The egress-allowlist Constitution principle as a Rego module compiled to WASM, wrapped by `WasmPolicyEngine` (opa-wasmtime, loaded once at construction) behind a `PolicyEngine` Protocol — allow for an allowlisted host, terminal deny for an attacker host.**

## Performance

- **Duration:** ~18 min (continuation session, post-checkpoint)
- **Completed:** 2026-06-02
- **Tasks:** 2 of 2 post-checkpoint (Task 2, Task 3; Task 1 was the human-verify checkpoint, approved)
- **Files created/modified:** 8 (this session) + the pre-checkpoint smoke script

## Accomplishments

- **Task 2 — the principle in Rego (D-02/POL-03):** `policies/egress.rego` authored directly as Rego with `default allow := false` (deny-by-default floor, T-01-13) and `allow if { input.type == "tool_call"; input.host in data.allowlist }`. `policies/egress_test.rego` covers both directions; `tools/opa/opa.exe test policies/` passes **2/2** (`test_allowlisted_host_allowed`, `test_attacker_host_denied`).
- **WASM build recipe (D-06):** compiled with the pinned OPA CLI v1.17.0 — `opa build -t wasm -e 'agentos/egress/allow' policies/egress.rego -o bundle.tar.gz`, extract `policy.wasm` → `policies/build/egress.wasm` (a gitignored CI/build artifact; `build/.gitkeep` keeps the directory).
- **Task 3 — the engine (POL-03/D-05):** `agentos_pipeline.policy` ships the `PolicyEngine` Protocol (runtime_checkable, the OPA-server toggle seam), the `PolicyResult` dataclass, and `WasmPolicyEngine` — `OPAPolicy` constructed **once** in `__init__` with `set_data({"allowlist": ...})`, `evaluate()` extracting `result[0]["result"]` and mapping allow→`egress_allowlisted` / deny→`egress_allowlist_violation` (`policy_id="egress.allow"`). Unexpected result shape fails closed.
- **Dependency locked:** `opa-wasmtime>=0.1.1,<0.2` + `wasmtime>=27` added to the pipeline package and `uv.lock` (resolving to 0.1.1 / 45.0.0). Verified **no `wasmer`** in the resolution.
- **Tests:** `pytest tests/unit/test_policy_engine.py` → **4/4 pass** (allow, deny, load-once probe, Protocol isinstance). Full suite: **50 passed, 2 xfailed**, no regressions.

## Task Commits

1. **Task 1: Human-verify opa-wasmtime (checkpoint)** — `79b4024` (chore, pre-checkpoint smoke script; APPROVED by human: "approved — lock opa-wasmtime")
2. **Task 2: Egress Rego principle + opa tests** — `e3359b5` (feat)
3. **Task 3: WasmPolicyEngine (TDD)** — `4a6eae5` (test, RED) → `71e514a` (feat, GREEN)

**Plan metadata:** committed separately (docs: complete plan).

_TDD task 3 produced the expected test → feat gate sequence; no refactor commit was needed (the GREEN implementation was already minimal)._

## Files Created/Modified

- `policies/egress.rego` — the single Phase-1 principle: deny-by-default, allow iff `input.host in data.allowlist` for a `tool_call` (D-02).
- `policies/egress_test.rego` — deterministic `opa test` coverage (allowlisted allowed, attacker denied) using `with data.allowlist as [...]`.
- `policies/build/.gitkeep` — stable output path for the compiled WASM (artifact gitignored, D-06).
- `packages/pipeline/src/agentos_pipeline/policy.py` — `PolicyEngine` Protocol, `PolicyResult`, `WasmPolicyEngine` (load-once, fail-closed).
- `tests/unit/test_policy_engine.py` — the four behavior tests (skips cleanly if `egress.wasm` is absent).
- `packages/pipeline/pyproject.toml`, `uv.lock` — locked opa-wasmtime + wasmtime.
- `.gitignore` — ignore the compiled `.wasm`/`bundle.tar.gz`; re-include `policies/build/.gitkeep` (the generic `build/` rule would otherwise hide the dir).

## Decisions Made

- **opa-wasmtime locked (`<0.2` cap)** after the Task-1 human-verify approval — the originally locked `opa-wasm` is Python-3.12-incompatible (stale `wasmer` dep with no modern wheels). The `<0.2` cap is deliberate given the package's youth (single maintainer, low traffic).
- **Result shape `[{"result": <bool>}]`** (recorded at the checkpoint): `evaluate()` returns a list, the `agentos/egress/allow` entrypoint is index 0, so `_extract_bool` reads `result[0]["result"]`.
- **WASM is a build artifact, not committed (D-06)** — only the Rego sources + `build/.gitkeep` are tracked; CI regenerates `egress.wasm`.
- **Allowlist as Rego `data`** (Claude's discretion per CONTEXT D-05 note) — keeps the rule logic in Rego while letting the host list be configuration, and lets the red-team test mutate the allowlist without recompiling.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Re-included `policies/build/.gitkeep` past the generic `build/` gitignore rule**
- **Found during:** Task 2 (staging the policy artifacts)
- **Issue:** The repo's standard Python `.gitignore` has a generic `build/` rule (line 11, distribution/packaging) that also matched `policies/build/`, blocking `git add policies/build/.gitkeep`. The plan requires `policies/build/` to exist in the tree.
- **Fix:** Added `!policies/build/` + `!policies/build/.gitkeep` negations alongside the WASM-artifact ignore lines, then confirmed `.gitkeep` is tracked and `egress.wasm` stays ignored.
- **Files modified:** `.gitignore`
- **Verification:** `git check-ignore policies/build/.gitkeep` → exit 1 (not ignored); `git check-ignore policies/build/egress.wasm` → exit 0 (ignored).
- **Committed in:** `e3359b5` (Task 2 commit)

---

**Total deviations:** 1 auto-fixed (1 blocking).
**Impact on plan:** A mechanical gitignore-precedence fix required to track the build directory as the plan specifies. No scope creep; no logic change.

## Issues Encountered

- `opa-wasmtime` prints its own benchmark stats to stdout during `evaluate()`/`set_data`, which truncated the visible pytest tail. Re-ran with a filtered summary to confirm `4 passed`. No code impact.

## User Setup Required

None new this plan. The pinned OPA CLI (`tools/opa/opa.exe`, v1.17.0) was installed and SHA-verified during the Task-1 checkpoint and is gitignored; CI must download the same pinned release to run `opa build`/`opa test`.

## Next Phase Readiness

- **Ready for the pipeline runner (01-05/01-06):** `WasmPolicyEngine` is the deterministic Stage-2 floor behind `PolicyEngine`; the runner can construct it once at startup and call `evaluate({"host","method","type"})`.
- **Ready for the red-team gate (D-04):** the allowlist is mutable via `set_data` without recompiling, and `default allow := false` means deleting the `allow` rule flips the attacker probe from deny→allow (the proof-of-life the CI gate will assert).
- **CI todo (D-06):** wire `opa build -t wasm -e 'agentos/egress/allow' policies/egress.rego` + `opa test policies/` into the wave-merge CI so `policies/build/egress.wasm` exists before `tests/unit/test_policy_engine.py` runs (the test skips cleanly if absent).

## Self-Check: PASSED

All created files exist on disk (`policies/egress.rego`, `egress_test.rego`, `build/.gitkeep`, `build/egress.wasm`, `policy.py`, `test_policy_engine.py`, this SUMMARY) and all task commits exist in git (`e3359b5`, `4a6eae5`, `71e514a`).

---
*Phase: 01-walking-skeleton*
*Completed: 2026-06-02*
