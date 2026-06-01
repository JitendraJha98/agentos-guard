---
phase: 01-walking-skeleton
verified: 2026-06-02T00:00:00Z
status: passed
score: 4/4 roadmap success criteria verified (13/13 requirement IDs accounted for; the D-06 CI-WASM-build gap was closed inline post-verification — see resolution)
mode: mvp
overrides_applied: 0
resolution:
  - gap: "D-06 CI WASM build (SC-4) — ci.yml never ran `opa build -t wasm`, so a clean CI checkout errored at fixture construction."
    resolved: 2026-06-02
    fix: >
      Added a 'Build egress policy WASM (D-06)' step to .github/workflows/ci.yml that runs
      `opa build -t wasm -e 'agentos/egress/allow' policies/egress.rego`, extracts policy.wasm
      to policies/build/egress.wasm, BEFORE the Pytest / Regression-lock steps.
      Mechanically verified by simulating a clean checkout: removed the local WASM, ran the
      exact CI build sequence (rebuilt egress.wasm, 134 KB), then `uv run pytest -m regression_lock`
      → 10 passed, e2e → 3 passed, full suite → 124 passed / 2 xfailed. The D-04 "delete the
      principle → CI fails" criterion is now genuinely enforced in CI.
gaps:
  - truth: "A pytest red-team test asserts the agent denies a known prompt-injection attack, and removing the Constitution principle makes that test FAIL THE CI BUILD (SC-4 / D-04 / D-06)."
    status: resolved
    reason: >
      The regression-lock mechanism is correctly designed and PASSES LOCALLY (the source of
      truth): test_exfil_injection_is_denied (deny WITH the real OPA WASM principle) and
      test_deleting_principle_makes_attack_pass (allow WITHOUT it) both pass, and the
      detector is deterministic over 100 runs. BUT the CI half is not wired: the compiled
      egress.wasm is gitignored (policies/build/*.wasm), and .github/workflows/ci.yml installs
      the OPA CLI and runs `opa test policies/` only — it NEVER runs `opa build -t wasm` to
      regenerate policies/build/egress.wasm. In a clean CI checkout the WASM is absent, so the
      `pipeline_with_principle` fixture errors at construction (OPAPolicy raises
      "Path: policies/build/egress.wasm is not a valid file"), making the regression_lock gate
      ERROR (exit 1) for the WRONG reason — verified empirically by removing the WASM and
      running `uv run pytest -m regression_lock --maxfail=1` (1 error, exit 1). Consequently
      "deleting the principle makes the test fail CI" is not actually exercised in CI, and
      plan 01-04's must-have truth "D-06 (the WASM build is wired into CI)" is unmet. Both the
      01-04 SUMMARY ("CI todo (D-06): wire `opa build -t wasm` ...") and the 01-06 SUMMARY
      ("regenerated in CI") acknowledge/assume a CI build step that does not exist in ci.yml.
    artifacts:
      - path: ".github/workflows/ci.yml"
        issue: >
          Missing the `opa build -t wasm -e 'agentos/egress/allow' policies/egress.rego`
          (extract policy.wasm -> policies/build/egress.wasm) step before the Pytest /
          Regression-lock gate steps. egress.wasm is gitignored, so without this step the
          WASM-backed tests (test_e2e_slice.py, test_exfil_injection.py::test_exfil_injection_is_denied,
          test_policy_engine.py) either ERROR or SKIP in CI.
      - path: "policies/build/egress.wasm"
        issue: >
          Gitignored CI/build artifact that is never produced by CI. The conftest
          `pipeline_with_principle` fixture loads it unconditionally (no skip guard), so its
          absence is a hard fixture error rather than a clean skip.
    missing:
      - "Add an `opa build -t wasm -e 'agentos/egress/allow' policies/egress.rego -o bundle.tar.gz` step to .github/workflows/ci.yml (extract policy.wasm -> policies/build/egress.wasm) BEFORE the Pytest and Regression-lock gate steps, so the WASM-backed e2e + red-team tests run in CI."
      - "Optionally, also assert in CI that deleting the egress `allow if` rule and rebuilding the WASM flips test_exfil_injection_is_denied to RED (the literal D-04 done-criterion), or document that the structural `_AllowAllPolicyEngine` model is the accepted proxy and add a CI smoke that rebuilds the WASM from current egress.rego."
deferred:
  - truth: "Real-Postgres concurrency / advisory-lock serialization / append-only-trigger validation of the audit chain (WR-01, WR-02)."
    addressed_in: "Phase 4"
    evidence: "01-CONTEXT.md D-14 Deviation Log: 'Phase 4 (audit hardening) ... MUST re-validate the chain against real Postgres'. AUD-02..05 mapped to Phase 4 in REQUIREMENTS.md."
  - truth: "Per-action-class fail-posture config; deterministic policy-error -> deny wrapping (WR-05); redaction-failure-on-deny audit record (WR-04)."
    addressed_in: "Phase 3"
    evidence: "PIPE-05 (fail-closed vs fail-open per action class) mapped to Phase 3 in REQUIREMENTS.md; 01-CONTEXT.md defers per-action-class fail-posture to Phase 3."
  - truth: "Detector inspects post-fetch retrieved content end-to-end (WR-03)."
    addressed_in: "Phase 2"
    evidence: "01-CONTEXT.md defers other interception types + content surfaces to Phase 2 (INT-02..06); Phase-1 detector is scoped to URL/argument inspection at PEP-interception time."
---

# Phase 1: Walking Skeleton Verification Report

**Phase Goal:** Prove the entire decision loop end-to-end on a single vertical slice — one LangGraph agent, one governed `http_get` tool, one Constitution principle ("only allowlisted hosts") — with every pipeline stage real (identity/trust → policy via opa-wasm → risk via SEC-01 detector → graduated response) producing one `Decision`; an allowed action runs the tool and appends one hash-chained `AuditRecord`; a denied action raises/returns a governed block; and a red-team pytest test denies a known prompt-injection and FAILS CI if the Constitution principle is removed.

**Verified:** 2026-06-02
**Status:** gaps_found
**Re-verification:** No — initial verification
**Mode:** mvp (the goal is a vertical-slice statement with 4 explicit, observable success criteria; `user-story.validate` returns `false` because the goal is not in strict "As a … I want … so that …" form. Per the explicit verification instruction I verified against the 4 success criteria rather than refusing — see "MVP-Mode Note" below.)

## MVP-Mode Note

`gsd-sdk roadmap.get-phase 1 --pick mode` = `mvp`, but the goal is an engineering vertical-slice statement, not a `As a [role], I want [capability], so that [outcome]` user story (`user-story.validate` = `false`). Strict MVP framing would refuse and route to `/gsd mvp-phase`. The verification prompt explicitly instructed me to verify the must_haves + 13 requirement IDs and produce VERIFICATION.md, and the 4 roadmap success criteria are concrete and observable, so I proceeded with goal-backward verification mapped to those criteria (treated as the user-flow steps below). **WARNING (non-blocking): the phase goal is not in User Story format for an `mode: mvp` phase.** Recommend reformatting via `/gsd mvp-phase 1` for consistency, or removing the `mvp` mode tag for an infrastructure walking-skeleton phase.

## User Flow Coverage (the vertical slice, end-to-end)

The "user" here is the governed LangGraph agent + the operator's CI. Each step maps to a roadmap success criterion; evidence is real code + tests RUN locally (the designated source of truth: `uv run pytest -q` = 124 passed, 2 xfailed; `opa test policies/` = 2/2; `pytest -m regression_lock` = 2 passed; determinism ×100 = 2700 passed).

| Step | Expected | Evidence | Status |
|------|----------|----------|--------|
| 1. Intercept + normalize (SC-1) | A LangGraph governed tool call is intercepted before execution and normalized into a serializable `AgentAction` via the stable `contract` package | `sdk/middleware.py:50-60` `GovernanceMiddleware.awrap_tool_call` → `normalize_action`; `contract/action.py` `AgentAction` (`extra="forbid"`, JSON round-trip); `test_e2e_slice.py`, `test_middleware.py`, `test_contract.py` all green | ✓ VERIFIED |
| 2. 4 real stages → one Decision + reasons; forged identity short-circuits (SC-2) | identity/trust → policy(OPA WASM) → risk(SEC-01) → graduated produces one `Decision` with per-stage machine-readable reasons; forged identity → terminal deny without running later stages | `pipeline/runner.py:76-126` (ordered stages, reason accumulation, terminal deny on `not ident.ok` BEFORE policy/risk/graduated, still audited); `test_pipeline.py::test_forged_identity_short_circuits_without_later_stages` proves `pol.calls==0`, `scorer.calls==0`; `test_valid_action_runs_all_four_stages_in_order` proves `reasons` stages == {identity,policy,risk,graduated} | ✓ VERIFIED |
| 3. Allow runs tool + 1 hash-chained AuditRecord; deny is a governed block (SC-3) | An allowed action runs the tool and appends one hash-chained `AuditRecord`; a denied action returns a governed block carrying the fired reasons | `middleware.py:54-60` deny → `ToolMessage` WITHOUT calling `handler` (no egress); `runner.py:91,125` audit append on both paths; `test_e2e_slice.py` (allow: `handler.calls==1`, 1 audit row; deny: `handler.calls==0`, `egress_allowlist_violation`; chain `rows[1].prev_hash==rows[0].record_hash`); `test_audit_chain.py` (seq 0→1, genesis NULL, recomputed canonical-JSON hash, fail-closed, CR-01 credential-strip) | ✓ VERIFIED |
| 4. Red-team denies injection AND removing the principle FAILS CI (SC-4 / D-04 / D-06) | A pytest red-team test denies a known prompt-injection; removing the Constitution principle makes that test FAIL THE CI BUILD | LOCAL mechanism VERIFIED (`test_exfil_injection.py` 2 passed; deterministic; real WASM WITH-principle deny). CI WIRING FAILED — `ci.yml` never runs `opa build -t wasm`; gitignored `egress.wasm` absent in clean CI → regression_lock gate ERRORs at fixture construction (verified empirically). D-06 ("WASM build wired into CI") unmet. | ✗ PARTIAL (BLOCKER) |
| Outcome | "Prove the loop end-to-end with a CI-enforced red-team gate" | Loop proven end-to-end locally on every real stage; the CI-enforcement half of the red-team gate is not wired (Step 4) | ⚠️ Loop proven; CI gate not enforced |

**Score:** 3/4 roadmap success criteria fully verified; SC-4 PARTIAL (local pass, CI not wired).

## Goal Achievement — Observable Truths (per-plan must_haves)

| # | Truth (source plan) | Status | Evidence |
|---|---------------------|--------|----------|
| 1 | AgentAction/Decision JSON round-trip; reject unknown fields; RiskFinding rejects raw payload (01-01) | ✓ VERIFIED | `test_contract.py` green; `risk.py` `_no_raw_payload` field_validator (rejects `http`/>64-char in `matched`); `extra="forbid"` on both models |
| 2 | uv workspace builds; contract imports with zero internal deps (01-01) | ✓ VERIFIED | `uv sync` clean; 4 package members; `contract/pyproject.toml` depends only on pydantic; `import agentos_contract` works |
| 3 | Agent self-registers; verifiable EdDSA JWT; tampered/wrong-issuer/unregistered → fail (01-02, IDN-01) | ✓ VERIFIED | `identity_engine.py` `algorithms=["EdDSA"]` explicit (no header-derived alg); `test_identity.py` + `test_identity_shortcircuit.py` green (tamper, wrong-key, sub-mismatch, unregistered all → ok=False) |
| 4 | Each Decision appends one AuditRecord; monotonic seq; prev_hash links; canonical-JSON hash; fail-closed redaction (01-02, AUD-01) | ✓ VERIFIED | `audit.py` (sha256 over `canonical_json` with `sort_keys=True`, asyncio.Lock serial chain, `_redact_or_raise` fail-closed); `test_audit_chain.py`: seq 0→1, genesis NULL, recomputed hash matches, unclassifiable payload writes 0 records, no secret/url leak |
| 5 | Audit runs through pluggable Store on SQLite (Postgres models retained, not exercised — no Docker) (01-02, D-14) | ✓ VERIFIED (approved deviation) | `store/models.py` dialect-agnostic generic types; `store/engine.py` `create_all`/`create_session_factory`; tests use `sqlite+pysqlite:///:memory:`; no `testcontainers`/Docker import anywhere. APPROVED per 01-CONTEXT.md D-14 + Deviation Log. |
| 6 | SEC-01 detector fires on each probe class; benign < 0.4; obfuscation-resistant; deterministic ×100; pure CPU, no network/model, 32 KB cap (01-03) | ✓ VERIFIED | `prompt_injection.py` imports only `re`+contract+normalize; class-level compiled bounded-quantifier regex (ReDoS-safe); `normalize.py` NFKC + zero-width strip + base64; `test_detector_recall.py --count=100` = 2700 passed; 2 documented xfail known-gaps (typoglycemia, sharded exfil — deferred to Phase 3) |
| 7 | Egress principle authored as Rego, compiles to WASM; WasmPolicyEngine loads once, allow/deny; opa test passes; D-05/D-06 (01-04, POL-03) | ⚠️ PARTIAL | `egress.rego` (`default allow := false`; `allow if input.host in data.allowlist`); `policy.py` loads OPAPolicy once at `__init__` (Pitfall 2); `opa test policies/` = 2/2; CR-02 case-normalization fixed (`[h.strip().lower() ...]`) + regression test. **D-06 FAILS: WASM build NOT wired into CI** (see gap). |
| 8 | 4-stage synchronous pipeline → one Decision; every stage contributes reasons; forged identity short-circuits + audited; trust feeds graduated (01-05, PIPE-01/02/03, IDN-02, TRST-01) | ✓ VERIFIED | `runner.py` ordered async evaluate; `test_pipeline.py` proves ordering, short-circuit (later stages skipped), evidence_ref on both paths, trust stamped |
| 9 | graduated_response never upgrades past policy deny (floor invariant) (01-05, POL-06, TRST-02 seed) | ✓ VERIFIED | `graduated.py:38-39` `if policy_outcome == deny: return deny` FIRST; `pytest -m floor_invariant` = 46 passed; `test_policy_deny_floor_holds_end_to_end_regardless_of_risk_trust` |
| 10 | LangGraph http_get intercepted + normalized; allow calls handler, deny does NOT (no egress); e2e allow+audit / attacker blocked (01-06, INT-01/SDK-01) | ✓ VERIFIED | `middleware.py` deny → ToolMessage without `handler`; `test_e2e_slice.py` + `test_middleware.py` green (handler.calls 1 vs 0) |
| 11 | Exfil probe denied WITH principle; deleting principle flips to allow and regression_lock fails CI (01-06, D-04) | ⚠️ PARTIAL | LOCAL: `test_exfil_injection.py` 2 passed (real WASM deny WITH; allow-all WITHOUT). CI: regression_lock gate would ERROR (WASM absent, not rebuilt) — the "fails CI on principle removal" property is not wired into CI. See gap. |

## Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `packages/contract/src/agentos_contract/{action,decision,risk,pipeline}.py` | Stable serializable contract (PIPE-07) | ✓ VERIFIED | Exist, substantive, imported by pipeline/sdk/controlplane; `extra="forbid"`, frozen RiskFinding, no-raw-payload validator |
| `packages/controlplane/.../identity_engine.py` | EdDSA issue/verify (IDN-01) | ✓ VERIFIED | Explicit `algorithms=["EdDSA"]`; wired into IdentityStage + registry |
| `packages/controlplane/.../audit.py` | Hash-chain + fail-closed redaction (AUD-01) | ✓ VERIFIED | sha256/canonical_json/serial-lock; CR-01 fix (`parts.hostname`, no userinfo) + regression test |
| `packages/controlplane/.../store/{models,engine}.py` | Pluggable Store (SQLite) | ✓ VERIFIED | Dialect-agnostic; SQLite backend; no Docker (D-14) |
| `packages/pipeline/.../risk/{prompt_injection,normalize,aggregator}.py` | SEC-01 detector | ✓ VERIFIED | Deterministic, ReDoS-safe, no network/model |
| `packages/pipeline/.../policy.py` | PolicyEngine + WasmPolicyEngine (POL-03) | ✓ VERIFIED (code) | Load-once; CR-02 allowlist lowercase fix |
| `policies/egress.rego` (+ `egress_test.rego`) | The single principle (D-02) | ✓ VERIFIED | deny-by-default + allowlist membership; opa test 2/2 |
| `policies/build/egress.wasm` | Compiled WASM bundle loaded at startup (D-06) | ⚠️ ORPHANED in CI | Present locally; gitignored; **never produced by CI** — fixture loads it unconditionally |
| `packages/pipeline/.../{runner,identity,graduated}.py` | 4-stage PDP (PIPE-01/02/03, IDN-02, POL-06, TRST-01) | ✓ VERIFIED | Ordered stages, short-circuit, floor invariant |
| `packages/sdk/.../{middleware,normalize,tools}.py` | LangChain PEP (INT-01/SDK-01) | ✓ VERIFIED | awrap_tool_call deny-blocks; http_get governed tool |
| `tests/redteam/test_exfil_injection.py` | D-04 regression lock | ✓ VERIFIED (local) | 2 regression_lock tests pass locally; CI enforcement gap is in ci.yml, not this file |
| `.github/workflows/ci.yml` | OPA build + test + pytest + regression_lock + determinism gates | ⚠️ PARTIAL | Has OPA-CLI install, `opa test`, pytest, regression_lock, determinism — **missing `opa build -t wasm`** |

## Key Link Verification

| From | To | Via | Status | Details |
|------|----|----|--------|---------|
| `GovernanceMiddleware.awrap_tool_call` | `pipeline.evaluate` | in-process call; deny does NOT call handler | ✓ WIRED | `middleware.py:53-60` |
| `runner.evaluate` | identity→policy→risk→graduated | ordered stages + short-circuit + reason accumulation | ✓ WIRED | `runner.py:79-126` |
| `graduated_response` | policy floor | deny is terminal; nothing upgrades it | ✓ WIRED | `graduated.py:38-39`; 46 floor_invariant tests |
| `runner.evaluate` | `audit.append` | writes AuditRecord + sets evidence_ref before return | ✓ WIRED | `runner.py:91,125`; both paths |
| `audit.append` | `audit_record` table | append-only INSERT + prev_hash + monotonic seq | ✓ WIRED | `audit.py:106-154` |
| `identity_engine.verify` | registry | registered-agent check | ✓ WIRED | `is_registered` checked; unregistered → ok=False |
| `PromptInjectionScorer` | `RiskFinding`/`RiskScorer` | implements Protocol; typed finding | ✓ WIRED | `prompt_injection.py:70-77` |
| `WasmPolicyEngine` | `policies/build/egress.wasm` | load once at construction | ⚠️ PARTIAL | Wired locally; the WASM is not produced in CI (build step missing) |
| `test_exfil_injection (deny WITH)` | `test (allow WITHOUT)` | the regression lock | ✓ WIRED (local) | Both pass; CI cannot run them (WASM absent) |
| `ci.yml` | `regression_lock` gate | `pytest -m regression_lock --maxfail=1` | ⚠️ PARTIAL | Gate step present, but ERRORs in CI without the WASM build step |

## Behavioral Spot-Checks (RUN — source of truth)

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| Full suite | `uv run pytest -q` | 124 passed, 2 xfailed | ✓ PASS |
| D-04 regression lock (WASM present) | `uv run pytest tests/redteam/test_exfil_injection.py -m regression_lock --maxfail=1` | 2 passed, 1 deselected | ✓ PASS |
| Detector determinism | `uv run pytest tests/unit/test_detector_recall.py --count=100 -q` | 2700 passed, 200 xfailed | ✓ PASS |
| Floor invariant sweep | `uv run pytest -m floor_invariant -q` | 46 passed | ✓ PASS |
| Egress Rego unit tests | `tools/opa/opa.exe test policies/` | PASS 2/2 | ✓ PASS |
| Regression lock in clean CI (WASM absent) | `mv egress.wasm; uv run pytest -m regression_lock --maxfail=1` | 1 ERROR (OPAPolicy: "not a valid file"), exit 1 | ✗ FAIL — gate breaks for the wrong reason in CI |

## Requirements Coverage (all 13 phase IDs accounted for)

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|-------------|-------------|--------|----------|
| PIPE-07 | 01-01 | Stable serializable contract package | ✓ SATISFIED | contract pkg, round-trip tests, zero internal deps |
| IDN-01 | 01-02 | Agent registers + signed identity token | ✓ SATISFIED | registry.register issues EdDSA JWT; test_identity green |
| AUD-01 | 01-02 | Hash-chained append-only AuditRecord | ✓ SATISFIED | audit.py + test_audit_chain (SQLite per approved D-14) |
| SEC-01 | 01-03 | Prompt-injection risk scoring, typed findings | ✓ SATISFIED | PromptInjectionScorer; recall/precision/determinism tests |
| POL-03 | 01-04 | YAML→OPA/Rego deterministic on hot path behind PolicyEngine | ⚠️ SATISFIED (code) / D-06 CI gap | egress.rego + WasmPolicyEngine + opa test 2/2; CI WASM-build step missing |
| PIPE-01 | 01-05 | Synchronous ordered stages → one Decision | ✓ SATISFIED | runner.evaluate; test_pipeline ordering |
| PIPE-02 | 01-05 | Every stage contributes machine-readable reasons | ✓ SATISFIED | reasons stages == {identity,policy,risk,graduated} |
| PIPE-03 | 01-05 | Stage short-circuit to terminal outcome | ✓ SATISFIED | forged identity → terminal deny, later stages skipped |
| IDN-02 | 01-05 | Verify token; forged/unknown short-circuits to deny | ✓ SATISFIED | identity stage + runner short-circuit, audited |
| TRST-01 | 01-05 | 0–1 trust score consumed by graduated stage | ✓ SATISFIED | trust loaded stage 1, stamped on Decision, feeds graduated |
| POL-06 | 01-05 | Graduated map {policy,risk,trust}→outcome | ✓ SATISFIED | graduated.py; floor invariant; allow+deny realized (D-13) |
| INT-01 | 01-06 | LangGraph tool calls intercepted via SDK middleware → AgentAction | ✓ SATISFIED | GovernanceMiddleware.awrap_tool_call; e2e green |
| SDK-01 | 01-06 | SDK interception middleware (the PEP) for LangChain/LangGraph | ✓ SATISFIED | agentos-sdk package; middleware PEP |

No ORPHANED requirements (REQUIREMENTS.md maps exactly these 13 to Phase 1; all appear in a plan's `requirements:` field). No MISSING requirements.

## Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| `.github/workflows/ci.yml` | (whole file) | Missing `opa build -t wasm` step; gitignored egress.wasm never produced in CI | 🛑 BLOCKER | WASM-backed e2e + red-team tests ERROR/SKIP in CI; D-04 CI-enforcement and D-06 not met (see Gaps) |
| (source) | — | TBD/FIXME/XXX/TODO/HACK/PLACEHOLDER debt markers | ℹ️ Info | NONE found in packages/, policies/, tests/ — clean |
| `audit.py` | 30 | Unused import `func` (IN-01 from 01-REVIEW) | ℹ️ Info | Dead import; cosmetic; not a goal blocker |
| (dependency) | — | opa-wasmtime atexit `min()` ValueError at interpreter shutdown | ℹ️ Info | Pure third-party shutdown noise (logged in deferred-items.md); tests pass; not agentos code |

## Critical-Review Fixes Confirmed (per deviation note)

| Finding | Fix in code | Regression test | Status |
|---------|-------------|-----------------|--------|
| CR-01 (audit URL-credential leak via netloc) | `audit.py:_redact_url` rebuilds from `parts.hostname` (no userinfo) | `test_audit_chain.py::test_redaction_strips_url_userinfo_credentials` (green) | ✓ FIXED + LOCKED |
| CR-02 (allowlist case-sensitivity vs lowercased host) | `policy.py:__init__` `[h.strip().lower() for h in allowlist]` | `test_policy_engine.py::test_mixed_case_allowlist_entry_matches_lowercased_host` (green) | ✓ FIXED + LOCKED |

The 6 Warnings (WR-01..06) from 01-REVIEW.md are intentionally deferred to later phases per the deviation note (audit atomicity/async → Phase 4; fail-posture/policy-error→deny/redaction-on-deny → Phase 3; content inspection → Phase 2) — NOT treated as Phase-1 gaps. See `deferred` frontmatter.

## Gaps Summary

The vertical slice is real and works end-to-end **locally** — every pipeline stage is genuine (no stubs), the floor invariant and identity short-circuit hold, the audit chain is correct and fail-closed, the two CRITICAL review findings (CR-01, CR-02) are fixed with regression tests, and 3 of 4 roadmap success criteria are fully verified. All 13 requirement IDs are accounted for and implemented.

The single blocking gap is in **CI wiring, not in product code**: `.github/workflows/ci.yml` installs the OPA CLI and runs `opa test policies/`, but it never runs `opa build -t wasm` to produce `policies/build/egress.wasm` — which is gitignored. Because the `pipeline_with_principle` fixture loads that WASM unconditionally, a clean CI checkout would make the e2e and red-team (`regression_lock`) tests ERROR at fixture construction (verified empirically: removing the WASM and running the regression_lock gate yields 1 error / exit 1). This means:

1. **D-06** ("the WASM build is wired into CI; the compiled bundle is the artifact the pipeline loads at startup") — a locked 01-CONTEXT.md decision and an explicit 01-04 must-have truth — is **unmet**.
2. **Success criterion 4** is only half-satisfied: the red-team test denies the injection and the regression lock provably bites *locally*, but "removing the Constitution principle makes that test fail **the CI build**" is not actually enforced in CI (the gate would fail for the wrong reason — a missing artifact — before the principle is even evaluated).

Both phase SUMMARYs flagged/assumed this: 01-04 lists it as an open "CI todo (D-06)" and 01-06 asserts the WASM is "regenerated in CI" — but no such step exists in ci.yml. This is the gap the planner should close (add the `opa build -t wasm` step before the Pytest/regression-lock steps). It is not covered by the authorized no-Docker/SQLite deviation.

---

_Verified: 2026-06-02_
_Verifier: Claude (gsd-verifier)_
