---
phase: 1
slug: walking-skeleton
status: draft
nyquist_compliant: true
wave_0_complete: false
created: 2026-06-01
updated: 2026-06-01
---

# Phase 1 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.
> Test map derived from `01-RESEARCH.md` § "Validation Architecture". Per-task IDs populated during planning (plans 01-01 … 01-06).

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | pytest 8.x (+ pytest-repeat, pytest-benchmark). No testcontainers — audit/e2e run on a SQLite-backed `Store` (no Docker; D-14 deviation). |
| **Config file** | `pyproject.toml [tool.pytest.ini_options]` created in **plan 01-01 / Wave 1** (markers: `regression_lock`, `floor_invariant`, `latency`; testpaths) |
| **Quick run command** | `uv run pytest tests/unit tests/redteam -m "not slow" -q` |
| **Full suite command** | `uv run pytest -q` (audit/integration run on a SQLite-backed `Store` — no Docker) + `opa test policies/` |
| **Estimated runtime** | ~5–15s full suite (all in-process; SQLite, no container startup) |

---

## Sampling Rate

- **After every task commit:** Run `uv run pytest tests/unit tests/redteam -q` (fast; no containers)
- **After every plan wave:** Run `uv run pytest -q` (full suite; SQLite-backed Store, no Docker) + `opa test policies/`
- **Before `/gsd:verify-work`:** Full suite green + `pytest -m regression_lock --maxfail=1` green + detector determinism (`--count=100`) green
- **Max feedback latency:** < 60 seconds (full); < 5 seconds (quick)

---

## Per-Task Verification Map

> Task ID / Plan / Wave columns populated to match plans 01-01 … 01-06. All files are Wave-0 gaps (greenfield) created by the listed plan.

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 01-01-T2 | 01-01 | 1 | PIPE-07 | T-01-01/02 | `AgentAction`/`Decision` round-trip serialize; reject extra fields; RiskFinding rejects raw payload | unit | `uv run pytest tests/unit/test_contract.py -x` | created by 01-01 | ⬜ pending |
| 01-06-T1 | 01-06 | 5 | INT-01 / SDK-01 | T-01-19/20 | `wrap_tool_call` denies (no `handler` call) on deny; allows by calling handler | unit | `uv run pytest tests/unit/test_middleware.py -x` | created by 01-06 | ⬜ pending |
| 01-05-T2 | 01-05 | 4 | PIPE-01 / PIPE-02 | T-01-17 | Ordered 4-stage run → one `Decision` with per-stage `reasons` | unit | `uv run pytest tests/unit/test_pipeline.py -x` | created by 01-05 | ⬜ pending |
| 01-05-T1/T2 | 01-05 | 4 | PIPE-03 / IDN-02 | T-01-15 | Forged/unknown identity → terminal deny; later stages NOT run | unit | `uv run pytest tests/unit/test_identity_shortcircuit.py -x` | created by 01-05 | ⬜ pending |
| 01-02-T1 | 01-02 | 2 | IDN-01 | T-01-04 | Registration issues verifiable EdDSA JWT; tampered/wrong-key token fails | unit | `uv run pytest tests/unit/test_identity.py -x` | created by 01-02 | ⬜ pending |
| 01-04-T2/T3 | 01-04 | 3 | POL-03 | T-01-13/14 | `egress.rego` allows allowlisted host, denies others (opa test + WASM load) | unit + smoke | `opa test policies/ && uv run pytest tests/unit/test_policy_engine.py -x` | created by 01-04 | ⬜ pending |
| 01-05-T1 | 01-05 | 4 | POL-06 / TRST-01 | T-01-16 | `graduated_response` never upgrades past policy deny (floor invariant) | unit | `uv run pytest tests/unit/test_graduated.py -m floor_invariant -x` | created by 01-05 | ⬜ pending |
| 01-03-FEAT | 01-03 | 2 | SEC-01 | T-01-08/09/11 | Detector fires on each covered probe class; benign content scores < 0.4 | unit | `uv run pytest tests/unit/test_detector_recall.py -x` | created by 01-03 | ⬜ pending |
| 01-03-FEAT | 01-03 | 2 | SEC-01 (determinism) | T-01-12 | Same action → byte-identical finding over 100 runs; no network/model import | unit | `uv run pytest tests/unit/test_detector_recall.py --count=100 -q` | created by 01-03 | ⬜ pending |
| 01-02-T2 | 01-02 | 2 | AUD-01 | T-01-05/06 | Hash-chained append; `seq` monotonic; chain links; redaction fails closed | integration | `uv run pytest tests/integration/test_audit_chain.py -x` (SQLite Store) | created by 01-02 | ⬜ pending |
| 01-06-T3 | 01-06 | 5 | **D-04 (done-criterion)** | T-01-20 | Exfil probe → deny WITH principle; **deleting principle → CI red** | redteam | `uv run pytest tests/redteam/test_exfil_injection.py -m regression_lock --maxfail=1` | created by 01-06 | ⬜ pending |
| 01-06-T2 | 01-06 | 5 | End-to-end | T-01-19/21 | LangGraph agent: allowlisted fetch runs, attacker fetch blocked, one audit record written | integration | `uv run pytest tests/integration/test_e2e_slice.py -x` (SQLite Store) | created by 01-06 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

> All satisfied by **plan 01-01 (Wave 1)** which scaffolds the workspace, pytest config, conftest, and CI; per-test files are then authored by their owning plans (above).

- [ ] `pyproject.toml [tool.pytest.ini_options]` — register markers (`regression_lock`, `floor_invariant`, `latency`), set testpaths *(01-01 Task 1)*
- [ ] `tests/conftest.py` — fixtures: `pipeline_with_principle`, `pipeline_without_principle`, `prompt_injection_scorer`, SQLite-backed `audit_store` fixture (no Docker), registered-agent + issued-token fixture *(scaffold 01-01 Task 3; filled in 01-06 Task 2)*
- [ ] `tests/unit/`, `tests/integration/`, `tests/redteam/` — all test files above (none exist; greenfield) *(per owning plan)*
- [ ] CI: pinned **OPA CLI** install + `opa build -t wasm` + `opa test` step; the `regression_lock` hard-fail gate; the `--count=100` determinism check *(01-01 Task 1; exercised meaningfully by 01-04 / 01-06)*
- [ ] Framework install: `uv add --dev pytest pytest-repeat pytest-benchmark` (no testcontainers — SQLite Store, no Docker) *(01-01 Task 1)*

---

## Manual-Only Verifications

| Behavior | Requirement | Plan | Why Manual | Test Instructions |
|----------|-------------|------|------------|-------------------|
| `opa-wasmtime` package fit-for-purpose | POL-03 | **01-04 Task 1** (`checkpoint:human-verify`, blocking) | Young/single-maintainer package replacing the incompatible `opa-wasm` (research A1); needs human review + smoke test before lock-in | Review `github.com/nickdeis/python-opa-wasmtime`; smoke-test loading a compiled `egress.wasm` and evaluating one allow + one deny input. Gate the policy-engine install behind this `checkpoint:human-verify`. |

*All other phase behaviors have automated verification.*

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references (plan 01-01)
- [x] No watch-mode flags
- [x] Feedback latency < 60s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** populated by planner 2026-06-01 (Task ID/Plan/Wave columns matched to plans 01-01 … 01-06)
