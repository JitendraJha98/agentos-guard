---
phase: 1
slug: walking-skeleton
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-06-01
---

# Phase 1 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.
> Test map derived from `01-RESEARCH.md` § "Validation Architecture". Per-task IDs populated during planning.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | pytest 8.x (+ pytest-repeat, pytest-benchmark, testcontainers[postgres] 4.14.2) |
| **Config file** | none yet — Wave 0 creates `pyproject.toml [tool.pytest.ini_options]` (markers: `regression_lock`, `floor_invariant`, `latency`; testpaths) |
| **Quick run command** | `uv run pytest tests/unit tests/redteam -m "not slow" -q` |
| **Full suite command** | `uv run pytest -q` (spins testcontainers Postgres for audit/integration) + `opa test policies/` |
| **Estimated runtime** | ~30–60s full suite (unit/redteam < 5s; testcontainers Postgres startup dominates) |

---

## Sampling Rate

- **After every task commit:** Run `uv run pytest tests/unit tests/redteam -q` (fast; no containers)
- **After every plan wave:** Run `uv run pytest -q` (full suite incl. testcontainers Postgres) + `opa test policies/`
- **Before `/gsd:verify-work`:** Full suite green + `pytest -m regression_lock --maxfail=1` green + detector determinism (`--count=100`) green
- **Max feedback latency:** < 60 seconds (full); < 5 seconds (quick)

---

## Per-Task Verification Map

> Requirement-level map from research; **Task ID / Plan / Wave columns are filled during planning** (plans don't exist yet). All files are Wave-0 gaps (greenfield — none exist).

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| (planner) | TBD | TBD | PIPE-07 | — | `AgentAction`/`Decision` round-trip serialize; reject extra fields | unit | `pytest tests/unit/test_contract.py -x` | ❌ W0 | ⬜ pending |
| (planner) | TBD | TBD | INT-01 / SDK-01 | T-1 indirect injection | `wrap_tool_call` denies (no `handler` call) on deny; allows by calling handler | unit | `pytest tests/unit/test_middleware.py -x` | ❌ W0 | ⬜ pending |
| (planner) | TBD | TBD | PIPE-01 / PIPE-02 | — | Ordered 4-stage run → one `Decision` with per-stage `reasons` | unit | `pytest tests/unit/test_pipeline.py -x` | ❌ W0 | ⬜ pending |
| (planner) | TBD | TBD | PIPE-03 / IDN-02 | T-spoof | Forged/unknown identity → terminal deny; later stages NOT run | unit | `pytest tests/unit/test_identity_shortcircuit.py -x` | ❌ W0 | ⬜ pending |
| (planner) | TBD | TBD | IDN-01 | T-spoof | Registration issues verifiable EdDSA JWT; tampered token fails | unit | `pytest tests/unit/test_identity.py -x` | ❌ W0 | ⬜ pending |
| (planner) | TBD | TBD | POL-03 | T-access | `egress.rego` allows allowlisted host, denies others (opa test + WASM load) | unit + smoke | `opa test policies/ && pytest tests/unit/test_policy_engine.py -x` | ❌ W0 | ⬜ pending |
| (planner) | TBD | TBD | POL-06 / TRST-01 | T-elevation | `graduated_response` never upgrades past policy deny (floor invariant) | unit | `pytest tests/unit/test_graduated.py -m floor_invariant -x` | ❌ W0 | ⬜ pending |
| (planner) | TBD | TBD | SEC-01 | T-injection | Detector fires on each covered probe class; benign content scores < 0.4 | unit | `pytest tests/unit/test_detector_recall.py -x` | ❌ W0 | ⬜ pending |
| (planner) | TBD | TBD | SEC-01 (determinism) | T-flaky | Same action → byte-identical finding over 100 runs | unit | `pytest tests/unit/test_detector_recall.py --count=100 -q` | ❌ W0 | ⬜ pending |
| (planner) | TBD | TBD | AUD-01 | T-tamper / T-leak | Hash-chained append; `seq` monotonic; chain links; redaction fails closed | integration | `pytest tests/integration/test_audit_chain.py -x` (testcontainers) | ❌ W0 | ⬜ pending |
| (planner) | TBD | TBD | **D-04 (done-criterion)** | T-injection | Exfil probe → deny WITH principle; **deleting principle → CI red** | redteam | `pytest tests/redteam/test_exfil_injection.py -m regression_lock --maxfail=1` | ❌ W0 | ⬜ pending |
| (planner) | TBD | TBD | End-to-end | — | LangGraph agent: allowlisted fetch runs, attacker fetch blocked, one audit record written | integration | `pytest tests/integration/test_e2e_slice.py -x` (testcontainers) | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `pyproject.toml [tool.pytest.ini_options]` — register markers (`regression_lock`, `floor_invariant`, `latency`), set testpaths
- [ ] `tests/conftest.py` — fixtures: `pipeline_with_principle`, `pipeline_without_principle`, `prompt_injection_scorer`, Postgres `testcontainers` fixture, registered-agent + issued-token fixture
- [ ] `tests/unit/`, `tests/integration/`, `tests/redteam/` — all test files above (none exist; greenfield)
- [ ] CI: pinned **OPA CLI** install + `opa build -t wasm` + `opa test` step; the `regression_lock` hard-fail gate; the `--count=100` determinism check
- [ ] Framework install: `uv add --dev pytest pytest-repeat pytest-benchmark "testcontainers[postgres]"`

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| `opa-wasmtime` package fit-for-purpose | POL-03 | Young/single-maintainer package replacing the incompatible `opa-wasm` (research A1); needs human review + smoke test before lock-in | Review `github.com/nickdeis/python-opa-wasmtime`; smoke-test loading a compiled `egress.wasm` and evaluating one allow + one deny input. Gate the policy-engine install behind this `checkpoint:human-verify`. |

*All other phase behaviors have automated verification.*

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 60s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
