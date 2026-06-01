---
phase: 01-walking-skeleton
plan: 01
subsystem: contract
tags: [scaffold, contract, pydantic, uv-workspace, ci, test-infra]
requires: []
provides:
  - "agentos_contract: AgentAction, ActionType, ActionContext, Decision, Outcome, Reason, RiskFinding, RiskScorer, PipelineProtocol"
  - "uv workspace root with packages/* members + shared lockfile"
  - "pytest config with regression_lock / floor_invariant / latency markers"
  - "tests/conftest.py: make_http_get helper + SQLite-backed audit_store seam + placeholder fixtures"
  - "CI skeleton: pinned OPA CLI 1.9.0 + pytest + regression-lock + determinism gates"
  - "docker-compose.yml (production Postgres target, not exercised — D-14)"
affects:
  - "every Phase-1 plan depends on agentos_contract (the stable boundary)"
tech-stack:
  added:
    - "uv 0.11.17 workspace"
    - "pydantic 2.13.4 (contract substrate)"
    - "pytest 9.0.3 + pytest-repeat + pytest-benchmark"
    - "langchain 1.3.2 / langgraph 1.2.2 (declared; governed framework)"
    - "sqlalchemy 2.0.50 / asyncpg / alembic (production audit target, declared not exercised — D-14)"
    - "PyJWT 2.13.0 / cryptography (identity, declared for plan 01-02)"
  patterns:
    - "Contract-first build order (D-08): the serializable boundary built before any consumer"
    - "extra=\"forbid\" at the serialization boundary (T-01-01)"
    - "pattern-IDs-only validator on RiskFinding.matched (T-01-02)"
    - "Protocol-defined seams (RiskScorer, PipelineProtocol) for additive PEP forms"
key-files:
  created:
    - "pyproject.toml"
    - "uv.lock"
    - "docker-compose.yml"
    - ".github/workflows/ci.yml"
    - "packages/contract/pyproject.toml"
    - "packages/contract/README.md"
    - "packages/contract/src/agentos_contract/__init__.py"
    - "packages/contract/src/agentos_contract/action.py"
    - "packages/contract/src/agentos_contract/decision.py"
    - "packages/contract/src/agentos_contract/risk.py"
    - "packages/contract/src/agentos_contract/pipeline.py"
    - "tests/conftest.py"
    - "tests/unit/test_contract.py"
  modified: []
decisions:
  - "D-08: contract package built FIRST with zero internal dependencies — honored."
  - "D-14: audit store seam is SQLite-backed; no testcontainers/Docker — honored in conftest."
  - "A1: opa-wasmtime/wasmtime intentionally NOT installed this wave (gated to plan 01-04)."
  - "Pinned OPA CLI 1.9.0 in CI; opa test policies/ is a no-op until plan 01-04 adds Rego."
metrics:
  duration_minutes: 5
  tasks_completed: 3
  files_created: 13
  completed_date: "2026-06-01"
---

# Phase 1 Plan 01: uv Workspace Scaffold + Wave-0 Test Infra + Serializable Contract Package Summary

Built the stable, serializable `agentos_contract` package (PIPE-07 / D-08) inside a fresh `uv` workspace, with Wave-0 test infrastructure (pytest markers, conftest scaffold, CI skeleton) so every downstream Phase-1 task has an automated verify target.

## What Was Built

**Task 1 — uv workspace + deps + docker-compose + CI skeleton** (`chore`, `d460506`)
- Root `pyproject.toml` with `[tool.uv.workspace] members = ["packages/*"]`, runtime deps (langchain, langgraph, pydantic, sqlalchemy[asyncio], asyncpg, alembic, PyJWT, cryptography), dev deps (pytest, pytest-repeat, pytest-benchmark), and `[tool.pytest.ini_options]` registering markers `regression_lock`, `floor_invariant`, `latency` with `testpaths = ["tests"]`.
- `packages/contract/pyproject.toml` declaring `agentos-contract` depending ONLY on pydantic (zero internal deps — D-08), hatchling build.
- `docker-compose.yml` with a `postgres:16` service on 5432 (production target; not exercised — D-14).
- `.github/workflows/ci.yml`: installs uv, `uv sync`, downloads pinned OPA CLI **1.9.0**, runs `opa test policies/` (no-op/skip while `policies/` has no Rego — keeps Wave-1 CI green), `uv run pytest -q`, plus the `regression_lock` hard-fail gate and the `--count=100` determinism check.
- `uv lock` produced `uv.lock`. `uv sync` resolved cleanly with NO wasmer/opa-wasm errors (those are intentionally absent this wave — A1).

**Task 2 — contract package** (`tdd`: RED `6ea674f` → GREEN `c3a0286`)
- `action.py`: `ActionType(str, Enum)` (all 5 members; only `tool_call` used this phase), `ActionContext`, `AgentAction` with `model_config = {"extra": "forbid"}` and UUID/timestamp defaults.
- `decision.py`: `Outcome(str, Enum)` (all 6 members), `Reason`, `Decision` with `extra="forbid"` and `risk_score`/`trust_score` bounded `Field(ge=0.0, le=1.0)`.
- `risk.py`: `RiskFinding` copied verbatim from AI-SPEC §4b — `model_config = {"frozen": True, "extra": "forbid"}`, `category: Literal[...]`, the `_no_raw_payload` `field_validator` on `matched` rejecting any element where `"http" in m or len(m) > 64`; plus the `RiskScorer` Protocol.
- `pipeline.py`: `PipelineProtocol` Protocol with `evaluate(action) -> Decision` (Protocol only, no implementation).
- `__init__.py` exports the full public surface. 8 boundary tests in `tests/unit/test_contract.py` all pass.

**Task 3 — conftest scaffold** (`test`, `80395dc`)
- `make_http_get(url, fetched_content="")` builds an `http_get` `AgentAction` (D-01).
- `audit_store` fixture yields a working in-memory SQLite-backed store seam (`sqlite+pysqlite:///:memory:` + `MetaData().create_all`) — **no testcontainers/Docker import** (D-14). Plan 01-02 swaps in the real `Store` over the same SQLite backend.
- Placeholder fixtures `pipeline_with_principle`, `pipeline_without_principle`, `prompt_injection_scorer`, `registered_agent_token` each `pytest.skip("provided by later wave")`.

## Verification

- `uv sync` clean; `uv run python -c "import agentos_contract"` → OK (no wasmer).
- `uv run pytest tests/unit/test_contract.py -x` → 8 passed.
- `uv run pytest --markers` lists `regression_lock`, `floor_invariant`, `latency`.
- `uv run pytest tests/ --collect-only` → 8 tests collected, conftest imports cleanly.
- `uv run pytest -q` (full suite) → 8 passed.
- `field_validator` present in `risk.py`; `AgentAction`/`Decision` set `extra="forbid"`, `RiskFinding` sets `frozen=True` + `extra="forbid"` (verified at runtime).

## Deviations from Plan

None at execution time — the plan text already incorporated the recorded environment deviations (CONTEXT.md D-14 SQLite-backed `Store` / no Docker, and RESEARCH A1 opa-wasmtime gated to plan 01-04). Those were honored as written:
- No `testcontainers` declared or imported; `audit_store` is SQLite-backed.
- No `opa-wasmtime`/`wasmtime` installed this wave; `uv sync` resolved without wasmer.
- `opa test policies/` left in CI but made a no-op while `policies/` is empty.

Note (not a deviation, recorded for traceability): `pytest>=8` resolved to `pytest 9.0.3` — within the declared constraint; markers and all gates behave as specified.

## Threat Model Coverage

- **T-01-01 (Tampering, deserialization):** `extra="forbid"` on `AgentAction` and `Decision` — tested (`test_*_rejects_unknown_field`).
- **T-01-02 (Information Disclosure, RiskFinding.matched → audit log):** `_no_raw_payload` validator rejects URL-like / >64-char strings — tested (`test_risk_finding_rejects_url_like_matched`, `test_risk_finding_rejects_long_matched`).
- **T-01-03 (Tampering, score bounds):** `risk_score`/`trust_score` bounded — tested (`test_decision_rejects_out_of_range_risk_score`).
- **T-01-SC (supply chain):** all Wave-1 packages VERIFIED + pinned in `uv.lock`; the only ASSUMED package (`opa-wasmtime`) intentionally NOT installed — gated to plan 01-04's human-verify checkpoint.

No new threat surface beyond the plan's `<threat_model>`.

## Known Stubs

The four placeholder conftest fixtures (`pipeline_with_principle`, `pipeline_without_principle`, `prompt_injection_scorer`, `registered_agent_token`) are intentional Wave-0 scaffolds that `pytest.skip` until their owning plans fill them in:
- `prompt_injection_scorer` → plan 01-03 (SEC-01 detector)
- `registered_agent_token` → plan 01-02 (identity engine)
- `pipeline_with_principle` → plan 01-05 (pipeline runner)
- `pipeline_without_principle` → plan 01-06 (D-04 red-team gate)

These do not block this plan's goal (the stable contract + Wave-0 infra); they are the documented seam the plan asked for.

## TDD Gate Compliance

Task 2 (`tdd="true"`) followed RED → GREEN:
- RED gate: `test(01-01)` commit `6ea674f` — failing contract tests (ImportError, modules empty).
- GREEN gate: `feat(01-01)` commit `c3a0286` — contract implemented, 8 tests pass.
- REFACTOR: not needed (implementation is the verbatim spec; minimal and clean).

## Self-Check: PASSED

All 13 created files exist on disk; all 4 task commits (`d460506`, `6ea674f`, `c3a0286`, `80395dc`) exist in git history.
