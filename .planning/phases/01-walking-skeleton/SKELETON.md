# Walking Skeleton — agentos-guard

**Phase:** 1
**Generated:** 2026-06-01

## Capability Proven End-to-End

A platform-security engineer can wrap one LangGraph agent's single governed `http_get` tool with the SDK middleware, and every tool call is intercepted before execution and run through the full four-stage decision pipeline (identity/trust → opa-wasm policy → SEC-01 risk → graduated response) producing one serializable `Decision`: a fetch to an allowlisted host runs the tool and appends one hash-chained `AuditRecord` to Postgres; a fetch to a non-allowlisted host (the data-exfiltration prompt-injection probe) is denied, the tool never executes, and a red-team pytest fails CI if the egress-allowlist Rego principle is removed.

## Architectural Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Language / runtime | Python 3.12 floor / 3.13 | Locked by ADR-0001; 3.12 has broadest wheel support. Rust hot path deferred to Phase 14 (PERF-01). |
| Package management / layout | `uv` workspace; `packages/{contract,pipeline,controlplane,sdk}` each with own `pyproject.toml`, one shared `uv.lock` | Keeps `contract` standalone with zero internal deps (D-08); later phases add `controlplane-api`/`gateway`/`dashboard` packages without restructuring. |
| Stable boundary | `contract` package built FIRST: `AgentAction`, `Decision`, `Outcome`, `Reason`, `RiskScorer` Protocol, `RiskFinding`, `PipelineProtocol.evaluate(AgentAction)->Decision` | PIPE-07 / D-08 — every PEP form (SDK now, gateway Phase 10, sidecar Phase 14) depends only on this; serializable from day one (Pydantic v2, `extra="forbid"`). |
| Interception (PEP) | LangChain v1 `AgentMiddleware.wrap_tool_call(request, handler)` in the `sdk` package; deny = return `ToolMessage` WITHOUT calling `handler` | INT-01 / SDK-01 (D-01). Verified seam (docs.langchain.com/oss/python/langchain/middleware/custom, 2026-06-01). PEP logic never leaks into the pipeline (Anti-Pattern 5). |
| Pipeline invocation | In-process library call (`pipeline.evaluate(action)`) — no network/HTTP control-plane endpoint | D-07; the network control plane is Phase 5 behind the same contract. |
| Policy engine | `opa-wasmtime` (NOT the stale `opa-wasm`) behind a `PolicyEngine` Protocol; Rego compiled to WASM by a pinned OPA CLI (`opa build -t wasm`), bundle loaded ONCE at startup | POL-03 / D-05 / D-06. `opa-wasm 0.3.2` needs `wasmer` (no Python 3.12+ wheels) — incompatible. `wasmtime` (Bytecode Alliance) has 3.12/3.13 wheels. Interface keeps OPA-server a future toggle and `opa-wasmtime` a one-file swap. |
| The single principle | Egress allowlist authored DIRECTLY as Rego (`policies/egress.rego`): `allow if input.type=="tool_call" and input.host in data.allowlist`; hosts supplied as Rego `data` at startup | D-02. The Constitution authoring layer + Constitution→YAML→Rego compiler are Phase 3 (POL-01/02) — NOT built here. |
| Risk detector (SEC-01) | In-house deterministic `PromptInjectionScorer` (stdlib `re` + Pydantic v2 typed `RiskFinding`) behind the `RiskScorer` Protocol; `normalize()` (NFKC + zero-width strip + base64) before matching; bounded 32 KB input; ReDoS-safe bounded quantifiers | AI-SPEC §2/§3/§4. No LLM/model on the hot path (P0-killer). Heavier ML detectors (Prompt Guard 2) slot behind the same Protocol in Phase 3. |
| Graduated response | Pure `graduated_response(policy_outcome, risk, trust) -> Outcome`; policy `deny` is terminal; risk/trust may only RESTRICT, never relax | POL-06 / TRST-01 (D-13). Floor invariant (POL-05/TRST-02) honored in code even though full enforcement is Phase 3. Phase 1 realizes `allow` + `deny` end-to-end; `warn`/`sandbox` are vocabulary-only. |
| Identity | EdDSA (Ed25519) JWT via PyJWT + `cryptography`; verify with explicit `algorithms=["EdDSA"]`, check `iss`/`sub`/registration; forged/unknown → terminal `deny` | IDN-01 / IDN-02 (D-10). Clean upgrade path to X.509 (Phase 7). Algorithm-confusion advisory GHSA-ffqj-6fqr-9h24 honored. |
| Trust | Single 0–1 `trust_score` column on the agent registry row, loaded in stage 1, fed to graduated response | TRST-01 (D-11). Longitudinal reputation engine is Phase 7. |
| Data layer | Pluggable `Store` interface. **Phase-1 backend: SQLite** (SQLAlchemy, dialect-agnostic generic types) — runs directly, no Docker. SQLAlchemy 2.0 + Alembic models authored for **PostgreSQL as the production target** (Phase 5 = backend swap, not rewrite); append-only `audit_record` table. | D-14 (REVISED, no-Docker deviation). Postgres append-only/concurrency hardening + real-PG validation deferred to Phase 4/5 (research caveat — SQLite hides it). |
| Audit | Hash-chained `AuditRecord`: stdlib `hashlib` SHA-256 over canonical JSON (sorted keys, no whitespace), monotonic `seq` covered by hash, `prev_hash` link; redaction fails closed (no write if redaction fails) | AUD-01 / D-14 / D-15. CI chain-verifier, external anchoring, full provenance = Phase 4 (AUD-02..05); Merkle DAG = Phase 11. `policy_version` column left nullable. |
| Test / red-team | pytest 8.x + pytest-repeat + pytest-benchmark (SQLite-backed `Store` for audit/e2e — no Docker/testcontainers); markers `regression_lock`, `floor_invariant`, `latency`; OPA CLI `opa test` in CI | D-04. The `regression_lock` red-team test hard-fails CI; deleting the principle flips the probe deny→allow and breaks the build. Determinism asserted with `--count=100` (non-flaky gate). |

## Stack Touched in Phase 1

- [x] Project scaffold — `uv` workspace, four `packages/*`, `pyproject.toml` with pytest config + markers, `docker-compose.yml`, CI workflow with pinned OPA CLI
- [x] Routing — N/A (single-process library + in-process pipeline; no HTTP control-plane endpoint until Phase 5). The "route" is `pipeline.evaluate(AgentAction) -> Decision`.
- [x] Database — at least one real read (chain head / agent registry lookup) AND one real write (append-only `audit_record` INSERT) against the SQLite-backed `Store` (no Docker; Postgres models retained as production target)
- [x] Interactive element wired to the engine — LangGraph agent's `http_get` tool call intercepted by `GovernanceMiddleware.wrap_tool_call`, enforced end-to-end (allow runs / deny blocks)
- [x] Local full-stack run — `uv run pytest -q` runs the full vertical slice directly (SQLite-backed `Store`, no Docker); documented in the repo README/Makefile

## Out of Scope (Deferred to Later Slices)

Explicitly NOT in the skeleton — recorded so future phases do not re-litigate Phase 1's minimalism:

- Constitution authoring layer + Constitution→YAML→Rego compiler — Phase 3 (POL-01/02). The single principle is hand-authored Rego.
- LLM semantic interpreter (`{outcome, cited principle, rationale}`) — Phase 3 (POL-04/05). No LLM on the hot path.
- Own decision/policy cache, p95 latency *budget gate*, per-action-class fail-posture config — Phase 3 (PIPE-04/05/06). (Latency is measured informationally in Phase 1 but NOT a CI gate.)
- Other interception types (model/memory/MCP/delegation) + coverage matrix — Phase 2 (INT-02..06).
- Full graduated outcomes (`warn`/`sandbox`/`require_consensus`/`require_approval`) + approval workflow — Phase 3 / Phase 9 (POL-07, POL-09). `Outcome` vocabulary is present; only `allow`/`deny` are enforced.
- Audit provenance (`policy_version`), CI chain-verifier, external anchoring, Merkle DAG — Phase 4 / Phase 11 (AUD-02..06).
- Control-plane declarative API, full SDK control-plane client, dashboard, kill switch — Phase 4 / Phase 5 (API-01..03, RUN-01/02, DASH-*).
- OpenTelemetry emission, compliance mapping engines, garak/PyRIT probe expansion — Phase 6 (OBS-01..03, CMP-01..03, TEST-01..06). Phase-1 red-team gate is a hand-authored deterministic pytest probe set.
- Full Presidio-grade PII redaction — Phase 4. Phase-1 redaction is minimal + fail-closed.

## Subsequent Slice Plan

Each later phase adds one vertical slice on top of this skeleton without altering its architectural decisions (the `contract` boundary and `evaluate(AgentAction)->Decision` are fixed):

- Phase 2: All five action types (model/memory/MCP/delegation) intercepted and normalized through the same pipeline; no-silent-gaps coverage check.
- Phase 3: Human-readable Constitution compiles to Rego; full graduated outcome spectrum + approvals; LLM advisory interpreter; latency budget + own cache + fail-posture.
- Phase 4: Tamper-evident audit (provenance, fail-closed redaction, CI verifier, anchoring); agent/fleet kill switches.
- Phase 5: Declarative resource API on Postgres + full Python SDK + minimal dashboard.
- Phase 6: OTel telemetry, OWASP/NIST/EU compliance mapping, pytest-native statistical red-team gate (closes Phase 0).
