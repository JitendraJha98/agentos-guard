---
phase: 01-walking-skeleton
plan: 02
subsystem: database
tags: [eddsa, jwt, pyjwt, ed25519, sqlalchemy, alembic, sqlite, audit, hash-chain, sha256, cryptography]

# Dependency graph
requires:
  - phase: 01-walking-skeleton (01-01)
    provides: agentos-contract package (AgentAction, Decision, Reason, Outcome) — the serializable boundary imported here
provides:
  - agentos-controlplane package (uv workspace member, editable-installed)
  - EdDSA (Ed25519) identity engine — issue_token / verify with explicit algorithms=["EdDSA"] allowlist (IDN-01/IDN-02 seed)
  - agent registry — self-registration returning the issued token; is_registered / load_trust lookup seam; TRST-01 seed trust_score
  - SQLAlchemy 2.0 models (Agent, append-only audit_record) using dialect-agnostic generic types (run on SQLite now, map to Postgres later)
  - Alembic migration 0001_initial creating both tables + a Postgres-only append-only UPDATE/DELETE trigger (dialect-guarded)
  - AuditWriter.append — hash-chained, monotonic-seq, canonical-JSON audit writer with fail-closed redaction (AUD-01 / D-15)
  - canonical_json helper (sorted keys, no whitespace) — reproducible SHA-256 hashes
affects: [01-05 pipeline (identity stage 1 verify + audit.append on hot path), 01-06 SDK/e2e (registration + token), Phase 4 audit hardening, Phase 5 control-plane-on-Postgres]

# Tech tracking
tech-stack:
  added: [PyJWT, cryptography (Ed25519), sqlalchemy[asyncio], alembic, stdlib hashlib/json/urllib]
  patterns:
    - "Pluggable Store seam: SQLAlchemy models authored for Postgres (production target) using dialect-agnostic generic types so the SQLite Phase-1 backend runs the same models (D-14 no-Docker)"
    - "Registry-lookup injection: IdentityEngine takes is_registered/load_trust callables — decoupled from persistence"
    - "Fail-closed redaction: redact BEFORE chain write; unknown field -> raise -> no record written (D-15)"
    - "Append-only at the app layer (writer only INSERTs); Postgres trigger is the production-target second line of defense"

key-files:
  created:
    - packages/controlplane/pyproject.toml
    - packages/controlplane/src/agentos_controlplane/__init__.py
    - packages/controlplane/src/agentos_controlplane/identity_engine.py
    - packages/controlplane/src/agentos_controlplane/registry.py
    - packages/controlplane/src/agentos_controlplane/audit.py
    - packages/controlplane/src/agentos_controlplane/store/models.py
    - packages/controlplane/src/agentos_controlplane/store/engine.py
    - packages/controlplane/src/agentos_controlplane/store/migrations/env.py
    - packages/controlplane/src/agentos_controlplane/store/migrations/versions/0001_initial.py
    - alembic.ini
    - tests/unit/test_identity.py
    - tests/integration/test_audit_chain.py
  modified:
    - pyproject.toml (workspace: add agentos-controlplane member + source)
    - .gitignore (ignore local SQLite store file)

key-decisions:
  - "Identity mechanism = JWT-EdDSA (PyJWT + cryptography Ed25519), per Claude's Discretion — standard iss/sub/exp semantics + clean Phase-7 X.509 upgrade path"
  - "Single control-plane Ed25519 keypair for Phase 1; per-agent public_key column modeled but not yet populated (X.509 is IDN-03/Phase 7)"
  - "Sync SQLAlchemy engine for the SQLite Store (registry lookups + serial chain are not I/O-bound on SQLite); asyncpg/Postgres swap is a factory change behind the Store seam"
  - "In-process asyncio.Lock serializes the audit chain (single writer) — the seam a Postgres advisory lock replaces in Phase 4"
  - "Redaction allowlist {url, content}: url -> scheme+host only (drops query/path secrets), content -> {len, sha256}; any other field fails closed"

patterns-established:
  - "Store seam: dialect-agnostic SQLAlchemy generic types (JSON not JSONB, Uuid, DateTime(timezone=True)) — one model set, two backends"
  - "JWT verify NEVER derives algorithm from the token header — explicit allowlist only (GHSA-ffqj-6fqr-9h24)"
  - "Audit body shape (seq, prev_hash, action_id, agent_id, outcome, risk_score, trust_score, reasons, redacted_payload) hashed via canonical JSON; seq is hash-covered, not wall-clock"

requirements-completed: [AUD-01, IDN-01]

# Metrics
duration: ~25min
completed: 2026-06-02
---

# Phase 1 Plan 02: Control-Plane Persistence Summary

**EdDSA (Ed25519) JWT identity engine + agent registry + SHA-256 hash-chained, fail-closed audit writer, all behind a pluggable SQLite-backed Store (Postgres models retained as the production target — D-14 no-Docker).**

## Performance

- **Duration:** ~25 min
- **Started:** 2026-06-01T23:41Z (approx, first task commit)
- **Completed:** 2026-06-02T00:06:27+05:30
- **Tasks:** 2 (both TDD: RED -> GREEN)
- **Files modified:** 19 (17 created, 2 modified)

## Accomplishments

- **Identity engine (IDN-01/IDN-02 seed):** Ed25519 JWT `issue_token` / `verify`. `verify` passes `algorithms=["EdDSA"]` explicitly (no header-derived alg — algorithm-confusion mitigation T-01-04/GHSA-ffqj-6fqr-9h24), checks `iss`, `sub == claimed_agent_id`, and registration; any `jwt.InvalidTokenError` is terminal `ok=False`. Tampered, wrong-key, mismatched, missing, and unregistered tokens all fail.
- **Agent registry (IDN-01 / TRST-01 seed):** `register` persists an `Agent` row and returns the issued token; `is_registered` / `load_trust` provide the verification lookup seam and the seed 0–1 trust score the graduated-response stage will consume.
- **Store schema:** SQLAlchemy 2.0 `Agent` + append-only `audit_record` models using dialect-agnostic generic types; Alembic `0001_initial` creates both tables and a Postgres-only `BEFORE UPDATE OR DELETE` append-only trigger (dialect-guarded so it is skipped on SQLite). Migration applies cleanly on a SQLite URL (smoke-verified).
- **Audit writer (AUD-01 / D-15):** `AuditWriter.append` redacts first and fails closed, then under a serial in-process lock reads the chain head, builds the canonical body, computes `record_hash = sha256(canonical_json(body)).hexdigest()`, and does an append-only INSERT returning the `evidence_ref`. `seq` is strictly monotonic and hash-covered; `prev_hash` links to the prior `record_hash` (NULL only at genesis).

## Task Commits

Each task was committed atomically (TDD: test -> feat):

1. **Task 1: EdDSA identity engine + agent registry + store schema** — `b13d843` (test) -> `24fe5bf` (feat); `7cc569a` (chore: gitignore local SQLite store)
2. **Task 2: Hash-chained audit writer with fail-closed redaction** — `3f2e6a0` (test) -> `4611d5a` (feat)

**Plan metadata:** _(this docs commit)_

## Files Created/Modified

- `packages/controlplane/pyproject.toml` — agentos-controlplane package (deps: agentos-contract, sqlalchemy[asyncio], alembic, PyJWT, cryptography)
- `packages/controlplane/src/agentos_controlplane/identity_engine.py` — Ed25519 JWT issue/verify; explicit algorithm allowlist
- `packages/controlplane/src/agentos_controlplane/registry.py` — self-registration, is_registered/load_trust, TRST-01 seed
- `packages/controlplane/src/agentos_controlplane/audit.py` — AuditWriter.append, canonical_json, _redact_or_raise (RedactionError fail-closed)
- `packages/controlplane/src/agentos_controlplane/store/models.py` — Agent + audit_record (dialect-agnostic generic types)
- `packages/controlplane/src/agentos_controlplane/store/engine.py` — sync engine/sessionmaker factory + create_all bootstrap (env AGENTOS_DB_URL)
- `packages/controlplane/src/agentos_controlplane/store/migrations/{env.py,script.py.mako,versions/0001_initial.py}` — Alembic config + initial migration + append-only trigger
- `alembic.ini` — Alembic config (sync URL; Postgres production target, AGENTOS_DB_URL override)
- `tests/unit/test_identity.py` — 6 identity behavior cases
- `tests/integration/test_audit_chain.py` — 5 audit-chain behavior cases (SQLite Store)
- `pyproject.toml` — workspace: add agentos-controlplane member + source
- `.gitignore` — ignore local SQLite store file

## Decisions Made

- **JWT-EdDSA over bare Ed25519** (Claude's Discretion, CONTEXT.md): standard `iss`/`sub`/`exp` semantics and a clean Phase-7 X.509 upgrade path.
- **Single control-plane keypair** for Phase 1; the per-agent `public_key` column is modeled but populated with the control-plane public key for now (X.509-per-agent is IDN-03, Phase 7).
- **Sync engine + asyncio.Lock** for the SQLite Store: the audit `append` keeps the async signature the pipeline (01-05) awaits, while the chain serializes via an in-process lock — the seam a Postgres advisory lock replaces in Phase 4.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing Critical] gitignore guard for the local SQLite store**
- **Found during:** Task 1 (store engine)
- **Issue:** The default `AGENTOS_DB_URL` creates `agentos_controlplane.db` on disk; nothing in `.gitignore` would prevent committing this generated runtime DB.
- **Fix:** Added `agentos_controlplane.db` and `*.db-journal` to `.gitignore`.
- **Files modified:** `.gitignore`
- **Verification:** No stray `.db` file present; `git status` clean.
- **Committed in:** `7cc569a`

### Acceptance-criterion note (not a deviation in substance)

- The plan's Task-1 acceptance grep looks for the literal `algorithms=["EdDSA"]`. The implementation uses a module constant `ALGORITHM = "EdDSA"` and passes `algorithms=[ALGORITHM]` — semantically identical and provably `["EdDSA"]`. The threat-model mitigation T-01-04 (explicit allowlist, no header-derived alg) is fully satisfied; the value is a named constant for clarity. A grep for `algorithms=[ALGORITHM]` returns 1.

### Honored locked environment deviation (D-14, no-Docker)

- Per CONTEXT.md D-14 and the executor's environment-deviation block, the audit integration test runs against a **SQLite-backed Store** (`Base.metadata.create_all` on an in-memory SQLite engine) — **no testcontainers, no Docker, no Postgres server**. The Alembic migration is authored for Postgres (production target); its append-only trigger is dialect-guarded and skipped on SQLite (append-only enforced at the app layer). Real-Postgres concurrency / advisory-lock / trigger validation is deferred to Phase 4 per the Deviation Log. This is the recorded locked decision, not an unplanned change.

---

**Total deviations:** 1 auto-fixed (1 missing-critical) + 1 acceptance-grep note.
**Impact on plan:** No scope creep. The gitignore guard prevents a generated runtime artifact from being tracked. The D-14 SQLite path is the recorded locked decision.

## Issues Encountered

None. Both TDD cycles went RED -> GREEN cleanly. The Alembic migration smoke-applied on a SQLite URL on the first attempt (dialect guard skipped the Postgres trigger as intended).

## Known Stubs

None that block the plan goal. Modeled-but-not-yet-exercised seams (intentional, by design):
- `Agent.public_key` is populated with the single control-plane public key (per-agent X.509 keys are IDN-03 / Phase 7).
- `policy_version` is intentionally omitted from the audit `body` (nullable) — AUD-03 / Phase 4.
- The Postgres append-only trigger is authored but not exercised in Phase 1 (no Postgres) — Phase 4 validates it.

## Threat Flags

None. The surface introduced (identity verify, audit write/redaction, append-only audit_record) is exactly the surface enumerated in the plan's `<threat_model>` (T-01-04 spoofing, T-01-05 info-disclosure redaction, T-01-06 tampering chain). No new endpoints, auth paths, or trust-boundary schema beyond the plan.

## Next Phase Readiness

- **01-05 (pipeline)** can wire stage-1 identity (`Registry` + `IdentityEngine.verify`) and the hot-path `await AuditWriter.append(action, decision)` returning the `evidence_ref`.
- **01-06 (SDK/e2e)** can call `Registry.register(agent_id)` to obtain the token the middleware attaches.
- **Phase 4** must re-validate the chain against real Postgres (append-only trigger, advisory-lock serialization, concurrency) — SQLite hides these (Deviation Log).

## Self-Check: PASSED

- All 11 key created files verified present on disk.
- All 5 task commits verified in git history (`b13d843`, `24fe5bf`, `7cc569a`, `3f2e6a0`, `4611d5a`).
- `uv run pytest tests/unit/test_identity.py -x` -> 6 passed.
- `uv run pytest tests/integration/test_audit_chain.py -x` -> 5 passed.
- Alembic `0001_initial` applies cleanly on a SQLite URL (both tables created; Postgres trigger dialect-skipped).

---
*Phase: 01-walking-skeleton*
*Completed: 2026-06-02*
