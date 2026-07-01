# Phase 5 — Control Plane, SDK & Minimal Dashboard — Design

**Date:** 2026-06-27
**Branch:** `phase-5-control-plane-sdk-dashboard` (stacked on `phase-4-audit-containment`)
**Roadmap:** `.planning/ROADMAP.md` Phase 5 · **Requirements:** API-01, API-02, SDK-02, SDK-04,
SDK-05, DISC-01, DISC-02, DASH-01, DASH-02, DASH-03

## Goal

Wrap the proven Phase-1–4 engines in a usable product surface so an outside team can run the whole
governed loop end-to-end:

1. a **declarative resource API** on a portable SQL store, compiling a Constitution to Policy/Rego on
   write;
2. the **Python SDK** surface — self-registration returning an identity token, plus a control-plane
   client for resource CRUD and approvals;
3. an **authoritative agent inventory** (agents, tools, prompts, memories);
4. a **zero-infra quickstart** — single `pip install`, SQLite + in-process opa-wasm, no Docker /
   Postgres / OPA server;
5. a **minimal operator dashboard** — read-only inventory + recent decisions/audit, resolve
   approvals, trigger agent/fleet kill switches.

API-03 (approve/deny) and the kill-switch API already shipped in Phases 3–4; Phase 5 builds the
resource layer around them, gates them behind auth, and gives them a UI.

## Cross-cutting decisions

1. **Persistence — SQLite-first, Postgres as the production target.** Build on the existing
   *sync* SQLAlchemy 2.0 models with dialect-agnostic generic types (`JSON` not `JSONB`, `Uuid`,
   `DateTime(timezone=True)`), exactly as `store/models.py` already does (D-14). Develop and run the
   full suite on SQLite; keep new Alembic migrations (`0006+`) Postgres-compatible; document Postgres
   as the production target and gate a Postgres-validation job the way the live-interpreter /
   RFC-3161 tests are gated. No async/asyncpg introduced — match the existing sync store.

2. **API stack.** FastAPI routers added to the existing `create_app`; Pydantic v2 request/response
   schemas with `model_config = {"extra": "forbid"}` and bounded fields (mirroring the existing
   `ResolveRequest` / `KillRequest`). Promote `fastapi` + `uvicorn` from test-only to controlplane
   runtime dependencies.

3. **Resource versioning.** Constitution/Policy carry a **content-hash version** — reuse the
   compiler's `constitution_version`. Mutable resources (TrustProfile, ABOM, Agent metadata) carry a
   monotonic `version` int with **optimistic concurrency**: a write supplying a stale version is
   rejected `409 Conflict`. This satisfies API-01's "validate, version, store".

4. **Auth — basic shared-token gate (P0).** A configurable shared secret (`AGENTOS_API_TOKEN`)
   gates the API via a FastAPI dependency checking `Authorization: Bearer <token>` → `401` on
   missing/bad token. Applied to **all** routers, including the existing approval/kill routers
   (retrofit). Self-registration presents this shared **enrollment** token to obtain its per-agent
   EdDSA identity token (so registration isn't open to the whole network). The dashboard uses a
   minimal token-login → httponly cookie. This is deliberately simple; per-principal authn / RBAC is
   a later phase and is documented as a known limitation.

5. **Dashboard tech.** FastAPI + Jinja2 + HTMX, server-rendered, mounted on the same app — per
   `STACK.md` ("do not build an SPA" in P0). Add `jinja2`. No Node toolchain, no build step.

6. **Testing.** Unit + FastAPI `TestClient` integration + an e2e quickstart smoke test. `floor_invariant`
   (430) and `regression_lock` stay green at every commit; latency budget unaffected (resource API
   and dashboard are off the per-action hot path).

## Data model additions (migrations `0006+`)

Dialect-agnostic generic types, mirroring `store/models.py`:

- **`Constitution`** — `id` (PK), `name`, `version` (content hash = `constitution_version`), `source`
  (the authored document), `created_at`. Immutable per version; "apply" inserts a new version row.
- **`Policy`** — `id` (PK), `constitution_version` (FK-ish link), `yaml_policy`, `rego`,
  `graduated_config` (JSON), `lists` (JSON), `sequences` (JSON), `created_at`. The compile-on-write
  output; the engine loads the latest.
- **`TrustProfile`** — `agent_id` (PK), `trust_score`, `band` config (JSON, optional), `version`,
  `updated_at`. (Agent already holds a seed `trust_score`; TrustProfile is the declarative resource
  form for API-01.)
- **`Abom`** — `id` (PK), `agent_id`, `components` (JSON: models/prompts/tools/mcp), `version`,
  `created_at`. Stored-and-versioned only in Phase 5 (provenance/vuln-analysis is Phase 8/14).
- **`InventoryComponent`** — `id` (PK), `agent_id`, `kind` (`tool|prompt|memory`), `name`, `source`
  (`declared|observed`), `first_seen_at`, `last_seen_at`. The authoritative inventory rows
  (DISC-02), unique on `(agent_id, kind, name)`.

`Agent` and `ApprovalRequest` already exist and are reused.

## Slice breakdown

Each slice is an independently shippable vertical slice, built subagent-driven
(implement → spec-review → quality-review → fix → re-review), one commit per task, gates green at
every commit — the Phase-3/4 rhythm.

### 5a — Declarative resource API + versioning + auth gate (API-01)
- New tables: `Constitution`, `Policy`, `TrustProfile`, `Abom` (+ migration `0006`). `InventoryComponent`
  lands in 5c.
- Pydantic v2 schemas (validate + bound) for each resource; `build_resource_router(store)` with
  list/get/create/update; optimistic-version `409` on stale mutable writes.
- `require_token` FastAPI dependency (`AGENTOS_API_TOKEN`); wire it as a router-level dependency on the
  resource router **and retrofit it onto the existing approval/kill routers**; `create_app` reads the
  token from config.
- Tests: CRUD happy-path + validation `422` + version-conflict `409` + auth `401`/`200`; existing
  approval/kill tests updated to pass the token.
- `create_app` accepts an explicit `api_token` (tests inject a known one); if `None`, it reads
  `AGENTOS_API_TOKEN`; if still unset it **generates a random token and logs it** — never
  wide-open. Existing approval/kill integration tests are updated to send the token.

### 5b — Compile-on-write Constitution → Policy/Rego (API-02)
- Applying a `Constitution` (POST) runs the Phase-3 compiler (`agentos_constitution.compiler`) and
  **atomically** persists the `Constitution` version **and** its derived `Policy`
  (yaml/rego/graduated_config/lists/sequences/version) in one transaction.
- Compiler/validation errors → `422` with the compiler's message; nothing persisted (fail-closed).
- `GET /policies/latest` (and by version) returns the compiled artifact the engine consumes.
- Tests: valid Constitution → Constitution+Policy rows with matching `constitution_version`, rego
  present; malformed Constitution → `422`, no rows; re-applying identical source is idempotent on
  version (same content hash).

### 5c — Agent inventory & discovery (DISC-01, DISC-02)
- `InventoryComponent` table (migration `0007`). Registration accepts an optional **manifest**
  (declared tools/prompts/memories) → `declared` rows. An **enrichment** path derives `observed`
  components from intercepted-action audit bodies (agent_id + action_type + target) → upserts
  `observed` rows (`last_seen_at` bumped).
- `GET /inventory` (all agents + components), `GET /inventory/{agent_id}`.
- Tests: register-with-manifest → declared rows; an observed action → observed row; same component
  declared then observed → single row, source reconciled, `last_seen_at` advanced; inventory read
  shapes.

### 5d — SDK self-register + control-plane client (SDK-02, SDK-04)
- `agentos_sdk` gains an `httpx`-based `ControlPlaneClient(base_url, token)`: `register(agent_id,
  manifest=None) -> identity_token` (presents the enrollment token), resource CRUD
  (constitutions/policies/trust/abom), `list_approvals` / `resolve_approval`, `list_inventory`. Add
  `httpx` dep.
- Tests: against the FastAPI `TestClient` transport — register returns a verifiable token; CRUD
  round-trips; resolve flows; a missing/bad token → client surfaces `401`.

### 5e — Zero-infra quickstart (SDK-05)
- A single install path (an `agentos[quickstart]` extra or a thin meta-package) and one command
  (console script, e.g. `agentos-quickstart` / `python -m agentos_sdk.quickstart`) that: creates a
  SQLite DB + runs migrations, loads the in-process **opa-wasm** policy engine (no OPA server),
  registers the Phase-1 `http_get` agent, runs an allowed and a denied action through the full
  governed loop, and prints the decisions + the generated dev API token. No Docker/Postgres/OPA-server.
- Tests: a smoke test invoking the entrypoint asserts the governed loop runs end-to-end on SQLite +
  opa-wasm and produces one allow + one deny with audit records.

### 5f — Minimal dashboard (DASH-01, DASH-02, DASH-03)
- FastAPI + Jinja2 + HTMX pages mounted on `create_app`: a token-login page → httponly cookie; an
  **inventory** view (agents + components); a **decisions/audit** view (recent records, read-only); an
  **approvals** view with approve/deny actions (POST to the existing resolve API); a **kill-switch**
  view to kill/clear an agent or the fleet (POST to the existing kill API). HTMX for the action
  buttons; no SPA.
- Tests: `TestClient` — unauthenticated page → redirect to login; with cookie → pages render; an
  approve action resolves the underlying `ApprovalRequest`; a kill action flips the kill switch
  (assert via the store/audit), and a killed agent is then denied by the pipeline (reuses the 4e e2e).

## Out of scope (Phase 5)

- Per-principal authentication / RBAC / TLS (P0 is a shared-token, trusted-operator gate).
- Reconciliation loops / cache-warming (API-04, Phase 7).
- The live agent graph, SLO/attack views, shadow/rogue discovery (DASH-04 / DISC-03–06, Phases 10/12).
- ABOM provenance + vulnerability impact analysis (ABOM-02/03, Phases 8/14) — Phase 5 only
  validates/versions/stores an ABOM resource.
- Real Postgres deployment validation runs in a gated CI job, not on this machine.

## Risks / watch-items

- **Auth threading.** The token gate touches the API, the dashboard (cookie), the SDK client, and
  the quickstart; retrofitting it onto the existing approval/kill routers must not break their tests
  — update those tests in 5a.
- **Compile-on-write atomicity.** Constitution + Policy must commit in one transaction or roll back
  together; a compile failure must leave no partial state.
- **Quickstart packaging.** uv workspace + console-script entrypoint must produce a genuinely
  single-command experience; the opa-wasm bundle must be available without an OPA server build step at
  run time (reuse the Phase-1 compiled `egress.wasm` artifact path).
- **Dashboard scope creep.** Keep it minimal/server-rendered; defer anything graph/SLO to Phase 12.

## Verification (phase-level success criteria)

1. The declarative API validates, versions, and stores Agent/Constitution/Policy/TrustProfile/
   ApprovalRequest/ABOM, compiling a Constitution to Policy/Rego on write (5a + 5b).
2. The SDK self-registers an agent (returns an identity token) and offers a control-plane client for
   resource CRUD + approvals; self-registered agents appear in the authoritative inventory tracking
   agents/tools/prompts/memories (5c + 5d).
3. An operator views inventory + recent decisions/audit, resolves pending approvals, and triggers
   agent/fleet kill switches from the dashboard (5f).
4. A zero-infra quickstart runs the full governed loop on SQLite + in-process opa-wasm from a single
   `pip install` — no Docker, Postgres, or OPA server (5e).
5. `floor_invariant` (430) + `regression_lock` green throughout; auth gate enforced on every route.
