# Phase 3 · Slice 6 (6a/6b/6c) — Approvals, Lifecycle Outcomes, Side-Effects, Latency Gate

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development.
> Commits: second `-m "Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"`. Tests:
> `./.venv/Scripts/python.exe -m pytest`. TDD per task. Gates `floor_invariant` (430) and
> `regression_lock` (10) must stay green at every commit.

**Goal:** `require_approval` parks a persisted `ApprovalRequest` and blocks via the store until
resolved or timed out to the class-posture default (POL-07); operators resolve via a minimal API
(API-03); `temporary_exception` is a human-ratified, time-boxed allow consumed as a pre-graduated
transform with auto-revoke at `expires_at` (POL-13); `governance_review` proceeds while opening an
async non-blocking review (POL-14); side-effects are derived and dispatched (PIPE-09); the interim
`should_execute` posture is replaced by the real outcome-enforcement map with middleware unified
onto one core; and the p95 cached-path latency budget becomes a CI gate (PIPE-04).

**Requirements:** POL-07, POL-13, POL-14, API-03, PIPE-09, PIPE-04.

**New deps (root pyproject only + `uv sync`):** `fastapi>=0.115`; dev group: `httpx>=0.27`
(TestClient).

---

## Locked design (overview rev-2 D3/D5 + review carry-forwards)

- **PDP decides, PEP blocks.** The pipeline never sleeps; `require_approval` blocking lives in SDK
  enforcement via an injected coordinator.
- **Store-awaited blocking (D3):** `await store.wait_resolved(id, deadline_s, poll_s=0.2)` polls
  the persisted row state — never an in-process future — so the Phase-5 out-of-process API is just
  another writer. Timeout resolves to the per-action-class posture default (fail-closed classes →
  deny, code `approval_timeout`); the row is marked `timed_out`.
- **Approval rows are redacted fail-closed** with the SAME `_redact_or_raise` the audit writer
  uses (import it; do not fork the logic).
- **Every lifecycle event is an `AuditRecord`** through the SAME hash chain: the audit writer
  gains `append_event(kind: str, body: dict) -> UUID` sharing the lock/seq/prev-hash discipline
  (body is ids/enums/short strings only — no payload; reuse canonical_json + hash covering
  {seq, prev_hash, kind, ...body}). Event kinds: `approval_resolved`, `approval_timed_out`,
  `exception_granted`, `review_opened`, `enforcement_substitution`, `side_effect`.
- **Temporary exception (D5):** scope = `(agent_id, principle_ref)`, granted ONLY via human
  resolution (`resolve(..., grant_exception_until=...)`) — never authorable, never interpreter-
  grantable. Consumption is a pre-graduated transform in the policy stage: floor would be deny
  from matched principles, but every deny-effect principle ref has an active unexpired exception →
  floor becomes `allow` + reason `temporary_exception_applied` (evidence: refs + expires_at).
  Risk still applies (may re-restrict — defense in depth). If the FINAL outcome is `allow` and an
  exception was applied → relabel outcome `temporary_exception` with `expires_at` = earliest
  consumed expiry. **Auto-revoke = read-time expiry check** (`expires_at > now()` in the lookup
  query) — no background job; plus explicit `revoke(exception_id)`. Review correction: the floor
  does NOT become `allow` — it re-derives from the remaining non-deny matched principles (or
  `allow` if none), so a co-fired restrictive principle (e.g. `require_approval`) still governs.
- **Outcome-enforcement map (replaces interim `should_execute`):**
  | Outcome | Enforcement |
  |---|---|
  | allow, warn | execute |
  | temporary_exception | execute (it IS a ratified allow; expiry checked at decision time) |
  | governance_review | open review via coordinator (non-blocking) + execute |
  | require_approval | park + block-await via coordinator; no coordinator → GovernanceDenied (fail-closed) |
  | sandbox, require_consensus | escalate to the approval path until RUN-03/POL-09 (Phase 9); audited as `enforcement_substitution`; no coordinator → GovernanceDenied |
  | deny | GovernanceDenied |
- **Review obligation survives escalation (D5):** the dispatcher opens a review when the outcome
  is `governance_review` OR any fired principle's effect was `governance_review` (covers risk-
  escalated floors) — no new SideEffect enum member.
- **Side-effect producers (PIPE-09):** fired principles' declared `side_effects` (from
  `principles_meta`) → `Decision.side_effects` (dedup, order-stable); risk findings with non-empty
  `matched` → `risk_flag`; fail-open → `notify` (set in `_fail_safe`). Dispatch = one audit event
  per effect via `append_event("side_effect", {...})` + an optional callback sink (Protocol,
  default None). One decision can permit AND escalate (`allow + risk_flag` test).
- **Latency gate (PIPE-04):** the benchmark becomes CI-gating at the real budget — assert
  cached-path `pipeline.evaluate` p95 < 10 ms AND mean < 5 ms (current measured ~3 ms mean —
  headroom is real, not aspirational). Keep `-m latency`.

## File structure
- `packages/controlplane/src/agentos_controlplane/store/models.py` — + `ApprovalRequest`
  (id, action_id, agent_id, action_type, target, context JSON [redacted], reasons JSON, risk/trust,
  status: pending|approved|denied|timed_out, deadline_at, created_at, resolved_at, resolver,
  resolution_note), `TemporaryException` (id, agent_id, principle_ref, granted_by, approval_id?,
  expires_at, revoked bool, created_at), `GovernanceReview` (id, action_id, agent_id, summary,
  status open|closed, opened_at, closed_at). + Alembic `0002_approvals.py` (mirror 0001 style).
- New `packages/controlplane/src/agentos_controlplane/approvals.py` — `ApprovalStore`
  (create/get/list_pending/resolve/wait_resolved/active_exceptions(agent_id, refs)->dict/
  revoke/open_review/close_review), all over the session factory; `wait_resolved` async-polls.
- `packages/controlplane/src/agentos_controlplane/audit.py` — `append_event` (shares `_lock`,
  `_chain_head`, `_insert`).
- New `packages/controlplane/src/agentos_controlplane/api.py` — FastAPI `APIRouter`:
  `GET /approvals?status=`, `POST /approvals/{id}/resolve` {approved, resolver, note?,
  exception_expires_at?} (404 unknown, 409 already-resolved), `GET /reviews?status=`.
  `create_app(store) -> FastAPI` factory.
- `packages/pipeline/src/agentos_pipeline/runner.py` — `exceptions: ExceptionLookup | None = None`
  (sync Protocol: `active_for(agent_id, refs: tuple[str,...]) -> Mapping[str, datetime]`);
  exception transform in the policy stage; side-effect derivation; relabel-to-temporary_exception;
  `_fail_safe` adds `notify`.
- `packages/sdk/src/agentos_sdk/enforce.py` — outcome map; `ApprovalCoordinator` Protocol
  (`park_and_wait(action, decision) -> bool`, `open_review(action, decision) -> None`,
  `record_event/substitution`); `governed_call(pipeline, action, run, *, coordinator=None,
  dispatcher=None)`; `should_execute` retired (delete; update its tests to the map).
- `packages/sdk/src/agentos_sdk/middleware.py` + `wrappers.py` — unified onto the one enforcement
  core with an injected block-surfacing strategy (raise vs ToolMessage vs AIMessage).
- New `packages/controlplane/src/agentos_controlplane/coordinator.py` — the concrete
  `StoreApprovalCoordinator(store, audit, posture)` implementing the SDK Protocol (parks redacted
  request, waits, audits resolution/timeout, opens reviews, writes substitution/side-effect events).
- Tests: `tests/unit/test_approval_store.py`, `test_audit_events.py`, `test_resolve_api.py`,
  `test_outcome_enforcement.py`, `test_side_effects.py`, pipeline additions
  (exception transform/relabel), `tests/integration/test_approval_e2e.py`;
  `tests/benchmarks/test_latency_trend.py` tightened.

## Tasks (TDD; one commit each)

### 6a-1: store models + migration
Tests: rows round-trip on SQLite; status transitions constrained at the store layer (not DB).
### 6a-2: `append_event` audit events
Tests: event record chains correctly (prev_hash links into action records and back — append an
action record, an event, another action record; verify seq/prev_hash continuity + hash covers
kind); unknown-payload-key safety N/A (body is constructed, not attacker payload — but assert a
`kind` allowlist: unknown kind raises).
### 6a-3: `ApprovalStore`
Tests: create (context REDACTED via the audit redactor — a payload with a secret-bearing URL is
host-only in the stored row; unclassifiable payload key → RedactionError, row NOT created);
resolve approve/deny (409-style error on double-resolve); `wait_resolved` returns promptly after
a concurrent resolve (asyncio task resolves after 0.3s; wait with deadline 5s returns ~0.3s);
timeout path marks row `timed_out` and returns None; `active_exceptions` honors `expires_at >
now` (expired → absent = auto-revoke, POL-13) and `revoked`; resolve-with-
`grant_exception_until` creates the TemporaryException + `exception_granted` audit event.
### 6a-4: resolve API (API-03)
FastAPI TestClient: list pending; resolve approve (200, row updated, audit event written);
resolve again → 409; unknown id → 404; resolve deny with note; resolve with
exception_expires_at grants the exception.
### 6a-5: pipeline exception transform (POL-13)
Tests (real constitution engine fixture + injected `exceptions` lookup): deny floor (1.1 fired)
+ active exception for ("test-agent","1.1") → final outcome `temporary_exception`, `expires_at`
set, reason `temporary_exception_applied` with evidence refs, audit body carries expires_at
(already hash-covered from H3); same but risk ≥ deny_at → outcome deny (risk re-restricts —
defense in depth, floor_invariant intact); expired exception → plain deny; deny from TWO
principles with exception covering only one → deny (ALL deny refs must be covered); no lookup
injected → behavior unchanged.
### 6b-1: side-effect derivation (PIPE-09 producers)
Tests: principle with `side_effects: [notify]` fires → decision.side_effects contains notify;
risk finding matched → risk_flag added; allow + risk_flag coexist (permit AND escalate); dedup +
bounded; fail-open decision carries notify.
### 6b-2: outcome map + coordinator + middleware unification
Tests: approve flow e2e (require_approval decision → coordinator parks → concurrent resolve
approve → run() executes → resolution audit event); deny flow (GovernanceDenied, run not
called); timeout flow (fail-closed class → GovernanceDenied, row timed_out, `approval_timed_out`
event); no-coordinator → GovernanceDenied fail-closed (the old interim behavior, now explicit);
sandbox → escalates to approval path + `enforcement_substitution` event (and without coordinator
→ blocked); governance_review → run() executes AND review row opened + `review_opened` event
(non-blocking: no wait); temporary_exception outcome → executes; warn → executes; middleware
tool + model hooks show the SAME map behavior via the shared core (blocked ToolMessage/AIMessage
on require_approval-no-coordinator; parity test tool vs wrapper).
### 6b-3: dispatcher
Tests: each side effect on a decision → one `side_effect` audit event; optional sink callback
invoked; dispatch failures are contained (a raising sink → logged reason/event, never blocks the
action result, never raises into the caller).
### 6c-1: latency gate
Tighten `tests/benchmarks/test_latency_trend.py`: p95 < 10 ms AND mean < 5 ms asserted
(CI-gating); docstring updated (this IS the PIPE-04 gate). If the measured numbers regressed
above budget due to slice 6 work, FIX the hot path (chain-head caching inside the audit lock is
the pre-approved first lever) rather than loosening the budget; report numbers.
### Final gate
Full suite green; `-m floor_invariant` 430; `-m regression_lock` 10; report counts + measured
latency.

## Self-review checklist
POL-07 (park/block/resolve/timeout-to-posture, full context redacted) / POL-13 (human-only
grant, read-time auto-revoke, transform + relabel + risk-re-restrict, ALL-refs-covered rule) /
POL-14 (non-blocking review, survives escalation) / API-03 (resolve endpoints) / PIPE-09
(producers + dispatch + permit-and-escalate) / PIPE-04 (gating budget with headroom) / no
in-memory futures (kill-the-process resumability argument documented in approvals.py docstring)
/ enforcement lives ONCE (middleware unified; `should_execute` gone) / every lifecycle event in
the hash chain / floor invariant untouched.
