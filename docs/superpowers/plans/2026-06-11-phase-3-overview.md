# Phase 3 — Constitution, Graduated Response & Approvals — Decomposition & Design

> **For agentic workers:** This is the **overview / decomposition** doc for Phase 3. It locks the
> slice breakdown, the cross-cutting design decisions, and the requirement-coverage matrix. Each
> slice below gets its own detailed, TDD-bite-sized plan doc
> (`2026-06-11-phase-3-0N-<slug>.md`) written just-in-time **before** that slice is executed,
> using `superpowers:writing-plans`. Execute slices in order with
> `superpowers:subagent-driven-development` (or `executing-plans`).

**Goal:** Operators author a human-readable Constitution that compiles deterministically to
OPA/Rego; ambiguous cases get an advisory cited-principle rationale that can never relax the
deterministic floor; and the full graduated outcome spectrum — including human approval,
time-boxed exceptions, async governance review, composable side-effects, and trust-modulates-only
— is enforced within a held p95 latency budget.

**Architecture:** Extend the existing Phase 1/2 substrate (the `contract` boundary, the 4-stage
`Pipeline`, the `WasmPolicyEngine` behind the `PolicyEngine` Protocol, the hash-chained
`AuditWriter`, the one `governed_call` enforcement core) — no new top-level architecture. New
units: a deterministic **Constitution compiler** (`Constitution → YAML policy → Rego`), a
**SemanticInterpreter** Protocol (advisory, conditional, cached), an **ApprovalStore** +
lifecycle, and the control-plane's **own** compiled-policy/decision cache.

**Tech Stack:** Python 3.12, uv workspace, Pydantic v2, SQLAlchemy 2.0 on SQLite (Postgres is the
deferred production target — no Docker on this machine), `opa-wasmtime` + the pinned OPA CLI for
Rego→WASM, `anthropic` (structured outputs, behind a toggle; deterministic stub is the default),
pytest + a pytest-benchmark-style latency gate.

---

## Spec source (treated as approved)

- `.planning/ROADMAP.md` → Phase 3 goal + 4 success criteria.
- `.planning/REQUIREMENTS.md` → the 17 requirement IDs (below).
- `docs/architecture/04-constitution-and-policy.md`, `adr/0005-graduated-response-model.md`.
- `.planning/research/PITFALLS.md` → the P0-killer invariants wired in as tested gates.

**Phase 3 requirement set (17):** POL-01, POL-02, POL-04, POL-05, POL-07, POL-08, POL-13, POL-14,
PIPE-04, PIPE-05, PIPE-06, PIPE-08, PIPE-09, SEC-02, SEC-03, SEC-12, TRST-02, API-03.

> **Scope flag for review:** `.planning/research/SUMMARY.md` (non-authoritative) notes SEC-13
> (cross-action sequence-intent) was "pulled forward to Phase 3", but the authoritative
> `ROADMAP.md`/`REQUIREMENTS.md` keep **SEC-13 → Phase 8**. This plan follows the authoritative
> tables: **SEC-13 is NOT in Phase 3.** Override here if that's wrong.

---

## Cross-cutting design decisions (flagged for user sign-off)

These are not pinned by the requirements; they are the design forks I'm carrying in. All three are
doc- and pitfall-aligned. **Confirm or adjust before execution.**

### D1 — Constitution authoring = structured declarative YAML (deterministic compile)
Each numbered principle is structured YAML with a prose `statement` (preserved **verbatim** for
citation/audit) plus structured `applies_to` / `effect` / `when` fields. A **deterministic**
compiler lowers `Constitution → YAML policy → Rego` — **no LLM in the compile path** (the LLM is
only the *runtime* interpreter for ambiguity). Every generated Rego rule cites its principle id
(round-trip provenance); **deny-overrides-allow** conflict precedence is a Phase-3 invariant;
golden tests lock compiler output. *Rejected:* free-prose principles + LLM compiler (Pitfall 7
fidelity loss + non-deterministic, un-lockable policy generation).

### D2 — Semantic interpreter = pluggable Protocol, deterministic stub by default
A `SemanticInterpreter` Protocol mirrors the `PolicyEngine` toggle seam. Default impl is a
**deterministic stub** (used in all tests + offline — no network/key needed). An
**Anthropic structured-outputs** adapter sits behind the toggle. Invoked **only** on no-rule /
ambiguous results; verdicts cached by `(action-shape, principle-set, policy-version)`;
**advisory-only** — it can never upgrade an action above the deterministic floor (POL-05 /
Pitfall 5). Untrusted payload is passed as labelled *data*, never concatenated into instructions;
output is the typed `{outcome, principle_ref, rationale}`. *Decision for review:* wire the
Anthropic adapter now but keep the phase's acceptance tests green on the stub (no API key
required to pass CI).

### D3 — Approval workflow = SQLite ApprovalStore + in-process blocking with deadline
`require_approval` parks an `ApprovalRequest` (full action context, fired principles, risk/trust)
in the SQLite store and **blocks** the calling action via an in-process await-with-deadline,
resolving when an operator approves/denies **or** timing out to a **per-action-class safe
default** (high-risk → deny; PIPE-05). A **minimal resolve API** (API-03) approves/denies.
`temporary_exception` = a human-ratified, time-boxed `allow` (`expires_at` + auto-revoke);
`governance_review` = proceed now + enqueue an async, non-blocking review. The **full** declarative
API + dashboard remain Phase 5.

---

## Invariants (P0-killers — each becomes a tested CI gate)

| Invariant | Req | Where proven |
|-----------|-----|--------------|
| p95 cached-path latency budget (low single-digit ms), benchmark fails CI | PIPE-04 | Slice 6 |
| Control plane keeps its **own** compiled-policy/decision cache, invalidated on policy-version change (OPA doesn't cache) | PIPE-06 | Slice 3 |
| Per-action-class fail-closed posture; **no silent allow**; every fail-open is an audit record | PIPE-05 | Slice 3 |
| LLM interpreter advisory-only — never relaxes the policy floor | POL-05 | Slice 5 |
| Trust modulates only **within** a policy-defined band; never flips a policy deny | TRST-02 | Slice 1 |
| Every Decision pins the exact constitution/policy version (hash-covered in audit body) | POL-08 | Slice 3 |
| Every Decision is an explainable denial: `{principle_ref, rationale, evidence}` + `inferred_intent` + `remediation` | PIPE-08 | Slices 1 & 4 |
| Deterministic intent-class tags feed risk/policy, advisory-to-floor | SEC-12 | Slices 1 & 4 |
| `deny-overrides-allow` precedence; principle-citation provenance; golden compiler tests | POL-02 (Pitfall 7) | Slice 2 |

---

## Slice breakdown (execution order)

### Slice 1 — Contract & graduated-response vocabulary
**Goal:** Extend the stable contract for the full spectrum and teach the graduated stage to map it
while preserving the floor invariant. Pure `contract` + `pipeline` change; no external deps.
**Requirements:** PIPE-08 (Decision/Reason shape), PIPE-09 (`side_effects`), POL-13/POL-14 (outcome
vocabulary + constraints), TRST-02 (trust band), SEC-12 (`inferred_intent` field).
**Key files:** `packages/contract/.../decision.py` (Outcome += `temporary_exception`,
`governance_review`; new `SideEffect` enum; `Reason` += `principle_ref`, `rationale`, `evidence`;
`Decision` += `side_effects`, `inferred_intent`, `remediation`, `constitution_version`,
`policy_version`); `packages/pipeline/.../graduated.py` (policy-driven thresholds config + trust
band + new outcomes, floor invariant preserved); `runner.py` (populate new fields).
**Verification:** extended floor-invariant property sweep across **all** outcomes (risk×trust can
only restrict); contract serialization round-trip with `extra="forbid"`; trust-band unit tests.
**Depends on:** nothing (first; everything else imports the extended contract).

### Slice 2 — Constitution authoring + deterministic compiler
**Goal:** A structured-YAML Constitution and the deterministic `Constitution → YAML policy → Rego`
compiler, versioned by content hash, with principle-citation provenance and deny-overrides-allow.
**Requirements:** POL-01, POL-02 (and produces the version key POL-08 stamps).
**Key files:** new `packages/constitution/` package — `schema.py` (Pydantic Constitution/Principle),
`compiler.py` (lower → YAML policy → Rego), `version.py` (content-hash version); example
`constitution.yaml`; `tests/golden/` (constitution → expected Rego fixtures).
**Verification:** golden tests (byte-stable Rego per constitution); compiler determinism (same in →
same out); round-trip — every Rego rule cites a principle id; deny-overrides-allow conflict test;
compiled bundle builds via the pinned OPA CLI.
**Depends on:** Slice 1 (outcome vocabulary referenced by principle `effect`).

### Slice 3 — Policy-engine integration, own cache, version stamping, fail-closed posture
**Goal:** Run the compiled multi-principle Rego through `WasmPolicyEngine`; add the control plane's
own version-keyed cache; stamp constitution/policy version on every Decision + audit body;
implement per-action-class fail-closed posture with audited fail-opens.
**Requirements:** PIPE-05, PIPE-06, POL-08, POL-03 (extension beyond the single egress rule).
**Key files:** `packages/pipeline/.../policy.py` (multi-principle eval + cache); new
`cache.py` (compiled-policy/decision cache invalidated on version change); `runner.py` (posture +
version stamping); `packages/controlplane/.../audit.py` (populate `policy_version` in body — field
already reserved).
**Verification:** cache-hit + invalidation-on-version-change tests; kill-the-control-plane test
(high-risk class denies, fail-open writes an audit record); every-decision-pins-version test.
**Depends on:** Slices 1, 2.

### Slice 4 — Intent tags, baseline guardrails, pluggable scorers, remediation
**Goal:** Deterministic intent-class tagging feeding risk + `inferred_intent`; baseline PII/unsafe/
format guardrails as inline scorers; explicit cheap-inline / expensive-flagged tiering; derive
`remediation` paths on denials.
**Requirements:** SEC-02, SEC-03, SEC-12, PIPE-08 (remediation).
**Key files:** new `packages/pipeline/.../intent.py` (deterministic tagger); new
`risk/guardrails.py` (PII/unsafe/format scorers); `risk/__init__.py` + `aggregator.py` (tiering:
expensive scorers only when an inline flag fires); remediation derivation in `runner.py`.
**Verification:** intent-tag unit tests (e.g. `drop_table` → `DATA_DESTRUCTION`); PII/guardrail
scorer tests; tiering test (expensive scorer NOT called unless flagged); remediation-present-on-
deny test.
**Depends on:** Slice 1 (`inferred_intent`/`remediation` fields).

### Slice 5 — Semantic interpreter (advisory, conditional, cached)
**Goal:** The `SemanticInterpreter` Protocol + deterministic stub (default) + Anthropic adapter
(toggle), invoked only on ambiguity, cached, advisory-only, injection-resistant.
**Requirements:** POL-04, POL-05.
**Key files:** new `packages/pipeline/.../interpreter/` — `protocol.py`, `stub.py`,
`anthropic_adapter.py`, `cache.py`; `runner.py` (conditional invocation between policy and
graduated, advisory-only clamp).
**Verification:** advisory-only floor test (interpreter returns `allow` on a policy-escalated
action → floor still holds); injection-of-the-judge test (payload says "approved" → no upgrade);
cache-hit test; stub determinism; Anthropic adapter contract test (mocked, no network in CI).
**Depends on:** Slices 1, 2, 3.

### Slice 6 — Approval workflow, lifecycle outcomes, resolve API, latency gate
**Goal:** ApprovalStore + blocking-with-deadline; minimal resolve API (API-03); temporary_exception
expiry/auto-revoke; governance_review async queue; side-effect dispatch; the closing p95 latency
benchmark gate.
**Requirements:** POL-07, POL-13, POL-14, API-03, PIPE-04, PIPE-09 (dispatch).
**Key files:** `packages/controlplane/.../store/models.py` (`ApprovalRequest`,
`TemporaryException`, `GovernanceReview` tables + migration); new
`packages/controlplane/.../approvals.py` (store + resolve + expiry sweep); minimal resolve API
(FastAPI router, API-03); `packages/sdk/.../enforce.py` (`governed_call` handles all outcomes incl.
blocking approval); new `tests/.../test_latency_budget.py` (benchmark gate).
**Verification:** approval blocks→resolves→runs; approval times out → deny for high-risk;
temporary_exception auto-revokes at `expires_at`; governance_review proceeds + enqueues;
side-effect dispatch test; **p95 cached-path latency benchmark gates CI**.
**Depends on:** Slices 1, 3 (and benefits from 4, 5 being present for a realistic latency profile).

---

## Requirement coverage matrix

| Req | Slice(s) | Req | Slice(s) |
|-----|----------|-----|----------|
| POL-01 | 2 | PIPE-04 | 6 |
| POL-02 | 2 | PIPE-05 | 3 |
| POL-04 | 5 | PIPE-06 | 3 |
| POL-05 | 5 | PIPE-08 | 1, 4 |
| POL-07 | 6 | PIPE-09 | 1, 6 |
| POL-08 | 3 | SEC-02 | 4 |
| POL-13 | 1, 6 | SEC-03 | 4 |
| POL-14 | 1, 6 | SEC-12 | 1, 4 |
| API-03 | 6 | TRST-02 | 1 |

All 17 mapped, no gaps.

---

## Phase-close acceptance (maps to ROADMAP Phase 3 success criteria)

1. Operator authors numbered principles → compiler lowers to YAML → Rego, evaluated
   deterministically; exact policy/constitution version on every Decision. *(Slices 2, 3)*
2. No-rule/ambiguous → interpreter returns `{outcome, cited principle, rationale}`, never upgrades
   past the floor; every Decision carries `{principle_ref, rationale, evidence}` + `inferred_intent`
   + `remediation`; deterministic intent tags feed risk/policy. *(Slices 1, 4, 5)*
3. Graduated stage maps `{policy, risk, trust}` to the full 8-outcome spectrum with policy-driven
   thresholds, trust-within-band; `require_approval` parks a blocking `ApprovalRequest`;
   `temporary_exception` is a time-boxed auto-revoking allow; `governance_review` proceeds +
   async-reviews; Decisions carry composable `side_effects`. *(Slices 1, 6)*
4. p95 cached-path latency budget held (benchmark); own cache invalidated on version change;
   per-action-class fail-closed, no silent allow. *(Slices 3, 6)*
