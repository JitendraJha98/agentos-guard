# Phase 3 — Constitution, Graduated Response, Approvals & Sequence Intent — Decomposition & Design

> **For agentic workers:** This is the **overview / decomposition** doc for Phase 3. It locks the
> slice breakdown, the cross-cutting design decisions, and the requirement-coverage matrix. Each
> slice gets its own detailed, TDD-bite-sized plan doc (`2026-06-11-phase-3-0N-<slug>.md`) written
> just-in-time **before** that slice is executed, using `superpowers:writing-plans`. Execute slices
> in order with `superpowers:subagent-driven-development`.
>
> **Rev 2 (2026-06-11):** revised after a two-agent adversarial review (design + code). Major
> changes from rev 1: SEC-13 restored to scope (rev 1 misread the authoritative tables — the
> 2026-06-10 roadmap update pulled it INTO Phase 3 with a 5th success criterion); the policy
> I/O contract and ambiguity semantics are now locked here; `temporary_exception` is not an
> authorable effect; deterministic enrichment moved ahead of the policy stage; Slice 6 split
> into 6a/6b/6c; a new Slice 7 delivers SEC-13 + the wedge demo; an interim fail-closed
> enforcement posture for unrealized outcomes lands immediately (pre-Slice-2 hardening batch).

**Goal:** Operators author a human-readable Constitution that compiles deterministically to
OPA/Rego; ambiguous cases get an advisory cited-principle rationale that can never relax the
deterministic floor; the full graduated outcome spectrum — human approval, time-boxed exceptions,
async governance review, composable side-effects, trust-modulates-only — is enforced within a held
p95 latency budget; and sequence/lineage intent correlation (SEC-13) catches multi-step evasions
(`rename_then_drop`) no single action reveals, proven by a scripted 5-minute wedge demo.

**Architecture:** Extend the Phase 1/2 substrate (contract boundary, 4-stage pipeline,
`WasmPolicyEngine` behind the `PolicyEngine` Protocol, hash-chained `AuditWriter`, one
`governed_call` enforcement core). New units: a deterministic **Constitution compiler**
(`Constitution → YAML policy → Rego`), a deterministic **enrichment stage** (intent tags +
guardrail flags) feeding policy input, a **SemanticInterpreter** Protocol (advisory, conditional,
cached), an **ApprovalStore** + lifecycle (store-awaited blocking), a **sequence-intent
correlator** over lineage, and the control plane's **own** caches (compiled policy, identity,
interpreter verdicts — never whole Decisions).

**Tech Stack:** Python 3.12, uv workspace, Pydantic v2, SQLAlchemy 2.0 on SQLite (Postgres
deferred — no Docker on this machine), vendored OPA CLI v1.17.0 (`tools/opa/opa.exe`) +
`opa-wasmtime` for Rego→WASM, `anthropic` structured outputs behind a toggle (deterministic stub
default), pytest + latency benchmark gate.

---

## Spec source (treated as approved)

- `.planning/ROADMAP.md` → Phase 3 goal + **5** success criteria (incl. the SEC-13 wedge demo).
- `.planning/REQUIREMENTS.md` → the **19** requirement IDs below.
- `docs/architecture/04-constitution-and-policy.md`, `adr/0005-graduated-response-model.md`,
  `docs/architecture/30-comparison-agt.md` (wedge framing).
- `.planning/research/PITFALLS.md` → P0-killer invariants wired in as tested gates.

**Phase 3 requirement set (19):** POL-01, POL-02, POL-04, POL-05, POL-07, POL-08, POL-13, POL-14,
PIPE-04, PIPE-05, PIPE-06, PIPE-08, PIPE-09, SEC-02, SEC-03, SEC-12, **SEC-13**, TRST-02, API-03.

---

## Cross-cutting design decisions (locked)

### D1 — Constitution authoring = structured declarative YAML (deterministic compile)
Each numbered principle: a prose `statement` (preserved **verbatim** for citation/audit) +
structured `applies_to` / `effect` / `when` / optional `side_effects` fields. A **deterministic**
compiler lowers `Constitution → YAML policy → Rego` — no LLM in the compile path. Every generated
Rego rule cites its principle id (round-trip provenance); **deny-overrides-allow** (most-restrictive-
wins via the outcome ladder) is the conflict precedence; golden tests lock compiler output;
constitution version = content hash.

- **`when` condition language (closed algebra, not Rego-in-YAML):** `all` / `any` / `not`
  combinators over typed leaves `{field, op, value | list_ref}` with ops
  `eq / ne / in / not_in / prefix / glob / gte / lte`. Fields come ONLY from the versioned
  policy-input document (D4). Named list refs resolve to Rego data documents (like the existing
  egress allowlist). **No regex** (ReDoS on the hot path), no free expressions. Each leaf lowers
  mechanically to one Rego expression — deterministic and golden-testable.
- **Authorable `effect` values:** `deny | require_approval | require_consensus | sandbox |
  governance_review | warn | allow`. **`temporary_exception` is NOT authorable** (D5) — the
  schema rejects it (POL-13: human-ratified only).
- **`graduated:` section** in the Constitution configures `GraduatedThresholds` (risk bands +
  trust band) per action class — this is what makes ROADMAP's "policy-driven thresholds" and
  TRST-02's "policy-defined band" literally true. Compiled into policy data; plumbed in Slice 3.
- **Principle-declared `side_effects`** (e.g. `notify` on a sensitive allow) are the primary
  PIPE-09 producer; risk findings map to `risk_flag`; fail-open maps to `notify` (Slice 6b).

### D2 — Semantic interpreter = pluggable Protocol, deterministic stub by default
`SemanticInterpreter` Protocol mirrors the `PolicyEngine` toggle seam. Default = deterministic
stub (tests/offline, no network). Anthropic structured-outputs adapter behind the toggle. Invoked
**only** on ambiguity (D4: `no_match`); verdicts cached by `(action-shape, principle-set,
policy-version)`; **advisory-only** — can never upgrade above the deterministic floor (POL-05).
Untrusted payload passed as labelled *data*, never as instructions; typed output
`{outcome, principle_ref, rationale}`.
**Real-LLM validation (new in rev 2):** a `skipif(no ANTHROPIC_API_KEY)` live smoke suite — 2–3
canonical ambiguous actions + one injection-of-the-judge payload against the real model, asserting
typed parse + floor-holds — plus recorded request/response fixtures replayed deterministically in
CI, and a phase-close human-verify checkpoint with the real adapter (mirrors the Phase-1
opa-wasmtime checkpoint).

### D3 — Approvals = SQLite ApprovalStore + **store-awaited** blocking with deadline
`require_approval` parks an `ApprovalRequest` and blocks via `await store.wait_resolved(id,
deadline)` — the blocked coroutine awaits the **persisted row state**, never an in-process
future/Event, so the Phase-5 out-of-process resolve API is just another writer of the same row
(SQLite poll now; Postgres LISTEN/NOTIFY later behind the same seam). Timeout falls to the
**per-action-class posture default** — the same classification PIPE-05 uses (one classification,
not two). Minimal resolve API (API-03) approves/denies. **Approval rows are redacted with the
same fail-closed redactor as audit** before persistence (they would otherwise be the system's
first raw-payload table). Every approval resolution / timeout / revocation is itself an
`AuditRecord` (doc 04) — the audit writer gains a second record kind through the same hash chain
(Slice 6a).

### D4 — Policy I/O contract + ambiguity semantics (new in rev 2; the load-bearing seam)
- **Policy input** is a versioned document built by `build_policy_input(action)` (a dedicated
  builder, not inline runner code): `{type, target, intent: {class}, guardrails: {pii, unsafe,
  format}, …per-type fields (host for tool_call; operation/key for memory_access; server/tool for
  mcp_call; to_agent for delegation; model for model_invocation)}`. The compiler's golden tests
  and the runner share this one schema.
- **PolicyResult v2:** `{outcome floor, matched: [(principle_ref, effect, evidence)], no_match:
  bool}` — multi-principle, feeds the new `Reason` fields directly.
- **Ambiguity ≡ `no_match`.** Multi-match conflicts auto-resolve most-restrictive-wins (the
  ladder), which IS the escalating pick Pitfall 7 demands — never a silent branch choice.
- **The no-match floor = the per-action-class posture default** (PIPE-05's classification). This
  makes POL-05's "never upgrade past the floor" well-defined exactly where the interpreter runs.

### D5 — `temporary_exception` & `governance_review` semantics (new in rev 2)
- `temporary_exception` is **never** a policy-floor input: not authorable (D1), not produced by
  risk. An **active exception** is consumed as a pre-graduated transform: policy deny + matching
  unexpired `TemporaryException` row → floor becomes allow-with-exception-evidence; **risk still
  applies** (defense-in-depth — risk may override an exception); if the final gate allows, the
  outcome is *labelled* `temporary_exception` with `expires_at` set. Auto-revoke at expiry.
- Outcomes carry **obligations, not just restrictiveness**: when a `governance_review` floor is
  escalated upward by risk, the async review obligation is preserved as a `side_effect` so the
  review still opens. (ADR-0005's spectrum-vs-ladder divergence gets a note in the ADR.)
- **Interim enforcement posture (landing NOW, pre-Slice-2):** `should_execute(decision)` in the
  contract/SDK — executable outcomes are `{allow, warn, governance_review}`; everything else
  (sandbox, require_consensus, require_approval, temporary_exception pre-6a) **blocks fail-closed**
  with the substitution recorded as a `Reason`. Slices 6a/6b replace blocks with real semantics.
  This closes the window where the pipeline *says* `sandbox`/`require_approval` but the SDK *runs*
  the action (both reviews' top blocker). `warn` executes + advisory reason. Until RUN-03/POL-09
  exist (Phases 9), `sandbox`/`require_consensus` escalate to the blocking path — recorded
  honestly, never silently executed.

### D6 — Deterministic enrichment runs BEFORE policy (new in rev 2)
SEC-12 says intent tags feed **risk and policy**; principles must be able to reference
`intent.class` and guardrail flags (e.g. "deny PII egress"). So the sub-ms deterministic
enrichment (intent tagger + cheap guardrail pattern flags — pure CPU) runs as a pre-policy step
and its outputs are first-class policy-input fields (D4). Expensive scorers stay post-policy,
invoked only on inline flags (SEC-03). Pipeline stage order becomes:
`identity → enrichment → policy(+exception transform) → risk → [interpreter on no_match] → graduated`.

---

## Invariants (P0-killers — each a tested CI gate)

| Invariant | Req | Where proven |
|-----------|-----|--------------|
| p95 cached-path latency budget, benchmark fails CI (non-gating trend from Slice 3) | PIPE-04 | 6c |
| Own caches (compiled policy / identity / interpreter verdicts — never whole Decisions), invalidated on policy-version change AND exception expiry | PIPE-06 | 3, 5 |
| Per-action-class fail-closed posture; no silent allow; every fail-open is an audit record; pipeline-failure → deny + payload-free audit record | PIPE-05 | 3 |
| Unrealized outcomes never silently execute (interim `should_execute` allowlist) | PIPE-05/POL-07 | hardening batch (now) |
| Interpreter advisory-only — never relaxes the floor; no-match floor = class posture | POL-04/05 | 5 |
| Trust modulates only within the policy-defined band; never flips a policy deny | TRST-02 | 1 ✅ (band config: 2, 3) |
| Every Decision pins exact constitution/policy version (hash-covered) | POL-08 | 3 |
| Audit body covers ALL Decision fields via fail-closed field allowlist (completeness guard) | AUD-01 seed | hardening batch (now) |
| Explainable denial: `{principle_ref, rationale, evidence}` + `inferred_intent` + `remediation` | PIPE-08 | 1 ✅, 3, 4 |
| Deterministic intent tags feed risk AND policy, advisory to floor | SEC-12 | 3 |
| deny-overrides-allow precedence; principle-citation provenance; golden compiler tests | POL-02 | 2 |
| Sequence evasion (`rename_then_drop`) denied with cited principle + remediation; wedge demo | SEC-13 | 7 |

---

## Slice breakdown (execution order)

### Hardening batch (pre-Slice-2, immediate)
Closes the review blockers cheaply before richer floors become producible:
`should_execute` interim posture in the one enforcement core + both middleware hooks; strict-JSON
`evidence` validation (no `default=str`) + URL-content rejection; audit body extended to ALL
Decision fields + fail-closed completeness guard + `model_dump(mode="json")`; `GraduatedThresholds`
constructor-injected through `Pipeline`; low-trust hardening step retargeted `sandbox →
require_approval` (human-in-loop instead of hard deny); tz-aware `expires_at` validator; bounds on
`detail`/`remediation`/`inferred_intent`; stale docstrings.
**Verification:** new unit tests per fix; full suite green.

### Slice 2 — Constitution authoring + deterministic compiler (POL-01, POL-02)
New `packages/constitution/`: Pydantic schema (statement verbatim; `when` algebra; authorable
effects excluding `temporary_exception`; `graduated:` thresholds section; principle `side_effects`),
deterministic compiler → YAML policy → Rego (every rule cites its principle id), content-hash
version, example constitution incl. the wedge principles (PII-egress deny; `rename_then_drop`
forbidden-sequence declaration for Slice 7), golden tests (byte-stable Rego), deny-overrides-allow
conflict test, bundle builds via vendored OPA CLI. **Also defines (as code-adjacent docs + types):
the D4 policy-input schema and PolicyResult v2.**
**Verification:** golden tests; determinism; provenance round-trip; precedence test; WASM build.

### Slice 3 — Enrichment + policy integration, caches, versions, posture (SEC-12, PIPE-05/06, POL-08)
Deterministic intent tagger (e.g. `drop_table`→`DATA_DESTRUCTION`) + cheap guardrail flags as the
pre-policy enrichment stage; `build_policy_input` builder; multi-principle `WasmPolicyEngine`
returning PolicyResult v2; compiled-policy + identity caches keyed/invalidated by version;
constitution/policy version stamped on every Decision + audit body; per-action-class posture map
(used by: fail-closed on unavailability, no-match floor, approval-timeout default) with every
fail-open an audit record; pipeline-failure semantics (RedactionError et al. → deny + payload-free
audit record); redactor digests non-str payload values; thresholds loaded from compiled
`graduated:` config. Non-gating latency trend benchmark starts here.
**Verification:** cache-hit + invalidation tests; kill-the-control-plane test; version-pinned test;
enrichment-feeds-policy test (a principle conditioned on `intent.class` fires); posture-map tests.

### Slice 4 — Guardrail scorers + tiering + remediation (SEC-02, SEC-03, PIPE-08)
PII/unsafe/format scorers (inline, pure CPU) wired into both enrichment flags and risk findings;
explicit cheap-inline / expensive-flag-gated tiering with a test proving expensive scorers don't
run unflagged; remediation derivation on denials (from fired principle → concrete next steps).
**Verification:** scorer unit tests; tiering test; remediation-present-on-denial test.

### Slice 5 — Semantic interpreter (POL-04, POL-05)
Protocol + stub (default) + Anthropic structured-outputs adapter; invoked only on `no_match`;
verdict cache (keyed by action-shape, principle-set, policy-version); advisory clamp to the
class-posture floor; payload-as-data prompt structure; live key-gated smoke suite + recorded
fixtures + phase-close human-verify checkpoint (D2).
**Verification:** advisory-only floor test; injection-of-the-judge test; cache test; stub
determinism; live smoke (key-gated).

### Slice 6a — Approval workflow + exception/review lifecycle (POL-07, POL-13, POL-14, API-03)
`ApprovalRequest`/`TemporaryException`/`GovernanceReview` tables (approval rows redacted
fail-closed); `await store.wait_resolved(id, deadline)` blocking seam; timeout → class-posture
default; minimal FastAPI resolve router; exception pre-graduated transform + auto-revoke sweep;
review queue (non-blocking); approval-lifecycle audit record kind through the same hash chain.
**Verification:** block→resolve→run; block→timeout→class default; exception grant/consume/expire;
review opens without blocking; lifecycle events in the audit chain.

### Slice 6b — Side-effect derivation + dispatch; real outcome map; middleware unification (PIPE-09)
Side-effect producers (principle-declared, risk→`risk_flag`, fail-open→`notify`, escalated
review→side-effect) and the dispatcher; replace the interim `should_execute` block with the real
outcome→enforcement map (warn=execute+advisory; sandbox/require_consensus=escalate-to-approval
until Phases 9, recorded as a Reason); refactor `middleware.py` hooks onto the one enforcement
core (block-surfacing strategy injected) so outcome semantics live once.
**Verification:** dispatch tests per producer; outcome-map tests incl. the honest-substitution
Reason; middleware/wrapper parity test.

### Slice 6c — Latency gate (PIPE-04)
p95 cached-path benchmark becomes CI-gating; audit chain-head in-memory cache (single-writer lock
seam) + any profile-directed fixes if the budget fails.
**Verification:** the benchmark gate itself.

### Slice 7 — Sequence-intent correlator + wedge demo (SEC-13)
Windowed per-conversation/lineage correlator over `parent_action_id`/`conversation_id` (already
persisted in the audit body) matching last-N intent-class sequences against forbidden sequences
declared as Constitution principles (Slice 2 schema); fires into risk + policy as a deterministic
signal (advisory to floor); the scripted 5-minute `rename_then_drop` wedge demo: each action
individually allowed, the sequence denied with cited principle + remediation.
**Verification:** correlator unit tests (`rename_then_drop`, copy-then-delete); end-to-end wedge
demo test; demo script in `examples/`.

---

## Requirement coverage matrix

| Req | Slice(s) | Req | Slice(s) |
|-----|----------|-----|----------|
| POL-01 | 2 | PIPE-05 | 3 (+ hardening batch) |
| POL-02 | 2 | PIPE-06 | 3, 5 |
| POL-04 | 5 | PIPE-08 | 1 ✅, 3, 4 |
| POL-05 | 5 (floor def: 3) | PIPE-09 | 1 ✅, 2, 6b |
| POL-07 | 6a | SEC-02 | 4 |
| POL-08 | 3 | SEC-03 | 4 |
| POL-13 | 1 ✅, 6a | SEC-12 | 3 |
| POL-14 | 1 ✅, 6a, 6b | SEC-13 | 7 |
| API-03 | 6a | TRST-02 | 1 ✅ (config: 2, 3) |
| PIPE-04 | 6c (trend from 3) | | |

All 19 mapped, no gaps. (Slice 1 ✅ = completed 2026-06-11: contract spectrum, Reason/Decision
fields, floor-preserving graduated_response + trust band, floor-invariant sweep.)

---

## Phase-close acceptance (maps to ROADMAP Phase 3 success criteria 1–5)

1. Constitution → YAML → Rego deterministic; exact versions on every Decision. *(2, 3)*
2. Interpreter `{outcome, cited principle, rationale}` advisory-only; explainable denials with
   intent + remediation; intent tags feed risk and policy. *(3, 4, 5)*
3. Full 8-outcome spectrum with policy-driven thresholds, trust-within-band, blocking approvals,
   auto-revoking exceptions, non-blocking reviews, composable side-effects. *(1 ✅, 6a, 6b)*
4. p95 budget held; own caches invalidated on version change; per-class fail-closed, no silent
   allow. *(3, 6c)*
5. `rename_then_drop` sequence denied with cited principle + remediation; 5-minute wedge demo.
   *(7)*
