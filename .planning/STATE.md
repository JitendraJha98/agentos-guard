---
gsd_state_version: 1.0
milestone: v1.0
milestone_name: milestone
status: phase_in_progress
stopped_at: 2026-08-11 — Phase 9 COMPLETE (6/6 slices) on branch phase-9-runtime-containment-consensus, pending PR into development. Every graduated outcome now has real enforcement (the sandbox/require_consensus approval substitution is retired). Phase 6's OSS-01 (first tagged PyPI release) remains the sole open item across Phases 6-9; Phase 10 not started.
last_updated: 2026-08-11
last_activity: 2026-08-11
progress:
  total_phases: 14
  completed_phases: 8
  total_plans: 49
  completed_plans: 49
  percent: 61
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-06-01)

**Core value:** Every agent action is intercepted at runtime and returned an explainable, graduated decision grounded in policy + a human-readable constitution, with tamper-evident audit evidence — making unsafe agent behavior structurally impossible rather than merely unlikely.
**Current focus:** Phase 10 — Gateway PEP, Second Adapter & Live Graph (not started). Phase 9 complete, pending PR.

## Current Position

Phase: 9 COMPLETE (2026-08-11) — branch `phase-9-runtime-containment-consensus`, pending PR into `development`
Plan: Phase 9 delivered as 6 slices covering all 6 requirements — 9a RUN-03 sandbox/quarantine, 9b RUN-04 privilege rings, 9c RUN-05 resource isolation, 9d RUN-06 circuit breakers, 9e RUN-07 emergency shutdown, 9f POL-09 2-of-3 consensus. Built via the superpowers workflow (spec -> per-slice plan -> subagent implement + two-stage adversarial review + fix + re-review).
Status: Phases 1–5, 7, 8, 9 complete; Phase 6 ~5/6 (OSS-01 first PyPI release the sole open item). Phase 10 not started.
Last activity: 2026-08-11

Progress: [████████████] 8/14 phases fully done (1–5, 7, 8, 9) + Phase 6 ~5/6

## Performance Metrics

**Velocity:**

- Total plans completed: 26
- Average duration: —
- Total execution time: 0 hours

**By Phase:**

| Phase | Plans | Total | Avg/Plan |
|-------|-------|-------|----------|
| 1 | 6 | - | - |
| 2 | 1 | - | - |
| 3 | 7 | - | - |
| 4 | 6 | - | - |
| 5 | 6 | - | - |

**Recent Trend:**

- Last 5 plans: —
- Trend: —

*Updated after each plan completion*
| Phase 01 P01 | 5 | 3 tasks | 13 files |
| Phase 01 P02 | 25 | 2 tasks | 19 files |
| Phase 01 P03 | 20 | 1 tasks | 11 files |
| Phase 01 P04 | 18 | 2 tasks | 8 files |
| Phase 01 P05 | 5 | 2 tasks | 6 files |
| Phase 01 P06 | 11 | 3 tasks | 13 files |

## Accumulated Context

### Decisions

Decisions are logged in PROJECT.md Key Decisions table.
Recent decisions affecting current work:

- [Roadmap]: 14 fine-grained vertical-slice phases. Phases 1–6 = Phase-0 parity loop, 7–12 = Phase-1 substrate, 13–14 = hard-gated Phase-2 moonshot.
- [Roadmap]: P0-killer invariants wired into early phases as acceptance criteria — contract-first (Phase 1), latency budget + no-silent-allow + own-cache + advisory-only interpreter + trust-modulates-only (Phase 3), fail-closed redaction + CI verifier + anchoring (Phase 4).
- [Roadmap]: Phase 14 is explicitly gated on the full P0/P1 substrate passing verification (latency held, audit externally verifiable, coverage matrix green, red-team gating CI).
- [Phase 1]: [01-01] Contract package built first with zero internal dependencies (D-08/PIPE-07) — the stable serializable boundary every PEP form plugs into.
- [Phase 1]: [01-01] Audit store seam is SQLite-backed (D-14 no-Docker deviation); opa-wasmtime/wasmtime gated to plan 01-04 (A1), not installed this wave.
- [Phase 1]: [01-02] EdDSA (Ed25519) JWT identity engine — verify uses explicit algorithms=[EdDSA] allowlist (GHSA-ffqj-6fqr-9h24), iss+sub+registered checks (IDN-01/IDN-02 seed).
- [Phase 1]: [01-02] Hash-chained audit writer (AUD-01): monotonic hash-covered seq, prev_hash links, canonical JSON, fail-closed redaction (D-15); SQLite Store, Postgres models retained as production target (D-14).
- [Phase 1]: [01-03] SEC-01 prompt-injection detector is stdlib re + Pydantic only — inline=True, sub-ms, ReDoS-safe, no LLM/model/network on the hot path (P0-killer, D-12); patterns compiled once at construction.
- [Phase 1]: [01-03] Detector is advisory-only and stateless — normalize() (NFKC + zero-width strip + base64) runs before matching; out-of-scope evasion (typoglycemia/sharded/paraphrase) honestly strict-xfail; 32 KB bounded input with recorded truncation.
- [Phase 1]: [01-04] opa-wasmtime locked (>=0.1.1,<0.2) + wasmtime>=27 after the human-verify checkpoint — the locked opa-wasm was Python-3.12-incompatible (stale wasmer dep); no wasmer in the resolution (POL-03/D-05).
- [Phase 1]: [01-04] WasmPolicyEngine behind a runtime_checkable PolicyEngine Protocol — OPAPolicy loaded ONCE at construction (Pitfall 2), allowlist injected as a Rego data document (set_data); evaluate() extracts result[0]['result'] and fails closed. egress.rego is deny-by-default; compiled egress.wasm is a gitignored CI/build artifact (D-06).
- [Phase 1]: [01-05] The 4-stage PDP (Pipeline.evaluate) orders identity->policy->risk->graduated into one Decision with per-stage machine-readable reasons (PIPE-01/02); forged/unknown identity short-circuits to a terminal, audited deny without running later stages (PIPE-03/IDN-02).
- [Phase 1]: [01-05] graduated_response enforces the floor invariant (POL-05/TRST-02) — a policy deny is terminal; risk/trust may only RESTRICT (proven by a risk x trust property sweep marked floor_invariant). Trust loaded in stage 1 feeds graduated but never overrides policy (TRST-01/POL-06).
- [Phase 1]: [01-05] agentos-pipeline keeps its single internal dependency on agentos-contract — the identity engine, policy engine, and audit writer are injected and typed via structural Protocols (same toggle discipline as PolicyEngine); no control-plane import in the pipeline package.
- [Phase 1]: [01-06] The SDK PEP (GovernanceMiddleware.awrap_tool_call) intercepts http_get tool calls, normalizes to AgentAction, awaits the 4-stage pipeline, and enforces allow (run handler) / deny (ToolMessage WITHOUT calling handler => no egress, D-03). INT-01/SDK-01.
- [Phase 1]: [01-06] Open Q2 RESOLVED — langchain 1.3.2 exposes awrap_tool_call (async); chose the async path so the pipeline + async audit write run in the LangGraph loop with no nested asyncio.run. SDK depends on contract + pipeline only (no PEP-in-PDP leak, Anti-Pattern 5).
- [Phase 1]: [01-06] D-04 red-team regression lock GREEN — WITH the egress principle the exfil probe is denied (egress_allowlist_violation); deleting the principle (allow-all engine, since an empty allowlist still denies by default) flips the same-host probe (benign body, to isolate floor from the risk stage) to allow and turns the deny test RED (CI-break proof verified). The Walking Skeleton is closed.

- [Phase 2]: Five action types governed via TWO interception shapes — LangChain native middleware hooks for tool (`awrap_tool_call`) + model (`awrap_model_call`, INT-02), and SDK async wrappers for memory/MCP/delegation (INT-03/04/05) since LangChain v1 exposes no middleware hook for those boundaries (matches docs/architecture/03 "middleware/decorators").
- [Phase 2]: All five forms share ONE enforcement core (`agentos_sdk/enforce.governed_call`) so allow/deny never diverges; deny raises `GovernanceDenied` (governed exception carrying the Decision) WITHOUT running the operation (no side effect / no egress).
- [Phase 2]: INT-06 coverage = a `@covers(ActionType)` registry populated at import (static gap -> `verify_coverage()` raises) PLUS a runtime bypass test (no-identity action -> fail-closed deny via IDN-02). No silent gaps.
- [Phase 2]: Egress principle scoped to `tool_call` egress (egress.rego + rebuilt WASM); non-tool types pass the floor (`no_egress_policy_applicable`) and get real policies in Phase 3 — Phase-1 deny-by-default tool gate (D-04) untouched.
- [Phase 2]: Audit redactor (D-15 fail-closed) extended to the four new payload shapes — identifiers verbatim, free-text/secret fields (messages/value/args/task) digested; `parent_action_id`+`conversation_id` persisted in the audit body (INT-05 lineage; AUD-09 seed).

- [Phase 7]: [7a] TRST-03 reputation = time-decayed Beta posterior (half-life 7d) over audit outcomes + human approval rulings, MIN'd with an anti-farming violation ceiling `1/(1+bad)`. The ceiling is the design's point: good conduct is diluted by volume, a violation is not, so 1000 allows cannot wash out one fresh deny (Pitfall 10). Only time heals. No history -> the seed, never an invented opinion.
- [Phase 7]: [7a] `Registry.load_trust` now resolves TrustProfile -> Agent seed -> 0.0. Before this, operator-graded trust (the gated `PUT /trust-profiles` route) never reached the pipeline — a pre-existing disconnect TRST-03 depends on.
- [Phase 7]: [7b] TRST-04 delegation = `min(child_trust, parent_trust*decay)` + scope INTERSECTION. Both halves are anti-escalation: the cap kills trust laundering (a 0.05-trust principal borrowing a trusted delegate's standing would bypass TRST-03 in one hop); intersection stops a delegation conjuring a capability neither party held. Unknown lineage FAILS CLOSED — a ledger miss must never be an escalation channel. In-process ledger is non-persistent (documented; distributed form is future work).
- [Phase 7]: [7c] IDN-03 = per-agent Ed25519 keypair + CA-issued X.509 with a SPIFFE-shaped URI SAN (`agentos://agent/<id>`), so IDN-04 is a change of scheme, not model. Control plane NEVER stores the agent private key. Real CRL; re-enroll rotates but does not auto-revoke (else a shared-token holder could knock out a healthy agent's cert).
- [Phase 7]: [7d] API-04 reconcilers report items CHANGED (zero == converged), isolate failures (a dead loop rots derived state silently — worse than a noisy one), and run via `asyncio.to_thread` since they do blocking DB I/O. CacheReconciler fires only on version change.

- [Phase 8]: All detectors follow the Phase-2 guardrail discipline (stdlib re compiled once, ReDoS-safe, pure CPU, no model/network; `matched` = pattern IDs, never raw payload). SEC-04/05/09/11 join the enrich() guardrail tier; new `guardrails.*` flags added to POLICY_INPUT_FIELDS in LOCKSTEP with the emitting flag (drift-locked test).
- [Phase 8]: [8a] Exfiltration (SEC-04) grades by DATA CLASS to honor "untrusted targets" without re-implementing the allowlist: a SECRET is 0.6 to any external host (a credential must never egress anywhere), PII stays advisory 0.35 (PII egress to an APPROVED host is the legit case the Phase-2 invariant protects; the egress floor denies PII to unapproved hosts). Preserved the "PII to allowlisted host stays allow" invariant.
- [Phase 8]: [8c] Memory-poisoning (SEC-09) is distinct from prompt_injection precisely because memory PERSISTS — it fires only on memory_access and raises `guardrails.memory_poison` so a constitution can hold STORED instructions to a stricter standard than transient ones. Poisoned READ flagged as well as WRITE.
- [Phase 8]: [8d] SEC-10 pipeline stages now 1b (delegation trust) / 1c (agent card) / 1d (MCP quarantine) — all injected, structural, None-default, terminal-audited denies. The fail-closed fail-safe caught a missing-import bug in 1c during dev (denied not allowed) — defensive posture working.
- [Phase 8]: [8e] ABOM-02 component DIGEST (canonical-JSON sha256) is the load-bearing field — SEC-06 drift + SEC-08 known-bad both consume it. merge_components preserves provenance (unchanged keeps first_seen/version; drift bumps + dates). Raw Phase-5 put_abom path untouched (provenance form under a reserved key).
- [Phase 8]: [8g] MCP gateway quarantine is STICKY — a rug-pull can't un-poison by serving a clean manifest; only operator release lifts it. Note: `(?m)` inline-flag mid-regex is illegal on Python 3.11+ — use `re.MULTILINE`.
- [Phase 8]: [8h] SEC-14 is ambiguity-gated (runs only when the deterministic SEC-12 tag is None) and STRICTLY advisory — a probabilistic match becomes an inferred_intent label + advisory risk finding (0.5, sandbox-at-most), NEVER a deterministic policy floor. Follows the POL-04 interpreter precedent: offline HashingEmbedder default (honest lexical proxy, NOT semantic) + pluggable real adapter behind the Embedder Protocol.

### Pending Todos

[From .planning/todos/pending/ — ideas captured during sessions]

None yet.

### Blockers/Concerns

[Issues that affect future work]

- **OPERATOR-VISIBLE BEHAVIOR CHANGE (Phase 9, Slice 9a — RUN-03): mid-risk actions are no longer approvable.** `sandbox` used to be substituted onto the approval path, so a mid-risk action parked for a human, could be approved, and then executed. It is now enforced through the new `SandboxRunner` seam: the real handler is NEVER awaited, so the action is contained rather than approvable. **Any deployment that wires a coordinator but not a sandbox runner must add one** — `GovernanceMiddleware(pipeline, token, sandbox=QuarantineSandbox(session_factory, audit))` — or every `sandbox` outcome (the default band above `sandbox_at=0.4`, plus every `allow` hardened by low trust) fails closed as a hard `Blocked by agentos-guard` with no approval request and no `sandbox_run` containment record. Wiring shown in `packages/sdk/README.md` and run end-to-end by `agentos_sdk.quickstart`. Contained outcomes now also return `ToolMessage(status="error")`, so a consumer branching on LangChain's tool-failure convention no longer reads a quarantine as a success.
- **EU AI Act clock (hard external date):** high-risk obligations bind **2026-08-02**. CMP-03 (minimal Art. 12/26 evidence claim) is **delivered** (PR #16 — `agentos_controlplane.compliance.export_compliance_evidence` + CLI). Resolved.
- **AGT re-verification — DONE 2026-07-17 (Phase-7 start), debt cleared.** AGT is still **v4.1.0 (2026-06-09)**; no release in five weeks, so every shipped-feature claim in `30-comparison-agt.md` re-confirmed accurate. **Material finding:** their `LIMITATIONS.md` future-work section now commits to *workflow-level sequence policies* and *intent declaration*, so the "no cross-action correlation" gap is **downgraded Durable → Contested** (their stateless kernel is not, by their own account, a structural blocker) and a new *Contested* row was added for intent validation. Roadmap ordering is **unaffected** (Phases 7–8 bet on neither claim); what changes is claim *language* — "we ship it, they plan it," never "they can't build it." Scorecard updated. **Still open:** the garak/PyRIT/OTel-GenAI version-pin re-check was NOT done as part of this pass.
- **OSS distribution — partially closed (2026-07-12):** OSS-02 done (SECURITY.md, CONTRIBUTING.md, issue/PR templates added). OSS-01 scaffolded (`.github/workflows/release.yml`, PyPI Trusted Publishing) but **not yet publishing** — needs the PyPI-side Trusted-Publisher config for each package and a first `vX.Y.Z` tag off `main`. Until then the quickstart's "single pip install" is still only true inside this repo.
- **OTel GenAI semconv (Phase-6 carryover):** the telemetry seam uses custom `agentos.*` span-attribute keys, not the OTel GenAI `gen_ai.*` semantic conventions the 6a design flagged, and the `opentelemetry-semantic-conventions` pin the spec called for was not added. Standard `gen_ai.*` attributes would let operators reuse off-the-shelf OTel GenAI dashboards — an adoption edge worth a small follow-up (attribute names are already centralized in `telemetry.py`, so it is a one-file change).
- Research-flagged spikes likely needed at plan time: Phase 3 Constitution→YAML→Rego compiler fidelity/precedence; Phase 4 audit external-anchoring + fail-closed-redaction last gate; Phase 8 ASI05/06/07 detector design; Phase 7 multi-node cache invalidation; all of Phases 13–14 (LOW-confidence moonshot tech — evaluate before commit).
- Competitive framing (confident-but-honest, ADR-0007 + `docs/architecture/00-manifesto.md`): paradigm = *Trust→Verify→Graduate→Prove* vs AGT's *Distrust→Block→Log*, carried by **seven pillars** (semantic constitution, graduated response, intent-based policy, cross-agent permission calculus, explainable denials w/ remediation, CI-gating red-team + self-play, provable audit). Phase 0 reaches AGT parity + already out-features it on graduated/semantic/CI-gating; the full "beat" compounds as pillars land. Crypto-economics (blockchain/staking/MPC) fenced out of core; only token-free Merkle/ZK kept (optional/Phase-2).

## Deferred Items

Items acknowledged and carried forward from previous milestone close:

| Category | Item | Status | Deferred At |
|----------|------|--------|-------------|
| *(none)* | | | |

## Session Continuity

Last session: 2026-06-01T19:36:11.235Z
Stopped at: Completed 01-06-PLAN.md
Resume file: None
