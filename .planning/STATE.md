---
gsd_state_version: 1.0
milestone: v1.0
milestone_name: milestone
status: phase_in_progress
stopped_at: 2026-08-19 — Phase 12 COMPLETE (6/6 slices), still on branch phase-10-gateway-adapter-graph (the operator asked Phases 11 and 12 to continue there), pending PR into development. Red-team moved from a one-shot CI claim to a continuous one with trends, campaigns exercise the SEC-13 correlator no single-shot probe can reach, health and the query-time evidence graph give an operator something to read before and after a failure, and all of it surfaces on the console. Phase 6's OSS-01 (first tagged PyPI release) remains the sole open item across Phases 6-12; Phase 13 not started.
last_updated: 2026-08-19
last_activity: 2026-08-19
progress:
  total_phases: 14
  completed_phases: 11
  total_plans: 67
  completed_plans: 67
  percent: 82
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-06-01)

**Core value:** Every agent action is intercepted at runtime and returned an explainable, graduated decision grounded in policy + a human-readable constitution, with tamper-evident audit evidence — making unsafe agent behavior structurally impossible rather than merely unlikely.
**Current focus:** Phase 13 — Constitution Amendments & Conflict Reasoning (not started). Phases 9-12 complete; all pending PR.

## Current Position

Phase: 12 COMPLETE (2026-08-19) — branch `phase-10-gateway-adapter-graph` (Phases 11 and 12 continued there at the operator's request), pending PR into `development`
Plan: Phase 11 delivered as 6 slices covering all 7 requirements — 11a AUD-06 Merkle audit, 11b ECON-01 cost attribution, 11c ECON-02 budget as policy, 11d ECON-03 GPU/downstream attribution, 11e CMP-04/05 EU AI Act + SOC 2, 11f CMP-06 evidence export. Built via the superpowers workflow (spec -> per-slice plan -> subagent implement + two-stage adversarial review + fix + re-review). EVERY slice came back NOT APPROVED on its first review pass; the findings were real and the reasoning is recorded in the commit messages.
Status: Phases 1–5, 7–12 complete; Phase 6 ~5/6 (OSS-01 first PyPI release the sole open item). Phase 13 not started.
Last activity: 2026-08-19

Progress: [███████████████] 11/14 phases fully done (1–5, 7–12) + Phase 6 ~5/6

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

- [Phase 9]: [9a] `sandbox` is CONTAINMENT, not an approval path — see the operator-visible behavior change under Blockers.

- [Phase 10]: [10a] INT-07 gateway = a reverse proxy in front of the model/tool endpoint, so an agent in ANY language/framework is governed with no SDK in its process. The governed target IS the forwarded target — resolved once, decided on, then sent — because a proxy that decides on one URL and forwards another has no enforcement at all, only a log.
- [Phase 10]: [10a] The gateway reuses `governed_call` rather than re-implementing outcomes, so a new PEP form can never drift from the SDK's allow/deny/sandbox/consensus semantics. Upstream faults propagate OUT of the governed callable (the 502 is built outside it) so RUN-06 circuit breakers still see the failure they exist to count.
- [Phase 10]: [10b] INT-08 = OpenAI Agents SDK adapter, governing the arguments the tool BODY receives (post-parse), not a pre-normalization copy — governing a different value than the one that executes is the same TOCTOU class as 10a's target bug.
- [Phase 10]: [10b] INT-06 coverage registry became `dict[ActionType, set[str]]` — with two adapters, a single owner per action type would have silently overwritten one PEP's claim and hidden a real gap behind a green check.
- [Phase 10]: [10c] DISC-03 detection resolves against INSTALLED distributions (`importlib.metadata`), never a stray import name — a false positive puts a framework in the operator's inventory that is not there, which is worse than silence.
- [Phase 10]: [10d/10e] Discovery output is BOUNDED with visible overflow (`<overflow>`), because every input is attacker-controlled: shadow identities come from unregistered callers and rogue components from caller-supplied manifests. Silent truncation would read as "nothing more to see"; overflow says otherwise.
- [Phase 10]: [10e] DISC-05 separates "never declared anything" from "declared and exceeded" via observed-class provenance — without it, every agent that has not published a manifest floods the finding stream on first contact and the signal drowns.
- [Phase 10]: [10f] DISC-06 builds only from IDENTITY-VERIFIED actions and advances a watermark (incremental, not a full rescan). The read returns a subgraph that is bounded AND closed — an edge is admitted only while both endpoints fit the node budget, since a view containing edges to absent nodes is wrong, not partial. **Lineage is CLAIMED, not proven:** `identity_verified` authenticates who ACTED, not that `parent_action_id` names a real delegation; closing that half needs the TRST-04 authority cross-check (Phase 13).

- [Phase 11]: [11a] AUD-06 is ADDITIVE — an RFC-6962 tree over `record_hash` values the chain already holds. Replacing the chain would have invalidated the very evidence the phase exists to make provable. `verify_bundle` is what an auditor runs; `verify_inclusion` alone binds only a hash and must never be handed to one. A root proves INCLUSION, not COMPLETENESS: no root can testify that nothing was withheld before sealing (witness quorum, Phase 14).
- [Phase 11]: [11a] The epoch row is attacker-writable, so the verifier measures it against the chain's own `merkle_epoch_sealed` announcement — and requires that announcement to be SIGNED, because appending is free and only signing is not. Deleting an epoch row is caught too: the chain still announces the epoch, so a missing row is a violation rather than a check that silently did not run.
- [Phase 11]: [11b] Usage is REPORTED, never inferred. Unrecognized usage records NOTHING (not zero — "free" and "unknown" must not collapse), an unpriced model keeps its tokens with a null cost, and usage is refused from any result a provider did not vouch for: an untrusted tool/MCP result forged $1.25M onto one call in review. Money is integer micro-USD because 11c makes DECISIONS on the sum.
- [Phase 11]: [11c] ECON-02's claim is proven by DELETING the principle and requiring the over-budget action to become an allow — if anything else still blocked, that would be the parallel enforcer the requirement forbids. Overshoot is bounded by what is IN FLIGHT, not by one action; the gate reads accumulated fact because a call's cost is unknowable before it returns. An agent with no budget row is NOT over budget: absence of a budget is not evidence of a breach.
- [Phase 11]: [11d] Every GPU figure carries the label saying WHAT IT MEASURED (process | device_shared), and the label travels with the number into the audit body. A device-wide counter cannot be honestly divided among concurrent agents — this is Slice 9c's tracemalloc finding on different hardware. `provider` is the action's own target, never a vendor inferred from it, and it is the first roll-up key an AGENT chooses, so it is ordered by call volume rather than alphabetically.
- [Phase 11]: [11e] EVIDENCE, NEVER CONFORMITY (D-8). Risk classification is operator-declared because the same agent is high-risk in a hiring pipeline and minimal-risk summarizing notes — guessing harms in both directions. Every citation was verified against primary sources (EUR-Lex consolidated OJ; the AICPA TSP 100 PDF) and anything unverifiable was DROPPED. Every "Art." in a section — key or list value — requires the disclaimer in that same section; the earlier key-only guard had a documented blind spot and something was duly threaded through it.
- [Phase 11]: [11f] CMP-06 is the payoff: a bundle verifiable STANDALONE against an anchored root, so an auditor gets the records they are entitled to and learns nothing about the rest. Its counters say what was actually CHECKED (records_anchor_verified, records_externally_anchored, records_signature_verified) rather than what was promised — the HTTP route holds no public key, so it checks no signatures, and the artifact now says so instead of claiming otherwise.

- [Phase 12]: [12a] A rate is a lossy summary of two numbers and the lost one says whether to believe it, so counts are stored and `n` travels with every rate a caller can obtain. An empty history is an empty trend, never 0.0 — that is the claim "every attack was blocked".
- [Phase 12]: [12b] Validation ASKS the guard, it never ATTACKS through it. Every probe goes through evaluate() and nothing invokes a handler: an executing probe on a timer, against a deployment whose guard has a hole, would PERFORM the exfiltration it was checking for. The review also found the loop would trip the validated agent's own breaker and floor its reputation — the health check taking the patient offline, more reliably the better the guard is — so the probe identity is now a separate required principal.
- [Phase 12]: [12c] Campaign steps share one conversation_id, which is the key the SEC-13 correlator windows on; without it a campaign silently degrades into N single-shot probes that merely run in order. The score is the STEP it was blocked at, because "blocked" collapses the opening move being caught with four hostile actions having already run.
- [Phase 12]: [12d] Health is a READ over facts already recorded — a health writer would be a second source that can disagree with the audit log, discovered while diagnosing an incident. Idle is not dead (a timestamp, no verdict) and a governance deny is not an error (counted apart, with the denominator named): folding them makes the best-governed agent look like the sickest and the operator's fix is to loosen the guard.
- [Phase 12]: [12e] AUD-09 joins at query time with NO separate graph database, and an iterative walk rather than a recursive CTE — both backends support WITH RECURSIVE but the JSON extraction differs, and a query that works on SQLite and breaks on Postgres is worse than an honest loop. parent_action_id is caller-supplied, so a cycle is assertable and an unbounded walk hangs the tool an operator reaches for DURING an incident. Lineage is CLAIMED, not proven, and every chain says so in its payload (TRST-04 cross-check is Phase 13).
- [Phase 12]: [12f] A template is where a carefully-qualified number gets reduced to a percentage, so the dashboard tests assert the RENDERED page: the failure rate with its denominator, no liveness verdict, "n/a" rather than 0% for unmeasured, and "no validation runs yet" rather than 0%. Graph layout is deterministic so a refresh cannot be mistaken for a topology change.

### Pending Todos

[From .planning/todos/pending/ — ideas captured during sessions]

None yet.

### Blockers/Concerns

[Issues that affect future work]

- **Two guards shipped with tests that could not fail, both caught by mutation rather than by review (Phase 12).** 12f's dangling-edge probe seeded 5 agents and never reached the 60-node page budget; its health probe asserted a percentage the fixture cannot produce. Both passed against the mutant. The lesson is now house practice: a security or honesty guard is not done until a mutant of it turns the suite red.
- **The harness OOMs (`0xC0000409`) under this workflow, and a crash leaves live pytest processes behind.** Two orphans (one at 144s CPU) inflated the suite from 94s to 379s and manufactured 20 failures + 43 errors that looked like a broken `api.py` — nothing was wrong with it. After any crash: `Get-Process python*`, kill, then re-run before trusting a timing-sensitive result. Mitigation on the harness side is `NODE_OPTIONS=--max-old-space-size=8192`; on the agent side, one workflow at a time rather than parallel waves.

- **Undeclared package dependency (pre-existing since Phase 9, found independently by two Phase-11 reviewers):** `packages/controlplane/src/agentos_controlplane/resource_governor.py` imports `agentos_sdk.enforce.ResourceLimits` while `packages/controlplane/pyproject.toml` declares only `agentos-contract`. So "the control plane cannot import from the SDK" is a convention, not a fact, and the control plane is not installable standalone. Phase 11 added no new edge (its `Usage` went to `agentos-contract`, the seam both sides already share). Left alone deliberately as out of scope, but it should be tracked and closed.
- **Phase 11 carry-overs, disclosed rather than silently deferred:** `BudgetReconciler` is wired by no composition root (this repo has none — the Phase-7 reconcilers are operator-wired too), so a multi-process deployment gets no budget convergence until an operator builds the loop. `MerkleSealer.seal()` likewise has no scheduled caller, so the epoch table stays empty and `/audit/disclose` 404s until an operator drives it. The evidence-export route passes no operator public key, so its self-verification checks no signatures — reported honestly as `records_signature_verified: 0` rather than hidden behind a green `chain_verifies`.
- **Postgres remains unverified for Phases 9-11 (D-14, no Docker on this machine).** Migrations 0023-0027 were applied and reverted on SQLite only. Two Phase-11 findings were specifically Postgres-shaped and unobservable locally: a VARCHAR length SQLite does not enforce, and tied-`recorded_at` paging that SQLite happens to order by rowid.

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
