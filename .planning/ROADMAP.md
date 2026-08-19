# Roadmap: agentos-guard

> **Two roadmaps, on purpose — this is the *execution-level* one.** This is the GSD decomposition:
> 14 fine-grained, independently-shippable vertical slices with goals, success criteria, REQ-IDs,
> and live status. The *design-level* roadmap — the three coarse phases (P0 / P1 / P2) and what
> they mean — is [`../docs/architecture/20-roadmap.md`](../docs/architecture/20-roadmap.md) and is
> authoritative for phase *intent*. Mapping: design P0 → Phases 1–6, P1 → Phases 7–12, P2 →
> Phases 13–14. Read this for *what to build next and its status*; read the design roadmap for
> *what the phases mean*.

## Overview

agentos-guard is a runtime governance and security control plane that intercepts every AI-agent action, runs it through a synchronous decision pipeline (identity/trust → policy → risk → graduated response), and writes tamper-evident audit evidence. The paradigm is *Trust→Verify→Graduate→Prove* (vs AGT's *Distrust→Block→Log*), carried by **seven differentiator pillars** (`docs/architecture/00-manifesto.md`): semantic constitution, graduated response, intent-based policy, cross-agent permission calculus, explainable denials with remediation, CI-gating red-team + self-play, and provable audit. The journey starts with a rock-solid walking skeleton — one agent, one tool, one Constitution principle, proven end-to-end with a CI-gating red-team test — then thickens that loop into a full Phase-0 parity control plane (five interception types, full graduated outcomes, explainable-remediation decisions + intent tags, approvals, kill switch, OWASP/NIST/EU-minimal compliance, SDK, dashboard). Phase 1 builds trust/reputation, containment, the full security engine (including the ASI05/06/07 detectors and deeper intent classification), the gateway PEP, Merkle audit, economics, ABOM, and reconciliation loops. Phase 2 reaches for the hard-gated moonshot differentiators (amendments, BFT consensus, self-play, ZK proofs, K8s operator, Rust hot path). **Crypto-economics (blockchain anchoring, token staking, MPC) are fenced out of core** (ADR-0007); only token-free Merkle/ZK cryptography is kept. Every phase is an independently shippable vertical slice; nothing horizontal ships alone.

**Wedge-first ordering (2026-06-10, AGT v4.1.0 re-verification):** the roadmap front-loads the *durable* AGT gaps — the semantic constitution and cross-action sequence-intent correlation (SEC-13, pulled forward into Phase 3), which AGT's deterministic-only philosophy and stateless kernel make structurally hard to copy — and deliberately defers parity features AGT already does well (privilege rings, SPIFFE/mTLS, multi-language SDKs, budget governance). Incidental gaps we already hold (memory interception, fail-closed redacted audit, deny-by-default, CI-gating red-team) are claimed loudly while they last but never bet a phase on. Positioning is *layer-first* ("the semantic-judgment and memory-governance layer deterministic enforcers admit they lack"), with an optional AGT adapter tracked alongside the Phase-10 gateway PEP. Re-verify AGT's feature set at the start of every phase — see `docs/architecture/30-comparison-agt.md`.

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [x] **Phase 1: Walking Skeleton** - One agent, one tool, one principle proven end-to-end: contract → pipeline → OPA → risk → graduated → hash-chained audit, with a red-team test that breaks CI if the policy is removed (completed 2026-06-01)
- [x] **Phase 2: Full Interception Coverage** - All five action types (tool/model/memory/MCP/delegation) intercepted, normalized, and verified with a no-silent-gaps coverage check (completed 2026-06-07)
- [x] **Phase 3: Constitution, Graduated Response, Approvals & Sequence Intent** - Human-readable Constitution compiles to OPA/Rego with cited-principle interpreter; full graduated outcome spectrum with policy-driven thresholds, trust-modulates-only, a working approval workflow, and sequence/lineage intent correlation (SEC-13, pulled forward — the durable AGT gap) proven by a 5-minute `rename_then_drop` wedge demo (completed 2026-06-12)
- [x] **Phase 4: Tamper-Evident Audit & Operator Containment** - Provenance-rich hash-chained audit with per-record Ed25519 signatures, fail-closed redaction + secret-scan last gate, a CI chain verifier, RFC-3161 external anchoring, and agent + fleet kill switches (completed 2026-07-03)
- [x] **Phase 5: Control Plane, SDK & Minimal Dashboard** - Declarative resource API with compile-on-write and optimistic versioning, gated self-registration + agent inventory, the `ControlPlaneClient` SDK, a zero-infra quickstart (SQLite + in-process opa-wasm — SDK-05), and a cookie-gated dashboard with approvals and kill switch (completed 2026-07-03)
- [~] **Phase 6: Observability, Compliance & Red-Team Gate** - OTel spans/metrics, OWASP/NIST/EU-minimal compliance mapping, and the pytest-native red-team layer that statistically gates CI (closes Phase 0). Slices 6a–6e + OSS-02 merged (PR #16 → development); **OSS-01 (first tagged PyPI release) remains** before Phase 0 fully closes
- [x] **Phase 7: Trust, Reputation & Identity Hardening** - Longitudinal reputation, bounded delegation trust chains, agent certificates, and reconciliation loops (completed 2026-07-17)
- [x] **Phase 8: Full Security Engine & MCP Gateway** - Data-exfil, secret-leakage, tool-poisoning, supply-chain, plus the ASI05/06/07 gap detectors and an MCP security gateway (completed 2026-07-17)
- [x] **Phase 9: Runtime Containment & Consensus** - Sandbox execution, privilege rings, resource isolation, circuit breakers, emergency shutdown, and 2-of-3 multi-agent consensus
- [x] **Phase 10: Gateway PEP, Second Adapter & Live Graph** - Framework-agnostic gateway PEP, a second framework adapter, framework/shadow/rogue discovery, and the live agent graph (completed 2026-08-18)
- [x] **Phase 11: Merkle Audit, Economics & Compliance Export** - Merkle DAG audit upgrade with inclusion proofs, cost/budget governance through the graduated engine, and one-click EU AI Act + SOC 2 evidence export (completed 2026-08-19)
- [ ] **Phase 12: Continuous Adversarial Validation & Rich Dashboard** - Attack-success-rate tracking, scheduled continuous validation, multi-step campaigns, health monitoring, and the rich SLO/graph/attack dashboard
- [ ] **Phase 13: Constitution Amendments & Conflict Reasoning** - Proposable/ratifiable Constitution amendments, cross-agent transitive-permission conflict resolution, and BFT-backed consensus
- [ ] **Phase 14: Self-Play, ZK Proofs, Decentralized Identity & Rust Hot Path** - Continuous self-play + runtime patching + threat intel, zero-knowledge compliance proofs, SPIFFE/mTLS + portable reputation (optional pluggable backend, ADR-0007), K8s sidecar/operator, ROI/ABOM impact analysis, and the profile-driven Rust rewrite

## Phase Details

### Phase 1: Walking Skeleton
**Goal**: Prove the entire decision loop end-to-end on a single vertical slice — one LangGraph agent, one governed tool, one Constitution principle — with every pipeline stage real and a red-team test that fails CI if the policy is removed.
**Mode:** mvp
**Depends on**: Nothing (first phase)
**Requirements**: PIPE-07, PIPE-01, PIPE-02, PIPE-03, INT-01, IDN-01, IDN-02, TRST-01, POL-03, POL-06, SEC-01, AUD-01, SDK-01
**Success Criteria** (what must be TRUE):
  1. A LangGraph agent's governed tool call is intercepted before execution and normalized into a serializable `AgentAction` via the stable `contract` package.
  2. The action passes synchronously through identity/trust → policy (one OPA-compiled principle) → risk (one injection heuristic) → graduated response, producing one `Decision` with machine-readable reasons; a forged identity short-circuits to deny without running later stages.
  3. An allowed action runs the tool and appends one hash-chained `AuditRecord`; a denied action raises a governed exception carrying the fired reasons.
  4. A pytest red-team test asserts the agent denies a known prompt-injection attack, and removing the Constitution principle makes that test fail the CI build.
**Plans**: 6 plans
- [x] 01-01-PLAN.md — uv workspace scaffold + Wave-0 test infra + the serializable contract package (PIPE-07)
- [x] 01-02-PLAN.md — Postgres store: agent registry, EdDSA identity engine (IDN-01), hash-chained fail-closed audit (AUD-01)
- [x] 01-03-PLAN.md — SEC-01 deterministic prompt-injection detector (RiskScorer + normalize + aggregator)
- [x] 01-04-PLAN.md — opa-wasmtime human-verify checkpoint + egress-allowlist Rego principle + WasmPolicyEngine (POL-03)
- [x] 01-05-PLAN.md — 4-stage decision pipeline: identity short-circuit, floor-respecting graduated response, runner (PIPE-01/02/03, IDN-02, TRST-01, POL-06)
- [x] 01-06-PLAN.md — LangChain SDK PEP middleware (INT-01/SDK-01), http_get tool, end-to-end slice + D-04 red-team CI gate

### Phase 2: Full Interception Coverage
**Goal**: Thicken the loop so all five action types are governed, not just tool calls, and prove there are no silent un-instrumented paths.
**Mode:** mvp
**Depends on**: Phase 1
**Requirements**: INT-02, INT-03, INT-04, INT-05, INT-06
**Success Criteria** (what must be TRUE):
  1. Model invocations, memory-access operations, and MCP-server calls are each intercepted and normalized into an `AgentAction` that flows through the same pipeline.
  2. Agent-to-agent delegation is intercepted and normalized with a `parent_action_id` capturing lineage.
  3. An interception-coverage check confirms all five action types are hooked and an adversarial bypass-attempt test (undecorated tool / direct model call) is detected rather than silently allowed.
**Plans**: delivered as one slice (see `.planning/phases/02-full-interception/02-SUMMARY.md`)
- [x] Model interception via LangChain `awrap_model_call` (INT-02); normalizers for all four new types
- [x] Governed wrappers for memory/MCP/delegation sharing one enforcement core (INT-03/04/05), delegation captures `parent_action_id` lineage
- [x] Interception-coverage registry + bypass-attempt fail-closed detection (INT-06)
- [x] Egress principle scoped to tool egress so non-tool types flow the pipeline; audit redactor + lineage extended for the four new payload shapes

### Phase 3: Constitution, Graduated Response, Approvals & Sequence Intent
**Goal**: Operators author a human-readable Constitution that compiles to deterministic OPA/Rego, ambiguous cases get a cited-principle rationale, the full graduated outcome spectrum — including human approval and trust-modulates-only — is enforced, and sequence/lineage intent correlation catches multi-step evasions no single action reveals (SEC-13, pulled forward from Phase 8: cross-action correlation is the durable AGT gap — their stateless kernel can't retrofit it — and the demoable wedge; see `docs/architecture/30-comparison-agt.md`).
**Mode:** mvp
**Depends on**: Phase 2
**Requirements**: POL-01, POL-02, POL-04, POL-05, POL-07, POL-08, POL-13, POL-14, PIPE-04, PIPE-05, PIPE-06, PIPE-08, PIPE-09, SEC-02, SEC-03, SEC-12, SEC-13, TRST-02, API-03
**Success Criteria** (what must be TRUE):
  1. An operator authors numbered Constitution principles that a compiler lowers to scoped YAML and then to OPA/Rego, evaluated deterministically with the exact policy/constitution version recorded on every `Decision`.
  2. On a no-rule/ambiguous result the LLM interpreter returns `{outcome, cited principle, rationale}` and can never upgrade a high-risk action beyond the deterministic policy floor (advisory-only); every `Decision` is an explainable denial carrying `{principle_ref, rationale, evidence}`, `inferred_intent`, and concrete `remediation` paths (PIPE-08), with deterministic intent-class tags mapping actions to a coarse intent (e.g. `DATA_DESTRUCTION`) that feeds risk and policy (SEC-12, advisory to the floor).
  3. The graduated-response stage maps {policy, risk, trust} to allow/warn/sandbox/require_consensus/require_approval/temporary_exception/governance_review/deny with policy-driven thresholds, where trust modulates only within a policy-defined band and never overrides a deterministic policy decision; a `require_approval` outcome parks an `ApprovalRequest` that blocks the action until resolved or times out to a safe default; a `temporary_exception` is a human-ratified, time-boxed allow that auto-revokes at `expires_at` (the interpreter may recommend but never grant one); a `governance_review` proceeds while opening an async non-blocking review; and every `Decision` can carry composable `side_effects` (notify/additional_monitoring/risk_flag/create_incident) orthogonal to its outcome (PIPE-09).
  4. The pipeline holds its p95 cached-path latency budget (verified by a benchmark test), keeps its own compiled-policy/identity cache invalidated on policy-version change, and applies per-action-class fail-closed posture with no silent allow on control-plane unavailability.
  5. Sequence/lineage intent analysis over `parent_action_id` chains (SEC-13) catches multi-step evasions — e.g. `rename_then_drop`, copy-then-delete — where every individual action would be allowed, and a scripted 5-minute wedge demo shows the Constitution denying such a sequence with a cited principle and remediation (the demoable proof of the two durable differentiators over AGT).
**Plans**: 7/7 complete — see `.planning/phases/03-constitution-graduated/`

### Phase 4: Tamper-Evident Audit & Operator Containment
**Goal**: Make audit evidence genuinely tamper-evident and verifiable, and give operators an immediate halt for a single agent or the whole fleet.
**Mode:** mvp
**Depends on**: Phase 3
**Requirements**: AUD-02, AUD-03, AUD-04, AUD-05, AUD-08, RUN-01, RUN-02
**Success Criteria** (what must be TRUE):
  1. Each `AuditRecord` links `AgentAction` → `Decision` → fired policies/principles → outcome and carries the exact policy/constitution version as evidence.
  2. Sensitive payloads are redacted at write time per policy and redaction fails closed — no record is written if redaction fails.
  3. A CI-runnable verifier re-validates the hash chain and detects any retroactive edit; chain checkpoints are externally anchored/signed; each `AuditRecord` also carries a detached per-record EdDSA signature so a single record verifies independently of the chain (AUD-08).
  4. An operator can kill-switch a single agent or the entire fleet and the targeted agents' actions halt immediately.
**Plans**: 6/6 complete — see `.planning/phases/04-audit-containment/` (scope addition during execution: a free NVIDIA-hosted interpreter adapter, slice 4f, extending the Phase-3 POL-04 seam — user-requested, no REQ-ID)

### Phase 5: Control Plane, SDK & Minimal Dashboard
**Goal**: Wrap the proven engines in a declarative resource API on Postgres, a complete Python SDK, and a minimal operator dashboard so the whole system is usable end-to-end by an outside team.
**Mode:** mvp
**Depends on**: Phase 4
**Requirements**: API-01, API-02, SDK-02, SDK-04, SDK-05, DISC-01, DISC-02, DASH-01, DASH-02, DASH-03
**Success Criteria** (what must be TRUE):
  1. A declarative API validates, versions, and stores Agent/Constitution/Policy/TrustProfile/ApprovalRequest/ABOM resources in PostgreSQL, compiling a Constitution to Policy/Rego on write.
  2. The SDK lets an agent self-register and receive an identity token, and provides a control-plane client for resource CRUD and approvals; self-registered agents appear in an authoritative inventory tracking agents, tools, prompts, and memories.
  3. An operator views the agent inventory and recent decisions/audit, resolves pending approval requests, and triggers agent/fleet kill switches from the dashboard.
  4. A zero-infra quickstart runs the full governed loop with SQLite + in-process opa-wasm from a single `pip install` — no Docker, Postgres, or OPA server — so first-run friction matches AGT's one-decorator pitch (SDK-05).
**Plans**: 6/6 complete — see `.planning/phases/05-control-plane-sdk-dashboard/` (note: "single `pip install`" currently means an editable/workspace install — publishing to PyPI is OSS-01, Phase 6)
**UI hint**: yes

### Phase 6: Observability, Compliance & Red-Team Gate
**Goal**: Close Phase 0 — emit standard telemetry, map evidence to the compliance frameworks that matter at launch, and ship the pytest-native red-team layer that statistically gates CI.
**Mode:** mvp
**Depends on**: Phase 5
**Requirements**: OBS-01, OBS-02, OBS-03, CMP-01, CMP-02, CMP-03, TEST-01, TEST-02, TEST-03, TEST-04, TEST-05, TEST-06, SDK-03, OSS-01, OSS-02
**Success Criteria** (what must be TRUE):
  1. Every `AgentAction`/`Decision` is emitted as an OpenTelemetry span to the user's backend, a `trace_id` correlates an action across stages and agents, and per-agent metrics (volume, outcome mix, violations, p95 latency) are emitted.
  2. Each detector/policy maps to OWASP Agentic Top 10 and NIST AI RMF categories, and the audit + approval evidence supports minimal EU AI Act Art. 12 / Art. 26 claims at launch.
  3. Engineers write pytest safety tests using provided fixtures/adapters that run an injection/tool-misuse/exfiltration/jailbreak attack library against a live agent, asserting statistical thresholds (attack-success-rate < X%).
  4. Fixed vulnerabilities are locked by regression tests and a failing safety test breaks the CI build.
  5. Versioned packages are published to PyPI via a tagged release workflow and CONTRIBUTING.md + SECURITY.md ship, so the P0 launch is installable and contributable by outsiders (OSS-01/OSS-02, added 2026-07-05 audit).
**Sequencing note (2026-07-05 audit):** EU AI Act high-risk obligations bind **2026-08-02** — under
four weeks away. Front-load CMP-03 (minimal Art. 12/26 evidence claim) in the slice order, and
re-verify AGT's live feature set at phase start (last verification 2026-06-10, v4.1.0 — now stale
per the project's own per-phase rule) plus the garak/PyRIT/OTel version pins from the 2026-06-01
research snapshot.
**Status (2026-07-12):** Slices 6a–6e delivered via PR #16 (merged to `development`): OTel tracing +
per-agent metrics seam (`agentos_pipeline.telemetry`), compliance mapping + evidence export
(`agentos_controlplane.compliance`), the pytest-native red-team harness (`agentos_sdk.redteam`), and
the garak/PyRIT ASR gate in a dedicated CI job. OSS-02 (SECURITY.md, CONTRIBUTING.md, issue/PR
templates) added 2026-07-12. **Remaining to close Phase 0: OSS-01** — `.github/workflows/release.yml`
is in place, but the first tagged PyPI release + the PyPI Trusted-Publisher setup are still pending.
**Carried debt:** the mandated AGT re-verification was NOT done at Phase-6 start (comparison scorecard
still dated 2026-06-10); do it before Phase 7 planning.
**Plans**: `docs/superpowers/plans/2026-07-10-phase-6-6{a..e}-*.md` (spec: `docs/superpowers/specs/2026-07-10-phase-6-*-design.md`) — note these live under `docs/superpowers/`, not `.planning/phases/06-*/` like Phases 1–5

### Phase 7: Trust, Reputation & Identity Hardening
**Goal**: Evolve flat trust into longitudinal reputation and bounded delegation trust, harden identity with certificates, and add the reconciliation loops that keep derived state and caches correct across writes.
**Mode:** mvp
**Depends on**: Phase 6
**Requirements**: TRST-03, TRST-04, IDN-03, API-04
**Success Criteria** (what must be TRUE):
  1. A longitudinal reputation score is derived from each agent's violation/approval history and feeds the graduated-response band.
  2. Trust propagates and decays across delegation edges as a bounded budget, and delegated scope is enforced as an intersection (never a union) of parent and child scope.
  3. Agents are issued X.509-style certificates binding identity to keys.
  4. Reconciliation loops continuously compile constitutions, refresh trust, materialize the graph, and warm hot-path caches.
**Plans**: 4/4 complete — one slice per requirement
- [x] 7a — TRST-03 longitudinal reputation (`agentos_controlplane.reputation`): time-decayed Beta posterior over audit outcomes + human approval rulings, capped by an anti-farming violation ceiling `1/(1+bad)` so 1000 compliant calls cannot wash out one fresh deny (Pitfall 10). Feeds the graduated band via `TrustProfile` → `load_trust`.
- [x] 7b — TRST-04 bounded delegation trust + scope intersection (`agentos_pipeline.delegation`): `min(child_trust, parent_trust*decay)` kills trust laundering; scope is an intersection so a delegation cannot conjure a capability neither party held. Pipeline stage 1b; unknown lineage fails closed.
- [x] 7c — IDN-03 X.509 agent certificates (`agentos_controlplane.certificates`): per-agent Ed25519 keypair + CA-issued cert with a SPIFFE-shaped URI SAN, real CRL revocation; the control plane never stores the agent's private key. Migration 0010.
- [x] 7d — API-04 reconciliation loops (`agentos_controlplane.reconcile`): constitution/trust/graph/cache reconcilers with per-reconciler intervals, failure isolation, and idempotent convergence.
**Scope additions during execution** (pre-existing bugs found in Phase-7's path, all regression-locked):
- `Registry.load_trust` read `agent.trust_score` while the gated operator route (`PUT /trust-profiles`) — per the registry's own docstring the only way trust is graded — wrote `trust_profile`. Operator-graded trust never reached the pipeline. TRST-03 depends on this path.
- `apply_constitution` raised `AttributeError` when a Constitution row existed without its Policy row — the exact drift API-04's ConstitutionReconciler repairs.
- `get_latest_policy()` returned the OLDER policy for two applies in the same second (`created_at` had second resolution, no tiebreaker) — a stale `GET /policies/latest` and a cache warmed to the wrong constitution.
- `Agent.public_key` stored the CONTROL PLANE's key in every row (certifying nothing); IDN-03 makes it mean what it was always documented to mean.

### Phase 8: Full Security Engine & MCP Gateway
**Goal**: Build out the full detection surface — data-exfil, secret-leakage, tool-poisoning, supply-chain — and close the surfaced OWASP-2026 gaps (ASI05/06/07), fronted by an MCP security gateway.
**Mode:** mvp
**Depends on**: Phase 7
**Requirements**: SEC-04, SEC-05, SEC-06, SEC-07, SEC-08, SEC-09, SEC-10, SEC-11, SEC-14, ABOM-01, ABOM-02
**Success Criteria** (what must be TRUE):
  1. Outbound payloads carrying secrets/PII to untrusted targets are scored for exfiltration, and credentials/keys in prompts, tool args, or outputs are flagged.
  2. Malicious or drifted tool definitions are flagged (manifest-drift), an MCP security gateway inspects/normalizes MCP interactions and quarantines hostile manifests, and supply-chain checks cross-reference an agent's ABOM against known-bad components.
  3. The gap detectors fire: memory/context-poisoning (ASI06) flags malicious memory writes/reads, inter-agent comms (ASI07) are authenticated with agent-card verification on delegation, and unsafe dynamic code/command execution (ASI05) is detected; intent classification deepens beyond the Phase-3 sequence analysis (SEC-13, delivered in Phase 3) — an embedding-similarity classifier flags novel actions near a forbidden-intent exemplar when deterministic tags are ambiguous (SEC-14).
  4. Each `Agent` declares a versioned, provenance-tracked Agent Bill of Materials of models, prompts, tools, and MCP servers.
**Plans**: 8/8 complete — grouped by cohesion
- [x] 8a — SEC-05 secret-leakage + SEC-04 data-exfiltration scorers (`risk/secret_leak.py`, `risk/exfiltration.py`). Exfil grades by data class: a secret is 0.6 to any external host, PII stays advisory (preserving "PII to an allowlisted host stays allow").
- [x] 8b — SEC-11 unsafe code-execution detector / ASI05 (`risk/code_execution.py`).
- [x] 8c — SEC-09 memory/context-poisoning detector / ASI06 (`risk/memory_poison.py`), scoped to memory_access where persistence makes injection worse than a transient one.
- [x] 8d — SEC-10 inter-agent auth + agent-card verification / ASI07 (`agent_card.py` + pipeline stage 1c), layered on IDN-01/IDN-03/TRST-04.
- [x] 8e — ABOM-01/02 provenance-tracked Agent Bill of Materials (`abom.py`): per-component digest/version/source, drift-preserving merge on re-declaration. The digests feed 8f.
- [x] 8f — SEC-06 tool-poisoning (manifest-hash drift) + SEC-08 supply-chain known-bad cross-reference (`supply_chain.py`).
- [x] 8g — SEC-07 MCP security gateway (`mcp_gateway.py` + pipeline stage 1d): hidden-instruction/typosquat/rug-pull inspection, sticky quarantine enforced on mcp_call.
- [x] 8h — SEC-14 embedding-similarity intent classifier (`intent_similarity/`), ambiguity-gated + advisory, following the POL-04 interpreter precedent (offline HashingEmbedder default + pluggable real adapter).

### Phase 9: Runtime Containment & Consensus
**Goal**: Make the sandbox and containment outcomes real — isolation, privilege rings, circuit breakers, emergency shutdown — and add 2-of-3 multi-agent consensus as a first-class graduated outcome.
**Mode:** mvp
**Depends on**: Phase 8
**Requirements**: RUN-03, RUN-04, RUN-05, RUN-06, RUN-07, POL-09
**Success Criteria** (what must be TRUE):
  1. A `sandbox` outcome runs the action in an isolated context with quarantined or reversible side effects, with sensitive tools gated behind higher privilege rings per agent.
  2. Resource isolation enforces CPU/memory/network limits per agent execution, and circuit breakers auto-trip an agent/tool after a threshold of violations or errors.
  3. Emergency shutdown stops the fleet with an audit-logged justification.
  4. A `require_consensus` outcome requires 2-of-3 agent agreement (application-level voting) before the action proceeds.
**Plans**: 6 slices (superpowers workflow; spec `docs/superpowers/specs/2026-08-04-phase-9-runtime-containment-consensus-design.md`)
- [x] 9a — sandboxed execution + quarantined side effects (RUN-03): the SandboxRunner seam replaces the interim approval substitution; the handler is never invoked, the run is persisted + audited, and the result surfaces as GovernanceQuarantined so quarantine can never be mistaken for success
- [x] 9b — privilege rings (RUN-04): stage-1e gate on a VERIFIED agent, registered-sensitivity model, rings capped by the delegation chain (no borrowing privilege across a delegation edge)
- [x] 9c — resource isolation (RUN-05): per-agent wall/memory/network budgets at both run sites, with the preventive-vs-detected distinction stated honestly, plus a capability-gated POSIX setrlimit path
- [x] 9d — circuit breakers (RUN-06): rolling-window trip per agent and per (agent,target), cooldown/half-open recovery, graduated-path-only signals (no feedback loop, no cross-agent trip)
- [x] 9e — emergency shutdown (RUN-07): fleet stop with a MANDATORY justification that can never veto the stop, an append-only incident record, and resume as the only exit
- [x] 9f — 2-of-3 consensus (POL-09): the ConsensusCoordinator seam retires the last substitution; only a genuine True from a voter approves, and error/timeout/silence deny

### Phase 10: Gateway PEP, Second Adapter & Live Graph
**Goal**: Break the single-framework, SDK-only ceiling — a framework-agnostic gateway PEP, a second framework adapter, framework/shadow/rogue discovery, and a materialized live agent graph behind the same pipeline contract.
**Mode:** mvp
**Depends on**: Phase 9
**Requirements**: INT-07, INT-08, DISC-03, DISC-04, DISC-05, DISC-06
**Success Criteria** (what must be TRUE):
  1. A framework-agnostic network gateway/proxy PEP intercepts actions with no SDK changes, behind the same `evaluate(AgentAction) -> Decision` contract, and at least one additional framework adapter (e.g. CrewAI or OpenAI Agents SDK) intercepts actions.
  2. Framework discovery detects LangChain/LangGraph, CrewAI, AutoGen, OpenAI Agents SDK, MCP, etc.; shadow-agent detection flags agents acting without registration; rogue-agent detection flags agents diverging from declared scope.
  3. A live agent graph materializes agents/tools/MCP/models/memories and delegation edges, with lineage derived from `parent_action_id`.
**Plans**: 6 slices (superpowers workflow; spec `docs/superpowers/specs/2026-08-11-phase-10-gateway-adapter-graph-design.md`)
- [x] 10a — gateway PEP (INT-07): a `agentos-gateway` reverse proxy that governs traffic with no SDK in the agent process, normalizing HTTP into the same `AgentAction` and enforcing through the one `governed_call` outcome map; the governed target is the forwarded target (no TOCTOU between what was decided and what was sent)
- [x] 10b — OpenAI Agents SDK adapter (INT-08): a second real framework intercepted at the tool boundary, governing the arguments the tool body actually receives rather than a pre-normalization copy; INT-06 coverage becomes a set per action type so two adapters can both claim a type
- [x] 10c — framework discovery (DISC-03): evidence-based detection from INSTALLED distributions (`importlib.metadata`), persisted + audited idempotently so a scheduled scan cannot bloat the chain — no guessing, so the inventory is true
- [x] 10d — shadow agents (DISC-04): agents acting without registration, detected from audit evidence with a bounded, overflow-visible identity space so an unregistered caller cannot mint unbounded rows
- [x] 10e — rogue agents (DISC-05): divergence from DECLARED scope, with observed-class provenance separating "never declared" from "declared and exceeded" so the finding stream stays true rather than flooding on first contact
- [x] 10f — live agent graph (DISC-06): agents/tools/MCP/models/memories plus delegation edges from `parent_action_id`, built incrementally from a watermark over IDENTITY-VERIFIED actions only, and read back as a bounded AND closed subgraph (lineage is honestly labelled CLAIMED — the TRST-04 authority cross-check is Phase-13 work)

### Phase 11: Merkle Audit, Economics & Compliance Export
**Goal**: Upgrade audit to a Merkle DAG, govern cost/budget as policy through the existing graduated-response engine, and produce exportable EU AI Act + SOC 2 evidence bundles.
**Mode:** mvp
**Depends on**: Phase 10
**Requirements**: AUD-06, ECON-01, ECON-02, ECON-03, CMP-04, CMP-05, CMP-06
**Success Criteria** (what must be TRUE):
  1. The hash chain is upgraded to a Merkle DAG enabling inclusion proofs and partial disclosure.
  2. Token/API/GPU cost is attributed to each agent/action, and token/budget limits are expressed as policy so over-budget actions are denied or escalated by the graduated-response engine (no parallel budget enforcer).
  3. A full EU AI Act mapping and SOC 2 control evidence are derived from the audit log, and a one-click export produces evidence bundles per framework and time range.

> The phase title previously read "ABOM". That was stale: ABOM-01/02 shipped in Phase 8 and ABOM-03
> is Phase 14, so this phase's requirement set contains no ABOM item. Corrected at close-out rather
> than honored by inventing scope to match it.

**Plans**: 6 slices (superpowers workflow; spec `docs/superpowers/specs/2026-08-18-phase-11-merkle-economics-compliance-design.md`)
- [x] 11a — Merkle DAG, inclusion proofs, partial disclosure (AUD-06): an RFC-6962 tree over the existing `record_hash` leaves, so the chain is untouched and the tree is additive; epochs are contiguous and anchored, and `verify_bundle` — not `verify_inclusion` — is what an auditor runs. A root proves INCLUSION, never completeness
- [x] 11b — cost attribution (ECON-01): usage is REPORTED, never inferred; unrecognized usage records nothing rather than zero, an unpriced model keeps its tokens with a null cost, and usage is refused from any result a provider did not vouch for
- [x] 11c — budget as policy (ECON-02): spend enters as policy input and the CONSTITUTION denies or escalates — proven by deleting the principle and requiring the block to disappear. Overshoot is bounded by what is in flight, and that bound is asserted rather than claimed
- [x] 11d — GPU & downstream attribution (ECON-03): capability-gated NVML behind the RUN-05 precedent, every GPU figure carrying the label saying what it measured, and `provider` taken from the action's own target — never a vendor inferred from it
- [x] 11e — EU AI Act mapping + SOC 2 evidence (CMP-04/05): eleven articles and three criteria, every citation verified against primary sources and anything unverifiable dropped. Risk classification is operator-declared; the bundle emits evidence and never conformity
- [x] 11f — one-click evidence export (CMP-06): per framework and per time range, verifiable STANDALONE against an anchored root — the payoff for 11a, and what makes the artifact evidence rather than an extract

### Phase 12: Continuous Adversarial Validation & Rich Dashboard
**Goal**: Move red-team from one-shot CI to continuous validation with trend tracking and campaign-style attacks, backed by health monitoring, conversation tracing, and a rich operator dashboard.
**Mode:** mvp
**Depends on**: Phase 11
**Requirements**: TEST-07, TEST-08, TEST-09, OBS-04, OBS-05, OBS-06, AUD-09, DASH-04
**Success Criteria** (what must be TRUE):
  1. Attack-success-rate is tracked over time per agent/attack class, continuous validation re-runs suites against the live agent on a schedule, and multi-step adversarial simulations run campaign-style attacks.
  2. Agent health monitoring tracks liveness/error-rate/circuit-breaker state per agent, and conversation tracing reconstructs a full conversation across tools and delegations over a forensic evidence graph that joins the audit log with the materialized agent graph at query time — no separate graph DB (AUD-09).
  3. The dashboard adds the live agent graph, per-agent SLOs/violations, and attack visualization.
**Plans**: TBD
**UI hint**: yes

### Phase 13: Constitution Amendments & Conflict Reasoning
**Goal**: Make the Constitution a living, amendable governing document with human ratification, reason about transitive permissions across delegation chains, and back consensus with BFT at scale.
**Mode:** mvp
**Depends on**: Phase 12
**Requirements**: POL-10, POL-11, POL-12
**Success Criteria** (what must be TRUE):
  1. Agents (or the self-play trainer) can propose Constitution amendments; humans review and ratify; the Constitution is versioned like a legal document.
  2. A conflict-resolution engine computes transitive permissions across delegation chains and flags emergent capability conflicts.
  3. BFT consensus backs multi-agent agreement for `require_consensus` at scale.
**Plans**: TBD

### Phase 14: Self-Play, ZK Proofs, Decentralized Identity & Rust Hot Path
**Goal**: Deliver the hard-gated moonshot layer — continuous adversarial self-play with ratifiable patches, zero-knowledge compliance proofs, SPIFFE/mTLS + portable reputation (optional pluggable backend, no required crypto-economics — ADR-0007), a K8s data plane, deeper analytics, and a profile-driven Rust hot path.
**Mode:** mvp
**Depends on**: Phase 13 (and the whole P0/P1 substrate passing verification: latency budget held, audit externally verifiable, coverage matrix green, red-team gating CI)
**Requirements**: TEST-10, TEST-11, AUD-07, IDN-04, TRST-05, INT-09, PERF-01, ECON-04, ABOM-03
**Success Criteria** (what must be TRUE):
  1. Continuous adversarial self-play generates novel attacks, scores defenses, and proposes Constitution/policy patches (human-ratified, held-out eval), and a runtime-patching path rolls out ratified defenses while a threat-intel feed imports emerging attack patterns.
  2. Zero-knowledge compliance proofs prove properties (e.g. "no PII exfiltrated") without revealing underlying data over the Merkle-anchored chain.
  3. SPIFFE/SVID workload identity enables zero-trust mTLS, portable reputation is exportable across deployments via an optional pluggable backend (any stake/slashing economics confined to that backend, never required — ADR-0007), and a Kubernetes sidecar/operator PEP intercepts at the network layer behind the same contract.
  4. ROI analytics present value-vs-cost per agent/workflow, ABOM vulnerability impact analysis answers "which agents use compromised component vX?" instantly, and hot-path enforcement components are rewritten in Rust (PyO3) where profiling justifies it.
**Plans**: TBD

## Progress

**Execution Order:**
Phases execute in numeric order: 1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9 → 10 → 11 → 12 → 13 → 14

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Walking Skeleton | 6/6 | Complete    | 2026-06-01 |
| 2. Full Interception Coverage | 1/1 | Complete    | 2026-06-07 |
| 3. Constitution, Graduated Response, Approvals & Sequence Intent | 7/7 | Complete    | 2026-06-12 |
| 4. Tamper-Evident Audit & Operator Containment | 6/6 | Complete    | 2026-07-03 |
| 5. Control Plane, SDK & Minimal Dashboard | 6/6 | Complete    | 2026-07-03 |
| 6. Observability, Compliance & Red-Team Gate | 5/6 | In progress (6a–6e + OSS-02 done; OSS-01 first release pending) | - |
| 7. Trust, Reputation & Identity Hardening | 4/4 | Complete    | 2026-07-17 |
| 8. Full Security Engine & MCP Gateway | 8/8 | Complete    | 2026-07-17 |
| 9. Runtime Containment & Consensus | 6/6 | Complete    | 2026-08-11 |
| 10. Gateway PEP, Second Adapter & Live Graph | 0/TBD | Not started | - |
| 11. Merkle Audit, Economics, ABOM & Compliance Export | 0/TBD | Not started | - |
| 12. Continuous Adversarial Validation & Rich Dashboard | 0/TBD | Not started | - |
| 13. Constitution Amendments & Conflict Reasoning | 0/TBD | Not started | - |
| 14. Self-Play, ZK Proofs, Decentralized Identity & Rust Hot Path | 0/TBD | Not started | - |
