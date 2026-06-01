# Roadmap: agentos-guard

## Overview

agentos-guard is a runtime governance and security control plane that intercepts every AI-agent action, runs it through a synchronous decision pipeline (identity/trust → policy → risk → graduated response), and writes tamper-evident audit evidence. The journey starts with a rock-solid walking skeleton — one agent, one tool, one Constitution principle, proven end-to-end with a CI-gating red-team test — then thickens that loop into a full Phase-0 parity control plane (five interception types, full graduated outcomes, approvals, kill switch, OWASP/NIST/EU-minimal compliance, SDK, dashboard). Phase 1 builds trust/reputation, containment, the full security engine (including the ASI05/06/07 detectors), the gateway PEP, Merkle audit, economics, ABOM, and reconciliation loops. Phase 2 reaches for the hard-gated moonshot differentiators (amendments, BFT consensus, self-play, ZK proofs, SPIFFE/staking, K8s operator, Rust hot path). Every phase is an independently shippable vertical slice; nothing horizontal ships alone.

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [ ] **Phase 1: Walking Skeleton** - One agent, one tool, one principle proven end-to-end: contract → pipeline → OPA → risk → graduated → hash-chained audit, with a red-team test that breaks CI if the policy is removed
- [ ] **Phase 2: Full Interception Coverage** - All five action types (tool/model/memory/MCP/delegation) intercepted, normalized, and verified with a no-silent-gaps coverage check
- [ ] **Phase 3: Constitution, Graduated Response & Approvals** - Human-readable Constitution compiles to OPA/Rego with cited-principle interpreter; full graduated outcome spectrum with policy-driven thresholds, trust-modulates-only, and a working approval workflow
- [ ] **Phase 4: Tamper-Evident Audit & Operator Containment** - Provenance-rich hash-chained audit with fail-closed redaction and a CI verifier; agent and fleet kill switches
- [ ] **Phase 5: Control Plane, SDK & Minimal Dashboard** - Declarative resource API on Postgres with compile-on-write, the full Python SDK surface, and a read-only dashboard with approvals and kill switch
- [ ] **Phase 6: Observability, Compliance & Red-Team Gate** - OTel spans/metrics, OWASP/NIST/EU-minimal compliance mapping, and the pytest-native red-team layer that statistically gates CI (closes Phase 0)
- [ ] **Phase 7: Trust, Reputation & Identity Hardening** - Longitudinal reputation, bounded delegation trust chains, agent certificates, and reconciliation loops
- [ ] **Phase 8: Full Security Engine & MCP Gateway** - Data-exfil, secret-leakage, tool-poisoning, supply-chain, plus the ASI05/06/07 gap detectors and an MCP security gateway
- [ ] **Phase 9: Runtime Containment & Consensus** - Sandbox execution, privilege rings, resource isolation, circuit breakers, emergency shutdown, and 2-of-3 multi-agent consensus
- [ ] **Phase 10: Gateway PEP, Second Adapter & Live Graph** - Framework-agnostic gateway PEP, a second framework adapter, framework/shadow/rogue discovery, and the live agent graph
- [ ] **Phase 11: Merkle Audit, Economics, ABOM & Compliance Export** - Merkle DAG audit upgrade, cost/budget governance, Agent Bill of Materials, and one-click EU AI Act + SOC 2 evidence export
- [ ] **Phase 12: Continuous Adversarial Validation & Rich Dashboard** - Attack-success-rate tracking, scheduled continuous validation, multi-step campaigns, health monitoring, and the rich SLO/graph/attack dashboard
- [ ] **Phase 13: Constitution Amendments & Conflict Reasoning** - Proposable/ratifiable Constitution amendments, cross-agent transitive-permission conflict resolution, and BFT-backed consensus
- [ ] **Phase 14: Self-Play, ZK Proofs, Decentralized Identity & Rust Hot Path** - Continuous self-play + runtime patching + threat intel, zero-knowledge compliance proofs, SPIFFE/mTLS + stake-based reputation, K8s sidecar/operator, ROI/ABOM impact analysis, and the profile-driven Rust rewrite

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
- [ ] 01-01-PLAN.md — uv workspace scaffold + Wave-0 test infra + the serializable contract package (PIPE-07)
- [ ] 01-02-PLAN.md — Postgres store: agent registry, EdDSA identity engine (IDN-01), hash-chained fail-closed audit (AUD-01)
- [ ] 01-03-PLAN.md — SEC-01 deterministic prompt-injection detector (RiskScorer + normalize + aggregator)
- [ ] 01-04-PLAN.md — opa-wasmtime human-verify checkpoint + egress-allowlist Rego principle + WasmPolicyEngine (POL-03)
- [ ] 01-05-PLAN.md — 4-stage decision pipeline: identity short-circuit, floor-respecting graduated response, runner (PIPE-01/02/03, IDN-02, TRST-01, POL-06)
- [ ] 01-06-PLAN.md — LangChain SDK PEP middleware (INT-01/SDK-01), http_get tool, end-to-end slice + D-04 red-team CI gate

### Phase 2: Full Interception Coverage
**Goal**: Thicken the loop so all five action types are governed, not just tool calls, and prove there are no silent un-instrumented paths.
**Mode:** mvp
**Depends on**: Phase 1
**Requirements**: INT-02, INT-03, INT-04, INT-05, INT-06
**Success Criteria** (what must be TRUE):
  1. Model invocations, memory-access operations, and MCP-server calls are each intercepted and normalized into an `AgentAction` that flows through the same pipeline.
  2. Agent-to-agent delegation is intercepted and normalized with a `parent_action_id` capturing lineage.
  3. An interception-coverage check confirms all five action types are hooked and an adversarial bypass-attempt test (undecorated tool / direct model call) is detected rather than silently allowed.
**Plans**: TBD

### Phase 3: Constitution, Graduated Response & Approvals
**Goal**: Operators author a human-readable Constitution that compiles to deterministic OPA/Rego, ambiguous cases get a cited-principle rationale, and the full graduated outcome spectrum — including human approval and trust-modulates-only — is enforced.
**Mode:** mvp
**Depends on**: Phase 2
**Requirements**: POL-01, POL-02, POL-04, POL-05, POL-07, POL-08, PIPE-04, PIPE-05, PIPE-06, SEC-02, SEC-03, TRST-02, API-03
**Success Criteria** (what must be TRUE):
  1. An operator authors numbered Constitution principles that a compiler lowers to scoped YAML and then to OPA/Rego, evaluated deterministically with the exact policy/constitution version recorded on every `Decision`.
  2. On a no-rule/ambiguous result the LLM interpreter returns `{outcome, cited principle, rationale}` and can never upgrade a high-risk action beyond the deterministic policy floor (advisory-only).
  3. The graduated-response stage maps {policy, risk, trust} to allow/warn/sandbox/require_consensus/require_approval/deny with policy-driven thresholds, where trust modulates only within a policy-defined band and never overrides a deterministic policy decision; a `require_approval` outcome parks an `ApprovalRequest` that blocks the action until resolved or times out to a safe default.
  4. The pipeline holds its p95 cached-path latency budget (verified by a benchmark test), keeps its own compiled-policy/identity cache invalidated on policy-version change, and applies per-action-class fail-closed posture with no silent allow on control-plane unavailability.
**Plans**: TBD

### Phase 4: Tamper-Evident Audit & Operator Containment
**Goal**: Make audit evidence genuinely tamper-evident and verifiable, and give operators an immediate halt for a single agent or the whole fleet.
**Mode:** mvp
**Depends on**: Phase 3
**Requirements**: AUD-02, AUD-03, AUD-04, AUD-05, RUN-01, RUN-02
**Success Criteria** (what must be TRUE):
  1. Each `AuditRecord` links `AgentAction` → `Decision` → fired policies/principles → outcome and carries the exact policy/constitution version as evidence.
  2. Sensitive payloads are redacted at write time per policy and redaction fails closed — no record is written if redaction fails.
  3. A CI-runnable verifier re-validates the hash chain and detects any retroactive edit; chain checkpoints are externally anchored/signed.
  4. An operator can kill-switch a single agent or the entire fleet and the targeted agents' actions halt immediately.
**Plans**: TBD

### Phase 5: Control Plane, SDK & Minimal Dashboard
**Goal**: Wrap the proven engines in a declarative resource API on Postgres, a complete Python SDK, and a minimal operator dashboard so the whole system is usable end-to-end by an outside team.
**Mode:** mvp
**Depends on**: Phase 4
**Requirements**: API-01, API-02, SDK-02, SDK-04, DISC-01, DISC-02, DASH-01, DASH-02, DASH-03
**Success Criteria** (what must be TRUE):
  1. A declarative API validates, versions, and stores Agent/Constitution/Policy/TrustProfile/ApprovalRequest/ABOM resources in PostgreSQL, compiling a Constitution to Policy/Rego on write.
  2. The SDK lets an agent self-register and receive an identity token, and provides a control-plane client for resource CRUD and approvals; self-registered agents appear in an authoritative inventory tracking agents, tools, prompts, and memories.
  3. An operator views the agent inventory and recent decisions/audit, resolves pending approval requests, and triggers agent/fleet kill switches from the dashboard.
**Plans**: TBD
**UI hint**: yes

### Phase 6: Observability, Compliance & Red-Team Gate
**Goal**: Close Phase 0 — emit standard telemetry, map evidence to the compliance frameworks that matter at launch, and ship the pytest-native red-team layer that statistically gates CI.
**Mode:** mvp
**Depends on**: Phase 5
**Requirements**: OBS-01, OBS-02, OBS-03, CMP-01, CMP-02, CMP-03, TEST-01, TEST-02, TEST-03, TEST-04, TEST-05, TEST-06, SDK-03
**Success Criteria** (what must be TRUE):
  1. Every `AgentAction`/`Decision` is emitted as an OpenTelemetry span to the user's backend, a `trace_id` correlates an action across stages and agents, and per-agent metrics (volume, outcome mix, violations, p95 latency) are emitted.
  2. Each detector/policy maps to OWASP Agentic Top 10 and NIST AI RMF categories, and the audit + approval evidence supports minimal EU AI Act Art. 12 / Art. 26 claims at launch.
  3. Engineers write pytest safety tests using provided fixtures/adapters that run an injection/tool-misuse/exfiltration/jailbreak attack library against a live agent, asserting statistical thresholds (attack-success-rate < X%).
  4. Fixed vulnerabilities are locked by regression tests and a failing safety test breaks the CI build.
**Plans**: TBD

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
**Plans**: TBD

### Phase 8: Full Security Engine & MCP Gateway
**Goal**: Build out the full detection surface — data-exfil, secret-leakage, tool-poisoning, supply-chain — and close the surfaced OWASP-2026 gaps (ASI05/06/07), fronted by an MCP security gateway.
**Mode:** mvp
**Depends on**: Phase 7
**Requirements**: SEC-04, SEC-05, SEC-06, SEC-07, SEC-08, SEC-09, SEC-10, SEC-11, ABOM-01, ABOM-02
**Success Criteria** (what must be TRUE):
  1. Outbound payloads carrying secrets/PII to untrusted targets are scored for exfiltration, and credentials/keys in prompts, tool args, or outputs are flagged.
  2. Malicious or drifted tool definitions are flagged (manifest-drift), an MCP security gateway inspects/normalizes MCP interactions and quarantines hostile manifests, and supply-chain checks cross-reference an agent's ABOM against known-bad components.
  3. The gap detectors fire: memory/context-poisoning (ASI06) flags malicious memory writes/reads, inter-agent comms (ASI07) are authenticated with agent-card verification on delegation, and unsafe dynamic code/command execution (ASI05) is detected.
  4. Each `Agent` declares a versioned, provenance-tracked Agent Bill of Materials of models, prompts, tools, and MCP servers.
**Plans**: TBD

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
**Plans**: TBD

### Phase 10: Gateway PEP, Second Adapter & Live Graph
**Goal**: Break the single-framework, SDK-only ceiling — a framework-agnostic gateway PEP, a second framework adapter, framework/shadow/rogue discovery, and a materialized live agent graph behind the same pipeline contract.
**Mode:** mvp
**Depends on**: Phase 9
**Requirements**: INT-07, INT-08, DISC-03, DISC-04, DISC-05, DISC-06
**Success Criteria** (what must be TRUE):
  1. A framework-agnostic network gateway/proxy PEP intercepts actions with no SDK changes, behind the same `evaluate(AgentAction) -> Decision` contract, and at least one additional framework adapter (e.g. CrewAI or OpenAI Agents SDK) intercepts actions.
  2. Framework discovery detects LangChain/LangGraph, CrewAI, AutoGen, OpenAI Agents SDK, MCP, etc.; shadow-agent detection flags agents acting without registration; rogue-agent detection flags agents diverging from declared scope.
  3. A live agent graph materializes agents/tools/MCP/models/memories and delegation edges, with lineage derived from `parent_action_id`.
**Plans**: TBD

### Phase 11: Merkle Audit, Economics, ABOM & Compliance Export
**Goal**: Upgrade audit to a Merkle DAG, govern cost/budget as policy through the existing graduated-response engine, and produce exportable EU AI Act + SOC 2 evidence bundles.
**Mode:** mvp
**Depends on**: Phase 10
**Requirements**: AUD-06, ECON-01, ECON-02, ECON-03, CMP-04, CMP-05, CMP-06
**Success Criteria** (what must be TRUE):
  1. The hash chain is upgraded to a Merkle DAG enabling inclusion proofs and partial disclosure.
  2. Token/API/GPU cost is attributed to each agent/action, and token/budget limits are expressed as policy so over-budget actions are denied or escalated by the graduated-response engine (no parallel budget enforcer).
  3. A full EU AI Act mapping and SOC 2 control evidence are derived from the audit log, and a one-click export produces evidence bundles per framework and time range.
**Plans**: TBD

### Phase 12: Continuous Adversarial Validation & Rich Dashboard
**Goal**: Move red-team from one-shot CI to continuous validation with trend tracking and campaign-style attacks, backed by health monitoring, conversation tracing, and a rich operator dashboard.
**Mode:** mvp
**Depends on**: Phase 11
**Requirements**: TEST-07, TEST-08, TEST-09, OBS-04, OBS-05, OBS-06, DASH-04
**Success Criteria** (what must be TRUE):
  1. Attack-success-rate is tracked over time per agent/attack class, continuous validation re-runs suites against the live agent on a schedule, and multi-step adversarial simulations run campaign-style attacks.
  2. Agent health monitoring tracks liveness/error-rate/circuit-breaker state per agent, and conversation tracing reconstructs a full conversation across tools and delegations.
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
**Goal**: Deliver the hard-gated moonshot layer — continuous adversarial self-play with ratifiable patches, zero-knowledge compliance proofs, decentralized stake-based identity, a K8s data plane, deeper analytics, and a profile-driven Rust hot path.
**Mode:** mvp
**Depends on**: Phase 13 (and the whole P0/P1 substrate passing verification: latency budget held, audit externally verifiable, coverage matrix green, red-team gating CI)
**Requirements**: TEST-10, TEST-11, AUD-07, IDN-04, TRST-05, INT-09, PERF-01, ECON-04, ABOM-03
**Success Criteria** (what must be TRUE):
  1. Continuous adversarial self-play generates novel attacks, scores defenses, and proposes Constitution/policy patches (human-ratified, held-out eval), and a runtime-patching path rolls out ratified defenses while a threat-intel feed imports emerging attack patterns.
  2. Zero-knowledge compliance proofs prove properties (e.g. "no PII exfiltrated") without revealing underlying data over the Merkle-anchored chain.
  3. SPIFFE/SVID workload identity enables zero-trust mTLS, agents stake on behavior with slashing and portable reputation, and a Kubernetes sidecar/operator PEP intercepts at the network layer behind the same contract.
  4. ROI analytics present value-vs-cost per agent/workflow, ABOM vulnerability impact analysis answers "which agents use compromised component vX?" instantly, and hot-path enforcement components are rewritten in Rust (PyO3) where profiling justifies it.
**Plans**: TBD

## Progress

**Execution Order:**
Phases execute in numeric order: 1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9 → 10 → 11 → 12 → 13 → 14

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Walking Skeleton | 0/6 | Planned | - |
| 2. Full Interception Coverage | 0/TBD | Not started | - |
| 3. Constitution, Graduated Response & Approvals | 0/TBD | Not started | - |
| 4. Tamper-Evident Audit & Operator Containment | 0/TBD | Not started | - |
| 5. Control Plane, SDK & Minimal Dashboard | 0/TBD | Not started | - |
| 6. Observability, Compliance & Red-Team Gate | 0/TBD | Not started | - |
| 7. Trust, Reputation & Identity Hardening | 0/TBD | Not started | - |
| 8. Full Security Engine & MCP Gateway | 0/TBD | Not started | - |
| 9. Runtime Containment & Consensus | 0/TBD | Not started | - |
| 10. Gateway PEP, Second Adapter & Live Graph | 0/TBD | Not started | - |
| 11. Merkle Audit, Economics, ABOM & Compliance Export | 0/TBD | Not started | - |
| 12. Continuous Adversarial Validation & Rich Dashboard | 0/TBD | Not started | - |
| 13. Constitution Amendments & Conflict Reasoning | 0/TBD | Not started | - |
| 14. Self-Play, ZK Proofs, Decentralized Identity & Rust Hot Path | 0/TBD | Not started | - |
