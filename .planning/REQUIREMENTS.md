# Requirements: agentos-guard

**Defined:** 2026-06-01
**Core Value:** Every agent action is intercepted at runtime and returned an explainable, graduated decision grounded in policy + a human-readable constitution, with tamper-evident audit evidence — making unsafe agent behavior structurally impossible rather than merely unlikely.

## Scope note

The milestone scope is the **full documented vision (Phases 0–2)**. Every requirement below is committed (v1) and carries a build-phase tag — **[P0]** MVP / parity walking skeleton, **[P1]** trust · containment · security · scale, **[P2]** moonshot (speculative, hard-gated on the P0/P1 substrate). Phase tags inform roadmap sequencing; they do not change commitment. Source of truth: `docs/architecture/` (authoritative) + `.planning/research/SUMMARY.md`.

## v1 Requirements

### Interception & PEP

- [x] **INT-01** [P0]: A LangChain/LangGraph agent's tool calls are intercepted before execution via SDK middleware and normalized into an `AgentAction`
- [x] **INT-02** [P0]: Model invocations are intercepted and normalized into an `AgentAction`
- [x] **INT-03** [P0]: Memory-access operations are intercepted and normalized into an `AgentAction`
- [x] **INT-04** [P0]: MCP-server calls are intercepted and normalized into an `AgentAction`
- [x] **INT-05** [P0]: Agent-to-agent delegation is intercepted and normalized into an `AgentAction` with `parent_action_id` lineage
- [x] **INT-06** [P0]: An interception-coverage check verifies all five action types are hooked and detects un-instrumented paths (no silent gaps)
- [ ] **INT-07** [P1]: A framework-agnostic network gateway/proxy PEP intercepts actions without SDK changes, behind the same pipeline contract
- [ ] **INT-08** [P1]: At least one additional framework adapter (e.g. CrewAI or OpenAI Agents SDK) intercepts actions
- [ ] **INT-09** [P2]: A Kubernetes sidecar/operator PEP intercepts at the network layer behind the same contract

### Decision Pipeline

- [x] **PIPE-01** [P0]: Each `AgentAction` passes synchronously through ordered stages identity/trust → policy → risk → graduated response, producing one `Decision`
- [x] **PIPE-02** [P0]: Every stage contributes machine-readable `reasons` (fired policies/principles) to the `Decision` for explainability
- [x] **PIPE-03** [P0]: A stage can short-circuit to a terminal outcome (e.g. forged identity → deny) without running later stages
- [x] **PIPE-04** [P0]: Pipeline overhead for cached policy/identity stays within a defined p95 latency budget (low single-digit ms), verified by a benchmark test
- [x] **PIPE-05** [P0]: Fail-closed vs fail-open on control-plane unavailability is a per-action-class policy decision; high-risk classes default fail-closed; no silent allow
- [x] **PIPE-06** [P0]: The control plane maintains its own decision/identity/compiled-policy cache (OPA does not cache), invalidated on policy-version change
- [x] **PIPE-07** [P0]: A stable, serializable `contract` package (`AgentAction` + `evaluate() -> Decision`) is the single dependency every PEP form uses
- [x] **PIPE-08** [P0]: Every `Decision` is an *explainable denial with remediation* (pillar 5) — `reasons` carry `{principle_ref, rationale, evidence}`, plus `inferred_intent` and concrete `remediation` paths, not just a rule id
- [x] **PIPE-09** [P0]: A `Decision` carries a set of composable `side_effects` (`notify`, `additional_monitoring`, `risk_flag`, `create_incident`) orthogonal to its gating `outcome`, so one decision can both permit and escalate (e.g. `allow + risk_flag`, `deny + create_incident`)

### Constitution, Policy & Graduated Response

- [x] **POL-01** [P0]: An operator authors a human-readable Constitution of numbered principles as a declarative resource
- [x] **POL-02** [P0]: A compiler lowers Constitution principles into structured YAML policies scoped to agents/tools/action types
- [x] **POL-03** [P0]: YAML policies compile to OPA/Rego and are evaluated deterministically on the hot path behind a `PolicyEngine` interface (OPA-server in P0, opa-wasm togglable)
- [x] **POL-04** [P0]: On no-rule/ambiguous results, an LLM semantic interpreter returns `{outcome, cited principle, rationale}` via structured outputs — never an unexplained verdict
- [x] **POL-05** [P0]: The semantic interpreter is advisory-only, runs only on flagged ambiguity, and can never upgrade a high-risk action beyond the deterministic policy floor
- [x] **POL-06** [P0]: The graduated-response stage maps {policy, risk, trust} to one outcome in {allow, warn, sandbox, require_consensus, require_approval, deny} with policy-driven thresholds
- [x] **POL-07** [P0]: A `require_approval` outcome parks an `ApprovalRequest` with full action context, fired principles, and risk/trust scores; the action blocks until resolved or times out to a safe default
- [x] **POL-08** [P0]: Every `Decision` records the exact Constitution/Policy version that evaluated the action
- [ ] **POL-09** [P1]: A `require_consensus` outcome requires 2-of-3 agent agreement before the action proceeds
- [ ] **POL-10** [P2]: Agents or the self-play trainer can propose Constitution amendments; humans review and ratify; the Constitution is versioned like a legal document
- [ ] **POL-11** [P2]: A conflict-resolution engine computes transitive permissions across delegation chains and flags emergent capability conflicts
- [ ] **POL-12** [P2]: BFT consensus backs multi-agent agreement for `require_consensus` at scale
- [x] **POL-13** [P0]: A `temporary_exception` outcome grants a **human-ratified, time-boxed** `allow` (carries `expires_at`) that auto-revokes on expiry; the semantic interpreter may recommend but can never grant one (upholds POL-05's policy-floor invariant)
- [x] **POL-14** [P0]: A `governance_review` outcome lets the action proceed while opening an **asynchronous, non-blocking** governance review (distinct from `require_approval`, which blocks)

### Security Engine — Detection / Risk

- [x] **SEC-01** [P0]: The risk stage scores prompt-injection patterns in tool inputs, retrieved content, and inter-agent messages, contributing to `risk_score` with typed findings
- [x] **SEC-02** [P0]: Baseline runtime guardrails score PII, unsafe content, and format violations on inputs/outputs
- [x] **SEC-03** [P0]: Detectors are pluggable scorers — cheap heuristics run inline, expensive models only when flagged
- [ ] **SEC-04** [P1]: Data-exfiltration detection scores outbound payloads carrying secrets/PII to untrusted targets
- [ ] **SEC-05** [P1]: Secret-leakage detection flags credentials/keys in prompts, tool args, or outputs
- [ ] **SEC-06** [P1]: Tool-poisoning detection flags malicious/drifted tool definitions (P0 records tool-manifest hashes for after-the-fact detection)
- [ ] **SEC-07** [P1]: An MCP security gateway inspects/normalizes MCP interactions and quarantines hostile tool manifests
- [ ] **SEC-08** [P1]: Supply-chain checks cross-reference an agent's ABOM against known-bad models/prompts/tools
- [ ] **SEC-09** [P1]: A memory/context-poisoning detector flags malicious memory writes/reads (OWASP ASI06)
- [ ] **SEC-10** [P1]: Inter-agent communication is authenticated and agent identity/card is verified on delegation (OWASP ASI07)
- [ ] **SEC-11** [P1]: A code-execution detector flags unsafe dynamic code/command execution by agents (OWASP ASI05)
- [x] **SEC-12** [P0]: Intent-based policy (pillar 3) — deterministic intent-class tags map single actions to a coarse intent class (e.g. `DATA_DESTRUCTION`), contributing to `risk_score` and populating `Decision.inferred_intent`; advisory to the policy floor, never a substitute for it
- [x] **SEC-13** [P0]: Sequence/lineage intent analysis over delegation chains catches multi-step evasions (e.g. `rename_then_drop`, copy-then-delete) that no single action string matches — *pulled forward from P1 (2026-06-10): cross-action correlation is a durable AGT gap (their stateless kernel can't retrofit it) and the demoable wedge; see `docs/architecture/30-comparison-agt.md`*
- [ ] **SEC-14** [P1]: An embedding-similarity intent classifier flags novel actions semantically close to a forbidden-intent exemplar, running only when deterministic tags are ambiguous

### Runtime Security — Containment

- [x] **RUN-01** [P0]: An operator can kill-switch a single agent, immediately halting its actions
- [x] **RUN-02** [P0]: An operator can kill-switch the entire fleet immediately
- [ ] **RUN-03** [P1]: A `sandbox` outcome runs the action in an isolated context with quarantined or reversible side effects
- [ ] **RUN-04** [P1]: Privilege rings gate sensitive tools behind higher capability tiers per agent
- [ ] **RUN-05** [P1]: Resource isolation enforces CPU/memory/network limits per agent execution
- [ ] **RUN-06** [P1]: Circuit breakers auto-trip an agent/tool after a threshold of violations or errors
- [ ] **RUN-07** [P1]: Emergency shutdown stops the fleet with an audit-logged justification

### Identity

- [x] **IDN-01** [P0]: Each `Agent` registers and is issued a signed identity token
- [x] **IDN-02** [P0]: The identity stage verifies the token; forged/unknown identity short-circuits to deny
- [ ] **IDN-03** [P1]: Agents are issued X.509-style certificates binding identity to keys
- [ ] **IDN-04** [P2]: SPIFFE/SVID workload identity enables zero-trust mTLS

### Trust & Reputation

- [x] **TRST-01** [P0]: Each `Agent` has a 0–1 trust score consumed by the graduated-response stage
- [x] **TRST-02** [P0]: Trust modulates outcome within a policy-defined band but never overrides a deterministic policy decision
- [ ] **TRST-03** [P1]: A longitudinal reputation score is derived from violation/approval history
- [ ] **TRST-04** [P1]: Trust propagates (and decays) across delegation edges as a bounded budget; delegated scope is enforced as an intersection, not a union
- [ ] **TRST-05** [P2]: Portable, longitudinal reputation is exportable across deployments via an **optional, deployment-pluggable** reputation backend; any stake/slashing economics live *only* in that optional backend and are **never required** to run the control plane (ADR-0007 — crypto-economics fenced out of core)

### Discovery & Agent Graph

- [x] **DISC-01** [P0]: Agents self-register via the SDK and appear in an authoritative agent inventory
- [x] **DISC-02** [P0]: The inventory tracks known agents, tools, prompts, and memories
- [ ] **DISC-03** [P1]: Framework discovery detects LangChain/LangGraph, CrewAI, AutoGen, OpenAI Agents SDK, MCP, etc.
- [ ] **DISC-04** [P1]: Shadow-agent detection flags agents acting without registration
- [ ] **DISC-05** [P1]: Rogue-agent detection flags agents diverging from declared scope
- [ ] **DISC-06** [P1]: A live agent graph materializes agents/tools/MCP/models/memories and delegation edges; lineage derives from `parent_action_id`

### Audit

- [x] **AUD-01** [P0]: Each `Decision` appends an `AuditRecord` to an append-only, hash-chained log (each record includes the prior record's hash)
- [x] **AUD-02** [P0]: Each `AuditRecord` links `AgentAction` → `Decision` → fired policies/principles → outcome
- [x] **AUD-03** [P0]: Each `AuditRecord` carries the exact policy/constitution version (policy evidence)
- [x] **AUD-04** [P0]: Sensitive payloads are redacted at write time per policy; redaction fails closed (no write if redaction fails)
- [x] **AUD-05** [P0]: A verifier (runnable in CI) detects any retroactive edit by re-validating the hash chain; chain checkpoints are externally anchored/signed
- [ ] **AUD-06** [P1]: The hash chain is upgraded to a Merkle DAG enabling inclusion proofs and partial disclosure
- [ ] **AUD-07** [P2]: Zero-knowledge compliance proofs prove properties (e.g. "no PII exfiltrated") without revealing underlying data
- [x] **AUD-08** [P0]: Each `AuditRecord` carries a detached per-record EdDSA signature (reusing identity keys) so a single record verifies independently of the chain — proving the control plane authored that decision
- [ ] **AUD-09** [P1]: A forensic "evidence graph" reconstructs causal chains by joining the audit log with the materialized agent graph at query time (`parent_action_id`/`conversation_id`/`trace_id`, Postgres recursive CTEs) — no separate graph database

### Compliance

- [x] **CMP-01** [P0]: Each detector/policy maps to OWASP Agentic Top 10 categories
- [x] **CMP-02** [P0]: Policy + audit evidence maps to NIST AI RMF (Govern/Map/Measure/Manage)
- [x] **CMP-03** [P0]: Minimal logging + human-oversight evidence supports EU AI Act Art. 12 / Art. 26 claims at launch (obligations bind 2026-08-02)
- [ ] **CMP-04** [P1]: Full EU AI Act mapping (risk classification, logging, human oversight) is produced
- [ ] **CMP-05** [P1]: SOC 2 control evidence (access, change, monitoring) is derived from the audit log
- [ ] **CMP-06** [P1]: One-click export produces evidence bundles per framework and time range

### Testing & Red-Team

- [x] **TEST-01** [P0]: Engineers write pytest safety tests using provided fixtures/adapters that run an attack library against an agent
- [x] **TEST-02** [P0]: A prompt-injection attack suite (garak/PyRIT-backed) runs in CI
- [x] **TEST-03** [P0]: Red-team suites cover tool misuse, exfiltration, and jailbreak scenarios
- [x] **TEST-04** [P0]: Safety assertions use statistical thresholds (e.g. attack-success-rate < X%), not single runs
- [x] **TEST-05** [P0]: Fixed vulnerabilities are locked by regression tests so they cannot silently return
- [x] **TEST-06** [P0]: A failing safety test breaks the CI build
- [ ] **TEST-07** [P1]: Attack-success-rate is tracked over time per agent/attack class
- [ ] **TEST-08** [P1]: Continuous validation re-runs suites against the live agent on a schedule
- [ ] **TEST-09** [P1]: Multi-step adversarial simulations run campaign-style attacks
- [ ] **TEST-10** [P2]: Continuous adversarial self-play generates novel attacks, scores defenses, and proposes Constitution/policy patches (human-ratified, held-out eval)
- [ ] **TEST-11** [P2]: A runtime-patching path rolls out ratified defenses; a threat-intel feed imports emerging attack patterns

### Observability

- [x] **OBS-01** [P0]: Every `AgentAction`/`Decision` is emitted as an OpenTelemetry span to the user's backend
- [x] **OBS-02** [P0]: `trace_id` correlates an action across pipeline stages and across agents (distributed tracing)
- [x] **OBS-03** [P0]: Per-agent metrics (action volume, outcome mix, violation counts, p95 pipeline latency) are emitted
- [ ] **OBS-04** [P1]: Agent health monitoring tracks liveness/error-rate/circuit-breaker state per agent
- [ ] **OBS-05** [P1]: Conversation tracing reconstructs a full conversation across tools and delegations
- [ ] **OBS-06** [P1]: Per-agent SLO and violation dashboards with attack visualization

### Economics

- [ ] **ECON-01** [P1]: Token/API cost is attributed to each agent/action
- [ ] **ECON-02** [P1]: Token/budget limits are expressed as policy; over-budget actions are denied/escalated by the graduated-response engine
- [ ] **ECON-03** [P1]: GPU usage and downstream API consumption are attributed per agent
- [ ] **ECON-04** [P2]: ROI analytics present value-vs-cost per agent/workflow

### ABOM (Supply Chain)

- [ ] **ABOM-01** [P1]: Each `Agent` declares an Agent Bill of Materials (models, prompts, tools, MCP servers) as a resource
- [ ] **ABOM-02** [P1]: ABOM components are versioned with provenance
- [ ] **ABOM-03** [P2]: Vulnerability impact analysis answers "which agents use compromised component vX?" instantly

### Control-Plane API & Persistence

- [x] **API-01** [P0]: A declarative API validates, versions, and stores resources (Agent, Constitution, Policy, TrustProfile, ApprovalRequest, ABOM) in PostgreSQL
- [x] **API-02** [P0]: Applying a Constitution compiles it to Policy/Rego on write (compile-on-write)
- [x] **API-03** [P0]: Operators approve/deny `ApprovalRequest`s via the API
- [ ] **API-04** [P1]: Reconciliation loops continuously compile constitutions, refresh trust, materialize the graph, and warm hot-path caches

### Python SDK

- [x] **SDK-01** [P0]: The SDK provides interception decorators/middleware for LangChain/LangGraph (the PEP)
- [x] **SDK-02** [P0]: The SDK provides agent self-registration returning an identity token
- [x] **SDK-03** [P0]: The SDK provides pytest adapters for the red-team layer
- [x] **SDK-04** [P0]: The SDK provides a control-plane client for resource CRUD and approvals
- [x] **SDK-05** [P0]: A zero-infra quickstart runs the full governed loop with SQLite + in-process opa-wasm from a single `pip install` — no Docker, Postgres, or OPA server required (first-run friction must match AGT's one-decorator pitch)

### Dashboard

- [x] **DASH-01** [P0]: A minimal dashboard shows read-only agent inventory and recent decisions/audit
- [x] **DASH-02** [P0]: Operators resolve pending `ApprovalRequest`s from the dashboard
- [x] **DASH-03** [P0]: Operators trigger agent/fleet kill switches from the dashboard
- [ ] **DASH-04** [P1]: The dashboard adds the live agent graph, per-agent SLOs/violations, and attack visualization

### OSS Distribution & Community

- [ ] **OSS-01** [P0]: Versioned releases of the workspace packages (and the quickstart extra) are published to PyPI via a tagged release workflow, so the zero-infra quickstart's single `pip install` (SDK-05) is true for someone outside this repository — added 2026-07-05 audit: the "best in open source" goal had zero distribution requirements
- [x] **OSS-02** [P0]: Adoption and security table stakes ship with the P0 launch: `CONTRIBUTING.md`, `SECURITY.md` (vulnerability-disclosure policy — non-negotiable for a security product), and issue/PR templates

### Performance

- [ ] **PERF-01** [P2]: Hot-path enforcement components are rewritten in Rust (PyO3 interop) where profiling justifies it

## v2 Requirements

Deferred beyond the documented vision. Tracked but not in the current roadmap.

### Compliance

- **CMP-V2-01**: Additional compliance frameworks beyond OWASP/NIST/EU/SOC2 (e.g. HIPAA, FedRAMP, ISO 42001)

### Identity & Policy

- **POL-V2-01**: Cedar as an alternative policy backend alongside OPA/Rego
- **IDN-V2-01**: DID-based decentralized identity interop

## Out of Scope

Explicitly excluded. Documented to prevent scope creep.

| Feature | Reason |
|---------|--------|
| Training or hosting the agents themselves | agentos-guard *governs* agents; it is not an agent framework |
| Managed SaaS offering | Open-source and self-hosted first |
| Replacing existing observability backends | We emit OpenTelemetry and integrate, not replace |
| Non-Python SDKs (TypeScript, Go) | Deferred until the Python surface stabilizes (ADR-0001) |
| Kubernetes as a Phase 0 requirement | Phase 0 is self-hosted (API + Postgres + dashboard); K8s operator/sidecar is Phase 2 |

## Traceability

Every v1 requirement maps to exactly one phase. Phases 1–6 deliver the documented Phase-0 parity loop, Phases 7–12 the Phase-1 substrate, and Phases 13–14 the hard-gated Phase-2 moonshot.

| Requirement | Phase | Status |
|-------------|-------|--------|
| INT-01 | Phase 1 | Complete |
| INT-02 | Phase 2 | Complete |
| INT-03 | Phase 2 | Complete |
| INT-04 | Phase 2 | Complete |
| INT-05 | Phase 2 | Complete |
| INT-06 | Phase 2 | Complete |
| INT-07 | Phase 10 | Pending |
| INT-08 | Phase 10 | Pending |
| INT-09 | Phase 14 | Pending |
| PIPE-01 | Phase 1 | Complete |
| PIPE-02 | Phase 1 | Complete |
| PIPE-03 | Phase 1 | Complete |
| PIPE-04 | Phase 3 | Complete |
| PIPE-05 | Phase 3 | Complete |
| PIPE-06 | Phase 3 | Complete |
| PIPE-07 | Phase 1 | Complete |
| PIPE-08 | Phase 3 | Complete |
| PIPE-09 | Phase 3 | Complete |
| POL-01 | Phase 3 | Complete |
| POL-02 | Phase 3 | Complete |
| POL-03 | Phase 1 | Complete |
| POL-04 | Phase 3 | Complete |
| POL-05 | Phase 3 | Complete |
| POL-06 | Phase 1 | Complete |
| POL-07 | Phase 3 | Complete |
| POL-08 | Phase 3 | Complete |
| POL-09 | Phase 9 | Pending |
| POL-10 | Phase 13 | Pending |
| POL-11 | Phase 13 | Pending |
| POL-12 | Phase 13 | Pending |
| POL-13 | Phase 3 | Complete |
| POL-14 | Phase 3 | Complete |
| SEC-01 | Phase 1 | Complete |
| SEC-02 | Phase 3 | Complete |
| SEC-03 | Phase 3 | Complete |
| SEC-04 | Phase 8 | Pending |
| SEC-05 | Phase 8 | Pending |
| SEC-06 | Phase 8 | Pending |
| SEC-07 | Phase 8 | Pending |
| SEC-08 | Phase 8 | Pending |
| SEC-09 | Phase 8 | Pending |
| SEC-10 | Phase 8 | Pending |
| SEC-11 | Phase 8 | Pending |
| SEC-12 | Phase 3 | Complete |
| SEC-13 | Phase 3 | Complete |
| SEC-14 | Phase 8 | Pending |
| RUN-01 | Phase 4 | Complete |
| RUN-02 | Phase 4 | Complete |
| RUN-03 | Phase 9 | Pending |
| RUN-04 | Phase 9 | Pending |
| RUN-05 | Phase 9 | Pending |
| RUN-06 | Phase 9 | Pending |
| RUN-07 | Phase 9 | Pending |
| IDN-01 | Phase 1 | Complete |
| IDN-02 | Phase 1 | Complete |
| IDN-03 | Phase 7 | Pending |
| IDN-04 | Phase 14 | Pending |
| TRST-01 | Phase 1 | Complete |
| TRST-02 | Phase 3 | Complete |
| TRST-03 | Phase 7 | Pending |
| TRST-04 | Phase 7 | Pending |
| TRST-05 | Phase 14 | Pending |
| DISC-01 | Phase 5 | Complete |
| DISC-02 | Phase 5 | Complete |
| DISC-03 | Phase 10 | Pending |
| DISC-04 | Phase 10 | Pending |
| DISC-05 | Phase 10 | Pending |
| DISC-06 | Phase 10 | Pending |
| AUD-01 | Phase 1 | Complete |
| AUD-02 | Phase 4 | Complete |
| AUD-03 | Phase 4 | Complete |
| AUD-04 | Phase 4 | Complete |
| AUD-05 | Phase 4 | Complete |
| AUD-06 | Phase 11 | Pending |
| AUD-07 | Phase 14 | Pending |
| AUD-08 | Phase 4 | Complete |
| AUD-09 | Phase 12 | Pending |
| CMP-01 | Phase 6 | Complete |
| CMP-02 | Phase 6 | Complete |
| CMP-03 | Phase 6 | Complete |
| CMP-04 | Phase 11 | Pending |
| CMP-05 | Phase 11 | Pending |
| CMP-06 | Phase 11 | Pending |
| TEST-01 | Phase 6 | Complete |
| TEST-02 | Phase 6 | Complete |
| TEST-03 | Phase 6 | Complete |
| TEST-04 | Phase 6 | Complete |
| TEST-05 | Phase 6 | Complete |
| TEST-06 | Phase 6 | Complete |
| TEST-07 | Phase 12 | Pending |
| TEST-08 | Phase 12 | Pending |
| TEST-09 | Phase 12 | Pending |
| TEST-10 | Phase 14 | Pending |
| TEST-11 | Phase 14 | Pending |
| OBS-01 | Phase 6 | Complete |
| OBS-02 | Phase 6 | Complete |
| OBS-03 | Phase 6 | Complete |
| OBS-04 | Phase 12 | Pending |
| OBS-05 | Phase 12 | Pending |
| OBS-06 | Phase 12 | Pending |
| ECON-01 | Phase 11 | Pending |
| ECON-02 | Phase 11 | Pending |
| ECON-03 | Phase 11 | Pending |
| ECON-04 | Phase 14 | Pending |
| ABOM-01 | Phase 8 | Pending |
| ABOM-02 | Phase 8 | Pending |
| ABOM-03 | Phase 14 | Pending |
| API-01 | Phase 5 | Complete |
| API-02 | Phase 5 | Complete |
| API-03 | Phase 3 | Complete |
| API-04 | Phase 7 | Pending |
| SDK-01 | Phase 1 | Complete |
| SDK-02 | Phase 5 | Complete |
| SDK-03 | Phase 6 | Complete |
| SDK-04 | Phase 5 | Complete |
| SDK-05 | Phase 5 | Complete |
| DASH-01 | Phase 5 | Complete |
| DASH-02 | Phase 5 | Complete |
| DASH-03 | Phase 5 | Complete |
| DASH-04 | Phase 12 | Pending |
| OSS-01 | Phase 6 | Pending |
| OSS-02 | Phase 6 | Complete |
| PERF-01 | Phase 14 | Pending |

**Coverage:**
- v1 requirements: 123 total
- Mapped to phases: 123 ✓
- Unmapped: 0

---
*Requirements defined: 2026-06-01*
*Last updated: 2026-07-12 — Phase 6 slices 6a–6e merged (PR #16): marked OBS-01/02/03, CMP-01/02/03, TEST-01–06, SDK-03 Complete. OSS-01 (PyPI release workflow — `.github/workflows/release.yml` added; PyPI Trusted Publisher setup pending) and OSS-02 (`SECURITY.md` + `CONTRIBUTING.md` + issue/PR templates added) are the remaining Phase 6 items; OSS-01 stays Pending until the first tagged release publishes. 123/123 mapped.*
*Previous: 2026-07-05 — post-Phase-5 planning audit: marked the 36 requirements delivered by Phases 3–5 Complete (checkboxes + traceability were stale at "Pending"); added OSS-01/OSS-02 (PyPI release engineering + CONTRIBUTING/SECURITY.md, Phase 6) — the open-source-market goal had no distribution/community requirements; 123/123 mapped*
*Previous: 2026-06-10 — AGT v4.1.0 re-verification: pulled SEC-13 (sequence/lineage intent correlation) forward P1→P0 / Phase 8→Phase 3 (durable AGT gap, demoable wedge); added SDK-05 (zero-infra SQLite + opa-wasm quickstart, Phase 5); 121/121 mapped*
*Previous: 2026-06-06 — added graduated-response extensions PIPE-09 (composable side-effects), POL-13 (temporary_exception), POL-14 (governance_review), AUD-08 (per-record signatures), AUD-09 (query-time evidence graph)*
