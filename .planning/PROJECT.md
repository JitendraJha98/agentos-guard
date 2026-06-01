# agentos-guard

## What This Is

agentos-guard is an open-source **governance and security control plane for AI agents**. It sits between AI agents and everything they touch — tools, memory, MCP servers, models, APIs, and each other — intercepts **every action** at runtime, evaluates it against declarative policy and a human-readable **constitution**, attaches cryptographic identity and a dynamic **trust score**, and returns a **graduated decision** (allow / warn / sandbox / require_consensus / require_approval / deny). Every decision is written to a tamper-evident, hash-chained audit log as compliance evidence, and a pytest-native red-team layer makes safety regressions fail CI like a unit test.

It is for **platform, security, and governance teams** running fleets of AI agents in production who need to *see*, *prove*, *govern*, *secure*, and *test* agent behavior from one place. It governs agents — it is **not** itself an agent framework.

## Core Value

Every agent action is intercepted at runtime and returned an **explainable, graduated decision** grounded in policy + a human-readable constitution, with tamper-evident audit evidence — making unsafe agent behavior *structurally impossible* rather than merely unlikely.

If everything else fails, the runtime **Decision Pipeline** (intercept → normalize → decide → enforce → record) must work.

## Requirements

### Validated

<!-- Shipped and confirmed valuable. -->

(None yet — design-only project, no code. Ship to validate.)

### Active

Building toward the full vision (Phases 0–2). Phase tags reflect the documented build sequence: **P0** = MVP that beats AGT, **P1** = trust / sandbox / scale, **P2** = moonshot differentiators.

**Interception & Pipeline**
- [ ] Intercept every agent action via Python SDK shim for LangChain/LangGraph; normalize to a single `AgentAction` event (P0)
- [ ] Synchronous Decision Pipeline — identity/trust → policy → risk → graduated response — each stage contributing explainability reasons (P0)
- [ ] Gateway/proxy interception (framework-agnostic) + additional framework adapters (P1)
- [ ] Kubernetes sidecar/operator data-plane interception (P2)

**Constitution & Policy**
- [ ] Human-readable Constitution → compiled YAML → OPA/Rego deterministic enforcement (P0)
- [ ] LLM semantic interpreter for ambiguous/novel cases, returning cited-principle rationale (P0)
- [ ] Graduated response engine mapping {policy, risk, trust} → outcome with policy-driven thresholds (P0)
- [ ] Human approval workflow via `ApprovalRequest` (P0)
- [ ] 2-of-3 multi-agent consensus outcome (P1)
- [ ] Constitution amendment proposals + cross-agent conflict-resolution / legal reasoning (P2)

**Security & Runtime**
- [ ] Prompt-injection detection + baseline runtime guardrails (PII / unsafe content / format) (P0)
- [ ] Operator kill switch — halt an agent or the whole fleet (P0)
- [ ] Data-exfiltration, secret-leakage, tool-poisoning detection; MCP security gateway; supply-chain checks (P1)
- [ ] Sandboxed execution, privilege rings, resource isolation, circuit breakers, emergency shutdown (P1)

**Identity, Trust & Discovery**
- [ ] Agent identity management with signed tokens; forged/unknown identity short-circuits to deny (P0)
- [ ] Basic 0–1 trust score consumed by the graduated-response stage (P0)
- [ ] SDK self-registration + authoritative agent inventory (P0)
- [ ] Reputation scoring, trust propagation, delegation trust chains, agent certificates (P1)
- [ ] Framework / shadow-agent / rogue-agent discovery; live agent graph + lineage (P1)
- [ ] SPIFFE/mTLS identity; stake-based accountability + portable decentralized reputation (P2)

**Audit & Compliance**
- [ ] Tamper-evident hash-chained audit log; decision records with policy-version provenance (P0)
- [ ] OWASP Agentic Top 10 + NIST AI RMF baseline compliance mapping (P0)
- [ ] Merkle DAG audit upgrade; EU AI Act + SOC 2 mapping; one-click compliance report export (P1)
- [ ] Zero-knowledge compliance proofs (RISC Zero / SP1) (P2)

**Testing & Red-Team**
- [ ] pytest-native red-team layer: injection suites, attack library, statistical safety thresholds, security-regression locks in CI (P0)
- [ ] Attack-success-rate tracking, continuous validation, multi-step adversarial simulations (P1)
- [ ] Continuous adversarial self-play + runtime patching + threat-intel feed (P2)

**Observability, Economics & ABOM**
- [ ] OpenTelemetry spans/metrics, distributed tracing, per-agent metrics (P0)
- [ ] Agent health monitoring, conversation tracing, per-agent SLO/violation dashboards (P1)
- [ ] Cost monitoring + token/GPU/API budgets enforced as policy; ABOM dependency tracking (P1)
- [ ] ROI analytics; ABOM vulnerability impact analysis (P2)

**Control Plane, API, SDK & Dashboard**
- [ ] Declarative Control-Plane API (Agent / Constitution / Policy / TrustProfile / ApprovalRequest / ABOM) on Postgres; compile-on-write (P0)
- [ ] Python SDK: interception decorators/middleware, registration, pytest adapters, control-plane client (P0)
- [ ] Minimal dashboard: read-only views + approvals + kill switch (P0)
- [ ] Reconciliation loops; richer dashboard (live graph, SLOs, attack visualization) (P1)
- [ ] BFT consensus; Rust rewrite of hot-path enforcement where profiling justifies it (P2)

### Out of Scope

<!-- Explicit boundaries. Includes reasoning to prevent re-adding. -->

- Training or hosting the agents themselves — agentos-guard *governs* agents; it is not an agent framework.
- Managed SaaS — open-source and self-hosted first.
- Replacing existing observability backends — we emit OpenTelemetry and integrate, not replace.
- Non-Python SDKs (TypeScript, Go) — deferred until the Python surface stabilizes (ADR-0001).
- Kubernetes as a Phase 0 requirement — Phase 0 runs self-hosted (API + Postgres + dashboard) with no K8s; the K8s-native operator/sidecar is Phase 2.

## Context

- **Design is fully documented** in `docs/architecture/` (README + docs 01–10 + 20-roadmap + 30-comparison + ADRs 0001–0006). These are **authoritative** and the source of truth for planning. No implementation exists yet.
- Directly inspired by, and positioned to **surpass**, Microsoft's **Agent Governance Toolkit (AGT)** and **RAMPART**. Five differentiation dimensions:
  1. Living semantic **constitution** (vs static YAML rules)
  2. **Graduated** response (vs binary allow/deny)
  3. Continuous, pytest-native adversarial **self-play** (vs pre-deployment red team)
  4. **Zero-knowledge** compliance proofs (vs tamper-evident logs alone)
  5. Decentralized, stake-based **reputation** (vs SPIFFE/mTLS-only identity)
- Borrows the **Kubernetes mental model**: a *data plane* (Policy Enforcement Points in the request path) + a *control plane* (engines that decide, store state, observe). Everything is a declarative resource reconciled toward desired state.
- The **request lifecycle** (intercept → normalize → decide → enforce → record) is the contract every engine plugs into; it stays stable across all three phases.
- Each documented phase is **independently shippable and demoable**. Phase 0 alone is intended to beat AGT before any moonshot feature is built.

## Constraints

- **Tech stack**: Python-first; Rust reserved for hot-path enforcement only, in a later phase, where profiling justifies it (ADR-0001).
- **Enforcement (v1)**: SDK interception (LangChain/LangGraph first); gateway + K8s come later behind the same pipeline contract (ADR-0002).
- **Policy substrate**: human-readable Constitution → compiled YAML → OPA/Rego, with an LLM semantic interpreter for ambiguous/graduated cases (ADR-0003). OPA chosen as CNCF-graduated, deterministic, side-effect-free.
- **Audit**: tamper-evident hash-chained log with policy-version provenance; Merkle DAG upgrade later (ADR-0004).
- **Decisioning**: graduated response, not binary allow/deny (ADR-0005).
- **Storage**: PostgreSQL for resources/state and the append-only hash-chained audit table (Phase 0).
- **Observability**: emit OpenTelemetry to the user's backend — integrate, don't replace.
- **Failure posture**: fail-safe vs fail-open is a per-agent / per-action-class **policy** decision, not hard-coded; high-risk classes default fail-closed.
- **Licensing / distribution**: open-source, self-hosted first.

## Key Decisions

<!-- Decisions that constrain future work. Add throughout project lifecycle. -->

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Python-first; Rust only for later hot paths | Ecosystem fit (LangChain/LangGraph, OPA, ML libs); optimize after profiling | — Pending (ADR-0001) |
| SDK interception as the v1 Policy Enforcement Point | Lowest-friction adoption; gateway/sidecar later behind the same contract | — Pending (ADR-0002) |
| Constitution → YAML → OPA/Rego policy substrate | Human-reviewable principles + deterministic, battle-tested enforcement | — Pending (ADR-0003) |
| Hash-chained tamper-evident audit log | Simple, verifiable start; Merkle DAG / ZK proofs later | — Pending (ADR-0004) |
| Graduated response instead of allow/deny | Signature differentiator over AGT | — Pending (ADR-0005) |
| Product name: agentos-guard | — | — Pending (ADR-0006) |
| Milestone scope = full vision (Phases 0–2) | User chose to roadmap the entire documented vision now | — Pending (this session) |
| Do not gate the MVP on moonshot features | Phase 0 competes with AGT on its own turf before reaching for research-grade features | — Pending |

## Evolution

This document evolves at phase transitions and milestone boundaries.

**After each phase transition** (via `/gsd-transition`):
1. Requirements invalidated? → Move to Out of Scope with reason
2. Requirements validated? → Move to Validated with phase reference
3. New requirements emerged? → Add to Active
4. Decisions to log? → Add to Key Decisions
5. "What This Is" still accurate? → Update if drifted

**After each milestone** (via `/gsd:complete-milestone`):
1. Full review of all sections
2. Core Value check — still the right priority?
3. Audit Out of Scope — reasons still valid?
4. Update Context with current state

---
*Last updated: 2026-06-01 after initialization*
