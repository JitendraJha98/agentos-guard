# agentos-guard

> **This is a planning document — it summarizes, it does not define.** The sections below restate
> the authoritative design ([`../docs/architecture/`](../docs/architecture/)) in condensed form so
> the GSD workflow has a self-contained execution brief. On any conflict, **the design docs win**.
> Pointers to the canonical source are given inline.

## What This Is

agentos-guard is an open-source **governance and security control plane for AI agents**. It sits between AI agents and everything they touch — tools, memory, MCP servers, models, APIs, and each other — intercepts **every action** at runtime, evaluates it against declarative policy and a human-readable **constitution**, attaches cryptographic identity and a dynamic **trust score**, and returns a **graduated decision** (allow / warn / sandbox / require_consensus / require_approval / deny). Every decision is written to a tamper-evident, hash-chained audit log as compliance evidence, and a pytest-native red-team layer makes safety regressions fail CI like a unit test.

It is for **platform, security, and governance teams** running fleets of AI agents in production who need to *see*, *prove*, *govern*, *secure*, and *test* agent behavior from one place. It governs agents — it is **not** itself an agent framework.

## Core Value

Every agent action is intercepted at runtime and returned an **explainable, graduated decision** grounded in policy + a human-readable constitution, with tamper-evident audit evidence — making unsafe agent behavior *structurally impossible* rather than merely unlikely.

If everything else fails, the runtime **Decision Pipeline** (intercept → normalize → decide → enforce → record) must work.

## Requirements

### Validated

<!-- Shipped and confirmed valuable. -->

Shipped by Phases 1–5 (merged to `development` 2026-07-03; ~1,040 tests, CI-gated):

- Full five-type interception (tool/model/memory/MCP/delegation) + `AgentAction` normalization + coverage/bypass checks (Phases 1–2)
- Four-stage decision pipeline with short-circuit, machine-readable reasons, latency benchmark, per-class fail-closed posture, own compiled-policy cache (Phases 1, 3)
- Constitution → YAML → Rego compiler, advisory-only semantic interpreter (Anthropic + NVIDIA adapters) with restrict-only clamp, full graduated outcome spectrum + composable side-effects, approvals, sequence-intent correlation (`rename_then_drop` wedge demo) (Phase 3)
- Tamper-evident audit: hash chain + per-record Ed25519 signatures, fail-closed redaction + secret last gate, CI chain verifier, RFC-3161 anchoring; agent/fleet kill switch (Phase 4)
- Declarative resource API with compile-on-write + optimistic versioning, gated self-registration + inventory, `ControlPlaneClient` SDK, zero-infra SQLite/opa-wasm quickstart, cookie-gated dashboard (Phase 5)

### Active

Building toward the full vision (Phases 0–2). Phase tags reflect the documented build sequence: **P0** = MVP reaching AGT parity + the durable wedge (semantic constitution, sequence-intent correlation), **P1** = trust / sandbox / scale, **P2** = moonshot differentiators.

**Interception & Pipeline**
- [x] Intercept every agent action via Python SDK shim for LangChain/LangGraph; normalize to a single `AgentAction` event (P0)
- [x] Synchronous Decision Pipeline — identity/trust → policy → risk → graduated response — each stage contributing explainability reasons (P0)
- [ ] Gateway/proxy interception (framework-agnostic) + additional framework adapters (P1)
- [ ] Kubernetes sidecar/operator data-plane interception (P2)

**Constitution & Policy**
- [x] Human-readable Constitution → compiled YAML → OPA/Rego deterministic enforcement (P0)
- [x] LLM semantic interpreter for ambiguous/novel cases, returning cited-principle rationale (P0)
- [x] Graduated response engine mapping {policy, risk, trust} → outcome with policy-driven thresholds; outcomes include allow/warn/sandbox/require_consensus/require_approval/temporary_exception (human-ratified, time-boxed)/governance_review (async, non-blocking)/deny, plus composable `side_effects` (notify/additional_monitoring/risk_flag/create_incident) orthogonal to the outcome (P0)
- [x] Human approval workflow via `ApprovalRequest` (P0)
- [ ] 2-of-3 multi-agent consensus outcome (P1)
- [ ] Constitution amendment proposals + cross-agent conflict-resolution / legal reasoning (P2)

**Security & Runtime**
- [x] Prompt-injection detection + baseline runtime guardrails (PII / unsafe content / format) (P0)
- [x] Operator kill switch — halt an agent or the whole fleet (P0)
- [ ] Data-exfiltration, secret-leakage, tool-poisoning detection; MCP security gateway; supply-chain checks (P1)
- [ ] Sandboxed execution, privilege rings, resource isolation, circuit breakers, emergency shutdown (P1)

**Identity, Trust & Discovery**
- [x] Agent identity management with signed tokens; forged/unknown identity short-circuits to deny (P0)
- [x] Basic 0–1 trust score consumed by the graduated-response stage (P0)
- [x] SDK self-registration + authoritative agent inventory (P0)
- [ ] Reputation scoring, trust propagation, delegation trust chains, agent certificates (P1)
- [ ] Framework / shadow-agent / rogue-agent discovery; live agent graph + lineage (P1)
- [ ] SPIFFE/mTLS identity; portable, exportable reputation via an optional pluggable backend (any stake/slashing economics confined to that backend, never required — ADR-0007) (P2)

**Audit & Compliance**
- [x] Tamper-evident hash-chained audit log with per-record EdDSA signatures (single-record verifiable); decision records with policy-version provenance; forensic evidence graph by joining the audit log with the agent graph at query time — no separate graph DB (P0 log/signing; P1 evidence-graph join) (P0)
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
- [x] Declarative Control-Plane API (Agent / Constitution / Policy / TrustProfile / ApprovalRequest / ABOM) on Postgres; compile-on-write (P0)
- [ ] Python SDK: interception decorators/middleware, registration, pytest adapters, control-plane client (P0) — *shipped except the pytest adapters (SDK-03, Phase 6)*
- [x] Zero-infra quickstart: full governed loop on SQLite + in-process opa-wasm from a single `pip install` — no Docker/Postgres/OPA server (P0)
- [x] Minimal dashboard: read-only views + approvals + kill switch (P0)
- [ ] Reconciliation loops; richer dashboard (live graph, SLOs, attack visualization) (P1)
- [ ] BFT consensus; Rust rewrite of hot-path enforcement where profiling justifies it (P2)

### Out of Scope

<!-- Explicit boundaries. Includes reasoning to prevent re-adding. -->

- Training or hosting the agents themselves — agentos-guard *governs* agents; it is not an agent framework.
- Managed SaaS — open-source and self-hosted first.
- Replacing existing observability backends — we emit OpenTelemetry and integrate, not replace.
- Non-Python SDKs (TypeScript, Go) — deferred until the Python surface stabilizes (ADR-0001).
- Kubernetes as a Phase 0 requirement — Phase 0 runs self-hosted (API + Postgres + dashboard) with no K8s; the K8s-native operator/sidecar is Phase 2.
- **Crypto-economics in core** — blockchain/on-chain anchoring, token staking/slashing settlement, and MPC are non-goals (ADR-0007). Enterprise audience treats mandatory chain/token dependencies as disqualifiers; "stake-based accountability" may exist only as an optional pluggable reputation backend. Token-free Merkle anchoring + ZK proofs are kept (optional/Phase-2).

## Context

- **Design is fully documented** in `docs/architecture/` (00-manifesto + README + docs 01–10 + 20-roadmap + 30-comparison + ADRs 0001–0007). These are **authoritative** and the source of truth for planning. `docs/` is the design layer (*what/why*); `.planning/` is the execution layer (*how/when* — phases, REQ-IDs, plans). They are not duplicates; see `docs/architecture/README.md` → "`docs/` vs `.planning/`". **Phases 1–5 are implemented and merged to `development` (2026-07-03)**; Phase 6 (observability, compliance, red-team gate) closes P0, and Phases 7–14 remain design ahead of code.
- Directly inspired by Microsoft's **Agent Governance Toolkit (AGT)** and **RAMPART**, and positioned **layer-first**: agentos-guard is *the semantic-judgment and memory-governance layer that deterministic enforcers — by their own documentation — do not provide*, with full-replacement positioning available later. The paradigm shift is *Distrust→Block→Log* (AGT) → *Trust→Verify→Graduate→Prove* (us). **Competitive facts re-verified 2026-06-10 (AGT v4.1.0)** — AGT has **no semantic/LLM layer** ("actions, not reasoning"), **no cross-action correlation** (stateless kernel), an admitted **memory/knowledge governance gap**, **raw unredacted audit parameters**, and a **default-allow posture**; it *does* ship Merkle audit, 0–1000 trust, SPIFFE/DID/mTLS, privilege rings, an MCP gateway, 5 language SDKs, and 19+ framework integrations. The durable gaps (semantic constitution, sequence-intent correlation) are front-loaded in the roadmap; parity features AGT does well are deliberately late. AGT releases monthly — **re-verify its feature set at the start of every phase** (`docs/architecture/30-comparison-agt.md` is the corrected scorecard). **Seven differentiator pillars** (see `docs/architecture/00-manifesto.md`), none requiring crypto-economics:
  1. Living semantic **constitution** (vs static YAML grep)
  2. **Graduated** response — allow/warn/sandbox/consensus/approval/temporary-exception/governance-review/deny + composable side-effects (vs binary)
  3. **Intent-based policy** — catches `rename_then_drop` & novel sequences (vs per-action stateless evaluation; sequence analysis pulled forward to roadmap Phase 3 as the demoable wedge)
  4. **Cross-agent permission calculus** — confused-deputy / transitive permissions (vs per-agent isolation)
  5. **Explainable denials with remediation** — cited principle + next steps (vs `GovernanceDenied: rule X`)
  6. Continuous, pytest-native red-team that **gates CI** + self-play (vs offline pre-deploy scan)
  7. **Prove, don't just log** — policy-version provenance → Merkle → ZK proofs (vs append-only logs)
- **Crypto-economics fenced out of core** (ADR-0007): blockchain anchoring, token staking, and MPC are non-goals; only token-free cryptography (Merkle anchoring, ZK proofs) survives as optional/hard-gated Phase-2 research. Differentiation is semantic reasoning + provable governance, not tokenomics.
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
| Python-first; Rust only for later hot paths | Ecosystem fit (LangChain/LangGraph, OPA, ML libs); optimize after profiling | ✅ Holding — validated by Phases 1–5 (ADR-0001) |
| SDK interception as the v1 Policy Enforcement Point | Lowest-friction adoption; gateway/sidecar later behind the same contract | ✅ Validated Phases 1–2 (ADR-0002) |
| Constitution → YAML → OPA/Rego policy substrate | Human-reviewable principles + deterministic, battle-tested enforcement | ✅ Validated Phase 3 (ADR-0003) |
| Hash-chained tamper-evident audit log | Simple, verifiable start; Merkle DAG / ZK proofs later | ✅ Validated Phases 1 & 4 (ADR-0004) |
| Graduated response instead of allow/deny | Signature differentiator over AGT | ✅ Validated Phase 3 (ADR-0005) |
| Product name: agentos-guard | — | ✅ Done (ADR-0006) |
| Milestone scope = full vision (Phases 0–2) | User chose to roadmap the entire documented vision now | — Active |
| Do not gate the MVP on moonshot features | Phase 0 competes with AGT on its own turf before reaching for research-grade features | — Holding |
| OSS distribution is a P0 requirement (OSS-01/02, 2026-07-05 audit) | "Best in open source" is unreachable without PyPI releases, CONTRIBUTING.md, and SECURITY.md; none existed in the 121 requirements | — Decided 2026-07-05 (mapped to Phase 6) |
| Layer-first positioning vs AGT | AGT wins on breadth (5 SDKs, 19+ frameworks); we lead as the semantic-judgment + memory-governance layer it admits it lacks, with an optional AGT adapter (tracked with the Phase-10 gateway PEP); full-replacement later | — Decided 2026-06-10 |
| SEC-13 (sequence-intent correlation) pulled P1→P0, Phase 8→Phase 3 | Cross-action correlation is a *durable* AGT gap (stateless kernel can't retrofit it) and the demoable wedge; incidental gaps (redaction, memory hooks) AGT can close in a sprint | — Decided 2026-06-10 |
| Zero-infra quickstart is a P0 requirement (SDK-05) | AGT's pitch is one decorator with zero cloud deps; demanding Docker+Postgres+OPA for first run loses the OSS adoption race | — Decided 2026-06-10 |
| Re-verify AGT's feature set at every phase start | AGT releases monthly (v3.2.0→v4.1.0 in 7 weeks); the 2026-06-01 research over-credited it a semantic layer it doesn't have — stale competitor intel distorts roadmap bets in both directions | — Decided 2026-06-10 |

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
*Last updated: 2026-07-05 — post-Phase-5 planning audit: Validated section populated (Phases 1–5 shipped), stale "design-only / no code" claims removed, ADR outcomes marked validated, OSS-01/02 distribution requirements added (Phase 6)*
*Previous: 2026-06-10 — AGT v4.1.0 re-verification: corrected competitive facts, layer-first positioning, SEC-13 pull-forward, SDK-05 zero-infra quickstart, per-phase AGT re-verification rule*
