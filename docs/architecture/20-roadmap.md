# 20 — Roadmap (Phased Build)

> **Two roadmaps, on purpose — this is the *design-level* one.** This doc defines the three
> coarse design phases (**P0 / P1 / P2**) and what each delivers. The *execution-level* roadmap —
> the 14 fine-grained, independently-shippable vertical slices that actually get built — lives in
> [`.planning/ROADMAP.md`](../../.planning/ROADMAP.md). Mapping: P0 → planning Phases 1–6, P1 →
> Phases 7–12, P2 → Phases 13–14. Read this for *what the phases mean*; read the planning roadmap
> for *what to build next and its status*.

The architecture describes the full vision, but it is built in three phases. **Phase 0 alone
already beats Microsoft AGT**; Phases 1–2 deliver the moonshot differentiators.

## Phase 0 — MVP (beats AGT)

The complete runtime loop, end to end, for one framework.

- **Interception:** Python SDK shim for LangChain / LangGraph; `AgentAction` normalization.
- **Decision Pipeline:** basic identity (signed tokens) → policy (Constitution → YAML →
  OPA/Rego) → risk (prompt-injection + baseline guardrails) → graduated response
  (allow / warn / deny / require_approval).
- **Audit:** tamper-evident hash-chained log with policy-version provenance.
- **Compliance:** OWASP Agentic Top 10 + NIST AI RMF baseline mapping.
- **Testing:** pytest-native red-team layer with attack library + statistical thresholds in CI.
- **Discovery:** SDK self-registration + agent inventory.
- **Safety levers:** operator kill switch.
- **Platform:** Control-Plane API + Postgres + OTel + minimal dashboard (read-only, approvals,
  kill switch).

**Phase 0 done = success criteria:** a LangGraph agent's every action is intercepted, policy-
and risk-checked, graduated-response-enforced, and written to a verifiable audit log — and a
failing safety test breaks CI.

## Phase 1 — Trust, sandbox, scale

- **Trust:** reputation scoring, trust propagation, delegation trust chains; agent certificates.
- **Runtime security:** sandboxed execution, privilege rings, resource isolation, circuit
  breakers, emergency shutdown.
- **Security engine (full):** data-exfil, secret-leakage, tool-poisoning, MCP security gateway,
  supply-chain checks.
- **Interception:** gateway/proxy (framework-agnostic) + more framework adapters.
- **Governance depth:** 2-of-3 multi-agent consensus outcome.
- **Engines:** economics (cost/budget governance), ABOM, lineage, simulation (blast-radius),
  conversation tracing, SLO dashboards.
- **Compliance:** EU AI Act + SOC 2; one-click report export. Merkle DAG audit upgrade.

## Phase 2 — Moonshot differentiators

- **Constitution:** amendment proposals + conflict-resolution / cross-agent legal reasoning.
- **Self-defense:** continuous adversarial self-play, runtime patching, threat-intel feed.
- **Proof:** zero-knowledge compliance proofs (RISC Zero / SP1).
- **Identity & economics:** SPIFFE/mTLS; portable, exportable reputation. Any stake/slashing
  economics live in an **optional, deployment-pluggable** backend only — never required to run
  the control plane ([`adr/0007-no-crypto-economics-in-core.md`](adr/0007-no-crypto-economics-in-core.md)).
- **Consensus:** BFT for multi-agent agreement.
- **Platform:** Kubernetes-native operator + sidecars.
- **Performance:** Rust rewrite of hot-path enforcement where profiling justifies it
  ([`adr/0001-python-first.md`](adr/0001-python-first.md)).

## Deliberately deferred / out-of-core

To keep contributors from silently promoting research-grade or off-strategy features into the
MVP, these are **fenced**. The seven [manifesto](00-manifesto.md) pillars beat AGT *without any
of them*.

| Feature | Status | Why fenced |
|---------|--------|------------|
| **Merkle DAG anchoring** | Phase 1, optional | Defensible, token-free; an upgrade to the hash chain, not a dependency. |
| **Zero-knowledge compliance proofs** | Phase 2, hard-gated research | Strong differentiator (prove without disclose), but research-grade; gated on the P0/P1 substrate. |
| **BFT consensus / self-play patching / decentralized reputation** | Phase 2, hard-gated research | High-value, high-risk; never gate the MVP on them. |
| **Blockchain / Ethereum / on-chain anchoring** | **Non-goal (core)** | Enterprise security teams treat a mandatory chain dependency as a disqualifier. |
| **Token staking (USDC/ETH/project token), slashing settlement** | **Non-goal (core)** | Financialized trust is off-strategy; "stake-based accountability" may exist only as a deployment-optional, pluggable reputation backend — never required to run the control plane. |
| **Multi-party computation (MPC) for sensitive workflows** | **Non-goal (core)** | Heavy cryptographic machinery with no clear adoption demand; revisit only on concrete user pull. |

See [ADR-0007](adr/0007-no-crypto-economics-in-core.md) for the decision and rationale.

## Sequencing principle

Each phase is independently shippable and demoable. We never build a moonshot feature before
the runtime loop it plugs into is solid — the pipeline contract from
[`03`](03-interception-and-pipeline.md) stays stable across all three phases. Pillars before
moonshot: we reach AGT parity and ship the seven differentiator pillars before reaching for any
hard-gated research feature.
