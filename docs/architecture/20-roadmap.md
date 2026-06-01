# 20 — Roadmap (Phased Build)

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
- **Identity & economics:** SPIFFE/mTLS; stake-based accountability + reputation slashing;
  portable decentralized reputation.
- **Consensus:** BFT for multi-agent agreement.
- **Platform:** Kubernetes-native operator + sidecars.
- **Performance:** Rust rewrite of hot-path enforcement where profiling justifies it
  ([`adr/0001-python-first.md`](adr/0001-python-first.md)).

## Sequencing principle

Each phase is independently shippable and demoable. We never build a moonshot feature before
the runtime loop it plugs into is solid — the pipeline contract from
[`03`](03-interception-and-pipeline.md) stays stable across all three phases.
