# Feature Research

> 📸 **Research snapshot — 2026-06-01. Not authoritative.** Point-in-time competitor/feature
> analysis (vs Microsoft AGT, OWASP, EU AI Act) that fed the design and plan. Authoritative design
> is [`docs/architecture/`](../../docs/architecture/) (esp. [`30-comparison-agt.md`](../../docs/architecture/30-comparison-agt.md));
> committed scope is [`.planning/REQUIREMENTS.md`](../REQUIREMENTS.md). Read this for *why* features
> were scoped the way they were, not for current truth.

**Domain:** Runtime governance & security control plane for AI agents (AgentOps / agent security)
**Researched:** 2026-06-01
**Confidence:** HIGH for the competitor/market landscape and compliance frameworks (verified against Microsoft AGT GitHub + docs, OWASP GenAI, EU AI Act primary sources); MEDIUM for the precise novelty boundary of agentos-guard's differentiators (AGT's roadmap is moving fast and some internals are undocumented).

---

## TL;DR for downstream consumers (read this first)

**The competitive premise in `docs/architecture/30-comparison-agt.md` is now partially stale and MUST be revised.** Those docs assume AGT enforces "static YAML rules with a binary allow/deny." That was true of pre-release AGT. The version Microsoft shipped **2026-04-02** already includes:

- **Graduated enforcement**: `allow` / `deny` / `require_approval` / `sandbox` (4 execution rings) + **trust-level downgrade** as a response. This is *not* binary.
- A **semantic intent classifier** that detects dangerous goals (`DESTRUCTIVE_DATA`, `DATA_EXFILTRATION`, `PRIVILEGE_ESCALATION`) regardless of phrasing — i.e. an LLM-style reasoning layer over policy, and Microsoft already brands part of this "Constitutional Constraints" (ADR-0006 in *their* repo).
- **Merkle audit trail** + "Decision BOM" (their ABOM analogue) + OWASP/NIST/EU AI Act/SOC 2 mapping with **automated evidence export**.
- **Dynamic trust scoring** (0–1000 across 5 behavioral tiers), **SPIFFE/DID/mTLS identity**, delegation-chain validation, **privilege rings**, saga orchestration, **kill switch**.
- **Continuous fuzzing** (ClusterFuzzLite, 7 fuzz targets) + `agt red-team scan` CLI (12-vector prompt-injection audit).
- **Multi-language SDKs**: Python, TypeScript, C#/.NET, Rust, Go — and framework hooks for LangChain, CrewAI, Google ADK, Microsoft Agent Framework.

**Implication:** Three of agentos-guard's five headline differentiators (graduated response, semantic/constitutional reasoning, Merkle audit, trust scoring) are now **table stakes or near-parity, not differentiators.** Only **four** things remain genuinely novel in mid-2026 (see Differentiators table). Phase 0 as currently scoped does *not* automatically "beat AGT" — it reaches **parity** on most axes while still missing several AGT capabilities (Cedar support, multi-language SDKs, semantic intent classifier breadth, continuous fuzzing). The roadmap should treat Phase 0 as **"reach parity on an open, Python-native, OPA-grounded control plane with a genuinely human-readable + amendable constitution,"** and front-load the surviving differentiators rather than parking all of them in Phase 2.

---

## Feature Landscape

### Table Stakes (Platform / security teams won't adopt without these)

In 2026, the bar was reset by AGT, OWASP Agentic Top 10 (Dec 2025), and the EU AI Act high-risk deadline (Aug 2, 2026). Missing any of these reads as "not a serious governance tool."

| Feature | Why Expected | Complexity | Phase | Design status | Notes |
|---------|--------------|------------|-------|---------------|-------|
| **Action interception (every tool/memory/MCP/model/delegation call)** | The entire category is defined by runtime interception; without it you're an observability tool, not a control plane | HIGH | 0 | Covered (SDK shim, LangChain/LangGraph) | AGT hooks native extension points across 4 frameworks; agentos-guard ships 1 framework in P0 — **adapter breadth is a parity gap.** |
| **Declarative policy enforcement** | Every competitor (AGT, OPA/Styra, Cedar, Airia, Arthur) does runtime policy eval | MEDIUM | 0 | Covered (Constitution→YAML→OPA/Rego) | OPA is the right CNCF-graduated choice. **Gap: AGT also supports Cedar**; some buyers standardize on Cedar. Pluggable backend would close this. |
| **Graduated / escalating enforcement (warn / sandbox / require_approval / deny)** | Was a differentiator in 2025; AGT shipped it, so it is now expected | MEDIUM | 0 | Covered (6-outcome engine) | agentos-guard's `require_consensus` tier is still ahead of AGT core — keep that as the *only* graduated-response differentiator. |
| **Human-in-the-loop approval workflow** | EU AI Act Art. 26 mandates human oversight for high-risk; AGT has `require_approval` w/ approvers | MEDIUM | 0 | Covered (`ApprovalRequest`) | Maps directly to EU AI Act Article 26 evidence. |
| **Tamper-evident audit log w/ decision provenance** | EU AI Act Art. 12 (automatic logging, 6-month retention); AGT ships Merkle trail | MEDIUM | 0 | Covered (hash-chained P0 → Merkle DAG P1) | **AGT already ships Merkle in its current release.** Consider pulling Merkle DAG forward to P0 to avoid shipping a "weaker audit than AGT" at launch. |
| **Agent identity (signed tokens; forged identity → deny)** | Zero-trust identity is universal (AGT: SPIFFE/DID/mTLS) | MEDIUM | 0 | Covered (signed tokens P0; SPIFFE P2) | **Parity gap: AGT ships SPIFFE/mTLS now; agentos-guard defers it to P2.** Signed tokens in P0 are weaker than AGT's launch identity story. |
| **Dynamic trust scoring** | AGT ships 0–1000 trust across 5 tiers, consumed by enforcement | MEDIUM | 0 | Covered (0–1 score P0) | Was framed as a differentiator; it is now table stakes. Keep, but stop marketing it as novel. |
| **Agent discovery + authoritative inventory** | "You can't govern what you can't see"; every visibility platform leads with inventory | MEDIUM | 0 | Covered (SDK self-registration) | Shadow/rogue-agent detection (P1) is the harder, more-valued half. |
| **Prompt-injection detection + baseline guardrails (PII / unsafe / format)** | OWASP ASI01 (Goal Hijack) is the #1 agentic risk; Lakera/NeMo/Guardrails AI all do this | MEDIUM | 0 | Covered | Cheap-heuristic-inline / expensive-model-on-flag design is correct and matches market. |
| **Kill switch (halt agent or fleet)** | Universal safety lever (AGT: hypervisor execution control) | LOW | 0 | Covered | Correctly shipped in P0 even before full sandboxing. |
| **OpenTelemetry export (spans/metrics/tracing)** | Arize/Datadog/Langfuse/LangSmith all standardize on OTel/OpenInference; "integrate don't replace" is the expected posture | MEDIUM | 0 | Covered | Correct strategic choice; matches the explicit non-goal of replacing observability backends. |
| **Compliance mapping: OWASP Agentic Top 10 + NIST AI RMF** | AGT covers 10/10 OWASP + NIST RMF 4 phases; this is now the entry ticket | MEDIUM | 0 | Covered | See Compliance Mapping section — verify mapping uses the **ASI01–ASI10** 2026 codes, not 2025 draft names. |
| **Red-team / safety testing in CI** | RAMPART-style pre-deploy red team + AGT `red-team scan` + ClusterFuzzLite | MEDIUM | 0 | Covered (pytest-native suites) | pytest-native framing is a genuinely nice DX angle (see Differentiators). |
| **Privilege rings / capability tiers + sandboxed execution** | AGT ships 4 execution rings now | HIGH | 1 | Covered (P1) | **Parity gap at launch** — AGT has this on day one; agentos-guard defers to P1. |
| **MCP security (tool-poisoning / typosquatting / hidden-instruction scan)** | OWASP ASI04; AGT's "Agent Marketplace" does this; supply chain is a top-3 buyer concern | HIGH | 1 | Covered (MCP gateway, tool-poisoning, supply-chain P1) | **Parity gap at launch.** MCP is the dominant integration surface in 2026 — consider pulling a minimal MCP manifest scanner into P0. |
| **Multi-framework adapters (CrewAI, AutoGen, OpenAI Agents SDK, ADK)** | AGT supports 4+ frameworks at launch; single-framework lock-in is an adoption blocker | HIGH | 1 | Covered (P1) | **Largest single adoption gap vs AGT.** LangGraph-only in P0 limits the addressable market. |
| **EU AI Act + SOC 2 mapping + one-click report export** | Aug 2 2026 high-risk deadline; AGT already exports EU AI Act + SOC 2 evidence | MEDIUM | 1 | Covered (P1) | Timing risk: the EU deadline lands *during* the build. If buyers need this at launch, P1 may be too late. |
| **Cost / token / budget governance (FinOps for agents)** | Increasingly expected; agents spend real money; AgentOps/Arize trending here | MEDIUM | 1 | Covered (P1) | Smart that budgets reuse the graduated-response engine (no separate enforcement path). |

### Differentiators (Genuine competitive advantage in mid-2026)

After AGT's April 2026 release, the field of *truly* novel features is much narrower than the design docs claim. These four (plus one DX angle) survive scrutiny:

| Feature | Value Proposition | Complexity | Phase | Still novel vs AGT? | Notes |
|---------|-------------------|------------|-------|---------------------|-------|
| **Living, human-readable, amendable Constitution** (agents query it; propose ratifiable amendments; cited-principle rationale) | AGT has a *semantic intent classifier* + static "Constitutional Constraints," but **not** a versioned, human-authored governing document that non-engineers review and that *evolves via proposal/ratification*. This is the strongest surviving differentiator and aligns with Core Value ("explainable, cited-principle decisions"). | HIGH | 0 (author + cite) / 2 (amendments) | **YES** for the amendable/governance-document aspect; **NO** for raw semantic classification (AGT has that) | Sharpen the pitch: it's *governance-as-evolving-law*, not "we use an LLM to interpret policy" (AGT does too). Cited-principle rationale is the demoable hook. |
| **`require_consensus` (2-of-3 multi-agent → BFT)** as a first-class graduated outcome | AGT's graduated response stops at human approval / trust downgrade. Multi-agent consensus as an *enforcement outcome* is not in AGT core. | HIGH | 1 (2-of-3) / 2 (BFT) | **YES** | Only piece of the graduated-response spectrum that AGT doesn't match. Worth foregrounding in the comparison doc. |
| **Continuous adversarial self-play** (system generates novel attacks against itself, scores defenses, proposes constitution/policy patches) | AGT has continuous *fuzzing* + pre-deploy red-team; it does **not** auto-generate novel attacks that feed ratifiable defense amendments. This closes the OWASP ASI10 (Rogue Agents / drift) loop. | HIGH | 2 | **YES** (the self-improving + amendment-feedback loop) | Research-grade; correctly in P2. Depends on Constitution amendments (P2) and red-team layer (P0). |
| **Zero-knowledge compliance proofs** (prove "no PII exfiltrated" / "all actions compliant" without revealing context, via RISC Zero / SP1) | AGT stops at Merkle tamper-evidence. ZK proof-of-compliance over undisclosed data is unique among governance tools and uniquely valuable in regulated industries. | HIGH | 2 | **YES** (clearly novel) | Highest-risk, highest-ceiling differentiator. Correctly P2. Depends on Merkle DAG audit (P1). |
| **Decentralized, stake-based, portable reputation** (stake on behavior; slash on violation; reputation portable across deployments) | AGT has trust scoring + DID but no economic staking/slashing or cross-deployment portability. | HIGH | 2 | **YES** | Most speculative; thin buyer demand evidence in 2026. Keep P2; do not over-invest until trust/reputation (P1) validates. |
| **pytest-native safety-as-correctness DX** (`assert attack_success_rate < 0.02` breaks CI like a unit test) | AGT exposes a CLI (`agt red-team scan`); agentos-guard makes safety a *native pytest assertion* engineers already know. Lower friction for Python shops. | MEDIUM | 0 | **Partial** (the *DX framing* is differentiated; the capability is not) | Cheap to build, strong demo, real adoption lever for Python-first teams. Lean into it as a developer-experience differentiator, not a capability one. |

### Anti-Features (Deliberately NOT build — confirmed against ADRs / non-goals)

The design's stated non-goals are well-judged and match market reality. Documented here to prevent re-adding.

| Feature | Why Requested | Why Problematic | Alternative (current design) |
|---------|---------------|-----------------|------------------------------|
| **Becoming an agent framework** (host/run/train agents) | "If you intercept everything, just run the agent too" | Conflates governor with governed; destroys the trust story (who governs the governor?); puts you in a crowded, fast-moving market vs LangChain/CrewAI | Govern *any* framework via PEP; stay framework-agnostic. Keep this boundary hard. |
| **Managed SaaS (control plane as a hosted service)** | Faster time-to-value; recurring revenue | Governance/audit data is the most sensitive data a security team has; self-host is a hard requirement for the target buyer; SaaS contradicts the ZK-proof value prop | Open-source, self-hosted control plane (API + Postgres + dashboard). |
| **Replacing observability backends** (build our own metrics store/UI to rival Datadog/Arize) | "One pane of glass" | Re-fighting a won war against entrenched OTel-native incumbents; dilutes focus from governance | Emit OpenTelemetry; integrate, don't replace. |
| **Non-Python SDKs at launch (TS/Go/C#)** | AGT ships 5 languages; matching is tempting | Splits a small team across surfaces before the Python contract stabilizes; AGT's multi-language story is a *feature gap to accept*, not chase early (ADR-0001) | Python-first; add SDKs after the Python surface stabilizes. **Note:** this is now a real competitive disadvantage vs AGT — flag it as a known tradeoff, not a non-issue. |
| **Kubernetes as a Phase 0 requirement** | "Cloud-native control plane needs K8s" | Adds heavy ops burden to the MVP; the SDK PEP doesn't need it | P0 self-hosted (API + Postgres + dashboard, no K8s); operator/sidecar is P2. |
| **Per-tenant "auto-fix the agent" / automatic remediation that rewrites agent code** | "Don't just block — fix it" | Crosses from governor to author; unsafe automatic mutation of governed systems; liability | Graduated response + amendment *proposals* humans ratify; never silent auto-mutation. |

---

## Gaps in the Current Design (explicitly surfaced)

These are real holes against the 2026 market / OWASP Agentic Top 10. Ordered by severity.

1. **No dedicated Memory / Context-Poisoning governance (OWASP ASI06).** *Confidence: HIGH this is a gap.* The design treats "memory access" as an interceptable action type, but there is **no detector for poisoned/persisted memory entries** — injected or hallucinated facts that persist across sessions. This is a top-cited 2026 enterprise gap (memory layers exist; governance layers don't). **Recommendation:** add a memory-integrity / context-provenance detector to the Security Engine (P1), and a memory entry to the ABOM/inventory.

2. **Inter-agent communication security is under-specified (OWASP ASI07 + A2A protocol).** *Confidence: MEDIUM-HIGH.* The design folds inter-agent messages into prompt-injection detection, but does not address **A2A agent-card verification, message authentication, replay protection, or impersonation** — exactly the things the A2A protocol leaves to implementers. With A2A adoption rising in 2026, this is an increasingly expected control. **Recommendation:** add explicit inter-agent message authentication + A2A agent-card verification (P1), tied to the identity layer.

3. **Identity is weaker than AGT at launch.** *Confidence: HIGH.* AGT ships SPIFFE/mTLS/DID now; agentos-guard defers SPIFFE to P2 and launches on signed tokens. For zero-trust buyers this is a checkbox they'll fail at evaluation. **Recommendation:** pull a minimal SPIFFE/mTLS path forward to P1 (it's already P2), or at least ship agent certificates (currently P1) in P0.

4. **Audit is weaker than AGT at launch.** *Confidence: HIGH.* AGT ships a Merkle trail; agentos-guard launches on a plain hash chain (Merkle is P1). Side-by-side, the MVP audit story looks behind. **Recommendation:** pull Merkle DAG into P0; it's not a large lift and removes a direct "AGT does X, you don't" comparison.

5. **No Cedar policy backend.** *Confidence: HIGH.* AGT supports YAML + OPA/Rego + **Cedar**. Buyers standardized on AWS Cedar will not adopt OPA-only. **Recommendation:** keep OPA as default but design the policy backend as pluggable (ADR) so Cedar can be added without re-architecture. Low priority but architecturally cheap to keep open.

6. **Single-framework launch (LangGraph only) is the biggest adoption-surface gap.** *Confidence: HIGH.* AGT supports 4+ frameworks at launch. **Recommendation:** prioritize at least CrewAI or OpenAI Agents SDK in P0/early-P1; treat framework breadth as a P0-stretch, not P1-default.

7. **No explicit RCE / autonomous-code-execution control (OWASP ASI05).** *Confidence: MEDIUM.* "Unexpected Code Execution" is an OWASP top-10 risk; the design covers tool calls and sandboxing but never names code-execution / generated-code validation as a detector. **Recommendation:** add a code-execution-intent detector to the Security Engine (P1), distinct from generic tool interception.

8. **EU AI Act timing risk.** *Confidence: MEDIUM.* The Aug 2, 2026 high-risk deadline lands during the build; EU AI Act mapping is P1. If early adopters are EU high-risk deployers, they need Art. 12 logging + Art. 26 oversight evidence at launch. **Recommendation:** confirm whether P0 hash-chained audit + approval workflow already satisfies Art. 12/26 minimally; if so, surface that as a P0 compliance claim even before the full EU mapping engine lands in P1.

**Not gaps (design correctly covers these):** cascading-failure containment (circuit breakers, ASI08), identity/privilege abuse (privilege rings + delegation trust, ASI03), human-agent trust exploitation (explainable cited-principle rationale defuses over-trust, ASI09), rogue-agent drift (rogue-agent detection + self-play, ASI10).

---

## Feature Dependencies

```
Interception (P0) ──required by──> EVERYTHING (the pipeline contract)
    └──required by──> Decision Pipeline (P0)
                          ├──required by──> Graduated Response (P0)
                          ├──required by──> Audit / Decision Records (P0)
                          └──required by──> OTel export (P0)

Constitution → YAML → OPA/Rego (P0)
    └──required by──> Semantic Interpreter (P0)
    └──required by──> Constitution Amendments (P2)
                          └──required by──> Continuous Self-Play patch loop (P2)

Identity: signed tokens (P0)
    └──enhanced by──> Agent certificates (P1) ──> SPIFFE/mTLS (P2)
    └──required by──> Trust score (P0)
                          └──> Reputation + propagation + delegation chains (P1)
                                   └──> Stake-based / portable reputation (P2)

Trust score (P0) ──feeds──> Graduated Response (P0)

Hash-chained audit (P0)
    └──upgraded by──> Merkle DAG (P1)
                          └──required by──> Zero-Knowledge compliance proofs (P2)

Discovery: self-registration + inventory (P0)
    └──required by──> Live agent graph + lineage (P1)
                          └──required by──> Cross-agent conflict / legal reasoning (P2)
    └──required by──> Shadow/rogue-agent detection (P1)

ABOM (P1) ──required by──> Supply-chain checks (P1) ──> Vulnerability impact analysis (P2)

Red-team pytest layer (P0)
    └──required by──> ASR tracking + continuous validation (P1)
                          └──required by──> Continuous adversarial self-play (P2)

require_approval (P0) ──prerequisite-for──> require_consensus 2-of-3 (P1) ──> BFT consensus (P2)

Economics / budgets (P1) ──reuses──> Graduated Response engine (P0)  [no separate enforcement path]
```

### Dependency Notes (roadmap-critical)

- **Constitution amendments (P2) require both the Constitution (P0) and the red-team/self-play loop (P0→P2).** Self-play (P2) cannot ship before amendments (P2); they must land together.
- **ZK proofs (P2) require the Merkle DAG audit (P1)**, which requires the hash chain (P0). This is a clean 3-phase chain — don't reorder.
- **`require_consensus` (P1) requires `require_approval` plumbing (P0)** since both pause execution awaiting an external decision; BFT (P2) generalizes the same outcome.
- **Cross-agent conflict reasoning (P2) requires the live agent graph + lineage (P1)**, which requires discovery (P0). Conflict reasoning is meaningless without the delegation-edge graph.
- **Economics (P1) reuses the graduated-response engine (P0)** — a genuine architectural win; budget violations flow through the same pipeline as safety violations. Preserve this; do not build a parallel budget enforcer.
- **MCP security + supply-chain (P1) require ABOM (P1)** to answer "which agents use the bad component?" — they should ship in the same phase.

---

## MVP Definition

### Launch With (Phase 0 — must reach AGT parity, not just "beat" it)

- [ ] **Interception (LangGraph/LangChain SDK shim) + `AgentAction` normalization** — the foundational contract; nothing works without it.
- [ ] **Decision Pipeline (identity → policy → risk → graduated response)** — the core loop and entire value prop.
- [ ] **Constitution → YAML → OPA/Rego + semantic interpreter w/ cited-principle rationale** — the surviving differentiator; the cited-principle output is the demo.
- [ ] **Graduated response (allow/warn/sandbox-stub/require_approval/deny)** — table stakes post-AGT.
- [ ] **Human approval workflow (`ApprovalRequest`)** — EU AI Act Art. 26 evidence.
- [ ] **Prompt-injection + baseline guardrails (PII/unsafe/format)** — OWASP ASI01.
- [ ] **Identity (signed tokens) + basic trust score** — *recommend stretching to agent certificates to narrow the AGT gap.*
- [ ] **Discovery: self-registration + inventory** — visibility table stakes.
- [ ] **Tamper-evident audit + decision/policy provenance** — *recommend Merkle DAG in P0, not P1, to match AGT.*
- [ ] **OWASP Agentic Top 10 (ASI01–ASI10) + NIST AI RMF mapping** — entry ticket.
- [ ] **pytest-native red-team layer (injection suites, statistical thresholds, CI regression locks)** — the DX differentiator.
- [ ] **Kill switch** — universal safety lever.
- [ ] **Control-Plane API + Postgres + OTel + minimal dashboard (read-only + approvals + kill switch)** — the platform.

**P0 stretch (close the most visible AGT gaps):** Merkle audit, agent certificates, a second framework adapter (CrewAI or OpenAI Agents SDK), a minimal MCP manifest scanner.

### Add After Validation (Phase 1)

- [ ] **Reputation, trust propagation, delegation trust chains, certificates** — trigger: P0 trust score proves useful and teams ask for history-based trust.
- [ ] **Sandboxing, privilege rings, resource isolation, circuit breakers, emergency shutdown** — trigger: real production deployments need containment beyond deny.
- [ ] **Full Security Engine (data-exfil, secret-leakage, tool-poisoning, MCP gateway, supply-chain)** — trigger: MCP-heavy adopters; **add memory-poisoning (ASI06) + RCE (ASI05) + inter-agent comms auth (ASI07) detectors here — currently missing.**
- [ ] **Gateway/proxy interception + more framework adapters** — trigger: non-Python or framework-agnostic demand.
- [ ] **`require_consensus` (2-of-3)** — trigger: multi-agent deployments need peer agreement.
- [ ] **Economics (cost/budget governance), ABOM, lineage, conversation tracing, SLO dashboards** — trigger: spend visibility / supply-chain asks.
- [ ] **EU AI Act + SOC 2 mapping + one-click export; Merkle DAG (if not pulled to P0)** — trigger: regulated buyers (note Aug 2 2026 deadline timing).

### Future Consideration (Phase 2 — moonshot, only after the loop is solid)

- [ ] **Constitution amendments + cross-agent conflict/legal reasoning** — why defer: needs a stable constitution + agent graph; research-grade.
- [ ] **Continuous adversarial self-play + runtime patching + threat-intel feed** — why defer: needs amendments + mature red-team layer.
- [ ] **Zero-knowledge compliance proofs (RISC Zero / SP1)** — why defer: needs Merkle DAG; highest implementation risk; flagship differentiator.
- [ ] **SPIFFE/mTLS + stake-based/portable reputation; BFT consensus** — why defer: thin 2026 buyer demand for staking; validate trust/reputation first.
- [ ] **Kubernetes operator/sidecars; Rust hot-path rewrite** — why defer: profile-driven; ops burden unjustified pre-scale.

---

## Feature Prioritization Matrix

| Feature | User Value | Implementation Cost | Priority |
|---------|------------|---------------------|----------|
| Interception + Decision Pipeline | HIGH | HIGH | P1 (must) |
| Graduated response | HIGH | MEDIUM | P1 |
| Constitution + cited-principle rationale | HIGH | HIGH | P1 |
| Tamper-evident audit (+ Merkle in P0) | HIGH | MEDIUM | P1 |
| OWASP/NIST mapping | HIGH | MEDIUM | P1 |
| pytest-native red-team | HIGH | MEDIUM | P1 |
| Prompt-injection guardrails | HIGH | MEDIUM | P1 |
| Identity + trust score | HIGH | MEDIUM | P1 |
| Kill switch | HIGH | LOW | P1 |
| Approval workflow | HIGH | MEDIUM | P1 |
| Second framework adapter | HIGH | MEDIUM | P2 (P0-stretch) |
| Memory-poisoning detector (ASI06 gap) | MEDIUM-HIGH | MEDIUM | P2 |
| Inter-agent comms auth / A2A (ASI07 gap) | MEDIUM | MEDIUM | P2 |
| `require_consensus` | MEDIUM | HIGH | P2 |
| MCP security + supply-chain + ABOM | HIGH | HIGH | P2 |
| EU AI Act + SOC 2 export | HIGH | MEDIUM | P2 |
| Cost/budget governance | MEDIUM | MEDIUM | P2 |
| Continuous self-play | MEDIUM | HIGH | P3 |
| Zero-knowledge proofs | MEDIUM-HIGH | HIGH | P3 |
| Stake-based reputation | LOW-MEDIUM | HIGH | P3 |
| K8s operator / Rust hot path | MEDIUM | HIGH | P3 |

**Priority key:** P1 = must-have for a credible launch (Phase 0). P2 = should-have, add when possible (Phase 1). P3 = defer until loop validated (Phase 2). *(Note: P1/P2/P3 here are launch-priority buckets, distinct from the roadmap's Phase 0/1/2 — the mapping is intentional but not identical, since some Phase-1 items are P2 launch-priority.)*

---

## Competitor Feature Analysis

| Feature | Microsoft AGT / RAMPART (Apr 2026) | Guardrails (Lakera / NeMo / Guardrails AI) | OPA / Styra / Cedar | AgentOps / Arize / Datadog | agentos-guard plan |
|---------|-----------------------------------|--------------------------------------------|---------------------|----------------------------|--------------------|
| Action interception | Yes (4 framework hooks) | Partial (LLM I/O only, not full action graph) | No (policy eval engine, not interceptor) | No (telemetry capture, not enforcement) | Yes (LangGraph P0 → multi P1) |
| Policy enforcement | YAML + OPA/Rego + **Cedar** | No (content rules, not authz policy) | Yes (Rego / Cedar) — but no agent interception | No | OPA/Rego (P0); Cedar = gap |
| Graduated response | allow/deny/approve/sandbox + trust downgrade | Binary block/allow | Binary (engine returns allow/deny) | N/A | Full spectrum + **require_consensus** (only true diff) |
| Living/amendable constitution | Semantic intent classifier + static "constitutional constraints" | No | No | No | **Yes — human-authored + amendable (diff)** |
| Trust scoring | Yes (0–1000, 5 tiers) | No | No | No | Yes (0–1 P0) — now parity, not diff |
| Identity | **SPIFFE/DID/mTLS now** | No | No | No | Signed tokens P0 (weaker) → SPIFFE P2 |
| Audit | **Merkle trail + Decision BOM now** | No | No | Trace logs (not tamper-evident) | Hash chain P0 → Merkle P1 (weaker at launch) |
| Compliance mapping | OWASP 10/10 + NIST + EU AI Act + SOC2 export | No | No | Partial dashboards | OWASP+NIST P0; EU+SOC2 P1 |
| Red-team / testing | `red-team scan` CLI + ClusterFuzzLite | Some (eval suites) | No | Eval/benchmark tooling | **pytest-native (DX diff)** + self-play P2 |
| Sandboxing / rings | 4 execution rings now | No | No | No | P1 (parity gap at launch) |
| MCP / supply-chain | Marketplace: poisoning/typosquat/hidden-instruction | Partial (Lakera) | No | Inventory only | P1 (parity gap at launch) |
| Multi-language SDK | Python/TS/C#/Rust/Go | Python/JS | N/A | Python/JS | Python-only (accepted tradeoff) |
| Zero-knowledge proofs | No | No | No | No | **Yes P2 (clear diff)** |
| Continuous self-play | No (fuzzing only) | No | No | No | **Yes P2 (diff)** |
| Stake-based reputation | No (trust + DID only) | No | No | No | **Yes P2 (diff, speculative)** |
| Open-source / self-host | Yes (MIT) | NeMo/Guardrails AI yes; Lakera no | Yes | Mixed | Yes (self-host first) |

---

## Compliance Framework Mapping (verified against primary sources)

**OWASP Top 10 for Agentic Applications 2026** (released Dec 2025; codes **ASI01–ASI10**) → agentos-guard coverage:

| OWASP 2026 | agentos-guard control | Phase | Coverage |
|------------|-----------------------|-------|----------|
| ASI01 Agent Goal Hijack | Prompt-injection detection + semantic interpreter | 0 | Strong |
| ASI02 Tool Misuse & Exploitation | Policy enforcement + privilege rings | 0 / 1 | Strong |
| ASI03 Identity & Privilege Abuse | Identity + delegation trust chains + privilege rings | 0 / 1 | Strong |
| ASI04 Agentic Supply Chain | ABOM + supply-chain checks + MCP gateway | 1 | Strong (P1) |
| ASI05 Unexpected Code Execution (RCE) | Sandboxing — **no explicit code-exec detector** | 1 | **Partial — GAP** |
| ASI06 Memory & Context Poisoning | Memory interception — **no poisoning detector** | — | **GAP** |
| ASI07 Insecure Inter-Agent Comms | Folded into prompt-injection — **no A2A/message auth** | — | **GAP** |
| ASI08 Cascading Failures | Circuit breakers + blast-radius simulation | 1 | Strong (P1) |
| ASI09 Human-Agent Trust Exploitation | Cited-principle rationale + approval workflow | 0 | Strong |
| ASI10 Rogue Agents | Rogue-agent detection + continuous self-play | 1 / 2 | Strong |

**NIST AI RMF** (Govern/Map/Measure/Manage): constitution+policy = Govern; discovery+inventory+ABOM = Map; risk scoring+observability = Measure; graduated response+kill switch+approval = Manage. Coverage: P0 baseline, full P1.

**EU AI Act** (high-risk obligations bind **Aug 2, 2026**): Article 12 (automatic event logging, ≥6-month retention) → tamper-evident audit log; Article 26 (human oversight by competent persons) → approval workflow + dashboard. **Timing flag:** full EU mapping is P1, but the deadline lands mid-build — confirm P0 audit+approval minimally satisfies Art. 12/26.

**SOC 2** (access / change / monitoring controls): audit log = monitoring + change evidence; identity + RBAC = access; mapped P1.

---

## Sources

- [Microsoft Agent Governance Toolkit — GitHub](https://github.com/microsoft/agent-governance-toolkit) (HIGH — primary)
- [Introducing the Agent Governance Toolkit — Microsoft Open Source Blog (2026-04-02)](https://opensource.microsoft.com/blog/2026/04/02/introducing-the-agent-governance-toolkit-open-source-runtime-security-for-ai-agents/) (HIGH)
- [AGT Architecture Deep Dive — Microsoft Community Hub](https://techcommunity.microsoft.com/blog/linuxandopensourceblog/agent-governance-toolkit-architecture-deep-dive-policy-engines-trust-and-sre-for/4510105) (HIGH)
- [AGT docs site](https://microsoft.github.io/agent-governance-toolkit/) (HIGH)
- [OWASP Top 10 for Agentic Applications 2026 — OWASP GenAI Security Project](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) (HIGH — primary)
- [OWASP Agentic Top 10 2026 categories — Indusface](https://www.indusface.com/learning/owasp-top-10-agentic-ai/) (MEDIUM — secondary, ASI01–ASI10 codes)
- [EU AI Act high-risk logging requirements — Help Net Security (2026-04-16)](https://www.helpnetsecurity.com/2026/04/16/eu-ai-act-logging-requirements/) (HIGH)
- [EU AI Act Article 26 — artificialintelligenceact.eu](https://artificialintelligenceact.eu/article/26/) (HIGH — primary)
- [Top 7 AI Agent Visibility and Governance Platforms — Straiker](https://www.straiker.ai/blog/top-7-ai-agent-visibility-and-governance-platforms) (MEDIUM)
- [Lakera Guard — AI Agent Security](https://www.lakera.ai/lakera-guard) (MEDIUM)
- [NVIDIA NeMo Guardrails — GitHub](https://github.com/NVIDIA-NeMo/Guardrails) (HIGH)
- [Why OPA is the missing guardrail for AI agents — Codilime](https://codilime.com/blog/why-use-open-policy-agent-for-your-ai-agents/) (MEDIUM)
- [AI Agent Memory Governance — Atlan](https://atlan.com/know/ai-agent-memory-governance/) (MEDIUM — ASI06 gap evidence)
- [A2A Protocol Security — Securew2](https://securew2.com/blog/a2a-protocol-security) (MEDIUM — ASI07 gap evidence)
- [Agent observability 2026: LangSmith/Langfuse/Arize — Digital Applied](https://www.digitalapplied.com/blog/agent-observability-platforms-langsmith-langfuse-arize-2026) (MEDIUM)

---
*Feature research for: runtime AI-agent governance & security control plane*
*Researched: 2026-06-01*
