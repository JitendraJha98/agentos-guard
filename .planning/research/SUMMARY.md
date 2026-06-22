# Project Research Summary

> 📸 **Research snapshot — 2026-06-01. Not authoritative.** Point-in-time research that fed the
> design and plan. Authoritative design is [`docs/architecture/`](../../docs/architecture/);
> live execution state is [`.planning/`](../) (PROJECT/REQUIREMENTS/ROADMAP/STATE). Read this for
> *why we chose what we chose*, not for current truth.

> ⚠️ **Correction — 2026-06-10 re-verification (AGT v4.1.0).** The "competitive-positioning
> correction" in the Executive Summary below **over-corrects**: AGT has **no semantic/LLM layer**
> (its enforcement is purely deterministic — "actions, not reasoning") and its graduated
> decisions stop at allow/deny/require_approval. Semantic/constitutional reasoning therefore
> **remains a durable differentiator**, alongside cross-action sequence-intent correlation
> (SEC-13, since pulled forward to roadmap Phase 3). The corrected, dated scorecard — including
> AGT's self-admitted gaps (memory/knowledge governance, raw unredacted audit, default-allow,
> no cross-action correlation) — is `docs/architecture/30-comparison-agt.md`. Re-verify AGT at
> the start of every phase; it releases monthly.

**Project:** agentos-guard
**Domain:** Open-source runtime governance & security control plane for AI agents (Kubernetes-style PEP/PDP split; synchronous decision pipeline on the hot path of every agent action)
**Researched:** 2026-06-01
**Confidence:** HIGH for the Phase 0 core (stack, architecture, table-stakes features, hot-path/audit pitfalls); MEDIUM for the exact novelty boundary vs Microsoft AGT and for in-process Rego / OTel-GenAI stability; LOW / speculative for all Phase 2 moonshot technology (ZK, SPIFFE, BFT, Rust interop).

## Executive Summary

agentos-guard is a control plane that intercepts **every** AI-agent action (tool / memory / MCP / model / delegation), runs it through a synchronous decision pipeline (identity -> policy -> risk -> graduated response), and writes tamper-evident audit evidence. The 2026 ecosystem has converged on exactly the PEP/PDP "authorization fabric" split the design already uses -- a Policy Enforcement Point that gatekeeps each action, normalizes it to a stable `AgentAction`, and calls a Policy Decision Point that returns a `Decision`. The prescriptive Phase 0 stack is mature and low-risk: **LangChain v1 `AgentMiddleware`** for interception (first-class short-circuitable hooks, no monkey-patching), a thin **`PolicyEngine` interface over an OPA server** (with an `opa-wasm` in-process toggle), an **Anthropic structured-outputs** semantic interpreter (schema-guaranteed `{outcome, cited_principle, rationale}`), **hashlib + Postgres** hash-chain audit, **Presidio** redaction, **FastAPI / Pydantic v2 / SQLAlchemy 2.0 / Alembic** for the control plane, **OpenTelemetry** for emit-don't-replace observability, and **garak + PyRIT** behind pytest for red-teaming.

The single most important finding is a **competitive-positioning correction**. The design docs assume Microsoft's Agent Governance Toolkit (AGT) enforces "static YAML, binary allow/deny." That is stale: the version Microsoft shipped **2026-04-02** already has graduated enforcement, a semantic intent classifier, a Merkle audit trail + Decision-BOM with EU AI Act / SOC 2 export, dynamic trust scoring, SPIFFE/mTLS/DID identity, privilege rings, continuous fuzzing, and five-language SDKs. Three of agentos-guard's five headline differentiators (graduated response, semantic reasoning, Merkle audit, trust scoring) are therefore now **table stakes or near-parity**, and Phase 0 actually *trails* AGT on identity (signed tokens vs SPIFFE), audit (hash chain vs Merkle), framework breadth (LangGraph-only vs 4+), and sandboxing. **Phase 0 must be reframed from "beats AGT" to "reaches parity as an open, Python-native, OPA-grounded control plane with a genuinely human-readable + amendable constitution."** The four genuinely surviving differentiators to foreground are: the amendable/ratifiable Constitution, `require_consensus`/BFT as an enforcement outcome, continuous adversarial self-play feeding ratifiable patches, and zero-knowledge compliance proofs -- plus the pytest-native "safety-as-a-failing-test" developer-experience angle.

The dominant risk is not technology choice but **discipline on the hot path and the security boundary**. Four pitfalls are flagged **P0-KILLER**: (1) running the LLM/heavy detectors inline on every action (blows the single-digit-ms budget; teams disable the guard); (2) un-cached / per-request Rego compilation; (3) accidental silent fail-open when the control plane is unavailable; and (4) incomplete interception across the five action types (90% coverage = 100% false confidence). The architectural mandates that prevent these are non-negotiable and must be built in from day one: a stable `contract/` package first; **agentos-guard owns its own decision/identity/Rego cache because OPA does not cache across queries**; **deterministic OPA is the security floor and the LLM interpreter is advisory-only -- it may recommend but never upgrade a high-risk action**; per-action-class fail posture with **no silent allow** (every fail-open is itself an audit record); and an audit chain that needs a monotonic hash-covered sequence, external anchoring, a CI verifier, and **fail-closed redaction**. The roadmapper should also fold three OWASP-2026 gaps into requirements (memory/context-poisoning ASI06, inter-agent/A2A comms ASI07, code-execution ASI05) and watch the **EU AI Act high-risk deadline binding 2026-08-02**, which lands mid-build.

## Key Findings

### Recommended Stack

The Phase 0 stack is HIGH-confidence and respects all locked ADRs (Python-first, SDK-interception-first, OPA/Rego, hash-chain audit, graduated response). It is deliberately boring and battle-tested where the system is security-critical, and pluggable where the future demands flexibility. The one explicit non-obvious move: **don't auto-instrument LangChain with a vendor library** -- your own middleware already sits on every action, so emit raw OTel GenAI spans there. Full detail in [STACK.md](./STACK.md).

**Core technologies (Phase 0):**
- **LangChain v1 `AgentMiddleware` 1.3.x** (`wrap_tool_call`/`wrap_model_call`/`before_model`/`after_model`): interception PEP -- calling `handler` zero times short-circuits, mapping 1:1 onto `allow/deny/sandbox`; no monkey-patching. `HumanInTheLoopMiddleware` + checkpointer is the native `require_approval` park/resume primitive.
- **OPA server (CNCF-graduated) behind a thin `PolicyEngine` interface**, with **opa-wasm 0.3.2** as an in-process toggle: deterministic Rego hot path; the interface keeps "sidecar vs in-process" a deployment config, not a rewrite. (Cedar explicitly rejected per ADR-0003; revisit `regorus` only for the P2 Rust path -- not yet on PyPI.)
- **anthropic 0.105.x + structured outputs (JSON-schema beta) with Pydantic v2 schemas**: the semantic interpreter always returns a schema-valid `{outcome, cited_principle_id, rationale, confidence}` -- no parse failures, runs only on the ambiguous minority.
- **hashlib (stdlib SHA-256) + canonical JSON + append-only Postgres table**: ADR-0004 is a pattern, not a dependency -- keep it stdlib and auditable.
- **Presidio (analyzer/anonymizer) 2.2.x**: standard OSS PII detection + redaction-at-write-time (required before the audit record is hashed).
- **FastAPI 0.136.x + Pydantic v2.13.x + SQLAlchemy 2.0.x (async) + asyncpg 0.31.x + Alembic 1.18.x + PostgreSQL 16/17**: the declarative control-plane API + persistence; Pydantic doubles as the JSON-schema source for both the API and the Claude interpreter.
- **opentelemetry-sdk 1.42.x + GenAI semantic conventions (opt-in, experimental -- pin and gate via `OTEL_SEMCONV_STABILITY_OPT_IN`)**: emit, integrate, don't replace.
- **pytest 8.x + garak 0.15.x (breadth of attack probes) + PyRIT 0.13.x (multi-turn orchestration)** behind a fixture: "safety as a failing test" with statistical thresholds; isolate in a dev/redteam extra so the runtime stays lean.
- **Supporting guardrails:** LlamaFirewall 1.0.x orchestrator wrapping Prompt Guard 2 (86M/22M, CPU-runnable inline classifier) + LLM Guard 0.3.x scanners; `cryptography` 48.x for signed identity tokens / record signatures.
- **Dev tooling:** uv, Ruff, mypy/pyright, OPA CLI (`opa fmt/test/build -t wasm`), `testcontainers[postgres]` (SQLite hides append-only/trigger behavior).

**Phase 2 stack is explicitly LOW-confidence/speculative:** ZK (RISC Zero / SP1, Rust-first, no Python SDK), SPIFFE/SPIRE (MEDIUM), BFT (no strong Python-native lib -- note the P1 "2-of-3 consensus" is application-level voting, *not* a BFT protocol), Rust interop via PyO3/maturin (HIGH on mechanism, not on need -- profile first). Sequence *evaluation* of these, not adoption.

### Expected Features

The 2026 bar was reset by AGT (Apr 2026), the OWASP Agentic Top 10 (Dec 2025, codes ASI01-ASI10), and the EU AI Act high-risk deadline (Aug 2, 2026). Full landscape, dependency graph, and competitor matrix in [FEATURES.md](./FEATURES.md).

**Must have (table stakes -- adoption blockers if missing):**
- Action interception across all five action types + `AgentAction` normalization
- Declarative policy enforcement (Constitution -> YAML -> OPA/Rego)
- Graduated enforcement (warn/sandbox/require_approval/deny) -- AGT shipped this, so it is now expected, not novel
- Human-in-the-loop approval workflow (EU AI Act Art. 26 evidence)
- Tamper-evident audit log with decision provenance (EU AI Act Art. 12)
- Agent identity (signed tokens) + dynamic trust score (now parity, not a differentiator)
- Agent self-registration + authoritative inventory
- Prompt-injection detection + baseline guardrails (PII / unsafe / format) -- OWASP ASI01
- Kill switch; OpenTelemetry export; OWASP + NIST AI RMF compliance mapping; pytest-native red-team in CI

**Should have (the four surviving differentiators + one DX angle):**
- **Living, human-readable, amendable Constitution** with cited-principle rationale -- the strongest survivor (AGT has semantic classification but *not* a versioned, human-authored, proposal/ratification-evolving governing document). Author + cite in P0; amendments in P2.
- **`require_consensus` (2-of-3 -> BFT)** as a first-class graduated outcome -- the only piece of the graduated-response spectrum AGT does not match. P1 then P2.
- **Continuous adversarial self-play** that generates novel attacks and proposes ratifiable defense amendments (closes the ASI10 drift loop) -- P2.
- **Zero-knowledge compliance proofs** (prove "no PII exfiltrated" without revealing context) -- clearly novel, highest ceiling, P2.
- **pytest-native safety-as-correctness DX** (`assert attack_success_rate < 0.02` breaks CI) -- cheap, strong demo, real adoption lever for Python shops. P0.

**Defer (Phase 1/2):** reputation/trust propagation/delegation chains, sandboxing/privilege rings/circuit breakers, full security engine (data-exfil, secret-leakage, tool-poisoning, MCP gateway, supply-chain), more framework adapters, economics/ABOM/lineage, EU AI Act + SOC 2 export (P1); constitution amendments, self-play, ZK proofs, SPIFFE/mTLS, stake-based reputation, K8s operator, Rust hot path (P2 moonshot, all gated on the P0/P1 substrate).

**Design gaps to fold into requirements (real holes vs OWASP-2026):**
1. **Memory / context-poisoning detector (ASI06)** -- memory is an interceptable type but there is *no detector* for poisoned/persisted entries. Add to Security Engine (P1).
2. **Inter-agent comms / A2A verification (ASI07)** -- currently folded into prompt-injection; no agent-card verification, message auth, or replay protection. Add (P1), tied to identity.
3. **Code-execution / generated-code detector (ASI05)** -- covered by generic tool interception but never named. Add (P1).
4. **Identity & audit trail weaker than AGT at launch** -- pull a minimal SPIFFE/mTLS or at least agent certificates, and Merkle DAG, earlier (P0-stretch).
5. **Single-framework launch (LangGraph-only)** is the biggest addressable-market gap; a second adapter (CrewAI or OpenAI Agents SDK) is a high-value P0-stretch.
6. **EU AI Act timing** -- the high-risk deadline binds **2026-08-02**, mid-build. Confirm whether P0 hash-chained audit + approval already minimally satisfy Art. 12/26 and consider surfacing that as a P0 compliance claim; pull minimal logging/human-oversight evidence earlier.

### Architecture Approach

The design is validated against 2026 patterns: a **data plane** of swappable PEP forms (P0 SDK shim -> P1 gateway -> P2 Envoy `ext_authz` sidecar) all emitting the **same normalized `AgentAction`** across **one stable PEP<->PDP contract**, and a **control plane** that decides, stores, and observes. The synchronous PDP runs four ordered, short-circuiting stages against in-memory caches; everything non-decision (OTel, graph materialization, dashboards, red-team) is async/off-path. Full structure, patterns, build order, and the walking-skeleton slice in [ARCHITECTURE.md](./ARCHITECTURE.md).

**Major components:**
1. **`contract/` (the load-bearing boundary)** -- `AgentAction` schema, `Decision` schema, `PipelineProtocol.evaluate()`. Everything depends only on this; design it **serializable and context-rich from day one** so the P1 gateway and P2 sidecar swap in without a schema break. Treat any change here as an API break.
2. **PEP / data plane** -- capture before execution, normalize, call the pipeline synchronously, realize the outcome. Owns enforcement, not decisions. All PEP-specific logic stays in `dataplane/*`; the pipeline never learns which PEP called it.
3. **Decision Pipeline / PDP** -- four stages: Identity & Trust (forged/unknown -> short-circuit deny) -> Policy (prepared Rego; route ambiguity to the LLM interpreter) -> Risk (cheap heuristics inline, heavy models only on flag) -> Graduated Response (pure function over {policy, risk, trust} -> outcome).
4. **`controlplane/cache/`** -- its own module **because OPA has no cross-query decision cache**; agentos-guard keeps prepared Rego + identity/trust caches keyed by `(action signature, policy_version)`, invalidated by reconcilers on write.
5. **Control-Plane API + reconcilers + Postgres** -- declarative resource CRUD; compile-on-write in P0 (loops are P1); resources + append-only hash-chained audit table.
6. **Proof & Audit layer** -- append signed, hash-chained records with policy-version provenance and write-time redaction; Merkle DAG (P1); ZK (P2).
7. **Observability + Red-team planes** -- both off the request path by construction; the red-team plane drives the *same* pipeline via a fixture, which is why removing a policy can fail CI.

**Build order (each step independently testable; the vertical slice closes first):** `contract/` -> `controlplane/store + api` -> `engines/identity` -> `engines/policy` (compiler + OPA client + compile-on-write + Rego cache; interpreter can start as a stub) -> `engines/security` (parallel-able) -> `pipeline/` -> `engines/audit` (before the SDK, so the first action already yields an `evidence_ref`) -> `dataplane/sdk` -> `observability/` -> `testing/` (last -- it consumes the finished pipeline) -> approvals + kill switch + read-only dashboard.

**Phase-0 walking-skeleton slice (build this first):** ONE LangGraph agent, ONE governed tool, ONE Constitution principle, proven end to end -- intercept -> normalize -> identity-verify -> OPA-evaluate one principle -> one injection heuristic -> graduated threshold -> one hash-chained audit record with policy_version -> enforce -> OTel span -- and ONE pytest red-team test wired so that *removing the policy fails the build*. This is the documented Phase-0 acceptance criterion verbatim; all other Phase-0 breadth layers on top of this proven loop.

### Critical Pitfalls

Top pitfalls from [PITFALLS.md](./PITFALLS.md) -- the four P0-KILLERs plus the must-hold security invariants. Each maps to a specific architectural mandate.

1. **Inline LLM/heavy detection on the hot path [P0-KILLER]** -- Avoid: deterministic OPA is the only unconditional stage; the LLM interpreter is **conditional** (ambiguous/no-rule only) and cached; cheap heuristics inline, heavy models only on flag; assert a per-stage latency budget (p95 cached-path < 5 ms) as a CI benchmark test.
2. **Un-cached / per-request Rego compilation [P0-KILLER]** -- Avoid: compile Constitution->Rego at write time, store the compiled artifact, version it; the pipeline only *evaluates*; use prepared queries + `opa build --optimize`; warm caches on startup + on policy change, never lazily on first action.
3. **Accidental silent fail-open / control-plane-unavailability bypass [P0-KILLER]** -- Avoid: failure posture is **explicit and per-action-class** (high-risk -> fail-closed; low-risk may fail-open *only with a logged warning audit record*); **no silent allow path** -- every fail-open is itself evidence; bounded local cache + circuit breaker + hard timeout; red-team test kills the control plane mid-run and asserts high-risk denies.
4. **Incomplete interception / shadow agents [P0-KILLER]** -- Avoid: treat the five action types as a **coverage matrix** with a test per type; build an adversarial bypass-attempt test (raw HTTP, undecorated tool, direct model call); flag unregistered `agent_id`s; **document the trust boundary honestly** (the P0 SDK is not a sandbox -- non-bypass needs the P1 gateway / P2 sidecar; never market "impossible to bypass").
5. **Prompt-injecting the governance LLM itself [P0-KILLER]** -- Avoid: **deterministic OPA is the security floor; the LLM is advisory and may never upgrade a high-risk action above what policy allows** (cap its max grant at warn/sandbox/escalate); separate trusted instructions from untrusted payload; typed schema output; pre-score injection upstream; adversarial-judge tests in the P0 red-team suite.
6. **Hash chain that isn't truly tamper-evident [P0-KILLER for the "proof" claim]** -- Avoid: monotonic hash-covered **sequence** (not wall-clock ordering); **external anchoring** of the chain head (app-external-signed root minimum in P0; Merkle DAG + richer anchoring P1); **fail-closed redaction** with a secret-detector last gate (a leaked secret in an immutable log is non-recoverable); ship and CI-run a chain-verification tool.
7. **Constitution->Rego fidelity loss & conflict explosion** -- Avoid: define **conflict precedence as a P0 invariant** (deny-overrides or explicit priority); conflict -> escalate, never silently branch; round-trip principle-citation provenance; golden tests; track the **ambiguous-routing rate** as an early-warning SLO.
8. **Gameable trust / delegation privilege escalation** -- Avoid: **trust modulates within the graduated band, never overrides hard policy**; delegated scope is the **intersection** (bounded, non-increasing), not union; slow accrual / fast decay; don't ship trust propagation before scope-intersection is enforced.
9. **Moonshot before the loop is solid** -- Avoid: treat sequencing as a **hard gate** -- no Phase 2 feature starts until its P0/P1 substrate passes verification (latency budget held, audit externally verifiable, coverage matrix green, red-team gating CI). ZK over an un-anchored chain proves a forgery; self-play against a weak constitution amplifies weakness.
10. **Reinventing OPA/OTel / heavy onboarding (adoption death)** -- Avoid: OPA is the only evaluator; emit standard OTel to the user's backend; few-line onboarding (`@governed` + register), no K8s in P0; measure time-to-first-governed-action.

## Implications for Roadmap

The research strongly supports the documented Phase 0 -> Phase 1 -> Phase 2 structure, with one reframing (parity, not "beats AGT") and several gap-driven additions. The dependency graph and architecture build order make the ordering nearly forced. Below is the suggested phase structure.

### Phase 0: Parity Walking Skeleton -- the runtime loop, rock-solid
**Rationale:** Everything depends on the `contract/` boundary and the intercept->decide->enforce->record loop; the four P0-KILLER pitfalls are all foundational and cannot be retrofitted; the documented acceptance criterion is a single proven vertical slice. Reframed goal: **reach parity as an open, Python-native, OPA-grounded control plane with a human-readable, cited-principle constitution** -- not "beat AGT."
**Delivers:** the walking-skeleton slice (one agent, one tool, one principle, end-to-end, with a CI-gating red-team test), then breadth on top: five-action-type interception, four-stage pipeline, Constitution->YAML->OPA/Rego + cited-principle interpreter, graduated response, approval workflow, signed-token identity + 0-1 trust, self-registration + inventory, hash-chained audit with provenance, OWASP+NIST mapping, prompt-injection + baseline guardrails, kill switch, OTel, control-plane API + Postgres + minimal dashboard, pytest red-team layer.
**Addresses (FEATURES):** all table stakes; the cited-principle constitution and pytest-DX differentiators.
**Uses (STACK):** LangChain v1 middleware, OPA-server behind `PolicyEngine`, Anthropic structured outputs, hashlib+Postgres, Presidio, FastAPI/Pydantic/SQLAlchemy/Alembic, OTel, garak+PyRIT.
**Implements (ARCH):** `contract/` first -> store/api -> identity -> policy (+ Rego cache) -> security -> pipeline -> audit -> sdk -> observability -> testing -> approvals/kill-switch/dashboard.
**Avoids (PITFALLS):** all six P0-KILLER/foundational invariants -- conditional+cached LLM, compile-on-write+prepared queries, per-class no-silent-allow fail posture, five-type coverage matrix, advisory-only LLM with deterministic floor, monotonic+anchored+fail-closed-redacted+verifiable audit chain. Plus conflict-precedence, trust-modulates-only, OPA/OTel reuse.
**P0-stretch (close the most visible AGT gaps):** Merkle DAG audit, agent certificates (or minimal SPIFFE/mTLS), a second framework adapter (CrewAI or OpenAI Agents SDK), a minimal MCP manifest-hashing scanner, and a minimal EU AI Act Art. 12/26 evidence claim.

### Phase 1: Trust, Containment, Security Engine & Scale
**Rationale:** These build directly on the P0 loop and close the remaining AGT parity gaps; they are where the surfaced OWASP gaps land; reconciliation loops + gateway PEP are the multi-node scaling answer.
**Delivers:** reputation / trust propagation / delegation trust chains / certificates; sandboxing, privilege rings, resource isolation, circuit breakers, emergency shutdown; the full Security Engine (data-exfil, secret-leakage, tool-poisoning, MCP gateway, supply-chain) **plus the three gap detectors -- memory/context-poisoning (ASI06), inter-agent/A2A comms auth (ASI07), code-execution (ASI05)**; gateway/proxy PEP + more framework adapters; `require_consensus` (2-of-3, application-level voting); economics/budget governance (reusing the graduated-response engine), ABOM, lineage, conversation tracing, SLO dashboards; Merkle DAG audit (if not pulled to P0); EU AI Act + SOC 2 mapping + one-click export; reconciliation loops.
**Uses (STACK):** pgmq (approvals upgrade), py-spiffe (MEDIUM), pymerkle/hashlib (Merkle), the same `PolicyEngine` interface (opa-wasm toggle if latency binds).
**Avoids (PITFALLS):** bounded/intersecting delegation scope before trust propagation; tool/MCP-poisoning via manifest-drift detection + treating descriptions as untrusted; multi-node cache-invalidation correctness via reconciliation loops; richer audit anchoring.
**Note:** the P1 "2-of-3 consensus" is voting, NOT BFT -- keep scope honest.

### Phase 2: Moonshot -- SPECULATIVE, gated on P0/P1 substrate
**Rationale:** Each moonshot is downstream of a P0/P1 base invariant (ZK <- Merkle DAG <- hash chain; self-play <- amendments + mature red-team; BFT <- 2-of-3 consensus; stake-based reputation <- validated trust). Pitfall 11 makes the sequencing a hard gate. All Phase 2 technology is LOW-confidence and Rust/immature-Python-interop.
**Delivers:** Constitution amendments + cross-agent conflict/legal reasoning; continuous adversarial self-play + runtime patching + threat-intel; zero-knowledge compliance proofs (RISC Zero / SP1); SPIFFE/mTLS + stake-based/portable reputation + BFT consensus; K8s operator/sidecar (Envoy ext_authz); Rust hot-path rewrite (profile-driven, candidates: `pipeline/runner.py` + `stage_policy.py`).
**Gate:** no Phase 2 work starts until the P0/P1 substrate passes verification (latency budget held, audit externally verifiable, coverage matrix green, red-team gating CI). Self-play amendments require mandatory human ratification and a held-out eval set.

### Phase Ordering Rationale

- **`contract/`-first and the walking skeleton are forced** by the architecture: the stable PEP<->PDP boundary is what makes every later phase additive rather than a rewrite. Get `AgentAction` serializable-and-rich now.
- **Engines before the pipeline** (identity/policy/security are thin-orchestrated by stages), and **audit before the SDK** (the first end-to-end action must already produce a verifiable `evidence_ref`), and **red-team last** (it consumes the finished pipeline).
- **Clean dependency chains forbid reordering:** hash chain (P0) -> Merkle DAG (P1) -> ZK (P2); `require_approval` (P0) -> `require_consensus` 2-of-3 (P1) -> BFT (P2); discovery (P0) -> live graph/lineage (P1) -> cross-agent conflict reasoning (P2); ABOM (P1) gates MCP+supply-chain (P1). Constitution amendments (P2) and self-play (P2) must land together.
- **Economics reuses the graduated-response engine** -- a genuine win; do not build a parallel budget enforcer.
- **Pitfall 11 is the meta-ordering rule:** moonshots are seductive but each amplifies a weak base if the loop isn't solid; gate every phase transition.

### Research Flags

Phases likely needing deeper research during planning (`/gsd:plan-phase --research-phase <N>`):
- **Phase 0 -- Constitution->YAML->Rego compiler:** the English-to-Rego fidelity/conflict-precedence problem (Pitfall 7) is genuinely hard and under-specified; needs design research on the YAML middle layer, precedence semantics, and golden-test strategy.
- **Phase 0 -- audit tamper-evidence:** external anchoring approach (HSM vs RFC-3161 vs transparency-log witness) and the fail-closed-redaction last-gate need a focused design pass before implementation.
- **Phase 1 -- Security Engine gap detectors (ASI06 memory-poisoning, ASI07 A2A, ASI05 code-exec):** newly surfaced, sparse production references; each needs a detector-design research spike.
- **Phase 1 -- multi-node cache invalidation:** the reconciliation-loop + cross-node invalidation pattern (Hazelcast/pub-sub) needs research before scaling.
- **All of Phase 2:** LOW-confidence by definition -- ZK (RISC Zero/SP1 Python interop), SPIFFE, BFT, Rust hot-path each need a dedicated evaluation spike *before* commitment; treat as research-then-decide, not build.

Phases with well-documented standard patterns (lighter or no research-phase):
- **Phase 0 -- control-plane API + persistence + interception + OTel:** FastAPI/Pydantic/SQLAlchemy/Alembic, LangChain middleware, and OTel are all HIGH-confidence with official docs and verified signatures; standard patterns.
- **Phase 0 -- pytest red-team layer:** garak/PyRIT integration is well-trodden; the only nuance (sample-size-aware thresholds + a separate deterministic regression-lock suite) is captured in Pitfall 12.

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Stack | HIGH (P0) / LOW (P2) | P0 picks verified against PyPI + official docs 2026-06-01; in-process Rego path and OTel-GenAI conventions MEDIUM (experimental); all P2 tech LOW (Rust-first, immature Python interop). |
| Features | HIGH (landscape) / MEDIUM (novelty boundary) | Competitor/compliance landscape verified against AGT GitHub+docs, OWASP, EU AI Act primary sources; the precise still-novel boundary is MEDIUM because AGT's roadmap moves fast and some internals are undocumented. |
| Architecture | HIGH | Locked ADRs + 2026 ecosystem patterns (arXiv runtime-governance, Microsoft authorization-fabric, Envoy ext_authz, OPA-Envoy) corroborate the design; build-order recommendations MEDIUM where they extend beyond documented decisions. |
| Pitfalls | HIGH (hot-path/audit) / MEDIUM (moonshot) | P0-KILLERs corroborated by OPA docs, OWASP, prompt-injection research, tamper-evidence literature; self-play/moonshot pitfalls MEDIUM (fewer production references). |

**Overall confidence:** HIGH for the Phase 0 roadmap (what to build, in what order, and the invariants that prevent disaster). MEDIUM for the competitive framing (parity vs AGT -- directionally certain, exact gap list fast-moving). LOW for Phase 2 specifics (correctly treated as moonshot/evaluation, not commitment).

### Gaps to Address

- **Competitive positioning is stale in the design docs.** `docs/architecture/30-comparison-agt.md` must be revised: Phase 0 reaches *parity*, not victory, and trails AGT on identity/audit/framework-breadth/sandboxing at launch. -> Reframe before requirements lock; foreground the four surviving differentiators.
- **Three OWASP-2026 detector gaps (ASI06 memory-poisoning, ASI07 A2A comms, ASI05 code-exec)** are not in the current design. -> Add as explicit P1 Security Engine requirements; each needs a research spike.
- **Identity & audit trail weaker than AGT at launch** (signed tokens vs SPIFFE; hash chain vs Merkle). -> Decide whether to pull agent certificates / Merkle DAG into P0-stretch to remove direct "AGT does X, you don't" comparisons.
- **Single-framework launch (LangGraph-only)** is the biggest addressable-market gap. -> Decide if a second adapter is a P0-stretch requirement.
- **EU AI Act high-risk deadline binds 2026-08-02 (mid-build).** -> Confirm whether P0 hash-chained audit + approval minimally satisfy Art. 12/26; consider a minimal P0 compliance claim and pulling logging/human-oversight evidence earlier.
- **Cedar policy backend** absent (AGT has it). -> Architecturally cheap to keep open: design the `PolicyEngine` interface pluggable so Cedar can be added later without re-architecture (low priority).
- **Latency budget is asserted but unvalidated** (single-digit-ms target). -> Phase 0 must build the CI benchmark test that makes the budget a tested invariant from day one.

## Sources

### Primary (HIGH confidence)
- LangChain v1 middleware official docs (`wrap_tool_call`/`wrap_model_call`, short-circuit semantics, HumanInTheLoopMiddleware) -- interception PEP design -- https://docs.langchain.com/oss/python/langchain/middleware/custom
- PyPI JSON API version checks (langchain 1.3.2, fastapi 0.136.3, pydantic 2.13.4, sqlalchemy 2.0.50, anthropic 0.105.2, opa-wasm 0.3.2, garak 0.15.0, pyrit 0.13.0, presidio 2.2.362, etc.), 2026-06-01 -- stack version pinning
- Anthropic structured outputs (JSON-schema guarantee on Sonnet 4.5 / Opus 4.x) -- https://platform.claude.com/docs/en/build-with-claude/structured-outputs
- OPA / Integrating OPA official docs (prepared queries avoid per-request compile; no cross-query decision cache; WASM option) -- https://www.openpolicyagent.org/docs/integration
- Microsoft Agent Governance Toolkit -- GitHub + launch blog (2026-04-02) -- parity-reset evidence -- https://github.com/microsoft/agent-governance-toolkit
- OWASP Top 10 for Agentic Applications 2026 (ASI01-ASI10) -- https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- EU AI Act Article 26 (human oversight) + high-risk logging (Art. 12, >=6-month retention; bind 2026-08-02) -- https://artificialintelligenceact.eu/article/26/
- Runtime Governance for AI Agents: Policies on Paths (arXiv, Mar 2026) + Microsoft "Authorization Fabric" PEP/PDP pattern + Google Cloud Envoy/ext_authz -- architecture validation -- https://arxiv.org/pdf/2603.16586
- Lakera "LLM-as-a-Judge fails at prompt injection defense" + arXiv "Bypassing Prompt Injection in LLM Guardrails" -- the advisory-only-LLM mandate -- https://www.lakera.ai/blog/stop-letting-models-grade-their-own-homework-why-llm-as-a-judge-fails-at-prompt-injection-defense
- MCP Tool Poisoning (OWASP + Invariant Labs) -- manifest-hashing mandate -- https://owasp.org/www-community/attacks/MCP_Tool_Poisoning

### Secondary (MEDIUM confidence)
- OTel GenAI semantic conventions (experimental status, `OTEL_SEMCONV_STABILITY_OPT_IN`) -- https://opentelemetry.io/docs/specs/semconv/gen-ai/
- AGT architecture deep dive (Microsoft Community Hub) + AGT docs site -- competitor internals
- WSO2 XACML PDP caching / Cerbos / Permit.io -- PDP cache-invalidation patterns
- Tamper-evident audit + external anchoring (DesignGurus, AppMaster, Tracehold) -- Pitfall 8 anchoring/redaction
- LLM guardrail latency benchmarks (TrueFoundry: judges 1-5s, classifiers 50-190ms) -- hot-path budget basis
- AI Agent Memory Governance (Atlan) / A2A Protocol Security (Securew2) -- ASI06/ASI07 gap evidence

### Tertiary (LOW confidence -- needs validation before commitment)
- microsoft/regorus (Rust Rego, not on PyPI), regopy -- P2 in-process/Rust Rego options
- RISC Zero / SP1 (ZK), SPIFFE/SPIRE + py-spiffe, CometBFT/HotStuff -- P2 moonshot tech (Rust-first, immature Python interop)
- Reward hacking in self-play / benchmark contamination (EvilGenie, MonitoringBench) -- P2 self-play pitfalls

---
*Research completed: 2026-06-01*
*Ready for roadmap: yes*
