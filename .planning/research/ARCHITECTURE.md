# Architecture Research

> 📸 **Research snapshot — 2026-06-01. Not authoritative.** The live, authoritative architecture
> is [`docs/architecture/`](../../docs/architecture/). This file's job is to **validate** that
> design against real-world 2026 patterns and to recommend a concrete, dependency-ordered **build
> sequence** and **code layout**. It does *not* re-specify the design — where you want "what the
> system is," read `docs/architecture/`; read here for "is the design sound, and in what order do
> we build it."

**Domain:** Runtime governance & security control plane for AI agents (PEP/PDP split; synchronous decision pipeline on the hot path)
**Researched:** 2026-06-01
**Confidence:** HIGH (locked ADRs + 2026 ecosystem patterns corroborate the design; build-order recommendations are MEDIUM where they extend beyond documented decisions)

Consistent with the locked ADRs: Python-first (ADR-0001), SDK-interception-first (ADR-0002),
Constitution→YAML→OPA/Rego (ADR-0003), hash-chained audit (ADR-0004), graduated response
(ADR-0005), no crypto-economics in core (ADR-0007). Where research *adds* a recommendation beyond
the docs, it is flagged inline.

---

## Standard Architecture (validation)

The 2026 ecosystem has converged on a **PEP / PDP split** for runtime AI-agent governance — the
exact mental model the design already uses. The arXiv paper *"Runtime Governance for AI Agents:
Policies on Paths"* (Mar 2026) and Microsoft's *"Authorization and Governance for AI Agents:
Runtime Authorization Beyond Identity"* both describe a reusable **Authorization Fabric**: a PEP
that gatekeeps every tool/action and a PDP that evaluates policy. Google Cloud's *"case for Envoy
networking in the agentic AI era"* and the OPA-Envoy `ext_authz` integration confirm the contract
shape: a **single request/response authorization protocol** that stays stable while the enforcement
point changes form (in-process → proxy → mesh sidecar). This is precisely the agentos-guard
"one pipeline contract, three PEP forms" thesis.

**Finding:** the design is sound and matches where the industry landed. No structural change
recommended.

> **The system overview, component responsibilities, request/state data-flow diagrams, and the
> control-plane model are defined authoritatively in the design — not duplicated here:**
> - Control-plane / data-plane model + request lifecycle → [`docs/architecture/01-overview.md`](../../docs/architecture/01-overview.md)
> - Domain entities + `AgentAction`/`Decision` shapes → [`docs/architecture/02-domain-model.md`](../../docs/architecture/02-domain-model.md)
> - PEP forms + the 4-stage pipeline → [`docs/architecture/03-interception-and-pipeline.md`](../../docs/architecture/03-interception-and-pipeline.md)
> - Per-engine responsibilities → docs `04`–`10`.

---

## Recommended Project Structure  *(research add — not in the design docs)*

A single Python package (monorepo-friendly) with a hard internal boundary between **data plane**
(PEP/SDK) and **control plane** (pipeline + engines + API). The boundary is the pipeline contract.

```
agentos_guard/
├── contract/              # THE STABLE BOUNDARY — depend-on-this, change-rarely
│   ├── action.py          # AgentAction schema (pydantic) — the normalized event
│   ├── decision.py        # Decision schema (outcome/risk/trust/reasons/evidence_ref)
│   └── pipeline.py        # PipelineProtocol: evaluate(AgentAction) -> Decision
│
├── dataplane/             # PEPs — everything that lives in the request path
│   ├── sdk/               # P0: LangGraph/LangChain decorators + middleware (the v1 PEP)
│   │   ├── interceptors.py# wrap tool/memory/model/delegation boundaries
│   │   ├── normalize.py   # framework call -> AgentAction
│   │   └── enforce.py     # realize allow/warn/sandbox/approval/deny
│   ├── gateway/           # P1: framework-agnostic proxy (same normalize/enforce)
│   └── sidecar/           # P2: Envoy ext_authz adapter + operator
│
├── pipeline/              # THE PDP — synchronous decision stages
│   ├── runner.py          # orchestrates stages, short-circuit, reason accumulation
│   ├── stage_identity.py  # stage 1
│   ├── stage_policy.py    # stage 2 (OPA client + interpreter router)
│   ├── stage_risk.py      # stage 3 (security engine entrypoint)
│   └── stage_graduated.py # stage 4 (threshold mapping)
│
├── engines/               # Control-plane engines the stages call into
│   ├── identity/          # token issue/verify, trust load
│   ├── policy/            # constitution compiler, OPA wrapper, interpreter
│   ├── security/          # pluggable risk scorers (injection, guardrails, intent tags)
│   ├── audit/             # hash-chain writer + verifier + redaction
│   └── discovery/         # self-registration, inventory (graph materialized later)
│
├── controlplane/          # API + persistence + reconciliation
│   ├── api/               # declarative resource CRUD, approvals, kill switch
│   ├── resources/         # Agent/Policy/Constitution/TrustProfile/ApprovalRequest/ABOM
│   ├── store/             # Postgres models + migrations (resources + audit table)
│   ├── reconcile/         # compile-on-write (P0); loops (P1+)
│   └── cache/             # hot-path caches (compiled Rego, identities, thresholds)
│
├── observability/         # OTel spans/metrics emitters (async, off hot path)
└── testing/               # pytest red-team adapters, attack library, thresholds

tests/
├── unit/
├── integration/           # end-to-end vertical slice lives here
└── redteam/               # the suites that gate CI
```

### Structure Rationale

- **`contract/` is the load-bearing folder.** `dataplane/*` and the rest of the system depend
  *only* on `contract/`. This is what lets the SDK shim (P0), gateway (P1), and sidecar (P2)
  swap in without touching the pipeline — exactly the ext_authz / OPA decoupling pattern. Treat
  any change here as an API break with a migration note.
- **`pipeline/` is separate from `engines/`** so stages stay thin orchestrators and the expensive
  logic (OPA, interpreter, scorers) is independently testable and independently optimizable
  (the P2 Rust candidates are `pipeline/runner.py` + `stage_policy.py`, per ADR-0001).
- **`controlplane/cache/` is explicitly its own module** because — see Pattern 3 below —
  **OPA does not cache decisions across queries**, so the caching that hits the single-digit-ms
  budget must live in agentos-guard, not in OPA.
- **`testing/` and `observability/` sit outside the request path** by construction, reinforcing the
  async/sync boundary at the directory level.

---

## Architectural Patterns

### Pattern 1: One stable PEP↔PDP contract, swappable enforcement points (ext_authz analogy)

**What:** Define a single `evaluate(AgentAction) -> Decision` contract. Every PEP form normalizes
its native call into `AgentAction`, calls `evaluate`, and realizes the `Decision`. The PDP never
learns which PEP called it. This mirrors Envoy's `ext_authz`: Envoy/Istio Ambient call an external
authz service over one protocol regardless of what is being proxied, and OPA-Envoy implements that
API with zero custom glue.

**When to use:** Always, from P0. It is the single most important design invariant — it is what
makes each phase independently shippable without a rewrite.

**Trade-offs:** (+) New PEP forms are additive. (+) The pipeline can be tested in isolation with a
fake PEP. (−) Forces you to design `AgentAction` to be rich enough for in-process context (tools,
memory, delegation edges) yet serializable for the eventual network/sidecar PEPs — design it
serializable from day one even though P0 calls in-process.

**Example:**
```python
# contract/pipeline.py — the only thing PEPs import
class PipelineProtocol(Protocol):
    async def evaluate(self, action: AgentAction) -> Decision: ...

# dataplane/sdk/interceptors.py — P0 PEP
@governed
async def run_tool(tool, args, ctx, pipeline: PipelineProtocol):
    action = normalize(tool, args, ctx)          # -> AgentAction (serializable)
    decision = await pipeline.evaluate(action)   # in-process now; network later
    return enforce(decision, lambda: tool(args)) # allow/sandbox/deny/...
```

### Pattern 2: Tiered hot-path evaluation — cheap-and-cached first, expensive only on flag

**What:** Order the pipeline cheapest-and-most-decisive first. Stage 1 (identity) and stage 2
(compiled-Rego policy) run against in-memory caches in low single-digit ms. The **LLM semantic
interpreter** (stage 2 fallback) and **heavy anomaly/ML models** (stage 3, incl. the embedding
intent classifier) run *only* when a cheaper stage flags ambiguity or elevated risk. A clear `deny`
from identity or policy short-circuits before any model is ever invoked.

**When to use:** From P0, to hold the latency budget. This is the documented design
(`docs/architecture/03` performance section) and is the standard PDP-performance posture in 2026.

**Trade-offs:** (+) p50 latency is dominated by cache hits, not model calls. (+) Cost is bounded —
LLM only on the ambiguous minority. (−) Two evaluation modes (deterministic + LLM) add complexity
and a consistency surface; the interpreter's outputs must be captured as proposed policy refinements
(Phase 2 amendments) so the deterministic core absorbs them over time.

### Pattern 3: Caching is the control plane's job, NOT OPA's (critical correction)

**What:** OPA guarantees consistency by **re-evaluating every query from scratch — it has no
cross-query decision cache**. To hit the low-single-digit-ms budget, agentos-guard must (a) keep
*compiled/prepared* Rego in memory (prepared queries avoid re-parse/re-compile per request) and
(b) maintain its **own** decision/identity/trust caches with explicit invalidation, warmed by the
reconcilers on resource writes.

**When to use:** From P0. Build `controlplane/cache/` with a TTL + event-driven invalidation: when a
`Policy`/`Constitution`/`TrustProfile` is written, the reconciler recompiles and invalidates the
affected cache entries (the WSO2/PlainID PDP-cache-invalidation pattern).

**Trade-offs:** (+) Sub-ms repeat decisions while preserving determinism. (−) Caching decisions in
front of a deliberately-stateless engine reintroduces the invalidation problem OPA avoided — get
invalidation wrong and you enforce stale policy. Mitigation: cache keyed by `(action signature,
policy_version)` so a new compile naturally produces new keys; never serve a cached decision whose
`policy_version` is no longer current. *(Wired as REQ PIPE-06.)*

### Pattern 4: Declarative resources + reconciliation (compile-on-write → loops)

**What:** Everything operators touch is a declarative resource (Agent/Policy/Constitution/
TrustProfile/ApprovalRequest/ABOM). The API persists desired state; reconcilers drive derived state
(compiled Rego, refreshed trust, materialized graph, warmed caches). **P0 compiles on write**
(synchronous, simple, correct for one node); **P1+ adds continuous loops** for scale and self-heal.

**When to use:** P0 for compile-on-write; defer loops until there is a scale/robustness need (multi-
node, drift). This matches the documented phasing (`docs/architecture/10`) and avoids building a
reconciliation framework before it earns its keep.

**Trade-offs:** (+) Kubernetes-familiar operator UX; clean upgrade path. (−) Compile-on-write can
miss out-of-band drift — acceptable single-node in P0, which is why loops arrive with the gateway.

### Pattern 5: Sync hot path, async everything-else (audit emit, OTel, red-team)

**What:** Only the four pipeline stages and the **audit write that produces the `evidence_ref`** are
on the synchronous hot path. OTel span/metric emission, dashboard projections, graph materialization,
and the entire red-team plane are async / out-of-band.

**When to use:** Always. Keeps the budget achievable and the request path minimal.

**Trade-offs:** (+) Predictable latency. (−) The audit write is a genuine tension: a hash chain is
inherently serial (each record needs the previous hash). See Anti-Pattern + Scaling below.

---

## Data Flow

The authoritative request lifecycle and state-management flows are in
[`docs/architecture/03`](../../docs/architecture/03-interception-and-pipeline.md) (pipeline) and
[`docs/architecture/10`](../../docs/architecture/10-control-plane-api-and-sdk.md) (reconciliation).
The research-specific observations that are *not* in the design docs:

1. **Decision flow (hot path):** `AgentAction → 4 stages → Decision → audit write → enforce`. The
   only synchronous DB write is the audit append; reads are cache-first.
2. **Provenance flow:** every `Decision`/`AuditRecord` carries the exact `policy_version` that
   evaluated it, so evidence is replayable **and** the audit cache key (Pattern 3) is correct.
3. **Lineage flow (derived, async):** `AgentAction.context.parent_action_id` chains build the
   delegation graph and decision provenance — materialized from relations, not a graph DB in P0
   (see Anti-Pattern 4).
4. **Red-team flow (CI, off path):** the attack library drives the *same* pipeline via a test
   fixture; `attack_success_rate` is asserted against a statistical threshold; a regression failure
   breaks CI. This shared-pipeline reuse is *why* removing a policy can fail CI.

---

## Suggested Build Order (with dependencies)  *(research add)*

Ordered so each step is independently testable and the **Phase-0 vertical slice closes first**.
Arrows = hard dependency.

```
1. contract/   (AgentAction, Decision, PipelineProtocol)
        │  (everything depends on this; design it serializable now)
        ▼
2. controlplane/store + api   (Postgres resources + hash-chained audit table + minimal CRUD)
        │
        ▼
3. engines/identity   (register agent, issue/verify signed token, basic 0–1 trust)
        │
        ▼
4. engines/policy   (Constitution→YAML→Rego compiler + OPA client + compile-on-write + Rego cache)
        │           └─ interpreter router can be a stub returning "ambiguous→escalate" first
        ▼
5. engines/security   (prompt-injection + baseline guardrails + intent tags → risk_score)  [‖ w/ 4]
        │
        ▼
6. pipeline/   (runner + 4 stages wired to 3,4,5; short-circuit + reason accumulation)
        │
        ▼
7. engines/audit   (hash-chain writer + verifier + write-time redaction; emits evidence_ref)
        │
        ▼
8. dataplane/sdk   (LangGraph decorators: normalize + enforce, calling pipeline.evaluate)
        │
        ▼
9. observability/   (OTel spans/metrics — async, can land alongside 8)
        │
        ▼
10. testing/   (pytest red-team adapter + attack library + statistical threshold + CI gate)
        │
        ▼
11. controlplane/api: ApprovalRequest + kill switch  +  minimal read-only dashboard
        │
        ═══════════ PHASE 0 COMPLETE ═══════════
        ▼
P1: reconciliation loops · gateway PEP · Merkle DAG audit · trust propagation/chains ·
    full security engine (incl. sequence/embedding intent) · sandbox runtime · consensus ·
    economics/ABOM/lineage · graph DB (if needed)
        ▼
P2: K8s operator+sidecar (Envoy ext_authz) · self-play · ZK proofs · SPIFFE/mTLS · BFT · Rust hot path
```

**Why this order:**
- `contract/` first because it is the boundary the whole codebase and all three PEP forms depend on
  — getting it serializable-and-rich now avoids a P1 rewrite when the gateway arrives.
- Engines (3–5) before the pipeline (6) because stages are thin orchestrators over engines; building
  engines first lets each be unit-tested without the runner.
- Audit (7) before the SDK (8) so the very first end-to-end action already produces an `evidence_ref`
  — the audit chain is a success criterion, not a bolt-on.
- Red-team (10) last in P0 because it consumes the *finished* pipeline as a fixture — and it is the
  literal definition of Phase-0 done ("a failing safety test breaks CI").

> **Status:** this sequence was executed as Phase 1 (the walking skeleton) — steps 1–10 are
> implemented and merged. See `.planning/phases/01-walking-skeleton/` and `.planning/ROADMAP.md`.

### Phase-0 Minimal End-to-End Vertical Slice (the thing built first)

> **Goal:** one LangGraph agent, one tool, one Constitution principle, proven end to end. This is the
> walking skeleton; breadth (more detectors, more frameworks, dashboard polish) comes after it walks.

```
ONE LangGraph agent with ONE governed tool
  └─ SDK decorator intercepts the tool call
       └─ normalize → AgentAction
            └─ pipeline.evaluate:
                 1. identity: verify the agent's signed token (deny if forged)   ← real
                 2. policy:   OPA evaluates ONE compiled principle
                              (e.g. "never send email to external domains")      ← real
                 3. risk:     ONE prompt-injection heuristic → risk_score         ← real
                 4. graduated: thresholds → {allow | deny | require_approval}     ← real
            └─ Decision
       └─ audit: append ONE hash-chained AuditRecord (with policy_version)        ← real, verifiable
       └─ enforce: allow runs the tool; deny raises a governed exception w/ reasons
  └─ OTel span emitted (async)                                                    ← real
ONE pytest red-team test:
  asserts the agent denies a known prompt-injection attack;
  this test is wired into CI such that REMOVING the policy makes it FAIL the build.
```

**Acceptance = the documented Phase-0 success criterion verbatim:** a LangGraph agent's action is
intercepted → policy- and risk-checked → graduated-response-enforced → written to a verifiable
hash-chained audit log — **and a failing safety test breaks CI.**

### Where the pipeline contract MUST stay stable across PEP forms

The contract is the `AgentAction` schema + `evaluate(AgentAction) -> Decision`. It must not change
when the PEP changes form. Concretely, design for these now even though P0 only needs the SDK:

| Requirement | Why it must hold from P0 |
|-------------|--------------------------|
| `AgentAction` is fully **serializable** | P1 gateway and P2 sidecar call `evaluate` over the network; an in-process-only object would force a schema break. |
| `AgentAction` carries **rich in-process context** (tools, memory refs, `parent_action_id`) | The SDK shim has access the gateway/sidecar won't; capture it now so policies that need it keep working as PEPs get "thinner." Network PEPs degrade gracefully on fields they can't populate. |
| `Decision` is **transport-agnostic** (outcome + reasons + scores + `evidence_ref`) | Maps cleanly onto Envoy `ext_authz`'s allow/deny+headers response in P2 without redesign. |
| Enforcement semantics are **named, not numeric** (allow/warn/sandbox/...) | Each PEP realizes outcomes differently (SDK stubs side-effectful tools; sidecar enforces network isolation) but they agree on the vocabulary. |

---

## Scaling Considerations  *(research add)*

| Scale | Architecture adjustments |
|-------|--------------------------|
| Single team / 1–50 agents (P0) | Single-node control plane (API + Postgres + dashboard) + in-process SDK PEP. Compile-on-write. No K8s. Pipeline in-process — no network hop, cleanly inside the latency budget. |
| Org / 50–1k agents (P1) | Introduce reconciliation **loops** (drift + multi-node cache warming). Add the gateway PEP for non-Python/framework-agnostic agents. Move OPA to a sidecar (local-host calls, 1–3ms) if the pipeline is split out of process. Merkle DAG audit for efficient inclusion proofs. |
| Fleet / 1k+ agents (P2) | K8s operator + Envoy `ext_authz` sidecars as the true data plane. Horizontally scale the PDP behind the stable contract. Rust rewrite of `pipeline/runner.py` + policy stage where profiling justifies it (ADR-0001). |

### Scaling Priorities (what breaks first)

1. **First bottleneck — the audit hash chain (serial writes).** Because each record needs the
   previous hash, naive synchronous chaining serializes all decisions through one writer. Fix order:
   (a) per-agent or per-tenant chains so writers parallelize; (b) batch + a Postgres advisory lock
   per chain; (c) Merkle DAG (P1) which is built for parallel inclusion. Do *not* let the chain become
   the throughput ceiling for the whole control plane.
2. **Second bottleneck — cache invalidation correctness at multi-node.** Compile-on-write is fine on
   one node; at scale a policy write on node A must invalidate node B's decision cache (Hazelcast-style
   broadcast or a pub/sub channel). This is exactly why reconciliation **loops** are a P1 requirement,
   not a P0 nicety.
3. **Third — the LLM interpreter on the hot path.** If too many actions route to "ambiguous," interpreter
   latency dominates. Track the ambiguous-rate as an SLO; feed interpreter verdicts back as policy
   refinements so the deterministic core absorbs them and the ambiguous-rate trends down.

---

## Anti-Patterns  *(research add — the traps to avoid in build)*

### Anti-Pattern 1: Relying on OPA to cache decisions

**What people do:** Assume OPA memoizes and treat repeated identical queries as free; or try to keep
serving decisions from OPA during a control-plane outage.
**Why it's wrong:** OPA deliberately re-evaluates every query from scratch for consistency and has
**no cross-query decision cache**. You get neither the latency win nor outage resilience you expected.
**Do this instead:** Keep **prepared** Rego in memory (avoids per-request parse/compile) and put the
decision/identity/trust cache in agentos-guard's `controlplane/cache/`, keyed by
`(action signature, policy_version)` with reconciler-driven invalidation.

### Anti-Pattern 2: Hard-coding fail-open or fail-closed

**What people do:** Pick one global failure posture (usually fail-open so agents "keep working") and
bake it into the PEP.
**Why it's wrong:** Fail-open on a high-risk action class (e.g. external email, payments) turns a
control-plane blip into a governance bypass; fail-closed on a trivial read needlessly breaks agents.
**Do this instead:** Make **fail-safe vs fail-open a per-agent / per-action-class policy decision**
(documented posture). High-risk classes default fail-closed; low-risk classes may fail-open with a
logged warning. The PEP reads the posture from policy, it does not decide it. *(REQ PIPE-05.)*

### Anti-Pattern 3: Putting non-critical work on the synchronous hot path

**What people do:** Emit OTel, materialize the agent graph, recompute trend metrics, or run heavy
anomaly models inline for *every* action.
**Why it's wrong:** Each adds to the per-action latency budget that must stay in the low single-digit
ms; most of it does not gate the decision.
**Do this instead:** Only the four stages + the audit write that yields `evidence_ref` are synchronous.
OTel, graph, dashboards, and (most) ML run async. Heavy risk models run *only on flagged actions*.

### Anti-Pattern 4: Introducing a graph database in Phase 0

**What people do:** Reach for Neo4j/a graph DB on day one because the design talks about an "agent
graph" and "lineage."
**Why it's wrong:** In P0 the graph is small and fully derivable from relational rows
(`AgentAction.context.parent_action_id`, registered tools, delegation edges). A graph DB is premature
operational weight and a second source of truth.
**Do this instead:** **Materialize** the graph from Postgres relations. Introduce a real graph store
only in P1+ when query patterns (transitive permission sets for cross-agent conflict resolution, deep
lineage traversal) make relational recursion the bottleneck — let evidence, not anticipation, trigger
the switch.

### Anti-Pattern 5: Letting the gateway/sidecar leak into the pipeline

**What people do:** Add PEP-specific branches inside the Decision Pipeline ("if from gateway, do X").
**Why it's wrong:** It dissolves the one invariant that makes phases shippable independently and turns
every new PEP into a pipeline change — the opposite of the ext_authz decoupling that 2026 architectures
rely on.
**Do this instead:** Keep all PEP-specific logic in `dataplane/*`. The pipeline sees only `AgentAction`.
If a PEP can't populate a field, it sends a documented absent/default value and policies degrade
gracefully.

---

## Integration Points  *(research add)*

### External Services

| Service | Integration pattern | Notes / gotchas |
|---------|---------------------|-----------------|
| **OPA / Rego** | Library or local sidecar; **prepared queries**; agentos-guard owns the cache | No built-in decision cache; sidecar gives 1–3ms local-host calls; WASM compilation is an option for embedding but adds build complexity — start with library/sidecar. |
| **LangChain / LangGraph** | SDK decorators/middleware wrapping tool/memory/model/delegation boundaries | The P0 PEP. Per-framework adapters; coverage grows over time (ADR-0002 trade-off). |
| **LLM (semantic interpreter)** | Async-capable client called only on ambiguous policy results | Bound cost/latency by routing only the ambiguous minority; capture verdicts as proposed amendments. |
| **OpenTelemetry backend** | Emit spans/metrics; **integrate, don't replace** | `trace_id` from `AgentAction.context` correlates across the pipeline and across agents. Off the hot path. |
| **PostgreSQL** | Resources + append-only hash-chained audit table | Enforce append-only at the app layer (no UPDATE/DELETE on audit); recompute-and-compare verifier; consider external anchoring of periodic checkpoints so even a recomputed chain rewrite is detectable. |
| **Envoy / Istio (P2)** | `ext_authz` API; OPA-Envoy already implements it | The P2 sidecar PEP slots into the *same* `Decision` vocabulary — design `Decision` to map onto ext_authz allow/deny+headers now. |
| **SPIFFE/SVID (P2)** | Workload identity for zero-trust mTLS | Stage-1 identity upgrade path: signed tokens (P0) → certs (P1) → SPIFFE (P2), behind the same identity-stage interface. |

### Internal Boundaries

| Boundary | Communication | Considerations |
|----------|---------------|----------------|
| `dataplane/*` ↔ `pipeline/` | `PipelineProtocol.evaluate` (in-process P0; network P1+) | **The stable contract.** Treat changes as API breaks. |
| `pipeline/` stages ↔ `engines/*` | Direct in-process calls behind stage interfaces | Stages are thin; engines hold logic and are independently testable + the Rust-rewrite candidates. |
| `controlplane/api` ↔ `controlplane/reconcile` ↔ `cache` | Write triggers compile + cache invalidation | Compile-on-write (P0) → loops (P1+). Invalidation correctness is the multi-node scaling risk. |
| `engines/audit` ↔ everything that decides | Synchronous append returning `evidence_ref` | Only synchronous DB write on the hot path; per-chain partitioning is the throughput lever. |
| `testing/` ↔ `pipeline/` | Test fixture invoking the real pipeline | Red-team plane reuses the production pipeline; this is why a removed policy can fail CI. |

---

## Sources

- [Runtime Governance for AI Agents: Policies on Paths (arXiv, Mar 2026)](https://arxiv.org/pdf/2603.16586) — confirms control point immediately before sensitive tool calls; runtime authorization thesis. **HIGH**
- [Authorization and Governance for AI Agents: Runtime Authorization Beyond Identity (Microsoft, 2026)](https://techcommunity.microsoft.com/blog/microsoft-security-blog/authorization-and-governance-for-ai-agents-runtime-authorization-beyond-identity/4509161) — PEP/PDP "Authorization Fabric" pattern. **HIGH**
- [The case for Envoy networking in the agentic AI era (Google Cloud, 2026)](https://cloud.google.com/blog/products/networking/the-case-for-envoy-networking-in-the-agentic-ai-era) — ext_authz as the stable enforcement contract for agentic systems. **HIGH**
- [How to Integrate Istio with OPA for AuthZ (2026)](https://oneuptime.com/blog/post/2026-02-24-how-to-integrate-istio-with-open-policy-agent-opa-for-authz/view) — OPA-Envoy implements the ext_authz API with no custom code. **HIGH**
- [Deploying OPA as a sidecar (AWS Open Source Blog)](https://aws.amazon.com/blogs/opensource/deploying-open-policy-agent-opa-as-a-sidecar-on-amazon-elastic-container-service-amazon-ecs/) — 1–3ms local-host sidecar latency; in-memory policy/data. **HIGH**
- [Integrating OPA (official docs)](https://www.openpolicyagent.org/docs/integration) — prepared queries avoid per-request compile; **no cross-query decision cache**; WASM compilation option. **HIGH**
- [Improving XACML PDP Performance with Caching (WSO2)](https://is.docs.wso2.com/en/5.9.0/learn/improving-xacml-pdp-performance-with-caching-techniques/) — decision/policy/attribute cache layers + invalidation-on-policy-update; Hazelcast cross-node invalidation. **MEDIUM**
- [Cerbos PDP decision points](https://docs.cerbos.dev/cerbos-hub/decision-points.html) / [Permit.io PDP overview](https://docs.permit.io/concepts/pdp/overview/) — co-located PDP for sub-ms decisions; PEP-side caching. **MEDIUM**
- [Tamper-evident audit trails in PostgreSQL with hash chaining (AppMaster)](https://appmaster.io/blog/tamper-evident-audit-trails-postgresql) and [immutable audit log with HMAC hash chaining (Tracehold)](https://tracehold.ai/blog/immutable-audit-log-hmac-hash-chain/) — append-only ≠ tamper-evident; advisory lock for serial chaining; recompute-to-verify; external anchoring. **MEDIUM**

---
*Architecture **validation** research for agentos-guard — authoritative design lives in [`docs/architecture/`](../../docs/architecture/).*
*Researched: 2026-06-01 · trimmed to validation + pointers 2026-06-05*
