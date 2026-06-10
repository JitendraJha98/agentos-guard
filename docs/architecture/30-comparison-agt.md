# 30 — Comparison: agentos-guard vs Microsoft AGT / RAMPART

agentos-guard is directly inspired by Microsoft's **Agent Governance Toolkit (AGT)** and
**RAMPART** — and aims to beat them where it matters. AGT/RAMPART combine runtime policy
enforcement, zero-trust identity, sandboxed execution, and tamper-evident audit with a
red-teaming layer. We keep all of that and change the *model*. This doc is the head-to-head
scorecard; the paradigm behind it is in [`00-manifesto.md`](00-manifesto.md).

> **Verification discipline:** AGT ships monthly (v3.2.0 → v4.1.0 between Apr and Jun 2026).
> This scorecard was **re-verified against the live repo, docs site, and `LIMITATIONS.md` on
> 2026-06-10 (AGT v4.1.0)**. Re-verify AGT's feature set at the start of every roadmap phase
> before citing any claim here; competitive facts older than one phase are presumed stale.

## AGT as shipped (v4.1.0, verified 2026-06-10)

```
Agent Call → Policy Engine (YAML/CEL · OPA/Rego · Cedar) → allow / deny / require_approval
                  ↓                                              ↓
        Deterministic rules only                      Merkle-chained audit log
        (no semantic layer)                           (raw, unredacted parameters)
```

What AGT genuinely has — do not understate it:

- **Graduated-ish decisions**: `allow` / `deny` / `require_approval` with quorum approval
  routing, plus privilege "execution rings" 0–3. Not binary — but a 3-outcome spectrum, not ours.
- **Merkle-chain tamper-evident audit**, CloudEvents envelope, decision provenance ("Decision BOMs").
- **Dynamic trust scoring** (0–1000, behavioral decay) consumed by enforcement.
- **Strong identity**: Ed25519 / SPIFFE / DID, mTLS, delegation chains with trust-ceiling
  propagation, Entra JWT verification.
- **MCP Security Gateway**: tool-poisoning detection, typosquatting prevention,
  hidden-instruction scanning, drift monitoring.
- **Breadth**: 5 language SDKs (Python/TS/.NET/Rust/Go), 19+ framework integrations,
  ~9,500 tests, RFC-2119 conformance specs, MIT, zero cloud dependencies in core.

What AGT **does not** have — by its own `LIMITATIONS.md` ("Transparency is a feature") and
verified inspection:

1. **No semantic layer.** Enforcement is purely deterministic (CEL/Rego/Cedar + regex content
   policies). Their docs: AGT governs *"actions, not reasoning"* and is unreliable against
   indirect prompt injection. There is **no LLM interpreter, no constitution, no cited-principle
   rationale**.
2. **No cross-action correlation.** Evaluation is per-action and stateless (a deliberate
   scaling choice). AGT *"does not correlate individually allowed actions into a malicious
   workflow"* — `rename_then_drop` sails through as two allowed actions.
3. **Knowledge/memory governance gap** (their words): it does not govern "the documents,
   databases, embeddings, and context retrieved during reasoning." No memory read/write
   interception.
4. **Raw, unredacted audit.** Audit logs store tool-call parameters verbatim — publicly
   criticized as a data-leak pathway. No redaction layer.
5. **Default-allow posture.** Their own docs warn agents "can appear 'governed' in dashboards
   while policies aren't actually loaded."
6. **Audit records attempts, not outcomes**, and the red-team story is a light CLI scan — no
   garak/PyRIT, nothing that gates CI.

## Durable vs incidental gaps — plan around the durable ones

AGT's velocity means some of these gaps **will close**. Sort them before betting a phase on one:

| Gap in AGT | Durability | Why |
|------------|-----------|-----|
| No semantic constitution / LLM interpreter | **Durable** | Philosophically opposed: AGT's core pitch is "deterministic only; prompt-level safety is not a control surface." Adding an LLM judge contradicts their positioning. |
| No cross-action / sequence intent correlation | **Durable** | Their stateless-kernel architecture (horizontal scaling) makes stateful sequence correlation structurally hard to retrofit. |
| No amendable constitution, no `require_consensus`, no ZK proofs | **Durable** | Not on their published roadmap; different product philosophy. |
| Unredacted audit parameters | *Incidental* | A Presidio-style redactor is a sprint for that team. Claim it now, expect parity later. |
| Memory governance gap | *Incidental–medium* | Basic memory hooks are easy; *semantic* memory-poisoning governance is harder and leans on our durable strengths. |
| No CI-gating red-team / garak / PyRIT | *Incidental* | Tooling integration, not architecture. Our durable edge is the pytest-native DX framing, not the capability. |

**Build order follows from this:** front-load the durable gaps (semantic constitution,
sequence-intent correlation — pulled forward to roadmap Phase 3), claim the incidental gaps
loudly while they last, and do **not** spend early phases chasing AGT parity features it
already does well (privilege rings, SPIFFE/mTLS, multi-language SDKs, budget governance —
all deliberately late in our roadmap).

## The weakness → counter scorecard

Each AGT weakness mapped to the agentos-guard counter, the doc that delivers it, and the build
phase. Pillars 1–7 are the [manifesto](00-manifesto.md) pillars. Status reflects the 2026-06-10
verification.

| # | AGT weakness (verified) | Why it matters | agentos-guard counter | Where | Phase |
|---|--------------|----------------|------------------------|-------|-------|
| 1 | **No semantic layer** — deterministic rules only; governs "actions, not reasoning" | An agent can't query *why* a rule exists; novel-but-compliant work gets blocked, novel-and-hostile work gets through | **Living semantic constitution** — human-readable principles, deterministic compiled core (the floor), advisory LLM interpreter with cited-principle rationale (pillar 1) | [`04`](04-constitution-and-policy.md) | P0 |
| 2 | **3-outcome ceiling** — allow/deny/require_approval | Complex workflows need more shades: sandboxing, consensus, time-boxed exceptions, async review | **Full graduated spectrum** — allow · warn · sandbox · consensus · approval · time-boxed exception · async review · deny, + composable side-effects (pillar 2) | [`04`](04-constitution-and-policy.md) | P0 |
| 3 | **No cross-action correlation** — per-action, stateless; their critics' #1 complaint | `rename_then_drop` is two individually-allowed actions; intent is invisible | **Intent-based policy** — single-action intent tags + sequence/lineage analysis over `parent_action_id` chains (pillar 3) | [`05`](05-security-and-runtime.md) | P0 (tags + sequence analysis, roadmap Phase 3) |
| 4 | **Single-process boundary** — middleware shares the agent's process (their own limitation #12) | Compromised agent = compromised governance | **PEP process boundary** behind one `evaluate()` contract; SDK → gateway → K8s sidecar | [`03`](03-interception-and-pipeline.md) | P0→P2 |
| 5 | **Memory/knowledge governance gap** — admitted in their LIMITATIONS.md | Poisoned memory and retrieved context steer agents invisibly | **Memory interception (shipped Phase 2)** + memory/context-poisoning detector (ASI06) | [`03`](03-interception-and-pipeline.md) · [`05`](05-security-and-runtime.md) | P0 (interception) → P1 (detector) |
| 6 | **Opaque denials** | `GovernanceDenied: rule X` gives no path forward | **Explainable denials with remediation** — cited principle, evidence, next steps on the `Decision` (pillar 5) | [`02`](02-domain-model.md) · [`04`](04-constitution-and-policy.md) | P0 |
| 7 | **Red-team is a CLI scan; nothing gates CI** | Novel prod attacks hit the same static rules until someone re-scans | **CI-gating pytest red-team** (shipped: removing a principle breaks the build) + Phase-2 **self-play** (pillar 6) | [`08`](08-testing-and-redteam.md) | P0→P2 |
| 8 | **Raw unredacted audit; attempts not outcomes; default-allow** | Audit log becomes a leak pathway; "governed" dashboards over unloaded policies | **Provable evidence** — fail-closed Presidio redaction *before* hashing (shipped), deny-by-default, policy-version provenance, CI verifier + anchoring, Phase-2 **ZK proofs** (pillar 7) | [`07`](07-audit-and-compliance.md) | P0→P2 |

## Positioning: the layer they admit they lack

Head-on, AGT wins on breadth (languages, frameworks, test count, brand). So we do not lead
with "a better AGT." We lead with:

> **agentos-guard is the semantic-judgment and memory-governance layer that deterministic
> enforcers — by their own documentation — do not provide.**

AGT's own docs recommend layering model-safety tools *above* it. That slot is ours: the
constitution, the intent correlation, the memory governance, the redacted provable audit.
Concretely:

- The deterministic OPA floor means we are credible *as* an enforcer too — this is layering
  from strength, not weakness.
- An **AGT adapter** (AGT as one PEP form behind our `evaluate()` contract) is a legitimate
  Phase-1+ option: govern *through* their enforcement footprint while owning the judgment
  layer. Track it alongside the gateway PEP (roadmap Phase 10).
- Full-replacement positioning stays available later, once framework breadth (Phase 10) and
  containment (Phase 9) land.

## The one-sentence pitch

> AGT says *"rule X blocked action Y."*
> agentos-guard says *"here is our constitution, here is why this action violates principle
> 3.2, here is the intent we inferred — including the multi-step intent no single action
> revealed — here are the graduated responses available, and here is provable, redacted
> evidence the whole process was compliant."*

Governance as a **collaborative, evolving system** rather than a static firewall.

## Honest positioning

We say plainly where we are, because a technical reader will check `git log` — and AGT's repo.

- **What AGT does well, and we adopt:** declarative policy, zero-trust identity, sandboxing,
  tamper-evident audit, a red-team layer. We extend these — we are not reinventing them.
- **Where we are ahead today (shipped):** memory-access interception (their admitted gap),
  fail-closed redacted audit (they store raw parameters), deny-by-default with coverage
  verification (they default-allow), and a red-team test that **breaks CI** if a principle is
  removed.
- **Where we are behind today, honestly:** framework breadth (1 vs 19+), language SDKs (1 vs 5),
  identity strength (signed JWTs vs SPIFFE/mTLS/DID), audit structure (hash chain vs Merkle),
  sandboxing and MCP gateway (theirs ship now; ours are Phases 8–9), and sheer test/conformance
  volume. Until roadmap Phase 3 lands, their three shipped outcomes also exceed our shipped
  three (theirs include approval). These are *deliberate* sequencing choices — parity features
  are late because they are not the wedge — but they are real gaps at evaluation time.
- **Where we are riskier:** the moonshot features (ZK proofs, BFT consensus, self-play
  patching, decentralized reputation) are research-grade, live in Phase 2, and are
  **hard-gated** on the P0/P1 substrate passing verification. We do **not** gate the MVP on
  them — see [`20-roadmap.md`](20-roadmap.md).

## What we deliberately did *not* copy from "AEGIS"

The maximalist counter-pitch reached for a crypto-economic stack — blockchain anchoring,
USDC/ETH token staking, multi-party computation, threshold signatures. We **keep these out of
core** because AGT's actual enterprise audience treats a mandatory blockchain/token dependency
as a disqualifier. Only the defensible, token-free cryptography (Merkle anchoring, ZK proofs)
survives as optional Phase-2 research. See [`00-manifesto.md`](00-manifesto.md#deliberately-out-of-core)
and [ADR-0007](adr/0007-no-crypto-economics-in-core.md). **We win on semantic reasoning and
graduated, provable governance — not on tokenomics.**

## Why open-source matters

Like AGT's multi-language SDK approach, an open, self-hostable control plane lowers adoption
friction and lets the community extend detectors, framework adapters, intent classes, and
compliance mappings. Adoption also depends on **first-run friction**: AGT's pitch is one
decorator with zero cloud dependencies, so we match it with a zero-infra quickstart
(SQLite + in-process opa-wasm, single `pip install`, no Docker/Postgres/OPA server — roadmap
Phase 5) and a five-minute wedge demo (constitution denies a `rename_then_drop` sequence with
a cited principle — roadmap Phase 3). The paradigm only compounds with contributors.
