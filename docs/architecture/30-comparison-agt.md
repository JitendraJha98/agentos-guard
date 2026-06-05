# 30 — Comparison: agentos-guard vs Microsoft AGT / RAMPART

agentos-guard is directly inspired by Microsoft's **Agent Governance Toolkit (AGT)** and
**RAMPART** — and aims to surpass them. AGT/RAMPART combine runtime policy enforcement,
zero-trust identity, sandboxed execution, and tamper-evident audit with a red-teaming layer.
We keep all of that and change the *model*. This doc is the head-to-head scorecard; the
paradigm behind it is in [`00-manifesto.md`](00-manifesto.md).

## AGT in one diagram

```
Agent Call → Policy Engine (Rego/Cedar) → Binary Allow/Deny → Audit Log (append-only)
                  ↓                              ↓
             Static YAML rules            Tamper-evident JSON (host-rewritable)
```

The policy engine is OPA/Cedar behind a thin wrapper. The "intelligence" is string matching and
attribute comparison against static YAML — no reasoning, no intent understanding, no adaptation,
and the engine shares the agent's process.

## The weakness → counter scorecard

Eight structural weaknesses in AGT's model, each mapped to the agentos-guard counter, the doc
that delivers it, and the build phase. Pillars 1–7 are the [manifesto](00-manifesto.md) pillars.

| # | AGT weakness | Why it matters | agentos-guard counter | Where | Phase |
|---|--------------|----------------|------------------------|-------|-------|
| 1 | **Static policy** frozen at deploy | An agent can't query *why* a rule exists or how to comply | **Living semantic constitution** — human-readable principles, deterministic compiled core, queryable rationale (pillar 1) | [`04`](04-constitution-and-policy.md) | P0 |
| 2 | **Binary enforcement** | Complex workflows either pass or crash; no middle ground | **Graduated response** — allow · warn · sandbox · consensus · approval · deny (pillar 2) | [`04`](04-constitution-and-policy.md) | P0 |
| 3 | **No semantic understanding** | `action.type in [...]` is grep; intent is invisible | **Intent-based policy** — classifies intent, catches `rename_then_drop` & novel sequences (pillar 3) | [`05`](05-security-and-runtime.md) | P0→P1 |
| 4 | **Single-process boundary** | Compromised agent = compromised governance | **PEP process boundary** behind one `evaluate()` contract; SDK → gateway → K8s sidecar | [`03`](03-interception-and-pipeline.md) | P0→P2 |
| 5 | **No composed-risk view** | Per-agent rules miss the confused-deputy / delegation chain | **Cross-agent permission calculus** — transitive permissions, emergent-capability flagging (pillar 4) | [`06`](06-identity-trust-discovery.md) | P1→P2 |
| 6 | **Opaque denials** | `GovernanceDenied: rule X` gives no path forward | **Explainable denials with remediation** — cited principle, evidence, next steps on the `Decision` (pillar 5) | [`02`](02-domain-model.md) · [`04`](04-constitution-and-policy.md) | P0 |
| 7 | **Offline red-team** | Novel prod attacks hit the same static rules until re-scanned | **CI-gating pytest red-team** + Phase-2 **self-play** (pillar 6) | [`08`](08-testing-and-redteam.md) | P0→P2 |
| 8 | **Audit without proof** | Host owner can rewrite logs and recompute hashes | **Provable evidence** — policy-version provenance, CI verifier + anchoring, Phase-2 **ZK proofs** (pillar 7) | [`07`](07-audit-and-compliance.md) | P0→P2 |

## The one-sentence pitch

> AGT says *"rule X blocked action Y."*
> agentos-guard says *"here is our constitution, here is why this action violates principle
> 3.2, here is the intent we inferred, here are three graduated responses you can choose, and
> here is provable evidence the whole process was compliant."*

Governance as a **collaborative, evolving system** rather than a static firewall.

## Honest positioning

We say plainly where we are, because a technical reader will check `git log`.

- **What AGT does well, and we adopt:** declarative policy, zero-trust identity, sandboxing,
  tamper-evident audit, a red-team layer. We extend these — we are not reinventing them.
- **Where we already out-feature AGT (shipped):** the Phase-1 walking skeleton runs a real
  graduated-response pipeline, semantic-constitution-backed policy (one principle, end to end),
  and a red-team test that **breaks CI** if the principle is removed — three things AGT's
  binary/static/offline model structurally cannot do.
- **Where it's parity, honestly:** AGT is mature in breadth of detectors, framework adapters,
  and compliance mappings; that breadth is what Phases 2–8 build. Phase 0 (roadmap Phases 1–6)
  reaches parity on AGT's turf; the pillars pull ahead from there.
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
compliance mappings. The paradigm only compounds with contributors.
