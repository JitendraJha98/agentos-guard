# 00 — Manifesto: Why agentos-guard Beats AGT

> Read this first. It is the thesis the rest of the architecture serves.

## The paradigm

Microsoft's **Agent Governance Toolkit (AGT)** — and tools like it — govern agents with one
reflex:

> **Distrust → Block → Log.**
>
> A static rule fires, the action is allowed or denied, an append-only line is written.

That model is a *firewall* bolted in front of a reasoning system. It treats every agent as a
hostile string of bytes and every decision as a binary. It cannot explain itself, cannot bend
without breaking, cannot see intent behind a novel action sequence, and cannot *prove* its log
wasn't rewritten by whoever owns the host.

agentos-guard runs a different reflex:

> **Trust → Verify → Graduate → Prove.**
>
> Establish *who* is acting and *how much* they've earned trust. Verify the action against a
> living, human-readable **constitution** — reasoning about **intent**, not just matching
> strings. Return a **graduated** response across a spectrum, not a coin flip. And make the
> resulting evidence **provable**, not merely append-only.

Governance becomes a collaborative, evolving control system instead of a static wall. That is
the whole game.

## The seven pillars

Each pillar names an AGT weakness and the agentos-guard answer. None of the seven requires
blockchain, tokens, or any crypto-economic apparatus — see **[Deliberately out of core](#deliberately-out-of-core)**.

| # | AGT does | agentos-guard does | Lives in |
|---|----------|--------------------|----------|
| 1 | **Static YAML rules** frozen at deploy | A **living semantic constitution** agents query, that compiles to deterministic policy and reasons about novel cases | [`04`](04-constitution-and-policy.md) |
| 2 | **Binary allow/deny** | **Graduated response** — allow · warn · sandbox · consensus · approval · deny — tuned by risk + trust | [`04`](04-constitution-and-policy.md) · [ADR-0005](adr/0005-graduated-response-model.md) |
| 3 | **Action-string matching** (`action.type == 'drop_table'`) | **Intent-based policy** — catches `rename_then_drop`, copy-then-delete, and novel sequences that reach the same outcome | [`05`](05-security-and-runtime.md) |
| 4 | **Per-agent isolated policy** | **Cross-agent permission calculus** — computes transitive permissions across delegation and catches the confused-deputy problem static rules miss | [`06`](06-identity-trust-discovery.md) · [`04`](04-constitution-and-policy.md) |
| 5 | **`GovernanceDenied: rule X`** | **Explainable denials with remediation paths** — cited principle, evidence, and concrete next steps as a first-class `Decision` output | [`02`](02-domain-model.md) · [`04`](04-constitution-and-policy.md) |
| 6 | **Offline, pre-deploy red team** | **Continuous, pytest-native red-team that gates CI** — a safety regression breaks the build like a failing unit test; self-play keeps probing in prod | [`08`](08-testing-and-redteam.md) |
| 7 | **Append-only "tamper-evident" logs** | **Prove, don't just log** — policy-version provenance on every record now, Merkle inclusion proofs next, zero-knowledge compliance proofs later | [`07`](07-audit-and-compliance.md) |

## The one-sentence pitch

> AGT says *"rule X blocked action Y."*
> agentos-guard says *"here is our constitution, here is why this action violates principle
> 3.2, here is the intent we inferred, here are three graduated responses you can choose, and
> here is provable evidence the whole process was compliant."*

## Honest positioning (confident, not inflated)

We are inspired by AGT/RAMPART and we intend to surpass them — but we say plainly where we are
on that journey, because a technical reader will check.

- **What AGT does well, and we keep:** declarative policy, zero-trust identity, sandboxing,
  tamper-evident audit, a red-team layer. We extend these; we do not pretend they're worthless.
- **Where we already out-feature AGT today:** even Phase 1 (the shipped
  [walking skeleton](20-roadmap.md)) runs a real **graduated-response** pipeline with
  **semantic-constitution** policy and a **CI-gating red-team** test — three things AGT's
  binary/static/offline model structurally cannot do.
- **What is parity, honestly:** the breadth of detectors, framework adapters, and compliance
  mappings is where AGT is mature and we are building. Phase 0 (roadmap Phases 1–6) reaches
  parity on AGT's own turf; the pillars are what pull ahead.
- **What is research, and stays fenced:** the moonshot layer (ZK proofs, BFT consensus,
  self-play patching, decentralized stake) is hard-gated in Phase 2 and **never** gates the
  MVP. The seven pillars beat AGT *without* it.

## Deliberately out of core

The original "AEGIS" framing reached for a crypto-economic apparatus — **blockchain/Ethereum
anchoring, USDC/ETH token staking, multi-party computation, threshold signatures**. We
**deliberately keep these out of the core**, because the enterprise security and platform teams
who are AGT's actual audience treat a mandatory blockchain or token dependency as a
*disqualifier*, not a feature.

- **Merkle anchoring + zero-knowledge proofs** survive as *optional, hard-gated Phase 2*
  research — they are the defensible cryptography (provable compliance without disclosure) and
  carry no token economy. See [`07`](07-audit-and-compliance.md) and
  [ADR-0007](adr/0007-no-crypto-economics-in-core.md).
- **Token staking, on-chain settlement, and MPC** are **explicit non-goals** of the core
  product. "Stake-based accountability" remains in the vision only as a pluggable,
  deployment-optional reputation backend — never a requirement to run the control plane.

Why this matters: our differentiation is *semantic reasoning and graduated, provable
governance*, not financialized trust. We win on intelligence, not on tokenomics.

## How to read on

Continue to [`01-overview.md`](01-overview.md) for the problem and the control-plane model,
then the numbered specs. Every numbered doc opens by naming the **AGT weakness it kills**. The
head-to-head scorecard lives in [`30-comparison-agt.md`](30-comparison-agt.md); the build
sequence in [`20-roadmap.md`](20-roadmap.md).
