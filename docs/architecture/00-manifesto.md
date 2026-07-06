# 00 — Manifesto: Why agentos-guard Beats AGT

> Read this first. It is the thesis the rest of the architecture serves.

## The paradigm

Microsoft's **Agent Governance Toolkit (AGT)** — and tools like it — govern agents with one
reflex:

> **Distrust → Block → Log.**
>
> A deterministic rule fires, the action is allowed, denied, or routed to a human, and a line
> is written.

That model is a *firewall* bolted in front of a reasoning system. By its own documentation it
governs "actions, not reasoning": it cannot explain *why* a rule exists, cannot see the intent
behind a multi-step action sequence (two individually-allowed actions compose into one attack),
does not govern the memory and knowledge the agent reasons over, and logs raw, unredacted
parameters. (AGT's current, verified feature set — it is *not* binary allow/deny anymore — is
kept honest in [`30-comparison-agt.md`](30-comparison-agt.md), re-verified each phase.)

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
| 2 | **Three-outcome ceiling** (allow / deny / require_approval) | **Graduated response** — allow · warn · sandbox · consensus · approval · time-boxed exception · async review · deny, plus composable side-effects (notify · monitor · risk-flag · open-incident) — tuned by risk + trust | [`04`](04-constitution-and-policy.md) · [ADR-0005](adr/0005-graduated-response-model.md) |
| 3 | **Per-action, stateless evaluation** — no cross-action correlation | **Intent-based policy** — catches `rename_then_drop`, copy-then-delete, and novel sequences that reach the same outcome | [`05`](05-security-and-runtime.md) |
| 4 | **Per-agent isolated policy** | **Cross-agent permission calculus** — computes transitive permissions across delegation and catches the confused-deputy problem static rules miss | [`06`](06-identity-trust-discovery.md) · [`04`](04-constitution-and-policy.md) |
| 5 | **`GovernanceDenied: rule X`** | **Explainable denials with remediation paths** — cited principle, evidence, and concrete next steps as a first-class `Decision` output | [`02`](02-domain-model.md) · [`04`](04-constitution-and-policy.md) |
| 6 | **Offline, pre-deploy red team** | **Continuous, pytest-native red-team that gates CI** — a safety regression breaks the build like a failing unit test; self-play keeps probing in prod | [`08`](08-testing-and-redteam.md) |
| 7 | **Raw, unredacted audit of attempts, not outcomes** (Merkle-chained, but parameters stored verbatim) | **Prove, don't just leak** — fail-closed PII redaction *before* hashing, policy-version provenance on every record now, Merkle inclusion proofs next, zero-knowledge compliance proofs later | [`07`](07-audit-and-compliance.md) |

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
- **Where we already out-feature AGT today (AGT facts verified 2026-06-10; our shipped list
  as of 2026-07-03, roadmap Phases 1–5 merged):** memory-access interception (AGT's own
  LIMITATIONS.md calls this its "knowledge governance gap"), **fail-closed redacted audit
  with per-record signatures + RFC-3161 anchoring** (AGT logs raw parameters),
  **deny-by-default** with coverage verification (AGT defaults to allow), a **CI-gating
  red-team** test — a safety regression breaks the build, which AGT's CLI-scan model does
  not do — the **full graduated spectrum** (eight outcomes + composable side-effects vs
  their three), the **semantic constitution with cited-principle rationale**, and
  **sequence-intent correlation** (the `rename_then_drop` catch their stateless kernel
  cannot retrofit).
- **What is parity, honestly:** the breadth of detectors, framework adapters, and compliance
  mappings is where AGT is mature and we are building. Phase 0 (roadmap Phases 1–6) reaches parity on AGT's own turf; the pillars
  are what pull ahead. The durable pillars — the ones AGT's deterministic-only philosophy and
  stateless kernel make structurally hard to copy — are the **semantic constitution** (pillar 1)
  and **cross-action intent correlation** (pillar 3); they are front-loaded in the roadmap for
  exactly that reason.
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
