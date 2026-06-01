# 30 — Comparison: agentos-guard vs Microsoft AGT / RAMPART

agentos-guard is directly inspired by Microsoft's **Agent Governance Toolkit (AGT)** and
**RAMPART** — and aims to surpass them. AGT/RAMPART combine runtime policy enforcement,
zero-trust identity, sandboxed execution, and tamper-evident audit with a red-teaming layer.
agentos-guard keeps all of that and changes the *model* in five dimensions.

## The differentiation table

| Dimension | AGT / RAMPART | agentos-guard | Where |
|-----------|---------------|---------------|-------|
| **Policy model** | Static YAML rules | A **living semantic constitution** agents can query and propose amendments to | [`04`](04-constitution-and-policy.md) |
| **Enforcement** | Allow / deny binary | **Graduated** response: warn → sandbox → consensus → human escalation → deny | [`04`](04-constitution-and-policy.md) |
| **Testing** | Pre-deployment red team | **Continuous adversarial self-play**, pytest-native, breaks the CI build | [`08`](08-testing-and-redteam.md) |
| **Audit** | Tamper-evident logs | **Zero-knowledge compliance proofs** — prove compliance without revealing context | [`07`](07-audit-and-compliance.md) |
| **Identity** | SPIFFE / mTLS | **Decentralized reputation** with stake-based accountability | [`06`](06-identity-trust-discovery.md) |

## The one-sentence pitch

> AGT says *"rule X blocks action Y."* agentos-guard says *"here is our constitution, here is
> why this action violates principle 3.2, here are three graduated responses you can choose,
> and here is a zero-knowledge proof that the whole process was compliant."*

Governance as a **collaborative, evolving system** rather than a static firewall.

## Honest positioning

- **What AGT does well that we adopt:** declarative policy, zero-trust identity, sandboxing,
  tamper-evident audit, a red-team layer. We are not reinventing these — we are extending them.
- **Where we are riskier:** the moonshot features (ZK proofs, BFT consensus, staking, self-play)
  are research-grade and live in Phase 2. We explicitly do **not** gate the MVP on them — see
  [`20-roadmap.md`](20-roadmap.md). Phase 0 competes with AGT on its own turf (policy +
  graduated response + identity + audit + pytest-native red-team) before we reach for the
  differentiators.
- **Why open-source matters:** like AGT's multi-language SDK approach, an open, self-hostable
  control plane lowers adoption friction and lets the community extend detectors, framework
  adapters, and compliance mappings.
