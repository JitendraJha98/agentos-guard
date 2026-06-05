# ADR 0007 — No crypto-economics in core; keep only token-free cryptography

- **Status:** Accepted
- **Date:** 2026-06-05

## Context

The competitive "AEGIS" framing that motivated several differentiators also proposed a
crypto-economic apparatus: blockchain/Ethereum anchoring of the audit root, token staking
(USDC/ETH/project token) with on-chain slashing, multi-party computation (MPC) for sensitive
workflows, and threshold-signature attestations. These are attention-grabbing, but they target
the wrong buyer. agentos-guard's audience is the same as AGT's — enterprise platform, security,
and governance teams. For that audience a *mandatory* blockchain, token, or on-chain settlement
dependency is a procurement and security **disqualifier**, not a feature. The genuinely
paradigm-shifting differentiators (semantic constitution, graduated response, intent-based
policy, cross-agent permission calculus, explainable remediation, CI-gating red-team, provable
audit) require none of that machinery.

## Decision

Crypto-economic features are **out of the core product**:

- **Non-goals (core):** blockchain / on-chain anchoring, token staking and slashing settlement,
  and multi-party computation. "Stake-based accountability" survives in the vision only as a
  **deployment-optional, pluggable reputation backend** — never required to run the control
  plane.
- **Kept (token-free cryptography only):** Merkle DAG anchoring (Phase 1, optional) and
  zero-knowledge compliance proofs (Phase 2, hard-gated research). These prove integrity and
  compliance *without disclosure* and carry no token economy or chain dependency.

The default audit-integrity story stays a hash chain → Merkle DAG → external anchoring/signing
of checkpoints (a notary or transparency log, not a blockchain) + an independent CI verifier.

## Consequences

- (+) Keeps the core adoptable by the enterprise audience we actually target; no chain/token in
  the critical path.
- (+) Sharpens positioning: we win on *semantic reasoning and provable governance*, not
  tokenomics ([`../00-manifesto.md`](../00-manifesto.md#deliberately-out-of-core)).
- (+) Preserves the strongest cryptographic differentiator (ZK "prove without disclose") without
  its weakest baggage.
- (−) Forgoes the "skin-in-the-game" narrative some find compelling; revisit only on concrete
  user pull, and then only as an optional backend.
- Fencing table and phase placement: [`../20-roadmap.md`](../20-roadmap.md#deliberately-deferred--out-of-core).
