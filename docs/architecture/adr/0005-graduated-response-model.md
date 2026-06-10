# ADR 0005 — Graduated response instead of binary allow/deny

- **Status:** Accepted
- **Date:** 2026-06-01

## Context

AGT/RAMPART and most policy engines return a binary allow/deny. Real governance needs softer
options: an action may be acceptable if observed, sandboxed, peer-confirmed, or human-approved.
A binary model forces a false choice between blocking useful work and permitting risk.

> **Note (2026-06-10):** the context above is stale on one fact — AGT now returns
> allow / deny / require_approval, not a binary. The decision stands unchanged: an
> eight-outcome spectrum with composable side-effects remains well beyond AGT's three-outcome
> ceiling. Current comparison: [`../30-comparison-agt.md`](../30-comparison-agt.md).

## Decision

The Decision Pipeline's terminal stage produces a **graduated outcome** on the spectrum
`allow → warn → sandbox → require_consensus → require_approval → temporary_exception →
governance_review → deny`. The mapping from `{policy result, risk score, trust score}` to
outcome is itself **policy-driven** (configurable thresholds), not hard-coded.

`outcome` is the single *gating* verdict. Orthogonal to it, a `Decision` may carry any subset of
composable **side-effects** — `notify`, `additional_monitoring`, `risk_flag`, `create_incident`
— that ride alongside any outcome. This keeps the gating spectrum small while still expressing
"allow but watch closely" or "deny and open an incident".

Two of the outcomes are deliberately constrained:
- **`temporary_exception`** is a **human-ratified, time-boxed `allow`** (carries `expires_at`).
  The semantic interpreter may *recommend* one but can **never grant** it — an LLM must never
  relax a deterministic policy denial (anti-prompt-injection invariant; see POL-05).
- **`governance_review`** lets the action proceed while opening an **asynchronous, non-blocking**
  review — distinct from `require_approval`, which blocks the action.

## Consequences

- (+) A primary differentiator over AGT; lets teams tune strictness per agent class.
- (+) Enables human-in-the-loop and (Phase 1) multi-agent consensus as first-class outcomes.
- (−) More outcomes than allow/deny means each PEP must implement `enforce()` for every outcome
  (e.g. sandbox semantics vary by PEP form — see [`0002`](0002-sdk-interception-first.md)).
- (−) Threshold tuning is a new operational surface; defaults must be sensible and documented.
- (+) Side-effects keep the gating spectrum small and orthogonal — escalation (monitor / incident)
  composes onto any verdict instead of multiplying outcome variants.
- (−) `temporary_exception` adds an expiry/auto-revoke lifecycle the control plane must enforce;
  `governance_review` adds an async review queue distinct from the blocking approval queue.
- Detail: [`../04-constitution-and-policy.md`](../04-constitution-and-policy.md).
