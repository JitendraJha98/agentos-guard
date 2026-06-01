# ADR 0005 — Graduated response instead of binary allow/deny

- **Status:** Accepted
- **Date:** 2026-06-01

## Context

AGT/RAMPART and most policy engines return a binary allow/deny. Real governance needs softer
options: an action may be acceptable if observed, sandboxed, peer-confirmed, or human-approved.
A binary model forces a false choice between blocking useful work and permitting risk.

## Decision

The Decision Pipeline's terminal stage produces a **graduated outcome** on the spectrum
`allow → warn → sandbox → require_consensus → require_approval → deny`. The mapping from
`{policy result, risk score, trust score}` to outcome is itself **policy-driven** (configurable
thresholds), not hard-coded.

## Consequences

- (+) A primary differentiator over AGT; lets teams tune strictness per agent class.
- (+) Enables human-in-the-loop and (Phase 1) multi-agent consensus as first-class outcomes.
- (−) More outcomes than allow/deny means each PEP must implement `enforce()` for every outcome
  (e.g. sandbox semantics vary by PEP form — see [`0002`](0002-sdk-interception-first.md)).
- (−) Threshold tuning is a new operational surface; defaults must be sensible and documented.
- Detail: [`../04-constitution-and-policy.md`](../04-constitution-and-policy.md).
