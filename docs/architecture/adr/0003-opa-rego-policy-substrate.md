# ADR 0003 — Layered Constitution → YAML → OPA/Rego policy substrate

- **Status:** Accepted
- **Date:** 2026-06-01

## Context

The spec mentioned YAML, OPA, and Cedar, plus a human-readable "semantic constitution" as a
killer feature. We need a substrate that is (a) human-authorable and auditable, (b)
deterministic and fast at runtime, and (c) able to handle ambiguity without hard-coding.

## Decision

Adopt a **three-layer stack**: human-readable **Constitution** → compiled **YAML** policies →
**OPA/Rego** for deterministic runtime evaluation, with an **LLM semantic interpreter** for
ambiguous or rule-absent cases. OPA is chosen over Cedar for its CNCF-graduated maturity,
ecosystem, and fit with the Kubernetes-for-agents positioning.

## Consequences

- (+) Non-engineers read/own the Constitution; engineers review compiled YAML; the hot path
  runs battle-tested Rego.
- (+) The semantic interpreter handles novelty and feeds Phase 2 amendment proposals.
- (−) A Constitution→YAML→Rego compiler must be built and kept correct.
- (−) Two evaluation modes (deterministic + LLM) add complexity; the interpreter runs only on
  the ambiguous minority to bound cost/latency.
- Detail: [`../04-constitution-and-policy.md`](../04-constitution-and-policy.md).
