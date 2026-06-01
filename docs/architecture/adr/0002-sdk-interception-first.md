# ADR 0002 — SDK interception as the v1 enforcement point

- **Status:** Accepted
- **Date:** 2026-06-01

## Context

Agent actions can be intercepted via (a) an SDK shim inside the agent process, (b) a network
gateway/proxy, or (c) Kubernetes sidecars/operator. Each is a Policy Enforcement Point (PEP).
We need one for the MVP that minimizes adoption friction while keeping the others open.

## Decision

Ship **SDK interception first**, targeting LangChain/LangGraph (see
[`0006`](0006-naming-agentos-guard.md) scope). Define the PEP↔pipeline contract so gateway
(Phase 1) and K8s sidecars (Phase 2) drop in without changing the Decision Pipeline.

## Consequences

- (+) Lowest-friction adoption — `pip install` + decorators, no infra changes.
- (+) Direct access to rich in-process context (tools, memory, delegation edges).
- (−) Per-framework adapters are needed; coverage grows over time.
- (−) In-process PEPs can't enforce network-level isolation — that arrives with the gateway and
  sidecars in later phases.
