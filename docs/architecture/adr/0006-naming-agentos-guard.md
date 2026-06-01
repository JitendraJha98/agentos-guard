# ADR 0006 — Product name: agentos-guard

- **Status:** Accepted
- **Date:** 2026-06-01

## Context

The raw spec referred to the project by several names (agentos-guard, SentinelAI, "the
Kubernetes Control Plane for AI Agents"). The git repository and existing files use
`agentos-guard`. A single consistent name is needed across docs, the API, and the SDK.

## Decision

The product is **agentos-guard**, matching the repository and committed files. Descriptive
taglines ("the control plane for AI agents", "Kubernetes for agents") are used in prose, not as
the product name. "SentinelAI" and other working titles are retired.

## Consequences

- (+) No rename churn; consistency between repo, package, API, and docs.
- (−) The name is functional rather than brandable — acceptable for an open-source project;
  revisit only if a separate product brand is ever needed.
