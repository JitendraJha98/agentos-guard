# agentos-guard — Architecture & Design

> Open-source **governance and security control plane for AI agents** —
> the Kubernetes, Istio, OPA, Datadog, CrowdStrike, and LangSmith for autonomous
> systems, combined into a single control plane.

agentos-guard sits between your AI agents and everything they touch — tools, memory,
MCP servers, models, APIs, and each other — and intercepts **every action** before it
executes. Each action is checked against declarative policy and a human-readable
**constitution**, enriched with cryptographic identity and a **trust score**, and
returned a **graduated decision** (allow / warn / sandbox / consensus / human-approval /
deny). Every decision is written to a **tamper-evident audit log** as compliance evidence,
and a **pytest-native red-team layer** makes safety regressions break CI like a failing
unit test.

## What we are beating

Microsoft's **Agent Governance Toolkit (AGT)** and **RAMPART**. They enforce mostly static
YAML rules with audit logs. agentos-guard differentiates with a *living* semantic
constitution, *graduated* (non-binary) response, reputation/trust scoring, continuous
adversarial self-play, and zero-knowledge compliance proofs. See
[`30-comparison-agt.md`](30-comparison-agt.md).

## How to read these docs

| # | Doc | Read it for |
|---|-----|-------------|
| — | [`README.md`](README.md) | This overview + glossary |
| 01 | [`01-overview.md`](01-overview.md) | Problem, goals/non-goals, control-plane model, request lifecycle |
| 02 | [`02-domain-model.md`](02-domain-model.md) | Core entities & data model |
| 03 | [`03-interception-and-pipeline.md`](03-interception-and-pipeline.md) | How actions are intercepted + the decision pipeline |
| 04 | [`04-constitution-and-policy.md`](04-constitution-and-policy.md) | Constitution → YAML → OPA/Rego, graduated response |
| 05 | [`05-security-and-runtime.md`](05-security-and-runtime.md) | Security engine + runtime sandboxing |
| 06 | [`06-identity-trust-discovery.md`](06-identity-trust-discovery.md) | Identity, trust scoring, discovery, the agent graph |
| 07 | [`07-audit-and-compliance.md`](07-audit-and-compliance.md) | Tamper-evident audit + compliance frameworks |
| 08 | [`08-testing-and-redteam.md`](08-testing-and-redteam.md) | pytest-native red-team + self-play |
| 09 | [`09-observability-economics-abom.md`](09-observability-economics-abom.md) | Observability, cost governance, ABOM |
| 10 | [`10-control-plane-api-and-sdk.md`](10-control-plane-api-and-sdk.md) | Declarative API, reconciliation, SDK, dashboard |
| 20 | [`20-roadmap.md`](20-roadmap.md) | Phase 0 / 1 / 2 phasing |
| 30 | [`30-comparison-agt.md`](30-comparison-agt.md) | Head-to-head vs AGT / RAMPART |
| ADR | [`adr/`](adr/) | Architecture Decision Records |

## Locked decisions (summary)

- **Name:** agentos-guard
- **Stack:** Python-first; Rust reserved for hot enforcement paths in a later phase
- **Ambition:** phased — MVP that beats AGT → roadmap to moonshot features
- **v1 enforcement:** SDK interception (LangChain / LangGraph first); gateway + K8s later
- **Policy substrate:** human-readable Constitution → compiled YAML → OPA/Rego, with an
  LLM semantic interpreter for ambiguous / graduated cases

## Glossary

- **PEP (Policy Enforcement Point):** where an agent action is intercepted (SDK shim,
  gateway, or sidecar).
- **AgentAction:** the normalized event representing one tool call / memory access / MCP
  call / model invocation / delegation.
- **Decision Pipeline:** the synchronous stages — identity → policy → risk → graduated
  response — that produce a decision for each `AgentAction`.
- **Constitution:** human-readable governing principles, compiled into enforceable policy.
- **Graduated response:** the spectrum of outcomes beyond allow/deny.
- **Trust score:** a dynamic, reputation-based measure of an agent's reliability.
- **ABOM:** Agent Bill of Materials — the dependency manifest of an agent.

---

*This is a design-only document set. No implementation exists yet; see
[`20-roadmap.md`](20-roadmap.md) for the build sequence.*
