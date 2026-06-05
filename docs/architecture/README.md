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

Microsoft's **Agent Governance Toolkit (AGT)** and **RAMPART**. They run on one reflex —
*Distrust → Block → Log* — enforcing static YAML rules with append-only logs. agentos-guard
runs *Trust → Verify → Graduate → Prove*: a *living* semantic constitution, **intent-based**
(not string-matching) policy, *graduated* (non-binary) response, **cross-agent permission
calculus**, explainable denials with remediation, a **CI-gating** red-team, and provable —
not merely append-only — evidence.

**Start with the [`00-manifesto.md`](00-manifesto.md)** — it states the paradigm and the seven
pillars. The head-to-head scorecard is in [`30-comparison-agt.md`](30-comparison-agt.md).

## How to read these docs

| # | Doc | Read it for |
|---|-----|-------------|
| — | [`README.md`](README.md) | This overview + glossary |
| 00 | [`00-manifesto.md`](00-manifesto.md) | **Read first** — the paradigm shift + the seven pillars that beat AGT |
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

## `docs/` vs `.planning/` — two layers, not a duplicate

These docs and the `.planning/` folder cover the same project but play different roles, on
purpose. Keep them straight:

| | `docs/architecture/` (here) | `.planning/` |
|---|------------------------------|--------------|
| **Role** | **Authoritative design** — *what* we build and *why* | **Execution decomposition** — *how* and *in what order* we build it |
| **Changes when** | The design itself changes | A phase is planned, executed, or verified (GSD workflow) |
| **Audience** | Anyone understanding the system | Whoever is building the next slice |
| **Source of truth for** | Components, contracts, paradigm | Phases, REQ-IDs, plans, traceability |

When they appear to overlap on a topic, `docs/` says what the thing *is*; `.planning/` says
*when and how* it gets built. The design is upstream; planning is downstream of it.

---

*This document set is **design-authoritative**. Phase 1 (the walking skeleton) is implemented
and merged; everything beyond it is design ahead of code. See [`20-roadmap.md`](20-roadmap.md)
for the build sequence and `.planning/ROADMAP.md` for execution status.*
