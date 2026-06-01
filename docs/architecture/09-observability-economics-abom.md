# 09 — Observability, Economics & Supply Chain (ABOM)

Three cross-cutting engines that turn the control plane into a place platform teams *live* —
seeing behavior, controlling spend, and tracking what each agent is built from.

## Observability

agentos-guard emits standard telemetry and **integrates with** existing backends rather than
replacing them.

| Capability | Phase | Notes |
|------------|-------|-------|
| **OpenTelemetry integration** | 0 | Every `AgentAction`/`Decision` is a span; metrics for outcomes, risk, latency. |
| **Distributed tracing** | 0 | `trace_id` correlates an action across the pipeline and across agents. |
| **Agent metrics** | 0 | Per-agent action volume, outcome mix, violation counts, p95 pipeline latency. |
| **Agent health monitoring** | 1 | Liveness/error-rate/circuit-breaker state per agent. |
| **Conversation tracing** | 1 | Reconstruct a full conversation across tools and delegations. |
| **Live agent graph** | 1 | The visual fleet map (shared with discovery, [`06`](06-identity-trust-discovery.md)). |
| **Per-agent SLOs & violation dashboards** | 1 | Platform-team views with attack visualization. |

## Economics (cost & resource governance)

Agents spend real money (tokens, GPU, API calls). This engine governs that spend like policy.

| Capability | Phase | Notes |
|------------|-------|-------|
| **Cost monitoring** | 1 | Attribute token/API cost to each agent/action. |
| **Token governance & budgets** | 1 | Budgets enforceable as policy — an over-budget action can be denied/escalated by the pipeline. |
| **GPU usage tracking** | 1 | Attribute compute to agents. |
| **API consumption monitoring** | 1 | Rate/quota visibility per downstream API. |
| **ROI analytics** | 2 | Value-vs-cost views per agent/workflow. |

Budgets are expressed as policy, so the **same graduated-response engine** that blocks unsafe
actions can also block unaffordable ones — no separate enforcement path.

## ABOM — Agent Bill of Materials (supply chain)

A manifest of everything an agent is composed of, enabling vulnerability impact analysis.

| Capability | Phase | Notes |
|------------|-------|-------|
| **Agent Bill of Materials** | 1 | Declared dependencies per `Agent`: models, prompts, tools, MCP servers. |
| **Model / prompt / tool / MCP dependency tracking** | 1 | Versioned components with provenance. |
| **Vulnerability impact analysis** | 2 | "Which agents use the compromised model/tool/prompt vX?" answered instantly. |

ABOM feeds the security engine's **supply-chain checks** ([`05`](05-security-and-runtime.md)):
when a component is flagged known-bad, the control plane can locate and quarantine every
affected agent.
