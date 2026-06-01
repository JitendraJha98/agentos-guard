# 02 — Domain Model & Data

The control plane is organized around a small set of declarative resources (Kubernetes-style)
and a handful of runtime event/record types. Everything else is an engine that reads or
writes these.

## Core entities

| Entity | Kind | Purpose |
|--------|------|---------|
| `Agent` | resource | A registered actor: identity, owner, framework, declared tools/permissions, trust profile reference. |
| `Policy` | resource | A declarative rule set (compiled to OPA/Rego) scoped to agents/tools/actions. |
| `Constitution` | resource | Human-readable governing principles; compiles into policy + feeds the semantic interpreter. |
| `TrustProfile` | resource | An agent's reputation/trust score, history, and (Phase 2) stake. |
| `ApprovalRequest` | resource | A pending human-in-the-loop decision with full action context. |
| `ABOM` | resource | Agent Bill of Materials — model/prompt/tool/MCP dependencies. |
| `AgentAction` | event | The normalized, intercepted action under evaluation. |
| `Decision` | record | The pipeline's output: outcome + reasons + policy/constitution references. |
| `AuditRecord` | record | Tamper-evident, hash-chained entry linking action → decision → evidence. |

## `AgentAction` (the normalized event)

Every interception — regardless of source — is normalized into one shape so the pipeline and
all engines are framework-agnostic:

```yaml
AgentAction:
  id: uuid
  agent_id: string            # resolved actor
  type: tool_call | memory_access | mcp_call | model_invocation | delegation
  target: string              # tool name, MCP server, model id, peer agent id
  payload: object             # arguments / prompt / message (redacted in logs by policy)
  context:
    conversation_id: string
    parent_action_id: string  # for delegation/lineage chains
    trace_id: string          # OpenTelemetry correlation
  timestamp: rfc3339
```

## `Decision` (the pipeline output)

```yaml
Decision:
  action_id: uuid
  outcome: allow | warn | sandbox | require_consensus | require_approval | deny
  risk_score: 0.0–1.0
  trust_score: 0.0–1.0
  reasons:                    # explainability: which principles/policies fired
    - policy_id | constitution_principle
  evidence_ref: audit_record_id
```

## Storage

| Concern | Choice (Phase 0) | Rationale |
|---------|------------------|-----------|
| Resources & state | **PostgreSQL** | Relational integrity for resources, decisions, approvals. |
| Tamper-evident log | Append-only, **hash-chained** table in Postgres (Merkle DAG later) | Simple to start; verifiable; see [`07`](07-audit-and-compliance.md). |
| Agent graph | Derived/materialized from resources + actions | Powers discovery & lineage; graph DB optional later. |
| Telemetry | **OpenTelemetry** → user's backend | We integrate, not replace. |

The data model is intentionally minimal in Phase 0 and extended per engine in later phases.
Resource definitions are versioned and validated through the Control-Plane API
([`10`](10-control-plane-api-and-sdk.md)).
