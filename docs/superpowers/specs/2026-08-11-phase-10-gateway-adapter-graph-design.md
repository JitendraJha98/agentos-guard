# Phase 10 — Gateway PEP, Second Adapter & Live Graph — Design

**Date:** 2026-08-11
**Branch:** `phase-10-gateway-adapter-graph` (off the Phase-9 tip `886ad59`; Phase 9 is pending PR into
`development`, so this stacks — the same pattern Phases 4→5 used)
**Roadmap:** `.planning/ROADMAP.md` Phase 10 · **Requirements:** INT-07, INT-08, DISC-03, DISC-04,
DISC-05, DISC-06

## Goal

Break the single-framework, SDK-only ceiling. Today every governed action arrives through the
LangChain/LangGraph SDK PEP; an agent written in another framework, or one nobody registered, is
invisible. Phase 10 delivers:

1. a **framework-agnostic network gateway PEP** that governs actions with no SDK changes (INT-07);
2. a **second framework adapter** — the OpenAI Agents SDK (INT-08);
3. **framework discovery** (DISC-03), **shadow-agent detection** (DISC-04) and **rogue-agent
   detection** (DISC-05);
4. a **live agent graph** with first-class nodes and delegation edges from `parent_action_id`
   (DISC-06).

## Cross-cutting decisions

1. **One enforcement core, three PEP forms.** The gateway and the OpenAI-Agents adapter both call the
   SAME `agentos_sdk.enforce.governed_call` that the LangChain middleware and the memory/MCP/delegation
   wrappers use. Phase 9 made every graduated outcome real there (sandbox quarantine, consensus quorum,
   resource budgets, breaker reporting); routing a new PEP anywhere else would silently lose all of it.
   A new PEP form therefore adds **normalization + transport**, never a second outcome map.
2. **The contract is the boundary.** Both new PEPs produce an `AgentAction` and consume a `Decision`
   via `evaluate(AgentAction) -> Decision` (PIPE-07). Neither imports pipeline internals.
3. **Fail-closed identity.** The gateway trusts nothing it cannot verify: a request without a usable
   identity token is denied by the existing stage-1 identity check (IDN-02), never proxied. An
   unverifiable caller is exactly the DISC-04 shadow signal.
4. **Interception coverage stays honest (INT-06).** Every new PEP form registers with the `@covers`
   registry so `verify_coverage()` keeps proving there are no silent gaps.
5. **Discovery is observation, not enforcement.** DISC-03/04/05 *detect and record*; they do not add
   new deny paths to the hot path. Shadow/rogue findings are persisted + audited so operators can act
   (and Phase-9 containment can be applied by an operator), keeping the per-action budget untouched.
6. **Audit convention (settled in Phase 9).** A per-action deny is the decision record; dedicated event
   kinds are for state transitions and administration. New kinds here are observation events
   (`shadow_agent_detected`, `rogue_agent_detected`, `framework_discovered`) with **short identifiers
   only** — free text stays in tables (the AUD-04 secret-gate lesson).
7. **Persistence** — Alembic `0017+` on the existing dialect-agnostic models (SQLite dev, Postgres
   target).
8. **Deterministic, offline tests** — the gateway is driven through `httpx.ASGITransport` against a
   stub upstream; the OpenAI-Agents adapter is driven through a **fake `ModelProvider`** so a real
   `Runner.run` executes with no network. No Docker, no live LLM.

## Verified external facts (checked 2026-08-11 against the installed package, not docs alone)

`openai-agents` **0.21.1** exposes:
- `function_tool(func=None, *, name_override=..., tool_input_guardrails=..., needs_approval=..., ...)`
- `RunHooks` with `on_tool_start` / `on_tool_end` / `on_llm_start` / `on_llm_end` / `on_agent_start`
- `Model.get_response(system_instructions, input, model_settings, tools, output_schema, handoffs,
  tracing, *, previous_response_id, conversation_id, prompt) -> ModelResponse`
- `ModelProvider.get_model(model_name) -> Model`, `RunConfig(model_provider=..., tracing_disabled=...)`,
  `Runner.run(starting_agent, input, *, hooks=..., run_config=...)`
- `agents.tool_guardrails.ToolInputGuardrail.run(data: ToolInputGuardrailData) ->
  ToolGuardrailFunctionOutput` with `AllowBehavior` / `RejectContentBehavior` / `RaiseExceptionBehavior`

**Design consequence:** the SDK documents no general pre-execution *middleware*, and hook semantics vary
across versions — so the primary adapter PEP wraps the **tool callable itself**, where blocking is
guaranteed by construction (the real body is simply never invoked). The framework-native
`tool_input_guardrails` path is offered as a second, optional entry point that delegates to the same
core, so adopters can choose either without the outcome map diverging.

## Slice breakdown

Six slices, one per requirement, each independently shippable and built subagent-driven
(implement → spec-review → adversarial quality review → fix → re-review), one commit per task, gates
green at every commit.

### 10a — Gateway PEP (INT-07)
A new `agentos-gateway` workspace package: an ASGI app that reverse-proxies upstream endpoints and
governs every request in flight.
- **Routes:** an OpenAI-compatible `POST /v1/chat/completions` (model invocation) and a generic
  `POST /tools/{tool_name}` (tool call); both normalize into an `AgentAction` via a new
  `normalize_gateway_*` pair registered with `@covers`.
- **Identity:** the agent's signed token rides an `Authorization`/`X-Agentos-Token` header; absent or
  unverifiable → denied by stage 1, never forwarded.
- **Enforcement:** `governed_call(...)` with the run callable being "forward upstream via httpx". So
  `allow` proxies and returns the upstream response; `deny`/quarantine/limit/consensus outcomes return a
  governed HTTP error carrying the fired reasons and **never touch the upstream** (the no-egress
  contract).
- **No SDK changes:** an agent adopts it by pointing its `base_url` at the gateway.
- Tests: allow proxies and returns the upstream body; deny never reaches the stub upstream (asserted by
  an upstream call counter); missing/forged token → denied unproxied; a `sandbox` outcome returns the
  quarantine surface; coverage registry updated.

### 10b — OpenAI Agents SDK adapter (INT-08)
`agentos_sdk.adapters.openai_agents` in an optional `adapters` dependency group.
- `governed_tool(pipeline, token, ...)` wraps a tool callable so governance runs before the body, then
  the caller passes the wrapped callable to `function_tool`. Blocking is structural.
- `governance_tool_guardrail(...)` builds a `ToolInputGuardrail` for `function_tool(tool_input_guardrails=[...])`,
  mapping a governed block onto `RejectContentBehavior`/`RaiseExceptionBehavior` — the framework-native
  path, delegating to the same `governed_call`.
- Tests: a REAL `Runner.run` against a **fake `ModelProvider`** whose `Model.get_response` returns a
  tool call — a denied tool is never executed (body never runs) and the run completes with the governed
  message; an allowed tool runs. Import-guarded so the main suite skips cleanly when the extra is absent.

### 10c — Framework discovery (DISC-03)
`FrameworkDetector` enumerating LangChain/LangGraph, CrewAI, AutoGen, OpenAI Agents SDK, and MCP via
`importlib.metadata` distributions + module presence, recording `{framework, version, detected_at}` to a
`discovered_framework` table with an audited `framework_discovered` event and a read API. Detection is
evidence-based (a distribution that is actually installed), never a guess.

### 10d — Shadow-agent detection (DISC-04)
An action whose agent is not registered is already denied at stage 1; this slice makes it **visible**:
a `ShadowAgentStore` records `{claimed_agent_id, action_type, first_seen, last_seen, attempts}` and
audits `shadow_agent_detected` (short identifiers only — a claimed id is attacker-controlled, so it is
recorded as a bounded, sanitized field and never used as a metric label, per the Phase-6 cardinality
lesson). Fed from the identity short-circuit path; read API + dashboard surface.

### 10e — Rogue-agent detection (DISC-05)
An agent *is* registered but acts outside its declared scope. Compares observed inventory against the
Phase-5 **declared** manifest: a component used but never declared is a divergence. Records
`{agent_id, kind, name, first_seen}` to a `rogue_finding` table, audits `rogue_agent_detected`, and
exposes a read API. Advisory by design (decision 5) — an operator escalates using Phase-9 containment.

### 10f — Live agent graph (DISC-06)
`AgentGraphStore` materializing first-class **nodes** (agent, tool, model, mcp, memory) and **edges**
(`agent -uses-> component`, `agent -delegates-> agent`), with delegation edges derived from
`parent_action_id` by joining audit records parent→child. Read API returns `{nodes, edges}`; a
reconciler pass keeps it current (superseding the Phase-7 capability-class seed, whose docstring already
defers the full graph to DISC-06).

## Out of scope (Phase 10)

- K8s sidecar/operator PEP (INT-09, Phase 14) — this is a userspace gateway, not a network sidecar.
- Transitive permission calculus / emergent-capability flagging (POL-11, Phase 13). Phase 10 supplies
  the graph those will walk.
- The rich dashboard graph visualisation (DASH-04, Phase 12) — read APIs land here, visualisation later.
- Adapters beyond the second one; CrewAI/AutoGen are *detected* (DISC-03) but not adapted.

## Risks / watch-items

- **The gateway must not become a second outcome map.** If it grows its own allow/deny handling it will
  drift from `governed_call` and silently lose Phase-9 containment. Reviewers must verify it delegates.
- **A proxy is a new egress path.** A denied request must never reach upstream — asserted with an
  upstream call counter, not by inspecting the response.
- **Header/token handling.** The gateway must not forward the agent's governance token upstream, and
  must not leak it into logs, spans, or audit bodies.
- **Adapter version drift.** `openai-agents` is pinned in an optional group; the callable-wrapper PEP is
  deliberately chosen so a hook/guardrail API change cannot silently disable enforcement.
- **Claimed identifiers are attacker-controlled** (shadow detection). Bound their length, never use them
  as metric labels, and keep them out of hash-covered audit bodies beyond short sanitized identifiers.
- **Graph growth.** Node/edge materialization scans the audit log; keep it a batch reconciler pass, off
  the per-action hot path.

## Verification (phase-level success criteria)

1. A framework-agnostic gateway PEP intercepts actions with no SDK changes, behind the same
   `evaluate(AgentAction) -> Decision` contract, and the OpenAI Agents SDK adapter intercepts actions
   (10a + 10b).
2. Framework discovery detects the listed frameworks; shadow detection flags agents acting without
   registration; rogue detection flags agents diverging from declared scope (10c + 10d + 10e).
3. A live agent graph materializes agents/tools/MCP/models/memories and delegation edges, with lineage
   derived from `parent_action_id` (10f).
4. `floor_invariant` + `regression_lock` green throughout; the per-action latency budget is untouched
   (all Phase-10 work is off the hot path); `verify_coverage()` still proves no silent interception gaps.
