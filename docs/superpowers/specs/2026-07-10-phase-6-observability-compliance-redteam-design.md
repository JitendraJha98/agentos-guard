# Phase 6 — Observability, Compliance & Red-Team Gate — Design

**Date:** 2026-07-10
**Branch:** `phase-6-observability-compliance-redteam` (off `development` @ `c7c21a4`, phases 1–5 merged)
**Roadmap:** `.planning/ROADMAP.md` Phase 6 · **Requirements:** OBS-01/02/03, CMP-01/02/03,
TEST-01/02/03/04/05/06, SDK-03

## Goal

Close the Phase-0 parity loop: emit standard telemetry for every governed action, map the guard's
evidence to the compliance frameworks that matter at launch, and ship the pytest-native red-team
layer that **breaks the CI build like any failing test**.

1. **Observability** — every `AgentAction`/`Decision` is an OpenTelemetry span carrying a `trace_id`
   that correlates it across pipeline stages and agents; per-agent metrics (volume, outcome mix,
   violations, p95 latency).
2. **Compliance** — each detector/policy maps to OWASP Agentic Top 10 + NIST AI RMF; audit + approval
   evidence supports minimal EU AI Act Art. 12 / Art. 26 claims; a one-call evidence export.
3. **Red-team gate** — a pytest-native attack harness (`attacks.run(agent, suite=…)` →
   `assert results.attack_success_rate < X%`) over a curated deterministic corpus, regression locks
   for fixed vulns, and a **garak + PyRIT-backed** suite that runs in CI and hard-gates the build.

## Cross-cutting decisions

1. **OTel instrumentation, integrate-don't-replace.** Instrument the pipeline `evaluate()` to emit one
   span per action/decision (attributes: `agent_id`, `action_type`, `outcome`, `risk_score`,
   `trust_score`, fired-reason count) carrying `trace_id` (reusing the existing seed
   `ActionContext.trace_id`; generate one if absent). Exporter is configurable via a small
   `telemetry` seam: OTLP (env `OTEL_EXPORTER_OTLP_ENDPOINT`) in production, an **in-memory** exporter
   in tests, and a **no-op tracer/meter when unconfigured** so the default hot path pays ~nothing. The
   existing `-m latency` gate must stay green with instrumentation enabled.
2. **Metrics** — a `MeterProvider`-backed set: counters `agentos_actions_total{agent_id,outcome}` and
   `agentos_violations_total{agent_id}`, histogram `agentos_pipeline_latency_ms{agent_id}`. Asserted
   in tests via an in-memory metric reader.
3. **Red-team target** — attacks run against the **governed agent/pipeline driven by a scripted fake
   model** (deterministic, no network — the existing `test_real_agent_governance` pattern). ASR =
   fraction of attacks the guard does **not** deny. This measures the guard, not an external LLM.
4. **garak/PyRIT in CI (per decision).** garak + PyRIT are real dependencies in a `redteam` extra. A
   **custom garak generator wraps the governed agent** (fake model → governance verdict), and a
   custom detector/scorer reads whether governance blocked the probe; PyRIT drives single-turn
   attacks the same way. They run in a **dedicated CI job** (separate from the core `pytest` job, so
   their weight/runtime never bloats or flakes the deterministic core suite) that **hard-gates** the
   build. Multi-turn PyRIT campaigns stay P1 (TEST-09).
5. **Compliance mapping is data + export, not hot-path.** A `compliance` registry maps each
   detector/policy/principle-effect to OWASP Agentic Top 10 + NIST AI RMF functions and points EU AI
   Act Art. 12 (logging) / Art. 26 (human oversight) claims at concrete evidence (the hash-chained
   audit chain, approval records). Coverage tests + a JSON export.
6. **No-Docker / offline discipline** holds: in-memory OTel exporters in tests; the core suite stays
   deterministic; only the dedicated garak/PyRIT CI job carries the heavy deps.

## Slice breakdown

Each slice is an independently shippable vertical slice, built subagent-driven
(implement → spec-review → quality-review → fix → re-review), one commit per task, gates green at
every commit — the Phases 3–5 rhythm.

### 6a — OTel tracing + trace correlation (OBS-01, OBS-02)
- A `telemetry.py` seam: `configure_tracing(exporter=None)` (OTLP / in-memory / no-op) + a helper the
  pipeline calls to open a span per `evaluate()`. Span attributes cover the decision; the span's
  `trace_id` reuses `ActionContext.trace_id` when the SDK set one and populates it otherwise, so the
  same id correlates the action across stages and across delegated agents. (Correlation lives in the
  span/context; the audit body has no `trace_id` field today and this slice does NOT add one — a
  forward-compatible audit-schema add is possible later but is out of scope here to avoid touching the
  hash-chained record.)
- Pipeline `runner.py` opens the span around the staged evaluation; the span is emitted whether the
  outcome is allow or deny (including short-circuits). No-op by default.
- Tests: an in-memory span exporter captures one span per action with the right attributes;
  `trace_id` is stable across the stages of one action and distinct across actions; `-m latency`
  green with tracing on.

### 6b — Per-agent metrics (OBS-03)
- Extend `telemetry.py` with `configure_metrics(reader=None)` + counters/histogram above, recorded in
  `runner.py` alongside the span (one place, cheap).
- Tests: an in-memory metric reader shows `agentos_actions_total` incrementing per outcome,
  `agentos_violations_total` on a denied/violating action, and a populated latency histogram — all
  labeled by `agent_id`.

### 6c — Compliance mapping + evidence export (CMP-01, CMP-02, CMP-03)
- A `compliance.py` registry: a typed mapping from each detector/policy/effect + audit/approval
  capability → `{owasp_asi: [...], nist_rmf: [...], eu_ai_act: [...]}`. A coverage test asserts every
  live detector/principle-effect and each P0 audit/approval capability has a mapping (no silent gap).
- `export_compliance_evidence(...) -> dict/JSON`: emits the framework mapping plus pointers to the
  concrete evidence (audit-chain verifiability, per-record signatures, approval records) backing the
  EU Art. 12 / Art. 26 claims.
- Tests: coverage completeness; the export contains OWASP + NIST + EU sections and cites real
  evidence artifacts.

### 6d — pytest-native red-team harness + curated corpus (TEST-01, TEST-03, TEST-04, TEST-05, SDK-03)
- SDK adapter (`agentos_sdk.redteam`): an `AttackLibrary`/`attacks.run(agent, suite=…) -> Results`
  with `Results.attack_success_rate`, plus a pytest fixture. A curated corpus with suites
  `prompt_injection`, `tool_misuse`, `exfiltration`, `jailbreak` (payloads seeded from garak/PyRIT
  taxonomies), each run through the governed agent; ASR = not-denied fraction.
- Statistical thresholds asserted (e.g. `asr < 0.02`); the D-04-style regression locks generalized so
  a fixed vuln stays fixed (a specific attack that must remain denied).
- Tests: the harness runs each suite deterministically; ASR is 0 (or below threshold) for the
  governed agent; a `regression_lock`-marked test locks a representative fixed vuln.

### 6e — garak + PyRIT integration + dedicated CI gate (TEST-02, TEST-06)
- `redteam` extra with `garak` + `pyrit` pinned. A custom garak generator wrapping the governed agent
  (fake model → governance verdict) and a detector that scores governance-block; a PyRIT single-turn
  target doing the same. An entrypoint runs the garak/PyRIT-backed suite and asserts the ASR
  threshold.
- CI: a **new dedicated job** in `.github/workflows/ci.yml` installs the `redteam` extra and runs the
  garak/PyRIT suite, hard-failing the build on threshold breach (TEST-06) — the existing
  `regression_lock` gate stays as the fast deterministic lock.
- Tests: a lightweight, deterministic unit test proves the custom generator/detector wire the
  governed agent correctly (a blocked probe scores as blocked, an allowed one as not) without needing
  the full heavy run; the full garak/PyRIT run is exercised by the CI job.

## Out of scope (Phase 6)

- Agent health monitoring, conversation tracing, live graph, SLO/attack dashboards (OBS-04/05/06,
  DASH-04 — Phase 12).
- ASR-over-time trend tracking, scheduled continuous validation, multi-step PyRIT campaigns
  (TEST-07/08/09 — Phase 12).
- Full EU AI Act mapping + SOC 2 + one-click bundle export (CMP-04/05/06 — Phase 11); Phase 6 does the
  minimal Art. 12 / Art. 26 launch claim only.
- Economics/cost telemetry (ECON-* — Phase 11).

## Risks / watch-items

- **Hot-path latency.** Span + metric emission runs per action. Keep the default no-op cheap and keep
  `-m latency` green with instrumentation on; record spans/metrics *after* the decision is computed so
  they never gate the verdict.
- **garak/PyRIT install weight + determinism.** They pull a large dependency tree and some probes
  assume a free-text LLM target; the harness measures governance-block-rate over the probe corpus (the
  meaningful metric for a guard), the target is a fake-model governed agent (no network), and they run
  in a dedicated CI job so core-suite determinism is untouched. Residual risk: CI job runtime/dep
  resolution — pin versions; if a probe is inherently non-deterministic, exclude or mark it.
- **OTel GenAI semconv is experimental** — pin `opentelemetry-semantic-conventions`, centralize
  attribute names in `telemetry.py` so a rename is one edit.
- **Pre-existing flake** on the merged base (a rare full-suite failure, ~1/5 runs; gates green) —
  logged for separate attention; Phase 6 must not add new flakiness.

## Verification (phase-level success criteria)

1. Every `AgentAction`/`Decision` emits an OTel span with a correlating `trace_id`; per-agent metrics
   (volume, outcome mix, violations, p95 latency) are emitted (6a + 6b).
2. Each detector/policy maps to OWASP + NIST; audit/approval evidence backs EU Art. 12/26; exportable
   (6c).
3. Engineers write pytest safety tests via the SDK adapter running an attack library at statistical
   thresholds; fixed vulns are regression-locked (6d).
4. A garak/PyRIT-backed suite runs in CI and a threshold breach breaks the build (6e).
5. `floor_invariant` (430) + `regression_lock` green throughout; `-m latency` green with telemetry on.
