# Phase 6 · Slice 6a — OTel Tracing + Trace Correlation (OBS-01, OBS-02) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Commits end
> with a second `-m "Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"`. Tests:
> `./.venv/Scripts/python.exe -m pytest`. TDD per task, one commit each. Gates `floor_invariant`
> (430) + `regression_lock` (10) + `latency` green at every commit.

**Goal (OBS-01/02):** Every `AgentAction`/`Decision` emits one OpenTelemetry span carrying a
`trace_id` that correlates the action across pipeline stages and across delegated agents. Integrate,
don't replace: emit spans; the exporter is the operator's choice.

**Architecture:** A `telemetry.py` seam in `agentos_pipeline` uses the OTel global tracer
(`trace.get_tracer(...)`) — a **no-op** when no provider is configured, so the default hot path pays
~nothing. `Pipeline.evaluate()` wraps the whole staged evaluation (incl. the fail-safe) in one span,
annotated with the decision AFTER it is computed. `ActionContext.trace_id` (the seed field) is
populated if absent and recorded on the span as the app-level correlation id shared across an action's
stages and a delegation chain. Tests install an in-memory exporter via `configure_tracing(...)`.

**Tech Stack:** `opentelemetry-api` + `opentelemetry-sdk` (new pipeline deps), pytest.

> First commit in this slice: `docs(phase-6): Slice 6a plan` for this file, then the tasks below.

## File structure
- Create `packages/pipeline/src/agentos_pipeline/telemetry.py` — `configure_tracing`,
  `reset_tracing`, `get_tracer`, `annotate_decision_span`.
- Modify `packages/pipeline/src/agentos_pipeline/runner.py` — wrap `evaluate()` in a span; populate +
  record `trace_id`.
- Modify `packages/pipeline/pyproject.toml` — add `opentelemetry-api>=1.42`, `opentelemetry-sdk>=1.42`.
- Tests: `tests/unit/test_telemetry_tracing.py`, `tests/integration/test_pipeline_tracing.py`.

---

### Task 1: `telemetry.py` tracing seam

**Files:**
- Create: `packages/pipeline/src/agentos_pipeline/telemetry.py`
- Modify: `packages/pipeline/pyproject.toml`
- Test: `tests/unit/test_telemetry_tracing.py`

```python
"""OBS-01/02 telemetry seam. Instrumentation uses the OTel GLOBAL tracer, which is a no-op until a
provider is configured — so the default hot path pays nothing and production wires an exporter
(OTLP to the operator's backend) at startup, off the hot path. Tests install an in-memory exporter.
Attribute names are centralized here (OTel GenAI semconv is experimental — one edit to rename)."""
from __future__ import annotations

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor

_TRACER_NAME = "agentos_pipeline"
SPAN_NAME = "agentos.pipeline.evaluate"

# We hold our OWN provider module-locally rather than OTel's GLOBAL one, because
# trace.set_tracer_provider() refuses to override an already-set provider (it warns and
# keeps the first) — which would silently break test isolation across configure/reset.
_provider: TracerProvider | None = None

# Centralized span attribute keys.
ATTR_TRACE_ID = "agentos.trace_id"
ATTR_AGENT_ID = "agentos.agent_id"
ATTR_ACTION_TYPE = "agentos.action_type"
ATTR_ACTION_ID = "agentos.action_id"
ATTR_PARENT_ACTION_ID = "agentos.parent_action_id"
ATTR_OUTCOME = "agentos.outcome"
ATTR_RISK = "agentos.risk_score"
ATTR_TRUST = "agentos.trust_score"
ATTR_REASON_COUNT = "agentos.reason_count"


def configure_tracing(exporter) -> None:
    """Install a module-local TracerProvider exporting to `exporter` (SimpleSpanProcessor —
    synchronous, so tests see finished spans immediately). Production passes an OTLP exporter (off
    the hot path, at startup); tests pass an InMemorySpanExporter. Fully re-callable."""
    global _provider
    _provider = TracerProvider()
    _provider.add_span_processor(SimpleSpanProcessor(exporter))


def reset_tracing() -> None:
    """Drop the configured provider back to the no-op default (test isolation)."""
    global _provider
    _provider = None


def get_tracer():
    """The module provider's tracer when configured; otherwise the global tracer, which is a
    no-op when no global provider is set — a zero-cost default hot path."""
    if _provider is not None:
        return _provider.get_tracer(_TRACER_NAME)
    return trace.get_tracer(_TRACER_NAME)


def annotate_decision_span(span, action, decision) -> None:
    """Record the decision on the span AFTER it is computed. Defensive: never raise into the
    hot path (a no-op span accepts set_attribute harmlessly; guard anyway)."""
    try:
        span.set_attribute(ATTR_TRACE_ID, action.context.trace_id or "")
        span.set_attribute(ATTR_AGENT_ID, action.agent_id)
        span.set_attribute(ATTR_ACTION_TYPE, action.type.value)
        span.set_attribute(ATTR_ACTION_ID, str(action.id))
        if action.context.parent_action_id is not None:
            span.set_attribute(ATTR_PARENT_ACTION_ID, str(action.context.parent_action_id))
        span.set_attribute(ATTR_OUTCOME, decision.outcome.value)
        span.set_attribute(ATTR_RISK, float(decision.risk_score))
        span.set_attribute(ATTR_TRUST, float(decision.trust_score))
        span.set_attribute(ATTR_REASON_COUNT, len(decision.reasons))
    except Exception:  # telemetry must never break governance
        pass
```

`pyproject.toml` deps gain `"opentelemetry-api>=1.42"`, `"opentelemetry-sdk>=1.42"`.

**Steps (TDD):**
- [ ] Test (`test_telemetry_tracing.py`): `reset_tracing()`; `exp = InMemorySpanExporter()`;
  `configure_tracing(exp)`; open a span via `get_tracer().start_as_current_span("t")` and end it;
  assert `exp.get_finished_spans()` has one span named "t". Also: after `reset_tracing()`,
  `get_tracer().start_as_current_span("x")` does NOT raise and records nothing (no-op). Run → fails.
- [ ] Implement `telemetry.py` + deps (`uv sync`). Run → passes.
- [ ] Commit `feat(pipeline): OTel tracing seam — no-op default, in-memory-testable (OBS-01)`.

---

### Task 2: instrument `Pipeline.evaluate()` with a span + trace_id

**Files:**
- Modify: `packages/pipeline/src/agentos_pipeline/runner.py`
- Test: `tests/integration/test_pipeline_tracing.py`

Change `evaluate()` (currently the try/except at runner.py:175-182) to wrap the evaluation in a span,
populate `trace_id` if absent, and annotate after:

```python
from uuid import uuid4
from agentos_pipeline.telemetry import SPAN_NAME, annotate_decision_span, get_tracer

    async def evaluate(self, action: AgentAction) -> Decision:
        # OBS-02: ensure an app-level correlation id exists (SDK sets it across a delegation
        # chain; generate one if absent) so every stage + delegated agent shares it.
        if action.context.trace_id is None:
            action.context.trace_id = uuid4().hex
        with get_tracer().start_as_current_span(SPAN_NAME) as span:
            floor_box: list[Outcome | None] = [None]
            try:
                decision = await self._evaluate(action, floor_box)
            except Exception as exc:  # total control-plane failure (PIPE-05)
                decision = await self._fail_safe(action, exc, computed_floor=floor_box[0])
            annotate_decision_span(span, action, decision)
            return decision
```

**Steps (TDD):**
- [ ] Test (`test_pipeline_tracing.py`, reuse the `pipeline_with_principle` fixture): `reset_tracing`;
  install an `InMemorySpanExporter` via `configure_tracing`; attach the wired token to a benign
  `http_get` action (no `trace_id` set) and `await pipeline.evaluate(action)`; assert exactly ONE
  finished span named `agentos.pipeline.evaluate` whose attributes include `agentos.agent_id`,
  `agentos.action_type == "tool_call"`, `agentos.outcome == "allow"`, and a non-empty
  `agentos.trace_id`; assert `action.context.trace_id` was populated and equals the span's
  `agentos.trace_id`. Add a second assertion: two actions built with the SAME preset
  `context.trace_id` produce two spans sharing that `agentos.trace_id` (cross-action/agent
  correlation, OBS-02). Add a deny case (exfil to a non-allowlisted host via
  `pipeline_with_principle`) → its span shows `agentos.outcome == "deny"`. Run → fails.
- [ ] Implement the `evaluate()` change. Run → passes.
- [ ] `reset_tracing()` in a fixture teardown so tracing state never leaks to other tests.
- [ ] Commit `feat(pipeline): emit one span per evaluate with trace_id correlation (OBS-01/02)`.

---

### Task 3: full gate (latency with tracing on)
- [ ] `pytest -q` green; `-m floor_invariant` 430; `-m regression_lock` 10.
- [ ] `-m latency` green **with tracing configured** — add a latency variant (or a one-off) that runs
  the gate after `configure_tracing(InMemorySpanExporter())` to prove span emission stays within the
  PIPE-04 budget; then `reset_tracing()`. If the in-memory SimpleSpanProcessor measurably dents the
  budget, that is expected only under an exporter — the DEFAULT path is no-op; document that the
  budget gate runs on the no-op default (production uses an async BatchSpanProcessor off the hot
  path). Confirm the default `-m latency` stays green.
- [ ] Commit only if incidental fixes were needed.

## Self-review
OBS-01: every `evaluate()` emits one span (allow/deny/fail-safe all annotated). OBS-02: an app-level
`trace_id` is populated on `ActionContext` and recorded on the span, shared across an action's stages
and (when the SDK propagates it) across delegated agents; `parent_action_id` is recorded for lineage.
No-op by default (zero-config hot path), in-memory-testable, OTLP-ready via the `configure_tracing`
seam; attribute names centralized (experimental semconv). Telemetry never raises into governance.
Gates green; the default hot path (no provider) is unchanged, so `-m latency` holds.
