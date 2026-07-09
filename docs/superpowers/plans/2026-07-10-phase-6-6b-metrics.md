# Phase 6 · Slice 6b — Per-Agent Metrics (OBS-03) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Commits end
> with a second `-m "Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"`. Tests:
> `./.venv/Scripts/python.exe -m pytest`. TDD per task, one commit each. Gates `floor_invariant`
> (430) + `regression_lock` (10) + `latency` (3) green at every commit.

**Goal (OBS-03):** Emit per-agent metrics — action volume, outcome mix, violation counts, and
pipeline latency — from the same `evaluate()` seam as the 6a span, so a backend can chart volume /
outcome mix / p95 latency per agent.

**Architecture:** Extend `agentos_pipeline/telemetry.py` (from 6a) with a metrics seam that mirrors
the tracing seam: a **module-local** `MeterProvider` (never OTel's global — same override-once
footgun), no-op by default, in-memory-testable. Three instruments — counter
`agentos_actions_total{agent_id,outcome}` (volume + outcome mix), counter
`agentos_violations_total{agent_id}` (non-allow outcomes), histogram
`agentos_pipeline_latency_ms{agent_id}`. `Pipeline.evaluate()` times the evaluation and records all
three after the decision, alongside `annotate_decision_span`. Guarded so metrics never break
governance.

**Tech Stack:** `opentelemetry-sdk` metrics (already a dep from 6a), pytest.

> First commit in this slice: `docs(phase-6): Slice 6b plan` for this file, then the tasks below.

## File structure
- Modify `packages/pipeline/src/agentos_pipeline/telemetry.py` — add the metrics seam.
- Modify `packages/pipeline/src/agentos_pipeline/runner.py` — time `evaluate()` + record metrics.
- Tests: `tests/unit/test_telemetry_metrics.py`, `tests/integration/test_pipeline_metrics.py`.

---

### Task 1: metrics seam in `telemetry.py`

**Files:**
- Modify: `packages/pipeline/src/agentos_pipeline/telemetry.py`
- Test: `tests/unit/test_telemetry_metrics.py`

Add to `telemetry.py` (imports: `from opentelemetry import metrics`; `from
opentelemetry.sdk.metrics import MeterProvider`; and `from agentos_contract import Outcome`):

```python
_METER_NAME = "agentos_pipeline"

# Centralized metric names + label keys (semconv is experimental — one edit to rename).
METRIC_ACTIONS = "agentos_actions_total"
METRIC_VIOLATIONS = "agentos_violations_total"
METRIC_LATENCY = "agentos_pipeline_latency_ms"
LABEL_AGENT_ID = "agent_id"
LABEL_OUTCOME = "outcome"

_meter_provider: MeterProvider | None = None


def _build_instruments(meter) -> dict:
    return {
        "actions": meter.create_counter(
            METRIC_ACTIONS, description="Governed actions evaluated, by outcome"),
        "violations": meter.create_counter(
            METRIC_VIOLATIONS, description="Actions with a non-allow (restricted) outcome"),
        "latency": meter.create_histogram(
            METRIC_LATENCY, unit="ms", description="Pipeline evaluate() wall latency"),
    }


# No-op instruments at import (global meter has no provider -> no-op); replaced on configure.
_instruments: dict = _build_instruments(metrics.get_meter(_METER_NAME))


def configure_metrics(reader) -> None:
    """Install a module-local MeterProvider reading into `reader` and (re)build the instrument
    handles from ITS meter. Tests pass an InMemoryMetricReader; production passes a
    PeriodicExportingMetricReader (OTLP). Fully re-callable — each call replaces the provider."""
    global _meter_provider, _instruments
    _meter_provider = MeterProvider(metric_readers=[reader])
    _instruments = _build_instruments(_meter_provider.get_meter(_METER_NAME))


def reset_metrics() -> None:
    """Drop the provider and rebuild no-op instruments from the global (no-provider) meter."""
    global _meter_provider, _instruments
    _meter_provider = None
    _instruments = _build_instruments(metrics.get_meter(_METER_NAME))


def record_decision_metrics(action, decision, latency_ms: float) -> None:
    """Record volume/outcome-mix/violation/latency for one decision. Guarded: telemetry must
    NEVER raise into governance. Violation == a non-allow (restricted) outcome."""
    try:
        labels = {LABEL_AGENT_ID: action.agent_id}
        _instruments["actions"].add(1, {**labels, LABEL_OUTCOME: decision.outcome.value})
        if decision.outcome is not Outcome.allow:
            _instruments["violations"].add(1, labels)
        _instruments["latency"].record(latency_ms, labels)
    except Exception:  # telemetry must never break governance
        pass
```

**Steps (TDD):**
- [ ] Test (`test_telemetry_metrics.py`): `from opentelemetry.sdk.metrics.export import
  InMemoryMetricReader`; `reset_metrics()`; `reader = InMemoryMetricReader()`;
  `configure_metrics(reader)`; build a tiny stub `action` (has `.agent_id`) and a stub `decision`
  (has `.outcome` = an `Outcome`); call `record_decision_metrics(action, deny_decision, 3.2)` and an
  allow one; then `data = reader.get_metrics_data()` and assert `agentos_actions_total` has points
  for both outcomes labeled by `agent_id`+`outcome`, `agentos_violations_total` counted ONLY the
  deny, and `agentos_pipeline_latency_ms` recorded the latency. Also: after `reset_metrics()`,
  recording does nothing observable (no-op) and never raises; a decision object that raises on
  `.outcome` is swallowed. Run → fails.
- [ ] Implement the metrics seam. Run → passes.
- [ ] Commit `feat(pipeline): OTel metrics seam — actions/violations/latency, no-op default (OBS-03)`.

---

### Task 2: record metrics from `Pipeline.evaluate()`

**Files:**
- Modify: `packages/pipeline/src/agentos_pipeline/runner.py`
- Test: `tests/integration/test_pipeline_metrics.py`

Time the evaluation and record after the decision (extend the 6a `evaluate()` body; add `import
time` if absent, and import `record_decision_metrics`):

```python
from agentos_pipeline.telemetry import (
    SPAN_NAME, annotate_decision_span, decision_span, record_decision_metrics,
)

        with decision_span() as span:
            floor_box: list[Outcome | None] = [None]
            start = time.perf_counter()
            try:
                decision = await self._evaluate(action, floor_box)
            except Exception as exc:  # total control-plane failure (PIPE-05)
                decision = await self._fail_safe(action, exc, computed_floor=floor_box[0])
            latency_ms = (time.perf_counter() - start) * 1000.0
            annotate_decision_span(span, action, decision)
            record_decision_metrics(action, decision, latency_ms)
            return decision
```

**Steps (TDD):**
- [ ] Test (`test_pipeline_metrics.py`, reuse `pipeline_with_principle`): `reset_metrics`;
  `reader = InMemoryMetricReader()`; `configure_metrics(reader)`; evaluate a benign allow action and
  an exfil deny action (via `pipeline_with_principle`); `reader.get_metrics_data()` shows
  `agentos_actions_total` with an `outcome=allow` point and an `outcome=deny` point (both labeled
  `agent_id`), `agentos_violations_total` == 1 (the deny), and `agentos_pipeline_latency_ms` with 2
  recorded values > 0. Teardown `reset_metrics()` so metrics never leak to other tests. Run → fails.
- [ ] Implement the `evaluate()` change. Run → passes.
- [ ] Commit `feat(pipeline): record per-agent metrics from evaluate() (OBS-03)`.

---

### Task 3: full gate (latency with metrics on)
- [ ] `pytest -q` green; `-m floor_invariant` 430; `-m regression_lock` 10; `-m latency` 3 green on
  the DEFAULT no-op path.
- [ ] Add a `latency`-marked variant (mirroring 6a's `test_cached_path_latency_gate_with_tracing`)
  that runs the best-of-N gate with an `InMemoryMetricReader` configured, asserting the PIPE-04
  budget still holds with metrics recording on; `reset_metrics()` in teardown. Production uses a
  `PeriodicExportingMetricReader` (OTLP) off the hot path.
- [ ] Commit `test(pipeline): latency gate holds with metrics recording on (OBS-03)`.

## Self-review
OBS-03: `agentos_actions_total{agent_id,outcome}` gives per-agent volume + outcome mix,
`agentos_violations_total{agent_id}` counts non-allow outcomes, `agentos_pipeline_latency_ms{agent_id}`
feeds p95 — all recorded once per `evaluate()` from the same seam as the 6a span. Module-local
`MeterProvider` (no global footgun), no-op by default (zero-config hot path), in-memory-testable,
guarded so metrics never break governance. Instruments rebuilt on configure/reset so a reconfigure
binds to the live provider. Gates green; `-m latency` holds with metrics on and (default) off.
