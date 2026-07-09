"""OBS-01/02/03 telemetry seam (tracing + per-agent metrics).

`get_tracer()` returns a module-LOCAL `TracerProvider`'s tracer when one is configured
(via `configure_tracing`), else the OTel global tracer — which is a no-op until a global
provider is set. Since we never touch the global provider, the DEFAULT hot path pays
nothing; production wires an exporter (e.g. OTLP to the operator's backend, off the hot
path via an async BatchSpanProcessor) at startup, and tests install an in-memory exporter.

Why a module-local provider and not OTel's global one: `trace.set_tracer_provider()`
refuses to override an already-set provider (it warns and keeps the first), which would
silently break test isolation across configure/reset. Holding our own provider keeps
`configure_tracing` / `reset_tracing` fully re-callable.

Attribute names are centralized here (the OTel GenAI semconv is experimental — one edit
to rename). Telemetry must NEVER raise into governance: `annotate_decision_span` swallows.
"""

from __future__ import annotations

import contextlib

from opentelemetry import metrics, trace
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor

from agentos_contract import Outcome

_TRACER_NAME = "agentos_pipeline"
SPAN_NAME = "agentos.pipeline.evaluate"

# Our OWN provider, held module-locally (see module docstring for why not the global one).
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
    """Install a module-local `TracerProvider` exporting to `exporter` via a
    `SimpleSpanProcessor` (synchronous, so tests see finished spans immediately).
    Production passes an OTLP exporter (off the hot path, at startup); tests pass an
    `InMemorySpanExporter`. Fully re-callable — each call replaces the provider."""
    global _provider
    _provider = TracerProvider()
    _provider.add_span_processor(SimpleSpanProcessor(exporter))


def reset_tracing() -> None:
    """Drop the configured provider back to the no-op default (test isolation)."""
    global _provider
    _provider = None


def get_tracer():
    """The module provider's tracer when configured; otherwise the global tracer, which
    is a no-op when no global provider is set — a zero-cost default hot path."""
    if _provider is not None:
        return _provider.get_tracer(_TRACER_NAME)
    return trace.get_tracer(_TRACER_NAME)


@contextlib.contextmanager
def decision_span():
    """The one `evaluate()` span, acquired so telemetry can NEVER gate the verdict.

    Yields a live span, or None when tracing is a no-op OR anything in the span
    lifecycle throws. BOTH ends are guarded, because a span processor's hooks fire
    on the context-manager boundaries, not on the `start_as_current_span()` call:
    `on_start` (and the sampler) run inside `__enter__`, `on_end` inside `__exit__`.
    A misconfigured/throwing processor, sampler, or provider therefore degrades to a
    None span here instead of propagating out of `evaluate()`. The default hot path
    (no provider) is a no-op recording span, entered and exited at zero cost."""
    cm = None
    span = None
    try:
        cm = get_tracer().start_as_current_span(SPAN_NAME)
        span = cm.__enter__()
    except Exception:  # telemetry must never break governance
        cm = None
        span = None
    try:
        yield span
    finally:
        if cm is not None:
            try:
                cm.__exit__(None, None, None)
            except Exception:  # on_end / exporter flush must not gate the verdict
                pass


def annotate_decision_span(span, action, decision) -> None:
    """Record the decision on the span AFTER it is computed. Defensive: never raise into
    the hot path (a no-op span accepts `set_attribute` harmlessly; guard anyway). A None
    span (acquisition failed, see `decision_span`) short-circuits — nothing to annotate."""
    if span is None:
        return
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


# --- OBS-03 metrics seam ----------------------------------------------------------------
#
# Mirrors the tracing seam above: a MODULE-LOCAL `MeterProvider` (never OTel's global one —
# `metrics.set_meter_provider()` has the same override-once footgun as the tracer global,
# which would break test isolation across configure/reset). The DEFAULT hot path records
# into no-op instruments (the global meter has no provider), so it pays ~nothing; production
# wires a `PeriodicExportingMetricReader` (OTLP) off the hot path at startup, and tests
# install an `InMemoryMetricReader`.
#
# Instrument handles are rebuilt in BOTH `configure_metrics` and `reset_metrics` so a
# reconfigure binds them to the LIVE provider. Without the rebuild, a pre-built no-op
# instrument (bound to the no-provider global meter at import time) would keep swallowing
# every record even after a provider is configured.

_METER_NAME = "agentos_pipeline"

# Centralized metric names + label keys (the OTel semconv is experimental — one edit to rename).
METRIC_ACTIONS = "agentos_actions_total"
METRIC_VIOLATIONS = "agentos_violations_total"
METRIC_LATENCY = "agentos_pipeline_latency_ms"
LABEL_AGENT_ID = "agent_id"
LABEL_OUTCOME = "outcome"

# Our OWN provider, held module-locally (see the note above for why not the global one).
_meter_provider: MeterProvider | None = None


def _build_instruments(meter) -> dict:
    """Create the three OBS-03 instrument handles from `meter`. Called at import time
    (no-op global meter) and on every configure/reset so the handles track the live meter."""
    return {
        "actions": meter.create_counter(
            METRIC_ACTIONS, description="Governed actions evaluated, by outcome"
        ),
        "violations": meter.create_counter(
            METRIC_VIOLATIONS, description="Actions with a non-allow (restricted) outcome"
        ),
        "latency": meter.create_histogram(
            METRIC_LATENCY, unit="ms", description="Pipeline evaluate() wall latency"
        ),
    }


# No-op instruments at import: the global meter has no provider, so these record nothing
# until `configure_metrics` rebinds them to a real provider's meter.
_instruments: dict = _build_instruments(metrics.get_meter(_METER_NAME))


def configure_metrics(reader) -> None:
    """Install a module-local `MeterProvider` reading into `reader` and (re)build the
    instrument handles from ITS meter. Tests pass an `InMemoryMetricReader`; production
    passes a `PeriodicExportingMetricReader` (OTLP). Fully re-callable — each call replaces
    the provider AND rebinds the instruments, so the LIVE reader observes every record."""
    global _meter_provider, _instruments
    _meter_provider = MeterProvider(metric_readers=[reader])
    _instruments = _build_instruments(_meter_provider.get_meter(_METER_NAME))


def reset_metrics() -> None:
    """Drop the provider and rebuild no-op instruments from the global (no-provider) meter,
    restoring the zero-cost default hot path (test isolation)."""
    global _meter_provider, _instruments
    _meter_provider = None
    _instruments = _build_instruments(metrics.get_meter(_METER_NAME))


def record_decision_metrics(action, decision, latency_ms: float) -> None:
    """Record volume / outcome-mix / violation / latency for one decision, once per
    `evaluate()`. Guarded: telemetry must NEVER raise into governance. A violation is any
    non-allow (restricted) outcome. No-op by default (no provider configured)."""
    try:
        labels = {LABEL_AGENT_ID: action.agent_id}
        _instruments["actions"].add(1, {**labels, LABEL_OUTCOME: decision.outcome.value})
        if decision.outcome is not Outcome.allow:
            _instruments["violations"].add(1, labels)
        _instruments["latency"].record(latency_ms, labels)
    except Exception:  # telemetry must never break governance
        pass
