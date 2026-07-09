"""OBS-01/02 telemetry seam.

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

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor

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


def annotate_decision_span(span, action, decision) -> None:
    """Record the decision on the span AFTER it is computed. Defensive: never raise into
    the hot path (a no-op span accepts `set_attribute` harmlessly; guard anyway)."""
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
