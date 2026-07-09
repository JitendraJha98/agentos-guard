"""OBS-01/02 unit tests for the `agentos_pipeline.telemetry` seam.

A MODULE-LOCAL `TracerProvider` (installed via `configure_tracing`) makes spans
in-memory-testable, while `get_tracer()` is a zero-cost no-op when no provider is
configured (the default hot path). `reset_tracing()` restores that no-op default so
tracing state never leaks across tests. `configure_tracing` must be fully re-callable
(a module-local provider, NOT OTel's global one — which refuses to override once set).
Telemetry must never raise into governance (`annotate_decision_span` swallows).
"""

from __future__ import annotations

import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from agentos_pipeline.telemetry import (
    annotate_decision_span,
    configure_tracing,
    get_tracer,
    reset_tracing,
)


@pytest.fixture
def exporter():
    """A fresh in-memory exporter wired via `configure_tracing`; `reset_tracing()` on
    teardown so tracing state never leaks to other tests."""
    reset_tracing()
    exp = InMemorySpanExporter()
    configure_tracing(exp)
    try:
        yield exp
    finally:
        reset_tracing()


def test_configured_tracer_captures_one_finished_span(exporter):
    with get_tracer().start_as_current_span("t"):
        pass
    spans = exporter.get_finished_spans()
    assert len(spans) == 1
    assert spans[0].name == "t"


def test_span_is_recording_when_configured(exporter):
    with get_tracer().start_as_current_span("t") as span:
        assert span.is_recording()


def test_noop_default_after_reset_records_nothing(exporter):
    # The fixture configured a provider; drop it back to the no-op default.
    reset_tracing()
    with get_tracer().start_as_current_span("x") as span:
        # No global provider is set, so the global tracer yields a NON-recording span:
        # it must neither raise nor record anything.
        assert span.is_recording() is False
    assert exporter.get_finished_spans() == ()


def test_configure_tracing_is_re_callable(exporter):
    # Reconfiguring must swap the provider cleanly (no "provider already set" refusal)
    # and route spans to the NEW exporter — proving a module-local, not global, provider.
    exp2 = InMemorySpanExporter()
    configure_tracing(exp2)
    with get_tracer().start_as_current_span("second"):
        pass
    assert [s.name for s in exp2.get_finished_spans()] == ["second"]
    assert exporter.get_finished_spans() == ()  # the first exporter saw nothing


def test_annotate_never_raises_into_governance(exporter):
    # Malformed action/decision: annotate must swallow the failure, never propagate it.
    with get_tracer().start_as_current_span("t") as span:
        annotate_decision_span(span, object(), object())
