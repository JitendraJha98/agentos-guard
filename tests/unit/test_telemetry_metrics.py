"""OBS-03 unit tests for the `agentos_pipeline.telemetry` metrics seam.

Mirrors the 6a tracing seam: a MODULE-LOCAL `MeterProvider` (installed via
`configure_metrics`) makes metrics in-memory-testable, while the DEFAULT hot path
records into no-op instruments (no provider) at ~zero cost. `reset_metrics()`
restores that no-op default so metric state never leaks across tests. Instrument
handles are rebuilt on BOTH configure and reset so a reconfigure binds to the live
provider (a pre-built no-op instrument would otherwise keep swallowing). Telemetry
must NEVER raise into governance (`record_decision_metrics` swallows).
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest
from opentelemetry.sdk.metrics.export import InMemoryMetricReader

from agentos_contract import Outcome
from agentos_pipeline.telemetry import (
    METRIC_ACTIONS,
    METRIC_LATENCY,
    METRIC_VIOLATIONS,
    configure_metrics,
    record_decision_metrics,
    reset_metrics,
)


@dataclass
class _StubAction:
    agent_id: str


@dataclass
class _StubDecision:
    outcome: Outcome


class _RaisingDecision:
    @property
    def outcome(self):  # noqa: D401 - test stub that blows up on access
        raise RuntimeError("boom")


@pytest.fixture
def reader():
    """A fresh in-memory metric reader wired via `configure_metrics`; `reset_metrics()`
    on teardown so metric state never leaks to other tests."""
    reset_metrics()
    rd = InMemoryMetricReader()
    configure_metrics(rd)
    try:
        yield rd
    finally:
        reset_metrics()


def _points_by_name(reader) -> dict[str, list]:
    """Flatten the collected metrics data into {metric_name: [data_points]}."""
    out: dict[str, list] = {}
    data = reader.get_metrics_data()
    if data is None:
        return out
    for rm in data.resource_metrics:
        for sm in rm.scope_metrics:
            for metric in sm.metrics:
                out.setdefault(metric.name, []).extend(metric.data.data_points)
    return out


def test_records_actions_violations_and_latency_labeled_by_agent(reader):
    agent = _StubAction(agent_id="agent-1")
    record_decision_metrics(agent, _StubDecision(Outcome.deny), 3.2)
    record_decision_metrics(agent, _StubDecision(Outcome.allow), 1.0)

    points = _points_by_name(reader)

    # agentos_actions_total: one point per (agent_id, outcome) — volume + outcome mix.
    action_pts = {
        (p.attributes["agent_id"], p.attributes["outcome"]): p.value
        for p in points[METRIC_ACTIONS]
    }
    assert action_pts == {("agent-1", "deny"): 1, ("agent-1", "allow"): 1}

    # agentos_violations_total: counts the deny ONLY (non-allow outcome), labeled agent_id.
    violation_pts = {p.attributes["agent_id"]: p.value for p in points[METRIC_VIOLATIONS]}
    assert violation_pts == {"agent-1": 1}
    assert all("outcome" not in p.attributes for p in points[METRIC_VIOLATIONS])

    # agentos_pipeline_latency_ms: histogram recorded both evaluations, labeled agent_id.
    latency_pts = points[METRIC_LATENCY]
    assert len(latency_pts) == 1  # one series (agent-1)
    lp = latency_pts[0]
    assert lp.attributes["agent_id"] == "agent-1"
    assert lp.count == 2
    assert lp.sum == pytest.approx(4.2)


def test_allow_only_records_no_violation(reader):
    record_decision_metrics(_StubAction("agent-2"), _StubDecision(Outcome.allow), 2.0)
    points = _points_by_name(reader)
    assert METRIC_VIOLATIONS not in points  # never touched -> no series emitted
    assert {p.attributes["outcome"] for p in points[METRIC_ACTIONS]} == {"allow"}


@pytest.mark.parametrize(
    "restricted",
    [Outcome.deny, Outcome.require_approval, Outcome.sandbox, Outcome.warn],
)
def test_any_non_allow_outcome_counts_as_violation(reader, restricted):
    record_decision_metrics(_StubAction("agent-3"), _StubDecision(restricted), 1.5)
    points = _points_by_name(reader)
    assert {p.attributes["agent_id"] for p in points[METRIC_VIOLATIONS]} == {"agent-3"}


def test_noop_default_after_reset_records_nothing(reader):
    # The fixture configured a provider; drop it back to the no-op default.
    reset_metrics()
    record_decision_metrics(_StubAction("agent-4"), _StubDecision(Outcome.deny), 9.9)
    # The fixture's reader is no longer wired to any provider -> it observes nothing.
    assert _points_by_name(reader) == {}


def test_configure_metrics_is_re_callable(reader):
    # Reconfiguring must swap the provider AND rebind the instruments to the NEW reader
    # (proving instruments are rebuilt on configure, not left pointing at a stale meter).
    record_decision_metrics(_StubAction("agent-5"), _StubDecision(Outcome.allow), 1.0)
    reader2 = InMemoryMetricReader()
    configure_metrics(reader2)
    record_decision_metrics(_StubAction("agent-6"), _StubDecision(Outcome.deny), 2.0)

    first = _points_by_name(reader)
    second = _points_by_name(reader2)
    assert {p.attributes["agent_id"] for p in first[METRIC_ACTIONS]} == {"agent-5"}
    assert {p.attributes["agent_id"] for p in second[METRIC_ACTIONS]} == {"agent-6"}


def test_record_never_raises_into_governance(reader):
    # A decision whose .outcome raises must be swallowed — telemetry never breaks governance.
    record_decision_metrics(_StubAction("agent-7"), _RaisingDecision(), 1.0)
    # A totally malformed action (no agent_id) is likewise swallowed.
    record_decision_metrics(object(), _StubDecision(Outcome.allow), 1.0)
