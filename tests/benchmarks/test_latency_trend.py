"""Cached-path latency TREND baseline (PIPE-04 seed; Slice-3 Task 8).

Measures the full wired hot path — identity -> enrichment -> compiled-constitution
WASM floor -> risk -> graduated -> SQLite hash-chained audit append — for a benign
allowlisted http_get. Every round evaluates a FRESH action (unique action.id), so
the audit chain genuinely appends each time; nothing is decision-cached (PIPE-06).

The asserted mean<50ms ceiling DOES gate CI — it is a deliberately generous smoke
ceiling (non-flaky, catches order-of-magnitude regressions) that records the trend
baseline. The hard p95 budget gate arrives in Slice 6c (PIPE-04).
"""

import asyncio

import pytest

from agentos_contract import ActionType, AgentAction, Outcome

pytestmark = pytest.mark.latency


@pytest.mark.latency
def test_cached_path_latency_trend(benchmark, pipeline_with_principle) -> None:
    wired = pipeline_with_principle

    def run_once() -> None:
        # FRESH action per round: a unique action.id, so the audit chain appends.
        action = AgentAction(
            agent_id=wired.agent_id,
            type=ActionType.tool_call,
            target="http_get",
            payload={"url": "https://api.example.com/data", "content": ""},
            identity_token=wired.token,
        )
        decision = asyncio.run(wired.pipeline.evaluate(action))
        assert decision.outcome is Outcome.allow  # the benign baseline path

    benchmark.pedantic(run_once, rounds=220, warmup_rounds=5)

    stats = benchmark.stats.stats
    data = sorted(stats.data)
    p95 = data[int(0.95 * (len(data) - 1))]
    print(
        f"\ncached-path latency: mean={stats.mean * 1000:.3f} ms  "
        f"p95={p95 * 1000:.3f} ms  rounds={len(data)}"
    )
    # CI-gating generous smoke ceiling (hard budget gate arrives in Slice 6c).
    assert stats.mean < 0.050
