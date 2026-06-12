"""Cached-path latency GATE — PIPE-04 (Slice 6c). This IS the budget gate.

Measures the full wired hot path — identity -> enrichment -> compiled-constitution
WASM floor -> risk -> graduated -> SQLite hash-chained audit append — for a benign
allowlisted http_get. Every round evaluates a FRESH action (unique action.id), so
the audit chain genuinely appends each time; nothing is decision-cached (PIPE-06).

CI-gating budget (the real one, not a smoke ceiling): p95 < 10 ms AND mean < 5 ms.
Headroom is real, not aspirational — the audit writer caches its chain head inside
the writer lock (Slice 6c), so the hot path is one INSERT, not SELECT+INSERT.
A regression above budget means FIX the hot path, never loosen the budget.
"""

import asyncio

import pytest

from agentos_contract import ActionType, AgentAction, Outcome

pytestmark = pytest.mark.latency


@pytest.mark.latency
def test_cached_path_latency_gate(benchmark, pipeline_with_principle) -> None:
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
    # PIPE-04: the CI-gating budget. Both bounds must hold.
    assert p95 < 0.010, f"p95 {p95 * 1000:.3f} ms exceeds the 10 ms budget (PIPE-04)"
    assert stats.mean < 0.005, (
        f"mean {stats.mean * 1000:.3f} ms exceeds the 5 ms budget (PIPE-04)"
    )
