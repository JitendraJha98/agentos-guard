"""Cached-path latency GATE — PIPE-04 (Slice 6c). This IS the budget gate.

Measures the full wired hot path — identity -> enrichment (+SEC-13 correlator) ->
compiled-constitution WASM floor -> risk -> graduated -> SQLite hash-chained audit
append — for a benign allowlisted http_get. Every round evaluates a FRESH action
(unique action.id), so the audit chain genuinely appends each time; nothing is
decision-cached (PIPE-06).

CI-gating budget (the real one, not a smoke ceiling): p95 < 10 ms AND mean < 5 ms.
A regression above budget means FIX the hot path, never loosen the budget.

Preemption robustness (Pitfall 12 — flaky gates breed re-run-until-green): on a
loaded Windows box the OS scheduler quantum (~15.6 ms) injects occasional wall-time
stalls that dominate tail percentiles while the mean stays honest. When ONLY the
tail breaches, the measurement is re-taken once on a fresh sample; a real hot-path
regression breaches the budget in BOTH passes (and the mean bound has no retry).
"""

import asyncio
import time

import pytest

from agentos_contract import ActionType, AgentAction, Outcome

pytestmark = pytest.mark.latency

_ROUNDS = 220
_P95_BUDGET_S = 0.010
_MEAN_BUDGET_S = 0.005


def _measure(wired) -> tuple[float, float]:
    """One sample: (mean, p95) over _ROUNDS fresh evaluations, wall time."""
    times: list[float] = []
    for _ in range(_ROUNDS):
        action = AgentAction(
            agent_id=wired.agent_id,
            type=ActionType.tool_call,
            target="http_get",
            payload={"url": "https://api.example.com/data", "content": ""},
            identity_token=wired.token,
        )
        start = time.perf_counter()
        decision = asyncio.run(wired.pipeline.evaluate(action))
        times.append(time.perf_counter() - start)
        assert decision.outcome is Outcome.allow  # the benign baseline path
    times.sort()
    mean = sum(times) / len(times)
    p95 = times[int(0.95 * (len(times) - 1))]
    return mean, p95


@pytest.mark.latency
def test_cached_path_latency_gate(pipeline_with_principle) -> None:
    wired = pipeline_with_principle
    # Warmup (WASM instantiation, identity key parse, SQLite first write).
    for _ in range(5):
        action = AgentAction(
            agent_id=wired.agent_id, type=ActionType.tool_call, target="http_get",
            payload={"url": "https://api.example.com/data", "content": ""},
            identity_token=wired.token,
        )
        asyncio.run(wired.pipeline.evaluate(action))

    mean, p95 = _measure(wired)
    print(f"\ncached-path latency: mean={mean * 1000:.3f} ms  p95={p95 * 1000:.3f} ms  rounds={_ROUNDS}")
    if p95 >= _P95_BUDGET_S and mean < _MEAN_BUDGET_S:
        # Tail-only breach: almost certainly scheduler preemption — one fresh sample.
        mean, p95 = _measure(wired)
        print(f"re-measure:          mean={mean * 1000:.3f} ms  p95={p95 * 1000:.3f} ms  rounds={_ROUNDS}")

    # PIPE-04: the CI-gating budget. Both bounds must hold (mean has NO retry).
    assert p95 < _P95_BUDGET_S, f"p95 {p95 * 1000:.3f} ms exceeds the 10 ms budget (PIPE-04)"
    assert mean < _MEAN_BUDGET_S, f"mean {mean * 1000:.3f} ms exceeds the 5 ms budget (PIPE-04)"
