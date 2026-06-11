"""CachingIdentityStage — the bounded PIPE-06 identity-verification TTL cache.

Behavior (Slice-3 Task 7):
  (a) two verifies of the same (token, agent_id) hit the underlying engine ONCE;
  (b) after ttl_seconds elapse (injected clock — no sleeping) the engine is hit again;
  (c) a FAILED verdict (ok=False) is NEVER cached — forged tokens always re-verify;
  (d) invalidate() clears everything (the policy-version-change hook);
  (e) bounded: max_entries+1 distinct tokens never grow the cache past max_entries.
"""

from agentos_contract import ActionType, AgentAction
from agentos_pipeline.identity import CachingIdentityStage


class _Verdict:
    def __init__(self, ok: bool, trust_score: float = 0.5, detail: str = "") -> None:
        self.ok = ok
        self.trust_score = trust_score
        self.detail = detail


class StubStage:
    """Counts verify calls; returns a preset verdict per token."""

    def __init__(self, ok: bool = True) -> None:
        self.calls = 0
        self._ok = ok

    def verify(self, action: AgentAction) -> _Verdict:
        self.calls += 1
        return _Verdict(ok=self._ok)


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def _action(token: str = "tok", agent_id: str = "agent-1") -> AgentAction:
    return AgentAction(
        agent_id=agent_id, type=ActionType.tool_call, target="http_get",
        payload={}, identity_token=token,
    )


def test_cache_hit_calls_engine_once() -> None:
    stub = StubStage(ok=True)
    cached = CachingIdentityStage(stub, ttl_seconds=60, max_entries=1024)
    assert cached.verify(_action()).ok
    assert cached.verify(_action()).ok
    assert stub.calls == 1  # second verify served from the cache


def test_ttl_expiry_reverifies() -> None:
    stub = StubStage(ok=True)
    clock = FakeClock()
    cached = CachingIdentityStage(stub, ttl_seconds=60, max_entries=1024, clock=clock)
    cached.verify(_action())
    clock.now = 60.0  # exactly ttl elapsed -> stale
    cached.verify(_action())
    assert stub.calls == 2


def test_failed_verdict_is_never_cached() -> None:
    stub = StubStage(ok=False)
    cached = CachingIdentityStage(stub, ttl_seconds=60, max_entries=1024)
    assert not cached.verify(_action(token="forged")).ok
    assert not cached.verify(_action(token="forged")).ok
    assert stub.calls == 2  # forged tokens ALWAYS re-verify


def test_invalidate_clears_everything() -> None:
    stub = StubStage(ok=True)
    cached = CachingIdentityStage(stub, ttl_seconds=60, max_entries=1024)
    cached.verify(_action())
    cached.invalidate()  # the policy-version-change hook
    cached.verify(_action())
    assert stub.calls == 2


def test_bounded_never_exceeds_max_entries() -> None:
    stub = StubStage(ok=True)
    cached = CachingIdentityStage(stub, ttl_seconds=60, max_entries=8)
    for i in range(9):  # max_entries + 1 distinct tokens
        cached.verify(_action(token=f"tok-{i}"))
    assert len(cached._cache) <= 8


def test_eviction_is_fifo_oldest_first() -> None:
    stub = StubStage(ok=True)
    cached = CachingIdentityStage(stub, ttl_seconds=60, max_entries=2)
    cached.verify(_action(token="a"))
    cached.verify(_action(token="b"))
    cached.verify(_action(token="c"))  # evicts "a"
    cached.verify(_action(token="b"))  # still cached
    assert stub.calls == 3
    cached.verify(_action(token="a"))  # was evicted -> re-verify
    assert stub.calls == 4
