"""RUN-06 — circuit breakers. A breaker trips an agent (or an agent+tool pair) after a threshold of
violations or errors inside a rolling window, denies while OPEN, admits trials after a cooldown, and
closes on a successful trial.

Shape mirrors the other Phase-9 containment stores: the per-action lookup is IN-MEMORY (no DB read on
the hot path), transitions are persisted + audited, and state reloads at construction so a restart
cannot silently un-trip a breaker. Counters are deliberately NOT persisted — a rolling window is a
recent-history view; only the tripped state is durable.

`now` is injectable for deterministic tests. It is WALL clock (not monotonic) because a reloaded OPEN
breaker must be able to compute how long it has been open across a process restart.

HALF_OPEN semantics (documented simplification): the state admits trial traffic rather than exactly one
request; the first violation re-opens it and the first success closes it. Strict single-trial admission
would need cross-process coordination, which is Phase-7 reconciler territory.

Who feeds this store matters as much as the state machine — see the pipeline's Stage 1f: signals come
from the GRADUATED path only. Counting the breaker's own denials would let an OPEN breaker feed itself
and never close, and counting pre-identity denials would let a forged agent_id trip somebody else's
breaker.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass
from typing import Callable

from sqlalchemy import select

from agentos_controlplane.store.models import CircuitBreakerState

_AGENT, _TOOL = "agent", "tool"


@dataclass(frozen=True)
class BreakerVerdict:
    """Returned ONLY when the breaker refuses the action."""

    key: str
    scope: str   # "agent" | "tool"
    state: str   # "open"


class CircuitBreakerStore:
    def __init__(
        self,
        session_factory,
        audit,
        *,
        failure_threshold: int = 5,
        window_s: float = 60.0,
        cooldown_s: float = 30.0,
        now: Callable[[], float] = time.time,
    ) -> None:
        if failure_threshold < 1:
            raise ValueError("failure_threshold must be >= 1")
        self._sf = session_factory
        self._audit = audit
        self._threshold = failure_threshold
        self._window_s = window_s
        self._cooldown_s = cooldown_s
        self._now = now
        self._fails: dict[str, deque[float]] = {}   # key -> failure timestamps (rolling window)
        self._state: dict[str, tuple[str, float | None]] = {}  # key -> (state, opened_at)
        self._load()

    def _load(self) -> None:
        with self._sf() as s:
            for row in s.scalars(select(CircuitBreakerState)).all():
                if row.state != "closed":
                    self._state[row.key] = (row.state, row.opened_at)

    # ---- keys ----
    @staticmethod
    def _keys(agent_id: str, target: str) -> tuple[tuple[str, str], tuple[str, str]]:
        """The two breakers an action touches, BROADEST FIRST: the agent, then the agent+tool pair."""
        return ((agent_id, _AGENT), (f"{agent_id}|{target}", _TOOL))

    # ---- hot path (in-memory only) ----
    def status(self, agent_id: str, target: str) -> BreakerVerdict | None:
        """None == permitted. A verdict == refused. Checks the agent breaker first (broader), then
        the agent+tool pair. An OPEN breaker past its cooldown becomes HALF_OPEN and permits."""
        for key, scope in self._keys(agent_id, target):
            entry = self._state.get(key)
            if entry is None:
                continue
            state, opened_at = entry
            if state == "open":
                if opened_at is not None and (self._now() - opened_at) >= self._cooldown_s:
                    self._state[key] = ("half_open", opened_at)  # cooldown elapsed -> admit trials
                    continue
                return BreakerVerdict(key=key, scope=scope, state="open")
        return None

    # ---- signals ----
    async def record_failure(self, agent_id: str, target: str) -> None:
        """RUN-06 — one violation OR execution error. Trips either breaker that crosses the threshold,
        and immediately re-opens a HALF_OPEN breaker (a failed trial)."""
        t = self._now()
        for key, scope in self._keys(agent_id, target):
            window = self._fails.setdefault(key, deque())
            window.append(t)
            cutoff = t - self._window_s
            while window and window[0] < cutoff:
                window.popleft()
            state = (self._state.get(key) or ("closed", None))[0]
            if state == "half_open" or len(window) >= self._threshold:
                if state != "open":
                    await self._trip(key, scope, len(window))

    async def record_success(self, agent_id: str, target: str) -> None:
        """A successful execution closes a HALF_OPEN breaker (and clears its window).

        An OPEN breaker is deliberately untouched: it must serve its cooldown, or any unrelated
        allowed action would un-contain the agent instantly.
        """
        for key, scope in self._keys(agent_id, target):
            if (self._state.get(key) or ("closed", None))[0] == "half_open":
                await self._close(key, scope, reason="trial_succeeded")

    async def reset(self, key: str, *, set_by: str) -> None:
        """Explicit operator reset."""
        scope = _TOOL if "|" in key else _AGENT
        await self._close(key, scope, reason="operator_reset", set_by=set_by)

    def list_open(self) -> list[dict]:
        return [
            {"key": k, "state": st, "opened_at": oa}
            for k, (st, oa) in sorted(self._state.items())
            if st != "closed"
        ]

    # ---- transitions (durable + audited) ----
    async def _trip(self, key: str, scope: str, observed: int) -> None:
        opened_at = self._now()
        with self._sf() as s:
            row = s.get(CircuitBreakerState, key)
            if row is None:
                s.add(
                    CircuitBreakerState(
                        key=key, scope=scope, state="open", opened_at=opened_at, trip_count=1
                    )
                )
            else:
                row.state, row.opened_at = "open", opened_at
                row.trip_count = (row.trip_count or 0) + 1
            s.commit()
        self._state[key] = ("open", opened_at)  # cache AFTER the commit (no divergence)
        await self._audit.append_event(
            "circuit_tripped",
            {"key": key, "scope": scope, "observed": observed, "threshold": self._threshold},
        )

    async def _close(self, key: str, scope: str, *, reason: str, set_by: str = "system") -> None:
        with self._sf() as s:
            row = s.get(CircuitBreakerState, key)
            if row is not None:
                row.state, row.opened_at = "closed", None
                s.commit()
        await self._audit.append_event(
            "circuit_reset", {"key": key, "scope": scope, "reason": reason, "set_by": set_by}
        )
        # Un-contain the hot path only AFTER the durable steps succeed (fail-toward-contained).
        self._state.pop(key, None)
        self._fails.pop(key, None)
