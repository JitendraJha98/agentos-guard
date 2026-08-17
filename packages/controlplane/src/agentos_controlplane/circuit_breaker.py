"""RUN-06 — circuit breakers. A breaker trips an agent (or an agent+tool pair) after a threshold of
violations or errors inside a rolling window, denies while OPEN, admits ONE trial per cooldown, and
closes on a permitted trial.

Shape mirrors the other Phase-9 containment stores: the per-action lookup is IN-MEMORY (no DB read on
the hot path), transitions are persisted + audited, and state reloads at construction so a restart
cannot silently un-trip a breaker. Counters are deliberately NOT persisted — a rolling window is a
recent-history view; only the tripped state is durable.

A breaker is identified by the COMPOSITE key (scope, agent_id, target) — a tuple in memory, three PK
columns in the table, three fields in the audit body. Never a concatenated `f"{agent_id}|{target}"`:
both `agent_id` (free-form, self-service registration) and `target` (free-form) may contain `|`, so a
single-string key let one breaker ALIAS another in BOTH directions — an attacker's own tool breaker
could be a victim's agent breaker (denying it fleet-wide) and vice versa. Structural keys remove the
class of bug, the same way `AgentPrivilege`/`TargetPrivilege` keep separate dicts.

`now` is injectable for deterministic tests. It is WALL clock (not monotonic) because a reloaded OPEN
breaker must be able to compute how long it has been open across a process restart.

HALF_OPEN semantics: a non-closed breaker refuses until its cooldown elapses, then admits ONE trial
and RE-STAMPS its clock. So a trial whose verdict is never recorded (a PIPE-05 fail-safe records
nothing by design) leaves the breaker armed — it simply serves another cooldown — instead of being
permanently disarmed by a read, and a cooldown boundary can never admit a flood. The re-stamp is
in-memory only, because `status` is on the hot path and must not touch the DB; a restart therefore
re-serves the cooldown from the persisted `opened_at`, which is the contained direction.

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

# (scope, agent_id, target) — `target` is "" for the agent scope.
_Key = tuple[str, str, str]


@dataclass(frozen=True)
class BreakerVerdict:
    """Returned ONLY when the breaker refuses the action."""

    scope: str      # "agent" | "tool"
    agent_id: str
    target: str     # "" for the agent scope
    state: str      # "open" | "half_open"


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
        self._fails: dict[_Key, deque[float]] = {}   # key -> failure timestamps (rolling window)
        self._state: dict[_Key, tuple[str, float | None]] = {}  # key -> (state, opened_at)
        self._load()

    def _load(self) -> None:
        with self._sf() as s:
            for row in s.scalars(select(CircuitBreakerState)).all():
                if row.state != "closed":
                    self._state[(row.scope, row.agent_id, row.target)] = (row.state, row.opened_at)

    # ---- keys ----
    @staticmethod
    def _keys(agent_id: str, target: str) -> tuple[_Key, _Key]:
        """The two breakers an action touches, BROADEST FIRST: the agent, then the agent+tool pair."""
        return ((_AGENT, agent_id, ""), (_TOOL, agent_id, target))

    # ---- hot path (in-memory only) ----
    def status(self, agent_id: str, target: str) -> BreakerVerdict | None:
        """None == permitted. A verdict == refused. Checks the agent breaker first (broader), then
        the agent+tool pair. A breaker past its cooldown admits ONE trial and re-stamps its clock."""
        now = self._now()
        admit: list[_Key] = []
        for key in self._keys(agent_id, target):
            entry = self._state.get(key)
            if entry is None:
                continue
            state, opened_at = entry
            if opened_at is None or (now - opened_at) < self._cooldown_s:
                return BreakerVerdict(scope=key[0], agent_id=key[1], target=key[2], state=state)
            admit.append(key)
        # Consume the trial only once the action is actually permitted — a breaker whose cooldown
        # elapsed must not burn its admission on an action a NARROWER breaker refuses anyway.
        for key in admit:
            self._state[key] = ("half_open", now)
        return None

    # ---- signals ----
    async def record_failure(self, agent_id: str, target: str) -> None:
        """RUN-06 — one violation OR execution error. Trips either breaker that crosses the threshold,
        and immediately re-opens a HALF_OPEN breaker (a failed trial)."""
        t = self._now()
        for key in self._keys(agent_id, target):
            window = self._fails.setdefault(key, deque())
            window.append(t)
            cutoff = t - self._window_s
            while window and window[0] < cutoff:
                window.popleft()
            state = (self._state.get(key) or ("closed", None))[0]
            if state == "half_open" or len(window) >= self._threshold:
                if state != "open":
                    await self._trip(key, len(window))

    async def record_success(self, agent_id: str, target: str) -> None:
        """A PERMITTED DECISION closes a HALF_OPEN breaker (and clears its window).

        Recorded by the PDP at DECISION time — before the handler runs — so it says "this action was
        permitted", not "it executed successfully"; the execution-side failure signal arrives
        separately via the PEP's `CircuitReporter`.

        An OPEN breaker is deliberately untouched: it must serve its cooldown, or any unrelated
        allowed action would un-contain the agent instantly.
        """
        for key in self._keys(agent_id, target):
            if (self._state.get(key) or ("closed", None))[0] == "half_open":
                await self._close(key, reason="trial_succeeded")

    async def reset(self, scope: str, agent_id: str, target: str = "", *, set_by: str) -> None:
        """Explicit operator reset — the escape hatch for a stuck breaker. `scope` is EXPLICIT: it was
        once inferred from a `|` in the key, which mislabeled any `|`-containing agent id as a tool
        breaker in the audit body."""
        await self._close((scope, agent_id, target), reason="operator_reset", set_by=set_by)

    def list_open(self) -> list[dict]:
        return [
            {"scope": sc, "agent_id": aid, "target": tg, "state": st, "opened_at": oa}
            for (sc, aid, tg), (st, oa) in sorted(self._state.items())
            if st != "closed"
        ]

    # ---- transitions (durable + audited) ----
    async def _trip(self, key: _Key, observed: int) -> None:
        scope, agent_id, target = key
        opened_at = self._now()
        # Cache FIRST (mirroring KillSwitchStore._set): on the ARMING direction a durability failure
        # must fail toward CONTAINED — a database outage cannot be allowed to silently stop the
        # breaker from containing in-process while the agent keeps violating. The reconciler / next
        # restart repairs the row.
        self._state[key] = ("open", opened_at)
        with self._sf() as s:
            row = s.get(CircuitBreakerState, key)
            if row is None:
                s.add(
                    CircuitBreakerState(
                        scope=scope,
                        agent_id=agent_id,
                        target=target,
                        state="open",
                        opened_at=opened_at,
                        trip_count=1,
                    )
                )
            else:
                row.state, row.opened_at = "open", opened_at
                row.trip_count = (row.trip_count or 0) + 1
            s.commit()
        await self._audit.append_event(
            "circuit_tripped",
            {
                "scope": scope,
                "agent_id": agent_id,
                "target": target,
                "observed": observed,
                "threshold": self._threshold,
            },
        )

    async def _close(self, key: _Key, *, reason: str, set_by: str = "system") -> None:
        scope, agent_id, target = key
        with self._sf() as s:
            row = s.get(CircuitBreakerState, key)
            if row is not None:
                row.state, row.opened_at = "closed", None
                s.commit()
        await self._audit.append_event(
            "circuit_reset",
            {
                "scope": scope,
                "agent_id": agent_id,
                "target": target,
                "reason": reason,
                "set_by": set_by,
            },
        )
        # Un-contain the hot path only AFTER the durable steps succeed (fail-toward-contained).
        self._state.pop(key, None)
        self._fails.pop(key, None)
