"""Phase 15 — keep every control-plane instance's hot-path caches within a bounded staleness.

The kill switch, circuit breakers, privilege rings, resource limits, identity cache and budget
ledger answer the hot path from memory — the PIPE-04 budget depends on it. With one instance the
memory is the truth. With several, a kill set through instance A was invisible to instance B.

Mechanism: a write bumps its topic's row in `control_state_version` IN THE SAME TRANSACTION as the
change (so a committed change always has a committed bump), and each instance polls that one small
table every `poll_interval_s`, reloading any topic whose version moved.

Freshness is enforced, not hoped for. Every successful poll stamps `confirmed_at`; if the poller
stops (DB down, thread dead, a reload that raises), `assert_fresh()` starts raising once
`max_staleness_s` has passed. The kill-switch lookup — stage 0, on every action — calls it, so a
stale instance falls into the PIPE-05 per-class failure posture (fail-CLOSED by default) instead of
enforcing state it can no longer vouch for.

Why polling rather than LISTEN/NOTIFY: the bound the design promises (<= 1 s) is met by a 200 ms
poll of a table with six rows, on any backend, with no dedicated connection to keep alive and
reconnect. NOTIFY would only shorten the typical lag; the poll would still be needed as the
backstop, so it would be a second mechanism for the same guarantee.

Bounded by design, stated plainly: circuit-breaker FAILURE COUNTS and HALF-OPEN TRIALS stay per
instance (only trips and resets are shared), so with N instances an agent can need up to
N x threshold failures before a trip, and a cooled-down breaker admits up to N trial actions.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Callable

from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from agentos_controlplane.store.models import ControlStateVersion

log = logging.getLogger(__name__)

TOPICS = frozenset(
    {"kill_switch", "breaker", "privilege", "resource_limits", "identity", "budget",
     "mcp_quarantine"}
)


class ControlStateStale(RuntimeError):
    """This instance cannot vouch that its control state is current (PIPE-05 fail posture)."""


class ControlStateBus:
    def __init__(
        self,
        session_factory,
        *,
        poll_interval_s: float = 0.2,
        max_staleness_s: float = 1.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not 0 < poll_interval_s < max_staleness_s:
            raise ValueError("need 0 < poll_interval_s < max_staleness_s")
        self._sf = session_factory
        self._interval = poll_interval_s
        self._max_staleness = max_staleness_s
        self._clock = clock
        self._subs: dict[str, list[Callable[[], object]]] = {}
        self._seen: dict[str, int] = {}
        self._confirmed_at: float | None = None
        self._poll_lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # ---- wiring ----
    def attach(self, topic: str, reload: Callable[[], object]) -> None:
        """Call `reload` whenever `topic` changes. The first poll reloads every attached topic,
        which closes the gap between a store's constructor load and the bus starting."""
        if topic not in TOPICS:
            raise ValueError(f"unknown control-state topic: {topic!r}")
        self._subs.setdefault(topic, []).append(reload)

    def wire(self, *participants) -> "ControlStateBus":
        """Attach every store/writer (anything with `attach_bus`) and return self. Any other object
        with an `invalidate()` — the pipeline's identity cache — subscribes to `identity`."""
        for p in participants:
            if hasattr(p, "attach_bus"):
                p.attach_bus(self)
            elif hasattr(p, "invalidate"):
                self.attach("identity", p.invalidate)
            else:
                raise TypeError(f"{type(p).__name__} cannot join the control-state bus")
        return self

    # ---- write side ----
    def bump(self, session, topic: str) -> None:
        """Advance `topic`'s version inside the caller's transaction (commits with the change)."""
        if topic not in TOPICS:
            raise ValueError(f"unknown control-state topic: {topic!r}")
        stmt = (
            update(ControlStateVersion)
            .where(ControlStateVersion.topic == topic)
            .values(version=ControlStateVersion.version + 1)
        )
        if session.execute(stmt).rowcount:
            return
        # First bump ever for this topic. Two instances can race here, so the insert must be
        # conflict-tolerant; the UPDATE that follows is then guaranteed to find the row.
        dialect = session.get_bind().dialect.name
        insert = pg_insert if dialect == "postgresql" else sqlite_insert
        session.execute(
            insert(ControlStateVersion)
            .values(topic=topic, version=0)
            .on_conflict_do_nothing(index_elements=["topic"])
        )
        session.execute(stmt)

    # ---- read side ----
    def poll_once(self) -> set[str]:
        """Reload every attached topic whose version moved; stamp freshness if all succeeded.

        A reload that raises leaves that topic's version unseen (so the next poll retries it) and
        withholds the freshness stamp, so a persistently broken reload ages this instance into the
        fail-closed posture rather than silently serving what it last loaded.
        """
        with self._poll_lock:
            with self._sf() as s:
                versions = dict(
                    s.execute(select(ControlStateVersion.topic, ControlStateVersion.version)).all()
                )
            changed: set[str] = set()
            ok = True
            for topic, reloads in self._subs.items():
                current = versions.get(topic, 0)
                if topic in self._seen and self._seen[topic] == current:
                    continue
                try:
                    for reload in reloads:
                        reload()
                except Exception:
                    log.exception("agentos-guard: reload of control state %r failed", topic)
                    ok = False
                    continue
                self._seen[topic] = current
                changed.add(topic)
            if ok:
                self._confirmed_at = self._clock()
            return changed

    def is_fresh(self) -> bool:
        return (
            self._confirmed_at is not None
            and self._clock() - self._confirmed_at <= self._max_staleness
        )

    def assert_fresh(self) -> None:
        if not self.is_fresh():
            raise ControlStateStale(
                f"control state not confirmed within {self._max_staleness}s on this instance"
            )

    # ---- lifecycle ----
    def start(self) -> None:
        """Poll once synchronously (so the instance starts fresh), then keep polling."""
        self.poll_once()
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="agentos-state-bus", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join()
            self._thread = None

    def _run(self) -> None:
        while not self._stop.wait(self._interval):
            try:
                self.poll_once()
            except Exception:
                # DB unreachable: no stamp, so assert_fresh() starts failing after the bound.
                log.exception("agentos-guard: control-state poll failed")


class SharedStateWriter:
    """For a writer that changes shared state but caches none itself (e.g. the registry changing
    what the identity cache holds): `attach_bus()` + `bump_in(session)`, no subscription."""

    _topic: str = ""
    _bus: ControlStateBus | None = None

    def attach_bus(self, bus: ControlStateBus) -> None:
        self._bus = bus

    def bump_in(self, session) -> None:
        if self._bus is not None:
            self._bus.bump(session, self._topic)


class SharedStateMixin(SharedStateWriter):
    """Gives a store an optional bus: `attach_bus()` subscribes its `_load`, and `bump_in(session)`
    advances its topic inside a write transaction. No bus -> both are no-ops (single instance)."""

    @property
    def _state_lock(self) -> threading.RLock:
        """Held across a local write's commit + cache update AND across a bus reload, so a reload
        that read the table just before the commit cannot swap the older state back in after it."""
        lock = self.__dict__.get("_state_lock_obj")
        if lock is None:
            lock = self.__dict__.setdefault("_state_lock_obj", threading.RLock())
        return lock

    def attach_bus(self, bus: ControlStateBus) -> None:
        self._bus = bus
        bus.attach(self._topic, self._locked_load)

    def _locked_load(self) -> None:
        with self._state_lock:
            self._load()
