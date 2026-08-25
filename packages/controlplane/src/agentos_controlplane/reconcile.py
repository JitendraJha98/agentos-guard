"""API-04 — reconciliation loops.

Everything the control plane derives from authored state — compiled policy,
reputation, the materialized inventory, the hot-path caches — drifts. A write
can land while a compile fails, a restart can drop a warm cache, an agent can
misbehave between trust refreshes. Reconciliation is the control-plane pattern
for that: instead of trusting every write path to update every derived view
transactionally, loops re-derive continuously and converge.

The four loops the requirement names, each a `Reconciler` here:

  * `ConstitutionReconciler` — every stored Constitution has a compiled Policy;
  * `TrustReconciler`        — refresh TRST-03 reputation from audit history;
  * `GraphReconciler`        — materialize observed components from activity;
  * `CacheReconciler`        — warm/invalidate the hot-path caches on version change.

## The loop's contract

A reconciler reports how many items it CHANGED. Zero means converged, which is
what makes the pass idempotent and the number meaningful: a loop reporting
constant churn is a bug, not activity.

**Failures are isolated and surfaced, never swallowed.** One reconciler throwing
must not stop its siblings (they are independent) and must not kill the loop (a
dead reconciliation loop rots every derived view silently, which is strictly
worse than a noisy one). Each pass yields a `ReconcilerResult` per reconciler,
including the failures, and the `on_result` sink is itself guarded — an
observability sink must never be able to halt governance state.

Reconcilers are SYNCHRONOUS callables run in a thread via `asyncio.to_thread`:
they do blocking SQLAlchemy I/O, and running that on the event loop would stall
the pipeline's async audit writes.

The one exception is a reconciler whose work is genuinely awaiting something —
TEST-08's validation pass drives the LIVE pipeline — which declares itself by
exposing `reconcile_async` instead, and is awaited on the loop. Two shapes rather
than one because the choice is not stylistic: blocking DB I/O on the loop stalls
the hot path, and a coroutine driven from a worker thread would need a SECOND
event loop for state that belongs to the first.

That exception is not clean, and pretending otherwise would misread the rule.
`ValidationStore.record` is `async def` over a blocking SQLAlchemy body, so the
async reconciler does put some blocking DB I/O on the loop after all — the same
thing `AuditWriter.append_event` already does on the hot path. It is tolerated
here for the same reason and no better one: it is a handful of rows every fifteen
minutes. The loop affinity above is what forces the shape; the DB half is a cost
this reconciler pays, not a property it has.

An async reconciler is also the only shape that can WEDGE the loop: `run_once` is
sequential and `_loop` awaits it, so an unbounded await stops every sibling and
`stop()` with it. Bounding the wait is the reconciler's job — see
`ValidationReconciler._suite_timeout_s`.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Callable, Protocol, runtime_checkable

# A reconciler pass that finds nothing to do is the steady state, so intervals are
# chosen for staleness tolerance, not cost:
DEFAULT_INTERVALS = {
    "constitution": 30.0,  # a missing compile blocks enforcement — notice fast
    "trust": 60.0,         # reputation moves slowly; a minute of staleness is fine
    "graph": 120.0,        # inventory is descriptive, not enforcing
    "cache": 15.0,         # a stale policy cache enforces the WRONG constitution
    # ECON-02: tighter than trust because spend does NOT move slowly — a runaway loop burns a
    # budget in seconds, and this interval is how far a multi-process fleet's view of spend can lag.
    "budget": 30.0,
    # TEST-08: the most expensive pass here, and NOT pure CPU. Each probe drives the full PDP: a
    # synchronous audit append on the same serialized write path the hot path uses, plus — on policy
    # `no_match`, which is much of a red-team corpus — a remote interpreter call of up to 20s. So a
    # pass is ~N audit appends and up to N provider calls, against live traffic. 15 minutes is often
    # enough to catch a regression the same working day and rare enough that the contention is
    # negligible; it is not free.
    "validation": 900.0,
}


@runtime_checkable
class Reconciler(Protocol):
    """One derived view that can be re-derived. `reconcile()` returns items changed."""

    name: str
    interval_s: float

    def reconcile(self) -> int: ...


@runtime_checkable
class AsyncReconciler(Protocol):
    """A reconciler whose work is genuinely awaited (TEST-08 drives the live pipeline).

    A DIFFERENT method name, not an `async def reconcile`, and that is the point: the loop would
    hand an async `reconcile` to `asyncio.to_thread`, `int()` the coroutine it got back, and report
    a TypeError every pass while the work never ran. Naming the shape makes the mismatch unable to
    happen quietly.
    """

    name: str
    interval_s: float

    async def reconcile_async(self) -> int: ...


AnyReconciler = Reconciler | AsyncReconciler


@dataclass(frozen=True)
class ReconcilerResult:
    """One reconciler's outcome for one pass."""

    name: str
    changed: int = 0
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


def periodic(
    reconcilers: list[AnyReconciler], *, last_run: dict[str, float], now: float
) -> list[AnyReconciler]:
    """The reconcilers due at `now`, each on its OWN interval.

    A reconciler with no recorded run is always due, so a fresh loop converges
    everything on its first pass rather than waiting out the longest interval.
    """
    return [
        r for r in reconcilers if now - last_run.get(r.name, float("-inf")) >= r.interval_s
    ]


class ReconciliationLoop:
    """Runs reconcilers on their own intervals, isolating failures (API-04)."""

    def __init__(
        self,
        reconcilers: list[AnyReconciler],
        *,
        on_result: Callable[[ReconcilerResult], None] | None = None,
        tick_s: float = 1.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._reconcilers = list(reconcilers)
        self._on_result = on_result
        self._tick_s = tick_s
        self._clock = clock
        self._last_run: dict[str, float] = {}
        self._task: asyncio.Task | None = None
        self._stopping = asyncio.Event()

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    async def _run(self, r: AnyReconciler) -> ReconcilerResult:
        try:
            if hasattr(r, "reconcile_async"):
                # Awaited HERE rather than in a thread: this shape's work is awaiting collaborators
                # (the live pipeline) whose async state is bound to THIS loop.
                changed = await r.reconcile_async()
            else:
                # to_thread: reconcilers do blocking DB I/O; on the event loop they
                # would stall the pipeline's async audit writes.
                changed = await asyncio.to_thread(r.reconcile)
            return ReconcilerResult(r.name, changed=int(changed))
        except Exception as exc:
            # Isolation: a broken reconciler degrades ONE derived view, and says so.
            return ReconcilerResult(r.name, error=f"{type(exc).__name__}: {exc}")

    def _emit(self, result: ReconcilerResult) -> None:
        if self._on_result is None:
            return
        try:
            self._on_result(result)
        except Exception:
            # The sink is observability. It may never halt reconciliation.
            pass

    async def run_once(self, reconcilers: list[AnyReconciler] | None = None) -> list[ReconcilerResult]:
        """Run one pass over `reconcilers` (default: all). Never raises."""
        results = []
        for r in reconcilers if reconcilers is not None else self._reconcilers:
            result = await self._run(r)
            self._last_run[r.name] = self._clock()
            self._emit(result)
            results.append(result)
        return results

    async def _loop(self) -> None:
        while not self._stopping.is_set():
            due = periodic(self._reconcilers, last_run=self._last_run, now=self._clock())
            if due:
                await self.run_once(due)
            try:
                # wait_for on the stop event, so stop() is responsive rather than
                # blocking for a full tick.
                await asyncio.wait_for(self._stopping.wait(), timeout=self._tick_s)
            except asyncio.TimeoutError:
                pass

    async def start(self) -> None:
        if self.running:
            return
        self._stopping.clear()
        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        self._stopping.set()
        if self._task is not None:
            await self._task
            self._task = None


# --------------------------------------------------------------- the four loops


class ConstitutionReconciler:
    """Every stored Constitution must have a compiled Policy (API-02/API-04).

    A Constitution whose compile failed — or whose Policy row was lost — leaves
    the control plane unable to enforce it. `apply_constitution` is idempotent on
    the content-hash version, so re-applying a converged Constitution is a no-op
    and this counts only genuine repairs.
    """

    name = "constitution"

    def __init__(self, resources, *, interval_s: float = DEFAULT_INTERVALS["constitution"]) -> None:
        self._resources = resources
        self.interval_s = interval_s

    def reconcile(self) -> int:
        repaired = 0
        for con in self._resources.list_constitutions():
            if self._resources.get_policy(con.version) is not None:
                continue
            # Recompile from the authored source; the version is a content hash, so
            # a successful compile lands on exactly the row that was missing.
            self._resources.apply_constitution(con.name, con.source)
            repaired += 1
        return repaired


class TrustReconciler:
    """Refresh every agent's TRST-03 reputation from its audit/approval history.

    Counts an agent as changed only when its score actually MOVED, so a converged
    fleet reports zero rather than "changed: 400" every minute.
    """

    name = "trust"

    def __init__(self, reputation, *, interval_s: float = DEFAULT_INTERVALS["trust"], epsilon: float = 1e-9) -> None:
        self._reputation = reputation
        self.interval_s = interval_s
        self._epsilon = epsilon
        self._last: dict[str, float] = {}

    def reconcile(self) -> int:
        changed = 0
        for result in self._reputation.refresh_all():
            previous = self._last.get(result.agent_id)
            if previous is None or abs(previous - result.score) > self._epsilon:
                changed += 1
            self._last[result.agent_id] = result.score
        return changed


class GraphReconciler:
    """Materialize the live agent graph (DISC-06) and keep the observed inventory current.

    Phase 7 shipped only the capability-class seed and its docstring deferred the
    real graph to DISC-06; this now drives `AgentGraphStore.materialize()` as
    well, so nodes, delegation edges and the observed inventory converge on the
    SAME pass. The inventory half is kept, not superseded: it is what supplies
    the per-NAME component nodes the audit body cannot (it carries no `target`).

    A batch pass, but NOT an independent one: it writes to the same database the
    AuditWriter appends to, so it competes for the same write lock. That is why
    `materialize()` is incremental (a persisted watermark) and commits in small
    batches — the earlier full-table pass held the lock for its whole duration,
    which stalled and then FAILED concurrent audit appends, and a failed append
    drives the pipeline's fail-safe. Keep any work added here bounded for the
    same reason: this loop cannot touch the hot path directly, but it can starve
    it through the store they share.
    """

    name = "graph"

    def __init__(
        self, inventory, *, graph=None, interval_s: float = DEFAULT_INTERVALS["graph"]
    ) -> None:
        self._inventory = inventory
        self._graph = graph
        self.interval_s = interval_s

    def reconcile(self) -> int:
        changed = int(self._inventory.enrich_from_audit() or 0)
        if self._graph is not None:
            changed += int(self._graph.materialize() or 0)
        return changed


class CacheReconciler:
    """Warm/invalidate the hot-path caches when the policy version changes (PIPE-06).

    A stale identity cache enforces yesterday's trust and a stale compiled-policy
    cache enforces the WRONG constitution — the failure mode the CachingIdentityStage
    docstring calls out ("deployments MUST call invalidate() on every
    policy/constitution version change"). This is the loop that actually does it.

    Invalidating on EVERY pass would defeat the cache, so it fires only on an
    observed version change: converged == 0 changes.
    """

    name = "cache"

    def __init__(
        self,
        resources,
        caches: list,
        *,
        interval_s: float = DEFAULT_INTERVALS["cache"],
    ) -> None:
        self._resources = resources
        self._caches = caches
        self.interval_s = interval_s
        self._seen_version: str | None = None

    def reconcile(self) -> int:
        policy = self._resources.get_latest_policy()
        version = policy.constitution_version if policy is not None else None
        if version == self._seen_version:
            return 0  # converged
        self._seen_version = version
        for cache in self._caches:
            cache.invalidate()
        return len(self._caches)
