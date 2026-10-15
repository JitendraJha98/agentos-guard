"""Phase 15 — SEC-13 sequence correlation and TRST-04 delegation lineage, shared across instances.

Drop-in replacements for the pipeline's in-memory `SequenceCorrelator` and `DelegationLedger`
(same `observe` / `record` / `authority_for` shapes), backed by the store. Use them when more than
one control-plane instance serves the same fleet; the in-memory ones stay the single-process
default, because a DB round-trip is not free on the hot path.

Why not reconstruct both from the audit log: the audit stores `inferred_intent`, which falls back
to the probabilistic SEC-14 similarity label when no deterministic tag fired — replaying it into
SEC-13 would let a guess drive a deterministic floor. And the effective delegation authority
(capped trust, intersected scope, depth, ring) is computed state the audit record never held.

Costs, stated: the correlator adds a SELECT + INSERT (+ a bounded trim) only for TAGGED actions;
the ledger adds one INSERT per resolved action and one indexed GET per delegated one.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Callable, Generic, TypeVar

from sqlalchemy import delete, select

from agentos_controlplane.store.models import CorrelationEvent, DelegationAuthority

A = TypeVar("A")

_MAX_KEY = 255


def _bounded_key(key: str) -> str:
    """Conversation ids are caller-supplied. Truncating would let two long ids that share a prefix
    share a window; digesting keeps them distinct at a fixed width."""
    if len(key) <= _MAX_KEY:
        return key
    return "sha256:" + hashlib.sha256(key.encode("utf-8")).hexdigest()


def _ordered_subsequence(needle: list[str], haystack: list[str]) -> bool:
    """Same matching rule as `agentos_pipeline.sequence` (this package does not import it)."""
    it = iter(haystack)
    return all(cls in it for cls in needle)


class SharedSequenceCorrelator:
    """`SequenceCorrelator.observe` over a shared table: same window, same matching semantics."""

    def __init__(self, session_factory, *, window: int = 8) -> None:
        if window < 1:
            raise ValueError("window must be >= 1")
        self._sf = session_factory
        self._window = window

    def observe(
        self, key: str, intent_class: str | None, sequences: list[dict]
    ) -> tuple[str, ...]:
        if not intent_class:
            return ()
        key = _bounded_key(key)
        with self._sf() as s:
            recent = s.execute(
                select(CorrelationEvent.id, CorrelationEvent.intent_class)
                .where(CorrelationEvent.key == key)
                .order_by(CorrelationEvent.id.desc())
                .limit(self._window)
            ).all()
            prior = [row.intent_class for row in reversed(recent)]
            matched = sorted(
                str(seq["principle_ref"])
                for seq in sequences
                if (classes := list(seq.get("intent_classes", [])))
                and classes[-1] == intent_class
                and _ordered_subsequence(classes[:-1], prior)
            )
            s.add(CorrelationEvent(key=key, intent_class=intent_class))
            if len(recent) == self._window:
                # After this insert the oldest of `recent` has aged out of the window: trim it and
                # anything older, so the table is bounded per conversation just like the deque.
                s.execute(
                    delete(CorrelationEvent).where(
                        CorrelationEvent.key == key, CorrelationEvent.id <= recent[-1].id
                    )
                )
            s.commit()
        return tuple(matched)


class SharedDelegationLedger(Generic[A]):
    """`DelegationLedger` over a shared table.

    `make_authority(agent_id=, trust=, scope=, depth=, ring=)` rebuilds the pipeline's `Authority`
    (injected so this package keeps no dependency on the pipeline). Entries older than
    `retention` are pruned; a child of a pruned parent then resolves as unknown lineage and is
    DENIED — the same fail-closed trade the in-memory FIFO bound makes, now by age instead of count.
    """

    def __init__(
        self,
        session_factory,
        make_authority: Callable[..., A],
        *,
        retention: timedelta = timedelta(hours=24),
        prune_every: int = 1000,
        now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        self._sf = session_factory
        self._make = make_authority
        self._retention = retention
        self._prune_every = prune_every
        self._now = now
        self._since_prune = 0

    def record(self, action_id: str, authority: A) -> None:
        with self._sf() as s:
            row = s.get(DelegationAuthority, action_id)
            values = dict(
                agent_id=authority.agent_id,
                trust=authority.trust,
                scope=sorted(authority.scope),
                depth=authority.depth,
                ring=authority.ring,
            )
            if row is None:
                s.add(DelegationAuthority(action_id=action_id, **values))
            else:
                for name, value in values.items():
                    setattr(row, name, value)
            s.commit()
        self._since_prune += 1
        if self._since_prune >= self._prune_every:
            self._since_prune = 0
            self.prune()

    def authority_for(self, action_id: str | None) -> A | None:
        if action_id is None:
            return None
        with self._sf() as s:
            row = s.get(DelegationAuthority, action_id)
            if row is None:
                return None
            return self._make(
                agent_id=row.agent_id,
                trust=row.trust,
                scope=frozenset(row.scope),
                depth=row.depth,
                ring=row.ring,
            )

    def prune(self) -> int:
        cutoff = self._now() - self._retention  # UTCDateTime normalizes it for either backend
        with self._sf() as s:
            n = s.execute(
                delete(DelegationAuthority).where(DelegationAuthority.created_at < cutoff)
            ).rowcount
            s.commit()
        return n
