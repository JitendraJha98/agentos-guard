"""DISC-04 — shadow-agent detection: the shadow_agent table, the event kind, and the store
(Slice 10d).

The pipeline already DENIES an unregistered actor at stage 1 (IDN-02). This slice makes it
VISIBLE: a hundred denies from one claimed id is an incident, a single deny is noise. Recording
only — no new deny path.

`claimed_agent_id` is ATTACKER-CONTROLLED (whatever an unverified caller put in its token), which
is what the tests below pin:
  * it is BOUNDED + sanitized before storage (a 10 MB id must not become a 10 MB row, and an
    operator reads it in a dashboard where a terminal escape would be a payload);
  * only the FIRST sighting is audited — a flood from one id must not let an unregistered caller
    grow the hash chain at will;
  * the number of DISTINCT ids is capped too — per-attempt bounding alone leaves an id-rotating
    prober one new row + one new chain record per probe;
  * the ROW is keyed by the digest of the full raw id, so two attackers whose ids sanitize alike
    are two rows with two events, not one;
  * the hash-covered audit body never carries the RAW id: it carries the bounded sanitized id plus
    a digest of the FULL raw string, so truncation cannot merge two attackers into one record and a
    secret-bearing id can never trip the AUD-04 gate and block its own evidence.
"""

from __future__ import annotations

import asyncio
import json
import re

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.pool import StaticPool

from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.audit_verify import verify_chain
from agentos_controlplane.shadow import (
    OVERFLOW_ID,
    ShadowAgentStore,
    claimed_id_digest,
    sanitize_claimed_id,
)
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import AuditRecord, ShadowAgent


@pytest.fixture
def store():
    # StaticPool + check_same_thread=False: the store does its DB work in a worker thread
    # (`asyncio.to_thread`), so the in-memory database must be the SAME one there.
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    create_all(engine)
    return create_session_factory(engine)


@pytest.fixture
def audit(store) -> AuditWriter:
    return AuditWriter(store)


def _events(store, kind: str = "shadow_agent_detected") -> list[dict]:
    with store() as s:
        rows = s.scalars(select(AuditRecord).order_by(AuditRecord.seq.asc())).all()
        return [r.body for r in rows if r.body.get("kind") == kind]


# --- Task 1: table + event kind ----------------------------------------------


def test_shadow_agent_row_round_trips(store) -> None:
    """The table exists and defaults a first sighting to one attempt."""
    with store() as s:
        s.add(
            ShadowAgent(
                claimed_id_digest=claimed_id_digest("ghost"),
                claimed_agent_id="ghost",
                action_type="tool_call",
            )
        )
        s.commit()

    with store() as s:
        row = s.get(ShadowAgent, claimed_id_digest("ghost"))
        assert row is not None
        assert (row.claimed_agent_id, row.action_type, row.attempts) == ("ghost", "tool_call", 1)
        assert row.first_seen_at is not None and row.last_seen_at is not None


def test_shadow_agent_detected_is_a_known_event_kind(store, audit) -> None:
    """The kind is registered; an unknown kind still fails closed."""
    asyncio.run(
        audit.append_event(
            "shadow_agent_detected",
            {"claimed_agent_id": "ghost", "claimed_id_digest": "abc123", "action_type": "tool_call"},
        )
    )
    assert len(_events(store)) == 1

    with pytest.raises(ValueError):
        asyncio.run(audit.append_event("shadow_agent_invented", {"claimed_agent_id": "ghost"}))


# --- Task 2: ShadowAgentStore -------------------------------------------------


@pytest.fixture
def shadow(store, audit) -> ShadowAgentStore:
    return ShadowAgentStore(store, audit)


def test_first_sighting_records_and_audits(store, shadow) -> None:
    first = asyncio.run(shadow.record("ghost", "tool_call"))

    assert first is True
    with store() as s:
        row = s.get(ShadowAgent, claimed_id_digest("ghost"))
        assert (row.claimed_agent_id, row.action_type, row.attempts) == ("ghost", "tool_call", 1)
    bodies = _events(store)
    assert len(bodies) == 1
    assert bodies[0]["claimed_agent_id"] == "ghost"
    assert bodies[0]["action_type"] == "tool_call"
    assert bodies[0]["claimed_id_digest"] == claimed_id_digest("ghost")


def test_repeat_sightings_count_but_append_only_once(store, shadow) -> None:
    """A flood from ONE unregistered id is one incident. Auditing per attempt would let an
    unregistered caller grow the hash chain at will — the whole point of the counter."""
    assert asyncio.run(shadow.record("ghost", "tool_call")) is True

    assert asyncio.run(shadow.record("ghost", "tool_call")) is False
    for _ in range(20):
        asyncio.run(shadow.record("ghost", "mcp_call"))

    with store() as s:
        row = s.get(ShadowAgent, claimed_id_digest("ghost"))
        assert row.attempts == 22
        assert row.action_type == "mcp_call"  # the LATEST attempt's shape
    assert len(_events(store)) == 1  # still exactly one chain entry


def test_oversized_claimed_id_is_bounded_not_stored_whole(store, shadow) -> None:
    """A 10 000-char id must not become a 10 000-char row (SQLite does not enforce the width)."""
    asyncio.run(shadow.record("g" * 10_000, "tool_call"))

    rows = shadow.list_shadow_agents()
    assert len(rows) == 1
    assert len(rows[0]["claimed_agent_id"]) == 255


def test_control_characters_are_sanitized(store, shadow) -> None:
    """An operator reads this in a dashboard and a log — a claimed id is a fine place to hide a
    terminal escape, a newline-forged log line, or markup."""
    hostile = "gh\x1b[31most\n<script>\x00 drop"
    asyncio.run(shadow.record(hostile, "tool_call"))

    stored = shadow.list_shadow_agents()[0]["claimed_agent_id"]
    assert re.fullmatch(r"[A-Za-z0-9._:@?-]+", stored), stored


def test_empty_claimed_id_aggregates_under_a_placeholder(store, shadow) -> None:
    assert asyncio.run(shadow.record("", "tool_call")) is True
    assert asyncio.run(shadow.record("", "tool_call")) is False

    rows = shadow.list_shadow_agents()
    assert [r["claimed_agent_id"] for r in rows] == ["<empty>"]
    assert rows[0]["attempts"] == 2


def test_truncation_cannot_merge_two_attackers(store, shadow) -> None:
    """Two DIFFERENT ids sharing the first 255 chars are TWO rows and TWO events.

    The row is keyed by the digest of the FULL raw id, not by the lossy display text. Keyed by
    the display text they shared one row, and because only a first sighting is audited the second
    attacker's digest never reached the chain at all — the digest defence was defeated by the very
    collision it exists to survive.
    """
    shared = "a" * 255
    asyncio.run(shadow.record(shared + "-attacker-one", "tool_call"))
    asyncio.run(shadow.record(shared + "-attacker-two", "tool_call"))

    digests = [b["claimed_id_digest"] for b in _events(store)]
    assert digests == [
        claimed_id_digest(shared + "-attacker-one"),
        claimed_id_digest(shared + "-attacker-two"),
    ]
    assert len(shadow.list_shadow_agents()) == 2


def test_ids_that_sanitize_identically_stay_two_incidents(store, shadow) -> None:
    """EVERY disallowed character maps to the same `?`, so a fleet with non-Latin agent ids (or an
    attacker who knows that) would otherwise collapse into one indistinguishable row."""
    for raw in ("агент", "エージェン", "中文测试啊", "!!!!!"):
        asyncio.run(shadow.record(raw, "tool_call"))

    rows = shadow.list_shadow_agents()
    assert [r["claimed_agent_id"] for r in rows] == ["?????"] * 4  # same DISPLAY text
    assert len({r["claimed_id_digest"] for r in rows}) == 4  # four distinct rows
    assert len({b["claimed_id_digest"] for b in _events(store)}) == 4  # four distinct events


def test_distinct_ids_are_capped_into_one_overflow_bucket(store, audit) -> None:
    """The per-attempt cap bounds ONE id; nothing bounded the number of ids. An id-rotating prober
    bought one new row AND one new tamper-evident chain record per probe — the same unbounded
    growth the first-sighting rule exists to prevent, one dimension over."""
    shadow = ShadowAgentStore(store, audit, max_rows=5)

    for i in range(20):
        asyncio.run(shadow.record(f"ghost-{i}", "tool_call"))

    rows = shadow.list_shadow_agents()
    assert len(rows) == 6  # 5 tracked ids + 1 bucket
    assert len(_events(store)) == 6  # and the chain grew by exactly as much
    overflow = [r for r in rows if r["claimed_agent_id"] == OVERFLOW_ID]
    assert len(overflow) == 1
    assert overflow[0]["attempts"] == 15  # the operator still sees HOW MUCH was folded away
    assert verify_chain(store).ok


def test_list_shadow_agents_is_bounded_at_the_query(store, audit) -> None:
    """The route materializes every selected row into ONE JSON response, so the bound belongs on
    the query too — not only on the write path that a pre-cap table never went through."""
    shadow = ShadowAgentStore(store, audit, max_rows=5)
    with store() as s:
        for i in range(60):
            s.add(
                ShadowAgent(
                    claimed_id_digest=f"{i:016x}",
                    claimed_agent_id=f"ghost-{i}",
                    action_type="tool_call",
                )
            )
        s.commit()

    assert len(shadow.list_shadow_agents()) == 6


def test_a_refused_chain_append_leaves_no_row_and_is_retried(store, audit) -> None:
    """The chain entry is written BEFORE the row (the 10c discipline). Committing the row first
    meant one transient append failure marked the id as already-seen forever, so its
    `shadow_agent_detected` event was NEVER written — silent evidence loss."""

    class FlakyAudit:
        def __init__(self, real) -> None:
            self._real = real
            self.fail_next = True

        async def append_event(self, kind, body):
            if self.fail_next:
                self.fail_next = False
                raise RuntimeError("chain unavailable")
            return await self._real.append_event(kind, body)

    shadow = ShadowAgentStore(store, FlakyAudit(audit))

    with pytest.raises(RuntimeError):
        asyncio.run(shadow.record("ghost", "tool_call"))
    assert shadow.list_shadow_agents() == []  # nothing claims the id was seen

    assert asyncio.run(shadow.record("ghost", "tool_call")) is True  # still FIRST -> retried
    assert len(_events(store)) == 1
    assert shadow.list_shadow_agents()[0]["attempts"] == 1


@pytest.mark.parametrize(
    "canary",
    [
        "AKIAIOSFODNN7EXAMPLE",  # survives the charset filter UNCHANGED — sanitizing is not enough
        "ghp_" + "a1B2c3D4e5" * 4,
        "aB3xQ9zL7mK2pW5vT8nR4jY6hC1gF0dS",  # opaque + high entropy: the AUD-04 entropy backstop
    ],
)
def test_secret_bearing_id_cannot_block_its_own_record(store, shadow, canary) -> None:
    """The AUD-04 gate scans the hash-covered body and fails CLOSED. If a secret-shaped id reached
    that body, an attacker could name itself after a credential and permanently prevent its own
    sighting from being recorded — so the body carries a placeholder + the digest, and the
    recognisable id stays in the TABLE (the Phase-9 detail-in-the-row convention)."""
    assert asyncio.run(shadow.record(canary, "tool_call")) is True

    bodies = _events(store)
    assert len(bodies) == 1
    assert canary not in json.dumps(bodies[0])
    assert bodies[0]["claimed_agent_id"] == "<secret-like>"
    assert bodies[0]["claimed_id_digest"] == claimed_id_digest(canary)
    assert shadow.list_shadow_agents()[0]["claimed_agent_id"] == canary  # operator still sees it
    assert verify_chain(store).ok


def test_two_secret_shaped_ids_stay_distinct_in_the_chain(store, shadow) -> None:
    """Both bodies say `<secret-like>`; the digests are what keep them two incidents, not one."""
    asyncio.run(shadow.record("AKIAIOSFODNN7EXAMPLE", "tool_call"))
    asyncio.run(shadow.record("AKIAIOSFODNN7EXAMPLF", "tool_call"))

    bodies = _events(store)
    assert [b["claimed_agent_id"] for b in bodies] == ["<secret-like>", "<secret-like>"]
    assert bodies[0]["claimed_id_digest"] != bodies[1]["claimed_id_digest"]
    assert len(shadow.list_shadow_agents()) == 2


def test_list_shadow_agents_shape_and_ordering(store, shadow) -> None:
    from datetime import datetime, timezone

    from agentos_controlplane.store.models import ShadowAgent

    asyncio.run(shadow.record("first", "tool_call"))
    asyncio.run(shadow.record("second", "mcp_call"))

    # Give the two sightings DISTINCT times before asserting recency. Recording back-to-back is
    # not enough: `last_seen_at` carries only the platform clock's resolution (~15.6ms on
    # Windows), so both rows can land on the same instant, and then NO ordering — however
    # implemented — can separate them. This assertion previously depended on the clock happening
    # to tick between the two records, which made it ~7% flaky here. Writing the timestamps tests
    # the ordering rule itself, on every platform.
    with store() as s:
        by_id = {r.claimed_agent_id: r for r in s.scalars(select(ShadowAgent)).all()}
        by_id["first"].last_seen_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
        by_id["second"].last_seen_at = datetime(2026, 1, 2, tzinfo=timezone.utc)
        s.commit()

    rows = shadow.list_shadow_agents()
    assert [r["claimed_agent_id"] for r in rows] == ["second", "first"]  # newest sighting first
    assert set(rows[0]) == {
        "claimed_agent_id",
        "claimed_id_digest",
        "action_type",
        "attempts",
        "first_seen_at",
        "last_seen_at",
    }
    # The digest is what tells two rows apart when their display text collides.
    assert rows[0]["claimed_id_digest"] == claimed_id_digest("second")
    assert rows[0]["first_seen_at"] and rows[0]["last_seen_at"]


def test_sightings_sharing_one_timestamp_still_list_in_a_stable_order(store, shadow) -> None:
    """Ties cannot be recency-ordered, but they MUST NOT reshuffle between reads.

    Same-tick sightings compare equal on `last_seen_at`, so without a tiebreaker the database
    returns them in whatever order it likes and the same operator page can list them differently
    on consecutive loads. The `id` tiebreak buys stability, which is the honest guarantee here.
    """
    from datetime import datetime, timezone

    from agentos_controlplane.store.models import ShadowAgent

    for name in ("alpha", "beta", "gamma"):
        asyncio.run(shadow.record(name, "tool_call"))
    tied = datetime(2026, 1, 1, tzinfo=timezone.utc)
    with store() as s:
        for row in s.scalars(select(ShadowAgent)).all():
            row.last_seen_at = tied
        s.commit()

    orders = {tuple(r["claimed_agent_id"] for r in shadow.list_shadow_agents()) for _ in range(10)}
    assert len(orders) == 1, f"tied sightings listed in {len(orders)} different orders: {orders}"


def test_concurrent_sightings_of_one_id_still_append_exactly_one_event(store, shadow) -> None:
    """The first-sighting cap must survive CONCURRENCY, or it is not a cap: an attacker fires N
    governed actions at once under one claimed id, every one of them reads "no row yet", and the
    flood buys N chain records after all — the cap defeated by the very off-the-loop DB work that
    keeps it from blocking enforcement."""

    async def main() -> None:
        await asyncio.gather(*(shadow.record("ghost", "tool_call") for _ in range(10)))

    asyncio.run(main())

    assert len(_events(store)) == 1
    assert shadow.list_shadow_agents()[0]["attempts"] == 10


def test_recording_does_not_block_the_event_loop(store, shadow) -> None:
    """`record` is `async` but its DB work is SYNCHRONOUS. Run inline it holds the event loop for
    the whole write, so an unauthenticated flood of unregistered actions queues every other
    governed agent's decision behind attacker-driven writes — observation degrading enforcement by
    availability rather than by exception."""

    async def main() -> int:
        ticks = 0

        async def ticker() -> None:
            nonlocal ticks
            while True:
                await asyncio.sleep(0)
                ticks += 1

        task = asyncio.create_task(ticker())
        await asyncio.sleep(0)  # let the ticker reach its loop
        before = ticks
        await shadow.record("ghost", "tool_call")
        task.cancel()
        return ticks - before

    assert asyncio.run(main()) > 0  # the loop kept running DURING the write


def test_sanitize_and_digest_are_independent_of_each_other() -> None:
    """The stored id is bounded; the digest is over the FULL raw input, deliberately not over the
    sanitized one — that is what keeps two truncated attackers distinguishable."""
    assert len(sanitize_claimed_id("x" * 5000)) == 255
    assert sanitize_claimed_id("") == "<empty>"
    assert len(claimed_id_digest("anything")) == 16
    assert claimed_id_digest("a" * 300) != claimed_id_digest("a" * 301)
