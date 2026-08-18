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

from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.audit_verify import verify_chain
from agentos_controlplane.shadow import (
    ShadowAgentStore,
    claimed_id_digest,
    sanitize_claimed_id,
)
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import AuditRecord, ShadowAgent


@pytest.fixture
def store():
    engine = create_engine("sqlite+pysqlite:///:memory:")
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
        s.add(ShadowAgent(claimed_agent_id="ghost", action_type="tool_call"))
        s.commit()

    with store() as s:
        row = s.get(ShadowAgent, "ghost")
        assert row is not None
        assert (row.action_type, row.attempts) == ("tool_call", 1)
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
        row = s.get(ShadowAgent, "ghost")
        assert (row.action_type, row.attempts) == ("tool_call", 1)
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
        row = s.get(ShadowAgent, "ghost")
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
    """Two DIFFERENT ids sharing the first 255 chars collapse to one ROW (bounded storage) but
    must never collapse in the EVIDENCE: the digest covers the FULL raw string."""
    shared = "a" * 255
    asyncio.run(shadow.record(shared + "-attacker-one", "tool_call"))
    asyncio.run(shadow.record(shared + "-attacker-two", "tool_call"))

    digests = [b["claimed_id_digest"] for b in _events(store)]
    assert len(digests) == 1  # same bounded row -> only the first sighting audited
    assert digests[0] == claimed_id_digest(shared + "-attacker-one")
    assert claimed_id_digest(shared + "-attacker-one") != claimed_id_digest(shared + "-attacker-two")


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
    asyncio.run(shadow.record("first", "tool_call"))
    asyncio.run(shadow.record("second", "mcp_call"))

    rows = shadow.list_shadow_agents()
    assert [r["claimed_agent_id"] for r in rows] == ["second", "first"]  # newest sighting first
    assert set(rows[0]) == {
        "claimed_agent_id",
        "action_type",
        "attempts",
        "first_seen_at",
        "last_seen_at",
    }
    assert rows[0]["first_seen_at"] and rows[0]["last_seen_at"]


def test_sanitize_and_digest_are_independent_of_each_other() -> None:
    """The stored id is bounded; the digest is over the FULL raw input, deliberately not over the
    sanitized one — that is what keeps two truncated attackers distinguishable."""
    assert len(sanitize_claimed_id("x" * 5000)) == 255
    assert sanitize_claimed_id("") == "<empty>"
    assert len(claimed_id_digest("anything")) == 16
    assert claimed_id_digest("a" * 300) != claimed_id_digest("a" * 301)
