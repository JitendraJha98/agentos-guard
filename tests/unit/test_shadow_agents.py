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

import pytest
from sqlalchemy import create_engine, select

from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.audit_verify import verify_chain
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
