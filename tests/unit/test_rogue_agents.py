"""DISC-05 — rogue-agent detection: a REGISTERED agent acting outside its DECLARED scope
(Slice 10e).

Shadow detection (10d) answers "who is not registered". This answers "who is registered but is not
doing what they said": the agent declared a manifest and was then observed using a component that
manifest never mentioned.

The comparison is sound because Phase 5 already stores both halves and `InventoryStore._upsert`
keeps a DECLARED component marked declared even after it is observed — so a row still marked
`observed` is precisely one the agent never declared.

Two judgement calls are pinned here because a future reader is likely to "fix" them:
  * detection is ADVISORY — there is no deny path, so a stale manifest can never become an
    automatic outage;
  * an agent that declared NOTHING is NOT rogue — Phase 5 made the manifest optional, so no
    declarations means "scope unknown", not "scope empty".
"""

from __future__ import annotations

import asyncio

import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.pool import StaticPool

from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import RogueFinding


@pytest.fixture
def store():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    create_all(engine)
    return create_session_factory(engine)


def test_rogue_finding_round_trips_unresolved_by_default(store) -> None:
    with store() as s:
        s.add(RogueFinding(agent_id="a", kind="tool", name="db_drop"))
        s.commit()
    with store() as s:
        row = s.query(RogueFinding).one()
        assert (row.agent_id, row.kind, row.name) == ("a", "tool", "db_drop")
        # A finding is evidence awaiting an operator, not a verdict already acted on.
        assert row.resolved is False
        assert row.first_seen_at is not None


def test_duplicate_agent_kind_name_is_rejected(store) -> None:
    """The uniqueness that makes a repeat scan idempotent lives in the SCHEMA, not only in the
    detector's read-before-write."""
    with store() as s:
        s.add(RogueFinding(agent_id="a", kind="tool", name="db_drop"))
        s.commit()
    with store() as s:
        s.add(RogueFinding(agent_id="a", kind="tool", name="db_drop"))
        with pytest.raises(IntegrityError):
            s.commit()


def test_rogue_agent_detected_is_a_known_event_kind(store) -> None:
    """The kind is registered; an unknown kind still fails closed.

    The body names the component `component_kind`/`component_name`, NOT `kind`/`name`: `kind` is a
    RESERVED chain field (it carries the event kind itself) and a body that shadows it is rejected
    fail-closed. Same short identifiers, non-colliding keys.
    """
    audit = AuditWriter(store)
    rec_id = asyncio.run(
        audit.append_event(
            "rogue_agent_detected",
            {"agent_id": "a", "component_kind": "tool", "component_name": "db_drop"},
        )
    )
    assert rec_id is not None
    with pytest.raises(ValueError):
        asyncio.run(audit.append_event("not_a_real_kind", {"agent_id": "a"}))

    # The reserved-key guard is what forced the rename — pin it so nobody "tidies" it back.
    with pytest.raises(ValueError):
        asyncio.run(
            audit.append_event("rogue_agent_detected", {"agent_id": "a", "kind": "tool"})
        )
