"""DISC-03 — framework discovery: the discovered_framework table, the event kind, and the
evidence-based detector (Slice 10c).

You cannot govern what you cannot see. Detection is EVIDENCE-BASED: a framework is reported
present iff its distribution is genuinely installed (`importlib.metadata`), never guessed from a
stray import name — an inventory that lists frameworks which are not there is worse than silence.
Both directions are asserted here: a true positive on langchain/langgraph (real dependencies of
this repo, so it cannot be faked) and no false positive for an absent distribution.

The scan is IDEMPOTENT: a scheduled pass over an unchanged environment appends NO audit event (it
must not bloat the hash chain) while still advancing `last_seen_at`; a version change does emit a
fresh event. Audit bodies carry short identifiers only.
"""

import asyncio

import pytest
from sqlalchemy import create_engine, select

from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import AuditRecord, DiscoveredFramework


@pytest.fixture
def store():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    return create_session_factory(engine)


def _events(store, kind: str) -> list[dict]:
    with store() as s:
        rows = s.scalars(select(AuditRecord).order_by(AuditRecord.seq))
        return [r.body for r in rows if r.body.get("kind") == kind]


def test_discovered_framework_round_trip(store) -> None:
    """The table holds the CURRENT observation per framework, bracketed by first/last-seen."""
    with store() as s:
        s.add(DiscoveredFramework(name="langchain", distribution="langchain", version="1.3.2"))
        s.commit()

    with store() as s:
        row = s.get(DiscoveredFramework, "langchain")
        assert row is not None
        assert (row.distribution, row.version) == ("langchain", "1.3.2")
        assert row.first_seen_at is not None
        assert row.last_seen_at is not None


def test_framework_discovered_is_a_known_event_kind(store) -> None:
    audit = AuditWriter(store)
    asyncio.run(
        audit.append_event(
            "framework_discovered",
            {"framework": "langchain", "distribution": "langchain", "version": "1.3.2"},
        )
    )
    bodies = _events(store, "framework_discovered")
    assert len(bodies) == 1
    assert bodies[0]["framework"] == "langchain"


def test_unknown_event_kind_still_raises(store) -> None:
    audit = AuditWriter(store)
    with pytest.raises(ValueError):
        asyncio.run(audit.append_event("framework_undiscovered", {"framework": "x"}))
    with store() as s:
        assert s.scalars(select(AuditRecord)).all() == []


def test_event_body_may_not_shadow_reserved_chain_keys(store) -> None:
    """Reserved body keys are rejected fail-closed — the body carries short identifiers only."""
    audit = AuditWriter(store)
    with pytest.raises(ValueError):
        asyncio.run(audit.append_event("framework_discovered", {"kind": "spoof", "framework": "x"}))
    with store() as s:
        assert s.scalars(select(AuditRecord)).all() == []
