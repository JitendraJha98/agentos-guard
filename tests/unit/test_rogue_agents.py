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
from sqlalchemy import create_engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.pool import StaticPool

from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.audit_verify import verify_chain
from agentos_controlplane.inventory import InventoryStore
from agentos_controlplane.rogue import Divergence, RogueDetector
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import AuditRecord, RogueFinding


@pytest.fixture
def store():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    create_all(engine)
    return create_session_factory(engine)


@pytest.fixture
def inventory(store) -> InventoryStore:
    return InventoryStore(store)


@pytest.fixture
def detector(store, inventory) -> RogueDetector:
    return RogueDetector(store, AuditWriter(store), inventory)


def _events(store, kind: str = "rogue_agent_detected") -> list[dict]:
    with store() as s:
        rows = s.scalars(select(AuditRecord).order_by(AuditRecord.seq.asc())).all()
        return [r.body for r in rows if r.body.get("kind") == kind]


def _rows(store) -> list[RogueFinding]:
    with store() as s:
        return list(s.scalars(select(RogueFinding)).all())


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


# --- Task 2: RogueDetector — declared vs observed ------------------------------


def test_declared_then_observed_is_not_a_divergence(detector, inventory, store) -> None:
    """The false positive this whole feature lives or dies on.

    `InventoryStore._upsert` keeps a DECLARED component declared even after it is observed, so an
    agent doing exactly what it declared leaves ONE row still marked `declared` — and must not be
    flagged. If declared ever stopped winning that upsert, every well-behaved agent in the fleet
    would light up here.
    """
    inventory.declare("a", tools=["http_get"])
    inventory.observe("a", "tool", "http_get")

    assert detector.divergences() == []
    assert asyncio.run(detector.scan()) == []
    assert _rows(store) == []
    assert _events(store) == []


def test_observed_component_never_declared_is_one_finding(detector, inventory, store) -> None:
    inventory.declare("a", tools=["http_get"])
    inventory.observe("a", "tool", "db_drop")

    assert detector.divergences() == [Divergence(agent_id="a", kind="tool", name="db_drop")]
    fresh = asyncio.run(detector.scan())
    assert fresh == [Divergence(agent_id="a", kind="tool", name="db_drop")]

    rows = _rows(store)
    assert [(r.agent_id, r.kind, r.name, r.resolved) for r in rows] == [
        ("a", "tool", "db_drop", False)
    ]
    assert len(_events(store)) == 1


def test_agent_that_declared_nothing_is_not_rogue(detector, inventory, store) -> None:
    """DOCUMENTED RULE — do not "fix" this into flagging every unmanifested agent.

    Phase 5 made the registration manifest OPTIONAL, so an agent with no declared rows has an
    UNKNOWN scope, not an EMPTY one. Treating unknown as empty would flag every action of every
    unmanifested agent in the fleet and bury the real signal — an agent that DID declare something
    and then stepped outside it.
    """
    inventory.observe("nomanifest", "tool", "db_drop")

    assert detector.divergences() == []
    assert asyncio.run(detector.scan()) == []
    assert _rows(store) == []
    assert _events(store) == []

    # ...and the same agent becomes accountable the moment it declares a scope.
    inventory.declare("nomanifest", tools=["http_get"])
    assert asyncio.run(detector.scan()) == [
        Divergence(agent_id="nomanifest", kind="tool", name="db_drop")
    ]


def test_repeat_scan_of_unchanged_fleet_writes_and_audits_nothing(
    detector, inventory, store
) -> None:
    """Idempotence is what makes a SCHEDULED sweep safe: a cron that re-scans an unchanged fleet
    every minute must not add a row or a hash-chain record every minute."""
    inventory.declare("a", tools=["http_get"])
    inventory.observe("a", "tool", "db_drop")
    assert len(asyncio.run(detector.scan())) == 1

    assert asyncio.run(detector.scan()) == []
    assert asyncio.run(detector.scan()) == []
    assert len(_rows(store)) == 1
    assert len(_events(store)) == 1


def test_new_divergence_after_first_scan_appends_exactly_one_more_event(
    detector, inventory, store
) -> None:
    inventory.declare("a", tools=["http_get"])
    inventory.observe("a", "tool", "db_drop")
    asyncio.run(detector.scan())

    inventory.observe("a", "memory", "secrets")
    assert asyncio.run(detector.scan()) == [
        Divergence(agent_id="a", kind="memory", name="secrets")
    ]
    assert len(_rows(store)) == 2
    assert len(_events(store)) == 2


def test_divergences_is_pure(detector, inventory, store) -> None:
    """A dry run must be free — no rows, no chain records — so an operator can ask "what would this
    flag?" without committing evidence."""
    inventory.declare("a", tools=["http_get"])
    inventory.observe("a", "tool", "db_drop")

    first = detector.divergences()
    second = detector.divergences()
    assert first == second != []
    assert _rows(store) == []
    assert _events(store) == []
    with store() as s:
        assert s.scalars(select(AuditRecord)).all() == []


def test_resolve_acknowledges_without_destroying_history(detector, inventory, store) -> None:
    inventory.declare("a", tools=["http_get"])
    inventory.observe("a", "tool", "db_drop")
    asyncio.run(detector.scan())

    finding_id = detector.list_findings()[0]["id"]
    assert detector.resolve(finding_id) is True

    assert detector.list_findings() == []
    kept = detector.list_findings(include_resolved=True)
    assert [(d["agent_id"], d["name"], d["resolved"]) for d in kept] == [("a", "db_drop", True)]
    # The sighting itself is still in the tamper-evident chain.
    assert len(_events(store)) == 1


def test_resolve_unknown_id_is_false(detector) -> None:
    assert detector.resolve("00000000-0000-0000-0000-000000000000") is False
    assert detector.resolve("not-a-uuid") is False


def test_resolved_finding_is_not_re_audited_by_a_later_scan(detector, inventory, store) -> None:
    """Acknowledging a finding must not make the next sweep re-raise it: the divergence is still in
    the inventory (the agent really did use that tool), so a resolve that reopened it would turn an
    operator's acknowledgement into an infinite alert loop."""
    inventory.declare("a", tools=["http_get"])
    inventory.observe("a", "tool", "db_drop")
    asyncio.run(detector.scan())
    detector.resolve(detector.list_findings()[0]["id"])

    assert asyncio.run(detector.scan()) == []
    assert len(_rows(store)) == 1
    assert len(_events(store)) == 1


def test_event_body_carries_short_identifiers_only_and_chain_verifies(
    detector, inventory, store
) -> None:
    inventory.declare("a", tools=["http_get"])
    inventory.observe("a", "tool", "db_drop")
    asyncio.run(detector.scan())

    body = _events(store)[0]
    # kind/seq/prev_hash are the chain's own fields; the component names use non-reserved keys.
    assert set(body) == {"kind", "seq", "prev_hash", "agent_id", "component_kind", "component_name"}
    assert (body["agent_id"], body["component_kind"], body["component_name"]) == (
        "a",
        "tool",
        "db_drop",
    )
    assert verify_chain(store).ok


def test_detection_is_advisory_only(detector, inventory) -> None:
    """DISC-05 adds NO deny path. A declaration gap is evidence (the manifest may just be stale),
    never an automatic outage — the detector exposes observation and acknowledgement, nothing that
    blocks, quarantines or revokes. Escalation is Phase-9 containment, chosen by an operator."""
    inventory.declare("a", tools=["http_get"])
    inventory.observe("a", "tool", "db_drop")
    asyncio.run(detector.scan())

    surface = {n for n in dir(detector) if not n.startswith("_")}
    assert surface == {"divergences", "scan", "list_findings", "resolve"}
