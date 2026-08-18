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
import json

import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.pool import StaticPool

from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.audit_verify import verify_chain
from agentos_controlplane.inventory import InventoryStore
from agentos_controlplane.rogue import Divergence, RogueDetector
from agentos_controlplane.shadow import claimed_id_digest
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import AuditRecord, RogueFinding


@pytest.fixture
def store():
    # StaticPool + check_same_thread=False: the sweep does its DB work in a worker thread
    # (`asyncio.to_thread`), so the in-memory database must be the SAME one there.
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
    # The digests are what keep two components distinct when the identifier itself had to be
    # replaced (an over-long name, or one shaped like a credential).
    assert set(body) == {
        "kind",
        "seq",
        "prev_hash",
        "agent_id",
        "agent_id_digest",
        "component_kind",
        "component_name",
        "component_name_digest",
    }
    assert (body["agent_id"], body["component_kind"], body["component_name"]) == (
        "a",
        "tool",
        "db_drop",
    )
    assert body["agent_id_digest"] == claimed_id_digest("a")
    assert body["component_name_digest"] == claimed_id_digest("db_drop")
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


# --- review fixes -------------------------------------------------------------
#
# Three failures the original slice shipped, each pinned here:
#   * the CLASS-LEVEL observation the only production writer emits was compared against per-tool
#     manifest names, so every declaring agent in the fleet was flagged for compliance;
#   * the row was committed BEFORE the chain entry, so one append failure lost the evidence for
#     good — and aborted the rest of the batch;
#   * the identifiers reached the hash-covered body raw, so an over-long or credential-shaped name
#     could bloat or BLOCK a record.


def test_class_level_observation_is_not_a_divergence(detector, inventory, store) -> None:
    """The false positive the REAL wiring produced for every manifest-declaring agent.

    `InventoryStore.enrich_from_audit` (driven by `GraphReconciler`) is the only production writer
    of observed activity, and the audit body omits the per-action target — so it records a
    CLASS-LEVEL placeholder (`name == kind`, e.g. ('tool','tool')). That can never equal a
    manifest's per-tool name ('http_get'), so comparing the two naming schemes flags an agent doing
    exactly what it declared. Class-level rows carry their own `source` and are NOT compared.
    """
    inventory.declare("a", tools=["http_get"])
    with store() as s:
        s.add(
            AuditRecord(
                seq=0,
                prev_hash=None,
                record_hash="h0",
                body={"seq": 0, "agent_id": "a", "action_type": "tool_call"},
            )
        )
        s.commit()
    assert inventory.enrich_from_audit() == 1  # the REAL observation path ran

    assert detector.divergences() == []
    assert asyncio.run(detector.scan()) == []
    assert _rows(store) == []
    assert _events(store) == []


def test_a_refused_chain_append_leaves_no_finding_and_is_retried(store, inventory) -> None:
    """Evidence ordering (the DISC-03/04 discipline): the chain entry is appended BEFORE the row.

    Committing the row first meant a transient append failure left a row claiming the divergence
    was already known — so the next sweep's read-before-write skipped it and its
    `rogue_agent_detected` event was NEVER written. Permanent, silent evidence loss with no retry.
    """

    class FlakyAudit:
        def __init__(self, real) -> None:
            self._real = real
            self.fail_next = True

        async def append_event(self, kind, body):
            if self.fail_next:
                self.fail_next = False
                raise RuntimeError("chain unavailable")
            return await self._real.append_event(kind, body)

    detector = RogueDetector(store, FlakyAudit(AuditWriter(store)), inventory)
    inventory.declare("a", tools=["http_get"])
    inventory.observe("a", "tool", "db_drop")

    assert asyncio.run(detector.scan()) == []  # the sweep survives it
    assert _rows(store) == []  # nothing claims the divergence is known
    assert _events(store) == []

    assert asyncio.run(detector.scan()) == [Divergence("a", "tool", "db_drop")]  # retried
    assert len(_rows(store)) == 1
    assert len(_events(store)) == 1


def test_one_failing_divergence_does_not_abort_the_batch(store, inventory) -> None:
    """A scheduled sweep processes a whole fleet: one divergence the chain refuses must cost only
    ITS evidence, not every finding sorted after it — and must still be retried next sweep."""

    class OneBadName:
        def __init__(self, real) -> None:
            self._real = real
            self.refuse = "boom"

        async def append_event(self, kind, body):
            if body["component_name"] == self.refuse:
                raise RuntimeError("chain unavailable")
            return await self._real.append_event(kind, body)

    audit = OneBadName(AuditWriter(store))
    detector = RogueDetector(store, audit, inventory)
    inventory.declare("a", tools=["http_get"])
    for name in ("aaa", "boom", "zzz"):
        inventory.observe("a", "tool", name)

    assert [d.name for d in asyncio.run(detector.scan())] == ["aaa", "zzz"]
    assert {r.name for r in _rows(store)} == {"aaa", "zzz"}
    assert len(_events(store)) == 2

    audit.refuse = ""  # the chain recovers
    assert [d.name for d in asyncio.run(detector.scan())] == ["boom"]
    assert len(_events(store)) == 3


def test_oversized_name_is_bounded_in_the_row_and_the_chain(detector, inventory, store) -> None:
    """A 10 000-char component name must not become a 10 000-byte chain record (SQLite does not
    enforce String(255), and on Postgres the same INSERT would fail and abort the sweep instead)."""
    inventory.declare("a", tools=["http_get"])
    inventory.observe("a", "tool", "x" * 10_000)

    assert len(asyncio.run(detector.scan())) == 1

    assert len(_rows(store)[0].name) <= 255
    body = _events(store)[0]
    assert len(body["component_name"]) <= 255
    assert len(json.dumps(body)) < 1_000
    assert verify_chain(store).ok


def test_bounding_cannot_merge_two_components(detector, inventory, store) -> None:
    """Truncation is lossy, so the bounded identifier carries a digest of the full raw value —
    otherwise two 400-char names would share their first 255 and become ONE finding."""
    inventory.declare("a", tools=["http_get"])
    inventory.observe("a", "tool", "y" * 400 + "one")
    inventory.observe("a", "tool", "y" * 400 + "two")

    assert len(asyncio.run(detector.scan())) == 2
    assert len({r.name for r in _rows(store)}) == 2
    assert len(_events(store)) == 2


def test_hostile_characters_are_sanitized_before_storage(detector, inventory, store) -> None:
    """An operator reads these in a dashboard and a log; a terminal escape or a script tag in a
    component name is a payload, not an identifier."""
    hostile = "\x1b]0;pwned\x07<script>alert(1)</script>\x00\r\n‮"
    inventory.declare("a", tools=["http_get"])
    inventory.observe("a", "tool", hostile)

    asyncio.run(detector.scan())

    stored = detector.list_findings()[0]["name"]
    charted = _events(store)[0]["component_name"]
    for text in (stored, charted):
        assert not any(c in text for c in "\x1b\x07\x00\r\n<>")
        assert "‮" not in text


@pytest.mark.parametrize(
    "canary",
    [
        "AKIAIOSFODNN7EXAMPLE",  # a structured-secret shape, unchanged by the charset filter
        # AUD-04's DOCUMENTED, accepted entropy false positive: an ordinary MCP tool name long
        # enough to look opaque. Raw in the body it fails the whole record closed.
        "GoogleDriveSearchDocumentsByFullTextQueryV2",
    ],
)
def test_a_secret_shaped_name_cannot_block_its_own_finding(
    detector, inventory, store, canary
) -> None:
    """The AUD-04 gate scans the hash-covered body and fails CLOSED. Raw identifiers therefore let
    a name BLOCK its own evidence — and the exception aborted the rest of the sweep with it."""
    inventory.declare("a", tools=["http_get"])
    inventory.observe("a", "tool", canary)

    assert len(asyncio.run(detector.scan())) == 1

    body = _events(store)[0]
    assert canary not in json.dumps(body)
    assert body["component_name"] == "<secret-like>"
    assert body["component_name_digest"] == claimed_id_digest(canary)
    # The recognisable name still reaches the operator through the ROW (the Phase-9 convention).
    assert detector.list_findings()[0]["name"] == canary
    assert verify_chain(store).ok


def test_a_secret_shaped_agent_id_cannot_block_the_finding(detector, inventory, store) -> None:
    agent = "ghp_" + "a1B2c3D4e5" * 4
    inventory.declare(agent, tools=["http_get"])
    inventory.observe(agent, "tool", "db_drop")

    assert len(asyncio.run(detector.scan())) == 1

    body = _events(store)[0]
    assert agent not in json.dumps(body)
    assert body["agent_id"] == "<secret-like>"
    assert body["agent_id_digest"] == claimed_id_digest(agent)
    assert detector.list_findings()[0]["agent_id"] == agent


def test_list_findings_is_bounded_at_the_query(store, inventory) -> None:
    """The route materializes everything it selects into ONE JSON response (the shadow /
    dashboard `.limit()` precedent)."""
    detector = RogueDetector(store, AuditWriter(store), inventory, max_findings=5)
    with store() as s:
        for i in range(20):
            s.add(RogueFinding(agent_id="a", kind="tool", name=f"t{i}"))
        s.commit()

    assert len(detector.list_findings()) == 5
    assert len(detector.list_findings(include_resolved=True)) == 5


def test_scan_does_not_hold_the_event_loop(detector, inventory, store) -> None:
    """The detector shares its session factory and AuditWriter with the pipeline, so a sweep driven
    in that process adds its whole wall time to every in-flight governed decision. The DB work is
    synchronous — it belongs in a worker thread (the DISC-04 rule: observation must never degrade
    enforcement). The idempotent NO-OP sweep is the case a schedule runs every minute, so it has to
    yield too."""

    inventory.declare("a", tools=["http_get"])
    for i in range(50):
        inventory.observe("a", "tool", f"t{i}")

    async def sweep_ticks() -> int:
        ticks = 0

        async def ticker() -> None:
            nonlocal ticks
            while True:
                await asyncio.sleep(0)
                ticks += 1

        task = asyncio.create_task(ticker())
        await asyncio.sleep(0)  # let the ticker reach its loop
        before = ticks
        await detector.scan()
        task.cancel()
        return ticks - before

    assert asyncio.run(sweep_ticks()) > 0
    assert asyncio.run(sweep_ticks()) > 0  # the converged sweep yields as well


def test_scan_is_not_one_select_per_divergence(store, inventory) -> None:
    """N+1: `list_inventory()` materialized the whole inventory and then the sweep issued a SELECT
    per divergence, so a converged fleet cost O(inventory) round trips every pass."""
    detector = RogueDetector(store, AuditWriter(store), inventory)
    inventory.declare("a", tools=["http_get"])
    for i in range(30):
        inventory.observe("a", "tool", f"t{i}")
    asyncio.run(detector.scan())

    statements: list[str] = []
    engine = store.kw["bind"]

    def _record(conn, cursor, statement, *rest) -> None:
        statements.append(statement)

    event.listen(engine, "before_cursor_execute", _record)
    try:
        assert asyncio.run(detector.scan()) == []  # converged: nothing to write
    finally:
        event.remove(engine, "before_cursor_execute", _record)

    selects = [s for s in statements if s.lstrip().upper().startswith("SELECT")]
    assert len(selects) <= 3, selects
