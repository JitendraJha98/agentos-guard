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
from datetime import datetime

import pytest
from sqlalchemy import create_engine, select

from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.audit_verify import verify_chain
from agentos_controlplane.framework_discovery import (
    FRAMEWORK_CATALOGUE,
    FrameworkDetector,
    detect_frameworks,
)
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import AuditRecord, DiscoveredFramework

# A distribution nobody has installed — the negative control for "no false positives".
ABSENT_DIST = "agentos-definitely-not-installed"


@pytest.fixture
def store():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    return create_session_factory(engine)


@pytest.fixture
def audit(store) -> AuditWriter:
    return AuditWriter(store)


def _events(store, kind: str) -> list[dict]:
    with store() as s:
        rows = s.scalars(select(AuditRecord).order_by(AuditRecord.seq))
        return [r.body for r in rows if r.body.get("kind") == kind]


def _rows(store) -> dict[str, DiscoveredFramework]:
    with store() as s:
        return {r.name: r for r in s.scalars(select(DiscoveredFramework)).all()}


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


# --- detection: evidence-based, both directions ------------------------------------------------


def test_detects_frameworks_that_are_genuinely_installed() -> None:
    """TRUE POSITIVE: langchain + langgraph are hard dependencies of this repo, so a detector that
    resolves against the INSTALLED distributions must find them — this cannot be faked."""
    found = {f.name: f for f in detect_frameworks()}
    assert "langchain" in found
    assert "langgraph" in found
    assert found["langchain"].distribution == "langchain"
    assert found["langchain"].version  # non-empty: the version actually installed
    assert found["langgraph"].version


def test_absent_distribution_is_never_reported() -> None:
    """NO FALSE POSITIVES: an inventory listing frameworks that are not there is worse than
    silence, so a catalogue naming an uninstalled distribution yields nothing."""
    assert detect_frameworks({"nope": (ABSENT_DIST,)}) == []


def test_alias_resolution_reports_the_distribution_actually_found() -> None:
    """The catalogue lists ALIASES (projects rename/split); the first installed one wins and the
    finding names the distribution that actually evidenced it."""
    found = detect_frameworks({"langchain": ("not-real-dist", "langchain")})
    assert len(found) == 1
    assert (found[0].name, found[0].distribution) == ("langchain", "langchain")


def test_catalogue_covers_the_frameworks_disc_03_names() -> None:
    assert {"langchain", "langgraph", "crewai", "autogen", "openai_agents", "mcp"} <= set(
        FRAMEWORK_CATALOGUE
    )


# --- scan: persistence, audit, idempotence ------------------------------------------------------


def test_scan_persists_and_audits_each_finding(store, audit) -> None:
    detector = FrameworkDetector(store, audit)
    findings = asyncio.run(detector.scan())

    assert findings, "the real environment must yield at least langchain/langgraph"
    rows = _rows(store)
    assert {f.name for f in findings} == set(rows)
    events = _events(store, "framework_discovered")
    assert len(events) == len(findings)
    assert {e["framework"] for e in events} == {f.name for f in findings}


def test_repeat_scan_is_idempotent_but_advances_last_seen(store, audit) -> None:
    """A SCHEDULED scan must not bloat the hash chain: an unchanged environment appends no event,
    yet the row must still show it was observed again."""
    detector = FrameworkDetector(store, audit)
    asyncio.run(detector.scan())
    first_events = len(_events(store, "framework_discovered"))

    # Backdate so the advance is provable without racing the clock.
    stale = datetime(2020, 1, 1, 0, 0, 0)
    with store() as s:
        for row in s.scalars(select(DiscoveredFramework)).all():
            row.last_seen_at = stale
        s.commit()

    asyncio.run(detector.scan())

    assert len(_events(store, "framework_discovered")) == first_events  # NO duplicate events
    for row in _rows(store).values():
        assert row.last_seen_at > stale  # ...but the observation is refreshed


def test_version_change_emits_a_fresh_event_and_updates_the_row(store, audit) -> None:
    catalogue = {"langchain": ("langchain",)}
    detector = FrameworkDetector(store, audit, catalogue=catalogue)
    asyncio.run(detector.scan())
    real_version = _rows(store)["langchain"].version
    assert len(_events(store, "framework_discovered")) == 1

    # Pretend the deployment was running an older version until now.
    with store() as s:
        s.get(DiscoveredFramework, "langchain").version = "0.0.1-old"
        s.commit()

    asyncio.run(detector.scan())

    events = _events(store, "framework_discovered")
    assert len(events) == 2  # a version change IS news
    assert events[-1]["version"] == real_version
    assert _rows(store)["langchain"].version == real_version


def test_scan_leaves_the_chain_verifiable_and_bodies_short(store, audit) -> None:
    detector = FrameworkDetector(store, audit)
    asyncio.run(detector.scan())

    assert verify_chain(store).ok
    for body in _events(store, "framework_discovered"):
        # kind/seq/prev_hash are the writer's chain fields; the DISC-03 body adds exactly three
        # short identifiers — no paths, no payloads, nothing free-text.
        assert set(body) - {"kind", "seq", "prev_hash"} == {
            "framework",
            "distribution",
            "version",
        }
        assert all(isinstance(body[k], str) for k in ("framework", "distribution", "version"))


def test_list_frameworks_reads_back_the_inventory(store, audit) -> None:
    detector = FrameworkDetector(store, audit)
    asyncio.run(detector.scan())

    listed = detector.list_frameworks()
    assert [d["name"] for d in listed] == sorted(d["name"] for d in listed)  # stable order
    assert "langchain" in {d["name"] for d in listed}
    entry = next(d for d in listed if d["name"] == "langchain")
    assert entry["distribution"] == "langchain"
    assert entry["version"] and entry["first_seen_at"] and entry["last_seen_at"]
