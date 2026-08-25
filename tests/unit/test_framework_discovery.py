"""DISC-03 — framework discovery: the discovered_framework table, the event kind, and the
evidence-based detector (Slice 10c).

You cannot govern what you cannot see. Detection is EVIDENCE-BASED: a framework is reported
present iff its distribution is genuinely installed (`importlib.metadata`), never guessed from a
stray import name — an inventory that lists frameworks which are not there is worse than silence.

Detection reads the CONTROL PLANE's own interpreter, and agentos-guard depends on several
catalogue entries itself (langchain/langgraph via agentos-sdk). Those rows would be constant-true
in every install — a tautology, not a discovery — so they are excluded, and the positive case is
asserted against a framework the guard does NOT depend on, planted as a real `.dist-info` on
sys.path. That test can genuinely fail; `assert "langchain" in found` could not.

A distribution's METADATA is SUPPLY-CHAIN input: a compromised dependency, a hand-rolled
`.dist-info`, or a writable PYTHONPATH entry can put any bytes in `Version:`. So the tests below
pin the three properties that keeps that from becoming an evidence problem:
  * a malformed distribution degrades to "that ONE framework is unknown", never a failed scan;
  * no externally-sourced text reaches the audit body (a sha256 digest does), and the chain entry
    is written BEFORE the row — a framework is never recorded as seen with no chain entry;
  * versions are bounded + charset-restricted, so SQLite and Postgres behave identically.

The scan is IDEMPOTENT per observing instance: a scheduled pass over an unchanged environment
appends NO audit event (it must not bloat the hash chain) while still advancing `last_seen_at`;
a version change does emit a fresh event; and two replicas disagreeing about a version no longer
flip one shared row on every pass.
"""

import asyncio
import hashlib
from datetime import datetime
from importlib import metadata

import pytest
from sqlalchemy import create_engine, select

from agentos_controlplane import framework_discovery as fd
from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.audit_verify import verify_chain
from agentos_controlplane.framework_discovery import (
    FRAMEWORK_CATALOGUE,
    UNPARSEABLE,
    FrameworkDetector,
    FrameworkFinding,
    detect_frameworks,
    guard_dependencies,
)
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import AuditRecord, DiscoveredFramework

# A distribution nobody has installed — the negative control for "no false positives".
ABSENT_DIST = "agentos-definitely-not-installed"
OBSERVER = "test-observer"


@pytest.fixture
def store():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    return create_session_factory(engine)


@pytest.fixture
def audit(store) -> AuditWriter:
    return AuditWriter(store)


@pytest.fixture
def site(tmp_path, monkeypatch):
    """A writable site-packages-alike on sys.path — the supply-chain surface every real deployment
    has (editable installs, vendored wheels, a writable PYTHONPATH entry). Returns a `plant`
    callable so a test can install a distribution with EXACTLY the metadata it wants."""
    root = tmp_path / "site"
    root.mkdir()
    monkeypatch.syspath_prepend(str(root))

    def plant(dist: str, version: str | None) -> None:
        # `.dist-info` directories carry the NORMALIZED distribution name (PEP 503/427), which is
        # how importlib.metadata finds them; the real name lives in METADATA.
        info = root / f"{dist.replace('-', '_')}-0.0.0.dist-info"
        info.mkdir(exist_ok=True)
        text = f"Metadata-Version: 2.1\nName: {dist}\n"
        if version is not None:
            text += f"Version: {version}\n"
        info.joinpath("METADATA").write_text(text, encoding="utf-8")

    return plant


def _events(store, kind: str) -> list[dict]:
    with store() as s:
        rows = s.scalars(select(AuditRecord).order_by(AuditRecord.seq))
        return [r.body for r in rows if r.body.get("kind") == kind]


def _rows(store) -> dict[str, DiscoveredFramework]:
    with store() as s:
        return {r.name: r for r in s.scalars(select(DiscoveredFramework)).all()}


def _detector(store, audit, catalogue, observer: str = OBSERVER) -> FrameworkDetector:
    return FrameworkDetector(store, audit, catalogue=catalogue, observer=observer)


def test_discovered_framework_round_trip(store) -> None:
    """The table holds the CURRENT observation per (observer, framework), bracketed by
    first/last-seen — the observer dimension is what keeps two replicas from sharing one row."""
    with store() as s:
        s.add(
            DiscoveredFramework(
                observer=OBSERVER, name="langchain", distribution="langchain", version="1.3.2"
            )
        )
        s.commit()

    with store() as s:
        row = s.get(DiscoveredFramework, (OBSERVER, "langchain"))
        assert row is not None
        assert (row.distribution, row.version) == ("langchain", "1.3.2")
        assert row.first_seen_at is not None
        assert row.last_seen_at is not None


def test_framework_discovered_is_a_known_event_kind(store) -> None:
    audit = AuditWriter(store)
    asyncio.run(
        audit.append_event(
            "framework_discovered",
            {
                "observer": OBSERVER,
                "framework": "langchain",
                "distribution": "langchain",
                "version_digest": hashlib.sha256(b"1.3.2").hexdigest(),
            },
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


# --- detection: evidence-based, both directions -------------------------------------------------


def test_detects_a_framework_the_guard_does_not_depend_on(site) -> None:
    """TRUE POSITIVE, and one that can actually FAIL: crewai is not a dependency of agentos-guard,
    so this only passes if the detector really resolves installed distributions."""
    site("crewai", "0.86.0")

    found = {f.name: f for f in detect_frameworks()}

    assert "crewai" in found
    assert (found["crewai"].distribution, found["crewai"].version) == ("crewai", "0.86.0")


def test_the_guards_own_dependencies_are_never_reported_as_discoveries() -> None:
    """langchain/langgraph are agentos-guard's OWN declared dependencies (via agentos-sdk), so they
    are constant-true in every install. Reporting them describes the guard's dependency graph, not
    the fleet — zero information, and in a sidecar topology it describes the wrong process."""
    assert {"langchain", "langgraph"} <= guard_dependencies()
    assert {"langchain", "langgraph"}.isdisjoint({f.name for f in detect_frameworks()})


def test_guard_dependencies_can_be_opted_back_in(site) -> None:
    """The exclusion is a default, not a wall: an operator who genuinely runs the agent in the
    control plane's interpreter can ask for the unfiltered view."""
    assert "langchain" in {f.name for f in detect_frameworks(exclude_guard_dependencies=False)}


def test_absent_distribution_is_never_reported() -> None:
    """NO FALSE POSITIVES: an inventory listing frameworks that are not there is worse than
    silence, so a catalogue naming an uninstalled distribution yields nothing."""
    assert detect_frameworks({"nope": (ABSENT_DIST,)}) == []


def test_alias_resolution_reports_the_distribution_actually_found(site) -> None:
    """The catalogue lists ALIASES (projects rename/split); the first installed one wins and the
    finding names the distribution that actually evidenced it."""
    site("pyautogen", "0.9.9")

    found = detect_frameworks({"autogen": ("not-real-dist", "pyautogen")})

    assert len(found) == 1
    assert (found[0].name, found[0].distribution) == ("autogen", "pyautogen")


def test_catalogue_covers_the_frameworks_disc_03_names() -> None:
    assert {"langchain", "langgraph", "crewai", "autogen", "openai_agents", "mcp"} <= set(
        FRAMEWORK_CATALOGUE
    )


# --- a malformed distribution degrades to "unknown", never a failed scan ------------------------


def test_distribution_with_no_version_field_is_not_reported(site) -> None:
    """`metadata.version()` has a NON-exception failure mode: a METADATA with no `Version:` field
    returns None. A finding with version=None violates the dataclass contract and lands as a NOT
    NULL violation on the row, so it must never become a finding at all."""
    site("noversion", None)
    assert metadata.version("noversion") is None  # the real behaviour this guards against

    assert detect_frameworks({"nv": ("noversion",)}) == []


def test_a_corrupt_distribution_falls_through_to_the_next_alias(site) -> None:
    """One unreadable `.dist-info` must cost that ONE alias, not the framework and not the scan."""
    site("brokenalias", None)
    site("goodalias", "2.5.0")

    found = detect_frameworks({"f": ("brokenalias", "goodalias")})

    assert [(f.distribution, f.version) for f in found] == [("goodalias", "2.5.0")]


def test_a_malformed_distribution_does_not_abort_the_whole_scan(store, audit, site) -> None:
    """A single bad distribution anywhere on sys.path must not disable discovery for everything
    else in the same pass — the frameworks after it are still detected, stored and audited."""
    site("aaa-broken", None)
    site("zzz-after", "3.1.4")
    catalogue = {"aaa": ("aaa-broken",), "zzz": ("zzz-after",)}

    findings = asyncio.run(_detector(store, audit, catalogue).scan())

    assert [f.name for f in findings] == ["zzz"]
    assert set(_rows(store)) == {"zzz"}
    assert [e["framework"] for e in _events(store, "framework_discovered")] == ["zzz"]


class _FlakyAudit:
    """An AuditWriter whose append fails for named frameworks — the fail-closed secret gate, a
    chain-head collision, or any other reason the chain can refuse a record."""

    def __init__(self, real: AuditWriter, failing: set[str]) -> None:
        self._real, self._failing = real, failing

    async def append_event(self, kind: str, body: dict):
        if body.get("framework") in self._failing:
            raise RuntimeError("chain refused the record")
        return await self._real.append_event(kind, body)


def test_a_framework_is_never_recorded_without_a_chain_entry(store, audit, site) -> None:
    """Evidence ordering: the chain entry is written FIRST. If the append fails, the row must NOT
    exist — a table asserting "this framework is present" while the tamper-evident chain has no
    record of it is exactly the silent evidence loss the chain exists to prevent."""
    site("aaa-refused", "1.0.0")
    site("zzz-after", "3.1.4")
    catalogue = {"aaa": ("aaa-refused",), "zzz": ("zzz-after",)}
    flaky = _FlakyAudit(audit, {"aaa"})

    asyncio.run(_detector(store, flaky, catalogue).scan())

    assert "aaa" not in _rows(store)  # no row without a chain entry...
    assert set(_rows(store)) == {"zzz"}  # ...and the innocent framework AFTER it still lands
    assert [e["framework"] for e in _events(store, "framework_discovered")] == ["zzz"]


def test_a_refused_append_is_retried_on_the_next_scan(store, audit, site) -> None:
    """Because nothing was recorded, the next pass still sees the framework as NEW — the failure
    is transient, not a permanent silence."""
    site("aaa-refused", "1.0.0")
    catalogue = {"aaa": ("aaa-refused",)}
    asyncio.run(_detector(store, _FlakyAudit(audit, {"aaa"}), catalogue).scan())

    asyncio.run(_detector(store, audit, catalogue).scan())

    assert _rows(store)["aaa"].version == "1.0.0"
    assert len(_events(store, "framework_discovered")) == 1


# --- externally-sourced text never reaches the audit body ---------------------------------------


def test_a_poisoned_version_cannot_block_the_chain(store, audit, site) -> None:
    """A version carrying secret-shaped text used to fail the writer's fail-closed secret gate
    AFTER the row was committed — losing the evidence permanently, since the next scan saw no
    change. The body carries a DIGEST, so there is nothing for the gate to fire on."""
    poisoned = "1.0+AKIAIOSFODNN7EXAMPLE"
    site("poison-dist", poisoned)
    catalogue = {"poisoned": ("poison-dist",)}

    asyncio.run(_detector(store, audit, catalogue).scan())

    events = _events(store, "framework_discovered")
    assert len(events) == 1
    assert "version" not in events[0]
    assert events[0]["version_digest"] == hashlib.sha256(poisoned.encode()).hexdigest()
    assert poisoned not in str(events[0])
    assert _rows(store)["poisoned"].version == poisoned  # the raw string stays in the TABLE
    assert verify_chain(store).ok


def test_audit_body_is_identifiers_and_a_digest_only(store, audit, site) -> None:
    site("zzz-after", "3.1.4")

    asyncio.run(_detector(store, audit, {"zzz": ("zzz-after",)}).scan())

    for body in _events(store, "framework_discovered"):
        # kind/seq/prev_hash are the writer's chain fields; the DISC-03 body adds exactly four
        # short identifiers — no paths, no payloads, nothing free-text.
        assert set(body) - {"kind", "seq", "prev_hash"} == {
            "observer",
            "framework",
            "distribution",
            "version_digest",
        }
        # seq is the writer's counter and prev_hash is NULL at genesis; everything DISC-03 adds is
        # a short string.
        assert all(isinstance(v, str) for k, v in body.items() if k not in ("seq", "prev_hash"))


# --- bounded, sanitized strings: SQLite and Postgres must behave identically ---------------------


def test_an_oversized_version_is_bounded_before_it_is_stored(store, audit, site) -> None:
    """A 10,000-char `Version:` is returned verbatim by importlib. SQLite would store it whole
    (VARCHAR length unenforced) and bloat the hash-covered record; Postgres would raise DataError.
    Bound it at the source so both behave the same."""
    site("bloat-dist", "9" * 10_000)

    asyncio.run(_detector(store, audit, {"bloat": ("bloat-dist",)}).scan())

    assert _rows(store)["bloat"].version == UNPARSEABLE
    assert len(_rows(store)["bloat"].version) <= 64


def test_control_characters_and_bidi_overrides_never_reach_the_row_or_the_chain(
    store, audit, site
) -> None:
    """A NUL aborts the chain write on Postgres (rejected in json/jsonb and in varchar) and an
    RTL override reaches operators verbatim through GET /discovery/frameworks. Neither survives."""
    site("evil-dist", "1.0\x00‮\x07")

    asyncio.run(_detector(store, audit, {"evil": ("evil-dist",)}).scan())

    row_version = _rows(store)["evil"].version
    assert row_version == UNPARSEABLE
    assert not any(c in row_version for c in ("\x00", "‮", "\x07"))
    assert verify_chain(store).ok


def test_a_bounded_version_is_still_reported_verbatim(site) -> None:
    """Sanitization must not eat legitimate PEP 440 versions — epochs, locals and pre-releases."""
    site("normal-dist", "1!2.0.0rc1+cuda.12")

    found = detect_frameworks({"normal": ("normal-dist",)})

    assert found[0].version == "1!2.0.0rc1+cuda.12"


def test_the_unparseable_placeholder_cannot_be_forged(site) -> None:
    """`<unparseable>` is a control-plane constant: `<` and `>` are outside the accepted charset,
    so no externally-sourced version can sanitize INTO it and impersonate the placeholder."""
    site("forge-dist", UNPARSEABLE)

    found = detect_frameworks({"forge": ("forge-dist",)})

    assert found[0].version == UNPARSEABLE  # normalized, not passed through
    assert fd._bounded(UNPARSEABLE, fd._VERSION_RE) == UNPARSEABLE


# --- scan: persistence, audit, idempotence ------------------------------------------------------


def test_scan_persists_and_audits_each_finding(store, audit, site) -> None:
    site("one-dist", "1.0.0")
    site("two-dist", "2.0.0")
    catalogue = {"one": ("one-dist",), "two": ("two-dist",)}

    findings = asyncio.run(_detector(store, audit, catalogue).scan())

    rows = _rows(store)
    assert {f.name for f in findings} == set(rows) == {"one", "two"}
    events = _events(store, "framework_discovered")
    assert {e["framework"] for e in events} == {"one", "two"}
    assert all(r.observer == OBSERVER for r in rows.values())


def test_repeat_scan_is_idempotent_but_advances_last_seen(store, audit, site) -> None:
    """A SCHEDULED scan must not bloat the hash chain: an unchanged environment appends no event,
    yet the row must still show it was observed again."""
    site("one-dist", "1.0.0")
    detector = _detector(store, audit, {"one": ("one-dist",)})
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


def test_version_change_emits_a_fresh_event_and_updates_the_row(store, audit, site) -> None:
    site("one-dist", "1.0.0")
    detector = _detector(store, audit, {"one": ("one-dist",)})
    asyncio.run(detector.scan())
    assert len(_events(store, "framework_discovered")) == 1

    site("one-dist", "1.1.0")  # the deployment upgraded
    asyncio.run(detector.scan())

    events = _events(store, "framework_discovered")
    assert len(events) == 2  # a version change IS news
    assert events[-1]["version_digest"] == hashlib.sha256(b"1.1.0").hexdigest()
    assert _rows(store)["one"].version == "1.1.0"


def test_two_observers_do_not_flip_one_shared_row(store, audit, monkeypatch) -> None:
    """Two control-plane replicas seeing DIFFERENT versions used to overwrite the same row on every
    pass — 12 events for 12 scans of an otherwise unchanged fleet, an unbounded event stream in
    steady state. Keyed by (observer, name), each replica converges to silence."""
    versions = iter(["1.3.2", "1.3.3"] * 6)
    monkeypatch.setattr(
        fd,
        "detect_frameworks",
        lambda *a, **k: [FrameworkFinding("langchain", "langchain", next(versions))],
    )
    a = FrameworkDetector(store, audit, observer="replica-a")
    b = FrameworkDetector(store, audit, observer="replica-b")

    for _ in range(6):
        asyncio.run(a.scan())
        asyncio.run(b.scan())

    assert len(_events(store, "framework_discovered")) == 2  # one per observer, not 12
    with store() as s:
        rows = {(r.observer, r.version) for r in s.scalars(select(DiscoveredFramework)).all()}
    assert rows == {("replica-a", "1.3.2"), ("replica-b", "1.3.3")}


def test_scan_leaves_the_chain_verifiable(store, audit, site) -> None:
    site("one-dist", "1.0.0")

    asyncio.run(_detector(store, audit, {"one": ("one-dist",)}).scan())

    assert verify_chain(store).ok


def test_list_frameworks_reads_back_the_inventory(store, audit, site) -> None:
    site("one-dist", "1.0.0")
    site("two-dist", "2.0.0")
    detector = _detector(store, audit, {"one": ("one-dist",), "two": ("two-dist",)})
    asyncio.run(detector.scan())

    listed = detector.list_frameworks()
    assert [d["name"] for d in listed] == sorted(d["name"] for d in listed)  # stable order
    entry = next(d for d in listed if d["name"] == "one")
    assert entry["distribution"] == "one-dist"
    assert entry["observer"] == OBSERVER
    assert entry["version"] and entry["first_seen_at"] and entry["last_seen_at"]


def test_observer_defaults_to_this_instance(store, audit, monkeypatch) -> None:
    """The row says WHICH process observed it; operators pin it explicitly per replica."""
    monkeypatch.setenv("AGENTOS_INSTANCE_ID", "control-plane-7")
    assert FrameworkDetector(store, audit).observer == "control-plane-7"


def test_a_hostile_instance_id_is_bounded_too(store, audit, monkeypatch) -> None:
    monkeypatch.setenv("AGENTOS_INSTANCE_ID", "x" * 500)
    observer = FrameworkDetector(store, audit).observer
    assert len(observer) <= 128
