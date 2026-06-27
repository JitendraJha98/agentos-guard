"""ResourceStore + resource models (API-01).

Optimistic-versioned CRUD for the declarative TrustProfile / Abom resources over a
function-scoped in-memory SQLite store (D-14: no Docker). A create starts at version 1;
an update with a stale (or missing) version raises VersionConflict (the API maps it to 409).
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm.exc import StaleDataError
from sqlalchemy.pool import StaticPool

from agentos_controlplane.store.engine import create_all, create_session_factory


@pytest.fixture
def store():
    # StaticPool + check_same_thread=False: one shared in-memory DB across every
    # session() so the concurrency tests can interleave two real sessions over it.
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    create_all(engine)
    return create_session_factory(engine)


def test_models_round_trip(store) -> None:
    """The two new ORM models persist and read back through the shared store."""
    from agentos_controlplane.store.models import Abom, TrustProfile

    with store() as s:
        s.add(TrustProfile(agent_id="a", trust_score=0.7))
        s.add(Abom(agent_id="a", components={"tools": ["http_get"]}))
        s.commit()
    with store() as s:
        tp = s.get(TrustProfile, "a")
        ab = s.get(Abom, "a")
        assert tp.trust_score == 0.7 and tp.version == 1
        assert ab.components == {"tools": ["http_get"]} and ab.version == 1


def test_trust_profile_create_update_conflict_list(store) -> None:
    from agentos_controlplane.resources import ResourceStore, VersionConflict

    rs = ResourceStore(store)

    created = rs.put_trust_profile("a", trust_score=0.7, band=None, expected_version=None)
    assert created.version == 1 and created.trust_score == 0.7

    got = rs.get_trust_profile("a")
    assert got is not None and got.version == 1

    updated = rs.put_trust_profile("a", trust_score=0.8, band={"x": 1}, expected_version=1)
    assert updated.version == 2 and updated.trust_score == 0.8 and updated.band == {"x": 1}

    with pytest.raises(VersionConflict):
        rs.put_trust_profile("a", trust_score=0.9, band=None, expected_version=1)

    # missing version on an existing row also conflicts.
    with pytest.raises(VersionConflict):
        rs.put_trust_profile("a", trust_score=0.9, band=None, expected_version=None)

    rs.put_trust_profile("b", trust_score=0.5, band=None, expected_version=None)
    listed = rs.list_trust_profiles()
    assert [d.agent_id for d in listed] == ["a", "b"]  # sorted

    assert rs.get_trust_profile("missing") is None


def test_abom_create_update_conflict_list(store) -> None:
    from agentos_controlplane.resources import ResourceStore, VersionConflict

    rs = ResourceStore(store)

    created = rs.put_abom("a", components={"tools": ["http_get"]}, expected_version=None)
    assert created.version == 1 and created.components == {"tools": ["http_get"]}

    got = rs.get_abom("a")
    assert got is not None and got.version == 1

    updated = rs.put_abom("a", components={"tools": ["drop_table"]}, expected_version=1)
    assert updated.version == 2 and updated.components == {"tools": ["drop_table"]}

    with pytest.raises(VersionConflict):
        rs.put_abom("a", components={"tools": []}, expected_version=1)

    rs.put_abom("b", components={"models": ["m1"]}, expected_version=None)
    listed = rs.list_aboms()
    assert [d.agent_id for d in listed] == ["a", "b"]  # sorted

    assert rs.get_abom("missing") is None


def test_trust_profile_concurrent_update_is_atomic(store) -> None:
    """Two writers that read the SAME version and both commit: the SECOND must lose.

    The optimistic guard must be enforced at the SQL layer (UPDATE ... WHERE version =
    :expected), not by a Python read-then-compare — otherwise the documented Postgres
    target (distinct connections, READ COMMITTED) silently drops the second write. We
    interleave two real sessions to expose the lost update the in-Python check misses;
    `version_id_col` makes the stale second commit raise StaleDataError.
    """
    from agentos_controlplane.resources import ResourceStore
    from agentos_controlplane.store.models import TrustProfile

    rs = ResourceStore(store)
    rs.put_trust_profile("a", trust_score=0.5, band=None, expected_version=None)  # version 1

    # Writer 1 and writer 2 both read version 1 before either commits.
    s1, s2 = store(), store()
    r1 = s1.get(TrustProfile, "a")
    r2 = s2.get(TrustProfile, "a")
    assert r1.version == r2.version == 1

    r1.trust_score = 0.6
    s1.commit()  # first write wins -> version 2

    # Second writer still holds the stale version-1 image; its commit must conflict,
    # not silently clobber writer 1's change.
    r2.trust_score = 0.9
    with pytest.raises(StaleDataError):
        s2.commit()
    s1.close()
    s2.close()

    assert rs.get_trust_profile("a").trust_score == 0.6  # writer 1 preserved


def test_abom_concurrent_update_is_atomic(store) -> None:
    """Same atomic-guard contract for the Abom resource (see trust_profile twin)."""
    from agentos_controlplane.resources import ResourceStore
    from agentos_controlplane.store.models import Abom

    rs = ResourceStore(store)
    rs.put_abom("a", components={"tools": ["t1"]}, expected_version=None)  # version 1

    s1, s2 = store(), store()
    r1 = s1.get(Abom, "a")
    r2 = s2.get(Abom, "a")
    assert r1.version == r2.version == 1

    r1.components = {"tools": ["t2"]}
    s1.commit()

    r2.components = {"tools": ["evil"]}
    with pytest.raises(StaleDataError):
        s2.commit()
    s1.close()
    s2.close()

    assert rs.get_abom("a").components == {"tools": ["t2"]}


def test_put_maps_concurrent_conflict_to_version_conflict(store, monkeypatch) -> None:
    """The store maps the atomic StaleDataError to its public VersionConflict.

    A genuine concurrent stale write surfaces as StaleDataError on commit (not the
    fast-fail equality check). put_* must translate that to VersionConflict so the API
    still returns 409 for the concurrent case, not a 500.
    """
    from sqlalchemy.orm import Session

    from agentos_controlplane.resources import ResourceStore, VersionConflict

    rs = ResourceStore(store)
    rs.put_trust_profile("a", trust_score=0.5, band=None, expected_version=None)  # version 1

    # Simulate the race: the row passes the in-Python equality check (it still reads
    # version 1) but a concurrent writer has advanced it, so the atomic commit fails.
    def stale_commit(self):
        raise StaleDataError("UPDATE matched 0 rows")

    monkeypatch.setattr(Session, "commit", stale_commit)
    with pytest.raises(VersionConflict):
        rs.put_trust_profile("a", trust_score=0.6, band=None, expected_version=1)
