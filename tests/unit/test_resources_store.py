"""ResourceStore + resource models (API-01).

Optimistic-versioned CRUD for the declarative TrustProfile / Abom resources over a
function-scoped in-memory SQLite store (D-14: no Docker). A create starts at version 1;
an update with a stale (or missing) version raises VersionConflict (the API maps it to 409).
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine

from agentos_controlplane.store.engine import create_all, create_session_factory


@pytest.fixture
def store():
    engine = create_engine("sqlite+pysqlite:///:memory:")
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
