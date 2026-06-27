"""ConstitutionResource + PolicyResource models and apply_constitution (API-02).

Compile-on-write: applying a Constitution validates (Pydantic) + compiles (the pure
agentos_constitution compiler) + persists the Constitution version AND its derived Policy
in ONE transaction over a function-scoped in-memory SQLite store (D-14: no Docker). A
malformed document raises ConstitutionError with NOTHING written; apply is idempotent on
the content-hash constitution_version (re-applying the same source returns the existing rows).
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from agentos_controlplane.store.engine import create_all, create_session_factory

_FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "test_constitution.yaml"


@pytest.fixture
def store():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    create_all(engine)
    return create_session_factory(engine)


def test_models_round_trip(store) -> None:
    """The two new ORM models persist and read back through the shared store."""
    from agentos_controlplane.store.models import ConstitutionResource, PolicyResource

    with store() as s:
        s.add(ConstitutionResource(name="t", version="v1", source={"a": 1}))
        s.add(
            PolicyResource(
                constitution_version="v1",
                yaml_policy="y",
                rego="r",
                graduated_config={},
                lists={},
                sequences=[],
            )
        )
        s.commit()
    with store() as s:
        con = s.get(ConstitutionResource, _only_id(s))
        pol = s.scalars(_select_policy()).one()
        assert con.name == "t" and con.version == "v1" and con.source == {"a": 1}
        assert pol.constitution_version == "v1" and pol.rego == "r" and pol.yaml_policy == "y"
        assert pol.graduated_config == {} and pol.lists == {} and pol.sequences == []


def _only_id(s):
    from agentos_controlplane.store.models import ConstitutionResource

    return s.scalars(_select_constitution()).one().id


def _select_constitution():
    from sqlalchemy import select

    from agentos_controlplane.store.models import ConstitutionResource

    return select(ConstitutionResource)


def _select_policy():
    from sqlalchemy import select

    from agentos_controlplane.store.models import PolicyResource

    return select(PolicyResource)


# ---- apply_constitution: compile-on-write, atomic, idempotent ----
def test_apply_constitution_compiles_and_persists(store) -> None:
    from agentos_controlplane.resources import ResourceStore

    rs = ResourceStore(store)
    src = yaml.safe_load(_FIXTURE.read_text(encoding="utf-8"))

    con, pol = rs.apply_constitution("test", src)

    assert con.version == pol.constitution_version
    assert "package agentos.constitution" in pol.rego
    assert pol.yaml_policy  # non-empty reviewable middle layer
    # the latest compiled policy is retrievable for the engine
    latest = rs.get_latest_policy()
    assert latest is not None and latest.constitution_version == con.version
    assert "package agentos.constitution" in latest.rego
    # version-keyed reads
    assert rs.get_constitution(con.version) is not None
    assert rs.get_policy(con.version) is not None


def test_apply_constitution_malformed_writes_nothing(store) -> None:
    from agentos_controlplane.resources import ConstitutionError, ResourceStore

    rs = ResourceStore(store)
    src = yaml.safe_load(_FIXTURE.read_text(encoding="utf-8"))
    bad = {**src, "bogus_top_level": 1}  # extra=forbid -> ValidationError

    with pytest.raises(ConstitutionError):
        rs.apply_constitution("test", bad)

    # fail-closed: nothing persisted
    assert rs.list_constitutions() == []
    assert rs.get_latest_policy() is None


def test_apply_constitution_is_idempotent(store) -> None:
    from agentos_controlplane.resources import ResourceStore

    rs = ResourceStore(store)
    src = yaml.safe_load(_FIXTURE.read_text(encoding="utf-8"))

    con1, pol1 = rs.apply_constitution("test", src)
    con2, pol2 = rs.apply_constitution("test", src)  # same source -> same content-hash version

    assert con1.version == con2.version
    assert pol1.constitution_version == pol2.constitution_version
    assert len(rs.list_constitutions()) == 1  # no duplicate row
