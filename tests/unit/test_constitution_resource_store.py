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
                seq=1,
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


def test_apply_constitution_concurrent_same_version_collapses_to_idempotent(store) -> None:
    """IDEMPOTENCY race: two concurrent applies of the SAME NEW version both see
    existing=None and both INSERT. The unique constraint on constitution.version fires
    IntegrityError on the second commit. The loser must rollback, re-SELECT the winner's
    committed rows, and return them (200 / one row) — NOT propagate the IntegrityError (500).

    Interleaving is forced deterministically: the second apply's commit is wrapped so that
    a *separate* session commits the conflicting rows first, then the real commit runs and
    trips the UNIQUE constraint — exactly the lost-update window on multi-worker Postgres."""
    from agentos_controlplane.resources import ResourceStore
    from agentos_controlplane.store.models import ConstitutionResource, PolicyResource

    rs = ResourceStore(store)
    src = yaml.safe_load(_FIXTURE.read_text(encoding="utf-8"))

    # Pre-compute the content-hash version + bundle so the concurrent "winner" inserts the
    # SAME version rows the loser is about to insert.
    from agentos_constitution import Constitution, compile_constitution

    bundle = compile_constitution(Constitution.model_validate(src))
    version = bundle.constitution_version

    real_commit = type(store()).commit
    injected = {"done": False}

    def winning_commit(self):
        # First time the loser's apply tries to commit its INSERT, the concurrent winner
        # commits identical-version rows through a distinct session -> the real commit below
        # then matches the UNIQUE(version) constraint and raises IntegrityError.
        if not injected["done"]:
            injected["done"] = True
            with store() as w:
                w.add(ConstitutionResource(name="winner", version=version, source=src))
                w.add(
                    PolicyResource(
                        constitution_version=version,
                        yaml_policy=bundle.yaml_policy,
                        rego=bundle.rego,
                        graduated_config=bundle.graduated_config,
                        lists=bundle.lists,
                        sequences=bundle.sequences,
                        seq=1,  # the injected winner is the only policy row in this store
                    )
                )
                w.commit()
        return real_commit(self)

    import unittest.mock as mock

    with mock.patch.object(type(store()), "commit", winning_commit):
        con, pol = rs.apply_constitution("test", src)  # the loser

    # Collapsed into the idempotent path: returns the winner's committed rows, no exception.
    assert con.version == version
    assert pol.constitution_version == version
    assert con.name == "winner"  # proves we returned the re-fetched committed row
    # exactly one row each — the loser's INSERT was rolled back.
    assert len(rs.list_constitutions()) == 1


@pytest.mark.regression_lock
def test_latest_policy_ignores_created_at_and_follows_seq(store) -> None:
    """Regression lock: `latest` must not be decided by the wall clock.

    The earlier fix gave `created_at` a Python-side default for microsecond resolution, but a
    Python default carries only the PLATFORM clock's resolution — ~15.6ms on Windows — so two
    applies inside one tick still tied and `get_latest_policy()` could return the OLDER policy
    (a stale GET /policies/latest, and an API-04 CacheReconciler warming the hot path to the
    WRONG constitution). Ordering derives from `seq` now, as it does for AuditRecord.

    The two rows here are written with an INVERTED `created_at` — the newer policy is stamped
    EARLIER — so a timestamp-based ORDER BY is guaranteed to pick the wrong one on every
    platform. That makes this lock independent of clock resolution, unlike the timing-sensitive
    e2e test that only exposed the bug on a coarse-clock machine.
    """
    from datetime import datetime, timedelta, timezone

    from agentos_controlplane.resources import ResourceStore
    from agentos_controlplane.store.models import PolicyResource

    now = datetime.now(timezone.utc)
    with store() as s:
        s.add(PolicyResource(
            constitution_version="older", yaml_policy="y", rego="r",
            graduated_config={}, lists={}, sequences=[], seq=1, created_at=now,
        ))
        s.add(PolicyResource(
            constitution_version="newer", yaml_policy="y", rego="r",
            graduated_config={}, lists={}, sequences=[], seq=2,
            created_at=now - timedelta(seconds=10),  # stamped EARLIER, applied LATER
        ))
        s.commit()

    assert ResourceStore(store).get_latest_policy().constitution_version == "newer"


def test_apply_assigns_strictly_increasing_policy_seq(store) -> None:
    from agentos_controlplane.resources import ResourceStore
    from agentos_controlplane.store.models import PolicyResource

    rs = ResourceStore(store)
    src = yaml.safe_load(_FIXTURE.read_text(encoding="utf-8"))
    rs.apply_constitution("t", src)
    second = dict(src)
    second["principles"] = list(src["principles"]) + [{
        "id": "4.1", "title": "Destructive intent requires approval",
        "statement": "Destructive actions require human approval.", "effect": "require_approval",
        "when": {"field": "intent.class", "op": "eq", "value": "DATA_DESTRUCTION"},
    }]
    _, newest = rs.apply_constitution("t", second)

    with store() as s:
        assert sorted(p.seq for p in s.query(PolicyResource).all()) == [1, 2]
    assert rs.get_latest_policy().constitution_version == newest.constitution_version
