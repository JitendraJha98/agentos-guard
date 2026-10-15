"""The production-target backend, exercised for real (Phase 15).

Until now every migration was "authored for Postgres" and run only on SQLite (D-14). These tests run
the full chain on a real Postgres (pgserver — no Docker) and compare the result against the models,
because a schema that migrates but drifts from what the ORM expects fails at the first query, not at
`upgrade head`.
"""

from __future__ import annotations

import pathlib

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect, text

from _pg import fresh_pg_url, pg_available
from agentos_controlplane.store.models import Base

pytestmark = pytest.mark.skipif(not pg_available(), reason="pgserver/psycopg not installed")

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_SCRIPTS = "packages/controlplane/src/agentos_controlplane/store/migrations"


@pytest.fixture
def alembic_on_postgres(monkeypatch):
    monkeypatch.chdir(_ROOT)
    url = fresh_pg_url()
    monkeypatch.setenv("AGENTOS_DB_URL", url)  # env.py prefers the env var over alembic.ini
    config = Config(str(_ROOT / "alembic.ini"))
    config.set_main_option("script_location", _SCRIPTS)
    config.set_main_option("sqlalchemy.url", url.replace("%", "%%"))  # ConfigParser interpolation
    engine = create_engine(url)
    yield config, engine
    engine.dispose()


def test_the_full_migration_chain_applies_on_postgres(alembic_on_postgres) -> None:
    config, engine = alembic_on_postgres
    command.upgrade(config, "head")
    tables = set(inspect(engine).get_table_names())
    assert set(Base.metadata.tables) <= tables, set(Base.metadata.tables) - tables


def test_the_migrated_schema_matches_the_models(alembic_on_postgres) -> None:
    """No drift between `upgrade head` and `Base.metadata` — types, nullability, columns, tables.
    Index/constraint naming is compared too: a missing UNIQUE is a missing invariant."""
    config, engine = alembic_on_postgres
    command.upgrade(config, "head")
    with engine.connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn), Base.metadata)
    assert diff == [], diff


def test_the_chain_downgrades_to_base_and_back(alembic_on_postgres) -> None:
    config, engine = alembic_on_postgres
    command.upgrade(config, "head")
    command.downgrade(config, "base")
    assert set(inspect(engine).get_table_names()) <= {"alembic_version"}
    command.upgrade(config, "head")


def test_the_audit_table_refuses_update_and_delete_on_postgres(alembic_on_postgres) -> None:
    """The append-only trigger from 0001 is the DB-level second line of defence. It has only ever
    been asserted on SQLite; on Postgres it is PL/pgSQL, a different code path entirely."""
    config, engine = alembic_on_postgres
    command.upgrade(config, "head")
    with engine.begin() as c:
        c.execute(
            text(
                "INSERT INTO audit_record (id, seq, prev_hash, record_hash, body) "
                "VALUES (gen_random_uuid(), 0, NULL, 'h0', '{}')"
            )
        )
    for stmt in ("UPDATE audit_record SET record_hash = 'x'", "DELETE FROM audit_record"):
        with pytest.raises(Exception):
            with engine.begin() as c:
                c.execute(text(stmt))
    with engine.begin() as c:
        assert c.execute(text("SELECT record_hash FROM audit_record")).scalar_one() == "h0"


def test_a_percent_encoded_env_url_does_not_crash_the_migration(monkeypatch) -> None:
    """A production password like `p%40ss` (URL-encoded `p@ss`) reaches env.py through
    AGENTOS_DB_URL. ConfigParser interpolation used to reject the `%` before any SQL ran."""
    monkeypatch.chdir(_ROOT)
    url = fresh_pg_url()  # carries `%3D` in its query string
    monkeypatch.setenv("AGENTOS_DB_URL", url)
    config = Config(str(_ROOT / "alembic.ini"))
    config.set_main_option("script_location", _SCRIPTS)
    command.upgrade(config, "head")
    assert "audit_record" in inspect(create_engine(url)).get_table_names()
