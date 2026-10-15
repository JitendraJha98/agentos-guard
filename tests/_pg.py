"""Real Postgres for the test suite, without Docker (Phase 15).

`pgserver` ships the Postgres binaries as a wheel, so one server per test session is started in a
temp dir and every caller gets a FRESH database — the same isolation the in-memory SQLite stores
give, on the production-target backend. D-14 (no Docker) still holds; "no Postgres" no longer does.

`AGENTOS_TEST_DB=postgres` reruns the WHOLE suite on Postgres: conftest routes every in-memory
SQLite URL through `fresh_pg_url()`. Without it, only tests that ask for `pg_engine` touch Postgres.
"""

from __future__ import annotations

import atexit
import os
import shutil
import tempfile
import threading
import uuid

_lock = threading.Lock()
_server = None
_admin_url: str | None = None


def pg_available() -> bool:
    try:
        import pgserver  # noqa: F401
        import psycopg  # noqa: F401
    except ImportError:
        return False
    return True


def _base_url() -> str:
    """The session server's admin URL (psycopg driver), starting the server on first use."""
    global _server, _admin_url
    with _lock:
        if _admin_url is None:
            import pgserver

            data_dir = tempfile.mkdtemp(prefix="agentos-pg-")
            _server = pgserver.get_server(data_dir, cleanup_mode="stop")
            _admin_url = _server.get_uri().replace("postgresql://", "postgresql+psycopg://", 1)
            atexit.register(shutil.rmtree, data_dir, True)
        return _admin_url


def fresh_pg_url() -> str:
    """A URL to a brand-new, empty SCHEMA on the session server, pinned via `search_path`.

    A schema, not a database: CREATE DATABASE copies a template (~3 s on Windows), which made the
    whole-suite Postgres run take hours. A schema is created in milliseconds and isolates tables,
    sequences and `alembic_version` just the same. (Advisory locks are database-wide, which is fine
    because tests run sequentially.)
    """
    from sqlalchemy import create_engine, text

    base = _base_url()
    name = "t_" + uuid.uuid4().hex[:16]
    admin = create_engine(base, isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        conn.execute(text(f'CREATE SCHEMA "{name}"'))
    admin.dispose()
    return f"{base}?options=-csearch_path%3D{name}"


def use_postgres_for_suite() -> bool:
    return os.environ.get("AGENTOS_TEST_DB", "").lower() == "postgres"
