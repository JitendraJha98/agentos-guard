"""Engine / sessionmaker factory.

D-14 no-Docker deviation: the active Phase-1 backend is SQLite. The DB URL is
read from the environment (``AGENTOS_DB_URL``) and defaults to an on-disk SQLite
file so the control plane runs with zero external services. The factory returns
a sync SQLAlchemy engine + sessionmaker — sufficient for the single-process
skeleton (the registry lookups and the serial audit chain are not I/O-bound on
SQLite). Swapping to async asyncpg/Postgres is a factory change behind the same
Store seam (Phase 5).
"""

import os

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from agentos_controlplane.store.models import Base

# Default to a local SQLite file (no Docker / no Postgres). Tests pass an
# explicit in-memory URL / engine instead.
DEFAULT_DB_URL = "sqlite+pysqlite:///agentos_controlplane.db"


def db_url() -> str:
    return os.environ.get("AGENTOS_DB_URL", DEFAULT_DB_URL)


def create_store_engine(url: str | None = None) -> Engine:
    """Build a sync engine for the control-plane store."""
    return create_engine(url or db_url())


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False)


def create_all(engine: Engine) -> None:
    """Create the registry + audit schema (Phase-1 SQLite bootstrap).

    The Alembic migration (0001_initial) is the production-target path; for the
    SQLite Store this `create_all` is the equivalent bootstrap.
    """
    Base.metadata.create_all(engine)
