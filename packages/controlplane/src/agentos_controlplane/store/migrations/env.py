"""Alembic migration environment.

Uses a SYNC driver/URL (Alembic runs sync). The DB URL is read from
``AGENTOS_DB_URL`` if set, otherwise from alembic.ini (Postgres production
target). The Phase-1 SQLite Store bootstraps via ``Base.metadata.create_all``
and does NOT run this migration in tests; the migration is authored for the
production-target Postgres backend (D-14).
"""

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from agentos_controlplane.store.models import Base

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Allow an env-var override (e.g. a sync sqlite URL for a manual migration run).
_env_url = os.environ.get("AGENTOS_DB_URL")
if _env_url:
    config.set_main_option("sqlalchemy.url", _env_url)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
