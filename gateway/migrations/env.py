"""Alembic environment. DB URL comes from AEGIS_DATABASE_URL (S10).

The gateway itself treats an unset ``AEGIS_DATABASE_URL`` as "use the in-memory
store", but a migration against no database is meaningless — so this script
fails fast with an actionable message instead of letting SQLAlchemy raise a bare
``KeyError: 'url'`` from deep inside ``engine_from_config``. Migrations run as a
one-shot init container in production (deploy/k8s/deployment.yaml), where that
opaque traceback surfaces only as a CrashLoopBackOff.
"""
from __future__ import annotations

import os

from alembic import context
from sqlalchemy import engine_from_config, pool

# Async drivers cannot back Alembic's synchronous engine. The store uses the
# sync psycopg driver (app/storage/sql_store.py), so the URL must match.
_ASYNC_DRIVERS = ("asyncpg", "aiosqlite", "aiomysql", "asyncmy", "psycopg_async")

config = context.config


def _database_url() -> str:
    """Resolve and validate the migration target URL."""
    url = os.getenv("AEGIS_DATABASE_URL", "").strip()
    if not url:
        raise SystemExit(
            "AEGIS_DATABASE_URL is not set — Alembic has no database to migrate.\n"
            "Set it to the same sync psycopg URL the gateway uses, e.g.:\n"
            "  export AEGIS_DATABASE_URL="
            "postgresql+psycopg://aegis:<password>@localhost:5432/aegis\n"
            "See .env.example and docs/PRODUCTION.md."
        )

    driver = url.split("://", 1)[0]
    if any(d in driver for d in _ASYNC_DRIVERS):
        raise SystemExit(
            f"AEGIS_DATABASE_URL uses the async driver '{driver}', which cannot "
            "back Alembic's synchronous engine.\n"
            "Use the sync psycopg driver instead, e.g.:\n"
            "  postgresql+psycopg://aegis:<password>@localhost:5432/aegis"
        )

    return url


config.set_main_option("sqlalchemy.url", _database_url())

target_metadata = None  # migrations are explicit (op.create_table)


def run_migrations_offline() -> None:
    context.configure(url=config.get_main_option("sqlalchemy.url"),
                      literal_binds=True, dialect_opts={"paramstyle": "named"})
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.", poolclass=pool.NullPool)
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
