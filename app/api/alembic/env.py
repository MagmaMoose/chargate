"""Alembic environment — uses a sync driver derived from the app's DB URL."""
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from chargate_api.config import get_settings
from chargate_api.db import Base
from chargate_api import models  # noqa: F401 — registers tables on Base.metadata

config = context.config
if config.config_file_name:
    fileConfig(config.config_file_name)

# asyncpg is async-only; alembic runs sync, so swap the driver for migrations.
sync_url = get_settings().database_url.replace("+asyncpg", "+psycopg")
config.set_main_option("sqlalchemy.url", sync_url)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    context.configure(url=sync_url, target_metadata=target_metadata, literal_binds=True,
                      dialect_opts={"paramstyle": "named"})
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(config.get_section(config.config_ini_section, {}),
                                     prefix="sqlalchemy.", poolclass=pool.NullPool)
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
