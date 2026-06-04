"""Database provider: pick a driver from config and run the portable schema.

D1 (Workers) is created from the binding inside the Worker entrypoint, not here.
This factory covers the Postgres (container) and SQLite (local/test) paths.
"""
from pathlib import Path

from .driver import Db, PostgresDb, SqliteDb

SCHEMA = (Path(__file__).parent / "schema.sql").read_text()


async def make_db(database_url: str) -> Db:
    if database_url.startswith(("postgres://", "postgresql://", "postgresql+")):
        return await PostgresDb.connect(database_url)
    if database_url.startswith("sqlite://"):
        # sqlite:///path → path  ·  sqlite:// (empty) → in-memory
        path = database_url.split("://", 1)[1].lstrip("/") or ":memory:"
        return await SqliteDb.connect(path)
    raise ValueError(f"unsupported CHARGATE_DATABASE_URL scheme: {database_url!r}")


async def migrate(db: Db) -> None:
    """Apply the portable schema (idempotent). For D1 use `wrangler d1 migrations`."""
    await db.executescript(SCHEMA)  # type: ignore[attr-defined]


__all__ = ["Db", "PostgresDb", "SqliteDb", "make_db", "migrate", "SCHEMA"]
