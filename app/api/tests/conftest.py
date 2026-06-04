import pytest_asyncio

from chargate_api.db import migrate
from chargate_api.db.driver import SqliteDb
from chargate_api.repository import Repository


@pytest_asyncio.fixture
async def repo():
    """A repository on a fresh in-memory SQLite DB. Since D1 *is* SQLite, this
    exercises the exact portable SQL the Cloudflare D1 driver will run."""
    db = await SqliteDb.connect(":memory:")
    await migrate(db)
    try:
        yield Repository(db)
    finally:
        await db.close()
