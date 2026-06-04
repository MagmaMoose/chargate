"""Apply the portable schema to the configured Postgres/SQLite database.

Run: `python -m chargate_api.migrate`. Idempotent (CREATE … IF NOT EXISTS).
On Cloudflare/D1 the schema is applied with `wrangler d1 migrations apply`
instead — see app/deploy/cloudflare/.
"""
import asyncio

from .config import get_settings
from .db import make_db, migrate


async def _main() -> None:
    settings = get_settings()
    db = await make_db(settings.database_url)
    try:
        await migrate(db)
        print(f"chargate: schema applied to {settings.database_url.split('://', 1)[0]}")
    finally:
        await db.close()  # type: ignore[attr-defined]


if __name__ == "__main__":
    asyncio.run(_main())
