"""Database driver abstraction.

Chargate's first-class target is Cloudflare Python Workers backed by **D1**
(SQLite over a binding), but the same backend must run on **Postgres** (Docker /
k8s) and **SQLite** (local / tests). None of those share a wire protocol — D1 is
a binding, not a DBAPI; Pyodide on Workers can't load asyncpg/SQLAlchemy — so the
app talks to a tiny async `Db` interface and the repository writes portable SQL.

Portability rules the repository SQL follows:
  • `?` positional placeholders (Postgres driver rewrites them to `$1…$n`)
  • TEXT for ids (uuid hex), JSON (stringified), and timestamps (ISO-8601)
  • INTEGER 0/1 for booleans
so one schema and one set of statements run unchanged on D1, SQLite and Postgres.
"""
from __future__ import annotations

import re
from typing import Any, Protocol, Sequence, runtime_checkable

Params = Sequence[Any]


@runtime_checkable
class Db(Protocol):
    async def fetch_all(self, sql: str, params: Params = ()) -> list[dict]: ...
    async def fetch_one(self, sql: str, params: Params = ()) -> dict | None: ...
    async def execute(self, sql: str, params: Params = ()) -> None: ...
    async def execute_many(self, sql: str, rows: Sequence[Params]) -> None: ...


# ── SQLite / aiosqlite (local dev + tests; same dialect D1 runs) ──────────────
class SqliteDb:
    def __init__(self, conn):
        self._conn = conn  # aiosqlite.Connection

    @classmethod
    async def connect(cls, path: str) -> "SqliteDb":
        import aiosqlite

        conn = await aiosqlite.connect(path)
        conn.row_factory = aiosqlite.Row
        await conn.execute("PRAGMA foreign_keys = ON")
        return cls(conn)

    async def fetch_all(self, sql: str, params: Params = ()) -> list[dict]:
        cur = await self._conn.execute(sql, tuple(params))
        rows = await cur.fetchall()
        await cur.close()
        return [dict(r) for r in rows]

    async def fetch_one(self, sql: str, params: Params = ()) -> dict | None:
        cur = await self._conn.execute(sql, tuple(params))
        row = await cur.fetchone()
        await cur.close()
        return dict(row) if row else None

    async def execute(self, sql: str, params: Params = ()) -> None:
        await self._conn.execute(sql, tuple(params))
        await self._conn.commit()

    async def execute_many(self, sql: str, rows: Sequence[Params]) -> None:
        await self._conn.executemany(sql, [tuple(r) for r in rows])
        await self._conn.commit()

    async def executescript(self, script: str) -> None:
        await self._conn.executescript(script)
        await self._conn.commit()

    async def close(self) -> None:
        await self._conn.close()


# ── Postgres / asyncpg (Docker, k8s) ─────────────────────────────────────────
_PLACEHOLDER = re.compile(r"\?")


def _to_pg(sql: str) -> str:
    """`?, ?, ?` → `$1, $2, $3` for asyncpg."""
    counter = iter(range(1, 10_000))
    return _PLACEHOLDER.sub(lambda _: f"${next(counter)}", sql)


class PostgresDb:
    def __init__(self, pool):
        self._pool = pool  # asyncpg.Pool

    @classmethod
    async def connect(cls, dsn: str) -> "PostgresDb":
        import asyncpg

        # asyncpg wants a bare postgres DSN, not the SQLAlchemy-style +driver URL.
        dsn = dsn.replace("postgresql+asyncpg://", "postgresql://").replace("+psycopg", "")
        pool = await asyncpg.create_pool(dsn, min_size=1, max_size=10)
        return cls(pool)

    async def fetch_all(self, sql: str, params: Params = ()) -> list[dict]:
        rows = await self._pool.fetch(_to_pg(sql), *params)
        return [dict(r) for r in rows]

    async def fetch_one(self, sql: str, params: Params = ()) -> dict | None:
        row = await self._pool.fetchrow(_to_pg(sql), *params)
        return dict(row) if row else None

    async def execute(self, sql: str, params: Params = ()) -> None:
        await self._pool.execute(_to_pg(sql), *params)

    async def execute_many(self, sql: str, rows: Sequence[Params]) -> None:
        await self._pool.executemany(_to_pg(sql), [tuple(r) for r in rows])

    async def executescript(self, script: str) -> None:
        async with self._pool.acquire() as conn:
            await conn.execute(script)

    async def close(self) -> None:
        await self._pool.close()


# ── Cloudflare D1 (first-class, runs inside a Python Worker) ──────────────────
class D1Db:
    """Wraps a D1 binding (``env.DB``). Only constructed inside the Worker, where
    the binding exists; never imported on the Postgres/SQLite paths."""

    def __init__(self, binding):
        self._db = binding

    @staticmethod
    def _rows(result) -> list[dict]:
        # D1 returns { results: [...] }; in Pyodide these are JS proxies.
        results = getattr(result, "results", None)
        if results is None and isinstance(result, dict):
            results = result.get("results", [])
        out = []
        for r in results or []:
            out.append(dict(r.to_py()) if hasattr(r, "to_py") else dict(r))
        return out

    async def fetch_all(self, sql: str, params: Params = ()) -> list[dict]:
        stmt = self._db.prepare(sql).bind(*params)
        return self._rows(await stmt.all())

    async def fetch_one(self, sql: str, params: Params = ()) -> dict | None:
        rows = await self.fetch_all(sql, params)
        return rows[0] if rows else None

    async def execute(self, sql: str, params: Params = ()) -> None:
        await self._db.prepare(sql).bind(*params).run()

    async def execute_many(self, sql: str, rows: Sequence[Params]) -> None:
        batch = [self._db.prepare(sql).bind(*r) for r in rows]
        await self._db.batch(batch)
