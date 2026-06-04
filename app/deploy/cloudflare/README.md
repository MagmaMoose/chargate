# Deploying Chargate on Cloudflare (first-class target)

The backend runs as a **FastAPI app on Cloudflare Python Workers**, backed by
**D1**. The exact same `chargate_api` package runs on Postgres in Docker/k8s —
the only thing that changes is the database driver (chosen at runtime), so this
is configuration, not a code fork.

## Backend → Python Workers + D1

Config lives in [`app/api/worker/`](../../api/worker/): the Worker entrypoint
(`entry.py`), `wrangler.toml`, and D1 `migrations/`.

```sh
cd app/api

# 1. Create the D1 database, paste its id into worker/wrangler.toml.
npx wrangler d1 create chargate

# 2. Apply the schema (migrations/0001_init.sql — the same portable schema).
npx wrangler d1 migrations apply chargate

# 3. Secrets (never vars):
for s in GITHUB_APP_ID GITHUB_APP_PRIVATE_KEY GITHUB_WEBHOOK_SECRET \
         GITHUB_OAUTH_CLIENT_ID GITHUB_OAUTH_CLIENT_SECRET SESSION_SECRET INGEST_SECRET; do
  npx wrangler secret put CHARGATE_$s
done

# 4. Deploy.
npx wrangler deploy --config worker/wrangler.toml
```

`CHARGATE_DATABASE_URL=d1` (set in `wrangler.toml`) tells the app to skip URL-based
DB init; the Worker injects a **D1-backed driver** from the `DB` binding on each
request. Point the GitHub App **webhook URL** and **OAuth callback** at the
deployed Worker origin.

> **How D1 works here:** D1 is SQLite reached through a binding, not a DBAPI — so
> the app never imports asyncpg/SQLAlchemy on this path. The `Db` driver
> abstraction (`chargate_api/db/driver.py`) has a `D1Db` implementation that
> issues the *same portable SQL* through `env.DB.prepare(...).bind(...)`. Because
> D1 is SQLite, the local SQLite test suite exercises the identical dialect.
>
> Python Workers + ASGI is a maturing platform; pin `compatibility_flags` and
> verify FastAPI/Pydantic load as Pyodide packages for your `compatibility_date`.

## Postgres adaptability

Nothing about the app is Cloudflare-specific. Set
`CHARGATE_DATABASE_URL=postgresql://…` and the same code runs on the Postgres
driver in Docker/k8s (see [`../k8s`](../k8s) and [`../../docker-compose.yml`](../../docker-compose.yml)),
or `sqlite:///chargate.db` locally. One schema, one set of queries, three drivers.

## Frontend → Cloudflare Pages

```sh
cd app/web
npm ci
VITE_API_BASE="https://chargate.<your-domain>" npm run build
npx wrangler pages deploy dist --project-name chargate-web
```

Put the API and SPA on one hostname (route `/api/*` + `/healthz` to the Worker,
the rest to Pages) so the session cookie stays first-party.
