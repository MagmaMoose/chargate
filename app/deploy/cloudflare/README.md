# Deploying Chargate on Cloudflare (first-class target)

The same artifacts that run in Docker/k8s run on Cloudflare — nothing in the app
is Cloudflare-specific, so this is configuration, not a code fork.

## Backend (FastAPI) → Cloudflare Containers

The backend is a standard ASGI app in a container, so it deploys to
**Cloudflare Containers** using the very same `app/api/Dockerfile`.

1. Provision **Postgres** (Neon, Supabase, or any managed PG) and create a
   **Hyperdrive** config pointing at it for pooled, low-latency access:
   ```sh
   npx wrangler hyperdrive create chargate-db --connection-string "postgres://USER:PASS@HOST:5432/chargate"
   ```
   Set `CHARGATE_DATABASE_URL` to the Hyperdrive connection string
   (`postgresql+asyncpg://...`).
2. Push the image and configure the container (see `wrangler.toml`):
   ```sh
   npx wrangler containers deploy   # builds app/api/Dockerfile and rolls it out
   ```
3. Set secrets (not vars) in the dashboard or via wrangler:
   `CHARGATE_GITHUB_APP_ID`, `CHARGATE_GITHUB_APP_PRIVATE_KEY`,
   `CHARGATE_GITHUB_WEBHOOK_SECRET`, `CHARGATE_GITHUB_OAUTH_CLIENT_ID`,
   `CHARGATE_GITHUB_OAUTH_CLIENT_SECRET`, `CHARGATE_SESSION_SECRET`,
   `CHARGATE_INGEST_SECRET`.
4. Point the GitHub App **webhook URL** and OAuth **callback** at the deployed
   origin (`https://chargate.<your-domain>`), and run migrations once:
   `alembic upgrade head` (a one-off `wrangler containers run ... alembic upgrade head`).

> Why Containers and not pure Python Workers: the app needs `asyncpg`,
> SQLAlchemy and Alembic — a full Python runtime. Containers give that and keep
> the image identical to Docker/k8s. If you prefer pure Workers-Python later, the
> ASGI app object (`chargate_api.main:app`) is the same entrypoint.

## Frontend (React/Vite) → Cloudflare Pages

```sh
cd app/web
npm ci
VITE_API_BASE="https://chargate.<your-domain>" npm run build
npx wrangler pages deploy dist --project-name chargate-web
```

Or connect the repo in the Pages dashboard with build command
`npm run build`, output dir `app/web/dist`, and `VITE_API_BASE` as a build var.

## Routing

Put the API and the SPA on one hostname (recommended so the session cookie is
first-party): route `/api/*` and `/healthz` to the Containers backend and
everything else to Pages, via a Cloudflare Worker or Pages Functions proxy.
Alternatively use two hostnames and set `CHARGATE_CORS_ORIGINS` +
`CHARGATE_WEB_BASE_URL` accordingly (cookies then need `SameSite=None`).
