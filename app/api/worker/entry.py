# Cloudflare Python Worker entrypoint — runs the FastAPI app on Workers with D1.
#
# Workers run Python on Pyodide. The D1 database is a *binding* (env.DB) available
# only in request scope, so we inject a D1-backed driver into the app on each
# request (CHARGATE_DATABASE_URL=d1 makes the app skip its own DB init). The
# schema is applied out-of-band with `wrangler d1 migrations apply` (see
# migrations/), not at runtime.
#
# This targets Cloudflare's Python Workers ASGI support; pin compatibility flags
# in wrangler.toml. FastAPI/Pydantic are loaded as Pyodide packages.
import asgi

from chargate_api.db.driver import D1Db
from chargate_api.main import app


async def on_fetch(request, env):
    # Bind this isolate's FastAPI app to the request's D1 database.
    app.state.db = D1Db(env.DB)
    return await asgi.fetch(app, request, env)
