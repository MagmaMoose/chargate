"""FastAPI application factory.

Portable by design: the same `app` runs under uvicorn locally, in the Docker/k8s
image (Postgres), and on Cloudflare Python Workers (D1). The only difference is
how `app.state.db` is provided:
  • container / local — the lifespan below builds it from CHARGATE_DATABASE_URL
  • Cloudflare Worker — the entrypoint injects a D1-backed driver per request
    (the D1 binding only exists in request scope), so set CHARGATE_DATABASE_URL=d1
    to skip the lifespan DB init there.
"""
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware

from .config import get_settings
from .db import make_db, migrate
from .routers import auth, findings, scans, webhooks


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    db = None
    if settings.database_url and not settings.database_url.startswith("d1"):
        db = await make_db(settings.database_url)
        await migrate(db)
        app.state.db = db
    yield
    if db is not None:
        await db.close()  # type: ignore[attr-defined]


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(title="Chargate", version="0.1.0", lifespan=lifespan,
                  description="Centralised security findings store + Security-tab API.")

    app.add_middleware(SessionMiddleware, secret_key=settings.session_secret,
                       same_site="lax", https_only=settings.is_production)
    app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins,
                       allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

    app.include_router(auth.router)
    app.include_router(webhooks.router)
    app.include_router(scans.router)
    app.include_router(findings.router)

    @app.get("/healthz", tags=["meta"])
    async def healthz():
        return {"status": "ok"}

    return app


app = create_app()
