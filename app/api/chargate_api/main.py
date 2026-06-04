"""FastAPI application factory.

Portable by design: the same app object runs under uvicorn locally, in the
Docker/k8s image, and on Cloudflare (Python Workers / Containers). Nothing here
knows where it's deployed — only the environment differs.
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware

from .config import get_settings
from .routers import auth, findings, scans, webhooks


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(title="Chargate", version="0.1.0",
                  description="Centralised security findings store + Security-tab API.")

    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.session_secret,
        same_site="lax",
        https_only=settings.is_production,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(auth.router)
    app.include_router(webhooks.router)
    app.include_router(scans.router)
    app.include_router(findings.router)

    @app.get("/healthz", tags=["meta"])
    async def healthz():
        return {"status": "ok"}

    return app


app = create_app()
