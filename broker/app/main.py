"""FastAPI shell over :mod:`app.broker` — local development and tests only.

**Production is AWS Lambda** (``app.lambda_handler``, behind an API Gateway HTTP API;
the Terraform lives in magmamoose/infra). This module exists so ``uvicorn app.main:app``
still gives a real server to poke at, and so the existing ``TestClient`` suite keeps
exercising the same ladder the Lambda runs.

It is deliberately **not** in the deployed zip. ``scripts/build_lambda_zip.py``
excludes it by name, because it is the one module that imports FastAPI — and FastAPI
is not in the shipped dependency set. Were it included, the failure would be an
``ImportError`` at cold start on a code path nobody watches, surfacing as PR comments
quietly losing their ``Chargate[bot]`` byline.

Mirrors the Diatreme broker's ``POST /token`` contract so the action-side request
script is shared:

    request  {oidcToken, owner, repo, ref?, runId?, sha?}
    response {token, expires_at, repository}
"""

from __future__ import annotations

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.broker import handle_health, handle_ready, handle_token
from app.config import BrokerConfig
from app.oidc import KeyResolver


def create_app(
    config: BrokerConfig | None = None,
    *,
    key_resolver: KeyResolver | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> FastAPI:
    """Build the dev app. ``key_resolver``/``transport`` are test seams.

    ``config=None`` means "resolve per request", matching the Lambda.
    """
    # openapi_url=None as well as docs_url/redoc_url: disabling the two doc UIs still
    # left /openapi.json serving a machine-readable description of a token minter.
    app = FastAPI(title="Chargate token broker", docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/healthz")
    async def healthz() -> JSONResponse:
        status, body = handle_health()
        return JSONResponse(body, status_code=status)

    @app.get("/readyz")
    async def readyz() -> JSONResponse:
        status, body = handle_ready(config)
        return JSONResponse(body, status_code=status)

    @app.post("/token")
    async def token(request: Request) -> JSONResponse:
        status, body = await handle_token(
            await request.body(),
            config=config,
            key_resolver=key_resolver,
            transport=transport,
        )
        return JSONResponse(body, status_code=status)

    return app


#: Module-level ASGI app for ``uvicorn app.main:app``. Safe to build at import time
#: because config is resolved per request, so no secret is read here.
app = create_app()
