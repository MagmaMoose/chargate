"""Chargate token broker — OIDC → repo-scoped Chargate App installation token.

Mirrors the Diatreme broker's ``POST /token`` contract so the action-side request
script is shared:

    request  {oidcToken, owner, repo, ref?, runId?, sha?}
    response {token, expires_at, repository}

The endpoint is **public** (GitHub runners must reach it) and authenticates each
caller by verifying their Actions OIDC token — never a shared secret. The minted
token is scoped to the caller's own repo with ``pull_requests: write`` only.
"""

from __future__ import annotations

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from broker.config import BrokerConfig
from broker.github import mint_installation_token
from broker.oidc import KeyResolver, OidcError, verify_oidc_token


def create_app(
    config: BrokerConfig | None = None,
    *,
    key_resolver: KeyResolver | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> FastAPI:
    """Build the broker app. ``key_resolver``/``transport`` are test seams."""
    config = config or BrokerConfig()
    app = FastAPI(title="Chargate token broker", docs_url=None, redoc_url=None)

    @app.get("/healthz")
    @app.get("/readyz")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/token")
    async def token(request: Request) -> JSONResponse:
        try:
            body = await request.json()
        except ValueError:
            return JSONResponse({"error": "invalid_json"}, status_code=400)
        if not isinstance(body, dict):
            return JSONResponse({"error": "invalid_json"}, status_code=400)

        oidc_token = body.get("oidcToken")
        owner = body.get("owner")
        repo = body.get("repo")
        if not (oidc_token and owner and repo):
            return JSONResponse({"error": "missing_fields"}, status_code=400)
        repository = f"{owner}/{repo}"

        allowlist = config.allowed()
        if allowlist and repository not in allowlist:
            return JSONResponse({"error": "repo_not_allowed"}, status_code=403)

        try:
            claims = verify_oidc_token(oidc_token, config.oidc_audience, key_resolver=key_resolver)
        except OidcError as exc:
            return JSONResponse({"error": "invalid_oidc", "detail": str(exc)}, status_code=401)

        # The OIDC `repository` claim is the caller's repo — it must match the
        # repo they're asking for a token for. This is what stops repo A minting
        # a token for repo B.
        if claims.get("repository") != repository:
            return JSONResponse({"error": "repo_mismatch"}, status_code=403)

        try:
            async with httpx.AsyncClient(timeout=15.0, transport=transport) as client:
                token_value, expires_at = await mint_installation_token(
                    client,
                    app_id=config.app_id,
                    private_key=config.private_key,
                    owner=owner,
                    repo=repo,
                    permissions=config.permissions(),
                    api_url=config.github_api_url,
                )
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code
            # App not installed on the repo → 404 from /installation.
            reason = "app_not_installed" if status == 404 else "mint_failed"
            return JSONResponse({"error": reason}, status_code=403 if status == 404 else 502)
        except httpx.HTTPError:
            return JSONResponse({"error": "mint_failed"}, status_code=502)

        return JSONResponse(
            {"token": token_value, "expires_at": expires_at, "repository": repository}
        )

    return app
