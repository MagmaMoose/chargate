"""Chargate token broker — OIDC → repo-scoped Chargate App installation token.

Mirrors the Diatreme broker's ``POST /token`` contract so the action-side request
script is shared:

    request  {oidcToken, owner, repo, ref?, runId?, sha?}
    response {token, expires_at, repository}

The endpoint is **public** (GitHub runners must reach it) and authenticates each
caller by verifying their Actions OIDC token — never a shared secret. The minted
token is scoped to the caller's own repo with ``pull_requests: write`` only.

Runs unchanged as a container (uvicorn) or as a Cloudflare Python Worker (the
runtime's ASGI bridge, via ``entry.py``). The only runtime-shaped difference is
where configuration comes from — see ``app.config``.
"""

from __future__ import annotations

import logging

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.config import BrokerConfig, load_config
from app.github import InvalidRepositoryError, mint_installation_token, validate_repository
from app.oidc import JwksUnavailable, KeyResolver, OidcError, verify_oidc_token

# Nothing request-derived is ever passed to this logger. /token is unauthenticated, so a
# caller-supplied string reaching a log record is CodeQL py/log-injection — see the
# OidcError handler for what is logged instead and why.
_log = logging.getLogger("chargate.broker")


def create_app(
    config: BrokerConfig | None = None,
    *,
    key_resolver: KeyResolver | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> FastAPI:
    """Build the broker app. ``key_resolver``/``transport`` are test seams.

    ``config=None`` means "resolve per request". That is required on a Worker,
    where secrets only exist on the invocation's ``env`` and so cannot be read at
    import time; passing an explicit config (as the tests do) keeps the old
    construct-time behaviour.
    """
    app = FastAPI(title="Chargate token broker", docs_url=None, redoc_url=None)

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        """Liveness. Answers whether or not configuration is present.

        This is what makes the Worker's "deploy once, then set the secrets" flow
        work: Cloudflare has no API for a secret on a script that was never
        uploaded, so the first deploy has to come up healthy with neither secret.
        """
        return {"status": "ok"}

    @app.get("/readyz")
    async def readyz() -> JSONResponse:
        """Readiness — liveness *and* resolvable configuration.

        Deliberately stricter than /healthz. Config used to be built when the app
        was constructed, so a broker missing APP_ID/PRIVATE_KEY crash-looped and was
        impossible to miss. Resolving per request (which the Worker requires, since
        secrets only exist on the invocation's `env`) would otherwise trade that
        loud failure for a pod that reports Ready and 500s on every token request.
        """
        try:
            config or load_config()
        except Exception:
            return JSONResponse({"status": "misconfigured"}, status_code=503)
        return JSONResponse({"status": "ok"})

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
        if not (isinstance(owner, str) and isinstance(repo, str)):
            return JSONResponse({"error": "invalid_repository"}, status_code=400)
        # Reject anything that isn't a plain GitHub owner/repo identifier before it
        # reaches an API URL or a claim comparison. A value containing '/' or '..'
        # would otherwise let the caller steer the request path (py/partial-ssrf).
        try:
            owner, repo = validate_repository(owner, repo)
        except InvalidRepositoryError:
            return JSONResponse({"error": "invalid_repository"}, status_code=400)
        repository = f"{owner}/{repo}"

        try:
            active = config or load_config()
        except Exception:
            # Missing or malformed APP_ID/PRIVATE_KEY. A 500 with a pydantic
            # traceback would read as a broker bug; this is a deployment that was
            # never finished, and the caller should retry once it is.
            return JSONResponse({"error": "config_unavailable"}, status_code=503)

        allowlist = active.allowed()
        if allowlist and repository not in allowlist:
            return JSONResponse({"error": "repo_not_allowed"}, status_code=403)

        # One client for both the JWKS fetch and the GitHub calls, so a warm
        # isolate reuses the connection. In tests `transport` mocks GitHub and a
        # `key_resolver` is always supplied, so the JWKS path never opens a socket.
        async with httpx.AsyncClient(timeout=15.0, transport=transport) as client:
            try:
                claims = await verify_oidc_token(
                    oidc_token,
                    active.oidc_audience,
                    client=client,
                    key_resolver=key_resolver,
                )
            except JwksUnavailable:
                return JSONResponse({"error": "jwks_unavailable"}, status_code=503)
            except OidcError as exc:
                # The exception text comes from PyJWT and can carry key ids, expected
                # audiences and other internals. It goes to the broker's own log (where
                # an operator debugging a consumer's OIDC setup needs it) and never to
                # the unauthenticated caller (CodeQL py/stack-trace-exposure).
                #
                # Both values go through _for_log: /token is unauthenticated, so writing
                # Only the exception's CLASS NAME is logged — never its message, and
                # never the caller-supplied repository. Both of those are request-derived
                # strings, and writing either into a log record on an unauthenticated
                # endpoint is CodeQL py/log-injection: a CRLF in the value forges a
                # second log line. A regex scrub at the sink genuinely prevents that but
                # is not a barrier CodeQL recognises, so the taint is removed instead of
                # laundered. `type(exc).__name__` carries no attacker-controlled bytes.
                #
                # This is also the more useful field: ExpiredSignatureError vs
                # InvalidAudienceError vs InvalidSignatureError names the misconfiguration
                # an operator is actually chasing, where the unverified repo name — which
                # the caller simply asserted — does not. Correlate to a specific request
                # through the access log.
                #
                # The CAUSE, not the OidcError itself: verify_oidc_token wraps every PyJWT
                # failure as `raise OidcError(str(exc)) from exc` (app.oidc), so the
                # wrapper's own name is the same string every time and says nothing. A few
                # OidcErrors are raised with no cause (missing kid, no resolver), hence the
                # fallback.
                cause = exc.__cause__
                _log.warning(
                    "OIDC verification failed: %s",
                    type(cause).__name__ if cause is not None else type(exc).__name__,
                )
                return JSONResponse({"error": "invalid_oidc"}, status_code=401)

            # The OIDC `repository` claim is the caller's repo — it must match the
            # repo they're asking for a token for. This is what stops repo A minting
            # a token for repo B.
            if claims.get("repository") != repository:
                return JSONResponse({"error": "repo_mismatch"}, status_code=403)

            try:
                token_value, expires_at = await mint_installation_token(
                    client,
                    app_id=active.app_id,
                    private_key=active.private_key,
                    owner=owner,
                    repo=repo,
                    permissions=active.permissions(),
                    api_url=active.github_api_url,
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


#: Module-level ASGI app for the Worker bridge (``asgi.fetch(app, ...)``) and for
#: ``uvicorn app.main:app``. Safe to build at import time because config is
#: resolved per request, so no secret is read here.
app = create_app()
