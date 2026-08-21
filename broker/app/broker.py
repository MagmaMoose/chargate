"""The broker's decisions, with no HTTP framework attached.

Every endpoint is a function from a request to ``(status, body)``. Two callers use
them unchanged:

* ``app.lambda_handler`` — production, behind an API Gateway HTTP API.
* ``app.main`` — a FastAPI shell for local development and the existing test suite.

**This module is the reason there is nothing to drift.** The Cloudflare Worker design
this replaces needed the logic to survive being re-hosted; the k8s design needed it to
survive a container. Lifting it out of the route handlers means the Lambda runs the
same ladder the tests exercise, rather than a copy of it — the same argument nievah's
edge package makes for ``verify_signature``.

THE EVALUATION ORDER IS LOAD-BEARING and is preserved verbatim from the FastAPI
handler it was lifted from. In particular a malformed request is answered *before*
configuration is consulted (``tests/test_readiness.py::test_bad_request_still_precedes_config``):
a caller who sent nonsense should be told so even on a broker that was never finished
being deployed.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

import httpx

from app.config import BrokerConfig, load_config
from app.github import InvalidRepositoryError, mint_installation_token, validate_repository
from app.oidc import JwksUnavailable, KeyResolver, OidcError, verify_oidc_token

# Nothing request-derived is ever passed to this logger. /token is unauthenticated, so a
# caller-supplied string reaching a log record is CodeQL py/log-injection — see the
# OidcError handler for what is logged instead and why.
_log = logging.getLogger("chargate.broker")


def _configure_level() -> None:
    """Set this logger's level explicitly. Without it, nothing below WARNING is emitted.

    THE AWS LAMBDA RUNTIME SETS THE ROOT LOGGER TO WARNING. This logger has no level of its
    own, so it inherits that, and every ``_outcome()`` line — the only observability this
    service has — was silently dropped in production.

    It passed every test, and that is the part worth remembering: `caplog.at_level(INFO)`
    SETS the level the runtime does not, so the tests were asserting against a configuration
    that exists nowhere else. The observability was asserted into existence.
    """
    requested = os.environ.get("CHARGATE_LOG_LEVEL", "INFO").upper()
    # A typo in the env var must not take the function down at import — that would turn a
    # logging preference into a cold-start crash on the fail-soft path.
    level = logging.getLevelNamesMapping().get(requested, logging.INFO)
    _log.setLevel(level)


_configure_level()


def _outcome(name: str) -> None:
    """Emit exactly one structured line naming how a /token request ended.

    THE ONLY OBSERVABILITY THIS SERVICE HAS. Every failure here is invisible from outside:
    the client fails soft, so a broker that refuses every request produces no red check
    anywhere, just PR comments quietly losing their Chargate[bot] byline. The Lambda error
    alarm catches a raise; it cannot catch a broker that is cleanly and consistently
    answering 403.

    ``name`` is a FIXED STRING chosen from the call sites below — never a caller-supplied
    value, never an exception message. /token is unauthenticated, so anything request-derived
    reaching a log record is CodeQL py/log-injection: a CRLF in the value forges a second
    line. Keeping the vocabulary closed is what makes this safe to emit unconditionally, and
    is also what lets a CloudWatch metric filter key on it.
    """
    _log.info('{"outcome": "%s"}', name)


def handle_health() -> tuple[int, dict[str, str]]:
    """Liveness. Answers whether or not configuration is present.

    Deliberately weak, and worth knowing exactly how weak: this returns 200 on a
    Lambda with no SSM parameters, no IAM permission to read them, and no App
    installed. It proves the function boots. It proves nothing about ``POST /token``
    — which is why ``.github/workflows/broker-smoke.yml`` exists and why the go-live
    runbook refuses to accept a green health check as evidence.
    """
    return 200, {"status": "ok"}


def handle_ready(config: BrokerConfig | None = None) -> tuple[int, dict[str, str]]:
    """Readiness — liveness *and* resolvable configuration.

    Stricter than /healthz on purpose. Config is resolved per request, so a broker
    missing APP_ID/PRIVATE_KEY would otherwise report healthy and 500 on every token
    request; this is the signal that says "deployed but not finished".
    """
    try:
        config or load_config()
    except Exception:
        return 503, {"status": "misconfigured"}
    return 200, {"status": "ok"}


async def handle_token(
    body: bytes,
    *,
    config: BrokerConfig | None = None,
    key_resolver: KeyResolver | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> tuple[int, dict[str, Any]]:
    """Exchange a caller's Actions OIDC token for a repo-scoped installation token.

    ``config=None`` means "resolve per request", which is what production does;
    passing an explicit config is the test seam. ``key_resolver``/``transport`` are
    likewise test seams — in production both are ``None`` and the real JWKS fetch and
    the real GitHub API are used.
    """
    try:
        parsed = json.loads(body)
    except ValueError:
        _outcome("invalid_json")
        return 400, {"error": "invalid_json"}
    if not isinstance(parsed, dict):
        _outcome("invalid_json")
        return 400, {"error": "invalid_json"}

    oidc_token = parsed.get("oidcToken")
    owner = parsed.get("owner")
    repo = parsed.get("repo")
    if not (oidc_token and owner and repo):
        _outcome("missing_fields")
        return 400, {"error": "missing_fields"}
    if not (isinstance(owner, str) and isinstance(repo, str)):
        _outcome("invalid_repository")
        return 400, {"error": "invalid_repository"}
    # Reject anything that isn't a plain GitHub owner/repo identifier before it
    # reaches an API URL or a claim comparison. A value containing '/' or '..'
    # would otherwise let the caller steer the request path (py/partial-ssrf).
    try:
        owner, repo = validate_repository(owner, repo)
    except InvalidRepositoryError:
        _outcome("invalid_repository")
        return 400, {"error": "invalid_repository"}
    repository = f"{owner}/{repo}"

    try:
        active = config or load_config()
    except Exception:
        # ConfigError (missing APP_ID/PRIVATE_KEY) or anything SSM raised. Broad on
        # purpose: every one of them means the same thing to the caller. A 500 with a
        # traceback would read as a broker bug; this is a deployment that was never
        # finished, and the caller should retry once it is.
        _outcome("config_unavailable")
        return 503, {"error": "config_unavailable"}

    allowlist = active.allowed()
    if allowlist and repository not in allowlist:
        _outcome("repo_not_allowed")
        return 403, {"error": "repo_not_allowed"}

    # One client for both the JWKS fetch and the GitHub calls, so a warm execution
    # environment reuses the connection. In tests `transport` mocks GitHub and a
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
            _outcome("jwks_unavailable")
            return 503, {"error": "jwks_unavailable"}
        except OidcError as exc:
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
            _outcome("invalid_oidc")
            return 401, {"error": "invalid_oidc"}

        # The OIDC `repository` claim is the caller's repo — it must match the
        # repo they're asking for a token for. This is what stops repo A minting
        # a token for repo B.
        if claims.get("repository") != repository:
            _outcome("repo_mismatch")
            return 403, {"error": "repo_mismatch"}

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
            _outcome(reason)
            return (403 if status == 404 else 502), {"error": reason}
        except httpx.HTTPError:
            _outcome("mint_failed")
            return 502, {"error": "mint_failed"}

    _outcome("mint_ok")
    return 200, {"token": token_value, "expires_at": expires_at, "repository": repository}
