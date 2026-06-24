"""Verify a GitHub Actions OIDC token: RS256, issuer-pinned, audience-checked.

The signing key is resolved from GitHub's JWKS (cached by :class:`PyJWKClient`).
``key_resolver`` is injectable so tests can supply a local public key instead of
reaching GitHub.
"""

from __future__ import annotations

from typing import Any, Protocol

import jwt
from jwt import PyJWKClient

from broker.config import GITHUB_OIDC_ISSUER, GITHUB_OIDC_JWKS


class KeyResolver(Protocol):
    def get_signing_key_from_jwt(self, token: str) -> Any: ...


class OidcError(Exception):
    """The OIDC token failed verification (bad signature, issuer, audience, …)."""


def verify_oidc_token(
    token: str,
    audience: str,
    *,
    key_resolver: KeyResolver | None = None,
) -> dict[str, Any]:
    """Return the verified claims, or raise :class:`OidcError`."""
    resolver = key_resolver or PyJWKClient(GITHUB_OIDC_JWKS)
    try:
        signing_key = resolver.get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=audience,
            issuer=GITHUB_OIDC_ISSUER,
        )
    except (jwt.PyJWTError, jwt.exceptions.PyJWKClientError) as exc:
        raise OidcError(str(exc)) from exc
    return claims
