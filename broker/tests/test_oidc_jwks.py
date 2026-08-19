"""Tests for the JWKS resolver that replaced PyJWKClient.

The rest of the suite injects a ``key_resolver``, so none of it touches this path —
which is the part the Worker port actually rewrote. These cover it directly: key
lookup by kid, the rotation refetch, and the failure mode that must not be
reported to a caller as a bad token.
"""

from __future__ import annotations

import json
import time

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

import app.oidc as oidc_module
from app.config import GITHUB_OIDC_ISSUER
from app.main import create_app
from app.oidc import JwksResolver, JwksUnavailable, OidcError, verify_oidc_token

KID = "test-key-1"


@pytest.fixture(autouse=True)
def _clear_jwks_cache():
    """The cache is module-level (a warm isolate reuses it), so tests must reset it."""
    oidc_module._jwks_cache["keys"] = None
    oidc_module._jwks_cache["fetched_at"] = 0.0
    yield
    oidc_module._jwks_cache["keys"] = None
    oidc_module._jwks_cache["fetched_at"] = 0.0


@pytest.fixture(scope="module")
def key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _jwks_body(key: rsa.RSAPrivateKey, kid: str = KID) -> dict:
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update({"kid": kid, "alg": "RS256", "use": "sig"})
    return {"keys": [jwk]}


def _oidc(key: rsa.RSAPrivateKey, *, kid: str = KID, repository: str = "org/repo") -> str:
    from cryptography.hazmat.primitives import serialization

    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    now = int(time.time())
    return jwt.encode(
        {
            "iss": GITHUB_OIDC_ISSUER,
            "aud": "chargate",
            "repository": repository,
            "iat": now,
            "exp": now + 300,
        },
        pem,
        algorithm="RS256",
        headers={"kid": kid},
    )


async def test_resolves_key_from_jwks(key):
    transport = httpx.MockTransport(lambda req: httpx.Response(200, json=_jwks_body(key)))
    async with httpx.AsyncClient(transport=transport) as client:
        claims = await verify_oidc_token(_oidc(key), "chargate", client=client)
    assert claims["repository"] == "org/repo"


async def test_unknown_kid_triggers_one_refetch_then_succeeds(key):
    """A GitHub key rotation must not need a cold isolate to recover."""
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        # First fetch predates the rotation and lacks the kid the token was signed with.
        body = _jwks_body(key, kid="stale-key") if calls["n"] == 1 else _jwks_body(key)
        return httpx.Response(200, json=body)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        claims = await verify_oidc_token(_oidc(key), "chargate", client=client)

    assert claims["repository"] == "org/repo"
    assert calls["n"] == 2, "expected exactly one forced refetch on kid miss"


async def test_kid_absent_after_refetch_is_rejected(key):
    transport = httpx.MockTransport(
        lambda req: httpx.Response(200, json=_jwks_body(key, kid="someone-else"))
    )
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(OidcError, match="no signing key"):
            await verify_oidc_token(_oidc(key), "chargate", client=client)


async def test_cache_is_reused_within_ttl(key):
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json=_jwks_body(key))

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        await verify_oidc_token(_oidc(key), "chargate", client=client)
        await verify_oidc_token(_oidc(key), "chargate", client=client)

    assert calls["n"] == 1, "second verification should hit the module-level cache"


async def test_jwks_fetch_failure_raises_jwks_unavailable(key):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("JWKS endpoint unreachable")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(JwksUnavailable):
            await verify_oidc_token(_oidc(key), "chargate", client=client)


async def test_malformed_token_is_rejected_before_any_fetch(key):
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json=_jwks_body(key))

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        resolver = JwksResolver(client)
        with pytest.raises(OidcError):
            await resolver.get_signing_key_from_jwt("not-a-jwt")
    assert calls["n"] == 0


def test_upstream_jwks_outage_is_503_not_401(key, monkeypatch):
    """A caller with a valid token must not be told their token is invalid."""

    async def boom(*args, **kwargs):
        raise JwksUnavailable("JWKS endpoint unreachable")

    monkeypatch.setattr("app.broker.verify_oidc_token", boom)

    from app.config import BrokerConfig

    config = BrokerConfig(app_id="123", private_key="unused-here", oidc_audience="chargate")
    client = TestClient(create_app(config))
    resp = client.post("/token", json={"oidcToken": _oidc(key), "owner": "org", "repo": "repo"})
    assert resp.status_code == 503
    assert resp.json()["error"] == "jwks_unavailable"
