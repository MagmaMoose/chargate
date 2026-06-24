"""Tests for the Chargate token broker — no network (mocked JWKS + GitHub API)."""

from __future__ import annotations

import time

import httpx
import jwt
import pytest
from broker.app import create_app
from broker.config import GITHUB_OIDC_ISSUER, BrokerConfig
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def keypair() -> tuple[str, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public_pem = (
        key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    return private_pem, public_pem


class _FakeResolver:
    """Stand-in for PyJWKClient: always returns the test public key."""

    def __init__(self, public_pem: str):
        self._key = type("K", (), {"key": public_pem})()

    def get_signing_key_from_jwt(self, token: str):
        return self._key


def _oidc(private_pem, *, audience="chargate", repository="org/repo", issuer=GITHUB_OIDC_ISSUER):
    now = int(time.time())
    return jwt.encode(
        {
            "iss": issuer,
            "aud": audience,
            "repository": repository,
            "sub": f"repo:{repository}:ref:refs/heads/main",
            "iat": now,
            "exp": now + 300,
        },
        private_pem,
        algorithm="RS256",
    )


def _github_ok() -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/installation"):
            return httpx.Response(200, json={"id": 4242})
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(
                201, json={"token": "ghs_minted", "expires_at": "2026-06-24T13:00:00Z"}
            )
        return httpx.Response(404, json={"message": "not found"})

    return httpx.MockTransport(handler)


def _client(keypair, *, transport=None, allowed=""):
    private_pem, public_pem = keypair
    config = BrokerConfig(
        app_id="123",
        private_key=private_pem,
        oidc_audience="chargate",
        allowed_repositories=allowed,
    )
    app = create_app(
        config, key_resolver=_FakeResolver(public_pem), transport=transport or _github_ok()
    )
    return TestClient(app), private_pem


def test_health(keypair):
    client, _ = _client(keypair)
    assert client.get("/healthz").json() == {"status": "ok"}
    assert client.get("/readyz").status_code == 200


def test_token_minted_for_matching_repo(keypair):
    client, private_pem = _client(keypair)
    resp = client.post(
        "/token",
        json={
            "oidcToken": _oidc(private_pem, repository="org/repo"),
            "owner": "org",
            "repo": "repo",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["token"] == "ghs_minted"
    assert body["repository"] == "org/repo"
    assert body["expires_at"]


def test_repo_mismatch_rejected(keypair):
    # OIDC proves the run is for org/other but it asks for a token for org/repo.
    client, private_pem = _client(keypair)
    resp = client.post(
        "/token",
        json={
            "oidcToken": _oidc(private_pem, repository="org/other"),
            "owner": "org",
            "repo": "repo",
        },
    )
    assert resp.status_code == 403
    assert resp.json()["error"] == "repo_mismatch"


def test_bad_audience_rejected(keypair):
    client, private_pem = _client(keypair)
    resp = client.post(
        "/token",
        json={"oidcToken": _oidc(private_pem, audience="diatreme"), "owner": "org", "repo": "repo"},
    )
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_oidc"


def test_bad_issuer_rejected(keypair):
    client, private_pem = _client(keypair)
    resp = client.post(
        "/token",
        json={
            "oidcToken": _oidc(private_pem, issuer="https://evil.example.com"),
            "owner": "org",
            "repo": "repo",
        },
    )
    assert resp.status_code == 401


def test_allowlist_blocks_other_repo(keypair):
    client, private_pem = _client(keypair, allowed="org/allowed")
    resp = client.post(
        "/token",
        json={
            "oidcToken": _oidc(private_pem, repository="org/repo"),
            "owner": "org",
            "repo": "repo",
        },
    )
    assert resp.status_code == 403
    assert resp.json()["error"] == "repo_not_allowed"


def test_missing_fields_rejected(keypair):
    client, _ = _client(keypair)
    assert client.post("/token", json={"owner": "org"}).status_code == 400


def test_app_not_installed_is_403(keypair):
    not_found = httpx.MockTransport(lambda req: httpx.Response(404, json={"message": "Not Found"}))
    client, private_pem = _client(keypair, transport=not_found)
    resp = client.post(
        "/token",
        json={
            "oidcToken": _oidc(private_pem, repository="org/repo"),
            "owner": "org",
            "repo": "repo",
        },
    )
    assert resp.status_code == 403
    assert resp.json()["error"] == "app_not_installed"
