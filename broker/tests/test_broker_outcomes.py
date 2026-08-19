"""Every /token path emits exactly one structured outcome line, from a closed vocabulary.

This is the only observability the broker has. The client fails soft, so a broker that is
cleanly and consistently answering 403 produces no error metric and no red check anywhere —
the Lambda error alarm catches a raise, not a wrong answer. A CloudWatch metric filter keys
on these lines.

The vocabulary must stay CLOSED: /token is unauthenticated, so any caller-supplied value
reaching a log record is CodeQL py/log-injection.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.broker import handle_token
from app.config import GITHUB_OIDC_ISSUER, BrokerConfig

_CONFIG = BrokerConfig(app_id="1", private_key="-----BEGIN RSA PRIVATE KEY-----\nx\n")


async def _outcomes(caplog, body: bytes, **kwargs) -> list[str]:
    with caplog.at_level(logging.INFO, logger="chargate.broker"):
        await handle_token(body, **kwargs)
    return [
        json.loads(r.getMessage())["outcome"]
        for r in caplog.records
        if r.name == "chargate.broker" and r.levelno == logging.INFO
    ]


@pytest.mark.parametrize(
    "body,expected",
    [
        (b"not json", "invalid_json"),
        (b'["a list"]', "invalid_json"),
        (b'{"owner": "org"}', "missing_fields"),
        (b'{"oidcToken": "x", "owner": {"a": 1}, "repo": "r"}', "invalid_repository"),
        (b'{"oidcToken": "x", "owner": "org", "repo": "r/../evil"}', "invalid_repository"),
    ],
)
async def test_each_rejection_names_itself(caplog, body, expected):
    assert await _outcomes(caplog, body, config=_CONFIG) == [expected]


async def test_exactly_one_line_per_request(caplog):
    """Two lines for one request would double-count every CloudWatch metric built on these."""
    assert len(await _outcomes(caplog, b"not json", config=_CONFIG)) == 1


async def test_the_line_is_machine_readable(caplog):
    with caplog.at_level(logging.INFO, logger="chargate.broker"):
        await handle_token(b"not json", config=_CONFIG)
    record = next(r for r in caplog.records if r.levelno == logging.INFO)
    # Must parse as JSON — a metric filter pattern depends on the shape, not on substrings.
    assert json.loads(record.getMessage()) == {"outcome": "invalid_json"}


async def test_no_request_derived_text_reaches_the_log(caplog):
    """A CRLF payload in the repo name must not appear, forged or escaped, in any record."""
    payload = b'{"oidcToken": "x", "owner": "org", "repo": "r\\r\\nWARNING:root:forged"}'
    outcomes = await _outcomes(caplog, payload, config=_CONFIG)
    assert outcomes == ["invalid_repository"]
    assert not any("forged" in r.getMessage() for r in caplog.records)


# --- the eight paths that need a config, a key and a transport ------------------------------


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


def _body(token: str, owner: str = "org", repo: str = "repo") -> bytes:
    return json.dumps({"oidcToken": token, "owner": owner, "repo": repo}).encode()


def _github(installation=200, mint=201) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/installation"):
            return httpx.Response(installation, json={"id": 4242} if installation == 200 else {})
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(
                mint, json={"token": "ghs_x", "expires_at": "2026-06-24T13:00:00Z"}
            )
        return httpx.Response(404, json={})

    return httpx.MockTransport(handler)


async def test_mint_ok(caplog, keypair):
    private_pem, public_pem = keypair
    config = BrokerConfig(app_id="1", private_key=private_pem)
    assert await _outcomes(
        caplog,
        _body(_oidc(private_pem)),
        config=config,
        key_resolver=_FakeResolver(public_pem),
        transport=_github(),
    ) == ["mint_ok"]


async def test_config_unavailable(caplog, monkeypatch, keypair):
    """config=None with nothing in the environment — the unfinished-deployment path."""
    monkeypatch.delenv("SECRET_PATH", raising=False)
    monkeypatch.delenv("APP_ID", raising=False)
    monkeypatch.delenv("PRIVATE_KEY", raising=False)
    private_pem, _ = keypair
    assert await _outcomes(caplog, _body(_oidc(private_pem))) == ["config_unavailable"]


async def test_repo_not_allowed(caplog, keypair):
    private_pem, public_pem = keypair
    config = BrokerConfig(app_id="1", private_key=private_pem, allowed_repositories="other/repo")
    assert await _outcomes(
        caplog,
        _body(_oidc(private_pem)),
        config=config,
        key_resolver=_FakeResolver(public_pem),
        transport=_github(),
    ) == ["repo_not_allowed"]


async def test_invalid_oidc(caplog, keypair):
    private_pem, public_pem = keypair
    config = BrokerConfig(app_id="1", private_key=private_pem)
    assert await _outcomes(
        caplog,
        _body(_oidc(private_pem, audience="somebody-else")),
        config=config,
        key_resolver=_FakeResolver(public_pem),
        transport=_github(),
    ) == ["invalid_oidc"]


async def test_repo_mismatch(caplog, keypair):
    """The claim says org/other; the caller asked for org/repo."""
    private_pem, public_pem = keypair
    config = BrokerConfig(app_id="1", private_key=private_pem)
    assert await _outcomes(
        caplog,
        _body(_oidc(private_pem, repository="org/other")),
        config=config,
        key_resolver=_FakeResolver(public_pem),
        transport=_github(),
    ) == ["repo_mismatch"]


async def test_app_not_installed(caplog, keypair):
    private_pem, public_pem = keypair
    config = BrokerConfig(app_id="1", private_key=private_pem)
    assert await _outcomes(
        caplog,
        _body(_oidc(private_pem)),
        config=config,
        key_resolver=_FakeResolver(public_pem),
        transport=_github(installation=404),
    ) == ["app_not_installed"]


async def test_mint_failed_on_a_non_404(caplog, keypair):
    private_pem, public_pem = keypair
    config = BrokerConfig(app_id="1", private_key=private_pem)
    assert await _outcomes(
        caplog,
        _body(_oidc(private_pem)),
        config=config,
        key_resolver=_FakeResolver(public_pem),
        transport=_github(installation=500),
    ) == ["mint_failed"]


async def test_jwks_unavailable(caplog, keypair, monkeypatch):
    """GitHub's JWKS could not be fetched — the caller's token may be perfectly valid."""
    from app import broker as broker_mod
    from app.oidc import JwksUnavailable

    async def boom(*_args, **_kwargs):
        raise JwksUnavailable("no jwks")

    monkeypatch.setattr(broker_mod, "verify_oidc_token", boom)
    private_pem, _ = keypair
    config = BrokerConfig(app_id="1", private_key=private_pem)
    assert await _outcomes(caplog, _body(_oidc(private_pem)), config=config) == ["jwks_unavailable"]


def test_every_outcome_string_is_covered():
    """The vocabulary is closed; this asserts the tests above actually exhaust it.

    A new return path that invents an outcome name nobody tests would otherwise ship silently
    and only be noticed when a CloudWatch metric filter failed to match it.
    """
    import re

    source = (Path(__file__).resolve().parents[1] / "app" / "broker.py").read_text()
    emitted = set(re.findall(r'_outcome\("([a-z_]+)"\)', source))
    # `reason` is computed (app_not_installed / mint_failed); both are asserted above.
    covered = {
        "invalid_json",
        "missing_fields",
        "invalid_repository",
        "config_unavailable",
        "repo_not_allowed",
        "jwks_unavailable",
        "invalid_oidc",
        "repo_mismatch",
        "mint_failed",
        "mint_ok",
    }
    assert emitted <= covered, f"untested outcome(s): {emitted - covered}"
