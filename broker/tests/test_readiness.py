"""Liveness vs readiness when the broker's secrets are absent.

Config is resolved per request (the Worker requires it — secrets only exist on the
invocation's ``env``). These pin the failure signal that change could have lost:
an unconfigured broker must still answer /healthz, must *not* claim readiness, and
must not report a misconfigured deployment as a broker bug.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import create_app


@pytest.fixture
def unconfigured(monkeypatch) -> TestClient:
    # No APP_ID / PRIVATE_KEY anywhere: not in the process environment, and no
    # Worker env published on the ContextVar.
    monkeypatch.delenv("APP_ID", raising=False)
    monkeypatch.delenv("PRIVATE_KEY", raising=False)
    return TestClient(create_app())


def test_healthz_answers_without_secrets(unconfigured):
    """The first Worker deploy has no secrets yet and must still come up."""
    resp = unconfigured.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_readyz_reports_misconfigured(unconfigured):
    """k8s readiness has to notice what construct-time config used to crash-loop on."""
    resp = unconfigured.get("/readyz")
    assert resp.status_code == 503
    assert resp.json()["status"] == "misconfigured"


def test_token_is_503_not_500_when_unconfigured(unconfigured):
    resp = unconfigured.post("/token", json={"oidcToken": "x", "owner": "org", "repo": "repo"})
    assert resp.status_code == 503
    assert resp.json()["error"] == "config_unavailable"


def test_bad_request_still_precedes_config(unconfigured):
    """A malformed request is the caller's fault even on an unconfigured broker."""
    resp = unconfigured.post("/token", json={"owner": "org"})
    assert resp.status_code == 400
    assert resp.json()["error"] == "missing_fields"


def test_readyz_ok_when_configured():
    from app.config import BrokerConfig

    config = BrokerConfig(app_id="123", private_key="-----BEGIN RSA PRIVATE KEY-----\nx\n")
    client = TestClient(create_app(config))
    assert client.get("/readyz").status_code == 200
