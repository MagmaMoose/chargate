"""Tests for the Worker config overlay mechanism.

``_worker_overlay`` + ``load_config`` are the only path that makes the Worker
target work — values come from ``cf_env``, not from ``os.environ``.  The container
tests in ``test_readiness.py`` never exercise this path because they never set
``cf_env``.
"""

from __future__ import annotations

import pytest

from app.config import BrokerConfig, _worker_overlay, cf_env, load_config


class _FakeCfEnv:
    """Minimal stand-in for a Cloudflare Worker ``env`` object."""

    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)


def test_worker_overlay_picks_up_declared_fields():
    token = cf_env.set(_FakeCfEnv(APP_ID="42", PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\nx\n"))
    try:
        overlay = _worker_overlay()
    finally:
        cf_env.reset(token)

    assert overlay["app_id"] == "42"
    assert "-----BEGIN" in overlay["private_key"]


def test_worker_overlay_ignores_undeclared_bindings():
    # ``env`` may carry KV bindings, D1 bindings, etc. — they must not leak into config.
    token = cf_env.set(
        _FakeCfEnv(APP_ID="1", PRIVATE_KEY="k", KV_NAMESPACE="some-binding", D1_DB="another")
    )
    try:
        overlay = _worker_overlay()
    finally:
        cf_env.reset(token)

    assert set(overlay.keys()) <= set(BrokerConfig.model_fields.keys())


def test_worker_overlay_empty_off_worker():
    assert _worker_overlay() == {}


def test_load_config_worker_overlay_wins_over_env(monkeypatch):
    monkeypatch.setenv("APP_ID", "env-value")
    monkeypatch.setenv("PRIVATE_KEY", "env-key")

    token = cf_env.set(_FakeCfEnv(APP_ID="cf-value", PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\nx\n"))
    try:
        config = load_config()
    finally:
        cf_env.reset(token)

    assert config.app_id == "cf-value"


def test_load_config_falls_back_to_env(monkeypatch):
    monkeypatch.setenv("APP_ID", "from-env")
    monkeypatch.setenv("PRIVATE_KEY", "-----BEGIN RSA PRIVATE KEY-----\nx\n")
    config = load_config()
    assert config.app_id == "from-env"
