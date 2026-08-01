"""Broker configuration — the Chargate GitHub App identity + OIDC policy.

Two runtimes, one settings class:

* **Container** — values arrive in the process environment (in k8s:
  ExternalSecret → Secret → ``envFrom``) and pydantic-settings reads them.
* **Cloudflare Worker** — there is no process environment. The runtime hands each
  invocation an ``env`` object carrying vars and secrets, so ``entry.py`` publishes
  it on :data:`cf_env` and :func:`load_config` overlays it on top of ``os.environ``.

The App private key arrives as a PEM string; secret stores commonly ``\\n``-escape
it, so we un-escape (mirrors caldrith's ``settings`` normalizer). PKCS#1 (the
``BEGIN RSA PRIVATE KEY`` form GitHub hands out) is loaded as-is — ``pyjwt[crypto]``
uses ``cryptography``, which reads it directly. No pkcs8 conversion is needed here;
that is only a constraint of the JavaScript ``crypto.subtle.importKey`` path.
"""

from __future__ import annotations

import json
from contextvars import ContextVar
from typing import Any

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

GITHUB_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
GITHUB_OIDC_JWKS = f"{GITHUB_OIDC_ISSUER}/.well-known/jwks"

#: The Worker runtime's ``env`` for the current invocation, or ``None`` off-Worker.
#: Set by ``Default.fetch`` in ``entry.py`` before anything reads configuration.
cf_env: ContextVar[Any | None] = ContextVar("cf_env", default=None)


class BrokerConfig(BaseSettings):
    # env_file is a no-op on Workers (no filesystem) and pydantic-settings ignores
    # a missing file, so the same config class serves both runtimes unchanged.
    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False, extra="ignore")

    # Set from the ExternalSecret (Secret keys APP_ID / PRIVATE_KEY), or from
    # `wrangler secret put APP_ID` / `PRIVATE_KEY` on the Worker.
    app_id: str
    private_key: str

    # The OIDC `aud` the consumer's action requests; must match on both sides.
    oidc_audience: str = "chargate"
    # Optional comma-separated owner/repo allowlist. Empty = allow any repo the
    # App is installed on (the public-app model).
    allowed_repositories: str = ""
    github_api_url: str = "https://api.github.com"
    # Least privilege: minted tokens can only comment on PRs.
    token_permissions_json: str = '{"pull_requests": "write"}'

    @field_validator("private_key")
    @classmethod
    def _normalize_pem(cls, value: str) -> str:
        if "\\n" in value and "-----BEGIN" in value:
            return value.replace("\\n", "\n")
        return value

    def allowed(self) -> set[str]:
        """The owner/repo allowlist as a set (empty set = allow any)."""
        return {entry.strip() for entry in self.allowed_repositories.split(",") if entry.strip()}

    def permissions(self) -> dict[str, Any]:
        return json.loads(self.token_permissions_json)


def _worker_overlay() -> dict[str, str]:
    """This invocation's Worker ``env`` as settings kwargs, or ``{}`` off-Worker.

    Reads only declared fields: the ``env`` object also carries bindings, and
    passing those to a settings model would be noise at best.
    """
    env = cf_env.get()
    if env is None:
        return {}
    overlay: dict[str, str] = {}
    for name in BrokerConfig.model_fields:
        value = getattr(env, name.upper(), None)
        if value is not None:
            overlay[name] = str(value)
    return overlay


def load_config() -> BrokerConfig:
    """Build config for the current invocation.

    Explicit kwargs win over the process environment, so on a Worker the ``env``
    overlay supplies everything and ``os.environ`` supplies nothing; in a container
    the overlay is empty and pydantic-settings reads the environment as before.
    """
    return BrokerConfig(**_worker_overlay())
