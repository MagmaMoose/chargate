"""Broker configuration — the Chargate GitHub App identity + OIDC policy.

Read from the environment (in k8s: ExternalSecret → Secret → ``envFrom``). The
App private key arrives as a PEM string; secret stores commonly ``\\n``-escape it,
so we un-escape (mirrors caldrith's ``settings`` normalizer).
"""

from __future__ import annotations

import json
from typing import Any

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

GITHUB_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
GITHUB_OIDC_JWKS = f"{GITHUB_OIDC_ISSUER}/.well-known/jwks"


class BrokerConfig(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False, extra="ignore")

    # Set from the ExternalSecret (Secret keys APP_ID / PRIVATE_KEY).
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
