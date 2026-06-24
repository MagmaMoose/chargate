"""Mint a short-lived, repo-scoped GitHub App installation token.

Signs an App JWT (RS256) with the Chargate App key, resolves the repo's
installation, then mints a token scoped to **just that repo** with **just** the
requested permissions. The ``httpx`` client is injected so tests can mock GitHub.
"""

from __future__ import annotations

import time
from typing import Any

import httpx
import jwt

_API_VERSION = "2022-11-28"


def app_jwt(app_id: str, private_key: str, *, now: float | None = None) -> str:
    """A ~9-minute App JWT (GitHub allows max 10), back-dated 60s for clock skew."""
    epoch = int(now if now is not None else time.time())
    payload = {"iat": epoch - 60, "exp": epoch + 9 * 60, "iss": str(app_id)}
    return jwt.encode(payload, private_key, algorithm="RS256")


async def mint_installation_token(
    client: httpx.AsyncClient,
    *,
    app_id: str,
    private_key: str,
    owner: str,
    repo: str,
    permissions: dict[str, Any],
    api_url: str = "https://api.github.com",
) -> tuple[str, str]:
    """Return ``(token, expires_at)`` scoped to ``owner/repo``. Raises on HTTP error."""
    headers = {
        "Authorization": f"Bearer {app_jwt(app_id, private_key)}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": _API_VERSION,
    }
    base = api_url.rstrip("/")
    installation = await client.get(f"{base}/repos/{owner}/{repo}/installation", headers=headers)
    installation.raise_for_status()
    installation_id = installation.json()["id"]

    minted = await client.post(
        f"{base}/app/installations/{installation_id}/access_tokens",
        headers=headers,
        json={"repositories": [repo], "permissions": permissions},
    )
    minted.raise_for_status()
    body = minted.json()
    return body["token"], body.get("expires_at", "")
