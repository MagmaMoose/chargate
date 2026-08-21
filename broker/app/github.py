"""Mint a short-lived, repo-scoped GitHub App installation token.

Signs an App JWT (RS256) with the Chargate App key, resolves the repo's
installation, then mints a token scoped to **just that repo** with **just** the
requested permissions. The ``httpx`` client is injected so tests can mock GitHub.
"""

from __future__ import annotations

import re
import time
from typing import Any

import httpx
import jwt

_API_VERSION = "2022-11-28"

# GitHub owner (user/org) and repo naming rules, tightened to what can never alter
# the shape of a URL path: no '/', no '%', no ':'. Owners are alphanumeric with
# single hyphens. Repo names allow '_' and '.' (e.g. foo.github.io), but '..' is
# the path-traversal primitive — reject that sequence specifically, not all dots.
#
# Kept as PATTERN STRINGS as well as compiled objects, because the two are not
# interchangeable to CodeQL. `py/partial-ssrf` only treats a value as sanitized when
# it flows through `StringRestrictionSanitizerGuard`, whose recognised shapes are the
# `str.isalnum()` family and `re.match`/`re.fullmatch` with the value as the *second*
# positional argument. The module-level form `re.fullmatch(PATTERN, value)` matches
# that model; a bound-method call on a precompiled object does not reliably, so the
# guard immediately before the request uses the string form.
_OWNER_PATTERN = r"\A[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})\Z"
_REPO_PATTERN = r"\A(?!.*\.\.)[A-Za-z0-9_.-]{1,100}\Z"
_OWNER_RE = re.compile(_OWNER_PATTERN)
_REPO_RE = re.compile(_REPO_PATTERN)


class InvalidRepositoryError(ValueError):
    """``owner`` or ``repo`` is not a syntactically valid GitHub identifier."""


def validate_repository(owner: str, repo: str) -> tuple[str, str]:
    """Return ``(owner, repo)`` iff both are safe to interpolate into an API path.

    The caller already pins these against the signed OIDC ``repository`` claim, so
    this is defence-in-depth: it guarantees that no value reaching an f-string URL
    can contain a path separator, a traversal sequence, or percent-encoding, which
    is what makes the request URL forgeable (CodeQL ``py/partial-ssrf``). Validating
    here rather than at the call site keeps the guarantee attached to the function
    that builds the URLs.
    """
    if not _OWNER_RE.match(owner or ""):
        raise InvalidRepositoryError(f"invalid owner: {owner!r}")
    if not _REPO_RE.match(repo or ""):
        raise InvalidRepositoryError(f"invalid repo: {repo!r}")
    return owner, repo


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
    """Return ``(token, expires_at)`` scoped to ``owner/repo``.

    Raises :class:`InvalidRepositoryError` if ``owner``/``repo`` are not valid
    GitHub identifiers, or ``httpx.HTTPStatusError`` on an API error.
    """
    owner, repo = validate_repository(owner, repo)
    headers = {
        "Authorization": f"Bearer {app_jwt(app_id, private_key)}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": _API_VERSION,
    }
    base = api_url.rstrip("/")
    # Re-assert the allowlist HERE, on the bare names, immediately before they reach the
    # URL. Redundant at runtime — validate_repository above already raised — and that is
    # the point: it is the only shape CodeQL's py/partial-ssrf accepts as a barrier.
    #
    # Two earlier attempts on this alert failed for reasons worth recording:
    #   * A regex check inside validate_repository cannot sanitize anything here. CodeQL's
    #     barrier applies to the guarded variable's uses in the guard's own scope; it does
    #     not follow the value back out through a return into the caller's new bindings.
    #     `if not _OWNER_RE.match(owner or "")` also wraps the call in a BoolExpr, which
    #     yields no barrier node at all.
    #   * quote(..., safe="") is modelled by FullUrlControlSanitizer, which the FULL-SSRF
    #     configuration uses and the PARTIAL-SSRF one does not — so percent-encoding could
    #     never have cleared this query, however correct it is as defence.
    # Do not "simplify" these two ifs away; they are load-bearing for the scan, not the
    # runtime. The values remain safe to interpolate raw: the allowlists admit no '/',
    # '%', ':' or '..', and the host comes from config, never from the caller.
    if not re.fullmatch(_OWNER_PATTERN, owner):
        raise InvalidRepositoryError(f"invalid owner: {owner!r}")
    if not re.fullmatch(_REPO_PATTERN, repo):
        raise InvalidRepositoryError(f"invalid repo: {repo!r}")
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
