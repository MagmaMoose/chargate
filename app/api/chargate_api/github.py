"""Thin async GitHub client: App auth, Check Runs, dispatch, OAuth.

All GitHub credentials live here (and nowhere in the Actions runner). Installation
tokens are minted on demand from the App's private key and cached until they near
expiry.
"""
from __future__ import annotations

import time
from datetime import datetime, timezone

import httpx
import jwt

from .config import Settings

_ACCEPT = "application/vnd.github+json"


class GitHubError(RuntimeError):
    pass


class GitHubApp:
    def __init__(self, settings: Settings):
        self.s = settings
        self.api = settings.github_api_url.rstrip("/")
        self._inst_tokens: dict[int, tuple[str, float]] = {}  # installation_id -> (token, expires_epoch)

    # ── App / installation auth ──────────────────────────────────────────────
    def _app_jwt(self) -> str:
        now = int(time.time())
        payload = {"iat": now - 60, "exp": now + 9 * 60, "iss": self.s.github_app_id}
        return jwt.encode(payload, self.s.github_app_private_key, algorithm="RS256")

    async def _request(self, method: str, url: str, *, token: str, **kw) -> httpx.Response:
        headers = {"Authorization": f"Bearer {token}", "Accept": _ACCEPT,
                   "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "chargate-api"}
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.request(method, url, headers=headers, **kw)
        if resp.status_code >= 300:
            raise GitHubError(f"{method} {url} → {resp.status_code}: {resp.text[:300]}")
        return resp

    async def installation_token(self, installation_id: int) -> str:
        cached = self._inst_tokens.get(installation_id)
        if cached and cached[1] - time.time() > 60:
            return cached[0]
        resp = await self._request(
            "POST", f"{self.api}/app/installations/{installation_id}/access_tokens",
            token=self._app_jwt(),
        )
        data = resp.json()
        exp = datetime.fromisoformat(data["expires_at"].replace("Z", "+00:00")).timestamp()
        self._inst_tokens[installation_id] = (data["token"], exp)
        return data["token"]

    async def scoped_token(self, installation_id: int, repositories: list[str], permissions: dict) -> str:
        """A least-privilege installation token: only these repos, only these scopes.
        Used for the read-only token handed to the Actions runner to check out one repo."""
        resp = await self._request(
            "POST", f"{self.api}/app/installations/{installation_id}/access_tokens",
            token=self._app_jwt(), json={"repositories": repositories, "permissions": permissions},
        )
        return resp.json()["token"]

    async def repo_installation_id(self, full_name: str) -> int:
        resp = await self._request("GET", f"{self.api}/repos/{full_name}/installation",
                                   token=self._app_jwt())
        return resp.json()["id"]

    # ── Check Runs ───────────────────────────────────────────────────────────
    async def create_check_run(self, installation_id: int, full_name: str, head_sha: str) -> int:
        token = await self.installation_token(installation_id)
        resp = await self._request(
            "POST", f"{self.api}/repos/{full_name}/check-runs", token=token,
            json={"name": "Chargate", "head_sha": head_sha, "status": "in_progress",
                  "output": {"title": "Chargate security & lint", "summary": "Scan in progress…"}},
        )
        return resp.json()["id"]

    async def complete_check_run(self, installation_id: int, full_name: str, check_run_id: int,
                                 conclusion: str, output: dict) -> None:
        token = await self.installation_token(installation_id)
        await self._request(
            "PATCH", f"{self.api}/repos/{full_name}/check-runs/{check_run_id}", token=token,
            json={"status": "completed", "conclusion": conclusion,
                  "completed_at": datetime.now(timezone.utc).isoformat(), "output": output},
        )

    # ── Dispatch to the Actions scan engine ──────────────────────────────────
    async def dispatch_scan(self, client_payload: dict) -> None:
        inst = await self.repo_installation_id(self.s.engine_repo)
        token = await self.installation_token(inst)
        await self._request(
            "POST", f"{self.api}/repos/{self.s.engine_repo}/dispatches", token=token,
            json={"event_type": self.s.engine_dispatch_event, "client_payload": client_payload},
        )

    # ── OAuth (user login) ───────────────────────────────────────────────────
    async def exchange_oauth_code(self, code: str) -> str:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.post(
                "https://github.com/login/oauth/access_token",
                headers={"Accept": "application/json"},
                data={"client_id": self.s.github_oauth_client_id,
                      "client_secret": self.s.github_oauth_client_secret, "code": code},
            )
        token = resp.json().get("access_token")
        if not token:
            raise GitHubError(f"oauth exchange failed: {resp.text[:200]}")
        return token

    async def user_profile(self, user_token: str) -> dict:
        return (await self._request("GET", f"{self.api}/user", token=user_token)).json()

    async def user_installation_ids(self, user_token: str) -> list[int]:
        """Installations of THIS app the user can access — the tenant scope."""
        ids, page = [], 1
        while True:
            resp = await self._request(
                "GET", f"{self.api}/user/installations?per_page=100&page={page}", token=user_token)
            batch = resp.json().get("installations", [])
            ids += [i["id"] for i in batch]
            if len(batch) < 100:
                break
            page += 1
        return ids
