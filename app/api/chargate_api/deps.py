"""Shared FastAPI dependencies: settings, GitHub client, repository, tenant scope."""
from __future__ import annotations

from functools import lru_cache

from fastapi import Depends, HTTPException, Request, status

from .config import Settings, get_settings
from .github import GitHubApp
from .repository import Repository


@lru_cache
def get_github() -> GitHubApp:
    return GitHubApp(get_settings())


def settings_dep() -> Settings:
    return get_settings()


def get_repo(request: Request) -> Repository:
    """Repository bound to the process-wide DB driver (set in the lifespan, or by
    the Cloudflare Worker entrypoint with a D1-backed driver)."""
    return Repository(request.app.state.db)


def current_user(request: Request) -> dict:
    user = request.session.get("user")
    if not user:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "not authenticated")
    return user


async def tenant_accounts(request: Request, repo: Repository = Depends(get_repo)) -> list[str]:
    """Account ids the signed-in user may read — the tenant scope for every query.

    The session carries the installation ids the user can access (from
    /user/installations at login); map those to local account rows.
    """
    user = current_user(request)
    accounts = await repo.accounts_for_installations(user.get("installation_ids") or [])
    return [a["id"] for a in accounts]


def require_tenant(accounts: list[str] = Depends(tenant_accounts)) -> list[str]:
    if not accounts:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "no accessible installations")
    return accounts
