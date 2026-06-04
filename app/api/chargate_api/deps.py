"""Shared FastAPI dependencies: settings, GitHub client, auth, tenant scoping."""
from __future__ import annotations

import uuid
from functools import lru_cache

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .config import Settings, get_settings
from .db import get_session
from .github import GitHubApp
from .models import Account


@lru_cache
def get_github(settings: Settings = None) -> GitHubApp:  # noqa: ARG001 — cached singleton
    return GitHubApp(get_settings())


def settings_dep() -> Settings:
    return get_settings()


def current_user(request: Request) -> dict:
    """The signed-in user from the session cookie, or 401."""
    user = request.session.get("user")
    if not user:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "not authenticated")
    return user


async def tenant_accounts(
    request: Request,
    db: AsyncSession = Depends(get_session),
) -> list[uuid.UUID]:
    """Account IDs the signed-in user may read — every query is filtered to these.

    The session carries the GitHub installation IDs the user can access (resolved
    at login from /user/installations); we map those to local account rows.
    """
    user = current_user(request)
    inst_ids = user.get("installation_ids") or []
    if not inst_ids:
        return []
    rows = await db.execute(select(Account.id).where(Account.installation_id.in_(inst_ids)))
    return [r[0] for r in rows.all()]


def require_tenant(accounts: list[uuid.UUID] = Depends(tenant_accounts)) -> list[uuid.UUID]:
    if not accounts:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "no accessible installations")
    return accounts
