"""GitHub OAuth login. The session cookie holds the user + the installation IDs
they can access — that set is the tenant scope for every read endpoint."""
from __future__ import annotations

import secrets
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import Settings
from ..db import get_session
from ..deps import current_user, settings_dep, get_github
from ..github import GitHubApp, GitHubError
from ..models import Account
from ..schemas import AccountOut, Me

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


@router.get("/login")
def login(request: Request, settings: Settings = Depends(settings_dep)):
    state = secrets.token_urlsafe(24)
    request.session["oauth_state"] = state
    query = urlencode({
        "client_id": settings.github_oauth_client_id,
        "redirect_uri": f"{settings.public_base_url}/api/v1/auth/callback",
        "scope": "read:user",
        "state": state,
    })
    return RedirectResponse(f"https://github.com/login/oauth/authorize?{query}")


@router.get("/callback")
async def callback(
    request: Request,
    code: str,
    state: str,
    settings: Settings = Depends(settings_dep),
    gh: GitHubApp = Depends(get_github),
):
    if not state or state != request.session.pop("oauth_state", None):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid oauth state")
    try:
        user_token = await gh.exchange_oauth_code(code)
        profile = await gh.user_profile(user_token)
        installation_ids = await gh.user_installation_ids(user_token)
    except GitHubError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc)) from exc

    request.session["user"] = {
        "login": profile["login"],
        "name": profile.get("name"),
        "avatar_url": profile.get("avatar_url"),
        "installation_ids": installation_ids,
    }
    return RedirectResponse(settings.web_base_url)


@router.post("/logout")
def logout(request: Request):
    request.session.clear()
    return {"ok": True}


@router.get("/me", response_model=Me)
async def me(
    request: Request,
    user: dict = Depends(current_user),
    db: AsyncSession = Depends(get_session),
):
    inst_ids = user.get("installation_ids") or []
    accounts = []
    if inst_ids:
        rows = await db.execute(select(Account).where(Account.installation_id.in_(inst_ids)))
        accounts = [AccountOut.model_validate(a) for a in rows.scalars().all()]
    return Me(login=user["login"], name=user.get("name"),
              avatar_url=user.get("avatar_url"), accounts=accounts)
