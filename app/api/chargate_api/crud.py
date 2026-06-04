"""Upsert helpers shared by the webhook + ingest paths."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import Account, Repository


async def upsert_account(db: AsyncSession, installation: dict) -> Account:
    acct = installation.get("account", {})
    inst_id = installation["id"]
    row = (await db.execute(select(Account).where(Account.installation_id == inst_id))).scalar_one_or_none()
    if row is None:
        row = Account(installation_id=inst_id, github_account_id=acct.get("id", 0))
        db.add(row)
    row.github_account_id = acct.get("id", row.github_account_id)
    row.login = acct.get("login", row.login if row.login else "unknown")
    row.account_type = acct.get("type", "Organization")
    row.avatar_url = acct.get("avatar_url")
    await db.flush()
    return row


async def upsert_repository(db: AsyncSession, account: Account, repo: dict) -> Repository:
    gid = repo["id"]
    row = (await db.execute(select(Repository).where(Repository.github_repo_id == gid))).scalar_one_or_none()
    if row is None:
        row = Repository(github_repo_id=gid, account_id=account.id)
        db.add(row)
    row.account_id = account.id
    row.name = repo.get("name", row.name if row.name else "")
    row.full_name = repo.get("full_name", row.full_name if row.full_name else "")
    row.private = repo.get("private", True)
    row.default_branch = repo.get("default_branch", row.default_branch if getattr(row, "default_branch", None) else "main")
    row.archived = repo.get("archived", False)
    await db.flush()
    return row


async def get_repo_by_github_id(db: AsyncSession, github_repo_id: int) -> Repository | None:
    return (await db.execute(
        select(Repository).where(Repository.github_repo_id == github_repo_id))).scalar_one_or_none()
