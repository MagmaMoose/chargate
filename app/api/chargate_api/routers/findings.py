"""Read API for the centralised Security tab. Every query is tenant-scoped to the
accounts the signed-in user can access (require_tenant)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from ..deps import get_repo, require_tenant
from ..repository import Repository
from ..schemas import FindingOut, Page, RepoOut, RepoSummary, ScanOut, Summary

router = APIRouter(prefix="/api/v1", tags=["findings"])


@router.get("/repos", response_model=list[RepoOut])
async def list_repos(accounts: list[str] = Depends(require_tenant), repo: Repository = Depends(get_repo)):
    return [RepoOut.model_validate(r) for r in await repo.list_repos(accounts)]


@router.get("/summary", response_model=Summary)
async def summary(accounts: list[str] = Depends(require_tenant), repo: Repository = Depends(get_repo)):
    data = await repo.summary(accounts)
    data["repos"] = [RepoSummary(repository=RepoOut.model_validate(rs["repository"]),
                                 totals=rs["totals"], last_scan_at=rs["last_scan_at"])
                     for rs in data["repos"]]
    return Summary(**data)


@router.get("/findings", response_model=Page[FindingOut])
async def list_findings(
    accounts: list[str] = Depends(require_tenant),
    repo: Repository = Depends(get_repo),
    repository_id: str | None = None,
    severity: str | None = Query(default=None),
    tool: str | None = Query(default=None),
    latest_only: bool = Query(default=True),
    limit: int = Query(default=100, le=500),
    offset: int = 0,
):
    rows, total = await repo.list_findings(accounts, repository_id=repository_id, severity=severity,
                                           tool=tool, latest_only=latest_only, limit=limit, offset=offset)
    return Page[FindingOut](items=[FindingOut.model_validate(r) for r in rows],
                            total=total, limit=limit, offset=offset)


@router.get("/scans", response_model=Page[ScanOut])
async def list_scans(
    accounts: list[str] = Depends(require_tenant),
    repo: Repository = Depends(get_repo),
    repository_id: str | None = None,
    limit: int = Query(default=50, le=200),
    offset: int = 0,
):
    rows, total = await repo.list_scans(accounts, repository_id, limit, offset)
    return Page[ScanOut](items=[ScanOut.model_validate(r) for r in rows],
                         total=total, limit=limit, offset=offset)
