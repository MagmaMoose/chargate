"""Read API for the centralised Security tab. Every query is tenant-scoped to the
accounts the signed-in user can access (require_tenant)."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query
from sqlalchemy import Select, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_session
from ..deps import require_tenant
from ..models import Finding, Repository, Scan, ScanStatus
from ..sarif import SEVERITIES
from ..schemas import FindingOut, Page, RepoOut, RepoSummary, ScanOut, Summary

router = APIRouter(prefix="/api/v1", tags=["findings"])


def _latest_scan_ids(accounts: list[uuid.UUID], repository_id: uuid.UUID | None = None) -> Select:
    """Subquery of the most-recent finished scan per repository, within scope."""
    cond = [Scan.account_id.in_(accounts), Scan.status.in_([ScanStatus.completed, ScanStatus.error])]
    if repository_id:
        cond.append(Scan.repository_id == repository_id)
    newest = (select(Scan.repository_id, func.max(Scan.created_at).label("mx"))
              .where(*cond).group_by(Scan.repository_id).subquery())
    return (select(Scan.id).join(
        newest, (Scan.repository_id == newest.c.repository_id) & (Scan.created_at == newest.c.mx)))


@router.get("/repos", response_model=list[RepoOut])
async def list_repos(accounts=Depends(require_tenant), db: AsyncSession = Depends(get_session)):
    rows = await db.execute(select(Repository).where(Repository.account_id.in_(accounts))
                            .order_by(Repository.full_name))
    return [RepoOut.model_validate(r) for r in rows.scalars().all()]


@router.get("/summary", response_model=Summary)
async def summary(accounts=Depends(require_tenant), db: AsyncSession = Depends(get_session)):
    latest = _latest_scan_ids(accounts).subquery()

    totals = {s: 0 for s in SEVERITIES}
    scans = (await db.execute(select(Scan).where(Scan.id.in_(select(latest.c.id))))).scalars().all()
    for sc in scans:
        for sev, n in (sc.totals or {}).items():
            totals[sev] = totals.get(sev, 0) + n

    tool_rows = await db.execute(
        select(Finding.tool, func.count()).where(Finding.scan_id.in_(select(latest.c.id)))
        .group_by(Finding.tool))
    by_tool = {t: n for t, n in tool_rows.all()}

    repo_rows = (await db.execute(select(Repository).where(Repository.account_id.in_(accounts)))).scalars().all()
    scan_by_repo = {sc.repository_id: sc for sc in scans}
    repos = [RepoSummary(repository=RepoOut.model_validate(r),
                         totals=(scan_by_repo[r.id].totals if r.id in scan_by_repo else {s: 0 for s in SEVERITIES}),
                         last_scan_at=scan_by_repo[r.id].completed_at if r.id in scan_by_repo else None)
             for r in repo_rows]
    repos.sort(key=lambda rs: sum(rs.totals.values()), reverse=True)

    return Summary(totals=totals, by_tool=by_tool, repo_count=len(repo_rows),
                   scan_count=len(scans), repos=repos)


@router.get("/findings", response_model=Page[FindingOut])
async def list_findings(
    accounts=Depends(require_tenant),
    db: AsyncSession = Depends(get_session),
    repository_id: uuid.UUID | None = None,
    severity: str | None = Query(default=None),
    tool: str | None = Query(default=None),
    latest_only: bool = Query(default=True),
    limit: int = Query(default=100, le=500),
    offset: int = 0,
):
    where = [Finding.account_id.in_(accounts)]
    if repository_id:
        where.append(Finding.repository_id == repository_id)
    if severity:
        where.append(Finding.severity == severity)
    if tool:
        where.append(Finding.tool == tool)
    if latest_only:
        where.append(Finding.scan_id.in_(_latest_scan_ids(accounts, repository_id)))

    total = (await db.execute(select(func.count()).select_from(Finding).where(*where))).scalar_one()
    order = {s: i for i, s in enumerate(SEVERITIES)}
    rows = (await db.execute(select(Finding).where(*where)
            .order_by(Finding.severity, Finding.tool).limit(limit).offset(offset))).scalars().all()
    items = sorted((FindingOut.model_validate(f) for f in rows),
                   key=lambda f: order.get(f.severity, 99))
    return Page[FindingOut](items=items, total=total, limit=limit, offset=offset)


@router.get("/scans", response_model=Page[ScanOut])
async def list_scans(
    accounts=Depends(require_tenant),
    db: AsyncSession = Depends(get_session),
    repository_id: uuid.UUID | None = None,
    limit: int = Query(default=50, le=200),
    offset: int = 0,
):
    where = [Scan.account_id.in_(accounts)]
    if repository_id:
        where.append(Scan.repository_id == repository_id)
    total = (await db.execute(select(func.count()).select_from(Scan).where(*where))).scalar_one()
    rows = (await db.execute(select(Scan).where(*where)
            .order_by(Scan.created_at.desc()).limit(limit).offset(offset))).scalars().all()
    return Page[ScanOut](items=[ScanOut.model_validate(s) for s in rows],
                         total=total, limit=limit, offset=offset)
