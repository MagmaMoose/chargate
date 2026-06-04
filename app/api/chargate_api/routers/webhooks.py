"""GitHub App webhook receiver — the single ingress for installs + PR events."""
from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import Settings
from ..crud import get_repo_by_github_id, upsert_account, upsert_repository
from ..db import SessionLocal, get_session
from ..deps import get_github, settings_dep
from ..github import GitHubApp
from ..models import Account, Scan, ScanStatus
from ..security import verify_webhook

router = APIRouter(prefix="/api/v1/webhooks", tags=["webhooks"])

_PR_ACTIONS = {"opened", "synchronize", "reopened", "ready_for_review"}


@router.post("/github")
async def github_webhook(
    request: Request,
    background: BackgroundTasks,
    x_github_event: str = Header(default=""),
    x_hub_signature_256: str | None = Header(default=None),
    settings: Settings = Depends(settings_dep),
    db: AsyncSession = Depends(get_session),
    gh: GitHubApp = Depends(get_github),
):
    body = await request.body()
    if not verify_webhook(settings.github_webhook_secret, body, x_hub_signature_256):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid signature")
    payload = await request.json()
    action = payload.get("action")

    if x_github_event == "ping":
        return {"ok": True, "pong": True}

    # Install / repo membership → keep accounts + repositories in sync.
    if x_github_event == "installation":
        account = await upsert_account(db, payload["installation"])
        for repo in payload.get("repositories", []):
            await upsert_repository(db, account, repo)
        return {"ok": True, "synced": True}

    if x_github_event == "installation_repositories":
        account = await upsert_account(db, payload["installation"])
        for repo in payload.get("repositories_added", []):
            await upsert_repository(db, account, repo)
        return {"ok": True, "synced": True}

    # PR opened/updated → create a scan and kick the engine.
    if x_github_event == "pull_request" and action in _PR_ACTIONS:
        pr = payload["pull_request"]
        head = pr.get("head", {})
        # Forked-PR heads live in a repo we're not installed on — skip for now.
        if (head.get("repo") or {}).get("full_name") != payload["repository"]["full_name"]:
            return {"ok": True, "ignored": "forked head"}
        scan = await _queue_scan(db, payload["installation"]["id"], payload["repository"],
                                 head_sha=head["sha"], head_ref=head.get("ref"), pull_number=pr.get("number"))
        if scan:
            background.add_task(_start_scan, settings, gh, str(scan.id),
                                payload["repository"]["full_name"], payload["installation"]["id"], head["sha"])
        return {"ok": True, "queued": bool(scan)}

    if x_github_event == "check_run" and action == "rerequested":
        cr = payload["check_run"]
        prs = cr.get("pull_requests") or [{}]
        scan = await _queue_scan(db, payload["installation"]["id"], payload["repository"],
                                 head_sha=cr["head_sha"], head_ref=(prs[0].get("head") or {}).get("ref"),
                                 pull_number=prs[0].get("number"))
        if scan:
            background.add_task(_start_scan, settings, gh, str(scan.id),
                                payload["repository"]["full_name"], payload["installation"]["id"], cr["head_sha"])
        return {"ok": True, "rerun": bool(scan)}

    return {"ok": True, "ignored": f"{x_github_event}.{action}"}


async def _queue_scan(db: AsyncSession, installation_id: int, repo_payload: dict, *,
                      head_sha: str, head_ref: str | None, pull_number: int | None) -> Scan | None:
    account = (await db.execute(
        select(Account).where(Account.installation_id == installation_id))).scalar_one_or_none()
    if account is None:
        account = await upsert_account(db, {"id": installation_id, "account": {}})
    repo = await get_repo_by_github_id(db, repo_payload["id"]) or await upsert_repository(db, account, repo_payload)
    scan = Scan(account_id=account.id, repository_id=repo.id, head_sha=head_sha,
                head_ref=head_ref, pull_number=pull_number, status=ScanStatus.queued)
    db.add(scan)
    await db.flush()
    return scan


async def _start_scan(settings: Settings, gh: GitHubApp, scan_id: str, full_name: str,
                      installation_id: int, head_sha: str) -> None:
    """Background: open the Check Run, then dispatch the Actions scan. Runs in its
    own session since the request's session is already closed."""
    from ..security import issue_ingest_token
    check_run_id = None
    try:
        check_run_id = await gh.create_check_run(installation_id, full_name, head_sha)
    except Exception:  # noqa: BLE001 — a failed check create shouldn't block the scan
        pass
    async with SessionLocal() as db:
        scan = await db.get(Scan, scan_id)
        if scan and check_run_id:
            scan.check_run_id = check_run_id
            scan.status = ScanStatus.running
            await db.commit()
    owner, repo = full_name.split("/", 1)
    # Read-only, single-repo token so the runner can check out the target — and
    # nothing else. The runner holds no standing GitHub credentials.
    repo_token = await gh.scoped_token(installation_id, [repo], {"contents": "read"})
    await gh.dispatch_scan({
        "scan_id": scan_id,
        "owner": owner,
        "repo": repo,
        "full_name": full_name,
        "head_sha": head_sha,
        "repo_token": repo_token,
        "ingest_url": f"{settings.public_base_url}/api/v1/scans/{scan_id}/results",
        "ingest_token": issue_ingest_token(settings, scan_id),
    })
