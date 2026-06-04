"""GitHub App webhook receiver — the single ingress for installs + PR events."""
from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException, Request, status

from ..config import Settings
from ..deps import get_github, get_repo, settings_dep
from ..github import GitHubApp
from ..repository import Repository
from ..security import issue_ingest_token, verify_webhook

router = APIRouter(prefix="/api/v1/webhooks", tags=["webhooks"])

_PR_ACTIONS = {"opened", "synchronize", "reopened", "ready_for_review"}


@router.post("/github")
async def github_webhook(
    request: Request,
    background: BackgroundTasks,
    x_github_event: str = Header(default=""),
    x_hub_signature_256: str | None = Header(default=None),
    settings: Settings = Depends(settings_dep),
    repo: Repository = Depends(get_repo),
    gh: GitHubApp = Depends(get_github),
):
    body = await request.body()
    if not verify_webhook(settings.github_webhook_secret, body, x_hub_signature_256):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid signature")
    payload = await request.json()
    action = payload.get("action")

    if x_github_event == "ping":
        return {"ok": True, "pong": True}

    if x_github_event == "installation":
        account = await repo.upsert_account(payload["installation"])
        for r in payload.get("repositories", []):
            await repo.upsert_repository(account["id"], r)
        return {"ok": True, "synced": True}

    if x_github_event == "installation_repositories":
        account = await repo.upsert_account(payload["installation"])
        for r in payload.get("repositories_added", []):
            await repo.upsert_repository(account["id"], r)
        return {"ok": True, "synced": True}

    if x_github_event == "pull_request" and action in _PR_ACTIONS:
        pr = payload["pull_request"]
        head = pr.get("head", {})
        if (head.get("repo") or {}).get("full_name") != payload["repository"]["full_name"]:
            return {"ok": True, "ignored": "forked head"}
        scan = await _queue_scan(repo, payload["installation"]["id"], payload["repository"],
                                 head_sha=head["sha"], head_ref=head.get("ref"), pull_number=pr.get("number"))
        background.add_task(_start_scan, settings, gh, repo, scan["id"],
                            payload["repository"]["full_name"], payload["installation"]["id"], head["sha"])
        return {"ok": True, "queued": True}

    if x_github_event == "check_run" and action == "rerequested":
        cr = payload["check_run"]
        prs = cr.get("pull_requests") or [{}]
        scan = await _queue_scan(repo, payload["installation"]["id"], payload["repository"],
                                 head_sha=cr["head_sha"], head_ref=(prs[0].get("head") or {}).get("ref"),
                                 pull_number=prs[0].get("number"))
        background.add_task(_start_scan, settings, gh, repo, scan["id"],
                            payload["repository"]["full_name"], payload["installation"]["id"], cr["head_sha"])
        return {"ok": True, "rerun": True}

    return {"ok": True, "ignored": f"{x_github_event}.{action}"}


async def _queue_scan(repo: Repository, installation_id: int, repo_payload: dict, *,
                      head_sha: str, head_ref: str | None, pull_number: int | None) -> dict:
    account = await repo.get_account_by_installation(installation_id)
    if account is None:
        account = await repo.upsert_account({"id": installation_id, "account": {}})
    repository = await repo.get_repo_by_github_id(repo_payload["id"])
    if repository is None:
        repository = await repo.upsert_repository(account["id"], repo_payload)
    return await repo.create_scan(account["id"], repository["id"], head_sha=head_sha,
                                  head_ref=head_ref, pull_number=pull_number)


async def _start_scan(settings: Settings, gh: GitHubApp, repo: Repository, scan_id: str,
                      full_name: str, installation_id: int, head_sha: str) -> None:
    """Background: open the Check Run, mark the scan running, then dispatch the
    Actions scan with only short-lived, single-purpose tokens. Uses the
    process-wide DB driver (pool / shared connection / D1 binding)."""
    check_run_id = None
    try:
        check_run_id = await gh.create_check_run(installation_id, full_name, head_sha)
    except Exception:  # noqa: BLE001 — a failed check create shouldn't block the scan
        pass
    await repo.set_scan_running(scan_id, check_run_id)

    owner, repo_name = full_name.split("/", 1)
    repo_token = await gh.scoped_token(installation_id, [repo_name], {"contents": "read"})
    await gh.dispatch_scan({
        "scan_id": scan_id, "owner": owner, "repo": repo_name, "full_name": full_name,
        "head_sha": head_sha, "repo_token": repo_token,
        "ingest_url": f"{settings.public_base_url}/api/v1/scans/{scan_id}/results",
        "ingest_token": issue_ingest_token(settings, scan_id),
    })
