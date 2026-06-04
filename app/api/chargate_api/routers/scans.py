"""Results ingest: the Actions engine POSTs SARIF here when a scan finishes."""
from __future__ import annotations

import jwt
from fastapi import APIRouter, Depends, Header, HTTPException, Path, status

from ..config import Settings
from ..deps import get_github, get_repo, settings_dep
from ..github import GitHubApp
from ..repository import Repository
from ..sarif import SEVERITIES, findings_from_docs, tally
from ..schemas import IngestIn, IngestOut
from ..security import verify_ingest_token

router = APIRouter(prefix="/api/v1/scans", tags=["scans"])


def _conclusion(totals: dict[str, int], blocking: bool, errored: bool) -> str:
    if errored:
        return "neutral"                       # never block on a broken scanner
    if sum(totals.values()) == 0:
        return "success"
    if blocking and (totals.get("critical", 0) + totals.get("high", 0)) > 0:
        return "failure"
    return "neutral"                           # advisory: findings shown, not blocking


def _check_output(totals: dict[str, int], findings: list[dict]) -> dict:
    total = sum(totals.values())
    rows = "\n".join(f"| {s} | {totals[s]} |" for s in SEVERITIES if totals[s])
    summary = (f"**{total}** finding(s).\n\n| Severity | Count |\n|---|---|\n{rows}"
               if total else "✅ No findings.")
    level = {"critical": "failure", "high": "failure", "medium": "warning",
             "low": "notice", "note": "notice"}
    annotations = []
    for f in findings:
        if not f.get("path"):
            continue
        line = f["line"] if isinstance(f["line"], int) and f["line"] > 0 else 1
        annotations.append({
            "path": f["path"], "start_line": line, "end_line": line,
            "annotation_level": level.get(f["severity"], "notice"),
            "title": f"{f['tool']}: {f['rule_id']}"[:255],
            "message": (f["message"] or f["rule_name"] or f["rule_id"] or "Finding")[:64000],
        })
        if len(annotations) >= 50:
            break
    return {"title": f"Chargate — {total} finding(s)" if total else "Chargate — clean",
            "summary": summary, "annotations": annotations}


@router.post("/{scan_id}/results", response_model=IngestOut)
async def ingest_results(
    payload: IngestIn,
    scan_id: str = Path(...),
    authorization: str = Header(default=""),
    settings: Settings = Depends(settings_dep),
    repo: Repository = Depends(get_repo),
    gh: GitHubApp = Depends(get_github),
):
    token = authorization.removeprefix("Bearer ").strip()
    try:
        if verify_ingest_token(settings, token) != scan_id:
            raise ValueError("scan mismatch")
    except (jwt.InvalidTokenError, ValueError) as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid ingest token") from exc

    scan = await repo.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown scan")

    parsed = findings_from_docs(payload.sarif)
    totals = tally(parsed)
    errored = (payload.security_result == "error") or (payload.lint_result == "error")
    conclusion = _conclusion(totals, settings.default_blocking, errored)

    await repo.insert_findings(scan, parsed)
    await repo.complete_scan(scan_id, status="error" if errored else "completed",
                             conclusion=conclusion, security_result=payload.security_result,
                             lint_result=payload.lint_result, totals=totals)

    if scan.get("check_run_id"):
        account = await repo.get_account(scan["account_id"])
        repository = await repo.get_repository(scan["repository_id"])
        try:
            await gh.complete_check_run(account["installation_id"], repository["full_name"],
                                        scan["check_run_id"], conclusion, _check_output(totals, parsed))
        except Exception:  # noqa: BLE001 — reporting failure mustn't lose the stored results
            pass

    return IngestOut(scan_id=scan_id, findings=sum(totals.values()), totals=totals, conclusion=conclusion)
