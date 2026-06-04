"""All data access, as portable SQL over the `Db` driver.

No ORM: every statement here runs unchanged on D1, SQLite and Postgres. Ids are
opaque uuid strings, JSON columns are (de)serialised here, booleans are 0/1, and
timestamps are ISO-8601 text (so `MAX(created_at)` orders correctly everywhere).
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Sequence

from .db.driver import Db
from .sarif import SEVERITIES


def _id() -> str:
    return str(uuid.uuid4())


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _in(values: Sequence[Any]) -> str:
    return ",".join("?" for _ in values)


_SCAN_COLS = ("id, account_id, repository_id, head_sha, head_ref, pull_number, status, "
              "conclusion, check_run_id, security_result, lint_result, totals, created_at, completed_at")


def _scan_row(r: dict) -> dict:
    r = dict(r)
    r["totals"] = json.loads(r.get("totals") or "{}")
    return r


class Repository:
    def __init__(self, db: Db):
        self.db = db

    # ── Accounts / repos (webhook sync) ──────────────────────────────────────
    async def upsert_account(self, installation: dict) -> dict:
        acct = installation.get("account") or {}
        inst_id = installation["id"]
        existing = await self.get_account_by_installation(inst_id)
        if existing:
            await self.db.execute(
                "UPDATE accounts SET github_account_id=?, login=?, account_type=?, avatar_url=? "
                "WHERE installation_id=?",
                (acct.get("id", existing["github_account_id"]),
                 acct.get("login", existing["login"]),
                 acct.get("type", existing["account_type"]),
                 acct.get("avatar_url"), inst_id),
            )
            return await self.get_account_by_installation(inst_id)
        row = {
            "id": _id(), "github_account_id": acct.get("id", 0), "installation_id": inst_id,
            "login": acct.get("login", "unknown"), "account_type": acct.get("type", "Organization"),
            "avatar_url": acct.get("avatar_url"), "created_at": _now(),
        }
        await self.db.execute(
            "INSERT INTO accounts (id, github_account_id, installation_id, login, account_type, "
            "avatar_url, suspended, created_at) VALUES (?, ?, ?, ?, ?, ?, 0, ?)",
            (row["id"], row["github_account_id"], row["installation_id"], row["login"],
             row["account_type"], row["avatar_url"], row["created_at"]),
        )
        return await self.get_account_by_installation(inst_id)

    async def get_account_by_installation(self, installation_id: int) -> dict | None:
        return await self.db.fetch_one("SELECT * FROM accounts WHERE installation_id=?", (installation_id,))

    async def get_account(self, account_id: str) -> dict | None:
        return await self.db.fetch_one("SELECT * FROM accounts WHERE id=?", (account_id,))

    async def get_repository(self, repository_id: str) -> dict | None:
        return await self.db.fetch_one("SELECT * FROM repositories WHERE id=?", (repository_id,))

    async def accounts_for_installations(self, installation_ids: Sequence[int]) -> list[dict]:
        if not installation_ids:
            return []
        return await self.db.fetch_all(
            f"SELECT * FROM accounts WHERE installation_id IN ({_in(installation_ids)})",
            tuple(installation_ids))

    async def upsert_repository(self, account_id: str, repo: dict) -> dict:
        existing = await self.get_repo_by_github_id(repo["id"])
        private = 1 if repo.get("private", True) else 0
        archived = 1 if repo.get("archived", False) else 0
        if existing:
            await self.db.execute(
                "UPDATE repositories SET account_id=?, name=?, full_name=?, private=?, "
                "default_branch=?, archived=? WHERE github_repo_id=?",
                (account_id, repo.get("name", existing["name"]), repo.get("full_name", existing["full_name"]),
                 private, repo.get("default_branch", existing["default_branch"]), archived, repo["id"]),
            )
            return await self.get_repo_by_github_id(repo["id"])
        rid = _id()
        await self.db.execute(
            "INSERT INTO repositories (id, account_id, github_repo_id, name, full_name, private, "
            "default_branch, archived) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (rid, account_id, repo["id"], repo.get("name", ""), repo.get("full_name", ""),
             private, repo.get("default_branch", "main"), archived),
        )
        return await self.get_repo_by_github_id(repo["id"])

    async def get_repo_by_github_id(self, github_repo_id: int) -> dict | None:
        return await self.db.fetch_one(
            "SELECT * FROM repositories WHERE github_repo_id=?", (github_repo_id,))

    async def list_repos(self, account_ids: Sequence[str]) -> list[dict]:
        if not account_ids:
            return []
        return await self.db.fetch_all(
            f"SELECT * FROM repositories WHERE account_id IN ({_in(account_ids)}) ORDER BY full_name",
            tuple(account_ids))

    # ── Scans ────────────────────────────────────────────────────────────────
    async def create_scan(self, account_id: str, repository_id: str, *, head_sha: str,
                          head_ref: str | None, pull_number: int | None) -> dict:
        sid = _id()
        await self.db.execute(
            "INSERT INTO scans (id, account_id, repository_id, head_sha, head_ref, pull_number, "
            "status, totals, created_at) VALUES (?, ?, ?, ?, ?, ?, 'queued', '{}', ?)",
            (sid, account_id, repository_id, head_sha, head_ref, pull_number, _now()),
        )
        return await self.get_scan(sid)

    async def get_scan(self, scan_id: str) -> dict | None:
        row = await self.db.fetch_one(f"SELECT {_SCAN_COLS} FROM scans WHERE id=?", (scan_id,))
        return _scan_row(row) if row else None

    async def set_scan_running(self, scan_id: str, check_run_id: int | None) -> None:
        await self.db.execute("UPDATE scans SET status='running', check_run_id=? WHERE id=?",
                              (check_run_id, scan_id))

    async def complete_scan(self, scan_id: str, *, status: str, conclusion: str,
                            security_result: str | None, lint_result: str | None,
                            totals: dict[str, int]) -> None:
        await self.db.execute(
            "UPDATE scans SET status=?, conclusion=?, security_result=?, lint_result=?, "
            "totals=?, completed_at=? WHERE id=?",
            (status, conclusion, security_result, lint_result, json.dumps(totals), _now(), scan_id),
        )

    async def insert_findings(self, scan: dict, findings: list[dict]) -> None:
        if not findings:
            return
        rows = [(_id(), scan["id"], scan["account_id"], scan["repository_id"], f["tool"], f["rule_id"],
                 f["rule_name"], f["severity"], f["message"], f["path"], f["line"], f["help_uri"],
                 f["fingerprint"]) for f in findings]
        await self.db.execute_many(
            "INSERT INTO findings (id, scan_id, account_id, repository_id, tool, rule_id, rule_name, "
            "severity, message, path, line, help_uri, fingerprint) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", rows)

    async def list_scans(self, account_ids: Sequence[str], repository_id: str | None,
                         limit: int, offset: int) -> tuple[list[dict], int]:
        where = [f"account_id IN ({_in(account_ids)})"]
        params: list[Any] = list(account_ids)
        if repository_id:
            where.append("repository_id=?")
            params.append(repository_id)
        clause = " AND ".join(where)
        total = (await self.db.fetch_one(f"SELECT COUNT(*) AS n FROM scans WHERE {clause}", params))["n"]
        rows = await self.db.fetch_all(
            f"SELECT {_SCAN_COLS} FROM scans WHERE {clause} ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (*params, limit, offset))
        return [_scan_row(r) for r in rows], total

    # ── Latest-scan-per-repo helpers (the "Security tab" view) ───────────────
    async def _latest_scan_ids(self, account_ids: Sequence[str], repository_id: str | None = None) -> list[str]:
        where = [f"account_id IN ({_in(account_ids)})", "status IN ('completed','error')"]
        params: list[Any] = list(account_ids)
        if repository_id:
            where.append("repository_id=?")
            params.append(repository_id)
        clause = " AND ".join(where)
        rows = await self.db.fetch_all(
            f"SELECT s.id AS id FROM scans s JOIN ("
            f"  SELECT repository_id, MAX(created_at) AS mx FROM scans WHERE {clause} GROUP BY repository_id"
            f") t ON s.repository_id=t.repository_id AND s.created_at=t.mx", params)
        return [r["id"] for r in rows]

    async def summary(self, account_ids: Sequence[str]) -> dict:
        latest_ids = await self._latest_scan_ids(account_ids)
        totals = {s: 0 for s in SEVERITIES}
        scan_by_repo: dict[str, dict] = {}
        if latest_ids:
            scans = await self.db.fetch_all(
                f"SELECT {_SCAN_COLS} FROM scans WHERE id IN ({_in(latest_ids)})", latest_ids)
            for sc in (_scan_row(s) for s in scans):
                scan_by_repo[sc["repository_id"]] = sc
                for sev, n in sc["totals"].items():
                    totals[sev] = totals.get(sev, 0) + n

        by_tool: dict[str, int] = {}
        if latest_ids:
            for r in await self.db.fetch_all(
                f"SELECT tool, COUNT(*) AS n FROM findings WHERE scan_id IN ({_in(latest_ids)}) "
                f"GROUP BY tool", latest_ids):
                by_tool[r["tool"]] = r["n"]

        repos = await self.list_repos(account_ids)
        repo_summaries = []
        for repo in repos:
            sc = scan_by_repo.get(repo["id"])
            repo_summaries.append({
                "repository": repo,
                "totals": sc["totals"] if sc else {s: 0 for s in SEVERITIES},
                "last_scan_at": sc["completed_at"] if sc else None,
            })
        repo_summaries.sort(key=lambda rs: sum(rs["totals"].values()), reverse=True)
        return {"totals": totals, "by_tool": by_tool, "repo_count": len(repos),
                "scan_count": len(latest_ids), "repos": repo_summaries}

    async def list_findings(self, account_ids: Sequence[str], *, repository_id: str | None,
                            severity: str | None, tool: str | None, latest_only: bool,
                            limit: int, offset: int) -> tuple[list[dict], int]:
        where = [f"account_id IN ({_in(account_ids)})"]
        params: list[Any] = list(account_ids)
        if repository_id:
            where.append("repository_id=?")
            params.append(repository_id)
        if severity:
            where.append("severity=?")
            params.append(severity)
        if tool:
            where.append("tool=?")
            params.append(tool)
        if latest_only:
            latest_ids = await self._latest_scan_ids(account_ids, repository_id)
            if not latest_ids:
                return [], 0
            where.append(f"scan_id IN ({_in(latest_ids)})")
            params += latest_ids
        clause = " AND ".join(where)
        total = (await self.db.fetch_one(f"SELECT COUNT(*) AS n FROM findings WHERE {clause}", params))["n"]
        # Order by severity rank (portable: a CASE expression).
        rank = " ".join(f"WHEN '{s}' THEN {i}" for i, s in enumerate(SEVERITIES))
        rows = await self.db.fetch_all(
            f"SELECT * FROM findings WHERE {clause} ORDER BY CASE severity {rank} ELSE 99 END, tool "
            f"LIMIT ? OFFSET ?", (*params, limit, offset))
        return rows, total
