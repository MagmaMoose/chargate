"""End-to-end repository tests on SQLite — proving the portable SQL (and thus the
D1 path) for the whole webhook → ingest → Security-tab flow."""
from chargate_api.sarif import findings_from_docs

INSTALL = {"id": 555, "account": {"id": 1, "login": "acme", "type": "Organization"}}
REPO = {"id": 99, "name": "widgets", "full_name": "acme/widgets", "private": True, "default_branch": "main"}

DOC = {
    "runs": [{
        "tool": {"driver": {"name": "Trivy", "rules": [
            {"id": "CVE-1", "properties": {"security-severity": "9.8"}},
            {"id": "CVE-2", "properties": {"security-severity": "3.1"}},
        ]}},
        "results": [
            {"ruleId": "CVE-1", "message": {"text": "boom"},
             "locations": [{"physicalLocation": {"artifactLocation": {"uri": "go.sum"},
                                                 "region": {"startLine": 7}}}]},
            {"ruleId": "CVE-2", "message": {"text": "meh"},
             "locations": [{"physicalLocation": {"artifactLocation": {"uri": "p.json"}}}]},
        ],
    }],
}


async def _seed_completed_scan(repo):
    account = await repo.upsert_account(INSTALL)
    repository = await repo.upsert_repository(account["id"], REPO)
    scan = await repo.create_scan(account["id"], repository["id"], head_sha="abc", head_ref="main", pull_number=1)
    findings = findings_from_docs([DOC])
    await repo.insert_findings(scan, findings)
    await repo.complete_scan(scan["id"], status="completed", conclusion="neutral",
                             security_result="findings", lint_result="pass",
                             totals={"critical": 1, "high": 0, "medium": 0, "low": 1, "note": 0})
    return account, repository, scan


async def test_account_and_repo_upsert_are_idempotent(repo):
    a1 = await repo.upsert_account(INSTALL)
    a2 = await repo.upsert_account({**INSTALL, "account": {**INSTALL["account"], "login": "acme2"}})
    assert a1["id"] == a2["id"] and a2["login"] == "acme2"
    r1 = await repo.upsert_repository(a1["id"], REPO)
    r2 = await repo.upsert_repository(a1["id"], REPO)
    assert r1["id"] == r2["id"]


async def test_full_flow_summary_and_findings(repo):
    account, repository, scan = await _seed_completed_scan(repo)

    accts = await repo.accounts_for_installations([555])
    assert [a["id"] for a in accts] == [account["id"]]
    ids = [account["id"]]

    summary = await repo.summary(ids)
    assert summary["totals"]["critical"] == 1
    assert summary["totals"]["low"] == 1
    assert summary["scan_count"] == 1
    assert summary["repo_count"] == 1
    assert summary["by_tool"] == {"Trivy": 2}
    assert summary["repos"][0]["repository"]["full_name"] == "acme/widgets"

    items, total = await repo.list_findings(ids, repository_id=None, severity=None, tool=None,
                                            latest_only=True, limit=50, offset=0)
    assert total == 2
    # Severity ordering: critical before low.
    assert items[0]["severity"] == "critical"

    crit, n = await repo.list_findings(ids, repository_id=repository["id"], severity="critical",
                                       tool=None, latest_only=True, limit=50, offset=0)
    assert n == 1 and crit[0]["rule_id"] == "CVE-1" and crit[0]["line"] == 7


async def test_tenant_isolation(repo):
    await _seed_completed_scan(repo)
    # A user with no matching installation sees nothing.
    assert await repo.accounts_for_installations([999]) == []
    empty = await repo.summary([])
    assert empty["repo_count"] == 0 and sum(empty["totals"].values()) == 0


async def test_latest_scan_supersedes_previous(repo):
    account, repository, _ = await _seed_completed_scan(repo)
    # A newer scan with no findings should make the repo show clean.
    newer = await repo.create_scan(account["id"], repository["id"], head_sha="def", head_ref="main", pull_number=2)
    await repo.complete_scan(newer["id"], status="completed", conclusion="success",
                             security_result="pass", lint_result="pass",
                             totals={"critical": 0, "high": 0, "medium": 0, "low": 0, "note": 0})
    summary = await repo.summary([account["id"]])
    assert sum(summary["totals"].values()) == 0
    assert summary["scan_count"] == 1   # one repo, its latest scan only
