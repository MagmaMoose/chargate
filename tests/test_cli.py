"""End-to-end tests for the CLI (chargate.cli) against a real repository."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from chargate.cli import main
from chargate.gate import EXIT_BLOCKED, EXIT_ERROR, EXIT_OK

pytestmark = pytest.mark.skipif(
    subprocess.run(["git", "--version"], capture_output=True).returncode != 0,
    reason="git is not available",
)


def _run(args: list[str], cwd: Path) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)


def _rev(cwd: Path) -> str:
    return subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=cwd, capture_output=True, text=True, check=True
    ).stdout.strip()


@pytest.fixture
def pr_repo(tmp_path: Path, make_sarif, make_result):
    """A repo whose head adds line 4 to app.py; returns (repo, base, head, sarif_path).

    The SARIF has two pre-existing findings (lines 1-2) and one net-new (line 4).
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    _run(["init", "-q", "-b", "main"], repo)
    _run(["config", "user.email", "t@e.com"], repo)
    _run(["config", "user.name", "T"], repo)
    _run(["config", "commit.gpgsign", "false"], repo)

    (repo / "app.py").write_text("a = 1\nb = 2\nc = 3\n", encoding="utf-8")
    _run(["add", "-A"], repo)
    _run(["commit", "-q", "-m", "base"], repo)
    base = _rev(repo)

    (repo / "app.py").write_text("a = 1\nb = 2\nc = 3\nd = 4\n", encoding="utf-8")
    _run(["add", "-A"], repo)
    _run(["commit", "-q", "-m", "pr"], repo)
    head = _rev(repo)

    sarif = make_sarif(
        [
            make_result("app.py", 1, rule_id="pre-1", level="error"),
            make_result("app.py", 2, rule_id="pre-2", level="error"),
            make_result("app.py", 4, rule_id="net-new", level="error"),
        ]
    )
    sarif_path = tmp_path / "report.sarif"
    sarif_path.write_text(json.dumps(sarif), encoding="utf-8")
    return repo, base, head, sarif_path


def test_filter_sarif_blocks_on_net_new(pr_repo, capsys):
    repo, base, head, sarif_path = pr_repo
    code = main(
        [
            "filter-sarif",
            "--sarif",
            str(sarif_path),
            "--base",
            base,
            "--head",
            head,
            "--repo",
            str(repo),
        ]
    )
    assert code == EXIT_BLOCKED
    err = capsys.readouterr().err
    assert "net-new 1 / 3 total" in err
    assert "net-new" in err  # the rule id of the blocking finding


def test_filter_sarif_writes_filtered_and_counts(pr_repo, tmp_path: Path):
    repo, base, head, sarif_path = pr_repo
    out = tmp_path / "filtered.sarif"
    counts = tmp_path / "counts.json"
    main(
        [
            "filter-sarif",
            "--sarif",
            str(sarif_path),
            "--base",
            base,
            "--head",
            head,
            "--repo",
            str(repo),
            "--out",
            str(out),
            "--counts-json",
            str(counts),
            "--quiet",
        ]
    )
    filtered = json.loads(out.read_text(encoding="utf-8"))
    kept = filtered["runs"][0]["results"]
    assert len(kept) == 1 and kept[0]["ruleId"] == "net-new"

    data = json.loads(counts.read_text(encoding="utf-8"))
    assert data["net_new_count"] == 1
    assert data["total_count"] == 3
    assert data["pre_existing_count"] == 2


def test_no_gate_exits_zero_but_still_reports(pr_repo):
    repo, base, head, sarif_path = pr_repo
    code = main(
        [
            "filter-sarif",
            "--sarif",
            str(sarif_path),
            "--base",
            base,
            "--head",
            head,
            "--repo",
            str(repo),
            "--no-gate",
        ]
    )
    assert code == EXIT_OK


def test_fail_on_none_passes(pr_repo):
    repo, base, head, sarif_path = pr_repo
    code = main(
        [
            "filter-sarif",
            "--sarif",
            str(sarif_path),
            "--base",
            base,
            "--head",
            head,
            "--repo",
            str(repo),
            "--fail-on",
            "none",
        ]
    )
    assert code == EXIT_OK


def test_missing_merge_base_returns_error_exit(tmp_path: Path, make_sarif, make_result):
    repo = tmp_path / "repo"
    repo.mkdir()
    _run(["init", "-q", "-b", "main"], repo)
    _run(["config", "user.email", "t@e.com"], repo)
    _run(["config", "user.name", "T"], repo)
    _run(["config", "commit.gpgsign", "false"], repo)
    (repo / "a.py").write_text("a = 1\n", encoding="utf-8")
    _run(["add", "-A"], repo)
    _run(["commit", "-q", "-m", "main"], repo)
    head = _rev(repo)
    _run(["checkout", "-q", "--orphan", "unrelated"], repo)
    (repo / "b.py").write_text("b = 2\n", encoding="utf-8")
    _run(["add", "-A"], repo)
    _run(["commit", "-q", "-m", "orphan"], repo)
    orphan = _rev(repo)

    sarif_path = tmp_path / "r.sarif"
    sarif_path.write_text(json.dumps(make_sarif([make_result("a.py", 1)])), encoding="utf-8")

    code = main(
        [
            "filter-sarif",
            "--sarif",
            str(sarif_path),
            "--base",
            head,
            "--head",
            orphan,
            "--repo",
            str(repo),
        ]
    )
    assert code == EXIT_ERROR


def test_missing_sarif_file_errors(tmp_path: Path):
    with pytest.raises(SystemExit) as exc:
        main(
            [
                "filter-sarif",
                "--sarif",
                str(tmp_path / "nope.sarif"),
                "--base",
                "x",
                "--head",
                "y",
                "--repo",
                str(tmp_path),
            ]
        )
    assert exc.value.code == EXIT_ERROR


def test_version_command(capsys):
    assert main(["version"]) == EXIT_OK
    assert capsys.readouterr().out.strip()


# ── chargate ci (using --sarif to skip the Docker MegaLinter run) ────────────


def test_ci_pr_mode_gates_and_ships_full_sarif(pr_repo, tmp_path: Path):
    repo, base, head, sarif_path = pr_repo
    full_out = tmp_path / "full.sarif"
    filtered_out = tmp_path / "net-new.sarif"
    counts = tmp_path / "counts.json"
    code = main(
        [
            "ci",
            "--mode",
            "pr",
            "--sarif",
            str(sarif_path),
            "--base",
            base,
            "--head",
            head,
            "--repo",
            str(repo),
            "--sarif-out",
            str(full_out),
            "--filtered-out",
            str(filtered_out),
            "--counts-json",
            str(counts),
            "--quiet",
        ]
    )
    assert code == EXIT_BLOCKED
    # Full SARIF shipped with ALL findings; filtered has only the net-new one.
    assert len(json.loads(full_out.read_text())["runs"][0]["results"]) == 3
    assert len(json.loads(filtered_out.read_text())["runs"][0]["results"]) == 1
    assert json.loads(counts.read_text())["net_new_count"] == 1


def test_ci_baseline_mode_never_gates(pr_repo, tmp_path: Path):
    repo, _base, _head, sarif_path = pr_repo
    counts = tmp_path / "counts.json"
    code = main(
        [
            "ci",
            "--mode",
            "baseline",
            "--sarif",
            str(sarif_path),
            "--repo",
            str(repo),
            "--counts-json",
            str(counts),
            "--quiet",
        ]
    )
    assert code == EXIT_OK
    data = json.loads(counts.read_text())
    assert data["net_new_count"] == 0  # baseline gates nothing
    assert data["total_count"] == 3  # but the full picture is still counted


def test_ci_pr_mode_requires_base(pr_repo):
    repo, _base, _head, sarif_path = pr_repo
    code = main(["ci", "--mode", "pr", "--sarif", str(sarif_path), "--repo", str(repo), "--quiet"])
    assert code == EXIT_ERROR


def test_ci_defectdojo_skipped_without_token(pr_repo, capsys, monkeypatch):
    repo, base, head, sarif_path = pr_repo
    monkeypatch.delenv("DEFECTDOJO_TOKEN", raising=False)
    code = main(
        [
            "ci",
            "--mode",
            "pr",
            "--sarif",
            str(sarif_path),
            "--base",
            base,
            "--head",
            head,
            "--repo",
            str(repo),
            "--defectdojo-url",
            "https://dd.example.com",
        ]
    )
    # DD skipped (no token) must NOT change the gate outcome.
    assert code == EXIT_BLOCKED
    assert "skipped (no token" in capsys.readouterr().err


def test_ci_dependency_track_skipped_without_key(pr_repo, capsys, monkeypatch):
    repo, base, head, sarif_path = pr_repo
    monkeypatch.delenv("DEPENDENCYTRACK_API_KEY", raising=False)
    code = main(
        [
            "ci",
            "--mode",
            "pr",
            "--sarif",
            str(sarif_path),
            "--base",
            base,
            "--head",
            head,
            "--repo",
            str(repo),
            "--dependency-track-url",
            "https://dtrack.example.com",
            "--dt-project-name",
            "p",
            "--bom",
            str(sarif_path),  # any existing file; skip happens before reading it
        ]
    )
    # DT skipped (no API key) must NOT change the gate outcome.
    assert code == EXIT_BLOCKED
    assert "skipped (no API key" in capsys.readouterr().err


def test_ci_dependency_track_skipped_without_bom(pr_repo, capsys):
    repo, base, head, sarif_path = pr_repo
    code = main(
        [
            "ci",
            "--mode",
            "pr",
            "--sarif",
            str(sarif_path),
            "--base",
            base,
            "--head",
            head,
            "--repo",
            str(repo),
            "--dependency-track-url",
            "https://dtrack.example.com",
        ]
    )
    assert code == EXIT_BLOCKED
    assert "skipped (no --bom path)" in capsys.readouterr().err


def _ci_pr_comment_args(repo, base, head, sarif_path, *extra: str) -> list[str]:
    return [
        "ci", "--mode", "pr",
        "--sarif", str(sarif_path),
        "--base", base, "--head", head, "--repo", str(repo),
        "--pr-comment", *extra,
    ]  # fmt: skip


def test_ci_pr_comment_skipped_without_token(pr_repo, capsys, monkeypatch):
    repo, base, head, sarif_path = pr_repo
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    code = main(
        _ci_pr_comment_args(repo, base, head, sarif_path, "--pr-number", "7", "--repo-slug", "o/r")
    )
    assert code == EXIT_BLOCKED  # PR-comment skip must NOT change the gate
    assert "skipped (no token" in capsys.readouterr().err


def test_ci_pr_comment_skipped_without_pr_number(pr_repo, capsys, monkeypatch):
    repo, base, head, sarif_path = pr_repo
    monkeypatch.setenv("GITHUB_TOKEN", "tok")
    code = main(_ci_pr_comment_args(repo, base, head, sarif_path, "--repo-slug", "o/r"))
    assert code == EXIT_BLOCKED
    assert "need --pr-number" in capsys.readouterr().err


def test_ci_pr_comment_posts_summary_and_inline(pr_repo, capsys, monkeypatch):
    repo, base, head, sarif_path = pr_repo
    monkeypatch.setenv("GITHUB_TOKEN", "tok")

    captured: dict = {}

    def _fake_post(config, *, summary_body=None, inline_comments=None):
        captured["config"] = config
        captured["summary_body"] = summary_body
        captured["inline_comments"] = inline_comments
        from chargate.github_comment import GitHubCommentResult

        return GitHubCommentResult(ok=True, message="summary created, 1 inline comment(s)")

    monkeypatch.setattr("chargate.github_comment.post_pr_feedback", _fake_post)

    code = main(
        _ci_pr_comment_args(repo, base, head, sarif_path, "--pr-number", "7", "--repo-slug", "o/r")
    )
    assert code == EXIT_BLOCKED  # the one net-new finding still gates
    assert "PR comments: summary created" in capsys.readouterr().err

    # Wiring: slug/pr/head-SHA flowed into the config; the head was resolved to a SHA.
    assert captured["config"].repo_slug == "o/r"
    assert captured["config"].pr_number == 7
    assert captured["config"].commit_id == head
    # The summary lists net-new; the one added line (4) becomes an inline comment.
    from chargate.github_comment import SUMMARY_MARKER

    assert SUMMARY_MARKER in captured["summary_body"]
    assert [c.line for c in captured["inline_comments"]] == [4]
    assert captured["inline_comments"][0].path == "app.py"


def test_ci_pr_comment_not_attempted_in_baseline_mode(pr_repo, capsys, monkeypatch):
    repo, _base, _head, sarif_path = pr_repo
    monkeypatch.setenv("GITHUB_TOKEN", "tok")
    called = {"n": 0}
    monkeypatch.setattr(
        "chargate.github_comment.post_pr_feedback",
        lambda *a, **k: called.__setitem__("n", called["n"] + 1),
    )
    main(["ci", "--mode", "baseline", "--sarif", str(sarif_path), "--repo", str(repo),
          "--pr-comment", "--pr-number", "7", "--repo-slug", "o/r"])  # fmt: skip
    assert called["n"] == 0  # baseline never comments


def test_local_no_staged_files_passes(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _run(["init", "-q", "-b", "main"], repo)
    _run(["config", "user.email", "t@e.com"], repo)
    _run(["config", "user.name", "T"], repo)
    assert main(["local", "--repo", str(repo), "--quiet"]) == EXIT_OK
