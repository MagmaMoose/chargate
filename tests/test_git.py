"""Integration tests for the git IO boundary against real repositories.

These validate the diff parser end-to-end on actual `git diff` output (not just
synthetic fixtures) and verify the actionable failure modes for shallow clones /
missing merge-bases required by the acceptance criteria.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from chargate import git as cgit
from chargate.sarif.diff import DiffIndex
from chargate.sarif.filter import filter_sarif

pytestmark = pytest.mark.skipif(
    subprocess.run(["git", "--version"], capture_output=True).returncode != 0,
    reason="git is not available",
)


def _run(args: list[str], cwd: Path) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)


def _init_repo(path: Path) -> None:
    _run(["init", "-q", "-b", "main"], path)
    _run(["config", "user.email", "test@example.com"], path)
    _run(["config", "user.name", "Test"], path)
    _run(["config", "commit.gpgsign", "false"], path)


def _commit_all(path: Path, message: str) -> str:
    _run(["add", "-A"], path)
    _run(["commit", "-q", "-m", message], path)
    return subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=path, capture_output=True, text=True, check=True
    ).stdout.strip()


def test_end_to_end_net_new_against_real_repo(tmp_path: Path, make_sarif, make_result):
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_repo(repo)

    # Base: a file with two findable lines already present (pre-existing debt).
    src = repo / "app.py"
    src.write_text("line1 = 1\nline2 = 2\nline3 = 3\n", encoding="utf-8")
    base_sha = _commit_all(repo, "base")

    # PR: append a new line (introducing line 4) and modify nothing else.
    src.write_text("line1 = 1\nline2 = 2\nline3 = 3\nnew_line = 4\n", encoding="utf-8")
    head_sha = _commit_all(repo, "pr")

    diff_index = cgit.compute_changed_lines(base_sha, head_sha, repo)
    assert isinstance(diff_index, DiffIndex)
    app = diff_index.get("app.py")
    assert app is not None
    assert app.contains_line(4)
    assert not app.contains_line(1)

    # 2 pre-existing findings + 1 net-new on the added line 4.
    sarif = make_sarif(
        [
            make_result("app.py", 1, rule_id="pre-1"),
            make_result("app.py", 2, rule_id="pre-2"),
            make_result("app.py", 4, rule_id="net-new"),
        ]
    )
    out = filter_sarif(sarif, diff_index)
    assert out.counts.total == 3
    assert out.counts.net_new == 1
    assert out.filtered_sarif["runs"][0]["results"][0]["ruleId"] == "net-new"


def test_new_file_in_real_repo_is_all_net_new(tmp_path: Path, make_sarif, make_result):
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_repo(repo)
    (repo / "keep.py").write_text("x = 1\n", encoding="utf-8")
    base_sha = _commit_all(repo, "base")
    (repo / "brand_new.py").write_text("a = 1\nb = 2\n", encoding="utf-8")
    head_sha = _commit_all(repo, "add file")

    diff_index = cgit.compute_changed_lines(base_sha, head_sha, repo)
    new_file = diff_index.get("brand_new.py")
    assert new_file is not None and new_file.is_new_file

    sarif = make_sarif([make_result("brand_new.py", 99)])
    out = filter_sarif(sarif, diff_index)
    assert out.counts.net_new == 1


def test_merge_base_missing_raises_actionable_error(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_repo(repo)
    (repo / "a.py").write_text("a = 1\n", encoding="utf-8")
    head_sha = _commit_all(repo, "main commit")

    # An orphan branch shares no history -> no merge-base.
    _run(["checkout", "-q", "--orphan", "unrelated"], repo)
    (repo / "b.py").write_text("b = 2\n", encoding="utf-8")
    orphan_sha = _commit_all(repo, "orphan commit")

    with pytest.raises(cgit.MergeBaseError) as exc:
        cgit.compute_changed_lines(head_sha, orphan_sha, repo)
    assert "fetch-depth: 0" in str(exc.value)


def test_shallow_clone_raises_shallow_error(tmp_path: Path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_repo(repo)
    (repo / "a.py").write_text("a = 1\n", encoding="utf-8")
    head_sha = _commit_all(repo, "main commit")
    _run(["checkout", "-q", "--orphan", "unrelated"], repo)
    (repo / "b.py").write_text("b = 2\n", encoding="utf-8")
    orphan_sha = _commit_all(repo, "orphan commit")

    # Force the shallow code path: merge-base fails AND the repo reports shallow.
    monkeypatch.setattr(cgit, "is_shallow", lambda cwd=None: True)
    with pytest.raises(cgit.ShallowCloneError) as exc:
        cgit.merge_base(head_sha, orphan_sha, repo)
    assert "shallow" in str(exc.value).lower()
    assert "fetch-depth: 0" in str(exc.value)
