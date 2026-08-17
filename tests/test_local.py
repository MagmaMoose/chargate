"""Unit tests for the local pre-commit runner (chargate.local)."""

from __future__ import annotations

import subprocess

from chargate.local import DEFAULT_CHECKS, LocalCheck, run_local


def _ok_runner(cmd):
    return subprocess.CompletedProcess(cmd, returncode=0)


def test_missing_tools_are_skipped_not_failed():
    code, outcomes = run_local(["a.py"], which=lambda _t: None)
    assert code == 0
    assert outcomes and all(o.status == "skipped" for o in outcomes)


def test_clean_run_passes():
    code, outcomes = run_local(["a.py"], which=lambda t: f"/usr/bin/{t}", runner=_ok_runner)
    assert code == 0
    assert any(o.status == "ok" for o in outcomes)


def test_findings_fail():
    def runner(cmd):
        return subprocess.CompletedProcess(cmd, returncode=1)

    code, outcomes = run_local(["a.py"], which=lambda t: f"/usr/bin/{t}", runner=runner)
    assert code == 1
    assert any(o.status == "findings" for o in outcomes)


def test_ruff_check_only_receives_python_files():
    seen: dict[str, list[str]] = {}

    def runner(cmd):
        seen[cmd[0]] = cmd
        return subprocess.CompletedProcess(cmd, returncode=0)

    checks = (LocalCheck("ruff", "ruff", lambda files: ["ruff", "check", *files]),)
    run_local(
        ["a.py", "b.txt", "c.pyi", "d.js"],
        checks=checks,
        which=lambda t: f"/usr/bin/{t}",
        runner=runner,
    )
    # argv[0] is the abs path `which` resolved, not the bare tool name (B607).
    assert seen["/usr/bin/ruff"] == ["/usr/bin/ruff", "check", "a.py", "c.pyi"]


def test_no_files_check_runs_without_files():
    seen: dict[str, list[str]] = {}

    def runner(cmd):
        seen[cmd[0]] = cmd
        return subprocess.CompletedProcess(cmd, returncode=0)

    checks = (
        LocalCheck(
            "secrets", "gitleaks", lambda _f: ["gitleaks", "protect", "--staged"], needs_files=False
        ),
    )
    run_local([], checks=checks, which=lambda t: f"/usr/bin/{t}", runner=runner)
    assert seen["/usr/bin/gitleaks"] == ["/usr/bin/gitleaks", "protect", "--staged"]


def test_default_checks_present():
    tools = {c.tool for c in DEFAULT_CHECKS}
    assert "gitleaks" in tools  # MegaLinter-native secrets choice
