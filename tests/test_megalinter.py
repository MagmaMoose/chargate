"""Unit tests for the MegaLinter wrapper (chargate.megalinter)."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

from chargate import megalinter as ml


def test_image_name_for_flavors():
    assert ml.MegaLinterConfig(flavor="all").image() == "oxsecurity/megalinter:v8"
    assert ml.MegaLinterConfig(flavor="").image() == "oxsecurity/megalinter:v8"
    assert ml.MegaLinterConfig(flavor="security").image() == "oxsecurity/megalinter-security:v8"
    assert ml.MegaLinterConfig(flavor="python", image_tag="v8.1").image() == (
        "oxsecurity/megalinter-python:v8.1"
    )


def test_build_env_disables_errors_and_enables_reporters():
    env = ml.build_env(ml.MegaLinterConfig(enable_linters=("REPOSITORY_TRIVY",)))
    assert env["DISABLE_ERRORS"] == "true"  # chargate owns the gate
    assert env["SARIF_REPORTER"] == "true"
    assert env["JSON_REPORTER"] == "true"
    assert env["SARIF_REPORTER_NORMALIZE_LINTERS_OUTPUT"] == "true"
    assert env["REPORT_OUTPUT_FOLDER"] == "megalinter-reports"
    assert env["ENABLE_LINTERS"] == "REPOSITORY_TRIVY"


def test_build_env_defaults_to_whole_repo_scan():
    env = ml.build_env(ml.MegaLinterConfig())
    assert env["VALIDATE_ALL_CODEBASE"] == "true"


def test_build_env_incremental_disables_validate_all_codebase():
    env = ml.build_env(ml.MegaLinterConfig(validate_all_codebase=False))
    assert env["VALIDATE_ALL_CODEBASE"] == "false"


def test_build_env_merges_extra_env():
    # Incremental runs pass DEFAULT_BRANCH so MegaLinter can find changed files.
    env = ml.build_env(
        ml.MegaLinterConfig(validate_all_codebase=False, extra_env={"DEFAULT_BRANCH": "main"})
    )
    assert env["DEFAULT_BRANCH"] == "main"


def test_build_docker_command_mounts_workspace_and_passes_env(tmp_path: Path):
    config = ml.MegaLinterConfig(workspace=str(tmp_path))
    cmd = ml.build_docker_command(config, {"FOO": "bar"})
    # argv[0] is `docker` or its resolved absolute path, depending on the host.
    assert Path(cmd[0]).stem == "docker"
    assert cmd[1:3] == ["run", "--rm"]
    assert "-e" in cmd and "FOO=bar" in cmd
    assert cmd[-1] == "oxsecurity/megalinter:v8"
    # workspace mounted to the MegaLinter default workspace path
    mount = f"{tmp_path.resolve()}:{ml.CONTAINER_WORKSPACE}"
    assert mount in cmd


def test_locate_sarif_prefers_configured_name(tmp_path: Path):
    reports = tmp_path / "megalinter-reports"
    reports.mkdir()
    (reports / "megalinter-report.sarif").write_text("{}", encoding="utf-8")
    config = ml.MegaLinterConfig(workspace=str(tmp_path))
    assert ml.locate_sarif(config) == config.sarif_path()


def test_locate_sarif_falls_back_to_any_sarif(tmp_path: Path):
    reports = tmp_path / "megalinter-reports"
    reports.mkdir()
    # Different filename (the documented ambiguity) — still found.
    (reports / "mega-linter-report.sarif").write_text("{}", encoding="utf-8")
    config = ml.MegaLinterConfig(workspace=str(tmp_path))
    assert ml.locate_sarif(config).name == "mega-linter-report.sarif"


def test_locate_sarif_missing_raises(tmp_path: Path):
    config = ml.MegaLinterConfig(workspace=str(tmp_path))
    with pytest.raises(ml.MegaLinterError):
        ml.locate_sarif(config)


def test_run_uses_injected_runner(tmp_path: Path):
    config = ml.MegaLinterConfig(workspace=str(tmp_path))
    captured: dict[str, list[str]] = {}

    def fake_runner(cmd: list[str]) -> subprocess.CompletedProcess:
        captured["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, returncode=0)

    run = ml.run(config, runner=fake_runner)
    assert run.returncode == 0
    assert Path(captured["cmd"][0]).stem == "docker"
    assert run.sarif_path == config.sarif_path()


def test_build_env_excludes_chargate_own_workspace_artifacts():
    """The BOM/SARIF chargate writes into the workspace must never be scanned.

    They are not in git, so a finding in them is `file-not-changed` forever: the
    gate can neither surface it as net-new nor clear it, but it sits open in the
    Security tab. (Regression guard for the 13 devskim alerts on the generated
    chargate-sbom.cdx.json.)
    """
    env = ml.build_env(ml.MegaLinterConfig())
    pattern = env["FILTER_REGEX_EXCLUDE"]
    for path in (
        ml.SBOM_FILE_NAME,
        f"{ml.SARIF_OUT_DIR}/full.sarif",
        "megalinter-reports/megalinter-report.sarif",
    ):
        assert re.search(pattern, path), f"{path} should be excluded by {pattern}"
    # Real source is still scanned.
    for path in ("src/chargate/cli.py", "k8s/base/deployment.yaml"):
        assert not re.search(pattern, path)


def test_build_env_exclude_ors_consumer_pattern_rather_than_replacing_it():
    env = ml.build_env(ml.MegaLinterConfig(extra_env={"FILTER_REGEX_EXCLUDE": "(vendor/)"}))
    pattern = env["FILTER_REGEX_EXCLUDE"]
    assert re.search(pattern, "vendor/thing.py")  # consumer's pattern honoured
    assert re.search(pattern, ml.SBOM_FILE_NAME)  # chargate's still applied
