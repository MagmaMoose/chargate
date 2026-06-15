"""Unit tests for the MegaLinter wrapper (chargate.megalinter)."""

from __future__ import annotations

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


def test_build_docker_command_mounts_workspace_and_passes_env(tmp_path: Path):
    config = ml.MegaLinterConfig(workspace=str(tmp_path))
    cmd = ml.build_docker_command(config, {"FOO": "bar"})
    assert cmd[:3] == ["docker", "run", "--rm"]
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
    assert captured["cmd"][0] == "docker"
    assert run.sarif_path == config.sarif_path()
