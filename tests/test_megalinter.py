"""Unit tests for the MegaLinter wrapper (chargate.megalinter)."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest

from chargate import megalinter as ml


def _completed(cmd: list[str], returncode: int = 0) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(cmd, returncode=returncode)


def _raise_oserror(cmd: list[str]) -> subprocess.CompletedProcess:
    raise OSError("no docker")


def _docker_version_fails(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(cmd, returncode=1, stdout="")


# ── Image resolution: registry, namespace, flavor, tag, digest, full override ──


def test_image_name_for_flavors():
    assert ml.MegaLinterConfig(flavor="all").image() == "ghcr.io/oxsecurity/megalinter:v10.0.0"
    assert ml.MegaLinterConfig(flavor="").image() == "ghcr.io/oxsecurity/megalinter:v10.0.0"
    assert ml.MegaLinterConfig(flavor="security").image() == (
        "ghcr.io/oxsecurity/megalinter-security:v10.0.0"
    )
    assert ml.MegaLinterConfig(flavor="python", image_tag="v10").image() == (
        "ghcr.io/oxsecurity/megalinter-python:v10"
    )


def test_default_registry_is_ghcr_not_docker_hub():
    # MegaLinter froze Docker Hub at v9.4.0; docker.io cannot serve the default tag.
    assert ml.DEFAULT_REGISTRY == "ghcr.io"
    assert ml.MegaLinterConfig().image().split("/")[0] == "ghcr.io"


def test_registry_and_namespace_are_overridable_for_a_mirror():
    config = ml.MegaLinterConfig(
        flavor="security", registry="registry.internal:5000", namespace="mirrors/oxsecurity"
    )
    assert config.image() == "registry.internal:5000/mirrors/oxsecurity/megalinter-security:v10.0.0"


def test_digest_tag_pins_with_an_at_sign():
    digest = "sha256:980e5e9877d1ad9846ee3409e74a3a8905cb2fbe35e79af53d1274210e02eb4f"
    assert ml.MegaLinterConfig(flavor="security", image_tag=digest).image() == (
        f"ghcr.io/oxsecurity/megalinter-security@{digest}"
    )


def test_image_ref_overrides_registry_namespace_flavor_and_tag():
    # The escape hatch: a custom flavor / air-gapped copy must win outright.
    config = ml.MegaLinterConfig(
        flavor="security",
        image_tag="v9.6.0",
        registry="ghcr.io",
        namespace="oxsecurity",
        image_ref="ghcr.io/acme/tools/megalinter-custom-flavor:2026.1",
    )
    assert config.image() == "ghcr.io/acme/tools/megalinter-custom-flavor:2026.1"


def test_standalone_image_name_is_per_linter_and_ignores_image_ref():
    config = ml.MegaLinterConfig(image_ref="ghcr.io/acme/custom:1")
    assert config.standalone_image("REPOSITORY_TRIVY") == (
        "ghcr.io/oxsecurity/megalinter-only-repository_trivy:v10.0.0"
    )


def test_composite_action_defaults_to_security_incremental_scanning():
    action = (Path(__file__).parent.parent / "action.yml").read_text(encoding="utf-8")

    assert re.search(r"flavor:\n(?:.*\n){0,6}\s+default: 'security'", action)
    assert re.search(r"incremental:\n(?:.*\n){0,15}\s+default: 'true'", action)


def test_composite_action_leaves_image_inputs_empty_so_cli_defaults_apply():
    # An action default of 'v8' would shadow the CLI default AND the CHARGATE_* env
    # fallbacks; these inputs must ship empty and be appended only when set.
    action = (Path(__file__).parent.parent / "action.yml").read_text(encoding="utf-8")
    for name in ("megalinter_tag", "megalinter_registry", "megalinter_image"):
        assert re.search(rf"  {name}:\n(?:.*\n){{0,10}}\s+default: ''", action), name
    assert '[ -n "$ML_TAG_IN" ] && args+=(--megalinter-tag "$ML_TAG_IN")' in action


# ── Environment assembly ──


def test_build_env_disables_errors_and_enables_reporters():
    env = ml.build_env(ml.MegaLinterConfig(enable_linters=("REPOSITORY_TRIVY",)))
    assert env["DISABLE_ERRORS"] == "true"  # chargate owns the gate
    assert env["SARIF_REPORTER"] == "true"
    assert env["JSON_REPORTER"] == "true"
    assert env["SARIF_REPORTER_NORMALIZE_LINTERS_OUTPUT"] == "true"
    assert env["ENABLE_LINTERS"] == "REPOSITORY_TRIVY"


def test_report_output_folder_is_absolute_inside_the_container():
    # A relative value resolves to /megalinter-reports (WORKDIR /), outside the bind
    # mount, and is destroyed by `docker run --rm` — the empty-gate bug.
    env = ml.build_env(ml.MegaLinterConfig())
    assert env["REPORT_OUTPUT_FOLDER"] == "/tmp/lint/megalinter-reports"  # nosec B108
    assert env["REPORT_OUTPUT_FOLDER"].startswith(ml.CONTAINER_WORKSPACE + "/")


def test_report_output_folder_follows_a_custom_report_dir():
    env = ml.build_env(ml.MegaLinterConfig(report_dir="reports/ml"))
    assert env["REPORT_OUTPUT_FOLDER"] == "/tmp/lint/reports/ml"  # nosec B108


def test_build_env_sets_runtime_uid_so_reports_are_not_root_owned():
    env = ml.build_env(ml.MegaLinterConfig())
    assert env["MEGALINTER_UID"].isdigit()
    assert env["MEGALINTER_GID"].isdigit()


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


def test_single_linter_env_names_only_that_linter():
    # A non-empty ENABLE_LINTERS deactivates every linter it omits, so a per-linter
    # container told about the global list would exit 0 having linted nothing.
    env = ml.build_env(
        ml.MegaLinterConfig(enable_linters=("PYTHON_RUFF", "REPOSITORY_TRIVY")),
        single_linter="REPOSITORY_TRIVY",
    )
    assert env["ENABLE_LINTERS"] == "REPOSITORY_TRIVY"
    assert env["SINGLE_LINTER"] == "REPOSITORY_TRIVY"
    assert env["REPORT_OUTPUT_FOLDER"] == "/tmp/lint/megalinter-reports/standalone/repository_trivy"  # nosec B108


# ── docker run assembly ──


def test_build_docker_command_mounts_workspace_and_passes_env(tmp_path: Path):
    config = ml.MegaLinterConfig(workspace=str(tmp_path))
    cmd = ml.build_docker_command(config, {"FOO": "bar"})
    assert cmd[:3] == ["docker", "run", "--rm"]
    assert "-e" in cmd and "FOO=bar" in cmd
    assert cmd[-1] == "ghcr.io/oxsecurity/megalinter:v10.0.0"
    # workspace mounted to the MegaLinter default workspace path
    mount = f"{tmp_path.resolve()}:{ml.CONTAINER_WORKSPACE}"
    assert mount in cmd


def test_build_docker_command_passes_platform_when_set(tmp_path: Path):
    config = ml.MegaLinterConfig(workspace=str(tmp_path), platform="linux/amd64")
    cmd = ml.build_docker_command(config, {})
    assert cmd[:5] == ["docker", "run", "--rm", "--platform", "linux/amd64"]


def test_build_docker_command_accepts_an_explicit_image(tmp_path: Path):
    config = ml.MegaLinterConfig(workspace=str(tmp_path))
    cmd = ml.build_docker_command(config, {}, "ghcr.io/oxsecurity/megalinter-only-python_ruff:v10")
    assert cmd[-1] == "ghcr.io/oxsecurity/megalinter-only-python_ruff:v10"


# ── Architecture detection ──


def test_docker_arch_prefers_the_daemon_over_the_host():
    # DOCKER_HOST / docker-out-of-docker: the daemon's arch is the one that decides
    # whether an image can execute, and it need not match this machine's.
    def fake(cmd: list[str]) -> subprocess.CompletedProcess:
        assert cmd == ["docker", "version", "--format", "{{.Server.Arch}}"]
        return subprocess.CompletedProcess(cmd, returncode=0, stdout="aarch64\n")

    assert ml.docker_arch(fake) == "arm64"


@pytest.mark.parametrize(
    "fake",
    [
        pytest.param(_raise_oserror, id="docker-absent"),
        pytest.param(_docker_version_fails, id="docker-errors"),
    ],
)
def test_docker_arch_falls_back_to_the_host_when_docker_cannot_answer(fake, monkeypatch):
    # No daemon to ask (missing binary, or `docker version` failing) must never raise —
    # it degrades to this machine's architecture, normalized to Docker's vocabulary.
    monkeypatch.setattr(ml.platform, "machine", lambda: "x86_64")
    assert ml.docker_arch(fake) == "amd64"


# ── Run planning: the arm64 guard ──


def test_plan_uses_the_flavor_image_on_amd64():
    plan = ml.resolve_plan(ml.MegaLinterConfig(flavor="security"), "amd64")
    assert plan.strategy == "flavor"
    assert len(plan.steps) == 1
    assert plan.steps[0].image == "ghcr.io/oxsecurity/megalinter-security:v10.0.0"


def test_plan_substitutes_standalone_images_on_arm64():
    plan = ml.resolve_plan(ml.MegaLinterConfig(flavor="security"), "arm64")
    assert plan.strategy == "standalone"
    assert len(plan.steps) == 18  # the SARIF-emitting linters of the v10 security flavor
    images = {step.image for step in plan.steps}
    assert "ghcr.io/oxsecurity/megalinter-only-repository_trivy:v10.0.0" in images
    assert all("megalinter-only-" in image for image in images)


def test_plan_arm64_error_names_the_arch_and_the_way_out():
    config = ml.MegaLinterConfig(flavor="security", strategy="flavor")
    with pytest.raises(ml.MegaLinterError) as excinfo:
        ml.resolve_plan(config, "arm64")
    message = str(excinfo.value)
    assert "arm64" in message
    assert "linux/amd64 ONLY" in message
    assert "megalinter-security:v10.0.0" in message
    assert "arch_strategy: standalone" in message
    assert "megalinter_image:" in message
    assert "docker_platform" in message


def test_plan_fail_strategy_refuses_to_degrade_on_arm64():
    with pytest.raises(ml.MegaLinterError):
        ml.resolve_plan(ml.MegaLinterConfig(strategy="fail"), "arm64")


def test_plan_fail_strategy_still_runs_the_flavor_image_on_amd64():
    plan = ml.resolve_plan(ml.MegaLinterConfig(strategy="fail"), "amd64")
    assert plan.strategy == "flavor"


def test_plan_explicit_platform_hands_the_wheel_to_the_operator():
    # qemu/binfmt is installed: run the amd64 flavor image under emulation as asked.
    plan = ml.resolve_plan(ml.MegaLinterConfig(platform="linux/amd64"), "arm64")
    assert plan.strategy == "flavor"


def test_plan_custom_image_is_trusted_on_arm64():
    plan = ml.resolve_plan(
        ml.MegaLinterConfig(image_ref="ghcr.io/acme/megalinter-custom-flavor:1"), "arm64"
    )
    assert plan.strategy == "flavor"
    assert plan.steps[0].image == "ghcr.io/acme/megalinter-custom-flavor:1"


def test_plan_rejects_an_unknown_strategy():
    with pytest.raises(ml.MegaLinterError, match="Unknown arch strategy"):
        ml.resolve_plan(ml.MegaLinterConfig(strategy="whatever"), "amd64")


def test_plan_refuses_to_substitute_the_all_flavor():
    # 100+ container starts is not something to do behind an operator's back.
    with pytest.raises(ml.MegaLinterError, match="No standalone linter set"):
        ml.resolve_plan(ml.MegaLinterConfig(flavor="all", strategy="standalone"), "arm64")


def test_plan_standalone_arm64_rejects_a_pre_v10_tag():
    # The arm64 capability table was verified at DEFAULT_TAG only; proceeding with an
    # older tag would reproduce the exec format error this PR exists to prevent.
    config = ml.MegaLinterConfig(flavor="security", image_tag="v9.6.0")
    with pytest.raises(ml.MegaLinterError) as excinfo:
        ml.resolve_plan(config, "arm64")
    assert "v9.6.0" in str(excinfo.value)
    assert ml.DEFAULT_TAG in str(excinfo.value)


def test_plan_standalone_arm64_accepts_a_digest_pin():
    # sha256: pins are treated as operator-verified — they uniquely identify a manifest.
    digest = "sha256:" + "a" * 64
    config = ml.MegaLinterConfig(flavor="security", image_tag=digest)
    plan = ml.resolve_plan(config, "arm64")
    assert plan.strategy == "standalone"


def test_plan_standalone_arm64_accepts_image_ref_override():
    # image_ref means the operator chose the image; chargate stops second-guessing it.
    config = ml.MegaLinterConfig(image_ref="ghcr.io/acme/custom-megalinter:v9.6.0")
    plan = ml.resolve_plan(config, "arm64")
    assert plan.strategy == "flavor"


def test_plan_skips_amd64_only_linters_on_arm64_with_a_reason():
    config = ml.MegaLinterConfig(
        strategy="standalone", standalone_linters=("PYTHON_RUFF", "COPYPASTE_JSCPD")
    )
    plan = ml.resolve_plan(config, "arm64")
    assert [step.linter for step in plan.steps] == ["PYTHON_RUFF"]
    assert plan.skipped == (
        ("COPYPASTE_JSCPD", "upstream image is linux/amd64 only (arm64 runner)"),
    )


def test_plan_skips_non_sarif_and_disabled_linters():
    config = ml.MegaLinterConfig(
        strategy="standalone",
        standalone_linters=("PYTHON_RUFF", "YAML_YAMLLINT", "PYTHON_BANDIT", "NOPE_NOPE"),
        disable_linters=("PYTHON_BANDIT",),
    )
    plan = ml.resolve_plan(config, "arm64")
    assert [step.linter for step in plan.steps] == ["PYTHON_RUFF"]
    reasons = dict(plan.skipped)
    assert "no SARIF" in reasons["YAML_YAMLLINT"]
    assert reasons["PYTHON_BANDIT"] == "disabled via disable_linters"
    assert "no megalinter-only image known" in reasons["NOPE_NOPE"]


def test_plan_errors_when_every_requested_linter_is_skipped():
    config = ml.MegaLinterConfig(strategy="standalone", standalone_linters=("COPYPASTE_JSCPD",))
    with pytest.raises(ml.MegaLinterError, match="zero runnable linters"):
        ml.resolve_plan(config, "arm64")


def test_plan_falls_back_to_enable_linters_when_no_standalone_set_given():
    config = ml.MegaLinterConfig(strategy="standalone", enable_linters=("PYTHON_BANDIT",))
    plan = ml.resolve_plan(config, "arm64")
    assert [step.linter for step in plan.steps] == ["PYTHON_BANDIT"]


# ── SARIF location + merge ──


def test_locate_sarif_prefers_configured_name(tmp_path: Path):
    reports = tmp_path / "megalinter-reports"
    reports.mkdir()
    (reports / "megalinter-report.sarif").write_text("{}", encoding="utf-8")
    config = ml.MegaLinterConfig(workspace=str(tmp_path))
    assert ml.locate_sarif(config) == config.sarif_path()


def test_locate_sarif_accepts_the_alternate_documented_name(tmp_path: Path):
    reports = tmp_path / "megalinter-reports"
    reports.mkdir()
    (reports / "mega-linter-report.sarif").write_text("{}", encoding="utf-8")
    config = ml.MegaLinterConfig(workspace=str(tmp_path))
    assert ml.locate_sarif(config).name == "mega-linter-report.sarif"


def test_locate_sarif_ignores_foreign_sarif_files(tmp_path: Path):
    # The old blind *.sarif glob matched KICS' stray kics-results.sarif and gated on
    # an empty report for months. A per-linter leftover must NOT be mistaken for the
    # merged report.
    reports = tmp_path / "megalinter-reports"
    reports.mkdir()
    (reports / "kics-results.sarif").write_text("{}", encoding="utf-8")
    config = ml.MegaLinterConfig(workspace=str(tmp_path))
    with pytest.raises(ml.MegaLinterError):
        ml.locate_sarif(config)


def test_locate_sarif_missing_raises(tmp_path: Path):
    config = ml.MegaLinterConfig(workspace=str(tmp_path))
    with pytest.raises(ml.MegaLinterError):
        ml.locate_sarif(config)


def test_merge_sarif_concatenates_runs(tmp_path: Path):
    first = tmp_path / "a.sarif"
    second = tmp_path / "b.sarif"
    first.write_text(json.dumps({"runs": [{"tool": {"driver": {"name": "trivy"}}}]}), "utf-8")
    second.write_text(json.dumps({"runs": [{"tool": {"driver": {"name": "bandit"}}}]}), "utf-8")
    destination = tmp_path / "out" / "merged.sarif"

    assert ml.merge_sarif([first, second], destination) == 2
    merged = json.loads(destination.read_text(encoding="utf-8"))
    assert merged["version"] == "2.1.0"
    assert merged["properties"]["comment"].startswith("Merged by chargate")
    assert [run["tool"]["driver"]["name"] for run in merged["runs"]] == ["trivy", "bandit"]


def test_merge_sarif_skips_missing_and_broken_reports(tmp_path: Path):
    # One linter crashing must not discard the other seventeen.
    good = tmp_path / "good.sarif"
    broken = tmp_path / "broken.sarif"
    good.write_text(json.dumps({"runs": [{"tool": {"driver": {"name": "trivy"}}}]}), "utf-8")
    broken.write_text("not json", encoding="utf-8")
    destination = tmp_path / "merged.sarif"

    assert ml.merge_sarif([good, broken, tmp_path / "absent.sarif"], destination) == 1


# ── Orchestration ──


def test_run_uses_injected_runner(tmp_path: Path):
    config = ml.MegaLinterConfig(workspace=str(tmp_path))
    captured: dict[str, list[str]] = {}

    def fake_runner(cmd: list[str]) -> subprocess.CompletedProcess:
        captured["cmd"] = cmd
        return _completed(cmd)

    run = ml.run(config, runner=fake_runner, arch="amd64")
    assert run.returncode == 0
    assert run.strategy == "flavor"
    assert captured["cmd"][0] == "docker"
    assert run.sarif_path == config.sarif_path()


def test_run_standalone_merges_every_linter_report(tmp_path: Path):
    config = ml.MegaLinterConfig(
        workspace=str(tmp_path),
        strategy="standalone",
        standalone_linters=("PYTHON_BANDIT", "REPOSITORY_TRIVY"),
        jobs=2,
    )
    started: list[str] = []

    def fake_runner(cmd: list[str]) -> subprocess.CompletedProcess:
        # Stand in for the container: write the merged SARIF the real image would.
        started.append(cmd[-1])
        folder = next(v.split("=", 1)[1] for v in cmd if v.startswith("REPORT_OUTPUT_FOLDER="))
        key = folder.rsplit("/", 1)[-1]
        host = tmp_path / "megalinter-reports" / "standalone" / key
        host.mkdir(parents=True, exist_ok=True)
        (host / "megalinter-report.sarif").write_text(
            json.dumps({"runs": [{"tool": {"driver": {"name": key}}}]}), encoding="utf-8"
        )
        return _completed(cmd)

    run = ml.run(config, runner=fake_runner, arch="arm64")

    assert run.strategy == "standalone"
    assert run.arch == "arm64"
    assert run.linters_run == ("PYTHON_BANDIT", "REPOSITORY_TRIVY")
    assert sorted(started) == [
        "ghcr.io/oxsecurity/megalinter-only-python_bandit:v10.0.0",
        "ghcr.io/oxsecurity/megalinter-only-repository_trivy:v10.0.0",
    ]
    merged = json.loads(run.sarif_path.read_text(encoding="utf-8"))
    assert sorted(r["tool"]["driver"]["name"] for r in merged["runs"]) == [
        "python_bandit",
        "repository_trivy",
    ]


def test_run_standalone_returns_the_worst_container_exit_code(tmp_path: Path):
    config = ml.MegaLinterConfig(
        workspace=str(tmp_path),
        strategy="standalone",
        standalone_linters=("PYTHON_BANDIT", "REPOSITORY_TRIVY"),
    )

    def fake_runner(cmd: list[str]) -> subprocess.CompletedProcess:
        return _completed(cmd, returncode=2 if "trivy" in cmd[-1] else 0)

    assert ml.run(config, runner=fake_runner, arch="arm64").returncode == 2


def test_run_raises_the_arch_guard_before_touching_docker(tmp_path: Path):
    config = ml.MegaLinterConfig(workspace=str(tmp_path), strategy="flavor")

    def fake_runner(cmd: list[str]) -> subprocess.CompletedProcess:  # pragma: no cover
        raise AssertionError("docker must not be invoked when the image cannot execute")

    with pytest.raises(ml.MegaLinterError):
        ml.run(config, runner=fake_runner, arch="arm64")
