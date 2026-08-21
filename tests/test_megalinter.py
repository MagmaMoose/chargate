"""Unit tests for the MegaLinter wrapper (chargate.megalinter)."""

from __future__ import annotations

import json
import os
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


def test_composite_action_exposes_jobs_so_standalone_concurrency_is_reachable():
    """`jobs` must be an action input, not CLI-only.

    Standalone mode is what arm64 uses, and it runs `jobs` per-linter containers at once
    (CLI default 4). Without an action input there is no way for a consumer on a small
    self-hosted runner to lower it — 4 concurrent MegaLinter containers on a 2-OCPU node
    is a scheduling fight, not a scan. Empty default so the CLI default still wins.
    """
    action = (Path(__file__).parent.parent / "action.yml").read_text(encoding="utf-8")
    assert re.search(r"^  jobs:\n(?:.*\n){0,12}?\s+default: ''", action, re.MULTILINE)
    assert "JOBS_IN: ${{ inputs.jobs }}" in action
    assert '[ -n "$JOBS_IN" ] && args+=(--jobs "$JOBS_IN")' in action


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


@pytest.mark.skipif(not hasattr(os, "getuid"), reason="POSIX-only uid drop")
def test_build_env_sets_runtime_uid_so_reports_are_not_root_owned():
    env = ml.build_env(ml.MegaLinterConfig())
    assert env["MEGALINTER_UID"].isdigit()
    assert env["MEGALINTER_GID"].isdigit()


@pytest.mark.skipif(not hasattr(os, "getuid"), reason="POSIX-only uid drop")
def test_runtime_uid_can_be_overridden_from_the_environment(monkeypatch):
    # The escape hatch for a containerised runner whose workspace is owned by a
    # different user than the job: dropping to the job's uid there leaves MegaLinter
    # unable to write its own report tree, which presents as a scan that found nothing.
    monkeypatch.setenv("MEGALINTER_UID", "0")
    monkeypatch.setenv("MEGALINTER_GID", "0")
    env = ml.build_env(ml.MegaLinterConfig())
    assert env["MEGALINTER_UID"] == "0"
    assert env["MEGALINTER_GID"] == "0"


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
    # argv[0] is `docker` or its resolved absolute path, depending on the host.
    assert Path(cmd[0]).stem == "docker"
    assert cmd[1:3] == ["run", "--rm"]
    assert "-e" in cmd and "FOO=bar" in cmd
    assert cmd[-1] == "ghcr.io/oxsecurity/megalinter:v10.0.0"
    # workspace mounted to the MegaLinter default workspace path
    mount = f"{tmp_path.resolve()}:{ml.CONTAINER_WORKSPACE}"
    assert mount in cmd


def test_build_docker_command_passes_platform_when_set(tmp_path: Path):
    config = ml.MegaLinterConfig(workspace=str(tmp_path), platform="linux/amd64")
    cmd = ml.build_docker_command(config, {})
    # argv[0] is docker's resolved absolute path where PATH has it and the bare name
    # otherwise, so assert on the basename — a literal "docker" here passes only on a
    # host without docker installed, which is how this slipped through locally.
    assert Path(cmd[0]).stem == "docker"
    assert cmd[1:5] == ["run", "--rm", "--platform", "linux/amd64"]


def test_build_docker_command_accepts_an_explicit_image(tmp_path: Path):
    config = ml.MegaLinterConfig(workspace=str(tmp_path))
    cmd = ml.build_docker_command(config, {}, "ghcr.io/oxsecurity/megalinter-only-python_ruff:v10")
    assert cmd[-1] == "ghcr.io/oxsecurity/megalinter-only-python_ruff:v10"


def test_build_docker_command_adds_user_flag_when_uid_gid_in_env(tmp_path: Path):
    # Generated files (reports, caches) must be owned by the runner user, not root.
    config = ml.MegaLinterConfig(workspace=str(tmp_path))
    env = {"MEGALINTER_UID": "1001", "MEGALINTER_GID": "1002"}
    cmd = ml.build_docker_command(config, env)
    assert "--user" in cmd
    assert cmd[cmd.index("--user") + 1] == "1001:1002"


def test_build_docker_command_no_user_flag_when_uid_gid_absent(tmp_path: Path):
    # Windows (no os.getuid): build_env omits MEGALINTER_UID/GID; no --user must appear.
    config = ml.MegaLinterConfig(workspace=str(tmp_path))
    cmd = ml.build_docker_command(config, {"FOO": "bar"})
    assert "--user" not in cmd


def test_build_docker_command_user_flag_with_explicit_root_escape_hatch(tmp_path: Path):
    # MEGALINTER_UID=0 is the ARC/docker-in-docker escape hatch; --user 0:0 propagates it.
    config = ml.MegaLinterConfig(workspace=str(tmp_path))
    env = {"MEGALINTER_UID": "0", "MEGALINTER_GID": "0"}
    cmd = ml.build_docker_command(config, env)
    assert "--user" in cmd
    assert cmd[cmd.index("--user") + 1] == "0:0"


def test_build_docker_command_user_flag_does_not_affect_mounts_or_image(tmp_path: Path):
    # Adding --user must not displace the volume mount or the image reference.
    config = ml.MegaLinterConfig(workspace=str(tmp_path))
    env = {"MEGALINTER_UID": "1001", "MEGALINTER_GID": "1001"}
    cmd = ml.build_docker_command(config, env)
    assert cmd[-1] == config.image()
    mount = f"{tmp_path.resolve()}:{ml.CONTAINER_WORKSPACE}"
    assert mount in cmd


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
    assert Path(captured["cmd"][0]).stem == "docker"
    assert run.sarif_path == config.sarif_path()


def test_build_env_excludes_chargate_own_workspace_artifacts():
    """Chargate's generated files must not be scanned as source by FILE-scope linters.

    They are not in git, so a finding in one is `file-not-changed` forever: the gate can
    neither surface it as net-new nor clear it, but it sits open in the Security tab.

    Note the scope. FILTER_REGEX_EXCLUDE filters the file list MegaLinter hands a linter,
    so it does nothing for project-scope REPOSITORY_* linters that walk the tree
    themselves. It is NOT what fixed the 13 devskim alerts on the generated BOM — moving
    the BOM out of the workspace was (see
    test_composite_action_writes_the_sbom_outside_the_scanned_workspace).
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
    for path in ("src/chargate/cli.py", "action.yml"):
        assert not re.search(pattern, path)


def test_build_env_exclude_ors_consumer_pattern_rather_than_replacing_it():
    env = ml.build_env(ml.MegaLinterConfig(extra_env={"FILTER_REGEX_EXCLUDE": "(vendor/)"}))
    pattern = env["FILTER_REGEX_EXCLUDE"]
    assert re.search(pattern, "vendor/thing.py")  # consumer's pattern honoured
    assert re.search(pattern, ml.SBOM_FILE_NAME)  # chargate's still applied


@pytest.mark.skipif(not hasattr(os, "getuid"), reason="POSIX-only uid drop")
def test_build_env_gives_the_dropped_uid_a_writable_home():
    """The uid MegaLinter drops to must have a writable HOME, outside the workspace.

    Without it `~` resolves to `/`, which a non-root uid cannot write, and grype, trivy
    and semgrep all die on their caches — reported as non-blocking TOOL ERRORS, so they
    contribute zero findings while the run stays green. Alerts those tools raised earlier
    can then never be closed either, because GitHub only retires an alert when the same
    tool reports again without it.
    """
    env = ml.build_env(ml.MegaLinterConfig())
    assert env["HOME"] == ml.CONTAINER_HOME
    # Writable (under /tmp) but NOT inside the mounted workspace, so caches are neither
    # scanned as source nor left behind in the checkout.
    assert env["HOME"].startswith("/tmp/")  # nosec B108 - asserting a container path
    assert not env["HOME"].startswith(ml.CONTAINER_WORKSPACE + "/")
    assert env["HOME"] != ml.CONTAINER_WORKSPACE
    for key in ("XDG_CACHE_HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME"):
        assert env[key].startswith(ml.CONTAINER_HOME + "/"), key


@pytest.mark.skipif(not hasattr(os, "getuid"), reason="POSIX-only uid drop")
def test_home_can_be_overridden_from_extra_env():
    env = ml.build_env(ml.MegaLinterConfig(extra_env={"HOME": "/tmp/mine"}))  # nosec B108
    assert env["HOME"] == "/tmp/mine"  # nosec B108 - container path in a test


def test_composite_action_writes_the_sbom_outside_the_scanned_workspace():
    """The generated BOM must not live in the tree MegaLinter mounts.

    devskim is a PROJECT-scope linter: it walks the workspace itself, so no MegaLinter
    file filter can keep it off a generated file inside the checkout. A BOM under
    GITHUB_WORKSPACE produced 13 unclosable alerts (DS173237 x12 on CycloneDX `purl`
    strings, DS137138 x1). The gate step's BOM path must agree, or the
    Dependency-Track upload silently stops happening.
    """
    action = (Path(__file__).parent.parent / "action.yml").read_text(encoding="utf-8")
    assert f"output-file: ${{{{ runner.temp }}}}/{ml.SBOM_FILE_NAME}" in action
    assert f"${{{{ github.workspace }}}}/{ml.SBOM_FILE_NAME}" not in action
    assert f'bom_abs="${{RUNNER_TEMP:-${{GITHUB_WORKSPACE:-$PWD}}}}/{ml.SBOM_FILE_NAME}"' in action


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


def test_bandit_excludes_test_directories_by_default():
    """B101 (assert_used) must not make every test-bearing PR unmergeable.

    A pytest test is nothing but asserts, so with bandit scanning `tests/` the net-new
    gate blocks once per NEW assertion. Observed on MagmaMoose/caldrith: one PR adding two
    test files produced 58 blocking findings, 57 of them test assertions.

    Scoped to bandit — every other linter still reads the tests — and bandit still scans
    shipped code, where `python -O` really does strip an `assert`.
    """
    pattern = ml.build_env(ml.MegaLinterConfig())["PYTHON_BANDIT_FILTER_REGEX_EXCLUDE"]
    for path in ("tests/test_files.py", "src/pkg/tests/test_x.py", "test/test_y.py"):
        assert re.search(pattern, path), f"{path} should be excluded by {pattern}"
    # Shipped code is still scanned, and a directory that merely CONTAINS "test" is not
    # caught — the pattern is anchored to a path boundary.
    for path in ("src/chargate/cli.py", "src/contests/views.py", "latest/thing.py"):
        assert not re.search(pattern, path), f"{path} must still be scanned"

    # The global file filter is a separate knob: excluding tests from bandit must not
    # quietly exclude them from every other linter too.
    assert not re.search(
        ml.build_env(ml.MegaLinterConfig())["FILTER_REGEX_EXCLUDE"], "tests/test_files.py"
    )


def test_bandit_exclude_ors_consumer_pattern_rather_than_replacing_it():
    env = ml.build_env(
        ml.MegaLinterConfig(extra_env={"PYTHON_BANDIT_FILTER_REGEX_EXCLUDE": "(vendor/)"})
    )
    pattern = env["PYTHON_BANDIT_FILTER_REGEX_EXCLUDE"]
    assert re.search(pattern, "vendor/thing.py")  # consumer's pattern honoured
    assert re.search(pattern, "tests/test_x.py")  # chargate's default still applied
