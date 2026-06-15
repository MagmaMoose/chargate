"""Invoke MegaLinter and locate its merged SARIF report.

Chargate runs MegaLinter whole-repo with ``DISABLE_ERRORS=true`` so MegaLinter
never sets the gate exit code — chargate owns the gate via the net-new filter.
The SARIF + JSON reporters are enabled and URIs normalized to repo-relative paths
(``SARIF_REPORTER_NORMALIZE_LINTERS_OUTPUT=true``) so the filter can match them
against ``git diff`` paths.

The Docker command / env assembly and report location are pure and unit-tested.
The actual ``docker run`` is injected (``runner=``) so the orchestration is
testable without Docker.

NOTE — verify against a real run: MegaLinter's exact merged-SARIF filename has
been documented as both ``megalinter-report.sarif`` and ``mega-linter-report.sarif``
across versions. :func:`locate_sarif` therefore prefers the configured name but
falls back to any ``*.sarif`` in the report folder. Confirm the path and field
shapes against a real MegaLinter run before relying on them in production.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_IMAGE = "oxsecurity/megalinter"
DEFAULT_TAG = "v8"  # pin to a digest in production; see docs.
CONTAINER_WORKSPACE = "/tmp/lint"  # MegaLinter's DEFAULT_WORKSPACE mount point.


class MegaLinterError(RuntimeError):
    """MegaLinter could not be run or produced no report."""


@dataclass(frozen=True)
class MegaLinterConfig:
    # Flavor "all"/"" → oxsecurity/megalinter (full, the chosen default);
    # otherwise oxsecurity/megalinter-<flavor> (e.g. "security", "python").
    flavor: str = "all"
    image_tag: str = DEFAULT_TAG
    workspace: str = "."
    report_dir: str = "megalinter-reports"
    sarif_file_name: str = "megalinter-report.sarif"
    enable_linters: tuple[str, ...] = ()
    disable_linters: tuple[str, ...] = ()
    validate_all_codebase: bool = True
    extra_env: dict[str, str] = field(default_factory=dict)

    def image(self) -> str:
        flavor = self.flavor.strip().lower()
        base = DEFAULT_IMAGE if flavor in ("", "all") else f"{DEFAULT_IMAGE}-{flavor}"
        return f"{base}:{self.image_tag}"

    def sarif_path(self) -> Path:
        return Path(self.workspace) / self.report_dir / self.sarif_file_name

    def report_path(self) -> Path:
        return Path(self.workspace) / self.report_dir


@dataclass(frozen=True)
class MegaLinterRun:
    returncode: int
    command: tuple[str, ...]
    sarif_path: Path


def build_env(config: MegaLinterConfig) -> dict[str, str]:
    """The MegaLinter env that makes it report-everything but gate-nothing."""
    env: dict[str, str] = {
        # chargate owns the gate; MegaLinter must always exit 0 on findings.
        "DISABLE_ERRORS": "true",
        "SARIF_REPORTER": "true",
        "JSON_REPORTER": "true",
        # Repo-relative SARIF URIs so the net-new filter can match diff paths.
        "SARIF_REPORTER_NORMALIZE_LINTERS_OUTPUT": "true",
        "REPORT_OUTPUT_FOLDER": config.report_dir,
        "SARIF_REPORTER_FILE_NAME": config.sarif_file_name,
        "APPLY_FIXES": "none",
        "FLAVOR_SUGGESTIONS": "false",
        "VALIDATE_ALL_CODEBASE": "true" if config.validate_all_codebase else "false",
        "GITHUB_STATUS_REPORTER": "false",
    }
    if config.enable_linters:
        env["ENABLE_LINTERS"] = ",".join(config.enable_linters)
    if config.disable_linters:
        env["DISABLE_LINTERS"] = ",".join(config.disable_linters)
    env.update(config.extra_env)
    return env


def build_docker_command(config: MegaLinterConfig, env: dict[str, str]) -> list[str]:
    """A ``docker run`` invocation of the MegaLinter image with ``env`` applied."""
    workspace = str(Path(config.workspace).resolve())
    cmd = ["docker", "run", "--rm"]
    for key, value in env.items():
        cmd += ["-e", f"{key}={value}"]
    cmd += ["-v", f"{workspace}:{CONTAINER_WORKSPACE}", config.image()]
    return cmd


def locate_sarif(config: MegaLinterConfig) -> Path:
    """Return the merged SARIF path, tolerating the documented filename ambiguity."""
    preferred = config.sarif_path()
    if preferred.is_file():
        return preferred
    report_dir = config.report_path()
    if report_dir.is_dir():
        candidates = sorted(report_dir.glob("*.sarif"))
        if candidates:
            return candidates[0]
    raise MegaLinterError(
        f"No SARIF report found at {preferred} (nor any *.sarif in {report_dir}). "
        "Ensure SARIF_REPORTER=true and the report folder is correct."
    )


def run(
    config: MegaLinterConfig,
    *,
    runner: Callable[[list[str]], subprocess.CompletedProcess] | None = None,
) -> MegaLinterRun:
    """Run MegaLinter via Docker (or an injected ``runner``) and return its status."""
    env = build_env(config)
    command = build_docker_command(config, env)
    run_fn = runner or (lambda cmd: subprocess.run(cmd, check=False))
    completed = run_fn(command)
    return MegaLinterRun(
        returncode=completed.returncode,
        command=tuple(command),
        sarif_path=config.sarif_path(),
    )
