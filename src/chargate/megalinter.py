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

import re
import shutil
import subprocess  # nosec B404 - chargate's job is to shell out to the MegaLinter container
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_IMAGE = "oxsecurity/megalinter"
DEFAULT_TAG = "v8"  # pin to a digest in production; see docs.
# MegaLinter's own DEFAULT_WORKSPACE mount point *inside the container* — a fixed
# path defined by the image, not a temp file this process creates, so the usual
# predictable-temp-path race does not apply.
CONTAINER_WORKSPACE = "/tmp/lint"  # nosec B108 - container-internal mount point

# The CycloneDX BOM chargate writes into the workspace for the Dependency-Track
# sink. Kept here as the single source of truth; `action.yml` ("Generate CycloneDX
# SBOM") must emit this exact name so `_artifact_exclude_regex` can exclude it.
SBOM_FILE_NAME = "chargate-sbom.cdx.json"

# Directory `action.yml` writes the emitted full SARIF into (under the workspace,
# so `hashFiles()` can guard the upload steps).
SARIF_OUT_DIR = "chargate-reports"


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


def _artifact_exclude_regex(config: MegaLinterConfig) -> str:
    """A ``FILTER_REGEX_EXCLUDE`` pattern covering chargate's own workspace output.

    Chargate writes three things into the workspace that MegaLinter would otherwise
    scan as if they were source: the Syft BOM (generated *before* the gate step so
    the Dependency-Track sink can upload it), the emitted full SARIF, and
    MegaLinter's own report folder.

    Scanning them is pure noise that the gate can never act on. A finding inside a
    generated BOM — devskim reading CycloneDX ``purl`` / ``externalReferences``
    strings as hardcoded tokens (DS173237) or insecure URLs (DS137138) — is
    permanently unresolvable: the file is not in git, so
    :mod:`chargate.sarif.filter` classifies it ``file-not-changed`` on every run
    and chargate can neither surface it as net-new nor clear it, while the
    Security tab holds the alert open forever.
    """
    names = (
        re.escape(SBOM_FILE_NAME),
        re.escape(SARIF_OUT_DIR) + "/",
        re.escape(config.report_dir) + "/",
    )
    return r"(^|/)(" + "|".join(names) + ")"


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
    # Chargate's own workspace artifacts are never scannable source. Applied last
    # and OR'd with (not overridden by) any consumer pattern, so a repo tuning
    # FILTER_REGEX_EXCLUDE can't accidentally re-admit chargate's generated files.
    artifacts = _artifact_exclude_regex(config)
    consumer = env.get("FILTER_REGEX_EXCLUDE", "").strip()
    env["FILTER_REGEX_EXCLUDE"] = f"({consumer})|({artifacts})" if consumer else artifacts
    return env


def build_docker_command(config: MegaLinterConfig, env: dict[str, str]) -> list[str]:
    """A ``docker run`` invocation of the MegaLinter image with ``env`` applied.

    ``argv[0]`` is the absolute ``docker`` path when it is resolvable on PATH, so
    the exec does not re-resolve a bare name (Bandit B607). When docker is absent
    the bare name is kept, letting the caller surface the usual "docker not found".
    """
    workspace = str(Path(config.workspace).resolve())
    cmd = [shutil.which("docker") or "docker", "run", "--rm"]
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
    # Fixed argv list assembled by build_docker_command (no shell, no user string
    # concatenation); `docker` is resolved through PATH by build_docker_command.
    run_fn = runner or (
        lambda cmd: subprocess.run(cmd, check=False)  # nosec B603 - list argv, shell=False
    )
    completed = run_fn(command)
    return MegaLinterRun(
        returncode=completed.returncode,
        command=tuple(command),
        sarif_path=config.sarif_path(),
    )
