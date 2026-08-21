"""Invoke MegaLinter and locate its merged SARIF report.

Chargate runs MegaLinter whole-repo with ``DISABLE_ERRORS=true`` so MegaLinter
never sets the gate exit code — chargate owns the gate via the net-new filter.
The SARIF + JSON reporters are enabled and URIs normalized to repo-relative paths
(``SARIF_REPORTER_NORMALIZE_LINTERS_OUTPUT=true``) so the filter can match them
against ``git diff`` paths.

The Docker command / env assembly, the run plan and the SARIF merge are pure and
unit-tested. The actual ``docker run`` is injected (``runner=``) so the orchestration
is testable without Docker.

Two things here are load-bearing and were each a live defect:

**The report folder must be an absolute container path.** MegaLinter uses
``REPORT_OUTPUT_FOLDER`` verbatim (``MegaLinter.py::initialize_output``) and its images
declare ``WORKDIR /``, so a *relative* value resolves to ``/megalinter-reports``
**inside** the container — outside the bind mount, and destroyed by ``docker run --rm``.
Chargate shipped that for its whole life: the merged SARIF never reached the host, and
:func:`locate_sarif`'s old blind ``*.sarif`` glob picked up the one stray file that did
land in the workspace (KICS' ``kics-results.sarif``, written from ``cwd=/tmp/lint``).
The gate was silently reading a report with zero results.

**Every flavor image is ``linux/amd64`` only.** ``megalinter``, ``megalinter-security``
and friends have a single-architecture manifest at every tag published to date, so on
an arm64 daemon they die with ``exec /bin/bash: exec format error``. The per-linter
``megalinter-only-*`` images *are* multi-arch from v10.0.0, so :func:`resolve_plan`
substitutes them (see :mod:`chargate.linters`) rather than failing — or, when the
operator has pinned something chargate cannot substitute, raises
:data:`ARM64_HELP` naming every way out.
"""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess  # nosec B404 - chargate's job is to shell out to the MegaLinter container
import sys
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from chargate.linters import FLAVOR_STANDALONE_SETS, STANDALONE_LINTERS

# MegaLinter froze Docker Hub publishing at v9.4.0 (2026-02-28); v9.5.0, v9.6.0 and
# v10.x exist ONLY on ghcr.io, which is also what upstream's own constants.py now
# points at (ML_DOCKER_IMAGE_HOST = "ghcr.io"). Chargate's old docker.io default made
# every version above v9.4.0 unreachable on any architecture.
DEFAULT_REGISTRY = "ghcr.io"
DEFAULT_NAMESPACE = "oxsecurity"
DEFAULT_REPO = "megalinter"
STANDALONE_REPO_PREFIX = "megalinter-only-"

# v10.0.0, the immutable release tag — deliberately not the floating `v10` alias.
# Verified against the live registry: ghcr.io/oxsecurity/megalinter:v10.0.0 is
# sha256:bed638e2aaa435859fff8ef5a90c20272c505ef95661cbaac793038ed28b08a0 and
# ghcr.io/oxsecurity/megalinter-security:v10.0.0 (the default flavor) is
# sha256:980e5e9877d1ad9846ee3409e74a3a8905cb2fbe35e79af53d1274210e02eb4f.
# v10 is also the floor for arm64: the megalinter-only-* images are single-arch at
# v9.6.0 and below, so no earlier tag can scan on arm64 at all.
DEFAULT_TAG = "v10.0.0"

CONTAINER_WORKSPACE = "/tmp/lint"  # MegaLinter's DEFAULT_DOCKER_WORKSPACE_DIR.  # nosec B108

# HOME for the non-root uid MegaLinter drops to. Deliberately a SIBLING of
# CONTAINER_WORKSPACE, not a child: tool caches (grype's vuln DB, trivy's, semgrep's
# rule cache) must be writable but must not land in the scanned tree. See build_env.
CONTAINER_HOME = "/tmp/chargate-home"  # nosec B108 - container-internal, /tmp is sticky
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"

# MegaLinter's merged-SARIF filename has been documented as both of these across
# versions; v10.0.0's DEFAULT_SARIF_REPORT_FILE_NAME is the first. Both names are
# accepted, but ONLY these — see locate_sarif for why a glob is not.
MEGALINTER_SARIF_NAMES = ("megalinter-report.sarif", "mega-linter-report.sarif")

ARCH_STRATEGIES = ("auto", "flavor", "standalone", "fail")

# `docker version --format {{.Server.Arch}}` and platform.machine() disagree on
# spelling; normalize both onto Docker's platform vocabulary.
_ARCH_ALIASES = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}

ARM64_HELP = """\
MegaLinter's flavor images are published for linux/amd64 ONLY — upstream ships no arm64
manifest for {image} (true of every flavor at every tag published to date), so this
Docker daemon ({arch}) cannot execute it. Left alone it fails with the opaque
`exec /bin/bash: exec format error`.

Pick one:
  * arch_strategy: standalone — run MegaLinter's per-linter images
    (ghcr.io/oxsecurity/megalinter-only-*), which ARE multi-arch from v10.0.0. This is
    the default on arm64; you have explicitly asked for the flavor image instead.
  * megalinter_image: ghcr.io/<owner>/<repo>/megalinter-custom-flavor:<version> — build
    your own arm64 flavor: https://megalinter.io/latest/custom-flavors/
  * runs-on: an amd64 runner (ubuntu-latest).
  * install qemu-user-static + binfmt on the runner and set docker_platform:
    linux/amd64 — it works, but an emulated MegaLinter run is roughly 5-10x slower."""

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
    # Flavor "all"/"" → <registry>/<namespace>/megalinter (full image); otherwise
    # <registry>/<namespace>/megalinter-<flavor> (e.g. "security", "python").
    flavor: str = "all"
    image_tag: str = DEFAULT_TAG
    workspace: str = "."
    report_dir: str = "megalinter-reports"
    sarif_file_name: str = "megalinter-report.sarif"
    enable_linters: tuple[str, ...] = ()
    disable_linters: tuple[str, ...] = ()
    validate_all_codebase: bool = True
    extra_env: dict[str, str] = field(default_factory=dict)
    registry: str = DEFAULT_REGISTRY
    namespace: str = DEFAULT_NAMESPACE
    # A full image reference wins over registry/namespace/flavor/tag entirely: a custom
    # flavor, an internal mirror, an air-gapped copy. This is the escape hatch that
    # means no operator is ever trapped by a name chargate composes.
    image_ref: str = ""
    platform: str = ""  # `docker run --platform` passthrough (forced emulation).
    strategy: str = "auto"  # one of ARCH_STRATEGIES.
    standalone_linters: tuple[str, ...] = ()
    jobs: int = 4  # standalone mode: concurrent linter containers.

    def _ref(self, repo: str) -> str:
        base = "/".join(
            part for part in (self.registry.strip("/"), self.namespace.strip("/"), repo) if part
        )
        tag = self.image_tag.strip()
        # `image_tag: sha256:...` pins by digest; anything else is an ordinary tag.
        separator = "@" if tag.startswith("sha256:") else ":"
        return f"{base}{separator}{tag}"

    def image(self) -> str:
        """The flavor image reference. An explicit ``image_ref`` wins outright."""
        if self.image_ref:
            return self.image_ref
        flavor = self.flavor.strip().lower()
        repo = DEFAULT_REPO if flavor in ("", "all") else f"{DEFAULT_REPO}-{flavor}"
        return self._ref(repo)

    def standalone_image(self, linter_key: str) -> str:
        """The per-linter image, e.g. ``ghcr.io/oxsecurity/megalinter-only-repository_trivy``.

        ``image_ref`` is deliberately NOT honoured here: it names one specific image,
        and there is no way to derive 18 per-linter references from it.
        """
        return self._ref(f"{STANDALONE_REPO_PREFIX}{linter_key.strip().lower()}")

    def container_report_dir(self, subdir: str = "") -> str:
        """The report folder as MegaLinter sees it — ALWAYS absolute.

        MegaLinter uses ``REPORT_OUTPUT_FOLDER`` verbatim and its images declare
        ``WORKDIR "/"``, so a relative value resolves to ``/megalinter-reports`` inside
        the container: outside the bind mount, and gone the moment ``--rm`` fires.
        Project-mode linters (trivy, bandit, gitleaks, …) additionally run with
        ``cwd=/tmp/lint`` and crash outright writing their per-linter SARIF to a folder
        that only exists at ``/``.
        """
        parts = [CONTAINER_WORKSPACE, self.report_dir]
        if subdir:
            parts.append(subdir)
        return "/".join(parts)

    def report_path(self, subdir: str = "") -> Path:
        """The same folder as :meth:`container_report_dir`, seen from the host."""
        path = Path(self.workspace) / self.report_dir
        return path / subdir if subdir else path

    def sarif_path(self) -> Path:
        return self.report_path() / self.sarif_file_name


@dataclass(frozen=True)
class RunStep:
    """One container to start: the flavor image, or one per-linter image."""

    linter: str  # "" for the flavor image.
    image: str
    env: dict[str, str]
    report_dir: Path  # Host path this step writes its merged SARIF into.


@dataclass(frozen=True)
class RunPlan:
    strategy: str  # "flavor" | "standalone"
    arch: str
    steps: tuple[RunStep, ...]
    skipped: tuple[tuple[str, str], ...] = ()  # (linter key, reason)


@dataclass(frozen=True)
class MegaLinterRun:
    returncode: int
    command: tuple[str, ...]
    sarif_path: Path
    strategy: str = "flavor"
    arch: str = "amd64"
    linters_run: tuple[str, ...] = ()
    linters_skipped: tuple[tuple[str, str], ...] = ()


# Test directories, for bandit only. `tests?` covers both `test/` and `tests/`; anchored to
# a path boundary so a source file named e.g. `contests/` is not caught.
_BANDIT_TEST_EXCLUDE = r"(^|/)tests?/"


def _artifact_exclude_regex(config: MegaLinterConfig) -> str:
    """A ``FILTER_REGEX_EXCLUDE`` pattern covering chargate's own workspace output.

    Chargate's generated files — the emitted full SARIF, MegaLinter's report folder,
    and (only when a caller writes it there, which ``action.yml`` no longer does) the
    Syft BOM — are not scannable source. A finding in one is permanently unresolvable:
    the file is not in git, so :mod:`chargate.sarif.filter` classifies it
    ``file-not-changed`` on every run, and the gate can neither surface it as net-new
    nor clear it while the Security tab holds the alert open.

    **This only covers file-scope linters.** ``FILTER_REGEX_EXCLUDE`` filters the file
    list MegaLinter hands a linter, so it does nothing for PROJECT-scope linters
    (``REPOSITORY_*``: devskim, trivy, checkov, semgrep, grype, betterleaks), which walk
    the tree themselves. Relying on it alone is what left 13 devskim alerts open on the
    generated BOM (DS173237 x12 on CycloneDX ``purl`` strings, DS137138 x1). The only
    thing that reliably keeps a generated file out of a project-scope scan is keeping it
    out of the mounted tree — hence ``action.yml`` writes the BOM to ``RUNNER_TEMP``.
    Treat this regex as defence for the file-scope case (and for a local ``chargate ci``
    run against a dirty working tree), not as the mechanism.
    """
    names = (
        re.escape(SBOM_FILE_NAME),
        re.escape(SARIF_OUT_DIR) + "/",
        re.escape(config.report_dir) + "/",
    )
    return r"(^|/)(" + "|".join(names) + ")"


def build_env(config: MegaLinterConfig, *, single_linter: str = "") -> dict[str, str]:
    """The MegaLinter env that makes it report-everything but gate-nothing.

    ``single_linter`` switches to standalone mode for one ``megalinter-only-*``
    container: that image ships ``MEGALINTER_FLAVOR=none`` and picks its one linter from
    ``SINGLE_LINTER``, and its reports go to their own subfolder so N concurrent
    containers cannot overwrite each other's merged SARIF.
    """
    report_subdir = f"standalone/{single_linter.lower()}" if single_linter else ""
    env: dict[str, str] = {
        # chargate owns the gate; MegaLinter must always exit 0 on findings.
        "DISABLE_ERRORS": "true",
        "SARIF_REPORTER": "true",
        "JSON_REPORTER": "true",
        # Repo-relative SARIF URIs so the net-new filter can match diff paths.
        "SARIF_REPORTER_NORMALIZE_LINTERS_OUTPUT": "true",
        "REPORT_OUTPUT_FOLDER": config.container_report_dir(report_subdir),
        "SARIF_REPORTER_FILE_NAME": config.sarif_file_name,
        "APPLY_FIXES": "none",
        "FLAVOR_SUGGESTIONS": "false",
        "VALIDATE_ALL_CODEBASE": "true" if config.validate_all_codebase else "false",
        "GITHUB_STATUS_REPORTER": "false",
    }
    if single_linter:
        # Linter.manage_activation: a NON-EMPTY ENABLE_LINTERS flips every linter not
        # named in it to inactive. Passing chargate's global list into a per-linter
        # container would therefore make it exit 0 having linted nothing at all — so
        # each container is told about exactly its own linter.
        env["ENABLE_LINTERS"] = single_linter
        env["SINGLE_LINTER"] = single_linter
    else:
        if config.enable_linters:
            env["ENABLE_LINTERS"] = ",".join(config.enable_linters)
        if config.disable_linters:
            env["DISABLE_LINTERS"] = ",".join(config.disable_linters)
    # MegaLinter runs as root and would leave a root-owned report tree in the workspace:
    # harmless on an ephemeral hosted runner, poison on a self-hosted one where the next
    # job's checkout cannot clean it up. entrypoint.sh drops to this uid/gid via
    # /usr/bin/setup-runtime-user.sh, which the flavor AND megalinter-only-* images both
    # ship. Not available on Windows, hence the guard.
    #
    # `env` is built from scratch above, so a bare setdefault() here could never have
    # been overridden by anything — the caller's environment is not its seed. That
    # matters on a containerised (ARC / docker-in-docker) runner where the job user and
    # the workspace owner differ: dropping to the job's uid makes MegaLinter unable to
    # write the report tree it was just told to write, and the failure looks exactly
    # like a scan that produced nothing. So consult the process environment explicitly —
    # `env: {MEGALINTER_UID: '0'}` on the step is the escape hatch, and it needs no new
    # action input.
    if hasattr(os, "getuid"):
        env["MEGALINTER_UID"] = os.environ.get("MEGALINTER_UID") or str(os.getuid())
        env["MEGALINTER_GID"] = os.environ.get("MEGALINTER_GID") or str(os.getgid())
        # ...and the uid we just dropped to has NO HOME. The images set HOME for root
        # only, so after setup-runtime-user.sh switches user, HOME is unset and every
        # tool that caches under it resolves `~` to `/` — which is not writable by a
        # non-root uid. Three scanners die there, and MegaLinter classifies each as a
        # non-blocking tool error rather than a finding, so they report NOTHING and the
        # run still looks green:
        #
        #   grype    unable to create db root dir /.cache/grype/db: mkdir /.cache: permission denied
        #   trivy    failed to download vulnerability DB: mkdir /.cache: permission denied
        #   semgrep  PermissionError: [Errno 13] Permission denied: '/.semgrep'
        #
        # A vulnerability scanner that silently finds zero CVEs is worse than one that
        # fails loudly: alerts it raised previously can never be closed either, because
        # GitHub only retires an alert when that same tool reports again without it.
        #
        # Point HOME at a writable path OUTSIDE the workspace — /tmp is world-writable
        # and sticky in these images, and a sibling of CONTAINER_WORKSPACE (/tmp/lint)
        # so the caches are neither scanned as source nor left in the checkout.
        env.setdefault("HOME", CONTAINER_HOME)
        env.setdefault("XDG_CACHE_HOME", f"{CONTAINER_HOME}/.cache")
        env.setdefault("XDG_CONFIG_HOME", f"{CONTAINER_HOME}/.config")
        env.setdefault("XDG_DATA_HOME", f"{CONTAINER_HOME}/.local/share")
    env.update(config.extra_env)
    # Chargate's own workspace artifacts are never scannable source. Applied last
    # and OR'd with (not overridden by) any consumer pattern, so a repo tuning
    # FILTER_REGEX_EXCLUDE can't accidentally re-admit chargate's generated files.
    artifacts = _artifact_exclude_regex(config)
    consumer = env.get("FILTER_REGEX_EXCLUDE", "").strip()
    env["FILTER_REGEX_EXCLUDE"] = f"({consumer})|({artifacts})" if consumer else artifacts
    # Bandit B101 (assert_used) fires on every `assert`, and a pytest test is nothing but
    # asserts — so on a Python repo the net-new gate blocks once per NEW assertion and any
    # PR that adds tests is unmergeable. Observed on MagmaMoose/caldrith: one PR adding two
    # test files produced 58 blocking findings, 57 of them test assertions.
    #
    # This is a gate-quality default, not a security relaxation: B101 keeps running on
    # shipped code, where `python -O` really does strip a runtime check. It only stops
    # counting assertions in files that never ship.
    #
    # OR'd with any consumer value for the same reason as FILTER_REGEX_EXCLUDE above — a
    # repo may exclude MORE from bandit, but re-admitting `tests/` is not something one
    # repo should be able to do to the org's gate. Repos that genuinely need bandit inside
    # tests should scope the exception per-finding with `# nosec`, which stays visible.
    bandit_consumer = env.get("PYTHON_BANDIT_FILTER_REGEX_EXCLUDE", "").strip()
    env["PYTHON_BANDIT_FILTER_REGEX_EXCLUDE"] = (
        f"({bandit_consumer})|({_BANDIT_TEST_EXCLUDE})" if bandit_consumer else _BANDIT_TEST_EXCLUDE
    )
    return env


def build_docker_command(
    config: MegaLinterConfig, env: dict[str, str], image: str | None = None
) -> list[str]:
    """A ``docker run`` invocation of ``image`` (default: the flavor image) with ``env``.

    ``argv[0]`` is the absolute ``docker`` path when it is resolvable on PATH, so
    the exec does not re-resolve a bare name (Bandit B607). When docker is absent
    the bare name is kept, letting the caller surface the usual "docker not found".
    """
    workspace = str(Path(config.workspace).resolve())
    cmd = [shutil.which("docker") or "docker", "run", "--rm"]
    if config.platform:
        cmd += ["--platform", config.platform]
    # --user covers linters that write cache dirs before the entrypoint privilege-drop.
    uid = env.get("MEGALINTER_UID")
    gid = env.get("MEGALINTER_GID")
    if uid is not None and gid is not None:
        cmd += ["--user", f"{uid}:{gid}"]
    for key, value in env.items():
        cmd += ["-e", f"{key}={value}"]
    cmd += ["-v", f"{workspace}:{CONTAINER_WORKSPACE}", image or config.image()]
    return cmd


def docker_arch(runner: Callable[[list[str]], subprocess.CompletedProcess] | None = None) -> str:
    """The Docker DAEMON's architecture — not the CLI host's.

    The two differ under ``DOCKER_HOST`` / docker-out-of-docker (an arm64 CLI driving an
    amd64 daemon, or the reverse in a containerised ARC runner), and it is the daemon's
    architecture that decides whether an image can execute. ``platform.machine()`` is
    only the fallback for when Docker cannot be asked.
    """
    run_fn = runner or (
        lambda cmd: subprocess.run(cmd, capture_output=True, text=True, check=False)  # nosec B603
    )
    try:
        proc = run_fn(["docker", "version", "--format", "{{.Server.Arch}}"])
    except OSError:
        proc = None
    out = (getattr(proc, "stdout", "") or "").strip() if proc is not None else ""
    if proc is not None and proc.returncode == 0 and out:
        return _ARCH_ALIASES.get(out, out)
    machine = platform.machine().lower()
    return _ARCH_ALIASES.get(machine, machine)


def _standalone_linters(
    config: MegaLinterConfig, arch: str
) -> tuple[list[str], list[tuple[str, str]]]:
    """Split the requested linters into (runnable, [(skipped, reason)]) for ``arch``."""
    # The arm64 flags in STANDALONE_LINTERS were probed once, at DEFAULT_TAG.
    # megalinter-only-* images are single-arch at v9 and below, so any pre-v10 tag
    # would fail with exec format error on arm64 — exactly the failure this PR fixes.
    # If the operator pins a different tag (without owning the image via image_ref or
    # platform), refuse rather than proceeding on unverified capability data.
    tag = config.image_tag.strip()
    if (
        arch != "amd64"
        and not config.image_ref
        and not config.platform
        and not tag.startswith("sha256:")
        and tag != DEFAULT_TAG
    ):
        raise MegaLinterError(
            f"The standalone arm64 image table was verified at {DEFAULT_TAG}; "
            f"the pinned tag '{tag}' has not been probed for arm64 capability. "
            "MegaLinter's per-linter images are multi-arch only from v10.0.0, so an "
            "earlier tag will fail with exec format error on arm64. "
            "Options: use the default tag, pin to a digest "
            "(image_tag: sha256:<digest>), or set image_ref / platform to indicate "
            "you have verified the tag yourself."
        )
    if config.standalone_linters:
        requested: tuple[str, ...] = config.standalone_linters
    elif config.enable_linters:
        requested = config.enable_linters
    else:
        flavor = (config.flavor or "security").strip().lower()
        requested = FLAVOR_STANDALONE_SETS.get(flavor, ())
        if not requested:
            raise MegaLinterError(
                f"No standalone linter set is defined for MegaLinter flavor '{flavor}'. "
                "Standalone mode runs one container per linter, so the 'all' flavor is "
                "not substituted automatically (100+ container starts and several GB of "
                "pulls is not a sane thing to do implicitly). Use flavor: security, or "
                "name the linters explicitly via standalone_linters / enable_linters."
            )
    disabled = {key.strip().upper() for key in config.disable_linters}
    keep: list[str] = []
    skipped: list[tuple[str, str]] = []
    for key in (k.strip().upper() for k in requested if k.strip()):
        image = STANDALONE_LINTERS.get(key)
        if key in disabled:
            skipped.append((key, "disabled via disable_linters"))
        elif image is None:
            skipped.append((key, "no megalinter-only image known at this MegaLinter version"))
        elif arch != "amd64" and not image.arm64:
            skipped.append((key, f"upstream image is linux/amd64 only ({arch} runner)"))
        elif not image.sarif:
            skipped.append((key, "linter emits no SARIF — it could never reach the gate"))
        else:
            keep.append(key)
    return keep, skipped


def resolve_plan(config: MegaLinterConfig, arch: str) -> RunPlan:
    """Decide how to run MegaLinter on ``arch``; raise with guidance when it cannot run.

    ``auto`` is the flavor image on amd64 and the per-linter images everywhere else.
    An explicit ``image_ref`` or ``platform`` is the operator taking the wheel — a
    custom arm64 flavor or a qemu/binfmt runner — so chargate stops second-guessing the
    architecture and runs the flavor image as asked.
    """
    strategy = (config.strategy or "auto").strip().lower()
    if strategy not in ARCH_STRATEGIES:
        raise MegaLinterError(
            f"Unknown arch strategy '{strategy}'. Choose one of: {', '.join(ARCH_STRATEGIES)}."
        )
    can_run_flavor = arch == "amd64" or bool(config.image_ref) or bool(config.platform)

    if strategy == "auto":
        strategy = "flavor" if can_run_flavor else "standalone"
    if strategy in ("flavor", "fail"):
        if not can_run_flavor:
            raise MegaLinterError(ARM64_HELP.format(image=config.image(), arch=arch))
        # `fail` differs from `flavor` only in refusing to degrade, which the guard
        # above has now settled; from here they are the same run.
        strategy = "flavor"

    if strategy == "flavor":
        step = RunStep("", config.image(), build_env(config), config.report_path())
        return RunPlan("flavor", arch, (step,))

    keep, skipped = _standalone_linters(config, arch)
    if not keep:
        detail = ", ".join(f"{key} ({reason})" for key, reason in skipped) or "none requested"
        raise MegaLinterError(
            f"Standalone mode resolved to zero runnable linters (skipped: {detail}). "
            "Set standalone_linters (or enable_linters) to MegaLinter linter keys that "
            "have a megalinter-only image for this architecture at this version."
        )
    steps = tuple(
        RunStep(
            key,
            config.standalone_image(key),
            build_env(config, single_linter=key),
            config.report_path(f"standalone/{key.lower()}"),
        )
        for key in keep
    )
    return RunPlan("standalone", arch, steps, tuple(skipped))


def merge_sarif(sources: Sequence[Path], destination: Path) -> int:
    """Merge per-linter MegaLinter SARIF documents into one; return the run count.

    MegaLinter's own ``SarifReporter`` builds its merged document exactly this way —
    concatenating each linter's ``runs`` into one envelope — so merging N standalone
    reports produces the shape the flavor image would have produced, and everything
    downstream (the net-new filter, DefectDojo, the Security tab) is unaffected.

    A missing or unparseable per-linter report is skipped rather than fatal: one linter
    crashing must not discard the other seventeen. The caller still sees the non-zero
    return code from that container, and an empty merge is reported loudly upstream.
    """
    merged: dict = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "properties": {"comment": "Merged by chargate from MegaLinter standalone images"},
        "runs": [],
    }
    for source in sources:
        if not source.is_file():
            continue
        try:
            document = json.loads(source.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        runs = document.get("runs")
        if isinstance(runs, list):
            merged["runs"].extend(runs)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(merged, indent=2), encoding="utf-8")
    return len(merged["runs"])


def locate_sarif(config: MegaLinterConfig) -> Path:
    """Return the merged SARIF path, tolerating the documented filename ambiguity.

    Deliberately NOT a ``*.sarif`` glob. Until this change it fell back to *any* .sarif
    in the report folder, which silently matched KICS' stray ``kics-results.sarif`` —
    the only file that landed in the workspace while the real merged report was written
    inside the container (see :meth:`MegaLinterConfig.container_report_dir`). Chargate
    then gated on a report with one empty run, reporting `net-new 0 / 0 total` on every
    PR, for every consumer, and looking perfectly healthy doing it.
    """
    report_dir = config.report_path()
    names = list(dict.fromkeys((config.sarif_file_name, *MEGALINTER_SARIF_NAMES)))
    for name in names:
        candidate = report_dir / name
        if candidate.is_file():
            return candidate
    raise MegaLinterError(
        f"MegaLinter produced no merged SARIF in {report_dir} "
        f"(looked for {', '.join(names)}). "
        "Check that SARIF_REPORTER=true and that REPORT_OUTPUT_FOLDER is an absolute "
        f"path under {CONTAINER_WORKSPACE} — a relative value is written inside the "
        "container and destroyed with `docker run --rm`."
    )


def _streaming_runner(cmd: list[str]) -> subprocess.CompletedProcess:
    """Run a container with its output inherited — one container, live logs."""
    return subprocess.run(cmd, check=False)  # nosec B603


def _capturing_runner(cmd: list[str]) -> subprocess.CompletedProcess:
    """Run a container capturing output, so N concurrent runs don't interleave."""
    return subprocess.run(cmd, capture_output=True, text=True, check=False)  # nosec B603


def _echo_step_output(step: RunStep, completed: subprocess.CompletedProcess) -> None:
    """Print one standalone container's captured output as a labelled block."""
    streams = (getattr(completed, "stdout", ""), getattr(completed, "stderr", ""))
    body = "".join(part for part in streams if part)
    if not body:
        return
    print(f"----- MegaLinter {step.linter} ({step.image}) -----", file=sys.stderr)
    print(body.rstrip(), file=sys.stderr)


def run(
    config: MegaLinterConfig,
    *,
    runner: Callable[[list[str]], subprocess.CompletedProcess] | None = None,
    arch: str | None = None,
) -> MegaLinterRun:
    """Run MegaLinter — one flavor container, or one container per linter — and report.

    Raises :class:`MegaLinterError` when this architecture cannot run what was asked for;
    the message names the architecture and every way out (see :data:`ARM64_HELP`).
    """
    resolved_arch = arch or docker_arch()
    plan = resolve_plan(config, resolved_arch)

    if plan.strategy == "flavor":
        step = plan.steps[0]
        command = build_docker_command(config, step.env, step.image)
        completed = (runner or _streaming_runner)(command)
        return MegaLinterRun(
            returncode=completed.returncode,
            command=tuple(command),
            sarif_path=config.sarif_path(),
            strategy="flavor",
            arch=resolved_arch,
        )

    # Standalone: N independent containers, each a complete one-linter MegaLinter.
    # Output is captured and replayed per linter, because four concurrent MegaLinter
    # runs interleaved line-by-line is not a log anyone can read.
    run_fn = runner or _capturing_runner
    commands = [build_docker_command(config, step.env, step.image) for step in plan.steps]
    workers = max(1, min(config.jobs, len(commands)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        completions = list(pool.map(run_fn, commands))
    for step, completed in zip(plan.steps, completions, strict=True):
        _echo_step_output(step, completed)
    merge_sarif(
        [step.report_dir / config.sarif_file_name for step in plan.steps],
        config.sarif_path(),
    )
    return MegaLinterRun(
        # Any failing container fails the run; --strict decides whether that gates.
        returncode=max((c.returncode for c in completions), default=0),
        command=tuple(commands[0]) if commands else (),
        sarif_path=config.sarif_path(),
        strategy="standalone",
        arch=resolved_arch,
        linters_run=tuple(step.linter for step in plan.steps),
        linters_skipped=plan.skipped,
    )
