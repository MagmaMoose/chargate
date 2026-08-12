"""Which MegaLinter linters chargate can run as standalone (``megalinter-only-*``) images.

MegaLinter publishes one image per linter — ``ghcr.io/oxsecurity/megalinter-only-<key
lowercased>`` — and **from v10.0.0 those are multi-arch** (``linux/amd64`` +
``linux/arm64``), while every *flavor* image (``megalinter``, ``megalinter-security``,
``megalinter-python``, …) is still a single ``linux/amd64`` manifest at every tag
published to date. Running the standalone set is therefore the only way to scan on an
arm64 runner with upstream-built images — see
:data:`chargate.megalinter.ARM64_HELP` for the alternatives.

A standalone image is a *full* MegaLinter, not a bare linter: it ships
``MEGALINTER_FLAVOR=none`` + ``SINGLE_LINTER=<key>``, the same ``/entrypoint.sh``, and
the same reporters (``MegaLinter.py`` takes the ``megalinter_flavor == "none"`` branch
and builds a one-linter run). So each container writes its own complete
``megalinter-report.sarif``, and merging N of them is a concatenation of their ``runs``
arrays — byte-for-byte the shape the flavor image would have produced.

Two flags per linter:

``arm64``
    An ``linux/arm64`` manifest exists at :data:`chargate.megalinter.DEFAULT_TAG`.
    13 of MegaLinter's 113 linters are amd64-only at v10.0.0 (arm-ttk, bicep, chktex,
    clj-kondo, cljstyle, 4x Salesforce code-analyzer, dartanalyzer, jscpd, powershell,
    powershell_formatter) — **none of them is a security linter**.

``sarif``
    The linter's descriptor sets ``can_output_sarif``. A linter that cannot emit SARIF
    is *invisible to chargate's gate*, which only ever reads the merged SARIF, so
    starting its container on arm64 is pure cost for zero coverage. Six linters in the
    v10 ``security`` flavor are in this category and have never reached the gate on any
    architecture.

This table is **version-pinned data**, not a guess: every entry below was probed
against the live ghcr.io registry at ``v10.0.0``. ``tests/test_linters_registry.py``
re-probes it on demand (and weekly in CI) so a MegaLinter bump cannot silently drop a
linter, rename an image, or lose an arm64 build — a shrinking arm64 scan that nobody
notices is exactly the failure mode this whole change exists to remove.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class LinterImage:
    """One ``megalinter-only-<key>`` image's capabilities at the pinned MegaLinter tag."""

    key: str
    arm64: bool
    sarif: bool

    def repository(self) -> str:
        """The image repository suffix, e.g. ``megalinter-only-repository_trivy``."""
        return f"megalinter-only-{self.key.lower()}"


def _entry(key: str, *, arm64: bool = True, sarif: bool = True) -> tuple[str, LinterImage]:
    return key, LinterImage(key, arm64, sarif)


#: Every linter chargate knows how to run standalone. Absence from this table is not a
#: claim that no image exists — it means chargate has not verified one, and standalone
#: mode will say so by name rather than guessing at an image reference that 404s.
STANDALONE_LINTERS: dict[str, LinterImage] = dict(
    (
        # ── v10 `security` flavor, SARIF-capable: chargate's arm64 default set ──
        _entry("ANSIBLE_ANSIBLE_LINT"),
        _entry("BASH_SHELLCHECK"),
        _entry("CLOUDFORMATION_CFN_LINT"),
        _entry("DOCKERFILE_HADOLINT"),
        _entry("KUBERNETES_KUBESCAPE"),
        _entry("PYTHON_BANDIT"),
        _entry("REPOSITORY_BETTERLEAKS"),
        _entry("REPOSITORY_CHECKOV"),
        _entry("REPOSITORY_DEVSKIM"),
        _entry("REPOSITORY_DUSTILOCK"),
        _entry("REPOSITORY_GRYPE"),
        _entry("REPOSITORY_KINGFISHER"),
        _entry("REPOSITORY_SECRETLINT"),
        _entry("REPOSITORY_SEMGREP"),
        _entry("REPOSITORY_SYFT"),
        _entry("REPOSITORY_TRIVY"),
        _entry("REPOSITORY_TRIVY_SBOM"),
        _entry("TERRAFORM_TFLINT"),
        # ── v10 `security` flavor, no SARIF output: never reaches chargate's gate ──
        # Listed so standalone mode can skip them *by name with a reason* instead of
        # silently dropping them, and so an operator who names one explicitly is told
        # why it produced nothing.
        _entry("BASH_EXEC", sarif=False),
        _entry("KUBERNETES_HELM", sarif=False),
        _entry("KUBERNETES_KUBECONFORM", sarif=False),
        _entry("REPOSITORY_OSV_SCANNER", sarif=False),
        _entry("REPOSITORY_TRUFFLEHOG", sarif=False),
        _entry("TERRAFORM_TERRAGRUNT", sarif=False),
        # ── Commonly requested via enable_linters / standalone_linters ──
        _entry("ACTION_ACTIONLINT"),
        _entry("GO_GOLANGCI_LINT"),
        _entry("JSON_JSONLINT", sarif=False),
        _entry("PYTHON_PYLINT"),
        _entry("PYTHON_RUFF"),
        _entry("REPOSITORY_GIT_DIFF", sarif=False),
        _entry("REPOSITORY_LS_LINT", sarif=False),
        _entry("MARKDOWN_MARKDOWNLINT", sarif=False),
        _entry("YAML_YAMLLINT", sarif=False),
        # ── amd64-only upstream at v10.0.0 ──
        # Auto-skipped (with a reason) on arm64 rather than failing the run.
        _entry("ARM_ARM_TTK", arm64=False, sarif=False),
        _entry("COPYPASTE_JSCPD", arm64=False, sarif=False),
        _entry("LATEX_CHKTEX", arm64=False, sarif=False),
        _entry("POWERSHELL_POWERSHELL", arm64=False),
    )
)

#: Flavor → the standalone set chargate substitutes when it cannot run that flavor's
#: image. Only flavors with a curated, registry-verified set appear here. ``all`` is
#: deliberately absent: substituting it would mean 100+ container starts and multiple
#: GB of pulls, which is not a sane thing to do behind an operator's back — with
#: ``flavor: all`` on arm64 chargate raises and names the choices instead.
FLAVOR_STANDALONE_SETS: dict[str, tuple[str, ...]] = {
    # The 18 SARIF-emitting linters of the v10 `security` flavor. The other six
    # security-flavor linters emit no SARIF and so could never have reached the gate.
    "security": (
        "ANSIBLE_ANSIBLE_LINT",
        "BASH_SHELLCHECK",
        "CLOUDFORMATION_CFN_LINT",
        "DOCKERFILE_HADOLINT",
        "KUBERNETES_KUBESCAPE",
        "PYTHON_BANDIT",
        "REPOSITORY_BETTERLEAKS",
        "REPOSITORY_CHECKOV",
        "REPOSITORY_DEVSKIM",
        "REPOSITORY_DUSTILOCK",
        "REPOSITORY_GRYPE",
        "REPOSITORY_KINGFISHER",
        "REPOSITORY_SECRETLINT",
        "REPOSITORY_SEMGREP",
        "REPOSITORY_SYFT",
        "REPOSITORY_TRIVY",
        "REPOSITORY_TRIVY_SBOM",
        "TERRAFORM_TFLINT",
    ),
}
