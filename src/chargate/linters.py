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

``arm64`` was always probed that way. ``sarif`` was **not**, until brimyr#33: it lives
in MegaLinter's descriptor rather than the registry, so three entries
(``ACTION_ACTIONLINT``, ``PYTHON_PYLINT``, ``POWERSHELL_POWERSHELL``) sat here carrying
the ``_entry`` default of ``True`` while upstream said otherwise — each one a container
that starts, pulls, runs and contributes nothing the gate can read. The same test now
cross-checks every ``sarif`` flag against the descriptors, so the two cannot drift again.
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
        # kubeconform validates manifests against OpenAPI schemas but emits no SARIF, so
        # it gates only via `strict` (a tool error), never the net-new SARIF gate. K8s
        # SARIF coverage is KUBERNETES_KUBESCAPE alone. There is deliberately no
        # KUBERNETES_KUBE_SCORE entry: kube-score has no MegaLinter descriptor upstream.
        _entry("KUBERNETES_KUBECONFORM", sarif=False),
        _entry("REPOSITORY_OSV_SCANNER", sarif=False),
        _entry("REPOSITORY_TRUFFLEHOG", sarif=False),
        _entry("TERRAFORM_TERRAGRUNT", sarif=False),
        # ── The `quality` set: SARIF-emitting quality linters, none of them security ──
        # Probed at v10.0.0 the same way as the security set. ESLint's keys are
        # JAVASCRIPT_ES / TYPESCRIPT_ES, NOT *_ESLINT — the `_eslint` image repositories
        # do not exist and a run naming them 404s.
        _entry("GO_GOLANGCI_LINT"),
        _entry("JAVASCRIPT_ES"),
        _entry("JAVA_PMD"),
        _entry("PYTHON_RUFF"),
        _entry("TYPESCRIPT_ES"),
        # ── Commonly requested via enable_linters / standalone_linters ──
        # actionlint and pylint carried `sarif=True` here purely because that is the
        # `_entry` default — neither was ever probed, and at v10.0.0 neither descriptor
        # sets `can_output_sarif`. Both therefore start a container whose output the
        # net-new gate cannot see: a linter that runs, costs a pull, and reports nothing.
        # That is the precise failure this table exists to make loud, so they are now
        # skipped BY NAME WITH A REASON instead. `tests/test_linters_registry.py` re-probes
        # every flag against the live descriptors so it cannot drift back.
        _entry("ACTION_ACTIONLINT", sarif=False),
        _entry("JAVA_CHECKSTYLE"),
        _entry("JSON_JSONLINT", sarif=False),
        _entry("KOTLIN_DETEKT"),
        _entry("PHP_PHPSTAN"),
        _entry("PYTHON_PYLINT", sarif=False),
        _entry("REPOSITORY_GIT_DIFF", sarif=False),
        _entry("REPOSITORY_LS_LINT", sarif=False),
        _entry("MARKDOWN_MARKDOWNLINT", sarif=False),
        _entry("YAML_YAMLLINT", sarif=False),
        # ── amd64-only upstream at v10.0.0 ──
        # Auto-skipped (with a reason) on arm64 rather than failing the run.
        _entry("ARM_ARM_TTK", arm64=False, sarif=False),
        _entry("COPYPASTE_JSCPD", arm64=False, sarif=False),
        _entry("LATEX_CHKTEX", arm64=False, sarif=False),
        # Neither PowerShell linter sets can_output_sarif at v10.0.0 either; this was
        # the third entry carrying the `_entry` default un-probed.
        _entry("POWERSHELL_POWERSHELL", arm64=False, sarif=False),
    )
)

#: Flavors chargate defines *itself*. MegaLinter publishes no image for these, so there
#: is nothing to substitute *for* — they are the standalone set, on every architecture,
#: and :func:`chargate.megalinter.resolve_plan` routes them there rather than composing
#: an image reference that would 404 on a pull.
#:
#: ``quality`` exists because MegaLinter has no quality *flavor*: the choice upstream
#: offers is one language flavor at a time or ``all`` (100+ linters). Neither is the
#: thing a quality gate wants, which is a small set of linters a team actually respects.
SYNTHETIC_FLAVORS = frozenset({"quality"})

#: Flavor → the standalone set chargate substitutes when it cannot run that flavor's
#: image, or (for a :data:`SYNTHETIC_FLAVORS` entry) the set that *is* the flavor. Only
#: flavors with a curated, registry-verified set appear here. ``all`` is deliberately
#: absent: substituting it would mean 100+ container starts and multiple GB of pulls,
#: which is not a sane thing to do behind an operator's back — with ``flavor: all`` on
#: arm64 chargate raises and names the choices instead.
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
    # Five linters, not a flavor's worth — deliberately. MegaLinter's quality half over
    # a mature repo produces hundreds of net-new findings on the first pull request,
    # because "changed line touched by a formatter-opinionated linter" is a far denser
    # event than "changed line with a security finding". A gate that goes red with 200
    # findings on its first real PR gets switched off, and then it is decoration. So:
    # start with five that earn their noise, and grow the set from evidence.
    #
    # Every one is SARIF-emitting at v10.0.0 (a linter that is not is invisible to the
    # net-new gate) and multi-arch, and NONE is in the `security` set above — a repo
    # running both gates must not have one finding block it twice.
    #
    # Chosen for signal over style: golangci-lint is Go's meta-linter (so GO_REVIVE is
    # redundant), Ruff covers the flake8/isort/pyupgrade families in one container, and
    # PMD finds Java bugs and code smells where JAVA_CHECKSTYLE — also available, also
    # verified — reports formatting opinion, which is the densest noise there is.
    #
    # There is no .NET entry: at v10.0.0 no C#/VB.NET linter sets `can_output_sarif`, so
    # none of them could reach the gate. Said here rather than discovered later by a
    # .NET team whose quality gate reports zero findings forever.
    "quality": (
        "GO_GOLANGCI_LINT",
        "JAVASCRIPT_ES",
        "JAVA_PMD",
        "PYTHON_RUFF",
        "TYPESCRIPT_ES",
    ),
}
