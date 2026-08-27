# What MegaLinter covers

<!-- sources: .mega-linter.yml, src/chargate/linters.py -->

Chargate v2 replaced a hand-rolled twelve-tool orchestration with MegaLinter. This page
maps the old set onto what runs now — useful when migrating from v1, and when asking
"is *X* still being scanned?"

## The mapping

| Concern | v1 (hand-rolled) | Now (MegaLinter linter key) |
| --- | --- | --- |
| SAST / IaC | Trivy, Semgrep, Checkov | `REPOSITORY_TRIVY`, `REPOSITORY_SEMGREP`, `REPOSITORY_CHECKOV` |
| Dockerfile | Hadolint | `DOCKERFILE_HADOLINT` |
| Shell | ShellCheck | `BASH_SHELLCHECK` |
| GitHub Actions | actionlint | `ACTION_ACTIONLINT` |
| JavaScript | ESLint | `JAVASCRIPT_ESLINT` |
| Dependencies / SCA | pip-audit, npm audit, govulncheck | `REPOSITORY_OSV_SCANNER`, `REPOSITORY_TRIVY`, `REPOSITORY_GRYPE` |
| Secrets | TruffleHog | `REPOSITORY_BETTERLEAKS`, `REPOSITORY_SECRETLINT`, `REPOSITORY_KINGFISHER` |
| SBOM | — | `REPOSITORY_SYFT`, `REPOSITORY_TRIVY_SBOM` |

Secrets scanning moved to MegaLinter's native set: `betterleaks` is v10's gitleaks
successor, joined by `secretlint` and `kingfisher`.

## Kubernetes, and why only one of them gates

Kubernetes manifests are covered by two linters that behave differently:

- **`KUBERNETES_KUBESCAPE`** emits SARIF, so it is the only K8s linter the net-new gate
  can see. Findings from it gate like any other.
- **`KUBERNETES_KUBECONFORM`** does schema validation and emits **no SARIF**. It cannot
  reach the gate at all; it fails the run only through `strict: true`. See the Kubernetes
  note in `.mega-linter.yml`.

`kube-score` has no MegaLinter descriptor and is not wired in.

This asymmetry is worth internalising: **a linter that emits no SARIF cannot gate.** It
can only ever fail the job wholesale via `strict`, or be invisible. When you enable a
linter and its findings never appear in the net-new count, this is usually why.

## Linters that cannot run everywhere

For the `security` flavor, the arm64 fallback covers **all 18** SARIF-emitting linters:
trivy, semgrep, checkov, grype, syft, bandit, betterleaks, kingfisher, secretlint,
devskim, dustilock, kubescape, tflint, hadolint, shellcheck, cfn-lint, ansible-lint,
trivy-sbom.

Upstream's thirteen amd64-only linters are all style and language tooling (jscpd,
powershell, chktex, …). Those are skipped **by name, never silently** — see
[Security model](security-model.md#what-a-reduced-scan-looks-like).

## Choosing a different set

`flavor` selects the MegaLinter image; `enable_linters` / `disable_linters` tune it.
Chargate also curates a `quality` flavor MegaLinter does not publish. Full detail in
[Setup](setup.md) and the [Action reference](action-reference.md).
