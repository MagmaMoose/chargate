# Chargate

[![License](https://img.shields.io/github/license/magmamoose/chargate)](LICENSE)

Chargate is a GitHub Marketplace composite action that runs a security and lint
gate for pull requests. It detects what changed, installs the scanners needed for
that change set, uploads SARIF when enabled, and reports normalized action
outputs for security and lint results.

The scanner implementation lives in
[MagmaMoose/platform apps/chargate](https://github.com/MagmaMoose/platform/tree/0acafb2cb991d84e772be412a60c08b7dda3a44e/apps/chargate).
This repository intentionally keeps only the Marketplace action metadata and
user-facing release material. `action.yml` fetches the platform runtime from that
pinned commit SHA; it does not fetch from `main`.

## Usage

```yaml
name: Security and lint

on:
  pull_request:
    branches: [main]

permissions:
  contents: read
  pull-requests: read
  security-events: write

jobs:
  chargate:
    runs-on: ubuntu-latest
    steps:
      - uses: magmamoose/chargate@v1
```

By default, Chargate checks out the repository, runs security scanners as a
blocking gate, runs lint checks as advisory, and uploads SARIF.

If your job already checked out the repository:

```yaml
steps:
  - uses: actions/checkout@v6
    with:
      fetch-depth: 0
  - uses: magmamoose/chargate@v1
    with:
      checkout: 'false'
      lint_fail: 'true'
```

To disable SARIF upload, set `enable_sarif_upload: 'false'` and omit
`security-events: write`.

## Permissions

```yaml
permissions:
  contents: read
  pull-requests: read
  security-events: write
```

`contents: read` and `pull-requests: read` support checkout and changed-file
detection. `security-events: write` is required only when
`enable_sarif_upload` is `true`.

## Inputs

| Input | Default | Description |
| --- | --- | --- |
| `checkout` | `true` | Run `actions/checkout` with `fetch-depth: 0` before scanning. |
| `security` | `true` | Run security scanners. |
| `lint` | `true` | Run lint checks. |
| `security_fail` | `true` | Fail the job on security findings. |
| `lint_fail` | `false` | Fail the job on lint findings. |
| `strict` | `false` | Treat scanner tool errors as failures. |
| `enable_sarif_upload` | `true` | Upload SARIF to the GitHub Security tab. |
| `github_token` | `${{ github.token }}` | Token used for SARIF upload and API access. |
| `trivy_severity` | `CRITICAL,HIGH` | Trivy vulnerability severities to flag. |
| `trivy_ignore_unfixed` | `true` | Ignore vulnerabilities with no fix available. |
| `trivyignore_file` | `.trivyignore` | Path to a Trivy ignore file, used only if it exists. |
| `trufflehog_exclude` | empty | Optional TruffleHog exclude-paths file. |
| `enable_sast` | `true` | Run Semgrep SAST. |
| `semgrep_config` | `p/default p/security-audit p/secrets` | Space-separated Semgrep rulesets. |
| `semgrep_baseline` | empty | Optional Semgrep ignore file. If blank, `.semgrepignore` is auto-detected. |
| `npm_audit_level` | `high` | Minimum severity for npm, yarn, or pnpm audit. |
| `checkov_skip_checks` | empty | Comma-separated Checkov check IDs to skip. |
| `enable_license_scan` | `false` | Run the Trivy license-compliance scan. |
| `eslint_script` | `lint` | Package script to run for ESLint. |
| `k8s_directory` | `./k8s` | Directory containing Kustomize files. |
| `kubernetes_version` | `1.32.0` | Kubernetes version for manifest validation. |
| `skip_kubeconform` | `false` | Skip kubeconform validation. |
| `skip_kubescore` | `false` | Skip kube-score advisory validation. |

All boolean inputs are strings, as expected by GitHub composite actions.

## Outputs

| Output | Description |
| --- | --- |
| `scan_skipped` | `true` when no relevant files changed and the scan was skipped. |
| `security_result` | `pass`, `findings`, `error`, `disabled`, or `skipped`. |
| `lint_result` | `pass`, `findings`, `error`, `disabled`, or `skipped`. |

## What Runs

Chargate runs tools only when the changed files call for them:

| Area | Tools |
| --- | --- |
| Vulnerabilities | Trivy filesystem scan, pip-audit, npm/yarn/pnpm audit, govulncheck |
| Secrets and SAST | TruffleHog verified-secret scan, Semgrep |
| IaC and containers | Checkov, Hadolint |
| Lint | ShellCheck, actionlint, ESLint, Kustomize, kubeconform, kube-score |
| Licenses | Trivy license scan, opt-in with `enable_license_scan` |

Scanner versions are pinned in the platform runtime, not as action inputs.

## Versioning and Releases

Use a major tag such as `magmamoose/chargate@v1` for normal adoption, or pin a
full action commit SHA for maximum reproducibility. Updating Chargate's scanner
logic requires updating the pinned platform SHA in `action.yml`, validating the
action, and publishing a new GitHub Release for the Marketplace listing.

This repository does not contain workflow files by design. GitHub Marketplace
requires a public action repository to contain one root `action.yml` or
`action.yaml` metadata file and no workflow files.

## License

MIT. See [LICENSE](LICENSE).
