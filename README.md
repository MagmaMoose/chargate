# Cinnabar

[![CI](https://github.com/magmamoose/cinnabar/actions/workflows/ci.yaml/badge.svg)](https://github.com/magmamoose/cinnabar/actions/workflows/ci.yaml)
[![License](https://img.shields.io/github/license/magmamoose/cinnabar)](LICENSE)

One security + lint gate for your repos. Trivy, TruffleHog, Semgrep, dependency audits, Checkov, ESLint, Kustomize, Hadolint, ShellCheck and actionlint — behind a single composite action with dynamic language detection, so each run does only the work the diff calls for.

The same scanners run **three ways from one source of truth**: as a composite **action**, as a reusable **workflow**, and as **pre-commit** hooks on your own machine. Write the scan logic once (`scripts/`), run it everywhere.

> Sibling to [diatreme](https://github.com/magmamoose/diatreme) (release management). Diatreme ships your releases; cinnabar guards what goes into them.

## Quickstart

```yaml
name: Security & Lint
on:
  pull_request:
    branches: [main]
permissions:
  contents: read
  pull-requests: read
  security-events: write
jobs:
  cinnabar:
    runs-on: ubuntu-latest
    steps:
      - uses: magmamoose/cinnabar@v1
```

That's it — the action checks out your code, detects what changed, installs the scanners it needs, and runs them. Security findings **block**; lint is **advisory** by default.

## Three ways to run

| Surface | Use it when | How |
|---|---|---|
| **Composite action** | You want a scan step inside an existing job, or full control over inputs | `uses: magmamoose/cinnabar@v1` |
| **Reusable workflow** | You want an isolated job with permissions baked in, as a standalone required check | `uses: magmamoose/cinnabar/.github/workflows/cinnabar.yaml@v1` |
| **pre-commit** | You want the same checks locally before you push | add the repo to `.pre-commit-config.yaml` (see [below](#local-pre-commit)) |

See [`examples/`](examples/) for ready-to-paste files for each.

## What runs

Each check fires only when the relevant files change (detected with `dorny/paths-filter` in CI, and per-hook `files:` patterns locally).

**Security** (blocks by default)

| Check | Tool | Triggers on |
|---|---|---|
| Vulnerabilities | Trivy (`fs`) | always |
| Secrets | TruffleHog (verified only) | always |
| SAST | Semgrep | always (`enable_sast`) |
| Python deps | pip-audit | `*.py`, `requirements*.txt`, `pyproject.toml` |
| JS deps | npm / yarn / pnpm audit | lockfile present |
| Go deps | govulncheck | `*.go`, `go.mod` |
| IaC | Checkov (Terraform/K8s/Dockerfile) | `*.tf`, `k8s/**`, … |
| Licenses | Trivy (`license`) | opt-in (`enable_license_scan`) |

**Lint** (advisory by default — set `lint_fail: true` to block)

| Check | Tool | Triggers on |
|---|---|---|
| Shell | ShellCheck | `*.sh`, `*.bash`, `*.zsh` |
| Workflows | actionlint | `.github/workflows/**` |
| Dockerfiles | Hadolint | `Dockerfile*` |
| JS/TS | ESLint (`npm run lint`) | `*.js`, `*.ts`, … |
| Kubernetes | Kustomize build + kubeconform + kube-score | `k8s/**`, `kustomization.yaml` |

## Why it won't fail when it shouldn't

Every scanner reports one of three things, and cinnabar treats them differently:

| Exit | Meaning | Effect |
|---|---|---|
| `0` | clean | pass |
| `1` | **real findings** | blocks (security) / advisory (lint) |
| `2` | **the tool itself crashed or is missing** | reported as a **warning**, never as a finding |

A flaky network, a missing binary, or a scanner that segfaults shows up as a *tool error* in the summary — it does **not** turn into a phantom security failure. Security fails *closed* (ambiguous results count as findings); lint fails *open*. This is the single biggest difference from hand-rolled scan workflows that pipe everything through `|| true` and conflate the two.

## Key inputs

| Input | Default | Description |
|---|---|---|
| `security` / `lint` | `true` | Toggle each domain. |
| `security_fail` | `true` | Fail the job on security findings. |
| `lint_fail` | `false` | Fail the job on lint findings (advisory otherwise). |
| `checkout` | `true` | Run `actions/checkout` first; set `false` if the job already checked out. |
| `enable_sast` | `true` | Run Semgrep. |
| `enable_license_scan` | `false` | Run the Trivy license scan. |
| `enable_sarif_upload` | `true` | Upload SARIF to the Security tab (needs GitHub Advanced Security on private repos). |
| `trivy_severity` | `CRITICAL,HIGH` | Severities Trivy flags. |
| `semgrep_config` | `p/default p/security-audit p/secrets` | Semgrep rulesets. |
| `checkov_skip_checks` | — | Comma-separated Checkov IDs to skip. |
| `k8s_directory` | `./k8s` | Where Kustomize lives. |

Tool versions (`trivy_version`, `semgrep_version`, `hadolint_version`, `actionlint_version`, `kustomize_version`, …) are pinned inputs too. See [`action.yml`](action.yml) for the full list.

**Outputs:** `scan_skipped`, `security_result`, `lint_result` (`pass | findings | error | disabled | skipped`).

## Ignoring known findings

All optional — cinnabar checks for each file before using it.

| Scanner | How |
|---|---|
| Trivy | `.trivyignore` (CVE IDs) |
| TruffleHog | a paths file via `trufflehog_exclude` |
| Semgrep | `.semgrepignore` (auto-detected) or `semgrep_baseline` |
| Checkov | `checkov_skip_checks` input, or inline `# checkov:skip=…` |

## Local pre-commit

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/magmamoose/cinnabar
    rev: v1
    hooks:
      - id: shellcheck
      - id: actionlint
      - id: trivy
      - id: trufflehog
      - id: semgrep
      - id: checkov
```

```sh
pre-commit install --hook-type pre-commit --hook-type pre-push
```

Tools auto-detect: whatever you don't have installed is skipped locally, so a missing scanner never blocks your commit — CI still enforces it. Fast linters run on `commit`, heavier security scans on `push`. Full hook list in [`.pre-commit-hooks.yaml`](.pre-commit-hooks.yaml).

## Enforcing it

Local git hooks can't be truly *forced* — `.git/hooks` isn't cloned and `git commit --no-verify` always bypasses them. So treat local hooks as fast feedback and enforce **server-side**:

- **Required status check — the real gate.** Run cinnabar on PRs (action or reusable workflow), then mark it required under **Settings → Branches → Branch protection**. Nothing merges unless cinnabar passes: zero developer setup, unbypassable.
- **[pre-commit.ci](https://pre-commit.ci)** (optional). Hosted app runs your `.pre-commit-config.yaml` on every PR and auto-fixes — also server-side, no dev action.

To make the *local* hooks install themselves (pre-push feedback without per-repo `pre-commit install`):

- **Auto-install on every future clone** (one-time per machine):
  ```sh
  pre-commit init-templatedir ~/.git-template
  git config --global init.templateDir ~/.git-template
  ```
- **Dev Containers / Codespaces** (zero-touch) — in `.devcontainer/devcontainer.json`:
  ```json
  "postCreateCommand": "pre-commit install -t pre-commit -t pre-push"
  ```
- **Node repos** (runs on `npm install`) — add to `package.json`: `"prepare": "pre-commit install -t pre-commit -t pre-push"`

**Bottom line:** the CI required check is the enforcement; local hooks are convenience.

## How it's built

`scripts/*.sh` hold the scan logic and obey the exit-code contract above. `action.yml` is the CI layer: detect → install pinned tools → run the scripts → upload SARIF → render the summary and enforce the gate. `.pre-commit-hooks.yaml` maps each hook to the same scripts. Nothing is implemented twice.

## License

MIT — see [LICENSE](LICENSE).
