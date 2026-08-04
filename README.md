# Chargate

[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-Chargate-2ea44f?logo=github)](https://github.com/marketplace/actions/chargate)
[![CI](https://github.com/MagmaMoose/chargate/actions/workflows/ci.yml/badge.svg)](https://github.com/MagmaMoose/chargate/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/MagmaMoose/chargate?sort=semver&logo=github)](https://github.com/MagmaMoose/chargate/releases)
[![License: MIT](https://img.shields.io/github/license/MagmaMoose/chargate)](LICENSE)
[![Python](https://img.shields.io/badge/python-%E2%89%A53.11-blue?logo=python&logoColor=white)](pyproject.toml)

> **Gate pull requests on the findings _this PR_ introduced — not your whole backlog.**

Chargate is a security + lint gate built on [MegaLinter](https://megalinter.io).
MegaLinter does **all** the scanning; Chargate adds the one thing that matters for
day-to-day developer flow: **net-new finding gating**. On a pull request the gate
passes or fails based *only* on findings the PR introduces relative to the
merge-base. Pre-existing findings never block. The full, unfiltered SARIF is
always emitted and shippable (first-class DefectDojo) so your security system
still sees everything, including inherited debt.

> **v2 is a ground-up re-platform.** Chargate no longer hand-rolls a 12-tool
> scanner orchestration — MegaLinter does that. If you used `magmamoose/chargate@v1`,
> see [Migrating from v1](#migrating-from-v1).

## Contents

- [Why net-new?](#why-net-new)
- [Two surfaces](#two-surfaces) · [Composite action](#1-composite-action-recommended) · [pre-commit hook](#2-pre-commit-hook)
- [Permissions](#permissions)
- [Inputs](#inputs) · [Outputs](#outputs)
- [Net-new semantics](#net-new-semantics)
- [PR comments](#pr-comments-ghas-style)
- [Sinks: DefectDojo & Dependency-Track](#sinks-defectdojo--dependency-track)
- [Modes](#modes) · [CLI](#cli)
- [Versioning & pinning](#versioning--pinning) · [Security](#security)
- [What MegaLinter covers](#what-megalinter-covers-vs-the-old-hand-rolled-set) · [Migrating from v1](#migrating-from-v1)
- [Documentation & contributing](#documentation--contributing)

## Why net-new?

A whole-repo security scan on a large codebase reports hundreds of pre-existing
findings. Blocking PRs on all of them is noise; ignoring them loses signal.
Chargate splits the difference:

- **Gate** on what *this PR* introduced (net-new) → actionable, low-noise.
- **Ship** the *complete* SARIF to DefectDojo / the Security tab → full visibility,
  including inherited debt and trends.

## Two surfaces

| Surface | What it is | When to use |
| --- | --- | --- |
| **Composite action** | `action.yml` | The CI gate — a few lines in a workflow. |
| **pre-commit hook** | `.pre-commit-hooks.yaml` (`chargate` hook) | Fast local first line on staged files. |

Both drive the same `chargate` Python CLI.

### 1. Composite action (recommended)

```yaml
# .github/workflows/security.yml
name: Security
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  pull-requests: read
  security-events: write

jobs:
  chargate:
    runs-on: ubuntu-latest
    steps:
      - uses: magmamoose/chargate@v2
        with:
          fail_on: high          # block only on net-new high/critical (default: any)
          # defectdojo_url: https://dd.example.com
          # defectdojo_token: ${{ secrets.DEFECTDOJO_TOKEN }}
          # dependency_track_url: https://dtrack.example.com
          # dependency_track_api_key: ${{ secrets.DEPENDENCYTRACK_API_KEY }}
```

On PRs it uses MegaLinter's focused `security` flavor and requests changed-files
analysis, gates on net-new findings, and ships the full SARIF. Repository-level
security scanners may still inspect the whole repo or history. On push to the default
branch it runs a non-gating whole-repo baseline scan. Set `flavor: all` for the full
lint image, or `incremental: 'false'` for a whole-repo PR scan. The action checks out
with `fetch-depth: 0` by default (net-new needs the merge-base) — set
`checkout: 'false'` if you already checked out with full history.

### 2. pre-commit hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/MagmaMoose/chargate
    rev: v2.0.0
    hooks:
      - id: chargate
```

```sh
pre-commit install
pre-commit run -a
```

The hook (`language: python`, no Docker) runs a **fast staged-file subset**
(gitleaks for secrets, ruff for Python — each skipped if not installed). It is a
first line, deliberately narrower than the CI whole-repo net. Local/CI disparity
is intended.

Chargate also ships **file-hygiene hooks** (bash, no Docker) that coexist with the
security `chargate` hook above:

```yaml
  - repo: https://github.com/MagmaMoose/chargate
    rev: v2.0.0
    hooks:
      - id: actions-pin-sha            # pin GitHub Actions uses: to SHAs (+semver comment)
      - id: conventional-branch-name   # enforce <type>/<desc> branch names (pre-push)
```

**Global auto-install** across all your repos — one command via Homebrew:

```sh
brew install calebsargeant/tap/chargate   # brings pre-commit along as a dependency
chargate install-hooks
```

`chargate install-hooks` generates pre-commit + pre-push + commit-msg dispatchers
(repointed at the **global** `~/.pre-commit-config.yaml`), sets `core.hooksPath` so
the hooks apply to **every existing repo immediately**, and sets `init.templateDir`
so new clones inherit them. It refuses to clobber a hand-maintained config unless you
pass `--force`, and `chargate uninstall-hooks` reverts everything (restoring any
prior `core.hooksPath`).

The managed config keeps chargate's hooks inside a `>>> chargate-managed >>>` block.
**Add your own repos/hooks outside that block and they're preserved** every time you
rerun `install-hooks` (only the block is regenerated):

```yaml
repos:
  # >>> chargate-managed (regenerated; edits here are overwritten) >>>
  - repo: https://github.com/MagmaMoose/chargate
    rev: v2.0.0
    hooks: [{ id: actions-pin-sha }, { id: conventional-branch-name }]
  # <<< chargate-managed <<<
  - repo: local            # ← your hooks live here, untouched on reinstall
    hooks: [...]
```

> Two delivery paths, by design: the **CLI** ships via Homebrew, while the **hook
> scripts** are fetched by pre-commit from this repo at the pinned `rev` — they are
> not in the installed wheel.
>
> ⚠️ `install-hooks` repoints your global `core.hooksPath`. If you already have global
> hooks at another path, they stop running (intended — that is how chargate takes
> over); the prior path is saved and restored on `uninstall-hooks`.

Prefer to wire it by hand instead? The equivalent manual setup:

```sh
tpl=~/.config/chargate/git-template
pre-commit init-templatedir "$tpl" \
  --hook-type pre-commit --hook-type pre-push --hook-type commit-msg
# init-templatedir bakes in a per-repo `--config=.pre-commit-config.yaml`; repoint
# it at the global file so the hooks apply in every repo:
sed -i '' "s#--config=.pre-commit-config.yaml#--config=$HOME/.pre-commit-config.yaml#" \
  "$tpl"/hooks/pre-commit "$tpl"/hooks/pre-push "$tpl"/hooks/commit-msg
git config --global core.hooksPath  "$tpl/hooks"
git config --global init.templateDir "$tpl"
```

## Permissions

Grant the job the least privilege it needs:

```yaml
permissions:
  contents: read           # checkout
  pull-requests: write     # PR comments (drop to `read`, or omit, if pr_comment: false)
  security-events: write   # upload the full SARIF to the Security tab
  id-token: write          # OPTIONAL — author PR comments as Chargate[bot] via the token broker
```

- `contents: read` is the only hard requirement.
- `pull-requests: write` enables the GHAS-style PR comments (on by default).
- `security-events: write` enables the Security-tab SARIF upload (needs GHAS on private repos).
- `id-token: write` is optional — it lets the action mint a `Chargate[bot]` token; without it, comments fall back to `github-actions[bot]`.

## Inputs

All inputs are optional. **DefectDojo / Dependency-Track are each active iff their
`*_url` is set** — there is no separate on/off toggle.

### Checkout

| Input | Default | Description |
| --- | --- | --- |
| `checkout` | `true` | Run `actions/checkout` first. Net-new gating needs full history. Set `false` if you already checked out with `fetch-depth: 0`. |
| `fetch_depth` | `0` | Checkout fetch-depth. **Must be `0`** for net-new gating (merge-base). |

### Gate behaviour

| Input | Default | Description |
| --- | --- | --- |
| `mode` | `auto` | `auto` (from the event) · `pr` (net-new gate) · `baseline` (full scan, no gate). |
| `fail_on` | `any` | Severity that blocks: `any` · `critical` · `high` · `medium` · `low` · `none`. |
| `precision` | `line` | Net-new precision: `line` · `file`. |
| `base_ref` | `''` | Override the base ref/SHA (default: PR base SHA from the event). |
| `head_ref` | `''` | Override the head ref/SHA (default: PR head SHA, else `github.sha`). |
| `strict` | `false` | Fail the job if MegaLinter itself errors (a tool error, not a finding). |

### MegaLinter

| Input | Default | Description |
| --- | --- | --- |
| `flavor` | `security` | MegaLinter flavor: `security` (focused default) · `all` (full lint image) · `python` · `go` · … |
| `megalinter_tag` | `v8` | MegaLinter image tag or digest to pin. |
| `enable_linters` | `''` | Comma-separated MegaLinter linter keys to enable (others off). |
| `disable_linters` | `''` | Comma-separated MegaLinter linter keys to disable. |
| `incremental` | `true` | PR events only: ask MegaLinter to scan just the changed files (`VALIDATE_ALL_CODEBASE=false`). Faster on large repos; repository-level scanners may still read the whole repo or history. The net-new gate still uses Chargate's own diff. |
| `ignore_sops_encrypted` | `true` | Ignore secret-scanner hits on SOPS-encrypted (`ENC[AES256_GCM,...]`) values — 100% false positives. A plaintext secret in the same file still gates. |

### SARIF output

| Input | Default | Description |
| --- | --- | --- |
| `emit_sarif_artifact` | `true` | Upload the full SARIF as a build artifact. |
| `sarif_artifact_name` | `chargate-sarif` | Artifact name for the full SARIF. |
| `upload_github_sarif` | `true` | Upload the full SARIF to the GitHub Security tab (non-PR events; needs GHAS on private repos). |
| `github_token` | `${{ github.token }}` | Token for the Security-tab upload + PR comments. |

### PR comments (GHAS-style, net-new only)

| Input | Default | Description |
| --- | --- | --- |
| `pr_comment` | `true` | Post GHAS-style PR comments for net-new findings (PR events only). Needs `pull-requests: write`. |
| `pr_comment_mode` | `both` | `summary` (one updatable comment) · `inline` (per-line) · `both`. |
| `pr_comment_max_inline` | `50` | Cap on inline comments per run; the rest are listed in the summary. |
| `pr_comment_token` | `''` | Override token used **only** to author the comments (BYO GitHub App). Usually unset — see [PR comments](#pr-comments-ghas-style). |
| `token_broker_url` | `https://chargate.magmamoose.com` | Token broker for `Chargate[bot]` authorship. Set empty to disable (fall back to `github-actions[bot]`). |
| `oidc_audience` | `chargate` | OIDC audience requested for the broker exchange (advanced). |

### DefectDojo (optional sink)

| Input | Default | Description |
| --- | --- | --- |
| `defectdojo_url` | `''` | DefectDojo base URL. **Set to enable** import of the full SARIF. |
| `defectdojo_token` | `''` | DefectDojo API token (pass a secret). |
| `defectdojo_product` | repo name | DefectDojo product name (auto-created if missing). |
| `defectdojo_product_type` | `Research and Development` | Product type (used to auto-create a new product). |
| `defectdojo_engagement` | `ci` | Engagement name (auto-created if missing). |
| `defectdojo_close_old` | `true` | Close findings no longer present on reimport. |

### Dependency-Track (optional sink)

| Input | Default | Description |
| --- | --- | --- |
| `dependency_track_url` | `''` | Dependency-Track base URL. **Set to enable** the CycloneDX BOM upload. |
| `dependency_track_api_key` | `''` | Dependency-Track API key (pass a secret). Needs `BOM_UPLOAD` (+ `PROJECT_CREATION_UPLOAD`, + `VIEW_PORTFOLIO` for the PR-comment link). |
| `dependency_track_project_name` | `${{ github.repository }}` | Project name (auto-created if missing). |
| `dependency_track_project_version` | `${{ github.ref_name }}` | Project version. |
| `dependency_track_auto_create` | `true` | Auto-create the project/version on first upload. |

### Runtime

| Input | Default | Description |
| --- | --- | --- |
| `python_version` | `3.12` | Python version used to run the Chargate CLI. |

## Outputs

| Output | Description |
| --- | --- |
| `mode` | Resolved run mode: `pr` or `baseline`. |
| `gate_result` | `pass` or `fail`. |
| `net_new_count` | Number of net-new (PR-introduced) findings. |
| `total_count` | Total findings in the full SARIF (net-new + pre-existing). |
| `sarif_path` | Path to the full (unfiltered) SARIF report. |

```yaml
- uses: magmamoose/chargate@v2
  id: gate
- run: echo "Gate ${{ steps.gate.outputs.gate_result }} — ${{ steps.gate.outputs.net_new_count }} net-new / ${{ steps.gate.outputs.total_count }} total"
```

## Net-new semantics

A SARIF result is **net-new** iff its primary location's file is in the PR diff
**and** (at line precision) its `startLine` falls inside an added/modified hunk.
The diff is computed against `merge-base(base, head)`, which is robust to base-branch
rebases and force-pushes.

| Case | Policy (default) | Configurable |
| --- | --- | --- |
| Brand-new file | all results net-new | — |
| Modified hunk | net-new iff `startLine` in an added range | `precision: line\|file` |
| Unchanged line in a changed file | pre-existing → never blocks | `precision: file` to flip |
| Renamed / copied file | matched by head path; content changes line-matched | — |
| Deleted file | dropped | — |
| Result with **no** file location (project-level: SBOM/license/some Trivy) | **not** net-new | `--no-location-policy block` |
| Changed file, result with no `startLine` (common for SCA on a lockfile) | net-new (file-level fallback) | `--no-region-fallback` to disable |
| Multiple locations | uses the **primary** (`locations[0]`) | documented |
| Missing merge-base / shallow clone | **fails loudly** — needs `fetch-depth: 0` | — |

`fail_on` controls the gate: `any` (default — any net-new blocks), `critical`,
`high`, `medium`, `low`, or `none` (report-only). Severity uses the SARIF
`security-severity` band when present, else the SARIF `level`
(error→high, warning→medium, note→low).

## PR comments (GHAS-style)

On pull requests Chargate reports the way GitHub Advanced Security does — scoped to
**net-new findings only**, so it stays quiet:

- **One summary comment**, updated in place on every push (found by a hidden marker
  and `PATCH`ed, never duplicated).
- **Inline review comments** on each net-new finding that sits on a changed line;
  prior Chargate inline comments are deleted and re-posted each run so they never stack.

It is **on by default** and needs `pull-requests: write`. Disable with
`pr_comment: false`; tune with `pr_comment_mode` / `pr_comment_max_inline` (see
[Inputs → PR comments](#pr-comments-ghas-style-net-new-only)).

**Comment as `Chargate[bot]` (opt-in, zero key management).** By default comments
are authored by `github-actions[bot]`. To post as **`Chargate[bot]`** instead:
(1) install the Chargate GitHub App on your org/repo, and (2) add `id-token: write`
to the job's `permissions`. The action then exchanges the run's OIDC token at the
[token broker](https://github.com/MagmaMoose/chargate/tree/main/broker) for a
short-lived, repo-scoped token — no App keys to manage. It is **fail-soft**: without
`id-token: write`, or if the App isn't installed, comments simply fall back to
`github-actions[bot]`. Prefer to self-host? Bring your own App token via
`actions/create-github-app-token` and pass it as `pr_comment_token`.

Full walkthrough: **[docs — PR comments](https://github.com/MagmaMoose/chargate/blob/main/docs/setup.md#pr-comments-ghas-style)**.

## Sinks (DefectDojo & Dependency-Track)

Both external sinks follow the **same enable rule: set a Variable for the host
and a Secret for the credential — the sink is active iff the host is set.** There
is no separate on/off toggle. Both are optional, first-class, and failure-isolated
(a sink outage is logged and never fails the gate).

### DefectDojo

Ships the **full** SARIF (never the filtered one) via DefectDojo's API:

```yaml
- uses: magmamoose/chargate@v2
  with:
    defectdojo_url: https://defectdojo.example.com   # active iff this is set
    defectdojo_token: ${{ secrets.DEFECTDOJO_TOKEN }}
    defectdojo_product: my-service
    defectdojo_product_type: Research and Development   # needed to auto-create a new product
    defectdojo_engagement: ci
```

- Uses `reimport-scan` by default (one Test per engagement; `close_old_findings`
  mitigates findings that disappear). Auto-creates the product/engagement.
- **A DefectDojo failure never fails the gate** — it is logged and the run
  continues.
- Prefer "emit artifact only" / "write to path"? Use the CLI's `--sarif-out` and
  skip `defectdojo_url`.

### Dependency-Track

The supply-chain analog: generates a CycloneDX BOM (Syft, any language) and
uploads it to your Dependency-Track server:

```yaml
- uses: magmamoose/chargate@v2
  with:
    dependency_track_url: https://dtrack.example.com   # active iff this is set
    dependency_track_api_key: ${{ secrets.DEPENDENCYTRACK_API_KEY }}
    dependency_track_project_name: my-service          # defaults to the repo
    dependency_track_project_version: 1.2.3            # defaults to the ref name
```

- Generates the BOM with `anchore/sbom-action` (Syft) and `POST`s it to
  `/api/v1/bom` (multipart); auto-creates the project/version on first upload.
- **A Dependency-Track failure never fails the gate** — it is logged and the run
  continues.

## Modes

- **PR events** → whole-repo MegaLinter → net-new gate → full SARIF to the sinks /
  artifact.
- **Push to default branch / scheduled** → full scan → full SARIF to the sinks as
  the authoritative baseline → **no** net-new gate.

`mode: auto` (default) picks this from the event; force with `mode: pr|baseline`.

## CLI

```sh
chargate filter-sarif --sarif report.sarif --base "$BASE" --head "$HEAD" \
    --out net-new.sarif --counts-json counts.json --fail-on any
chargate ci --mode auto --flavor all --sarif-out full.sarif
chargate local path/to/file.py        # what the pre-commit hook runs
```

Exit codes: `0` pass · `1` blocking net-new findings · `2` setup/usage error.

## Versioning & pinning

Chargate follows [Semantic Versioning](https://semver.org), released automatically
from [Conventional Commits](https://www.conventionalcommits.org). Pick a pin by how
much you value stability vs. immutability:

| Reference | Example | Gets | Use when |
| --- | --- | --- | --- |
| **Moving major** | `magmamoose/chargate@v2` | Non-breaking updates within v2 | **Recommended default.** |
| **Exact release** | `magmamoose/chargate@v2.8.0` | Nothing until you bump | You want reproducible, opt-in updates. |
| **Commit SHA** | `magmamoose/chargate@<sha>` | Nothing until you bump | Highest supply-chain assurance (pair with Dependabot/Renovate). |

Breaking changes bump the **major**; the **`v1` tag is frozen** on the old runtime,
so existing v1 pins keep working until you migrate (see [Migrating from v1](#migrating-from-v1)).

## Security

Chargate is a security tool and is built to be one:

- **Least privilege by default.** See [Permissions](#permissions). The optional
  `Chargate[bot]` token is short-lived, scoped to the calling repo, and carries
  `pull_requests: write` **only**.
- **Injection-hardened.** Every action input is passed to the gate step through the
  environment, never interpolated into a shell body, so a malicious input value
  can't break out via `${{ }}` template injection.
- **Pinned supply chain.** Every third-party action Chargate calls (`checkout`,
  `setup-python`, `codeql-action/upload-sarif`, `upload-artifact`, `sbom-action`) is
  **SHA-pinned** with a `# vX.Y.Z` comment; the core CLI has **no runtime
  dependencies** (stdlib only).
- **Fail-safe integrations.** DefectDojo, Dependency-Track, PR comments, and the
  token broker are all failure-isolated — an outage is logged and **never** changes
  the gate outcome.

**Reporting a vulnerability:** please use [GitHub private vulnerability
reporting](https://github.com/MagmaMoose/chargate/security/advisories/new) or see
[`SECURITY.md`](SECURITY.md). Please do not open a public issue for security reports.

## What MegaLinter covers (vs the old hand-rolled set)

Trivy, Semgrep, Checkov, Hadolint, ShellCheck, actionlint, ESLint, kubeconform/
kube-score all map to MegaLinter linters. Dependency/SCA scanning (formerly
pip-audit / npm audit / govulncheck) is covered by `REPOSITORY_OSV_SCANNER` +
`REPOSITORY_TRIVY` + `REPOSITORY_GRYPE`. Secrets scanning moved from TruffleHog to
MegaLinter's native `gitleaks` / `secretlint` / `kingfisher`.

## Migrating from v1

v1 was a composite action that fetched a hand-rolled scanner runtime from
`MagmaMoose/platform`. v2 is a MegaLinter wrapper with net-new gating, in-repo.

| v1 | v2 |
| --- | --- |
| `security` / `lint` / `enable_sast` toggles, per-tool inputs (`trivy_severity`, `semgrep_config`, …) | Configure MegaLinter via `.mega-linter.yml` + `flavor` / `enable_linters` / `disable_linters`. |
| `security_fail` / `lint_fail` | `fail_on` (severity threshold over net-new). |
| `strict` | `strict` (MegaLinter tool error fails the job). |
| Outputs `security_result` / `lint_result` / `scan_skipped` | Outputs `gate_result`, `net_new_count`, `total_count`, `sarif_path`, `mode`. |
| Blocks on all findings | Blocks only on **net-new** findings. |

The **`v1` tag is frozen** on the old runtime, so existing pins keep working until
you migrate. Move to the `v2` composite action when ready.

## Documentation & contributing

- **Full docs** (MkDocs): [architecture](docs/architecture.md) ·
  [net-new gating](docs/net-new.md) · [setup & usage](docs/setup.md) ·
  [CLI reference](docs/cli.md). Preview locally with `uv run --group docs mkdocs serve`.
- **Contributing:** issues and PRs are welcome — see [`CONTRIBUTING.md`](CONTRIBUTING.md).
  Dev stack: Python ≥ 3.11, **uv + Ruff + pytest**, full type hints, stdlib-only core.
  External GitHub Actions are SHA-pinned; releases are automated (Conventional Commits
  → semantic-release), so never bump the version by hand.
- **Security policy:** [`SECURITY.md`](SECURITY.md).

## License

MIT © Caleb Sargeant. See [LICENSE](LICENSE).
