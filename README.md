# Chargate

[![License](https://img.shields.io/github/license/magmamoose/chargate)](LICENSE)

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

On PRs it runs MegaLinter whole-repo, gates on net-new findings, and ships the
full SARIF; on push to the default branch it runs a non-gating baseline scan. The
action checks out with `fetch-depth: 0` by default (net-new needs the merge-base) —
set `checkout: 'false'` if you already checked out with full history.

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

## Conventions

Python (uv + Ruff + pytest, type-hinted). External actions are SHA-pinned. MIT.

## License

MIT. See [LICENSE](LICENSE).
