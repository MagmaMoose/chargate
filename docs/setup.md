# Setup & usage

## 1. Reusable workflow (recommended)

```yaml
# .github/workflows/security.yml
name: Security
on:
  pull_request:
  push:
    branches: [main]

jobs:
  chargate:
    uses: magmamoose/chargate/.github/workflows/gate.yml@v2
    secrets:
      defectdojo_token: ${{ secrets.DEFECTDOJO_TOKEN }}   # optional
```

On PRs it runs MegaLinter whole-repo, gates on net-new findings, and ships the
full SARIF. On push to the default branch it runs a non-gating baseline scan.
Reusable workflows are consumed by path, independent of the Marketplace listing.

## 2. Composite action

```yaml
name: Security
on: [pull_request]

permissions:
  contents: read
  pull-requests: write   # required for Chargate's PR comments (read if pr_comment: false)
  security-events: write

jobs:
  chargate:
    runs-on: ubuntu-latest
    steps:
      - uses: magmamoose/chargate@v2
        with:
          fail_on: high          # block only on net-new high/critical (default: any)
          # pr_comment: 'false'  # turn off the GHAS-style PR comments (on by default)
          # defectdojo_url: https://dd.example.com
          # defectdojo_token: ${{ secrets.DEFECTDOJO_TOKEN }}
          # dependency_track_url: https://dtrack.example.com
          # dependency_track_api_key: ${{ secrets.DEPENDENCYTRACK_API_KEY }}
```

The action checks out with `fetch-depth: 0` by default (net-new needs the
merge-base). Set `checkout: 'false'` if you already checked out with full history.

## 3. pre-commit hook

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

## PR comments (GHAS-style)

On pull requests Chargate posts feedback the way GitHub Advanced Security does —
scoped to **net-new findings only**, so it stays quiet:

- **One summary comment** that is *updated in place* on every push (found by a
  hidden marker and `PATCH`ed, never duplicated).
- **Inline review comments** on each net-new finding that sits on a changed line.
  Prior Chargate inline comments are deleted and re-posted each run, so they never
  stack. Findings without a precise changed line (project-level, or SCA on a
  lockfile) are listed in the summary instead.

It is **on by default** and needs `pull-requests: write` on the workflow. Toggle
and tune it with the action inputs:

| Input | Default | Effect |
|-------|---------|--------|
| `pr_comment` | `true` | Post the PR comments (set `false` to disable). |
| `pr_comment_mode` | `both` | `summary`, `inline`, or `both`. |
| `pr_comment_max_inline` | `50` | Cap on inline comments; the rest stay in the summary. |

**Less noise — one surface per finding.** To avoid double-reporting, the full
SARIF is uploaded to the Security tab only on **non-PR events** (the default-branch
baseline keeps the inventory current). On PRs the native code-scanning diff
annotations are therefore suppressed, leaving Chargate's comments as the sole
PR-diff surface. The full, unfiltered SARIF is still always shipped (Security tab
on push, artifact, and any configured sink).

## Sinks (DefectDojo & Dependency-Track)

Both external sinks share one enable rule: **set a Variable for the host and a
Secret for the credential — the sink is active iff the host is set.** No separate
on/off toggle. Both are optional, first-class, and failure-isolated (a sink outage
is logged and never fails the gate).

### DefectDojo

Uploads the **full** SARIF (never the filtered one):

```yaml
- uses: magmamoose/chargate@v2
  with:
    defectdojo_url: https://defectdojo.example.com   # active iff this is set
    defectdojo_token: ${{ secrets.DEFECTDOJO_TOKEN }}
    defectdojo_product: my-service
    defectdojo_product_type: Research and Development   # needed to auto-create a new product
    defectdojo_engagement: ci
```

Uses `reimport-scan` by default (one Test per engagement; `close_old_findings`
mitigates findings that disappear) and auto-creates the product/engagement.

### Dependency-Track

Generates a CycloneDX BOM (Syft, any language) and uploads it to your
Dependency-Track server:

```yaml
- uses: magmamoose/chargate@v2
  with:
    dependency_track_url: https://dtrack.example.com   # active iff this is set
    dependency_track_api_key: ${{ secrets.DEPENDENCYTRACK_API_KEY }}
    dependency_track_project_name: my-service          # defaults to the repo
    dependency_track_project_version: 1.2.3            # defaults to the ref name
```

Generates the BOM with `anchore/sbom-action` (Syft) and `POST`s it to
`/api/v1/bom` (multipart), auto-creating the project/version on first upload. The
API key needs `BOM_UPLOAD` (plus `PROJECT_CREATION_UPLOAD` for auto-create).

## MegaLinter configuration

Chargate injects the critical env (`DISABLE_ERRORS`, `SARIF_REPORTER`,
`JSON_REPORTER`, `SARIF_REPORTER_NORMALIZE_LINTERS_OUTPUT`, `REPORT_OUTPUT_FOLDER`)
so the gate is always Chargate's. Drop a `.mega-linter.yml` at your repo root to
tune which linters run; it is additive to the injected env.

## Migrating from v1

v1 was a composite action that fetched a hand-rolled scanner runtime from
`MagmaMoose/platform`. v2 is a MegaLinter wrapper with net-new gating, in-repo.

| v1 | v2 |
| --- | --- |
| `security` / `lint` / `enable_sast` toggles, per-tool inputs (`trivy_severity`, …) | Configure MegaLinter via `.mega-linter.yml` + `flavor` / `enable_linters` / `disable_linters`. |
| `security_fail` / `lint_fail` | `fail_on` (severity threshold over net-new). |
| `strict` | `strict` (MegaLinter tool error fails the job). |
| Outputs `security_result` / `lint_result` / `scan_skipped` | Outputs `gate_result`, `net_new_count`, `total_count`, `sarif_path`, `mode`. |
| Blocks on all findings | Blocks only on **net-new** findings. |

The **`v1` tag is frozen** on the old runtime, so existing pins keep working until
you migrate.

## Local development

```sh
uv sync                       # install deps + dev tools
uv run pytest -q              # run the test suite
uv run ruff check .          # lint
uv run ruff format --check . # format check (CI gate)
```

(If `uv` is not on PATH, `python -m uv ...` works after `pip install uv`.)

## Building these docs

```sh
uv run --group docs mkdocs serve   # live preview at http://127.0.0.1:8000
uv run --group docs mkdocs build   # render to ./site (gitignored)
```

The `docs` dependency group (`mkdocs-material`) lives in `pyproject.toml`; it is
non-default, so `uv sync` and CI are unaffected until you opt in with `--group
docs`.
