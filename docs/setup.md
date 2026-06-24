# Setup & usage

## 1. Composite action (recommended)

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

## 2. pre-commit hook

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
    # Optional — these default to the repo name / "Research and Development" / "ci":
    # defectdojo_product: my-service
    # defectdojo_product_type: Research and Development   # used to auto-create a new product
    # defectdojo_engagement: ci
```

URL + token is all you need: `defectdojo_product` defaults to the repo name,
`defectdojo_product_type` to `Research and Development`, and `defectdojo_engagement`
to `ci`. Uses `reimport-scan` by default (one Test per engagement;
`close_old_findings` mitigates findings that disappear) and auto-creates the
product/engagement.

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
