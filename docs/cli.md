# CLI reference

All three GitHub surfaces drive the same `chargate` CLI. Exit codes: `0` pass ·
`1` blocking net-new findings · `2` setup/usage error.

```sh
chargate <filter-sarif | ci | local | version> [options]
```

## `chargate filter-sarif`

The pure net-new filter: a SARIF report + a base/head → filtered SARIF + counts +
a gate exit code. Decoupled from GitHub Actions and unit-tested in isolation.

```sh
chargate filter-sarif --sarif report.sarif --base "$BASE" --head "$HEAD" \
    --out net-new.sarif --counts-json counts.json --fail-on any
```

| Flag | Default | Purpose |
| --- | --- | --- |
| `--sarif` | (required) | Path to the full SARIF report. |
| `--base` | (required) | Base ref/SHA (PR target). |
| `--head` | `HEAD` | Head ref/SHA. |
| `--repo` | `.` | Path to the git repository. |
| `--precision` | `line` | Net-new precision: `line` or `file`. |
| `--no-location-policy` | `ignore` | Treatment of results with no file location: `ignore` (never block) or `block`. |
| `--no-region-fallback` | off | Disable file-level fallback for changed-file results lacking a `startLine`. |
| `--strip-prefix` | — | Path prefix to strip from SARIF URIs before matching (repeatable). |
| `--no-merge-base` | off | Diff `base..head` directly instead of `merge-base(base, head)..head`. |
| `--out` / `--full-out` / `--counts-json` | — | Write the net-new SARIF / a copy of the full SARIF / counts JSON. |
| `--fail-on` | `any` | Severity threshold that blocks: `any\|critical\|high\|medium\|low\|none`. |
| `--no-gate` | off | Always exit `0` (report only). |
| `--quiet` | off | Suppress the human summary. |

## `chargate ci`

The full CI flow: run MegaLinter, preserve the full SARIF, gate on net-new (PR
events only), and optionally ship to the sinks (DefectDojo / Dependency-Track).
Each sink is active iff its host/URL flag is set.

```sh
chargate ci --mode auto --flavor all --sarif-out full.sarif
```

Key flags beyond the shared filter options:

| Flag | Default | Purpose |
| --- | --- | --- |
| `--mode` | `auto` | `auto` (from `GITHUB_EVENT_NAME`), `pr` (net-new gate), or `baseline` (no gate). |
| `--sarif` | — | Use an existing SARIF instead of running MegaLinter. |
| `--flavor` | `all` | MegaLinter flavor (`all` = full image). |
| `--megalinter-tag` | `v8` | MegaLinter image tag/digest. |
| `--enable-linter` / `--disable-linter` | — | Toggle a linter (repeatable). |
| `--sarif-out` / `--filtered-out` / `--counts-json` | — | Write the full / net-new / counts outputs. |
| `--strict` | off | Fail the job if MegaLinter itself errors. |
| `--defectdojo-url` | — | DefectDojo base URL (enables import of the full SARIF). |
| `--defectdojo-token-env` | `DEFECTDOJO_TOKEN` | Env var holding the DD API token. |
| `--dd-product` / `--dd-engagement` / `--dd-engagement-id` | — | DefectDojo targeting. |
| `--dd-import` / `--dd-no-close-old` / `--dd-insecure` | off | Use import (not reimport) / keep old findings / skip TLS verify. |
| `--dependency-track-url` | — | Dependency-Track base URL (enables CycloneDX BOM upload). |
| `--dt-api-key-env` | `DEPENDENCYTRACK_API_KEY` | Env var holding the DT API key. |
| `--bom` | — | Path to the CycloneDX BOM to upload (the action generates this with Syft). |
| `--dt-project-name` / `--dt-project-version` / `--dt-project-uuid` | — | Dependency-Track project targeting. |
| `--dt-no-auto-create` / `--dt-is-latest` / `--dt-insecure` | off | Don't auto-create the project / mark latest / skip TLS verify. |

## `chargate local`

Fast staged-file checks for pre-commit (gitleaks + ruff, each skipped if the tool
is absent). A first line, deliberately narrower than the full CI net.

```sh
chargate local path/to/file.py     # pre-commit passes the staged files
chargate local                      # no args -> checks staged files
```

## `chargate version`

Prints the chargate version (also `chargate --version`).
