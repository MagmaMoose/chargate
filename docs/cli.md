# CLI reference

<!-- sources: src/chargate/cli.py, src/chargate/gate.py -->

Both GitHub surfaces drive the same `chargate` CLI. Exit codes: `0` pass ·
`1` blocking net-new findings · `2` setup/usage error.

```sh
chargate <filter-sarif | ci | local | install-hooks | uninstall-hooks | version> [options]
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
| `--no-sops-ignore` | off | Gate on secret-scanner hits even on SOPS-encrypted values (`ENC[AES256_GCM,...]`). By default these are dropped as false positives, see [Net-new gating](net-new.md#sops-encrypted-secrets). |
| `--strip-prefix` |, | Path prefix to strip from SARIF URIs before matching (repeatable). |
| `--no-merge-base` | off | Diff `base..head` directly instead of `merge-base(base, head)..head`. |
| `--out` / `--full-out` / `--counts-json` |, | Write the net-new SARIF / a copy of the full SARIF / counts JSON. |
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

Every image-selection flag also reads a `CHARGATE_*` env var when the flag is
omitted (`CHARGATE_MEGALINTER_REGISTRY`, `CHARGATE_MEGALINTER_NAMESPACE`,
`CHARGATE_MEGALINTER_IMAGE`, `CHARGATE_MEGALINTER_TAG`, `CHARGATE_DOCKER_PLATFORM`,
`CHARGATE_ARCH_STRATEGY`, `CHARGATE_JOBS`), so a self-hosted runner fleet can point
every repo at an internal mirror without editing any workflow. Explicit flag beats
env var beats built-in default.

Key flags beyond the shared filter options:

| Flag | Default | Purpose |
| --- | --- | --- |
| `--mode` | `auto` | `auto` (from `GITHUB_EVENT_NAME`), `pr` (net-new gate), or `baseline` (no gate). |
| `--sarif` |, | Use an existing SARIF instead of running MegaLinter. |
| `--flavor` | `all` | MegaLinter flavor (`all` = full image). |
| `--megalinter-tag` | `v10.0.0` | MegaLinter image tag, or a `sha256:…` digest to pin. |
| `--megalinter-registry` | `ghcr.io` | Registry host. Docker Hub is frozen at `v9.4.0`, so it cannot serve `v9.5.0+`. |
| `--megalinter-namespace` | `oxsecurity` | Image namespace (set for a mirror / pull-through cache). |
| `--megalinter-image` |, | Full image reference, overriding registry/namespace/flavor/tag entirely. |
| `--docker-platform` |, | Value for `docker run --platform` (e.g. `linux/amd64` to force emulation). |
| `--arch-strategy` | `auto` | `auto` (flavor image on amd64, per-linter images on arm64) · `flavor` · `standalone` · `fail`. |
| `--standalone-linter` |, | Linter key for standalone mode (repeatable). Default: the flavor's SARIF-emitting set. |
| `--jobs` | `4` | Standalone mode: concurrent linter containers. |
| `--enable-linter` / `--disable-linter` |, | Toggle a linter (repeatable). |
| `--incremental` | off | PR/gate mode only. Runs MegaLinter over just the files changed vs the base (`VALIDATE_ALL_CODEBASE=false`) instead of the whole repo. The net-new gate still uses chargate's own diff, so this changes scan cost, not the verdict. |
| `--default-branch` | `""` | Base branch for incremental change detection. Sets MegaLinter's `DEFAULT_BRANCH`. |
| `--sarif-out` / `--filtered-out` / `--counts-json` |, | Write the full / net-new / counts outputs. |
| `--strict` | off | Fail the job if MegaLinter itself errors. (A SARIF with no runs fails without it, see [architecture](architecture.md).) |
| `--defectdojo-url` |, | DefectDojo base URL (enables import of the full SARIF). |
| `--defectdojo-token-env` | `DEFECTDOJO_TOKEN` | Env var holding the DD API token. |
| `--dd-product` / `--dd-engagement` / `--dd-engagement-id` |, | DefectDojo targeting. |
| `--dd-product-type` |, | DefectDojo product type name. Required only when the product does not exist yet and has to be auto-created. |
| `--dd-test-title` |, | Title for the DefectDojo test. |
| `--dd-tag` |, | Tag to attach to the import. Repeatable. |
| `--dd-import` / `--dd-no-close-old` / `--dd-insecure` | off | Use import (not reimport) / keep old findings / skip TLS verify. |
| `--dependency-track-url` |, | Dependency-Track base URL (enables CycloneDX BOM upload). |
| `--dt-api-key-env` | `DEPENDENCYTRACK_API_KEY` | Env var holding the DT API key. |
| `--bom` |, | Path to the CycloneDX BOM to upload (the action generates this with Syft). |
| `--dt-project-name` / `--dt-project-version` / `--dt-project-uuid` |, | Dependency-Track project targeting. |
| `--dt-parent-name` / `--dt-parent-version` |, | Parent project, when you keep Dependency-Track projects in a hierarchy. |
| `--dt-no-auto-create` / `--dt-is-latest` / `--dt-insecure` | off | Don't auto-create the project / mark latest / skip TLS verify. |
| `--pr-comment` | off | Post GHAS-style PR comments for net-new findings (PR/gate mode only). |
| `--pr-number` / `--repo-slug` |, | Pull request number and `owner/repo` to comment on. |
| `--github-token-env` | `GITHUB_TOKEN` | Env var with a token that has `pull-requests: write`. |
| `--pr-comment-mode` | `both` | `summary` (one updatable comment), `inline`, or `both`. |
| `--pr-comment-max-inline` | `50` | Cap on inline comments; the rest stay in the summary. |
| `--pr-comment-insecure` | off | Skip TLS verification for the GitHub API (GHES testing). |

PR comments are net-new only and failure-isolated: a GitHub API error is logged and
never changes the gate outcome. The host action sets `--pr-number` / `--repo-slug`
from the event and honors `GITHUB_API_URL` for GHES.

## `chargate local`

Fast staged-file checks for pre-commit (gitleaks + ruff, each skipped if the tool
is absent). A first line, deliberately narrower than the full CI net.

```sh
chargate local path/to/file.py     # pre-commit passes the staged files
chargate local                      # no args -> checks staged files
```

## `chargate install-hooks`

Wire Chargate's git hooks into **every** repo globally, using the
[pre-commit](https://pre-commit.com) framework (which must be installed). It
generates `pre-commit` + `pre-push` + `commit-msg` dispatchers pointed at a global
`~/.pre-commit-config.yaml`, sets `core.hooksPath` (so the hooks apply to existing
repos immediately) and `init.templateDir` (so new clones inherit them).

```sh
chargate install-hooks          # refuses to clobber a hand-maintained config
chargate install-hooks --force  # overwrite a non-chargate ~/.pre-commit-config.yaml
```

Chargate's hooks live inside a regenerated `>>> chargate-managed >>>` block; any
repos you add outside that block are preserved on reinstall. Installed via Homebrew,
`brew install calebsargeant/tap/chargate` brings `pre-commit` along. See
[Setup → Global hook install](setup.md#global-hook-install-all-repos) for the full
walkthrough.

## `chargate uninstall-hooks`

Revert `install-hooks`, restoring (or unsetting) the prior global `core.hooksPath`
and `init.templateDir`.

```sh
chargate uninstall-hooks
```

## `chargate version`

Prints the chargate version (also `chargate --version`).
