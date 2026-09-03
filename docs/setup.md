# Setup & usage

<!-- sources: action.yml, .pre-commit-hooks.yaml, scripts/request-app-token.sh -->

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
  pull-requests: write   # required for Chargate's PR comments (read if pr_comment: false)
  security-events: write

jobs:
  chargate:
    runs-on: ubuntu-latest
    steps:
      - uses: magmamoose/chargate@v2
        with:
          fail_on: high          # block only on net-new high/critical (default: any)
          # ignore_sops_encrypted: 'false'  # gate on SOPS-encrypted values too (dropped by default)
          # pr_comment: 'false'  # turn off the GHAS-style PR comments (on by default)
          # defectdojo_url: https://dd.example.com
          # defectdojo_token: ${{ secrets.DEFECTDOJO_TOKEN }}
          # dependency_track_url: https://dtrack.example.com
          # dependency_track_api_key: ${{ secrets.DEPENDENCYTRACK_API_KEY }}
```

On PRs it uses MegaLinter's focused `security` flavor and requests changed-files
analysis, gates on net-new findings, and ships the full SARIF. Repository-level
security scanners may still inspect the whole repo or history. On push to the default
branch it runs a non-gating whole-repo baseline scan. Set `flavor: all` for the full
lint image, `flavor: quality` for the [curated quality set](#the-quality-flavor), or
`incremental: 'false'` for a whole-repo PR scan. The action checks out
with `fetch-depth: 0` by default (net-new needs the merge-base), set
`checkout: 'false'` if you already checked out with full history.

## 2. pre-commit hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/MagmaMoose/chargate
    rev: v2
    hooks:
      - id: chargate
```

```sh
pre-commit install
pre-commit run -a
```

The hook (`language: python`, no Docker) runs a **fast staged-file subset**
(gitleaks for secrets, ruff for Python, each skipped if not installed). It is a
first line, deliberately narrower than the CI whole-repo net. Local/CI disparity
is intended.

## Global hook install (all repos)

Rather than adding `.pre-commit-config.yaml` to each repo, install Chargate's hooks
**once, globally** so they apply to every existing and future repo:

```sh
brew install calebsargeant/tap/chargate   # brings pre-commit along as a dependency
chargate install-hooks
```

`install-hooks` generates `pre-commit` + `pre-push` + `commit-msg` dispatchers
pointed at a global `~/.pre-commit-config.yaml`, sets `core.hooksPath` (retroactive
across existing repos) and `init.templateDir` (new clones inherit them). It also
installs the file-hygiene hooks (`actions-pin-sha`, `conventional-branch-name`).

Chargate's entries live inside a regenerated `>>> chargate-managed >>>` block:
**add your own repos/hooks outside that block and they're preserved** on every
reinstall. It refuses to clobber a hand-maintained config unless you pass `--force`,
and `chargate uninstall-hooks` reverts everything (restoring any prior
`core.hooksPath`).

!!! warning "It repoints your global `core.hooksPath`"
    If you already have global hooks at another path they stop running (intended:
    that's how Chargate takes over); the prior path is saved and restored on
    `uninstall-hooks`.

See the [CLI reference](cli.md#chargate-install-hooks) for flags.

## PR comments (GHAS-style)

On pull requests Chargate posts feedback the way GitHub Advanced Security does:
scoped to **net-new findings only**, so it stays quiet:

- **One summary comment** that is *updated in place* on every push (found by a
  hidden marker and `PATCH`ed, never duplicated).
- **Inline review comments** on each net-new finding that sits on a changed line.
  Prior Chargate inline comments are deleted and re-posted each run, so they never
  stack. Findings without a precise changed line (project-level, or SCA on a
  lockfile) are listed in the summary instead.

When the full SARIF / BOM are shipped to DefectDojo / Dependency-Track, the summary
comment footer links straight to the imported Test and project there.

It is **on by default** and needs `pull-requests: write` on the workflow. Toggle
and tune it with the action inputs:

| Input | Default | Effect |
|-------|---------|--------|
| `pr_comment` | `true` | Post the PR comments (set `false` to disable). |
| `pr_comment_mode` | `both` | `summary`, `inline`, or `both`. |
| `pr_comment_max_inline` | `50` | Cap on inline comments; the rest stay in the summary. |
| `pr_comment_token` | `github_token` | Explicit override token for authorship (usually unset, see below). |
| `token_broker_url` | `https://broker-chargate.magmamoose.com` | Token broker for `Chargate[bot]` authorship; empty disables. |
| `oidc_audience` | `chargate` | OIDC audience for the broker exchange (advanced). |

**Comment as `Chargate[bot]` (opt-in, zero key management).** By default the
comments are authored by `github-actions[bot]` (the default `GITHUB_TOKEN`'s
identity, which can't be renamed). To have them posted by **`Chargate[bot]`**
instead, with its own name + avatar:

1. **Install the Chargate GitHub App** on your org/repo.
2. Add **`id-token: write`** to the workflow's `permissions`.

```yaml
permissions:
  contents: read
  pull-requests: write
  id-token: write          # exchange OIDC for a Chargate[bot] token
  security-events: write
```

That's it, no app keys to manage. The action exchanges the run's OIDC token at the
Chargate token broker for a short-lived token scoped to your repo with
`pull_requests: write` only. It is **fail-soft**: without `id-token: write`, or if
the App isn't installed, comments simply fall back to `github-actions[bot]`.

*Self-hosted alternative:* if you'd rather not depend on the broker, bring your own
App token, `actions/create-github-app-token` → pass it as `pr_comment_token` (it
takes precedence over the broker). That App needs only **Pull requests: write**.

**Less noise, one surface per finding.** To avoid double-reporting, the full
SARIF is uploaded to the Security tab only on **non-PR events** (the default-branch
baseline keeps the inventory current). On PRs the native code-scanning diff
annotations are therefore suppressed, leaving Chargate's comments as the sole
PR-diff surface. The full, unfiltered SARIF is still always shipped (Security tab
on push, artifact, and any configured sink).

## Sinks (DefectDojo & Dependency-Track)

Both external sinks share one enable rule: **set a Variable for the host and a
Secret for the credential. The sink is active iff the host is set.** No separate
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

The uploaded SARIF carries a leading findings-free `chargate` run. DefectDojo derives a
Test's type from `runs[0].tool.driver.name` alone, and MegaLinter's merged report has no
stable first run, whichever linter emitted first wins, which follows the file types in
the diff. Without that stamp the derived type changes from PR to PR and `reimport-scan`
returns HTTP 400 `Test type mismatch`, so the full SARIF silently stops arriving. Your
Tests are therefore typed `chargate Scan (SARIF)`; if an engagement already holds a Test
typed by an earlier tool, Chargate retries once against `import-scan` to create a
correctly-typed one and reimports into that from then on.

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
API key needs `BOM_UPLOAD` (plus `PROJECT_CREATION_UPLOAD` for auto-create, and
`VIEW_PORTFOLIO` so the PR-comment footer can resolve the project's UUID into a
link, without it the upload still succeeds, just with no link).

**Upload happens on push / tags only.** Dependency-Track tracks *shipped*
artifacts, so the BOM is generated and uploaded only on non-PR events (push to the
default branch, tags). On pull requests Chargate skips the upload entirely, no
throwaway per-PR versions, faster PR CI, and instead links the PR comment to the
project's existing default-branch version. (DefectDojo still imports the full SARIF
on PRs, since reimport updates one Test rather than spawning versions.)

## MegaLinter configuration

Chargate injects the critical env (`DISABLE_ERRORS`, `SARIF_REPORTER`,
`JSON_REPORTER`, `SARIF_REPORTER_NORMALIZE_LINTERS_OUTPUT`, `REPORT_OUTPUT_FOLDER`)
so the gate is always Chargate's. Drop a `.mega-linter.yml` at your repo root to
tune which linters run; it is additive to the injected env.

`REPORT_OUTPUT_FOLDER` is injected as an **absolute container path**
(`/tmp/lint/megalinter-reports`) and must stay one. MegaLinter uses the value
verbatim and its images declare `WORKDIR /`, so a relative value resolves to
`/megalinter-reports` *inside* the container, outside the bind mount, and destroyed
by `docker run --rm`. Do not override it to a relative path in `.mega-linter.yml`.

Images come from `ghcr.io/oxsecurity` at `v10.0.0` by default. MegaLinter froze Docker
Hub publishing at `v9.4.0`, so `docker.io` cannot serve any current version. Point
`megalinter_registry` / `megalinter_namespace` at a mirror if you need one, or
`megalinter_image` at a full reference to bypass name composition entirely.

### The `quality` flavor

`flavor: quality` is **not** a MegaLinter flavor. MegaLinter publishes no
`megalinter-quality` image, so Chargate curates the set itself: five SARIF-emitting
quality linters, run as per-linter `megalinter-only-*` containers.

| Linter | Covers |
| --- | --- |
| `GO_GOLANGCI_LINT` | Go — the meta-linter, so `GO_REVIVE` would be redundant. |
| `JAVASCRIPT_ES` | JavaScript (ESLint). |
| `TYPESCRIPT_ES` | TypeScript (ESLint). |
| `JAVA_PMD` | Java bugs and code smells. |
| `PYTHON_RUFF` | Python — the flake8 / isort / pyupgrade families in one container. |

**Five, not a flavor's worth, deliberately.** MegaLinter's quality half over a mature
repo produces hundreds of net-new findings on the first pull request, because "changed
line touched by a formatter-opinionated linter" is a far denser event than "changed line
with a security finding". A gate that goes red with 200 findings on its first real PR
gets switched off, and then it is decoration. The set starts at five that earn their
noise and grows from evidence. `JAVA_CHECKSTYLE` is verified and available via
`standalone_linters`, but is not in the set: it reports formatting opinion, which is the
densest noise there is.

Every entry is disjoint from the `security` set, so a repo running both gates never has
one finding block it twice. There is **no .NET entry**: at MegaLinter `v10.0.0` no
C#/VB.NET linter sets `can_output_sarif`, so none of them could reach the net-new gate
at all. Said here rather than discovered later by a .NET team whose quality gate reports
zero findings forever.

!!! note "It always runs standalone, on every architecture"
    With no flavor image to run, `quality` takes the per-linter path on amd64 too — the
    one place every other flavor uses a single container. `arch_strategy: flavor` or
    `fail` therefore cannot be honoured and Chargate raises, naming this reason rather
    than the arm64 guidance, which would be a confusing answer to a question nobody
    asked. `arch_strategy: auto` (the default) is the strategy this flavor supports.
    Setting `megalinter_image` overrides all of it: an image has been named, so Chargate
    stops reasoning about what upstream publishes and runs it.

Quality linters emit a SARIF `level` and no numeric `security-severity`, which decides
how you threshold over them — see
[the band note in Consuming the output](consuming-output.md#the-counts-document).

### Kubernetes manifests

MegaLinter's `KUBERNETES` descriptor has three linters and the `security` flavor runs
two of them:

| Linter | What it checks | On the net-new gate? |
| --- | --- | --- |
| `KUBERNETES_KUBESCAPE` | Security posture (misconfig, RBAC, …) | **Yes**, it emits SARIF. |
| `KUBERNETES_KUBECONFORM` | Manifest schema validation | No SARIF; fails the job only under `strict: true`. |

`kube-score` has **no** MegaLinter descriptor, so there is no linter key to enable. Run
it as a standalone [pre-commit hook](https://github.com/zegl/kube-score) if you want it.

The chargate-recommended `.mega-linter.yml` enables `KUBERNETES_KUBECONFORM` with
`--ignore-missing-schemas` (so CRDs without a published schema are not false errors) and
an exclude regex that keeps it off files that are not standalone manifests:

- **Kustomize / Flux overlays and patches** are fragments, not whole objects. kubeconform
  validates finished manifests, so render first (`kustomize build ./overlay | kubeconform`
  or [`flux-local`](https://github.com/allenporter/flux-local)) and validate the output:
  the security image ships kubeconform but not kustomize, so rendering runs outside it.
- **SOPS-encrypted secrets** (`*.sops.yaml`, `secret*`) are ciphertext, not valid YAML.
- **Chart templates** (`/templates/`) and CI config (`.github/`) are not K8s objects.

Tune the pattern for your layout via `KUBERNETES_KUBECONFORM_FILTER_REGEX_EXCLUDE`.

## Troubleshooting

**`exec /bin/bash: exec format error`**: the runner is arm64 and MegaLinter's flavor
images are `linux/amd64` only. Chargate's default `arch_strategy: auto` avoids this by
running the multi-arch per-linter images instead; you see this error only with
`arch_strategy: flavor`, and Chargate replaces it with a message naming the alternatives.
See [Architecture support](https://github.com/MagmaMoose/chargate#architecture-support).

**"MegaLinter linted 0 files" on a containerised (ARC / docker-in-docker) runner**, the
`-v` bind mount is resolved by the *host* Docker daemon, not by the job container, so the
workspace path must exist on the host with the same path. Mount the runner's work
directory through at an identical path, or run Chargate on a runner with a local daemon.

**"Permission denied" writing `megalinter-reports/` on a containerised runner**, Chargate
passes `MEGALINTER_UID`/`MEGALINTER_GID` from the calling process so the report tree is not
left root-owned on a self-hosted runner. Where the job user and the workspace owner differ,
that drops MegaLinter to a uid that cannot write, and the symptom is an empty scan rather
than an obvious error. Override on the step, no action input needed:

```yaml
- uses: magmamoose/chargate@v2
  env:
    MEGALINTER_UID: '0'
    MEGALINTER_GID: '0'
```

**The gate reports `net-new 0 / 0 total` on every PR**, the scan produced nothing.
Chargate prints `ERROR: MegaLinter's SARIF contains no runs` and fails the job with
exit `2`, with or without `strict`, because a gate that scanned nothing must not
report a pass. Check `REPORT_OUTPUT_FOLDER` (above) first.

**`actions/setup-python` fails with "version not found" on arm64**, `setup-python`
publishes `linux/arm64` builds only for the Ubuntu 22.04/24.04/26.04 images. Set
`setup_python: 'false'` and provide Python 3.11+ on the runner image; Chargate is
stdlib-only pure Python and needs nothing else.

**PR comments are authored by `github-actions[bot]` instead of `Chargate[bot]`**, the
token broker step is fail-soft and logs a `::warning::` with the reason. On a minimal
self-hosted image the usual reason is a missing `jq` or `curl`.

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
