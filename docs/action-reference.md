# Action reference

<!-- sources: action.yml -->

Every input and output of the `magmamoose/chargate` composite action, read from
`action.yml`. For the task-shaped version with worked examples, see
[Setup and usage](setup.md). For the CLI these inputs drive, see the
[CLI reference](cli.md).

## Inputs

All 43 inputs are optional. A blank default means the action leaves the
value unset and the CLI's own default applies.

| Input | Default | Description |
| --- | --- | --- |
| `checkout` | `true` | Run actions/checkout first. Net-new gating needs full history (fetch-depth 0). |
| `fetch_depth` | `0` | Checkout fetch-depth. MUST be 0 for net-new gating (merge-base). |
| `mode` | `auto` | auto \| pr (net-new gate) \| baseline (full scan, no gate). |
| `fail_on` | `any` | Severity that blocks: any \| critical \| high \| medium \| low \| none. |
| `precision` | `line` | Net-new precision: line \| file. |
| `base_ref` | (none) | Override the base ref/SHA (default: PR base SHA from the event). |
| `head_ref` | (none) | Override the head ref/SHA (default: PR head SHA, else github.sha). |
| `strict` | `false` | Fail the job if MegaLinter itself errors (a tool error, not a finding). A SARIF with no runs fails regardless. |
| `flavor` | `security` | MegaLinter flavor: security (default) \| all (full lint image) \| python \| go \| ... |
| `megalinter_registry` | (none) | Registry host for the MegaLinter images. Default ghcr.io, MegaLinter froze Docker Hub publishing at v9.4.0, so docker.io cannot serve v9.5.0+ at all. Point this at a mirror or pull-through cache if you have one. |
| `megalinter_namespace` | (none) | Image namespace under the registry. Default oxsecurity. |
| `megalinter_image` | (none) | Full image reference, overriding registry + namespace + flavor + tag entirely. Use it for a MegaLinter custom flavor (e.g. ghcr.io/you/repo/megalinter-custom-flavor:v10.0.0, the supported way to get a single-image arm64 build) or an internal mirror. When set, Chargate never composes an image name. |
| `megalinter_tag` | (none) | MegaLinter image tag, or a `sha256:...` digest to pin. Default v10.0.0 (the immutable release tag, not the floating `v10` alias). |
| `docker_platform` | (none) | Value for `docker run --platform`. Only needed to force emulation, e.g. linux/amd64 on an arm64 runner that has qemu-user-static + binfmt installed. Setting it also tells Chargate you have taken responsibility for the architecture, so it stops substituting the per-linter images. |
| `arch_strategy` | `auto` | How to run MegaLinter when the Docker daemon is not linux/amd64. auto (default): the flavor image on amd64, MegaLinter's per-linter `megalinter-only-*` images (multi-arch from v10.0.0) on arm64. flavor: always the flavor image, fails fast with an actionable error on arm64 instead of `exec format error`. standalone: always per-linter images. fail: refuse to run rather than degrade. |
| `standalone_linters` | (none) | Comma-separated MegaLinter linter keys to run in standalone mode. Default: the SARIF-emitting linters of the selected flavor. |
| `enable_linters` | (none) | Comma-separated MegaLinter linter keys to enable (others off). |
| `disable_linters` | (none) | Comma-separated MegaLinter linter keys to disable. |
| `incremental` | `true` | PR events only: ask MegaLinter to analyze just the files the PR changes (VALIDATE_ALL_CODEBASE=false) instead of the whole repo, faster on large repos. Repository-level scanners may still read the whole repo or history. The net-new gate still uses Chargate's own diff. Baseline (push) scans are always whole-repo. Default on. |
| `ignore_sops_encrypted` | `true` | Ignore secret-scanner hits on SOPS-encrypted values (ENC[AES256_GCM,...]), they are already encrypted and are 100% false positives. A plaintext secret in the same file still gates. Set to false to gate on them anyway. Default on. |
| `emit_sarif_artifact` | `true` | Upload the full SARIF as a build artifact. |
| `sarif_artifact_name` | `chargate-sarif` | Artifact name for the full SARIF. |
| `upload_github_sarif` | `true` | Upload the full SARIF to the GitHub Security tab (needs GHAS on private repos). |
| `github_token` | (none) | Token for the GitHub Security-tab SARIF upload + PR comments. Needs pull-requests: write on the consumer workflow for comments. |
| `pr_comment` | `true` | Post GHAS-style PR comments for net-new findings (PR events only). Needs pull-requests: write. |
| `pr_comment_mode` | `both` | What to post: summary (one updatable comment) \| inline (per-line) \| both. |
| `pr_comment_max_inline` | `50` | Cap on inline comments per run; the rest are listed in the summary. |
| `pr_comment_token` | (none) | Explicit override token used ONLY to author the PR comments (BYO GitHub App via actions/create-github-app-token). Usually unset: with id-token: write the token broker provides a Chargate[bot] token automatically. |
| `token_broker_url` | `https://broker-chargate.magmamoose.com` | Chargate token-broker base URL. With job permission id-token: write and the Chargate App installed, comments are authored by Chargate[bot]. Set empty to disable (fall back to github-actions[bot]). |
| `oidc_audience` | `chargate` | OIDC audience requested for the token-broker exchange (advanced). |
| `defectdojo_url` | (none) | DefectDojo base URL. Set to enable import of the FULL SARIF. |
| `defectdojo_token` | (none) | DefectDojo API token (pass a secret). Used only if defectdojo_url is set. |
| `defectdojo_product` | (none) | DefectDojo product name (auto-created if missing). Defaults to the repo name. |
| `defectdojo_product_type` | `Research and Development` | DefectDojo product type name (used to auto-create a new product). |
| `defectdojo_engagement` | `ci` | DefectDojo engagement name (auto-created if missing). |
| `defectdojo_close_old` | `true` | Close findings no longer present on reimport. |
| `dependency_track_url` | (none) | Dependency-Track base URL. Set to enable the CycloneDX BOM upload (pass a Variable). |
| `dependency_track_api_key` | (none) | Dependency-Track API key (pass a Secret). Needs BOM_UPLOAD (+ PROJECT_CREATION_UPLOAD for auto-create, + VIEW_PORTFOLIO for the PR-comment project link). |
| `dependency_track_project_name` | (none) | Dependency-Track project name (auto-created if missing). |
| `dependency_track_project_version` | (none) | Dependency-Track project version. |
| `dependency_track_auto_create` | `true` | Auto-create the project/version on first upload. |
| `setup_python` | `true` | Run actions/setup-python. Set false on a runner that already has a suitable Python 3.11+, setup-python only publishes linux/arm64 builds for the Ubuntu 22.04/24.04/26.04 images, so on any other arm64 self-hosted/ARC image it fails with "version not found". Chargate itself is stdlib-only pure Python and runs anywhere. |
| `python_version` | `3.12` | Python version used to run the chargate CLI. |

One `flavor` value is not a MegaLinter flavor: `quality` is a five-linter set Chargate
curates itself and runs as per-linter images on every architecture. See
[The `quality` flavor](setup.md#the-quality-flavor).

## Outputs

| Output | Description |
| --- | --- |
| `mode` | Resolved run mode (pr \| baseline). |
| `gate_result` | pass \| fail. |
| `net_new_count` | Number of net-new (PR-introduced) findings. |
| `total_count` | Total findings in the full SARIF (net-new + pre-existing). |
| `sarif_path` | Path to the full (unfiltered) SARIF report. |
| `filtered_sarif_path` | Path to the net-new-only SARIF (`chargate-reports/net-new.sarif`). Written on every run, baseline included, where the net-new set is empty by construction. |
| `counts_path` | Path to the counts JSON (`chargate-reports/counts.json`), the versioned document a downstream gate reads. Written on every run. See [Consuming the output](consuming-output.md). |
| `scan_mode` | How MegaLinter actually ran: flavor (the flavor image) \| standalone (per-linter megalinter-only-* images, the arm64 path) \| provided (an existing SARIF was passed in). Assert on this to fail a release job that would otherwise ship on a reduced scan. |
| `linters_skipped` | Linters standalone mode could not run, with the reason for each (empty otherwise). |

Read them with `steps.<id>.outputs.<name>`:

```yaml
      - uses: magmamoose/chargate@v2
        id: gate
      - if: steps.gate.outputs.scan_mode != 'flavor'
        run: |
          echo "reduced scan: ${{ steps.gate.outputs.linters_skipped }}"
          exit 1
```

That example is the reason `scan_mode` exists: on arm64 the action falls back to
per-linter images, and a release job can refuse to ship on a reduced scan.
