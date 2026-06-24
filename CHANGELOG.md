# CHANGELOG

<!-- version list -->

## v2.5.1 (2026-06-24)

### Bug Fixes

- **ci**: Restore dropped release-workflow wiring + dedupe release.yaml
  ([`1ab0068`](https://github.com/MagmaMoose/chargate/commit/1ab00681b8a64619998f928cb17644c9e4697b4b))


## v2.5.0 (2026-06-24)

### Bug Fixes

- Bump the actions-version group across 1 directory with 3 updates
  ([`90367b7`](https://github.com/MagmaMoose/chargate/commit/90367b7aea7c956b4f8c2f4b23810d444e821bc5))


## v2.4.0 (2026-06-24)

### Bug Fixes

- **k8s**: Clear all 14 Chargate net-new findings (addresses self-gated review)
  ([`9703d61`](https://github.com/MagmaMoose/chargate/commit/9703d61cf5e1ad56d11bbf5f96eed1f01ba76744))

- **security.yml**: Suppress KICS id-token false positive with ignore-line
  ([`85563cd`](https://github.com/MagmaMoose/chargate/commit/85563cdd7105eb9351e9688d15213a9b43524da8))

### Features

- Author PR comments as Chargate[bot] via an OIDC token broker
  ([`3701126`](https://github.com/MagmaMoose/chargate/commit/3701126462c2b120f714ffa30ecd8e5d432c1d4d))


## v2.3.0 (2026-06-24)

### Chores

- Provision required workflows (caldrith)
  ([`be4ef0c`](https://github.com/MagmaMoose/chargate/commit/be4ef0c5eb99d6ab689a828aa78d5e05f0706ecc))

### Features

- Post GHAS-style PR comments for net-new findings
  ([`1386d64`](https://github.com/MagmaMoose/chargate/commit/1386d640c5c5b5f07e2ac78d3c654a831dd50960))


## v2.2.0 (2026-06-24)

### Chores

- Provision required workflows (caldrith)
  ([`81a93a4`](https://github.com/MagmaMoose/chargate/commit/81a93a49354ab2a1fa55ed4ab9f037e21e370a58))

### Features

- Make the composite action the single surface; minimal-config sinks
  ([`8bc02a5`](https://github.com/MagmaMoose/chargate/commit/8bc02a548c41fa27687e4d3a2076dac25e0ba625))


## v2.1.0 (2026-06-17)

### Bug Fixes

- Pass product_type_name to DefectDojo so auto-create works
  ([`c625a5b`](https://github.com/MagmaMoose/chargate/commit/c625a5b92981d3fdc7ff71428441dc7268f5c188))

- Send an identifying User-Agent on sink uploads (Cloudflare 1010)
  ([`696865b`](https://github.com/MagmaMoose/chargate/commit/696865b7253198823acf72e4d76bd651e00c6384))

- Upload BOM to Dependency-Track via POST multipart (proxy-friendly)
  ([`2c5017a`](https://github.com/MagmaMoose/chargate/commit/2c5017a2a4d4f20665f6ff57817c28ab9bca6488))

### Continuous Integration

- Trust the MagmaMoose tap before the Homebrew bump
  ([`af960c6`](https://github.com/MagmaMoose/chargate/commit/af960c6024ee5722dd4997f363be34c73a919a11))

### Features

- Optional Dependency-Track BOM sink, mirroring the DefectDojo sink
  ([`9ca11d6`](https://github.com/MagmaMoose/chargate/commit/9ca11d6385093788619fe1024b262844ea853908))


## v2.0.1 (2026-06-16)


## v2.0.0 (unreleased)

### BREAKING CHANGES

- Re-platformed onto **MegaLinter**: the hand-rolled 12-tool scanner orchestration
  (and its `MagmaMoose/platform` runtime fetch) is retired. MegaLinter does all
  scanning; Chargate adds **net-new (PR-diff) finding gating** as the differentiator.
- Inputs/outputs changed. Per-tool inputs (`trivy_severity`, `semgrep_config`,
  `enable_sast`, …) and `security`/`lint`/`security_fail`/`lint_fail` are replaced
  by MegaLinter config (`.mega-linter.yml`, `flavor`, `enable_linters`,
  `disable_linters`) plus `fail_on` (severity threshold over net-new findings).
  Outputs are now `gate_result`, `net_new_count`, `total_count`, `sarif_path`,
  `mode` (was `security_result`/`lint_result`/`scan_skipped`).
- Secrets scanning moved from TruffleHog to MegaLinter-native gitleaks /
  secretlint / kingfisher.
- The `v1` tag is frozen on the old runtime; existing pins keep working until
  migration. See the README "Migrating from v1" section.

### Features

- **Net-new SARIF filter** — a pure, deterministic, heavily unit-tested module
  (`chargate filter-sarif`): SARIF + base/head → filtered SARIF (net-new only) +
  the untouched full SARIF + counts. Line- or file-level precision; documented
  policies for new/renamed/deleted files, project-level findings, and shallow
  clones (fails loudly, needs `fetch-depth: 0`).
- **`chargate` Python CLI** (uv + Ruff): `ci`, `filter-sarif`, `local`, `version`.
- **DefectDojo** import of the full SARIF (reimport by default, `close_old_findings`,
  auto-create context). Failure-isolated — never fails the gate.
- **Three surfaces**: composite `action.yml`, reusable workflow
  `.github/workflows/gate.yml`, and a `chargate` pre-commit hook.
- **Modes**: PR (whole-repo scan → net-new gate) and baseline (full scan → DD, no
  gate) resolved from the event.


## v1.1.3 (2026-06-06)

### Bug Fixes

- Bump the actions group with 3 updates ([#1](https://github.com/MagmaMoose/chargate/pull/1),
  [`aada2cd`](https://github.com/MagmaMoose/chargate/commit/aada2cde582eee659cfb704cf9d27eb3e3664298))


## v1.1.2 (2026-06-03)

### Bug Fixes

- Bump pinned scanner versions to latest upstream
  ([`083fe32`](https://github.com/MagmaMoose/chargate/commit/083fe324900ca9bb1b225687b828094e57bb090e))

### Continuous Integration

- Make update-tools push resilient to concurrent main changes
  ([`a3876ce`](https://github.com/MagmaMoose/chargate/commit/a3876ce75cdb62b3082908cb66741bc6b11f6936))


## v1.1.1 (2026-06-03)

### Bug Fixes

- Resolve tool versions via github.com release redirect
  ([`866a230`](https://github.com/MagmaMoose/chargate/commit/866a2301f0b51a5e0f58d473c82d7249bcfced34))


## v1.1.0 (2026-06-03)

### Features

- Centralize pinned tool versions in versions.env + add strict mode
  ([`85c5980`](https://github.com/MagmaMoose/chargate/commit/85c598091a20b0c694a737e6e7db2acf18a26fae))

- Self-updating pinned tools with gated semantic-release to Marketplace
  ([`efc9c8e`](https://github.com/MagmaMoose/chargate/commit/efc9c8ecc2b1095f1321e7aa87b3032744e41bad))


## v1.0.2 (2026-06-03)


## v1.0.1 (2026-06-03)

### Documentation

- Add 'Enforcing it' — CI required check vs local hook auto-install
  ([`053366c`](https://github.com/MagmaMoose/chargate/commit/053366c0f9b79b9df707d293a0950101b30c8d36))


## v1.0.0 (2026-06-03)

- Initial Release
