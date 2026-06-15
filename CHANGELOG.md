# CHANGELOG

<!-- version list -->

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
