# Chargate

[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-Chargate-2ea44f?logo=github)](https://github.com/marketplace/actions/chargate)
[![CI](https://github.com/MagmaMoose/chargate/actions/workflows/ci.yml/badge.svg)](https://github.com/MagmaMoose/chargate/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/MagmaMoose/chargate?sort=semver&logo=github)](https://github.com/MagmaMoose/chargate/releases)
[![Docs](https://img.shields.io/badge/docs-chargate-blue)](https://magmamoose.github.io/chargate/)
[![License: Apache 2.0](https://img.shields.io/github/license/MagmaMoose/chargate)](LICENSE)

> **Gate pull requests on the findings _this PR_ introduced — not your whole backlog.**

Chargate is a security and lint gate built on [MegaLinter](https://megalinter.io).
MegaLinter does all the scanning; Chargate decides what should block. On a pull request
the gate passes or fails on findings the PR introduces relative to the merge-base, so a
large existing backlog never blocks anyone — while the full, unfiltered SARIF is still
emitted and shipped, so your security system keeps seeing everything.

**[Documentation](https://magmamoose.github.io/chargate/)** ·
[Setup](https://magmamoose.github.io/chargate/setup/) ·
[Action reference](https://magmamoose.github.io/chargate/action-reference/) ·
[Marketplace](https://github.com/marketplace/actions/chargate)

## Quickstart

```yaml
# .github/workflows/security.yml
name: Security
on: [pull_request]

permissions:
  contents: read           # checkout
  pull-requests: write     # PR comments
  security-events: write   # SARIF to the Security tab

jobs:
  chargate:
    runs-on: ubuntu-latest
    steps:
      - uses: magmamoose/chargate@v2
        with:
          fail_on: high    # block only on net-new high/critical (default: any)
```

Net-new gating needs the merge-base, so the action checks out with `fetch-depth: 0` by
default. A shallow clone fails loudly rather than silently passing.

## What it does

- **Gates on net-new only** — findings on lines this PR added or changed. Pre-existing
  findings are reported, never blocking.
- **Reports like GHAS** — one updatable summary comment plus inline comments on changed
  lines, scoped to net-new so it stays quiet.
- **Ships everywhere** — full SARIF to the GitHub Security tab, DefectDojo, and a build
  artifact; a CycloneDX BOM to Dependency-Track. Each sink activates by setting its URL.
- **Runs on arm64** — MegaLinter publishes flavor images for amd64 only, so Chargate
  substitutes the multi-arch per-linter images automatically.
- **Hands off a stable contract** — every run writes `counts.json` and a net-new-only
  SARIF that another gate can read without importing any of Chargate.

> **A reduced scan is not a clean repo.** When Chargate falls back to per-linter images
> it says so in the job summary and on the PR, and names every linter it skipped. Assert
> on the `scan_mode` output if a release must never ship on a degraded scan.

## Most-used inputs

| Input | Default | What it does |
| --- | --- | --- |
| `fail_on` | `any` | Severity that blocks: `any` · `critical` · `high` · `medium` · `low` · `none`. |
| `flavor` | `security` | MegaLinter flavor. `all` for the full lint image; `quality` is a Chargate-curated set. |
| `mode` | `auto` | `auto` from the event · `pr` (net-new gate) · `baseline` (full scan, no gate). |
| `precision` | `line` | Net-new precision: `line` · `file`. |
| `defectdojo_url` | — | Set to enable the DefectDojo import. |
| `dependency_track_url` | — | Set to enable the CycloneDX BOM upload. |

All inputs and every output → **[Action reference](https://magmamoose.github.io/chargate/action-reference/)**

## Documentation

| | |
| --- | --- |
| [Setup and usage](https://magmamoose.github.io/chargate/setup/) | Workflows, the pre-commit hook, sinks, MegaLinter config, migrating from v1 |
| [Net-new gating](https://magmamoose.github.io/chargate/net-new/) | Exactly what counts as net-new, and how `fail_on` decides |
| [Action reference](https://magmamoose.github.io/chargate/action-reference/) · [CLI reference](https://magmamoose.github.io/chargate/cli/) | Every input, output, command and exit code |
| [Consuming the output](https://magmamoose.github.io/chargate/consuming-output/) | The `counts.json` contract for downstream gates |
| [Architecture](https://magmamoose.github.io/chargate/architecture/) · [Troubleshooting](https://magmamoose.github.io/chargate/troubleshooting/) | How it works, and what to do when it doesn't |

## Local use

Chargate also ships pre-commit hooks — a fast staged-file security scan, plus
file-hygiene hooks that pin GitHub Actions to SHAs and enforce branch naming:

```sh
brew install calebsargeant/tap/chargate && chargate install-hooks
```

Deliberately narrower than the CI net: it is a first line, not a substitute.
See [Setup](https://magmamoose.github.io/chargate/setup/).

## Where it sits

**Chargate** gates security and lint · [Brimyr](https://github.com/MagmaMoose/brimyr)
gates tests and coverage · [Diatreme](https://github.com/MagmaMoose/diatreme) releases
what passes.

## Versioning

Pin `@v2` for the floating major, or a tag or SHA to freeze.
v2 is a ground-up re-platform onto MegaLinter — coming from `@v1`, see
[Migrating from v1](https://magmamoose.github.io/chargate/setup/#migrating-from-v1).

## Security · Contributing · License

[Report a vulnerability](SECURITY.md) · [Contributing](CONTRIBUTING.md) ·
Apache 2.0, see [LICENSE](LICENSE).
