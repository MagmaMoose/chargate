# CLAUDE.md

Guidance for Claude Code (and humans) working in this repo.

## What Chargate is

A security + lint gate that wraps **MegaLinter** (which does all scanning) and
adds **net-new (PR-diff) finding gating**: on a PR, the gate is decided only by
findings the PR introduced relative to the merge-base; pre-existing findings
never block. The full, unfiltered SARIF is always emitted and shipped (DefectDojo
/ Security tab / artifact).

This repo consolidates three surfaces, all driving one `chargate` Python CLI:
- `action.yml` — composite GitHub Action (thin: install CLI → `chargate ci`).
- `.github/workflows/gate.yml` — reusable workflow (`on: workflow_call`).
- `.pre-commit-hooks.yaml` — local `chargate` hook (`language: python`).

## Architecture

```
src/chargate/
  cli.py          # argparse dispatch: filter-sarif | ci | local | version
  sarif/          # ★ THE CROWN JEWEL — pure, deterministic, no I/O, heavily tested
    diff.py       #   unified-diff text -> DiffIndex (changed files + added line ranges)
    model.py      #   defensive SARIF result accessors (uri, startLine, level, severity)
    filter.py     #   net-new classification + FilterPolicy + filter_sarif()
    counts.py     #   totals + per-severity breakdowns
  git.py          # the ONLY git/subprocess boundary (merge-base, diff, shallow detect)
  gate.py         # net-new verdicts + fail_on threshold -> pass/fail + exit code
  megalinter.py   # build env/command, run, locate the merged SARIF
  defectdojo.py   # import/reimport client (urllib, failure-isolated, never raises)
  modes.py        # PR (gate) vs baseline (no gate) resolution
  report.py       # GitHub job summary + step outputs
  local.py        # pre-commit fast staged-file runner
```

**Design rule:** `sarif/` is pure — it takes parsed data (a SARIF dict + a
`DiffIndex`) and returns verdicts. `git.py` is the only thing that shells out, so
the filter is unit-tested with synthetic diff text and SARIF dicts (no real repo).
Keep it that way: do not import subprocess / os / GitHub Actions into `sarif/`.

Exit-code contract (mirrors the legacy scripts): `0` pass · `1` blocking net-new ·
`2` setup/tool error. A *broken* scanner is a tool error, never a finding.

## Conventions

- Python ≥ 3.11, **uv** + **Ruff** + **pytest**, full type hints, stdlib-only core
  (no runtime deps — the DefectDojo client uses `urllib`).
- SHA-pin external GitHub Actions (with a `# vX.Y.Z` comment).
- MIT license.

## Running things

```sh
uv sync
uv run pytest -q
uv run ruff check .
uv run ruff format .
```

(If `uv` is not on PATH, `python -m uv ...` works after `pip install uv`.)

## ⚠️ Verify MegaLinter against a real run

`megalinter.py` is written to MegaLinter's *documented* behaviour, but the spec
demands verification against a real run before trusting field names/paths:
- The merged-SARIF filename has appeared as both `megalinter-report.sarif` and
  `mega-linter-report.sarif`; `locate_sarif()` prefers the configured name and
  falls back to any `*.sarif` in `megalinter-reports/`.
- Confirm `DISABLE_ERRORS`, `SARIF_REPORTER`, `JSON_REPORTER`,
  `SARIF_REPORTER_NORMALIZE_LINTERS_OUTPUT`, and `REPORT_OUTPUT_FOLDER` semantics,
  and the SARIF URI shape (repo-relative vs `/tmp/lint/...`) — `chargate ci`
  strips the `/tmp/lint` container prefix and the abs repo path defensively.

## Net-new edge-case policies

See `FilterPolicy` in `sarif/filter.py` and the README table. Defaults: line
precision; project-level (no-location) results do **not** block; changed-file
results lacking a `startLine` fall back to file-level (catches SCA on lockfiles).

## Lineage

Chargate is the public productization of the security side of
`CalebSargeant/pre-commit-hooks` → `CalebSargeant/cinnabar`. The formatting /
file-hygiene / Actions-SHA-pinning hooks stay in `pre-commit-hooks`; the
`chargate` hook is the security + lint first line and is meant to coexist.
