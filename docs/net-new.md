# Net-new gating

A SARIF result is **net-new** (and therefore gate-blocking) iff its primary
location's file is in the PR diff **and** — at line precision — its `startLine`
falls inside an added/modified hunk. The diff is computed against
`merge-base(base, head)`, which is robust to base-branch rebases and force-pushes.

## Classification rules

| Case | Policy (default) | Configurable |
| --- | --- | --- |
| Brand-new file | all results net-new | — |
| Modified hunk | net-new iff `startLine` in an added range | `precision: line\|file` |
| Unchanged line in a changed file | pre-existing → never blocks | `precision: file` to flip |
| Renamed / copied file | matched by head path; content changes line-matched | — |
| Deleted file | dropped | — |
| Result with **no** file location (project-level: SBOM/license/some Trivy) | **not** net-new | `--no-location-policy block` |
| Changed file, result with no `startLine` (common for SCA on a lockfile) | net-new (file-level fallback) | `--no-region-fallback` to disable |
| Multiple locations | uses the **primary** (`locations[0]`) | documented |
| Missing merge-base / shallow clone | **fails loudly** — needs `fetch-depth: 0` | — |

These knobs are expressed on `FilterPolicy` in
`src/chargate/sarif/filter.py`. The file-level fallback exists so a genuinely
PR-introduced dependency vulnerability attached to a changed lockfile (no
`startLine`) still blocks, while truly project-global findings (no file at all)
fall under the no-location policy.

## The `fail_on` threshold

`fail_on` controls the gate over the net-new set:

- `any` (default) — any net-new finding blocks (the product's core promise).
- `critical` / `high` / `medium` / `low` — block only at or above that band.
- `none` — report-only; never blocks.

Severity uses the SARIF `security-severity` band when present
(`≥9.0` critical, `≥7.0` high, `≥4.0` medium, `>0` low), else the SARIF `level`
(`error`→high, `warning`→medium, `note`→low).

!!! tip "Full vs filtered SARIF"
    The gate only ever looks at the **net-new** subset, but the **full**,
    unfiltered SARIF is what gets shipped to DefectDojo / the Security tab /
    artifact. The input report is never mutated.
