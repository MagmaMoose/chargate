# Architecture

Chargate is one `chargate` Python CLI (`src/chargate/cli.py:main`) behind three
GitHub surfaces. The design splits cleanly into a **pure core** and a thin set of
**side-effecting edges**.

## Module map

```
src/chargate/
  cli.py          # argparse dispatch: filter-sarif | ci | local | version
  sarif/          # ★ THE PURE CORE — deterministic, no I/O, heavily tested
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

A structured, machine-readable version (exports, dependencies, call graph,
hotspots) lives at [`PROJECT_INDEX.json`](https://github.com/MagmaMoose/chargate/blob/main/PROJECT_INDEX.json)
in the repo root.

## The design rule

`sarif/` is **pure**: it takes already-parsed data (a SARIF dict + a `DiffIndex`)
and returns verdicts. `git.py` is the only thing that shells out, so the filter is
unit-tested with synthetic diff text and SARIF dicts — no real repository
required.

!!! warning "Keep the boundary"
    Do **not** import `subprocess`, `os`, network code, or GitHub Actions into
    `sarif/`. That separation is what makes the crown-jewel filter trivially
    testable and deterministic.

## Data flow (PR / gate mode)

1. **`modes.resolve_mode`** decides PR (gate) vs baseline (no gate) from
   `GITHUB_EVENT_NAME` or an explicit flag.
2. **`megalinter.run`** runs MegaLinter whole-repo with `DISABLE_ERRORS=true` (so
   MegaLinter never sets the exit code) and locates the merged SARIF.
3. **`git.compute_changed_lines`** resolves `merge-base(base, head)`, runs
   `git diff --unified=0`, and hands the text to `sarif.diff.parse_unified_diff` →
   a `DiffIndex`.
4. **`sarif.filter.filter_sarif`** classifies every result as net-new or
   pre-existing under a `FilterPolicy`, returning a pruned deep copy (net-new
   only), per-result verdicts, and `Counts`. The input SARIF is never mutated.
5. **`gate.decide_gate`** applies the `fail_on` threshold to the net-new set →
   a `GateDecision` and exit code.
6. **`defectdojo.import_sarif`** (optional) ships the **full** SARIF. It is
   failure-isolated: it never raises, so a DefectDojo outage can't fail the gate.
7. **`report`** writes the GitHub job summary and step outputs.

Baseline mode skips steps 3–5's gating: it counts everything against an empty
`DiffIndex` with `fail_on=none`, ships the full SARIF, and never blocks.

## Exit-code contract

| Code | Meaning |
| --- | --- |
| `0` | pass |
| `1` | blocking net-new finding(s) |
| `2` | setup / tool / usage error |

A *broken* scanner is a tool error (`2`), never a finding. A MegaLinter tool
failure only fails the job under `--strict`.

## Testing

Tests mirror modules 1:1 under `tests/` (e.g. `test_sarif_filter.py`,
`test_gate.py`, `test_git.py`). The pure core is tested with synthetic inputs; the
subprocess and HTTP boundaries inject their runner/opener so they are exercised
without Docker, git, or a live DefectDojo.
