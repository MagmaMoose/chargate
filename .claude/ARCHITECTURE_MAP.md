# Architecture map

One `chargate` Python CLI (`src/chargate/cli.py:main`) backs two GitHub
surfaces: a composite action (`action.yml`) and a pre-commit hook
(`.pre-commit-hooks.yaml`).

The flow: **MegaLinter** does all scanning and emits SARIF; chargate filters it to
**net-new** findings (those the PR diff introduced vs the merge-base) and gates
only on those. The full, unfiltered SARIF is always shipped (DefectDojo / Security
tab / artifact); pre-existing findings never block.

`sarif/` (diff → model → counts → filter) is the **pure, deterministic, I/O-free
core** — it takes a SARIF dict + a `DiffIndex` and returns verdicts. `git.py` is
the **only** subprocess boundary (merge-base + diff). `gate.py` turns verdicts +
`fail_on` into an exit code; `megalinter.py`, `defectdojo.py`, `modes.py`,
`report.py`, `local.py` are the side-effecting edges. Exit codes: `0` pass · `1`
blocking net-new · `2` setup/tool error.

Full module table + call graph: read `./PROJECT_INDEX.json`.
