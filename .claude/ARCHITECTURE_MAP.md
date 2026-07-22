# Architecture map

One `chargate` Python CLI (`src/chargate/cli.py:main`) backs two GitHub
surfaces: a composite action (`action.yml`) and a pre-commit hook
(`.pre-commit-hooks.yaml`).

The flow: **MegaLinter** does all scanning and emits SARIF; chargate filters it to
**net-new** findings (those the PR diff introduced vs the merge-base) and gates
only on those. The full, unfiltered SARIF is always shipped (DefectDojo / Security
tab / artifact), a CycloneDX BOM (Syft) goes to Dependency-Track (push/tags only),
and net-new findings post as GHAS-style PR comments; pre-existing findings never block.

`sarif/` (diff → model → counts → filter, + `sops.py`) is the **pure, deterministic,
I/O-free core** — it takes a SARIF dict + a `DiffIndex` and returns verdicts. `git.py`
is the **only** subprocess boundary (merge-base + diff). `gate.py` turns verdicts +
`fail_on` into an exit code; `megalinter.py`, `defectdojo.py`, `dependencytrack.py`,
`github_comment.py`, `install_hooks.py`, `modes.py`, `report.py`, `local.py` are the
side-effecting edges. The two external sinks are optional + **failure-isolated**
(a sink outage is logged, never fails the gate). Exit codes: `0` pass · `1`
blocking net-new · `2` setup/tool error.

Separate from the CLI: the **`broker/`** FastAPI service (own dep-group; `k8s/` + Flux)
exchanges a run's Actions OIDC token for a `Chargate[bot]` App token to author PR comments.

Full module table + call graph: read `./PROJECT_INDEX.json`.
