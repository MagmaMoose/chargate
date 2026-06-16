# CLAUDE.md

Chargate wraps **MegaLinter** (which does all the scanning) and adds **net-new
(PR-diff) finding gating**: on a PR the gate is decided only by findings the diff
introduced vs the merge-base; pre-existing findings never block. The full,
unfiltered SARIF is always emitted and shipped (DefectDojo / Security tab /
artifact). One `chargate` CLI backs three surfaces: `action.yml` (composite
action), `.github/workflows/gate.yml` (reusable workflow), and
`.pre-commit-hooks.yaml` (local hook).

@.claude/QUICK_START.md
@.claude/ARCHITECTURE_MAP.md
@.claude/COMMON_MISTAKES.md

## Conventions

Python ≥ 3.11, **uv + Ruff + pytest**, full type hints, stdlib-only core (no
runtime deps — the DefectDojo client uses `urllib`). SHA-pin external GitHub
Actions with a `# vX.Y.Z` comment. MIT. Tests mirror modules 1:1 under `tests/`.

**Releases** are automated: pushing to `main` runs Diatreme + python-semantic-release
(single-env TBD, `.github/workflows/release.yaml`), which cuts the next stable
`vX.Y.Z` from conventional commits and bumps `project.version` + `__init__.__version__`
— never bump those by hand.

## Finding code & context

- Before locating unfamiliar code, read `./PROJECT_INDEX.json` first (module map,
  call graph, hotspots). It is loaded on demand — do **not** @-import it.
- Load `.claude/decisions` and `.claude/sessions` ONLY when the task relates to
  them, never by default. Full human docs live in `./docs` (MkDocs).

## [tooling]

- Prefer targeted line-range reads over whole files; use `PROJECT_INDEX.json` to
  find the location first.
- grep/find/glob: return matching paths and matched lines only, not whole files.
- Commands that can flood output: pipe through `head`/`tail`/`grep` or redirect to
  `.claude/last_output.txt` and read ranges. Don't paste thousands of lines.
- After a successful write/edit, trust it; don't re-read just to "verify".

## [maintenance]

- Bug that took >1h: append to `.claude/COMMON_MISTAKES.md`.
- Architectural decision: run `/adr`.
- Public behaviour/API/config/setup changed: run `/update-docs`.
- `PROJECT_INDEX.json` stale (new module, big refactor): regenerate the affected
  modules section only.
- Keep `CLAUDE.md` under ~500 tokens; push detail into on-demand `.claude/` files.
