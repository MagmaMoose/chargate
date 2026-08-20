# CLAUDE.md

Canonical agent context for this repo. `AGENTS.md` restates it for other agents —
**edit both together.**

Chargate wraps **MegaLinter** and adds **net-new (PR-diff) finding gating**: on a PR
only findings the diff introduced vs the merge-base can block. It runs on every repo
in the org, so a false block stops everyone's CI and a missed finding is a security
gap. One `chargate` CLI backs `action.yml` and `.pre-commit-hooks.yaml`; a separate
deployable under `broker/` mints the `Chargate[bot]` token PR comments are authored
with. Detail below in the architecture map.

@.claude/QUICK_START.md
@.claude/ARCHITECTURE_MAP.md

## Conventions

Python ≥ 3.11, **uv + Ruff + pytest**, full type hints, stdlib-only **core** (no
runtime deps — the DefectDojo/Dependency-Track clients use `urllib`); the `broker/`
service has its own `broker/pyproject.toml` and virtualenv. SHA-pin external
GitHub Actions with a `# vX.Y.Z` comment. MIT. Tests mirror modules 1:1 under `tests/`.

**Releases** are automated: pushing to `main` runs Diatreme + python-semantic-release
(single-env TBD, `.github/workflows/release.yml`), which cuts the next stable
`vX.Y.Z` from conventional commits and bumps `project.version` + `__init__.__version__`
— never bump those by hand.

**Never bypass the git hooks** (`--no-verify`, `core.hooksPath=/dev/null`). They run
`chargate local`, SHA-pin and branch-name checks. Chargate enforces these; routing
around them here is self-defeating.

## Finding code & context

- Before locating unfamiliar code, read `./PROJECT_INDEX.json` first (module map,
  call graph, hotspots). It is loaded on demand — do **not** @-import it.
- **Read `.claude/COMMON_MISTAKES.md` before changing** the SARIF core, the broker,
  MegaLinter/linter config, a GitHub workflow, or anything paired with
  `magmamoose/infra`. 20 entries, each one an incident that already cost hours.
  On demand — not @-imported, because it outgrew the per-session budget.
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
  modules section only, and update `generated`.
- Keep `CLAUDE.md` under ~500 tokens; push detail into on-demand `.claude/` files.
