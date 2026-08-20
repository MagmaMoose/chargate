# AGENTS.md

`CLAUDE.md` is **canonical**. This file restates the same rules for agents that do not
read it. There is no `@`-import mechanism here, so the substance is repeated rather than
referenced — **edit both files together, or they drift and the agents disagree.**

## What this repo is

Chargate wraps **MegaLinter** (which does all the scanning) and adds **net-new (PR-diff)
finding gating**: on a PR the gate is decided only by findings the diff introduced vs the
merge-base; pre-existing findings never block. The full, unfiltered SARIF is always
emitted and shipped (DefectDojo / Security tab / artifact) and a CycloneDX BOM (Syft)
goes to Dependency-Track; on PRs it posts GHAS-style comments for net-new findings.

One `chargate` CLI backs two surfaces: `action.yml` (composite action) and
`.pre-commit-hooks.yaml` (local hook). A separate service under `broker/` (its own
pyproject; an AWS Lambda behind an API Gateway HTTP API, Terraform in
`magmamoose/infra`) mints the `Chargate[bot]` token the PR comments are authored with.

## Commands

```sh
uv sync                        # install deps + dev tools
uv run pytest -q               # test suite
uv run ruff check .            # lint
uv run ruff format --check .   # format check (what CI gates on)

# broker/ is a separate deployable with its OWN pyproject + venv, not a dep group:
cd broker && uv sync --extra dev && uv run pytest -q
```

Full list: `.claude/QUICK_START.md`.

## Conventions

- Python ≥ 3.11, uv + Ruff + pytest, full type hints.
- **Core stays stdlib-only** — the CLI has no runtime dependencies (DefectDojo and
  Dependency-Track clients use `urllib`). Broker deps live in `broker/pyproject.toml`.
- **Keep `src/chargate/sarif/` pure**: no `subprocess`, `os`, network or Actions imports.
  `git.py` is the only subprocess boundary.
- Tests mirror modules 1:1 under `tests/`.
- SHA-pin external GitHub Actions with a `# vX.Y.Z` comment.
- Releases are automated from conventional commits — **never** bump `project.version` or
  `__init__.__version__` by hand.
- **Never bypass the git hooks** (`--no-verify`, `core.hooksPath=/dev/null`).

## Finding code and context

- Read `./PROJECT_INDEX.json` before hunting for unfamiliar code.
- Read `.claude/COMMON_MISTAKES.md` before changing the SARIF core, the broker,
  MegaLinter/linter config, a GitHub workflow, or anything paired with `magmamoose/infra`.
- `.claude/decisions/` and `.claude/sessions/` only when the task relates to them.
- Human docs live in `./docs` (MkDocs); `.claude/*.md` is terse agent context. Keep the
  two surfaces distinct.

## Tooling

- Targeted line-range reads over whole files; use `PROJECT_INDEX.json` to locate first.
- grep/find/glob: matching paths and lines only, never whole-file dumps.
- Flood-prone commands: pipe through `head`/`tail`/`grep`, or redirect to
  `.claude/last_output.txt` and read ranges.
- After a successful write or edit, trust it; don't re-read to verify.
