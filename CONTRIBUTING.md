# Contributing to Chargate

Thanks for your interest! Issues and pull requests are welcome.

## Development setup

Chargate uses [uv](https://docs.astral.sh/uv/):

```sh
uv sync                       # install deps + dev tools (pytest, ruff)
uv run pytest -q              # run the test suite
uv run ruff check .          # lint
uv run ruff format --check . # format check (CI gates on this)
```

The `broker/` service is a separate deployable with its **own** `pyproject.toml` and
virtualenv — it is not a dependency group of the root project, so `cd` into it:

```sh
cd broker && uv sync --extra dev && uv run pytest -q
```

(If `uv` is not on your PATH, `python -m uv ...` works after `pip install uv`.)

## Ground rules (what CI and review will check)

- **Keep `src/chargate/sarif/` pure.** No `subprocess`, `os`, network, or GitHub
  Actions imports in the SARIF core — it is unit-tested with synthetic diff text +
  SARIF dicts. The git/IO boundary lives only in `git.py`.
- **Core stays stdlib-only.** The CLI has no runtime dependencies (the DefectDojo /
  Dependency-Track clients use `urllib`). Keep the broker's pyjwt/httpx deps in
  `broker/pyproject.toml` so the CLI wheel stays dependency-free.
- **Tests mirror modules 1:1** under `tests/` (e.g. `test_gate.py` for `gate.py`).
  Add or update tests with every change; the pure core should stay deterministic.
- **SHA-pin external GitHub Actions** with a `# vX.Y.Z` comment.
- **Full type hints**, Python ≥ 3.11.

## Commits & releases

Releases are **automated** via [Conventional Commits](https://www.conventionalcommits.org)
+ python-semantic-release. Your commit messages drive the next version:

- `feat: …` → minor bump
- `fix:` / `perf: …` → patch bump
- `feat!:` or a `BREAKING CHANGE:` footer → major bump
- `docs:` / `chore:` / `refactor:` / `test:` / `ci:` … → no release

**Never bump `project.version` or `__version__` by hand** — semantic-release writes
both on merge to `main`.

Branch names follow the same convention: `<type>/<short-description>`
(e.g. `feat/dast-sink`, `fix/shallow-clone-hint`).

## Pull requests

1. Branch from `main`.
2. Keep the change focused; update `docs/` and `PROJECT_INDEX.json` if you change
   public behaviour or add a module.
3. Ensure `pytest`, `ruff check`, and `ruff format --check` pass.
4. Open the PR — Chargate runs on itself, so the gate will comment on any net-new
   findings your change introduces.

## Reporting security issues

Please **do not** open a public issue for vulnerabilities — see
[`SECURITY.md`](SECURITY.md).
