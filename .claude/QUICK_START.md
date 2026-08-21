# Quick start (most-run commands)

```sh
uv sync                       # install deps + dev tools (pytest, ruff)
uv run pytest -q              # run the test suite (add a path for one module)
uv run ruff check .          # lint
uv run ruff format .         # format (CI gates on `--check`)

# The broker/ service is a separate deployable with its OWN pyproject + venv.
# It is NOT a dependency group of the root project — cd into it:
cd broker && uv sync --extra dev && uv run pytest -q

# Build the deployable Lambda artifact (--platform is required, no default:
# a Mac-resolved wheel set deploys fine and then ImportErrors at cold start):
cd broker && uv run python scripts/build_lambda_zip.py \
  --out ../dist/chargate-broker.zip --platform x86_64-manylinux_2_28

# Exercise the CLI (full flag reference: docs/cli.md):
uv run chargate ci --mode auto --flavor all --sarif-out full.sarif
uv run chargate local path/to/file.py   # what the pre-commit hook runs
uv run chargate install-hooks           # wire hooks globally across all repos

# Docs (docs group: mkdocs-material):
uv run --group docs mkdocs serve   # live preview at :8000
uv run --group docs mkdocs build   # render ./site
```

(If `uv` is not on PATH, `python -m uv ...` works after `pip install uv`.)
