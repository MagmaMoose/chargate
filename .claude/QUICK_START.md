# Quick start (most-run commands)

```sh
uv sync                       # install deps + dev tools (pytest, ruff)
uv run pytest -q              # run the test suite (add a path for one module)
uv run ruff check .          # lint
uv run ruff format .         # format (CI gates on `--check`)

# Exercise the CLI (full flag reference: docs/cli.md):
uv run chargate ci --mode auto --flavor all --sarif-out full.sarif
uv run chargate local path/to/file.py   # what the pre-commit hook runs

# Docs (docs group: mkdocs-material):
uv run --group docs mkdocs serve   # live preview at :8000
uv run --group docs mkdocs build   # render ./site
```

(If `uv` is not on PATH, `python -m uv ...` works after `pip install uv`.)
