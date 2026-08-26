"""Path coverage for the ``actions-pin-sha`` hook's ``files`` pattern.

pre-commit filters the file list against ``files`` BEFORE it invokes the hook, so
a path missing from this regex is a path the hook can never see. That is not a
theoretical gap: the pattern used to cover ``.github/workflows/`` only, and an
admin repo keeps the workflow bodies for the whole org inside
``.github/settings.yml`` as literal blocks. A ``uses: owner/repo@v2`` committed
there was rendered onto every managed default branch unpinned, and the hook
reported ``(no files to check) Skipped`` while it happened.

The hook script needs no path knowledge of its own — it uses the filenames
pre-commit hands it verbatim — so this regex is the whole contract.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

HOOKS_YAML = Path(__file__).resolve().parent.parent / ".pre-commit-hooks.yaml"


def _files_pattern(hook_id: str) -> re.Pattern[str]:
    hooks = yaml.safe_load(HOOKS_YAML.read_text(encoding="utf-8"))
    for hook in hooks:
        if hook["id"] == hook_id:
            return re.compile(hook["files"])
    raise AssertionError(f"no hook with id {hook_id!r} in {HOOKS_YAML}")


@pytest.fixture(scope="module")
def pattern() -> re.Pattern[str]:
    return _files_pattern("actions-pin-sha")


@pytest.mark.parametrize(
    "path",
    [
        ".github/workflows/ci.yml",
        ".github/workflows/release.yaml",
        ".github/workflows/nested/dir/build.yml",
        # The regression this file exists for.
        ".github/settings.yml",
        ".github/settings.yaml",
        # Composite actions reference other actions and are just as pinnable.
        "action.yml",
        "action.yaml",
        ".github/actions/setup/action.yml",
    ],
)
def test_covered(pattern: re.Pattern[str], path: str) -> None:
    assert pattern.search(path), f"{path} must be scanned for floating refs"


@pytest.mark.parametrize(
    "path",
    [
        # Ordinary config that never carries a `uses:` line. Scanning it would
        # mean rewriting files on behalf of tools that have nothing to do with
        # Actions, and the hook auto-fixes.
        "docker-compose.yml",
        "mkdocs.yml",
        ".pre-commit-config.yaml",
        "src/chargate/data/linters.yml",
        # Near-misses on the new alternations.
        ".github/dependabot.yml",
        ".github/actions/action.yml",
        "docs/action.yml",
    ],
)
def test_not_covered(pattern: re.Pattern[str], path: str) -> None:
    assert not pattern.search(path), f"{path} must be left alone"
