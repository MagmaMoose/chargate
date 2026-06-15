"""Local pre-commit entrypoint — a fast, staged-file first line of defence.

Deliberately *not* a full re-implementation of the CI scanner set: CI (MegaLinter
whole-repo + net-new gate) is the broad net; pre-commit is the fast first pass on
staged content. This runs a small set of quick checks, each guarded by tool
presence (a missing tool is skipped, never an error — matching the lineage's
auto-detect behaviour) so a contributor without every tool installed is never
blocked spuriously.

The check registry is data-driven and easy to extend. The subprocess runner and
tool-presence probe are injectable so the dispatch logic is unit-tested without
the real tools.
"""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass

_STAGED_FILE_CAP = 2000


@dataclass(frozen=True)
class LocalCheck:
    """One fast local check. ``build_argv(files)`` yields the command to run."""

    name: str
    tool: str
    build_argv: Callable[[Sequence[str]], list[str]]
    # Some tools (e.g. gitleaks protect) scan staged git state directly and
    # ignore explicit file args; for those, running with no files is still valid.
    needs_files: bool = True


@dataclass(frozen=True)
class CheckOutcome:
    name: str
    status: str  # "ok" | "findings" | "skipped"
    detail: str = ""


# Fast defaults. All optional; skipped when the tool is absent. gitleaks is the
# MegaLinter-native secrets choice and runs quickly against staged content.
DEFAULT_CHECKS: tuple[LocalCheck, ...] = (
    LocalCheck(
        name="secrets (gitleaks)",
        tool="gitleaks",
        build_argv=lambda _files: ["gitleaks", "protect", "--staged", "--no-banner", "--redact"],
        needs_files=False,
    ),
    LocalCheck(
        name="python lint (ruff)",
        tool="ruff",
        build_argv=lambda files: ["ruff", "check", *files],
    ),
)

Runner = Callable[[list[str]], subprocess.CompletedProcess]
Which = Callable[[str], str | None]


def staged_files(repo: str = ".") -> list[str]:
    """Added/copied/modified staged files, capped, for the no-args fallback."""
    proc = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return []
    files = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    return files[:_STAGED_FILE_CAP]


def _select_files(files: Sequence[str], check: LocalCheck) -> list[str]:
    selected = list(files)
    if check.tool == "ruff":
        selected = [f for f in selected if f.endswith((".py", ".pyi"))]
    return selected


def run_local(
    files: Sequence[str],
    checks: Sequence[LocalCheck] = DEFAULT_CHECKS,
    *,
    runner: Runner | None = None,
    which: Which | None = None,
) -> tuple[int, list[CheckOutcome]]:
    """Run the checks over ``files``. Returns ``(exit_code, outcomes)``.

    Exit code is 0 when nothing found, 1 when any check reports findings. Missing
    tools are skipped (never fail the commit).
    """
    run_fn: Runner = runner or (lambda cmd: subprocess.run(cmd, check=False))
    which_fn: Which = which or shutil.which

    outcomes: list[CheckOutcome] = []
    failed = False
    for check in checks:
        if which_fn(check.tool) is None:
            outcomes.append(CheckOutcome(check.name, "skipped", f"{check.tool} not installed"))
            continue
        selected = _select_files(files, check)
        if check.needs_files and not selected:
            outcomes.append(CheckOutcome(check.name, "ok", "no matching staged files"))
            continue
        completed = run_fn(check.build_argv(selected))
        if completed.returncode == 0:
            outcomes.append(CheckOutcome(check.name, "ok"))
        else:
            failed = True
            outcomes.append(CheckOutcome(check.name, "findings", f"exit {completed.returncode}"))
    return (1 if failed else 0), outcomes
