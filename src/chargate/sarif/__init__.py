"""Pure, deterministic SARIF net-new filtering — the Chargate crown jewel.

Nothing in this package imports GitHub Actions, subprocess, or network code. It
operates on already-parsed data:

* :mod:`chargate.sarif.diff` turns unified-diff text into a :class:`DiffIndex`
  (changed files + added/modified line ranges).
* :mod:`chargate.sarif.model` provides typed accessors over SARIF result objects.
* :mod:`chargate.sarif.filter` classifies each result as net-new or pre-existing
  against a :class:`DiffIndex`, given a :class:`FilterPolicy`.
* :mod:`chargate.sarif.counts` summarizes totals and per-severity breakdowns.

The git/IO boundary (running ``git diff``, computing the merge-base, detecting a
shallow clone) lives in :mod:`chargate.git` so this package can be unit-tested
with synthetic diff text and SARIF dicts — no real repository required.
"""

from chargate.sarif.counts import Counts, count_results
from chargate.sarif.diff import DiffIndex, FileDiff, parse_unified_diff
from chargate.sarif.filter import (
    FilterPolicy,
    FilterResult,
    NoLocationPolicy,
    Precision,
    ResultVerdict,
    classify_results,
    filter_sarif,
)

__all__ = [
    "Counts",
    "DiffIndex",
    "FileDiff",
    "FilterPolicy",
    "FilterResult",
    "NoLocationPolicy",
    "Precision",
    "ResultVerdict",
    "classify_results",
    "count_results",
    "filter_sarif",
    "parse_unified_diff",
]
