"""Summaries of a SARIF report: totals and per-severity breakdowns.

Kept dependency-light and decoupled from :mod:`chargate.sarif.filter` (which
imports this module): it takes the set of net-new ``(run_index, result_index)``
keys rather than verdict objects, so there is no import cycle.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from chargate.sarif.model import (
    iter_results,
    resolve_level,
    security_severity,
    severity_band,
)


@dataclass(frozen=True)
class Counts:
    """Total and net-new counts, broken down by SARIF level and severity band.

    ``per_level_*`` keys are SARIF levels (error/warning/note/none). ``per_band_*``
    keys are security-severity bands (critical/high/medium/low/none) and are only
    populated for results that carry a numeric ``security-severity`` property.
    """

    total: int
    net_new: int
    per_level_total: dict[str, int] = field(default_factory=dict)
    per_level_net_new: dict[str, int] = field(default_factory=dict)
    per_band_total: dict[str, int] = field(default_factory=dict)
    per_band_net_new: dict[str, int] = field(default_factory=dict)

    @property
    def pre_existing(self) -> int:
        return self.total - self.net_new


def count_results(
    sarif: dict[str, Any],
    net_new_keys: Iterable[tuple[int, int]],
) -> Counts:
    """Tally totals and net-new counts by level and severity band."""
    keys = set(net_new_keys)
    per_level_total: Counter[str] = Counter()
    per_level_net_new: Counter[str] = Counter()
    per_band_total: Counter[str] = Counter()
    per_band_net_new: Counter[str] = Counter()
    total = 0
    net_new = 0

    for run_index, result_index, result, run in iter_results(sarif):
        total += 1
        level = resolve_level(result, run)
        per_level_total[level] += 1
        band = severity_band(security_severity(result, run))
        if band is not None:
            per_band_total[band] += 1
        if (run_index, result_index) in keys:
            net_new += 1
            per_level_net_new[level] += 1
            if band is not None:
                per_band_net_new[band] += 1

    return Counts(
        total=total,
        net_new=net_new,
        per_level_total=dict(per_level_total),
        per_level_net_new=dict(per_level_net_new),
        per_band_total=dict(per_band_total),
        per_band_net_new=dict(per_band_net_new),
    )
