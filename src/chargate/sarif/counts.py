"""Summaries of a SARIF report: totals and per-severity breakdowns.

Kept dependency-light and decoupled from :mod:`chargate.sarif.filter` (which
imports this module): it takes the set of net-new ``(run_index, result_index)``
keys rather than verdict objects, so there is no import cycle.

The shape :class:`Counts` is serialised into by ``--counts-json`` is a **public
interface** across a process boundary — brimyr reads it to run its own quality gate
(MagmaMoose/brimyr#33) without importing any of this. :data:`COUNTS_SCHEMA_VERSION`
is what lets the far side tell a document it understands from one it does not.
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

#: Version of the JSON document ``chargate ... --counts-json`` writes.
#:
#: **Bump this only on a breaking change** — a key removed, renamed, or given a new
#: meaning. Adding a key is not breaking: a reader that does not know it ignores it.
#: Consumers are expected to hard-fail on a version they do not recognise rather than
#: guess, so a bump is a coordinated release on both sides of the boundary, not a
#: cosmetic edit.
#:
#: 1 — net_new_count, total_count, pre_existing_count, suppressed_count,
#:     sops_ignored_count, deduped_count, per_level_total, per_level_net_new,
#:     per_severity_total, per_severity_net_new.
COUNTS_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class Counts:
    """Total and net-new counts, broken down by SARIF level and severity band.

    ``per_level_*`` keys are SARIF levels (error/warning/note/none). ``per_band_*``
    keys are security-severity bands (critical/high/medium/low/none) and are only
    populated for results that carry a numeric ``security-severity`` property.
    """

    total: int
    net_new: int
    suppressed: int = 0  # author-accepted in-source suppressions (never gate)
    sops_ignored: int = 0  # secret-scanner hits on SOPS-encrypted values (never gate)
    deduped: int = 0  # net-new findings collapsed into an earlier identical one
    per_level_total: dict[str, int] = field(default_factory=dict)
    per_level_net_new: dict[str, int] = field(default_factory=dict)
    per_band_total: dict[str, int] = field(default_factory=dict)
    per_band_net_new: dict[str, int] = field(default_factory=dict)

    @property
    def pre_existing(self) -> int:
        """Findings that are neither net-new, suppressed, SOPS-ignored, nor deduped.

        Suppressed, SOPS-ignored, and de-duplicated results are carved into their own
        buckets so a risk accepted (or a false positive / duplicate dropped) *in this
        PR* isn't hidden among truly pre-existing findings.
        """
        return self.total - self.net_new - self.suppressed - self.sops_ignored - self.deduped


def count_results(
    sarif: dict[str, Any],
    net_new_keys: Iterable[tuple[int, int]],
    suppressed_keys: Iterable[tuple[int, int]] = (),
    sops_keys: Iterable[tuple[int, int]] = (),
    deduped_keys: Iterable[tuple[int, int]] = (),
) -> Counts:
    """Tally totals, net-new, suppressed, SOPS-ignored, and de-duplicated counts.

    ``suppressed_keys`` are results carrying an author-accepted in-source
    suppression; ``sops_keys`` are secret-scanner hits on a SOPS-encrypted value;
    ``deduped_keys`` are net-new findings collapsed into an earlier identical one.
    All three are disjoint from ``net_new_keys`` (none is ever net-new) and from one
    another, and are broken out so they don't inflate ``pre_existing``.
    """
    keys = set(net_new_keys)
    suppressed_set = set(suppressed_keys)
    sops_set = set(sops_keys)
    deduped_set = set(deduped_keys)
    per_level_total: Counter[str] = Counter()
    per_level_net_new: Counter[str] = Counter()
    per_band_total: Counter[str] = Counter()
    per_band_net_new: Counter[str] = Counter()
    total = 0
    net_new = 0
    suppressed = 0
    sops_ignored = 0
    deduped = 0

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
        elif (run_index, result_index) in suppressed_set:
            suppressed += 1
        elif (run_index, result_index) in sops_set:
            sops_ignored += 1
        elif (run_index, result_index) in deduped_set:
            deduped += 1

    return Counts(
        total=total,
        net_new=net_new,
        suppressed=suppressed,
        sops_ignored=sops_ignored,
        deduped=deduped,
        per_level_total=dict(per_level_total),
        per_level_net_new=dict(per_level_net_new),
        per_band_total=dict(per_band_total),
        per_band_net_new=dict(per_band_net_new),
    )
