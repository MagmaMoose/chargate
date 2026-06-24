"""Classify SARIF results as net-new vs pre-existing against a diff — pure.

A result is **net-new** (gate-blocking) iff its primary location's file is in the
diff *and*, at line precision, its ``startLine`` falls inside an added/modified
hunk. All edge-case policies (no-location, renamed/copied, deleted, no-region
fallback, precision) are expressed on :class:`FilterPolicy` and applied here.

The full input SARIF is never mutated; :func:`filter_sarif` returns a pruned deep
copy containing only the net-new results, alongside per-result verdicts (with a
human-readable reason for gate citations) and :class:`Counts`.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from enum import StrEnum
from typing import Any
from urllib.parse import unquote

from chargate.sarif.counts import Counts, count_results
from chargate.sarif.diff import DiffIndex, FileDiff, normalize_path
from chargate.sarif.model import (
    iter_results,
    primary_message,
    primary_start_line,
    primary_uri,
    resolve_level,
    security_severity,
    severity_band,
)


class Precision(StrEnum):
    """Net-new precision: per-line (default) or whole-file."""

    LINE = "line"
    FILE = "file"


class NoLocationPolicy(StrEnum):
    """How to treat results with no usable file location (project-level findings)."""

    IGNORE = "ignore"  # default: never block on project-level findings
    BLOCK = "block"


@dataclass(frozen=True)
class FilterPolicy:
    """Knobs controlling net-new classification.

    ``file_level_fallback_when_no_region``: when a result's file *is* in the diff
    but it carries no ``startLine`` (common for SCA findings attached to a changed
    lockfile), treat it as net-new even at line precision. This stops a genuinely
    PR-introduced dependency vulnerability from slipping through, while truly
    project-global findings (no file at all) still fall under ``no_location_policy``.
    """

    precision: Precision = Precision.LINE
    no_location_policy: NoLocationPolicy = NoLocationPolicy.IGNORE
    file_level_fallback_when_no_region: bool = True
    # Path prefixes (e.g. container workspace roots) stripped from SARIF URIs
    # before matching against diff paths. `chargate ci` sets these per runtime.
    strip_prefixes: tuple[str, ...] = ()


# `_classify_one` reasons whose result is guaranteed to sit on a RIGHT-side line
# that is part of the PR diff (so a GitHub inline review comment cannot 422).
_INLINE_SAFE_REASONS = frozenset({"added-line", "new-file"})


@dataclass(frozen=True)
class ResultVerdict:
    """The net-new verdict for a single SARIF result, with provenance."""

    run_index: int
    result_index: int
    net_new: bool
    reason: str
    uri: str | None
    start_line: int | None
    level: str
    band: str | None = None  # security-severity band (critical/high/...) if the tool emits one
    rule_id: str | None = None
    message: str | None = None  # the tool's finding text, for PR comment bodies

    @property
    def inline_safe(self) -> bool:
        """Whether this verdict maps to a line that's guaranteed to be in the diff.

        Only ``added-line`` / ``new-file`` net-new results sit on a RIGHT-side
        changed line, so only those are safe targets for an inline review comment
        (others would 422). File-precision and no-region findings go to the summary.
        """
        return self.net_new and self.start_line is not None and self.reason in _INLINE_SAFE_REASONS


@dataclass(frozen=True)
class FilterResult:
    """Output of :func:`filter_sarif`."""

    filtered_sarif: dict[str, Any]
    verdicts: tuple[ResultVerdict, ...]
    counts: Counts

    @property
    def net_new(self) -> tuple[ResultVerdict, ...]:
        return tuple(v for v in self.verdicts if v.net_new)


def normalize_sarif_uri(uri: str, strip_prefixes: tuple[str, ...] = ()) -> str:
    """Normalize a SARIF artifact URI to a repo-relative path for diff matching.

    Handles ``file://`` scheme, percent-encoding, backslashes, leading ``./`` and
    optional container/workspace prefixes. MegaLinter with
    ``SARIF_REPORTER_NORMALIZE_LINTERS_OUTPUT=true`` already emits repo-relative
    URIs, so by default this is mostly a no-op.
    """
    value = uri
    if value.startswith("file://"):
        value = value[len("file://") :]
    value = unquote(value).replace("\\", "/")
    value = normalize_path(value)
    for prefix in strip_prefixes:
        norm_prefix = normalize_path(prefix.replace("\\", "/")).rstrip("/")
        if not norm_prefix:
            continue
        for candidate in (norm_prefix + "/", norm_prefix.lstrip("/") + "/"):
            if value.startswith(candidate):
                value = value[len(candidate) :]
                break
    return value.lstrip("/") if value.startswith("/") else value


def _classify_one(
    uri: str | None,
    start_line: int | None,
    changed: dict[str, FileDiff],
    policy: FilterPolicy,
) -> tuple[bool, str]:
    if uri is None:
        if policy.no_location_policy is NoLocationPolicy.BLOCK:
            return True, "no-location-blocked"
        return False, "no-location-ignored"

    norm = normalize_sarif_uri(uri, policy.strip_prefixes)
    file_diff = changed.get(norm)
    if file_diff is None:
        return False, "file-not-changed"
    if file_diff.is_deleted:
        return False, "deleted-file"
    if file_diff.is_new_file:
        return True, "new-file"

    # File is modified/renamed/copied with content on the new side.
    if policy.precision is Precision.FILE:
        return True, "file-precision"

    if start_line is None:
        if policy.file_level_fallback_when_no_region:
            return True, "no-region-file-fallback"
        if policy.no_location_policy is NoLocationPolicy.BLOCK:
            return True, "no-region-blocked"
        return False, "no-region-ignored"

    if file_diff.contains_line(start_line):
        return True, "added-line"
    return False, "pre-existing-line"


def classify_results(
    sarif: dict[str, Any],
    diff_index: DiffIndex,
    policy: FilterPolicy | None = None,
) -> tuple[ResultVerdict, ...]:
    """Return a verdict for every result in document order."""
    policy = policy or FilterPolicy()
    changed = diff_index.as_dict()
    verdicts: list[ResultVerdict] = []
    for run_index, result_index, result, run in iter_results(sarif):
        uri = primary_uri(result)
        start_line = primary_start_line(result)
        level = resolve_level(result, run)
        band = severity_band(security_severity(result, run))
        net_new, reason = _classify_one(uri, start_line, changed, policy)
        verdicts.append(
            ResultVerdict(
                run_index=run_index,
                result_index=result_index,
                net_new=net_new,
                reason=reason,
                uri=uri,
                start_line=start_line,
                level=level,
                band=band,
                rule_id=result.get("ruleId"),
                message=primary_message(result),
            )
        )
    return tuple(verdicts)


def filter_sarif(
    sarif: dict[str, Any],
    diff_index: DiffIndex,
    policy: FilterPolicy | None = None,
) -> FilterResult:
    """Classify, then return a pruned deep copy with only net-new results.

    The input ``sarif`` is left untouched (it is the full report shipped to
    DefectDojo / uploaded as an artifact).
    """
    verdicts = classify_results(sarif, diff_index, policy)
    keep = {(v.run_index, v.result_index) for v in verdicts if v.net_new}

    filtered = copy.deepcopy(sarif)
    for run_index, run in enumerate(filtered.get("runs") or []):
        results = run.get("results") or []
        run["results"] = [
            result
            for result_index, result in enumerate(results)
            if (run_index, result_index) in keep
        ]

    return FilterResult(
        filtered_sarif=filtered,
        verdicts=verdicts,
        counts=count_results(sarif, keep),
    )
