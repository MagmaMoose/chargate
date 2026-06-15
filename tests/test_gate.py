"""Unit tests for the gate decision (chargate.gate)."""

from __future__ import annotations

import pytest

from chargate.gate import EXIT_BLOCKED, EXIT_OK, decide_gate, effective_band
from chargate.sarif.diff import DiffIndex, FileDiff
from chargate.sarif.filter import ResultVerdict, filter_sarif


def _all_new_diff() -> DiffIndex:
    return DiffIndex((FileDiff(path="a.py", status="added", added_ranges=((1, 100),)),))


def _verdict(level: str, band: str | None = None) -> ResultVerdict:
    return ResultVerdict(0, 0, True, "new-file", "a.py", 1, level, band)


def test_effective_band_prefers_explicit_band():
    assert effective_band(_verdict("note", "critical")) == "critical"


def test_effective_band_maps_level_when_no_band():
    assert effective_band(_verdict("error")) == "high"
    assert effective_band(_verdict("warning")) == "medium"
    assert effective_band(_verdict("note")) == "low"


def test_fail_on_any_blocks_on_any_net_new(make_sarif, make_result):
    sarif = make_sarif([make_result("a.py", 1, level="note")])
    decision = decide_gate(filter_sarif(sarif, _all_new_diff()), "any")
    assert decision.failed
    assert decision.exit_code == EXIT_BLOCKED
    assert decision.net_new_total == 1


def test_fail_on_high_ignores_low_severity(make_sarif, make_result):
    sarif = make_sarif([make_result("a.py", 1, level="note")])  # low band
    decision = decide_gate(filter_sarif(sarif, _all_new_diff()), "high")
    assert not decision.failed
    assert decision.exit_code == EXIT_OK
    assert decision.net_new_total == 1  # still net-new, just below threshold


def test_fail_on_high_blocks_high_severity(make_sarif, make_result):
    sarif = make_sarif([make_result("a.py", 1, security_severity="8.0")])
    decision = decide_gate(filter_sarif(sarif, _all_new_diff()), "high")
    assert decision.failed
    assert len(decision.blocking) == 1


def test_fail_on_none_is_report_only(make_sarif, make_result):
    sarif = make_sarif([make_result("a.py", 1, level="error")])
    decision = decide_gate(filter_sarif(sarif, _all_new_diff()), "none")
    assert not decision.failed
    assert decision.net_new_total == 1


def test_pre_existing_never_counts(make_sarif, make_result):
    # Finding on an unchanged file is not net-new, so it can't block.
    diff = DiffIndex((FileDiff(path="changed.py", status="modified", added_ranges=((1, 1),)),))
    sarif = make_sarif([make_result("untouched.py", 50, level="error")])
    decision = decide_gate(filter_sarif(sarif, diff), "any")
    assert not decision.failed
    assert decision.net_new_total == 0


def test_invalid_fail_on_raises(make_sarif, make_result):
    sarif = make_sarif([make_result("a.py", 1)])
    with pytest.raises(ValueError, match="invalid fail_on"):
        decide_gate(filter_sarif(sarif, _all_new_diff()), "bogus")
