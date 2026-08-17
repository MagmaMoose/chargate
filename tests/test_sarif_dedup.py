"""Tests for engine-agnostic net-new de-duplication (chargate.sarif.dedup + filter).

These prove the two contracts the SAST decision record (docs/sast-benchmark.md)
commits chargate to as an aggregator:

1. The same logical finding reported by multiple SARIF producers gates once.
2. Pre-existing debt is *never* net-new, whichever engine reports it — the
   introduced-vs-pre-existing logic is identical across runs.
"""

from __future__ import annotations

from typing import Any

from chargate.sarif.dedup import dedup_key, finding_fingerprint
from chargate.sarif.diff import DiffIndex, FileDiff
from chargate.sarif.filter import FilterPolicy, classify_results, filter_sarif


def _index(*files: FileDiff) -> DiffIndex:
    return DiffIndex(files)


def _multi_run_sarif(*runs: tuple[str, list[dict]]) -> dict[str, Any]:
    """A SARIF with one run per (tool_name, results) pair — an aggregated report."""
    return {
        "version": "2.1.0",
        "runs": [
            {"tool": {"driver": {"name": name}}, "results": results} for name, results in runs
        ],
    }


# ── fingerprint / key ─────────────────────────────────────────────────────────


def test_fingerprint_prefers_tool_provided(make_result):
    result = make_result("src/a.py", 5, rule_id="R1")
    result["partialFingerprints"] = {"primaryLocationLineHash": "abc123:1"}
    assert finding_fingerprint(result) == "primaryLocationLineHash=abc123:1"


def test_fingerprints_beats_partial_fingerprints(make_result):
    # `fingerprints` is listed first in _FINGERPRINT_KEYS as "most stable";
    # when both keys are present it must win over `partialFingerprints`.
    result = make_result("src/a.py", 5, rule_id="R1")
    result["fingerprints"] = {"hkl": "stable-hash"}
    result["partialFingerprints"] = {"primaryLocationLineHash": "abc123:1"}
    assert finding_fingerprint(result) == "hkl=stable-hash"


def test_fingerprint_falls_back_to_location_and_message(make_result):
    result = make_result("src/a.py", 5, message="SQL injection")
    assert finding_fingerprint(result) == "src/a.py:5:SQL injection"


def test_dedup_key_is_rule_plus_fingerprint(make_result):
    result = make_result("src/a.py", 5, rule_id="R1", message="x")
    assert dedup_key(result) == ("R1", "src/a.py:5:x")


# ── de-duplication in classification ──────────────────────────────────────────


def test_identical_net_new_findings_collapse(make_sarif, make_result):
    diff = _index(FileDiff(path="src/a.py", status="added", added_ranges=((1, 9),)))
    sarif = make_sarif(
        [make_result("src/a.py", 5, rule_id="R1"), make_result("src/a.py", 5, rule_id="R1")]
    )
    verdicts = classify_results(sarif, diff)
    assert verdicts[0].net_new and verdicts[0].reason == "new-file"
    assert not verdicts[1].net_new and verdicts[1].reason == "duplicate"


def test_same_finding_from_two_engines_gates_once(make_result):
    diff = _index(FileDiff(path="src/a.py", status="added", added_ranges=((1, 9),)))
    # Two engines (two runs) report the same rule id at the same location.
    sarif = _multi_run_sarif(
        ("Semgrep", [make_result("src/a.py", 5, rule_id="sqli")]),
        ("Semgrep-rescan", [make_result("src/a.py", 5, rule_id="sqli")]),
    )
    result = filter_sarif(sarif, diff)
    assert result.counts.net_new == 1
    assert result.counts.deduped == 1
    assert len(result.net_new) == 1


def test_different_rule_ids_are_not_merged(make_sarif, make_result):
    diff = _index(FileDiff(path="src/a.py", status="added", added_ranges=((1, 9),)))
    sarif = make_sarif(
        [make_result("src/a.py", 5, rule_id="R1"), make_result("src/a.py", 5, rule_id="R2")]
    )
    verdicts = classify_results(sarif, diff)
    assert all(v.net_new for v in verdicts)


def test_dedup_can_be_disabled(make_sarif, make_result):
    diff = _index(FileDiff(path="src/a.py", status="added", added_ranges=((1, 9),)))
    sarif = make_sarif(
        [make_result("src/a.py", 5, rule_id="R1"), make_result("src/a.py", 5, rule_id="R1")]
    )
    verdicts = classify_results(sarif, diff, FilterPolicy(deduplicate=False))
    assert all(v.net_new for v in verdicts)


def test_pre_existing_duplicate_never_counted_as_dedup(make_sarif, make_result):
    # A duplicated finding on an unchanged line is pre-existing, not "duplicate":
    # only *net-new* findings are collapsed.
    diff = _index(FileDiff(path="src/a.py", status="modified", added_ranges=((100, 100),)))
    sarif = make_sarif(
        [make_result("src/a.py", 5, rule_id="R1"), make_result("src/a.py", 5, rule_id="R1")]
    )
    result = filter_sarif(sarif, diff)
    assert result.counts.net_new == 0
    assert result.counts.deduped == 0
    assert result.counts.pre_existing == 2


# ── mixed corpus: introduced findings gate, pre-existing debt never does ───────


def test_mixed_corpus_only_introduced_findings_gate():
    """A file with pre-existing debt on old lines and a newly introduced finding
    across two engines: only the introduced finding gates, exactly once."""
    diff = _index(FileDiff(path="app/views.py", status="modified", added_ranges=((42, 42),)))

    def result(line: int, rule_id: str, message: str = "finding") -> dict[str, Any]:
        return {
            "ruleId": rule_id,
            "message": {"text": message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "app/views.py"},
                        "region": {"startLine": line},
                    }
                }
            ],
        }

    sarif = _multi_run_sarif(
        # CodeQL: one pre-existing (line 5), one introduced (line 42).
        ("CodeQL", [result(5, "py/sql-injection"), result(42, "py/sql-injection")]),
        # Semgrep re-reports the same introduced finding (same rule + location).
        ("Semgrep", [result(42, "py/sql-injection")]),
    )

    out = filter_sarif(sarif, diff)
    assert out.counts.total == 3
    assert out.counts.net_new == 1  # only the introduced finding, collapsed once
    assert out.counts.deduped == 1  # Semgrep's duplicate of it
    assert out.counts.pre_existing == 1  # the line-5 debt, never blocked
    reasons = {(v.reason, v.start_line) for v in out.verdicts}
    assert ("added-line", 42) in reasons
    assert ("pre-existing-line", 5) in reasons
    assert ("duplicate", 42) in reasons
