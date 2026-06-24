"""Unit tests for net-new classification (chargate.sarif.filter)."""

from __future__ import annotations

from chargate.sarif.diff import DiffIndex, FileDiff
from chargate.sarif.filter import (
    FilterPolicy,
    NoLocationPolicy,
    Precision,
    classify_results,
    filter_sarif,
    normalize_sarif_uri,
)


def _index(*files: FileDiff) -> DiffIndex:
    return DiffIndex(files)


def _verdict_for(verdicts, uri):
    return next(v for v in verdicts if v.uri == uri)


# ── URI normalization ────────────────────────────────────────────────────────


def test_normalize_sarif_uri_handles_scheme_and_prefix():
    assert (
        normalize_sarif_uri("file:///github/workspace/src/a.py", ("/github/workspace",))
        == "src/a.py"
    )
    assert normalize_sarif_uri("./src/a.py") == "src/a.py"
    assert normalize_sarif_uri("src/with%20space.py") == "src/with space.py"


# ── Core edge cases (acceptance criteria) ────────────────────────────────────


def test_new_file_all_results_net_new(make_sarif, make_result):
    diff = _index(FileDiff(path="src/new.py", status="added", added_ranges=((1, 5),)))
    sarif = make_sarif([make_result("src/new.py", 2), make_result("src/new.py", 99)])
    verdicts = classify_results(sarif, diff)
    # Every result in a brand-new file is net-new, even a line outside the hunk
    # range (the whole file is new — defensive against odd tool line numbers).
    assert verdicts[0].net_new and verdicts[0].reason == "new-file"
    assert verdicts[1].net_new and verdicts[1].reason == "new-file"


def test_added_line_in_modified_file_is_net_new(make_sarif, make_result):
    diff = _index(FileDiff(path="src/a.py", status="modified", added_ranges=((21, 22),)))
    sarif = make_sarif([make_result("src/a.py", 21)])
    [v] = classify_results(sarif, diff)
    assert v.net_new and v.reason == "added-line"


def test_unchanged_line_in_changed_file_is_pre_existing(make_sarif, make_result):
    diff = _index(FileDiff(path="src/a.py", status="modified", added_ranges=((21, 22),)))
    sarif = make_sarif([make_result("src/a.py", 5)])
    [v] = classify_results(sarif, diff)
    assert not v.net_new and v.reason == "pre-existing-line"


def test_result_in_unchanged_file_is_pre_existing(make_sarif, make_result):
    diff = _index(FileDiff(path="src/a.py", status="modified", added_ranges=((1, 1),)))
    sarif = make_sarif([make_result("src/other.py", 1)])
    [v] = classify_results(sarif, diff)
    assert not v.net_new and v.reason == "file-not-changed"


def test_deleted_file_results_dropped(make_sarif, make_result):
    diff = _index(FileDiff(path="src/gone.py", status="deleted"))
    sarif = make_sarif([make_result("src/gone.py", 1)])
    [v] = classify_results(sarif, diff)
    assert not v.net_new and v.reason == "deleted-file"


def test_no_location_default_not_net_new(make_sarif, make_result):
    diff = _index(FileDiff(path="src/a.py", status="added", added_ranges=((1, 1),)))
    sarif = make_sarif([make_result(uri=None)])  # project-level finding
    [v] = classify_results(sarif, diff)
    assert not v.net_new and v.reason == "no-location-ignored"


def test_no_location_block_policy(make_sarif, make_result):
    diff = _index()
    sarif = make_sarif([make_result(uri=None)])
    policy = FilterPolicy(no_location_policy=NoLocationPolicy.BLOCK)
    [v] = classify_results(sarif, diff, policy)
    assert v.net_new and v.reason == "no-location-blocked"


# ── Renames, precision, and the SCA no-region fallback ───────────────────────


def test_renamed_file_matched_by_head_path(make_sarif, make_result):
    diff = _index(
        FileDiff(
            path="new/name.py", status="renamed", added_ranges=((5, 5),), old_path="old/name.py"
        )
    )
    sarif = make_sarif([make_result("new/name.py", 5), make_result("new/name.py", 1)])
    verdicts = classify_results(sarif, diff)
    assert _verdict_for(verdicts, "new/name.py").net_new  # line 5 is in the changed range
    line1 = next(v for v in verdicts if v.start_line == 1)
    assert not line1.net_new and line1.reason == "pre-existing-line"


def test_file_precision_treats_any_changed_file_result_as_net_new(make_sarif, make_result):
    diff = _index(FileDiff(path="src/a.py", status="modified", added_ranges=((21, 22),)))
    sarif = make_sarif([make_result("src/a.py", 5)])
    [v] = classify_results(sarif, diff, FilterPolicy(precision=Precision.FILE))
    assert v.net_new and v.reason == "file-precision"


# ── Provenance carried for PR comments (message + inline_safe) ────────────────


def test_verdict_carries_finding_message(make_sarif, make_result):
    diff = _index(FileDiff(path="src/a.py", status="modified", added_ranges=((21, 22),)))
    sarif = make_sarif([make_result("src/a.py", 21, message="Use of weak MD5 hash")])
    [v] = classify_results(sarif, diff)
    assert v.message == "Use of weak MD5 hash"


def test_inline_safe_only_for_added_line_and_new_file(make_sarif, make_result):
    # added-line → safe inline target
    added = _index(FileDiff(path="src/a.py", status="modified", added_ranges=((21, 22),)))
    [v_added] = classify_results(make_sarif([make_result("src/a.py", 21)]), added)
    assert v_added.reason == "added-line" and v_added.inline_safe

    # new-file → safe inline target
    new = _index(FileDiff(path="src/new.py", status="added", added_ranges=((1, 5),)))
    [v_new] = classify_results(make_sarif([make_result("src/new.py", 2)]), new)
    assert v_new.reason == "new-file" and v_new.inline_safe

    # file-precision (line may be outside the diff) → NOT inline-safe
    [v_file] = classify_results(
        make_sarif([make_result("src/a.py", 5)]), added, FilterPolicy(precision=Precision.FILE)
    )
    assert v_file.net_new and not v_file.inline_safe

    # no-region fallback (no start_line at all) → NOT inline-safe
    lock = _index(FileDiff(path="lock.json", status="modified", added_ranges=((1, 9),)))
    [v_noregion] = classify_results(make_sarif([make_result("lock.json", start_line=None)]), lock)
    assert v_noregion.net_new and not v_noregion.inline_safe


def test_no_region_in_changed_file_falls_back_to_file_level_by_default(make_sarif, make_result):
    # SCA findings (e.g. a new vuln in a changed lockfile) often lack a startLine.
    diff = _index(FileDiff(path="package-lock.json", status="modified", added_ranges=((100, 120),)))
    sarif = make_sarif([make_result("package-lock.json", start_line=None)])
    [v] = classify_results(sarif, diff)
    assert v.net_new and v.reason == "no-region-file-fallback"


def test_no_region_fallback_disabled_does_not_block(make_sarif, make_result):
    diff = _index(FileDiff(path="package-lock.json", status="modified", added_ranges=((100, 120),)))
    sarif = make_sarif([make_result("package-lock.json", start_line=None)])
    policy = FilterPolicy(file_level_fallback_when_no_region=False)
    [v] = classify_results(sarif, diff, policy)
    assert not v.net_new and v.reason == "no-region-ignored"


def test_multiple_locations_uses_primary(make_sarif, make_result):
    diff = _index(FileDiff(path="src/a.py", status="modified", added_ranges=((10, 10),)))
    # Primary location is an unchanged line in a changed file; secondary is changed.
    locations = [
        {"physicalLocation": {"artifactLocation": {"uri": "src/a.py"}, "region": {"startLine": 5}}},
        {
            "physicalLocation": {
                "artifactLocation": {"uri": "src/a.py"},
                "region": {"startLine": 10},
            }
        },
    ]
    sarif = make_sarif([make_result(locations=locations)])
    [v] = classify_results(sarif, diff)
    assert v.start_line == 5
    assert not v.net_new and v.reason == "pre-existing-line"


# ── filter_sarif: pruning, immutability, counts ──────────────────────────────


def test_filter_sarif_keeps_only_net_new_and_preserves_full(make_sarif, make_result):
    # Acceptance: N=2 pre-existing + 1 net-new -> filtered has exactly 1; full untouched.
    diff = _index(FileDiff(path="src/a.py", status="modified", added_ranges=((30, 30),)))
    results = [
        make_result("src/a.py", 5, rule_id="pre-1"),
        make_result("src/a.py", 6, rule_id="pre-2"),
        make_result("src/a.py", 30, rule_id="net-new-1"),
    ]
    sarif = make_sarif(results)
    out = filter_sarif(sarif, diff)

    assert out.counts.total == 3
    assert out.counts.net_new == 1
    assert out.counts.pre_existing == 2

    kept = out.filtered_sarif["runs"][0]["results"]
    assert len(kept) == 1
    assert kept[0]["ruleId"] == "net-new-1"

    # Full input SARIF must be untouched (it ships to DefectDojo / artifact).
    assert len(sarif["runs"][0]["results"]) == 3
    # And the filtered copy must not alias the input results.
    kept[0]["ruleId"] = "MUTATED"
    assert sarif["runs"][0]["results"][2]["ruleId"] == "net-new-1"


def test_filter_sarif_preserves_tool_driver(make_sarif, make_result):
    diff = _index(FileDiff(path="src/a.py", status="added", added_ranges=((1, 1),)))
    rules = [{"id": "R1", "defaultConfiguration": {"level": "error"}}]
    sarif = make_sarif([make_result("src/a.py", 1, rule_id="R1")], rules=rules)
    out = filter_sarif(sarif, diff)
    driver = out.filtered_sarif["runs"][0]["tool"]["driver"]
    assert driver["name"] == "TestTool"
    assert driver["rules"][0]["id"] == "R1"
