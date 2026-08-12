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
from chargate.sarif.model import is_suppressed
from chargate.sarif.sops import SopsIndex


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
    # The sample message is inert on purpose — see the note above `primary_message` in
    # sarif/model.py. The previous fixture named a weak legacy digest, which DevSkim
    # matched as DS126858 on both lines below, adding two error-level false positives
    # to chargate's own SARIF for a string that is only ever carried around as data.
    # Do not reintroduce the algorithm name here either; the rule matches line text.
    diff = _index(FileDiff(path="src/a.py", status="modified", added_ranges=((21, 22),)))
    sarif = make_sarif([make_result("src/a.py", 21, message="Image should use digest")])
    [v] = classify_results(sarif, diff)
    assert v.message == "Image should use digest"


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


# ── Suppressions (in-source accepted risks must never gate) ──────────────────


def _suppressed(result: dict, *, status: str | None = None) -> dict:
    """Attach a SARIF in-source suppression, as checkov/bandit/semgrep emit."""
    suppression: dict = {"kind": "inSource", "justification": "accepted risk"}
    if status is not None:
        suppression["status"] = status
    result["suppressions"] = [suppression]
    return result


def test_suppressed_result_on_added_line_is_not_net_new(make_sarif, make_result):
    # The exact shape checkov emits for `# checkov:skip=CKV_AWS_117:...` on a
    # brand-new file — it must be treated as an accepted risk, not a blocker.
    diff = _index(FileDiff(path="src/new.py", status="added", added_ranges=((1, 5),)))
    sarif = make_sarif([_suppressed(make_result("src/new.py", 2, rule_id="CKV_AWS_117"))])
    [v] = classify_results(sarif, diff)
    assert not v.net_new
    assert v.reason == "suppressed"


def test_rejected_suppression_still_gates(make_sarif, make_result):
    # A suppression a reviewer explicitly rejected does not accept the risk.
    diff = _index(FileDiff(path="src/new.py", status="added", added_ranges=((1, 5),)))
    sarif = make_sarif([_suppressed(make_result("src/new.py", 2, rule_id="R1"), status="rejected")])
    [v] = classify_results(sarif, diff)
    assert v.net_new
    assert v.reason == "new-file"


def test_empty_suppressions_array_still_gates(make_sarif, make_result):
    # SARIF: a result is suppressed iff `suppressions` is present *and non-empty*.
    diff = _index(FileDiff(path="src/a.py", status="modified", added_ranges=((21, 22),)))
    result = make_result("src/a.py", 21, rule_id="R1")
    result["suppressions"] = []
    [v] = classify_results(make_sarif([result]), diff)
    assert v.net_new
    assert v.reason == "added-line"


def test_filter_sarif_prunes_suppressed_results(make_sarif, make_result):
    diff = _index(FileDiff(path="src/new.py", status="added", added_ranges=((1, 5),)))
    sarif = make_sarif(
        [
            make_result("src/new.py", 2, rule_id="blocks"),
            _suppressed(make_result("src/new.py", 3, rule_id="accepted")),
        ]
    )
    out = filter_sarif(sarif, diff)
    kept = out.filtered_sarif["runs"][0]["results"]
    assert [r["ruleId"] for r in kept] == ["blocks"]
    assert out.counts.net_new == 1
    # The suppressed result is tallied on its own, not folded into pre-existing.
    assert out.counts.suppressed == 1
    assert out.counts.pre_existing == 0
    assert out.counts.total == 2


def test_is_suppressed_predicate():
    assert is_suppressed({"suppressions": [{"kind": "inSource"}]}) is True
    assert is_suppressed({"suppressions": [{"status": "accepted"}]}) is True
    assert is_suppressed({"suppressions": [{"status": "rejected"}]}) is False
    # `underReview` is not a dismissal (GitHub keeps the alert open), so it gates.
    assert is_suppressed({"suppressions": [{"status": "underReview"}]}) is False
    # Any accepted suppression in the array is enough, even alongside a rejected one.
    assert is_suppressed({"suppressions": [{"status": "rejected"}, {"kind": "inSource"}]}) is True
    assert is_suppressed({"suppressions": []}) is False
    assert is_suppressed({}) is False


# ── SOPS-encrypted secret false positives (never gate) ───────────────────────


def _secret(make_sarif, results):
    """A SARIF run whose driver is a secret scanner (gitleaks)."""
    return make_sarif(results, tool_name="gitleaks")


def _sops(path: str, *lines: int) -> SopsIndex:
    return SopsIndex({path: frozenset(lines)})


def test_secret_on_sops_encrypted_line_is_not_net_new(make_sarif, make_result):
    diff = _index(FileDiff(path="k8s/secret.yaml", status="modified", added_ranges=((7, 7),)))
    sarif = _secret(make_sarif, [make_result("k8s/secret.yaml", 7, rule_id="generic-api-key")])
    [v] = classify_results(sarif, diff, sops_index=_sops("k8s/secret.yaml", 7))
    assert not v.net_new
    assert v.reason == "sops-encrypted"


def test_secret_on_plaintext_line_in_sops_file_still_gates(make_sarif, make_result):
    # "unless it's unencrypted": line 8 is a plaintext secret (not in the index).
    diff = _index(FileDiff(path="k8s/secret.yaml", status="modified", added_ranges=((7, 8),)))
    sarif = _secret(make_sarif, [make_result("k8s/secret.yaml", 8, rule_id="generic-api-key")])
    [v] = classify_results(sarif, diff, sops_index=_sops("k8s/secret.yaml", 7))
    assert v.net_new and v.reason == "added-line"


def test_non_secret_finding_on_encrypted_line_still_gates(make_sarif, make_result):
    # A yamllint line-length on the (unavoidably long) encrypted blob is not a
    # secret finding, so it is out of scope and still gates.
    diff = _index(FileDiff(path="k8s/secret.yaml", status="modified", added_ranges=((7, 7),)))
    sarif = make_sarif(
        [make_result("k8s/secret.yaml", 7, rule_id="line-length")], tool_name="yamllint"
    )
    [v] = classify_results(sarif, diff, sops_index=_sops("k8s/secret.yaml", 7))
    assert v.net_new and v.reason == "added-line"


def test_sops_ignore_disabled_still_gates(make_sarif, make_result):
    diff = _index(FileDiff(path="k8s/secret.yaml", status="modified", added_ranges=((7, 7),)))
    sarif = _secret(make_sarif, [make_result("k8s/secret.yaml", 7, rule_id="generic-api-key")])
    policy = FilterPolicy(ignore_sops_encrypted=False)
    [v] = classify_results(sarif, diff, policy, sops_index=_sops("k8s/secret.yaml", 7))
    assert v.net_new and v.reason == "added-line"


def test_no_sops_index_means_no_suppression(make_sarif, make_result):
    diff = _index(FileDiff(path="k8s/secret.yaml", status="modified", added_ranges=((7, 7),)))
    sarif = _secret(make_sarif, [make_result("k8s/secret.yaml", 7, rule_id="generic-api-key")])
    [v] = classify_results(sarif, diff)  # feature needs the index built at the IO edge
    assert v.net_new and v.reason == "added-line"


def test_in_source_suppression_wins_over_sops(make_sarif, make_result):
    # Both signals say "don't gate"; the author suppression is reported as such.
    diff = _index(FileDiff(path="k8s/secret.yaml", status="added", added_ranges=((1, 9),)))
    sarif = _secret(make_sarif, [_suppressed(make_result("k8s/secret.yaml", 7, rule_id="R1"))])
    [v] = classify_results(sarif, diff, sops_index=_sops("k8s/secret.yaml", 7))
    assert not v.net_new and v.reason == "suppressed"


def test_filter_sarif_prunes_sops_ignored_and_tallies(make_sarif, make_result):
    diff = _index(FileDiff(path="k8s/secret.yaml", status="added", added_ranges=((1, 9),)))
    sarif = _secret(
        make_sarif,
        [
            make_result("k8s/secret.yaml", 6, rule_id="plaintext-leak"),  # net-new, gates
            make_result("k8s/secret.yaml", 7, rule_id="encrypted-fp"),  # SOPS false positive
        ],
    )
    out = filter_sarif(sarif, diff, sops_index=_sops("k8s/secret.yaml", 7))
    kept = out.filtered_sarif["runs"][0]["results"]
    assert [r["ruleId"] for r in kept] == ["plaintext-leak"]
    assert out.counts.net_new == 1
    assert out.counts.sops_ignored == 1
    assert out.counts.pre_existing == 0
    assert out.counts.total == 2
