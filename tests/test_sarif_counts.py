"""Unit tests for counts + severity resolution (chargate.sarif.counts/model)."""

from __future__ import annotations

from chargate.sarif.counts import count_results
from chargate.sarif.model import resolve_level, security_severity, severity_band


def test_resolve_level_explicit_then_rule_default_then_warning(make_sarif, make_result):
    rules = [{"id": "R1", "defaultConfiguration": {"level": "error"}}]
    sarif = make_sarif(
        [
            make_result("a.py", 1, level="note"),  # explicit
            make_result("a.py", 2, rule_id="R1"),  # from rule default
            make_result("a.py", 3),  # nothing -> warning
        ],
        rules=rules,
    )
    run = sarif["runs"][0]
    results = run["results"]
    assert resolve_level(results[0], run) == "note"
    assert resolve_level(results[1], run) == "error"
    assert resolve_level(results[2], run) == "warning"


def test_security_severity_and_band(make_sarif, make_result):
    sarif = make_sarif([make_result("a.py", 1, security_severity="8.8")])
    run = sarif["runs"][0]
    value = security_severity(run["results"][0], run)
    assert value == 8.8
    assert severity_band(value) == "high"


def test_severity_band_thresholds():
    assert severity_band(9.5) == "critical"
    assert severity_band(7.0) == "high"
    assert severity_band(4.0) == "medium"
    assert severity_band(0.1) == "low"
    assert severity_band(0.0) == "none"
    assert severity_band(None) is None


def test_count_results_totals_and_breakdowns(make_sarif, make_result):
    results = [
        make_result("a.py", 1, level="error", security_severity="9.1"),
        make_result("a.py", 2, level="warning"),
        make_result("a.py", 3, level="error", security_severity="5.0"),
    ]
    sarif = make_sarif(results)
    # Pretend results 0 and 2 are net-new.
    counts = count_results(sarif, {(0, 0), (0, 2)})

    assert counts.total == 3
    assert counts.net_new == 2
    assert counts.pre_existing == 1
    assert counts.per_level_total == {"error": 2, "warning": 1}
    assert counts.per_level_net_new == {"error": 2}
    assert counts.per_band_total == {"critical": 1, "medium": 1}
    assert counts.per_band_net_new == {"critical": 1, "medium": 1}


def test_count_results_breaks_out_suppressed(make_sarif, make_result):
    results = [
        make_result("a.py", 1, level="error"),  # net-new
        make_result("a.py", 2, level="warning"),  # suppressed
        make_result("a.py", 3, level="note"),  # truly pre-existing
    ]
    sarif = make_sarif(results)
    counts = count_results(sarif, {(0, 0)}, suppressed_keys={(0, 1)})

    assert counts.total == 3
    assert counts.net_new == 1
    assert counts.suppressed == 1
    # Suppressed is carved out of pre-existing: total == net_new + suppressed + pre_existing.
    assert counts.pre_existing == 1


def test_count_results_breaks_out_sops_ignored(make_sarif, make_result):
    results = [
        make_result("a.py", 1, level="error"),  # net-new
        make_result("secret.yaml", 2, level="error"),  # SOPS-encrypted false positive
        make_result("a.py", 3, level="note"),  # truly pre-existing
    ]
    sarif = make_sarif(results)
    counts = count_results(sarif, {(0, 0)}, sops_keys={(0, 1)})

    assert counts.total == 3
    assert counts.net_new == 1
    assert counts.sops_ignored == 1
    # SOPS-ignored is its own bucket: total == net_new + sops_ignored + pre_existing.
    assert counts.pre_existing == 1


def test_count_results_suppressed_and_sops_are_disjoint_buckets(make_sarif, make_result):
    results = [
        make_result("a.py", 1, level="error"),  # net-new
        make_result("a.py", 2, level="warning"),  # suppressed
        make_result("secret.yaml", 3, level="error"),  # SOPS-ignored
        make_result("a.py", 4, level="note"),  # pre-existing
    ]
    sarif = make_sarif(results)
    counts = count_results(sarif, {(0, 0)}, suppressed_keys={(0, 1)}, sops_keys={(0, 2)})

    assert (counts.total, counts.net_new, counts.suppressed, counts.sops_ignored) == (4, 1, 1, 1)
    assert counts.pre_existing == 1


def test_count_results_empty():
    counts = count_results({"runs": []}, set())
    assert counts.total == 0
    assert counts.net_new == 0
    assert counts.suppressed == 0
    assert counts.sops_ignored == 0
    assert counts.per_level_total == {}
