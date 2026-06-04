from chargate_api.sarif import fingerprint, findings_from_docs, tally

DOC = {
    "version": "2.1.0",
    "runs": [{
        "tool": {"driver": {"name": "Trivy", "rules": [
            {"id": "CVE-1", "shortDescription": {"text": "crit"}, "helpUri": "https://x",
             "properties": {"security-severity": "9.8"}},
            {"id": "CVE-2", "properties": {"security-severity": "3.1"}},
        ]}},
        "results": [
            {"ruleId": "CVE-1", "level": "error", "message": {"text": "boom"},
             "locations": [{"physicalLocation": {"artifactLocation": {"uri": "go.sum"},
                                                 "region": {"startLine": 42}}}]},
            {"ruleId": "CVE-2", "level": "warning", "message": {"text": "meh"},
             "locations": [{"physicalLocation": {"artifactLocation": {"uri": "pkg.json"}}}]},
        ],
    }],
}


def test_parses_and_buckets_severity():
    findings = findings_from_docs([DOC])
    assert len(findings) == 2
    by_rule = {f["rule_id"]: f for f in findings}
    assert by_rule["CVE-1"]["severity"] == "critical"
    assert by_rule["CVE-1"]["path"] == "go.sum"
    assert by_rule["CVE-1"]["line"] == 42
    assert by_rule["CVE-2"]["severity"] == "low"
    assert by_rule["CVE-2"]["line"] is None


def test_tally():
    assert tally(findings_from_docs([DOC])) == {"critical": 1, "high": 0, "medium": 0, "low": 1, "note": 0}


def test_fingerprint_is_stable_and_distinct():
    a = fingerprint("Trivy", "CVE-1", "go.sum", 42, "boom")
    assert a == fingerprint("Trivy", "CVE-1", "go.sum", 42, "boom")
    assert a != fingerprint("Trivy", "CVE-1", "go.sum", 43, "boom")


def test_malformed_input_never_raises():
    assert findings_from_docs([{"runs": "nonsense"}, {}, {"runs": [{"results": [None, 1]}]}]) == []
