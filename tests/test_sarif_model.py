"""Unit tests for SARIF model accessors (chargate.sarif.model).

Focused on the helpers added for the SOPS feature — the rest of ``model`` is
exercised through the filter/counts suites.
"""

from __future__ import annotations

from chargate.sarif.model import is_secret_result, tool_driver_name


def _run(sarif: dict) -> dict:
    return sarif["runs"][0]


def test_tool_driver_name(make_sarif):
    assert tool_driver_name(_run(make_sarif([], tool_name="gitleaks"))) == "gitleaks"


def test_tool_driver_name_missing():
    assert tool_driver_name({}) is None
    assert tool_driver_name({"tool": {"driver": {}}}) is None


def test_is_secret_result_by_driver(make_sarif, make_result):
    # Dedicated secret scanners, matched case-insensitively and as a substring.
    for driver in ("gitleaks", "TruffleHog", "secretlint", "gitleaks v8"):
        run = _run(make_sarif([make_result("a.yaml", 1)], tool_name=driver))
        assert is_secret_result(run["results"][0], run), driver


def test_is_secret_result_by_v10_secret_scanner_driver(make_sarif, make_result):
    # MegaLinter v10 removed gitleaks in favour of betterleaks and promoted kingfisher;
    # without these the SOPS false-positive filter silently degrades to keyword matching.
    for driver in ("betterleaks", "Kingfisher", "betterleaks v1.7.3"):
        run = _run(make_sarif([make_result("secrets.enc.yaml", 1)], tool_name=driver))
        assert is_secret_result(run["results"][0], run), driver


def test_is_secret_result_by_checkov_rule(make_sarif, make_result):
    run = _run(make_sarif([make_result("a.yaml", 1, rule_id="CKV_SECRET_6")], tool_name="checkov"))
    assert is_secret_result(run["results"][0], run)


def test_is_secret_result_by_tag(make_sarif):
    result = {"message": {"text": "x"}, "properties": {"tags": ["Secret", "cwe-798"]}}
    run = _run(make_sarif([result], tool_name="Trivy"))
    assert is_secret_result(run["results"][0], run)


def test_is_secret_result_kics_by_rule_name(make_sarif, make_result):
    # The real shape from a MegaLinter run over SOPS files: KICS driver, UUID rule
    # id, the secret signal only in the rule name / message (no tag, no snippet).
    rules = [{"id": "uuid-1", "name": "Passwords And Secrets - Generic Password"}]
    run = _run(
        make_sarif(
            [make_result("secret.yaml", 21, rule_id="uuid-1")], rules=rules, tool_name="KICS"
        )
    )
    assert is_secret_result(run["results"][0], run)


def test_is_secret_result_by_hardcoded_message(make_sarif, make_result):
    run = _run(
        make_sarif(
            [make_result("secret.yaml", 21, message="Hardcoded secret key appears in source")],
            tool_name="KICS",
        )
    )
    assert is_secret_result(run["results"][0], run)


def test_kubernetes_native_secret_mgmt_is_not_a_hardcoded_secret(make_sarif, make_result):
    # A best-practice finding that merely mentions "secret" must NOT be treated as a
    # hardcoded-secret finding (it isn't one, and it doesn't sit on an encrypted value).
    rules = [{"id": "uuid-2", "name": "Using Kubernetes Native Secret Management"}]
    run = _run(
        make_sarif(
            [
                make_result(
                    "secret.yaml",
                    4,
                    rule_id="uuid-2",
                    message="External secret storage is not in use",
                )
            ],
            rules=rules,
            tool_name="KICS",
        )
    )
    assert not is_secret_result(run["results"][0], run)


def test_non_secret_finding_is_not_secret(make_sarif, make_result):
    run = _run(make_sarif([make_result("a.yaml", 1, rule_id="line-length")], tool_name="yamllint"))
    assert not is_secret_result(run["results"][0], run)
