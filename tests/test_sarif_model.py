"""Unit tests for SARIF model accessors (chargate.sarif.model).

Focused on the helpers added for the SOPS feature — the rest of ``model`` is
exercised through the filter/counts suites.
"""

from __future__ import annotations

from chargate.sarif.model import (
    canonical_tool_name,
    canonicalize_tool_names,
    is_secret_result,
    tool_driver_name,
)


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


# ── Tool-name canonicalization ──
#
# MegaLinter renames each SARIF run's driver to "<Tool> (MegaLinter <DESCRIPTOR_KEY>)".
# GitHub's Security tab keys its Tools list on that string, so a scanner uploaded under
# both names shows up twice ("Trivy" AND "Trivy (MegaLinter REPOSITORY_TRIVY)").


def test_canonical_tool_name_strips_the_megalinter_suffix():
    assert canonical_tool_name("Trivy (MegaLinter REPOSITORY_TRIVY)") == "Trivy"
    assert canonical_tool_name("Semgrep OSS (MegaLinter REPOSITORY_SEMGREP)") == "Semgrep OSS"
    assert canonical_tool_name("Bandit (MegaLinter PYTHON_BANDIT)") == "Bandit"
    assert canonical_tool_name("devskim (MegaLinter REPOSITORY_DEVSKIM)") == "devskim"


def test_canonical_tool_name_leaves_other_names_alone():
    # Tools that never carried the suffix, and parentheses that are not the suffix.
    for name in ("CodeQL", "Trivy", "syft", "dustilock", "KICS", "grype (v0.74)"):
        assert canonical_tool_name(name) == name


def test_canonical_tool_name_never_returns_empty():
    # A driver named only by the suffix keeps its original name; GitHub rejects "".
    assert canonical_tool_name("(MegaLinter REPOSITORY_TRIVY)") == "(MegaLinter REPOSITORY_TRIVY)"


def test_canonicalize_tool_names_folds_duplicates_in_place(make_sarif, make_result):
    sarif = {
        "runs": [
            make_sarif([make_result("a.py", 1)], tool_name="Trivy (MegaLinter REPOSITORY_TRIVY)")[
                "runs"
            ][0],
            make_sarif([make_result("b.py", 2)], tool_name="Trivy")["runs"][0],
            make_sarif([make_result("c.py", 3)], tool_name="CodeQL")["runs"][0],
        ]
    }
    assert canonicalize_tool_names(sarif) == 1  # only the suffixed run changed
    names = [tool_driver_name(run) for run in sarif["runs"]]
    assert names == ["Trivy", "Trivy", "CodeQL"]
    # Results are untouched — this renames the driver, nothing else.
    assert [len(run["results"]) for run in sarif["runs"]] == [1, 1, 1]


def test_canonicalize_tool_names_tolerates_malformed_runs():
    sarif = {
        "runs": [{}, {"tool": {}}, {"tool": {"driver": {}}}, {"tool": {"driver": {"name": ""}}}]
    }
    assert canonicalize_tool_names(sarif) == 0
    assert canonicalize_tool_names({}) == 0
