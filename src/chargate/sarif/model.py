"""Typed, defensive accessors over SARIF 2.1.0 result objects.

SARIF in the wild is uneven: optional ``level``, severity sometimes only on the
rule's ``defaultConfiguration`` or in ``properties["security-severity"]``,
results with no ``physicalLocation`` at all (project-level findings such as some
Trivy/SBOM/license results). These helpers centralize that messiness so the
filter logic stays readable. Everything here tolerates missing/None fields.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

# SARIF result `level` values, plus a band derived from `security-severity`.
SARIF_LEVELS = ("error", "warning", "note", "none")


def iter_results(sarif: dict[str, Any]) -> Iterator[tuple[int, int, dict, dict]]:
    """Yield ``(run_index, result_index, result, run)`` for every result."""
    for ri, run in enumerate(sarif.get("runs") or []):
        for xi, result in enumerate(run.get("results") or []):
            yield ri, xi, result, run


def is_suppressed(result: dict) -> bool:
    """True if a result carries an in-source suppression (SARIF 2.1.0 §3.27.23).

    A result is suppressed iff its ``suppressions`` array is present and non-empty.
    This is how linters report an author-acknowledged accepted risk: checkov's
    ``# checkov:skip=<id>:<reason>``, Bandit's ``# nosec``, Semgrep's
    ``# nosemgrep`` all surface as ``suppressions: [{"kind": "inSource", ...}]``.
    Such a finding is an explicit, in-code decision and must never gate.

    Per SARIF §3.35.3 a suppression's ``status`` is ``accepted`` (the default when
    absent — what checkov/bandit/semgrep emit), ``underReview``, or ``rejected``.
    Only ``accepted`` (or an absent status) suppresses; ``underReview`` and
    ``rejected`` do not, matching GitHub, which keeps those alerts open.
    """
    suppressions = result.get("suppressions")
    if not isinstance(suppressions, list) or not suppressions:
        return False
    return any(
        isinstance(s, dict) and s.get("status", "accepted") == "accepted" for s in suppressions
    )


def tool_driver_name(run: dict) -> str | None:
    """The run's ``tool.driver.name`` (e.g. ``"gitleaks"``, ``"KICS"``), or None."""
    driver = (run.get("tool") or {}).get("driver") or {}
    name = driver.get("name")
    return name if isinstance(name, str) and name else None


# MegaLinter's SarifReporter renames each run's driver to "<Tool> (MegaLinter <KEY>)" —
# e.g. "Trivy (MegaLinter REPOSITORY_TRIVY)". GitHub's Security tab keys its Tools list
# on that string, so the same scanner appears twice whenever anything also uploads it
# under its own name: "Trivy" AND "Trivy (MegaLinter REPOSITORY_TRIVY)", "Semgrep OSS
# (MegaLinter REPOSITORY_SEMGREP)" beside a plain Semgrep, and so on. The suffix carries
# no information the rule ids don't already: it names the MegaLinter descriptor key, not
# the tool or its version.
_MEGALINTER_SUFFIX = re.compile(r"\s*\(MegaLinter\b[^)]*\)\s*$")


def canonical_tool_name(name: str) -> str:
    """``"Trivy (MegaLinter REPOSITORY_TRIVY)"`` -> ``"Trivy"``; other names unchanged.

    Only a trailing ``(MegaLinter ...)`` group is removed, and only if something is left
    over — a driver named nothing but the suffix keeps its original name rather than
    becoming an empty string that GitHub would reject.
    """
    stripped = _MEGALINTER_SUFFIX.sub("", name).strip()
    return stripped or name


def canonicalize_tool_names(sarif: dict[str, Any]) -> int:
    """Rewrite every run's driver name in place; return how many changed.

    In place, and on the FULL document, so the Security-tab upload, the DefectDojo push,
    the artifact and the PR comments all name the tool identically.
    """
    changed = 0
    for run in sarif.get("runs") or []:
        driver = (run.get("tool") or {}).get("driver")
        if not isinstance(driver, dict):
            continue
        name = driver.get("name")
        if not isinstance(name, str) or not name:
            continue
        canonical = canonical_tool_name(name)
        if canonical != name:
            driver["name"] = canonical
            changed += 1
    return changed


# Dedicated secret/credential scanners: every finding is a secret. Matched as a
# substring of the lowercased driver name, so versioned names ("gitleaks v8") hit.
_SECRET_SCANNER_DRIVERS = (
    "gitleaks",  # removed in MegaLinter v10; kept for repos pinned to v8/v9
    "betterleaks",  # v10's replacement for gitleaks (same rules, same config files)
    "kingfisher",
    "trufflehog",
    "secretlint",
    "ggshield",
    "detect-secrets",
    "detect_secrets",
)

# Phrases in a rule's name/description or the result message that mark a
# hardcoded-secret finding from a general-purpose scanner. Verified against a real
# MegaLinter run: KICS was the linter that flagged SOPS files, emitting rule name
# "Passwords And Secrets - Generic Password" and message "Hardcoded secret key
# appears in source" — no driver hint, no `secret` tag, no snippet, UUID rule id.
# MegaLinter v10 removed KICS outright (Checkmarx supply-chain compromise) in favour
# of checkov, whose equivalent findings are already caught by the CKV_SECRET* rule-id
# branch below; these markers stay because they are driver-agnostic and still fire for
# repos pinned to v8/v9 and for any other scanner that words it the same way.
_SECRET_TEXT_MARKERS = ("passwords and secrets", "hardcoded secret", "hard-coded secret")
_HARDCODED = ("hardcoded", "hard-coded", "hard coded")
_CREDENTIAL_WORDS = (
    "secret",
    "password",
    "credential",
    "api key",
    "api-key",
    "private key",
    "token",
)


def _finding_text(result: dict, run: dict) -> str:
    """Lowercased rule name/description + result message, for keyword classification."""
    parts: list[str] = []
    message = result.get("message")
    if isinstance(message, dict) and isinstance(message.get("text"), str):
        parts.append(message["text"])
    rule = _rule_for(result, run)
    if rule is not None:
        if isinstance(rule.get("name"), str):
            parts.append(rule["name"])
        for key in ("shortDescription", "fullDescription"):
            desc = rule.get(key)
            if isinstance(desc, dict) and isinstance(desc.get("text"), str):
                parts.append(desc["text"])
    return " ".join(parts).lower()


def is_secret_result(result: dict, run: dict) -> bool:
    """Best-effort: does this result report a hardcoded secret/credential?

    True when the emitting tool is a dedicated secret scanner (gitleaks,
    trufflehog, secretlint, ...), the rule id is one of checkov's ``CKV_SECRET_*``
    checks, the result carries a ``secret`` tag, or the rule/message text names a
    hardcoded secret — KICS' "Passwords And Secrets" queries (the linter that
    actually flags SOPS files) plus generic "hardcoded password/credential"
    wording. Used to scope the SOPS-encrypted-value false-positive filter to secret
    findings, so a non-secret finding that merely lands on an encrypted line (e.g. a
    yamllint line-length on the long blob) still gates.
    """
    driver = (tool_driver_name(run) or "").lower()
    if any(hint in driver for hint in _SECRET_SCANNER_DRIVERS):
        return True
    rule_id = result.get("ruleId")
    if isinstance(rule_id, str) and rule_id.upper().startswith("CKV_SECRET"):
        return True
    props = result.get("properties")
    if isinstance(props, dict):
        tags = props.get("tags")
        if isinstance(tags, list) and any(
            isinstance(tag, str) and "secret" in tag.lower() for tag in tags
        ):
            return True
    text = _finding_text(result, run)
    if any(marker in text for marker in _SECRET_TEXT_MARKERS):
        return True
    return any(h in text for h in _HARDCODED) and any(w in text for w in _CREDENTIAL_WORDS)


def _primary_location(result: dict) -> dict | None:
    """The primary (first) location of a result, per SARIF convention.

    A result may carry multiple ``locations``; Chargate uses ``locations[0]`` as
    the primary and documents that choice. Returns None when there are none.
    """
    locations = result.get("locations") or []
    if not locations:
        return None
    first = locations[0]
    return first if isinstance(first, dict) else None


def primary_uri(result: dict) -> str | None:
    """artifactLocation.uri of the primary physical location, or None."""
    loc = _primary_location(result)
    if loc is None:
        return None
    phys = loc.get("physicalLocation") or {}
    art = phys.get("artifactLocation") or {}
    uri = art.get("uri")
    return uri if isinstance(uri, str) and uri else None


def primary_start_line(result: dict) -> int | None:
    """region.startLine of the primary physical location, or None."""
    loc = _primary_location(result)
    if loc is None:
        return None
    region = (loc.get("physicalLocation") or {}).get("region") or {}
    start = region.get("startLine")
    return start if isinstance(start, int) else None


# The docstring's example finding deliberately names no hash algorithm and no crypto
# primitive. DevSkim regex-matches raw line *text* and has no idea it is reading a
# docstring, so the previous wording — which quoted a sample finding about a weak
# legacy digest by name — was itself reported as DS126858 "Weak/Broken Hash Algorithm"
# at error level, against a module that does no hashing whatsoever. Rewording is the
# fix rather than a suppression, because there is nothing here to accept: it was never
# code. A permanent error-level false positive in chargate's own SARIF is precisely
# the noise that let an empty report go unnoticed for months. Keep this comment free
# of the algorithm name too, or the rule simply moves down here.
def primary_message(result: dict) -> str | None:
    """The result's human-readable ``message.text``, trimmed, or None.

    This is the finding text a tool reports (e.g. "Image should use digest"); used to
    give PR comments a body. Tolerates missing/blank/oddly-typed messages.
    """
    message = result.get("message")
    if not isinstance(message, dict):
        return None
    text = message.get("text")
    if isinstance(text, str) and text.strip():
        return text.strip()
    return None


def _rule_for(result: dict, run: dict) -> dict | None:
    driver = (run.get("tool") or {}).get("driver") or {}
    rules = driver.get("rules") or []
    rule_id = result.get("ruleId")
    if rule_id is not None:
        for rule in rules:
            if rule.get("id") == rule_id:
                return rule
    idx = result.get("ruleIndex")
    if isinstance(idx, int) and 0 <= idx < len(rules):
        return rules[idx]
    return None


def resolve_level(result: dict, run: dict) -> str:
    """Resolve a result's effective SARIF level.

    Order: explicit ``result.level`` → the rule's ``defaultConfiguration.level``
    → SARIF's own default of ``"warning"`` when nothing else is specified.
    """
    level = result.get("level")
    if isinstance(level, str) and level in SARIF_LEVELS:
        return level
    rule = _rule_for(result, run)
    if rule is not None:
        default_level = (rule.get("defaultConfiguration") or {}).get("level")
        if isinstance(default_level, str) and default_level in SARIF_LEVELS:
            return default_level
    return "warning"


def security_severity(result: dict, run: dict) -> float | None:
    """Numeric ``security-severity`` (GitHub/CVSS convention) if present.

    Checked on the result's ``properties`` first, then the rule's. Used by the
    gate to support a ``fail_on`` severity threshold; not all tools emit it.
    """

    def _read(props: Any) -> float | None:
        if not isinstance(props, dict):
            return None
        value = props.get("security-severity")
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    on_result = _read(result.get("properties"))
    if on_result is not None:
        return on_result
    rule = _rule_for(result, run)
    if rule is not None:
        return _read(rule.get("properties"))
    return None


def severity_band(security_severity_value: float | None) -> str | None:
    """Map a numeric security-severity to a band (GitHub code-scanning thresholds)."""
    if security_severity_value is None:
        return None
    if security_severity_value >= 9.0:
        return "critical"
    if security_severity_value >= 7.0:
        return "high"
    if security_severity_value >= 4.0:
        return "medium"
    if security_severity_value > 0.0:
        return "low"
    return "none"
