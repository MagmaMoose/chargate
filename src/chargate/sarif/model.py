"""Typed, defensive accessors over SARIF 2.1.0 result objects.

SARIF in the wild is uneven: optional ``level``, severity sometimes only on the
rule's ``defaultConfiguration`` or in ``properties["security-severity"]``,
results with no ``physicalLocation`` at all (project-level findings such as some
Trivy/SBOM/license results). These helpers centralize that messiness so the
filter logic stays readable. Everything here tolerates missing/None fields.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

# SARIF result `level` values, plus a band derived from `security-severity`.
SARIF_LEVELS = ("error", "warning", "note", "none")


def iter_results(sarif: dict[str, Any]) -> Iterator[tuple[int, int, dict, dict]]:
    """Yield ``(run_index, result_index, result, run)`` for every result."""
    for ri, run in enumerate(sarif.get("runs") or []):
        for xi, result in enumerate(run.get("results") or []):
            yield ri, xi, result, run


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
