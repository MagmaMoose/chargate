"""SARIF 2.1.0 → normalised findings.

Mirrors scripts/lib/sarif.py (the CLI/dashboard parser) so a finding looks the
same whether it's rendered to the static HTML artifact or ingested into Postgres.
Tolerant by contract: bad data is skipped, never raised.
"""
from __future__ import annotations

import hashlib
from typing import Any, Iterable

SEVERITIES = ["critical", "high", "medium", "low", "note"]
_LEVEL_TO_SEV = {"error": "high", "warning": "medium", "note": "note", "none": "note"}


def bucket_score(score: Any) -> str | None:
    try:
        s = float(score)
    except (TypeError, ValueError):
        return None
    if s >= 9.0:
        return "critical"
    if s >= 7.0:
        return "high"
    if s >= 4.0:
        return "medium"
    if s > 0.0:
        return "low"
    return "note"


def _severity(result: dict, rule: dict) -> str:
    for src in (result.get("properties"), rule.get("properties")):
        if isinstance(src, dict) and "security-severity" in src:
            bucket = bucket_score(src.get("security-severity"))
            if bucket:
                return bucket
    level = result.get("level") or rule.get("defaultConfiguration", {}).get("level")
    return _LEVEL_TO_SEV.get(level, "note")


def _text(node: Any) -> str:
    if isinstance(node, dict):
        return node.get("text") or node.get("markdown") or ""
    return node if isinstance(node, str) else ""


def _location(result: dict) -> tuple[str, int | None]:
    try:
        phys = result["locations"][0]["physicalLocation"]
        return phys.get("artifactLocation", {}).get("uri") or "", phys.get("region", {}).get("startLine")
    except (KeyError, IndexError, TypeError):
        return "", None


def _rule_index(run: dict) -> dict[str, dict]:
    index: dict[str, dict] = {}
    tool = run.get("tool", {}) if isinstance(run.get("tool"), dict) else {}
    for comp in [tool.get("driver", {})] + list(tool.get("extensions", []) or []):
        for rule in (comp or {}).get("rules", []) or []:
            if isinstance(rule, dict) and rule.get("id"):
                index[rule["id"]] = rule
    return index


def _tool_name(run: dict) -> str:
    try:
        return run["tool"]["driver"]["name"] or "unknown"
    except (KeyError, TypeError):
        return "unknown"


def fingerprint(tool: str, rule_id: str, path: str, line: int | None, message: str) -> str:
    raw = f"{tool}\x00{rule_id}\x00{path}\x00{line or 0}\x00{message}".encode()
    return hashlib.sha256(raw).hexdigest()[:32]


def findings_from_doc(doc: dict) -> Iterable[dict]:
    """Yield normalised finding dicts from one parsed SARIF document."""
    for run in doc.get("runs", []) or []:
        if not isinstance(run, dict):
            continue
        tool = _tool_name(run)
        rules = _rule_index(run)
        for result in run.get("results", []) or []:
            if not isinstance(result, dict):
                continue
            try:
                rule_id = result.get("ruleId") or ""
                rule = rules.get(rule_id, {})
                uri, line = _location(result)
                message = _text(result.get("message")).strip()
                yield {
                    "tool": tool,
                    "rule_id": rule_id,
                    "rule_name": _text(rule.get("shortDescription")) or rule_id,
                    "severity": _severity(result, rule),
                    "message": message,
                    "path": uri or None,
                    "line": line,
                    "help_uri": rule.get("helpUri") or None,
                    "fingerprint": fingerprint(tool, rule_id, uri, line, message),
                }
            except Exception:  # noqa: BLE001 — one bad result must not abort ingest
                continue


def findings_from_docs(docs: Iterable[dict]) -> list[dict]:
    out: list[dict] = []
    for doc in docs:
        if isinstance(doc, dict):
            out.extend(findings_from_doc(doc))
    return out


def tally(findings: list[dict]) -> dict[str, int]:
    counts = {sev: 0 for sev in SEVERITIES}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return counts
