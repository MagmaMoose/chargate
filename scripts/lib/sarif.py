"""Shared SARIF 2.1.0 parsing for Chargate's reporting tools.

One parser, several renderers: the HTML dashboard and the GitHub Check Run
annotations both consume findings from here, so severity bucketing and field
extraction stay identical across surfaces.

Contract: parsing must never raise on malformed, partial, or empty SARIF — a
bad result is skipped, a bad file is skipped, an empty scan yields no findings.
"""
import glob
import json
import os
import sys

# ── Severity model ───────────────────────────────────────────────────────────
# GHAS ranks findings with a numeric `security-severity` (0.0–10.0, CVSS-like)
# carried in the rule's properties. We bucket that the same way the Security tab
# does, and fall back to the SARIF `level` when no score is present.
SEVERITIES = ["critical", "high", "medium", "low", "note"]
_LEVEL_TO_SEV = {"error": "high", "warning": "medium", "note": "note", "none": "note"}


def bucket_score(score):
    """CVSS-style score (float) → GHAS severity bucket, or None if unparseable."""
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


def severity(result, rule):
    """Resolve a finding's severity from security-severity (preferred) or level."""
    for src in (result.get("properties"), rule.get("properties")):
        if isinstance(src, dict) and "security-severity" in src:
            bucket = bucket_score(src.get("security-severity"))
            if bucket:
                return bucket
    level = result.get("level") or rule.get("defaultConfiguration", {}).get("level")
    return _LEVEL_TO_SEV.get(level, "note")


def text(node):
    """Pull human text out of a SARIF multiformatMessageString-ish node."""
    if isinstance(node, dict):
        return node.get("text") or node.get("markdown") or ""
    return node if isinstance(node, str) else ""


def location(result):
    """First physical location as (uri, line) — best effort, never raises."""
    try:
        phys = result["locations"][0]["physicalLocation"]
        uri = phys.get("artifactLocation", {}).get("uri") or ""
        line = phys.get("region", {}).get("startLine")
        return uri, line
    except (KeyError, IndexError, TypeError):
        return "", None


def _rule_index(run):
    """Map ruleId → rule object for the run's driver (+ any extension)."""
    index = {}
    tool = run.get("tool", {}) if isinstance(run.get("tool"), dict) else {}
    components = [tool.get("driver", {})] + list(tool.get("extensions", []) or [])
    for comp in components:
        for rule in (comp or {}).get("rules", []) or []:
            if isinstance(rule, dict) and rule.get("id"):
                index[rule["id"]] = rule
    return index


def _tool_name(run):
    try:
        return run["tool"]["driver"]["name"] or "unknown"
    except (KeyError, TypeError):
        return "unknown"


def parse_file(path):
    """Yield finding dicts from one SARIF file. Bad data is skipped, not fatal."""
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError) as exc:
        print(f"chargate: skipping unreadable SARIF {path}: {exc}", file=sys.stderr)
        return
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
                uri, line = location(result)
                yield {
                    "tool": tool,
                    "rule_id": rule_id,
                    "rule_name": text(rule.get("shortDescription")) or rule_id,
                    "severity": severity(result, rule),
                    "message": text(result.get("message")).strip(),
                    "uri": uri,
                    "line": line,
                    "help_uri": rule.get("helpUri") or "",
                }
            except Exception as exc:  # noqa: BLE001 — a single bad result must never abort the report
                print(f"chargate: skipping malformed result in {path}: {exc}", file=sys.stderr)


def collect(sarif_dir):
    """All findings from every *.sarif in a directory, sorted by severity then tool."""
    findings = []
    if os.path.isdir(sarif_dir):
        for path in sorted(glob.glob(os.path.join(sarif_dir, "*.sarif"))):
            findings.extend(parse_file(path))
    order = {sev: i for i, sev in enumerate(SEVERITIES)}
    findings.sort(key=lambda f: (order.get(f["severity"], 99), f["tool"], f["uri"]))
    return findings


def counts(findings):
    """Per-severity tally, keyed by every bucket (zeros included)."""
    out = {sev: 0 for sev in SEVERITIES}
    for f in findings:
        out[f["severity"]] = out.get(f["severity"], 0) + 1
    return out
