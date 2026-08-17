"""Engine-agnostic finding fingerprints for net-new de-duplication.

Chargate is a SARIF *aggregator*: on any given run it ingests results from many
engines (MegaLinter's own linters, plus optionally CodeQL, Semgrep/Opengrep,
KICS/checkov/hadolint uploads) into one net-new diff gate. When two producers —
or the same producer run twice — report the *same logical finding*, gating and
PR comments must treat it as **one** finding, not N.

The de-dup key is **rule id + fingerprint** (per the decision record in
``docs/sast-benchmark.md``):

* ``fingerprint`` prefers a tool-provided stable fingerprint
  (``result.fingerprints`` / ``result.partialFingerprints``, SARIF 2.1.0 §3.27.16)
  — these survive line shifts and are what GitHub code-scanning itself keys on;
* otherwise it is derived from the primary location (uri + startLine) and the
  message text, which is stable enough to collapse identical re-reports.

The tool/driver name is deliberately **not** part of the key: the same rule id
reported by the same engine across two uploaded SARIFs is one finding. Different
engines emit different rule ids, so their findings never silently merge — that is
intentional, matching the "by rule plus fingerprint" contract.

This module is pure and has no dependency on the filter/gate layer.
"""

from __future__ import annotations

from typing import Any

from chargate.sarif.model import primary_message, primary_start_line, primary_uri

# SARIF result keys carrying a tool-provided fingerprint, most-stable first.
_FINGERPRINT_KEYS = ("fingerprints", "partialFingerprints")


def finding_fingerprint(result: dict[str, Any]) -> str:
    """A stable, engine-agnostic fingerprint for one SARIF result.

    Uses the tool's own ``fingerprints``/``partialFingerprints`` when present
    (deterministically flattened over sorted keys), else falls back to the
    primary location and message text.
    """
    for key in _FINGERPRINT_KEYS:
        fps = result.get(key)
        if isinstance(fps, dict) and fps:
            return ";".join(f"{k}={fps[k]}" for k in sorted(fps))
    uri = primary_uri(result)
    line = primary_start_line(result)
    message = primary_message(result) or ""
    return f"{uri}:{line}:{message}"


def dedup_key(result: dict[str, Any]) -> tuple[str | None, str]:
    """The ``(rule_id, fingerprint)`` key two identical findings share."""
    rule_id = result.get("ruleId")
    return (rule_id if isinstance(rule_id, str) else None, finding_fingerprint(result))
