"""Run-mode resolution: PR (net-new gate) vs baseline (authoritative full scan).

* **PR events** → ``Mode.PR``: MegaLinter whole-repo, net-new gate, full SARIF to
  DefectDojo/artifact.
* **Push to default branch / scheduled** → ``Mode.BASELINE``: full scan, full SARIF
  to DefectDojo as the authoritative baseline, no net-new gate.
"""

from __future__ import annotations

from enum import StrEnum

_PR_EVENTS = {"pull_request", "pull_request_target"}


class Mode(StrEnum):
    PR = "pr"
    BASELINE = "baseline"

    @property
    def gates(self) -> bool:
        """Whether this mode applies the net-new gate."""
        return self is Mode.PR


def resolve_mode(explicit: str | None = None, event_name: str | None = None) -> Mode:
    """Resolve the run mode from an explicit flag (``auto`` defers to the event)."""
    if explicit and explicit.lower() not in ("", "auto"):
        return Mode(explicit.lower())
    if event_name and event_name.lower() in _PR_EVENTS:
        return Mode.PR
    return Mode.BASELINE
