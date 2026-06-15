"""Turn a net-new filter result into a pass/fail gate decision.

The gate blocks on net-new results whose *effective severity* meets a configurable
``fail_on`` threshold. Effective severity unifies the two scales SARIF tools use:
a numeric ``security-severity`` band when present (critical/high/medium/low/none),
otherwise a mapping from the SARIF ``level`` (error→high, warning→medium,
note→low). ``fail_on="any"`` (the default) blocks on any net-new finding — the
product's core promise — while ``fail_on="high"`` etc. raise the bar, and
``fail_on="none"`` makes the run report-only.
"""

from __future__ import annotations

from dataclasses import dataclass

from chargate.sarif.filter import FilterResult, ResultVerdict

# Exit-code contract (mirrors the legacy chargate scripts):
#   0 pass · 1 blocking net-new findings · 2 setup/tool error (handled in the CLI).
EXIT_OK = 0
EXIT_BLOCKED = 1
EXIT_ERROR = 2

FAIL_ON_CHOICES = ("any", "critical", "high", "medium", "low", "none")

_BAND_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_LEVEL_TO_BAND = {"error": "high", "warning": "medium", "note": "low", "none": "none"}


def effective_band(verdict: ResultVerdict) -> str:
    """The verdict's effective severity band (security-severity, else level-derived)."""
    if verdict.band is not None:
        return verdict.band
    return _LEVEL_TO_BAND.get(verdict.level, "medium")


@dataclass(frozen=True)
class GateDecision:
    failed: bool
    fail_on: str
    blocking: tuple[ResultVerdict, ...]
    net_new_total: int

    @property
    def exit_code(self) -> int:
        return EXIT_BLOCKED if self.failed else EXIT_OK


def decide_gate(result: FilterResult, fail_on: str = "any") -> GateDecision:
    """Decide whether the net-new set blocks, given a ``fail_on`` threshold."""
    normalized = fail_on.lower()
    if normalized not in FAIL_ON_CHOICES:
        raise ValueError(f"invalid fail_on {fail_on!r}; choose one of {', '.join(FAIL_ON_CHOICES)}")

    net_new = result.net_new
    if normalized == "none":
        blocking: tuple[ResultVerdict, ...] = ()
    elif normalized == "any":
        blocking = net_new
    else:
        threshold = _BAND_RANK[normalized]
        blocking = tuple(v for v in net_new if _BAND_RANK[effective_band(v)] >= threshold)

    return GateDecision(
        failed=bool(blocking),
        fail_on=normalized,
        blocking=blocking,
        net_new_total=len(net_new),
    )
