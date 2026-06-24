"""Human + machine output helpers: GitHub job summary, step outputs, key=value.

Kept tiny and side-effect-explicit: functions either return strings (pure, easy
to test) or append to the GitHub Actions files named by ``GITHUB_STEP_SUMMARY`` /
``GITHUB_OUTPUT`` when those env vars are present (no-ops otherwise).
"""

from __future__ import annotations

import os
from collections.abc import Mapping, Sequence

from chargate.gate import GateDecision, effective_band
from chargate.github_comment import FINDING_MARKER, SUMMARY_MARKER
from chargate.modes import Mode
from chargate.sarif.counts import Counts
from chargate.sarif.filter import ResultVerdict


def render_summary(
    counts: Counts,
    decision: GateDecision,
    mode: Mode,
    *,
    megalinter_ok: bool = True,
    dd_message: str | None = None,
    dt_message: str | None = None,
    pr_message: str | None = None,
) -> str:
    """Render the Markdown job summary for a CI run."""
    lines: list[str] = ["## Chargate", ""]
    lines.append(
        f"**Mode:** `{mode.value}` · **Gate:** " + ("`fail`" if decision.failed else "`pass`")
    )
    lines.append("")
    lines.append("| Metric | Count |")
    lines.append("|--------|-------|")
    lines.append(f"| Net-new findings | {counts.net_new} |")
    lines.append(f"| Pre-existing (never blocking) | {counts.pre_existing} |")
    lines.append(f"| Total in full SARIF | {counts.total} |")
    if counts.per_band_net_new:
        bands = ", ".join(f"{k}={v}" for k, v in sorted(counts.per_band_net_new.items()))
        lines.append(f"| Net-new by severity | {bands} |")
    lines.append("")

    if not megalinter_ok:
        lines.append(
            "> ⚠️ MegaLinter did not complete cleanly — treated as a tool error, not a finding."
        )
        lines.append("")

    if decision.failed:
        lines.append(
            f"❌ **Blocking {len(decision.blocking)} net-new** (fail_on=`{decision.fail_on}`):"
        )
        lines.append("")
        for verdict in decision.blocking:
            where = verdict.uri or "(no location)"
            if verdict.start_line is not None:
                where = f"{where}:{verdict.start_line}"
            rule = f" `{verdict.rule_id}`" if verdict.rule_id else ""
            lines.append(f"- **{effective_band(verdict)}**{rule} — {where}")
        lines.append("")
    elif not mode.gates:
        lines.append("📋 Baseline scan — full SARIF shipped; no net-new gate.")
        lines.append("")
    else:
        lines.append("✅ No net-new findings introduced by this change.")
        lines.append("")

    if dd_message:
        lines.append(f"**DefectDojo:** {dd_message}")
        lines.append("")

    if dt_message:
        lines.append(f"**Dependency-Track:** {dt_message}")
        lines.append("")

    if pr_message:
        lines.append(f"**PR comments:** {pr_message}")
        lines.append("")

    return "\n".join(lines)


def _finding_line(verdict: ResultVerdict, *, blocking: bool) -> str:
    """One Markdown bullet describing a net-new finding (severity, rule, where, text)."""
    where = verdict.uri or "(no location)"
    if verdict.start_line is not None:
        where = f"{where}:{verdict.start_line}"
    rule = f" `{verdict.rule_id}`" if verdict.rule_id else ""
    text = f" — {verdict.message}" if verdict.message else ""
    icon = "❌" if blocking else "⚠️"  # blocking vs below-threshold net-new
    return f"- {icon} **{effective_band(verdict)}**{rule} — {where}{text}"


def render_pr_summary(
    counts: Counts,
    decision: GateDecision,
    mode: Mode,
    net_new: Sequence[ResultVerdict],
    *,
    note: str | None = None,
    defectdojo_url: str | None = None,
    dependency_track_url: str | None = None,
) -> str:
    """Render the updatable PR summary comment (carries :data:`SUMMARY_MARKER`).

    Lists *every* net-new finding (blocking and below-threshold), marking which
    ones block. Mirrors the job summary but is tuned to live on the PR thread.
    When the full SARIF / BOM were shipped to DefectDojo / Dependency-Track, the
    footer links straight to where they landed.
    """
    blocking_ids = {(v.run_index, v.result_index) for v in decision.blocking}
    gate = "❌ `fail`" if decision.failed else "✅ `pass`"
    lines: list[str] = [
        SUMMARY_MARKER,
        "## Chargate: Security & Linting",
        "",
        f"**Mode:** `{mode.value}` · **Gate:** {gate}",
        "",
        "| Net-new | Pre-existing | Total in full SARIF |",
        "|--------|--------------|---------------------|",
        f"| {counts.net_new} | {counts.pre_existing} | {counts.total} |",
        "",
    ]

    if net_new:
        lines.append(f"**Net-new findings ({len(net_new)}):**")
        lines.append("")
        for verdict in net_new:
            blocking = (verdict.run_index, verdict.result_index) in blocking_ids
            lines.append(_finding_line(verdict, blocking=blocking))
        lines.append("")
    elif mode.gates:
        lines.append("✅ No net-new findings introduced by this change.")
        lines.append("")
    else:
        lines.append("📋 Baseline scan — full SARIF shipped; no net-new gate.")
        lines.append("")

    if note:
        lines.append(note)
        lines.append("")

    uploads: list[str] = []
    if defectdojo_url:
        uploads.append(f"[SARIF in DefectDojo]({defectdojo_url})")
    if dependency_track_url:
        uploads.append(f"[SBOM in Dependency-Track]({dependency_track_url})")
    if uploads:
        lines.append("**Uploaded:** " + " · ".join(uploads))
        lines.append("")

    lines.append(
        "<sub>Pre-existing findings never block. The full, unfiltered SARIF ships to "
        "the Security tab or as an artifact.</sub>"
    )
    return "\n".join(lines)


def render_inline_body(verdict: ResultVerdict) -> str:
    """Render one inline review comment body (carries :data:`FINDING_MARKER`)."""
    rule = f" · `{verdict.rule_id}`" if verdict.rule_id else ""
    headline = f"**{effective_band(verdict)}**{rule}"
    body = verdict.message or "Net-new finding introduced by this change."
    return f"{FINDING_MARKER}\n{headline}\n\n{body}\n\n<sub>Chargate · net-new finding</sub>"


def append_step_summary(text: str) -> None:
    """Append Markdown to the GitHub job summary, if running under Actions."""
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(text + "\n")


def write_outputs(pairs: Mapping[str, str]) -> None:
    """Append ``key=value`` action outputs, if running under Actions."""
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as handle:
        for key, value in pairs.items():
            handle.write(f"{key}={value}\n")
