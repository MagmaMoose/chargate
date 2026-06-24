"""Unit tests for reporting helpers (chargate.report)."""

from __future__ import annotations

from pathlib import Path

from chargate.gate import decide_gate
from chargate.github_comment import FINDING_MARKER, SUMMARY_MARKER
from chargate.modes import Mode
from chargate.report import (
    append_step_summary,
    render_inline_body,
    render_pr_summary,
    render_summary,
    write_outputs,
)
from chargate.sarif.diff import DiffIndex, FileDiff
from chargate.sarif.filter import filter_sarif


def _result_and_decision(make_sarif, make_result, fail_on="any"):
    diff = DiffIndex((FileDiff(path="a.py", status="added", added_ranges=((1, 100),)),))
    sarif = make_sarif([make_result("a.py", 1, rule_id="R1", level="error")])
    result = filter_sarif(sarif, diff)
    return result, decide_gate(result, fail_on)


def test_render_summary_pr_fail_lists_blocking(make_sarif, make_result):
    result, decision = _result_and_decision(make_sarif, make_result)
    md = render_summary(result.counts, decision, Mode.PR)
    assert "Gate:** `fail`" in md
    assert "Blocking 1 net-new" in md
    assert "R1" in md


def test_render_summary_pr_pass(make_sarif, make_result):
    result, decision = _result_and_decision(make_sarif, make_result, fail_on="none")
    md = render_summary(result.counts, decision, Mode.PR)
    assert "No net-new findings" in md


def test_render_summary_baseline(make_sarif, make_result):
    diff = DiffIndex(())
    sarif = make_sarif([make_result("a.py", 1, level="error")])
    result = filter_sarif(sarif, diff)
    decision = decide_gate(result, "none")
    md = render_summary(result.counts, decision, Mode.BASELINE)
    assert "Baseline scan" in md


def test_render_summary_notes_megalinter_tool_error(make_sarif, make_result):
    result, decision = _result_and_decision(make_sarif, make_result, fail_on="none")
    md = render_summary(result.counts, decision, Mode.PR, megalinter_ok=False)
    assert "tool error" in md


def test_render_summary_includes_sink_messages(make_sarif, make_result):
    result, decision = _result_and_decision(make_sarif, make_result, fail_on="none")
    md = render_summary(
        result.counts,
        decision,
        Mode.PR,
        dd_message="uploaded",
        dt_message="uploaded",
    )
    assert "**DefectDojo:** uploaded" in md
    assert "**Dependency-Track:** uploaded" in md


def test_render_summary_includes_pr_message(make_sarif, make_result):
    result, decision = _result_and_decision(make_sarif, make_result, fail_on="none")
    md = render_summary(result.counts, decision, Mode.PR, pr_message="summary updated")
    assert "**PR comments:** summary updated" in md


# ── PR comment bodies ────────────────────────────────────────────────────────


def _pr_inputs(make_sarif, make_result, fail_on="any"):
    diff = DiffIndex((FileDiff(path="a.py", status="added", added_ranges=((1, 100),)),))
    sarif = make_sarif(
        [
            make_result(
                "a.py", 4, rule_id="B105", level="error", message="Possible hardcoded password"
            )
        ]
    )
    result = filter_sarif(sarif, diff)
    return result, decide_gate(result, fail_on)


def test_render_pr_summary_lists_net_new_with_marker(make_sarif, make_result):
    result, decision = _pr_inputs(make_sarif, make_result)
    md = render_pr_summary(result.counts, decision, Mode.PR, list(result.net_new))
    assert md.startswith(SUMMARY_MARKER)
    assert "Net-new findings (1)" in md
    assert "a.py:4" in md
    assert "B105" in md
    assert "Possible hardcoded password" in md
    assert "❌" in md  # blocking finding marked


def test_render_pr_summary_pass_when_no_net_new(make_sarif, make_result):
    diff = DiffIndex(())  # nothing changed → no net-new
    sarif = make_sarif([make_result("a.py", 1, level="error")])
    result = filter_sarif(sarif, diff)
    md = render_pr_summary(result.counts, decide_gate(result, "any"), Mode.PR, list(result.net_new))
    assert "No net-new findings" in md


def test_render_pr_summary_appends_note(make_sarif, make_result):
    result, decision = _pr_inputs(make_sarif, make_result)
    md = render_pr_summary(
        result.counts, decision, Mode.PR, list(result.net_new), note="_inline cap hit_"
    )
    assert "_inline cap hit_" in md


def test_render_inline_body_carries_marker_and_detail(make_sarif, make_result):
    result, _ = _pr_inputs(make_sarif, make_result)
    body = render_inline_body(result.net_new[0])
    assert body.startswith(FINDING_MARKER)
    assert "B105" in body
    assert "Possible hardcoded password" in body


def test_write_outputs_and_summary_to_files(tmp_path: Path, monkeypatch, make_sarif, make_result):
    out_file = tmp_path / "out.txt"
    sum_file = tmp_path / "sum.md"
    monkeypatch.setenv("GITHUB_OUTPUT", str(out_file))
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(sum_file))

    write_outputs({"net_new_count": "1", "gate_result": "fail"})
    append_step_summary("## hello")

    assert "net_new_count=1" in out_file.read_text(encoding="utf-8")
    assert "gate_result=fail" in out_file.read_text(encoding="utf-8")
    assert "## hello" in sum_file.read_text(encoding="utf-8")


def test_write_outputs_noop_without_env(monkeypatch):
    monkeypatch.delenv("GITHUB_OUTPUT", raising=False)
    write_outputs({"x": "1"})  # must not raise
