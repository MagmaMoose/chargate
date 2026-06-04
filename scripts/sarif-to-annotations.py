#!/usr/bin/env python3
"""Turn Chargate's SARIF into a GitHub Checks API `output` object + annotations.

Used by the Chargate GitHub App's scan workflow to report findings as a Check
Run on the pull request — the same SARIF that feeds the HTML dashboard, mapped
onto inline annotations so findings show up right on the diff.

Usage:
  sarif-to-annotations.py --sarif-dir DIR --out check-output.json

Writes a JSON `{title, summary, annotations[]}` ready to drop into the
`output` field of a PATCH /repos/{o}/{r}/check-runs/{id} call, and emits a few
tallies to $GITHUB_OUTPUT (total / per-severity / has_findings / has_blocking)
so the workflow can pick the check conclusion. Never raises on bad SARIF.
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import sarif  # noqa: E402 — local module, path set just above

# GitHub accepts at most 50 annotations per Checks API request. We send one
# batch; anything beyond is summarised as overflow (full detail is in the
# dashboard artifact and the job log).
MAX_ANNOTATIONS = 50

# A finding's severity → the three annotation levels GitHub renders. This is
# presentation only; whether the check *blocks* is the conclusion, set by the
# workflow from has_blocking, not by these levels.
_LEVEL = {
    "critical": "failure",
    "high": "failure",
    "medium": "warning",
    "low": "notice",
    "note": "notice",
}


def annotation(f):
    """One finding → a Checks annotation, or None if it has no location to anchor to."""
    if not f["uri"]:
        return None
    line = f["line"] if isinstance(f["line"], int) and f["line"] > 0 else 1
    title = f"{f['tool']}: {f['rule_id']}".strip(": ") or f["tool"]
    message = f["message"] or f["rule_name"] or f["rule_id"] or "Finding"
    if f["help_uri"]:
        message = f"{message}\n\n{f['help_uri']}"
    return {
        "path": f["uri"],
        "start_line": line,
        "end_line": line,
        "annotation_level": _LEVEL.get(f["severity"], "notice"),
        "title": title[:255],
        "message": message[:64000],
    }


def summary_md(findings, counts, tools, shown, total):
    lines = ["| Severity | Count |", "|----------|-------|"]
    for sev in sarif.SEVERITIES:
        if counts[sev]:
            lines.append(f"| {sev} | {counts[sev]} |")
    body = [
        f"**{total}** finding(s) across **{len(tools)}** tool(s): "
        f"{', '.join(tools) if tools else '—'}.",
        "",
        "\n".join(lines) if total else "✅ No findings.",
    ]
    located = sum(1 for f in findings if f["uri"])
    if shown < located:
        body += ["", f"> Showing the first {shown} of {located} located findings as "
                 "inline annotations. The full set is in the **chargate-security-dashboard** "
                 "artifact on this run."]
    if total - located > 0:
        body += ["", f"> {total - located} finding(s) have no file location and aren't "
                 "shown inline — see the dashboard artifact."]
    return "\n".join(body)


def main(argv=None):
    p = argparse.ArgumentParser(description="SARIF → GitHub Checks output JSON.")
    p.add_argument("--sarif-dir", required=True)
    p.add_argument("--out", required=True, help="Where to write the check `output` JSON.")
    p.add_argument("--title", default="Chargate security & lint")
    p.add_argument("--max-annotations", type=int, default=MAX_ANNOTATIONS)
    args = p.parse_args(argv)

    findings = sarif.collect(args.sarif_dir)
    counts = sarif.counts(findings)
    tools = sorted({f["tool"] for f in findings})
    total = len(findings)
    has_blocking = (counts["critical"] + counts["high"]) > 0

    annotations = []
    for f in findings:
        a = annotation(f)
        if a:
            annotations.append(a)
        if len(annotations) >= args.max_annotations:
            break

    title = f"{args.title} — {total} finding(s)" if total else f"{args.title} — clean"
    output = {"title": title[:255], "summary": summary_md(findings, counts, tools,
                                                           len(annotations), total),
              "annotations": annotations}

    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(output, fh)

    gho = os.environ.get("GITHUB_OUTPUT")
    if gho:
        with open(gho, "a", encoding="utf-8") as fh:
            fh.write(f"total={total}\n")
            for sev in sarif.SEVERITIES:
                fh.write(f"{sev}={counts[sev]}\n")
            fh.write(f"has_findings={'true' if total else 'false'}\n")
            fh.write(f"has_blocking={'true' if has_blocking else 'false'}\n")
    print(f"chargate: {total} finding(s), {len(annotations)} annotation(s) → {args.out}",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
