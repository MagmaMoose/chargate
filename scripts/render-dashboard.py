#!/usr/bin/env python3
"""Render Chargate's SARIF output into a single self-contained HTML dashboard.

This is the no-GHAS "Security tab": the same SARIF that github/codeql-action
would upload (and which is silently dropped on private repos without a GitHub
Advanced Security licence) is parsed here and rendered into one static HTML
page — no JavaScript required to read it, no external assets, no network.

Usage:
  render-dashboard.py --sarif-dir DIR --out FILE.html

Metadata for the header is read from CLI flags, falling back to the standard
GitHub Actions environment variables, falling back to sensible defaults — so it
works the same in CI and when run by hand against a local SARIF directory.

Design contract: this is a *reporting* tool, never a gate. It must not crash on
malformed, partial, or empty SARIF — a bad finding is skipped, a bad file is
skipped, and an empty scan renders a clean "no findings" page. It always exits 0
unless its arguments are unusable.
"""
import argparse
import glob
import html
import json
import os
import sys
from datetime import datetime, timezone

# ── Severity model ───────────────────────────────────────────────────────────
# GHAS ranks findings with a numeric `security-severity` (0.0–10.0, CVSS-like)
# carried in the rule's properties. We bucket that the same way the Security tab
# does, and fall back to the SARIF `level` when no score is present.
SEVERITIES = ["critical", "high", "medium", "low", "note"]
_LEVEL_TO_SEV = {"error": "high", "warning": "medium", "note": "note", "none": "note"}


def _bucket_score(score):
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


def _severity(result, rule):
    """Resolve a finding's severity from security-severity (preferred) or level."""
    for src in (result.get("properties"), rule.get("properties")):
        if isinstance(src, dict) and "security-severity" in src:
            bucket = _bucket_score(src.get("security-severity"))
            if bucket:
                return bucket
    level = result.get("level") or rule.get("defaultConfiguration", {}).get("level")
    return _LEVEL_TO_SEV.get(level, "note")


# ── SARIF parsing ────────────────────────────────────────────────────────────
def _text(node):
    """Pull human text out of a SARIF multiformatMessageString-ish node."""
    if isinstance(node, dict):
        return node.get("text") or node.get("markdown") or ""
    return node if isinstance(node, str) else ""


def _location(result):
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


def parse_sarif_file(path):
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
                uri, line = _location(result)
                yield {
                    "tool": tool,
                    "rule_id": rule_id,
                    "rule_name": _text(rule.get("shortDescription")) or rule_id,
                    "severity": _severity(result, rule),
                    "message": _text(result.get("message")).strip(),
                    "uri": uri,
                    "line": line,
                    "help_uri": rule.get("helpUri") or "",
                }
            except Exception as exc:  # noqa: BLE001 — a single bad result must never abort the report
                print(f"chargate: skipping malformed result in {path}: {exc}", file=sys.stderr)


def collect(sarif_dir):
    findings = []
    for path in sorted(glob.glob(os.path.join(sarif_dir, "*.sarif"))):
        findings.extend(parse_sarif_file(path))
    return findings


# ── HTML rendering ───────────────────────────────────────────────────────────
def esc(value):
    return html.escape("" if value is None else str(value))


CSS = """
:root{color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;background:#0d1117;color:#e6edf3;font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif}
a{color:#58a6ff;text-decoration:none}a:hover{text-decoration:underline}
header{padding:24px 32px;border-bottom:1px solid #30363d;background:#161b22}
header h1{margin:0 0 4px;font-size:20px}
header h1 .shield{color:#da3633}
.meta{color:#8b949e;font-size:12px}
.meta code{background:#21262d;padding:1px 6px;border-radius:6px;color:#c9d1d9}
main{padding:24px 32px;max-width:1200px;margin:0 auto}
.cards{display:flex;flex-wrap:wrap;gap:12px;margin-bottom:24px}
.card{flex:1;min-width:120px;background:#161b22;border:1px solid #30363d;border-radius:8px;padding:14px 16px}
.card .n{font-size:26px;font-weight:600}
.card .l{font-size:12px;color:#8b949e;text-transform:uppercase;letter-spacing:.04em}
.card.critical{border-color:#da3633}.card.critical .n{color:#ff7b72}
.card.high{border-color:#bb8009}.card.high .n{color:#e3b341}
.card.medium .n{color:#d29922}.card.low .n{color:#58a6ff}.card.note .n{color:#8b949e}
.bar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:14px}
.bar .tools{color:#8b949e;font-size:12px}
table{width:100%;border-collapse:collapse;background:#161b22;border:1px solid #30363d;border-radius:8px;overflow:hidden}
th,td{text-align:left;padding:10px 12px;border-bottom:1px solid #21262d;vertical-align:top}
th{background:#1c2128;color:#8b949e;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
tr:last-child td{border-bottom:0}
.sev{display:inline-block;font-size:11px;font-weight:600;padding:2px 8px;border-radius:999px;text-transform:uppercase}
.sev.critical{background:#da363322;color:#ff7b72;border:1px solid #da3633}
.sev.high{background:#bb800922;color:#e3b341;border:1px solid #bb8009}
.sev.medium{background:#d2992222;color:#d29922;border:1px solid #9e6a03}
.sev.low{background:#1f6feb22;color:#58a6ff;border:1px solid #1f6feb}
.sev.note{background:#6e768122;color:#8b949e;border:1px solid #30363d}
.loc{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;color:#c9d1d9;word-break:break-all}
.rule{color:#8b949e;font-size:12px}
.msg{max-width:520px}
.empty{text-align:center;padding:60px 20px;color:#3fb950}
.empty .big{font-size:40px;margin-bottom:8px}
footer{padding:16px 32px;color:#8b949e;font-size:12px;border-top:1px solid #30363d}
.filter{background:#21262d;border:1px solid #30363d;color:#c9d1d9;border-radius:6px;padding:4px 10px;cursor:pointer;font-size:12px}
.filter[aria-pressed=true]{background:#1f6feb;border-color:#1f6feb;color:#fff}
"""

# Progressive enhancement: every row is visible without JS; this only adds
# click-to-filter on top. The page is fully readable with scripting disabled.
JS = """
(function(){
  var rows=[].slice.call(document.querySelectorAll('tr[data-severity]'));
  var btns=[].slice.call(document.querySelectorAll('.filter'));
  btns.forEach(function(b){b.addEventListener('click',function(){
    var sev=b.getAttribute('data-sev'),on=b.getAttribute('aria-pressed')!=='true';
    btns.forEach(function(x){x.setAttribute('aria-pressed','false')});
    b.setAttribute('aria-pressed',on?'true':'false');
    rows.forEach(function(r){
      r.style.display=(!on||sev==='all'||r.getAttribute('data-severity')===sev)?'':'none';
    });
  });});
})();
"""


def render_html(findings, meta):
    counts = {sev: 0 for sev in SEVERITIES}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    tools = sorted({f["tool"] for f in findings})
    order = {sev: i for i, sev in enumerate(SEVERITIES)}
    findings = sorted(findings, key=lambda f: (order.get(f["severity"], 99), f["tool"], f["uri"]))

    cards = "".join(
        f'<div class="card {sev}"><div class="n">{counts[sev]}</div>'
        f'<div class="l">{sev}</div></div>'
        for sev in SEVERITIES
    )
    total = len(findings)

    parts = []
    parts.append("<!doctype html><html lang=en><head><meta charset=utf-8>")
    parts.append('<meta name=viewport content="width=device-width,initial-scale=1">')
    parts.append(f"<title>Chargate Security Dashboard — {esc(meta['repo'])}</title>")
    parts.append(f"<style>{CSS}</style></head><body>")

    parts.append("<header>")
    parts.append('<h1><span class="shield">⬢</span> Chargate Security Dashboard</h1>')
    bits = []
    if meta["repo"]:
        bits.append(f"<code>{esc(meta['repo'])}</code>")
    if meta["ref"]:
        bits.append(f"branch <code>{esc(meta['ref'])}</code>")
    if meta["sha"]:
        sha = meta["sha"][:7]
        if meta["run_url"]:
            bits.append(f'commit <a href="{esc(meta["run_url"])}"><code>{esc(sha)}</code></a>')
        else:
            bits.append(f"commit <code>{esc(sha)}</code>")
    bits.append(f"generated {esc(meta['generated'])}")
    parts.append(f'<div class="meta">{" · ".join(bits)}</div>')
    parts.append("</header><main>")

    parts.append(f'<div class="cards"><div class="card"><div class="n">{total}</div>'
                 '<div class="l">total findings</div></div>' + cards + "</div>")

    if not findings:
        parts.append('<div class="empty"><div class="big">✅</div>'
                     "<div>No findings in this scan.</div></div>")
    else:
        parts.append('<div class="bar"><button class="filter" data-sev="all" '
                     'aria-pressed="true">all</button>')
        for sev in SEVERITIES:
            if counts[sev]:
                parts.append(f'<button class="filter" data-sev="{sev}">'
                             f"{esc(sev)} ({counts[sev]})</button>")
        parts.append(f'<span class="tools">tools: {esc(", ".join(tools)) or "—"}</span></div>')

        parts.append("<table><thead><tr><th>Severity</th><th>Tool</th>"
                     "<th>Location</th><th>Finding</th></tr></thead><tbody>")
        for f in findings:
            loc = esc(f["uri"]) or "—"
            if f["uri"] and f["line"]:
                loc = f"{esc(f['uri'])}:{esc(f['line'])}"
            rule = esc(f["rule_id"])
            if f["help_uri"]:
                rule = f'<a href="{esc(f["help_uri"])}">{rule}</a>'
            msg = esc(f["message"]) or esc(f["rule_name"])
            parts.append(
                f'<tr data-severity="{esc(f["severity"])}">'
                f'<td><span class="sev {esc(f["severity"])}">{esc(f["severity"])}</span></td>'
                f'<td>{esc(f["tool"])}</td>'
                f'<td class="loc">{loc}</td>'
                f'<td class="msg">{msg}<div class="rule">{rule}</div></td></tr>'
            )
        parts.append("</tbody></table>")

    parts.append("</main>")
    parts.append('<footer>Generated by <a href="https://github.com/magmamoose/chargate">'
                 "Chargate</a> from SARIF — a self-hosted alternative to the GitHub "
                 "Advanced Security code-scanning view.</footer>")
    parts.append(f"<script>{JS}</script></body></html>")
    return "".join(parts)


def gather_meta(args):
    return {
        "repo": args.repo or os.environ.get("GITHUB_REPOSITORY", ""),
        "ref": args.ref or os.environ.get("GITHUB_REF_NAME", ""),
        "sha": args.sha or os.environ.get("GITHUB_SHA", ""),
        "run_url": args.run_url or os.environ.get("CHARGATE_RUN_URL", ""),
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    }


def main(argv=None):
    p = argparse.ArgumentParser(description="Render Chargate SARIF into an HTML dashboard.")
    p.add_argument("--sarif-dir", required=True, help="Directory containing *.sarif files.")
    p.add_argument("--out", required=True, help="Output HTML file path.")
    p.add_argument("--repo", default="", help="owner/name (default: $GITHUB_REPOSITORY).")
    p.add_argument("--ref", default="", help="Branch/ref (default: $GITHUB_REF_NAME).")
    p.add_argument("--sha", default="", help="Commit SHA (default: $GITHUB_SHA).")
    p.add_argument("--run-url", default="", help="Link target for the commit (e.g. the run URL).")
    args = p.parse_args(argv)

    if not os.path.isdir(args.sarif_dir):
        # Not an error: no SARIF dir means nothing was scanned. Emit an empty
        # dashboard so the artifact/page is always present and self-explaining.
        print(f"chargate: no SARIF directory at {args.sarif_dir} — rendering empty dashboard",
              file=sys.stderr)
        findings = []
    else:
        findings = collect(args.sarif_dir)

    out_dir = os.path.dirname(os.path.abspath(args.out))
    os.makedirs(out_dir, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(render_html(findings, gather_meta(args)))
    print(f"chargate: dashboard written to {args.out} ({len(findings)} findings)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
