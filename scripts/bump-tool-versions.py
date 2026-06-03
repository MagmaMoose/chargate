#!/usr/bin/env python3
"""Bump Chargate's pinned scanner versions in versions.env to the latest upstream releases.

Usage:
  bump-tool-versions.py [--check]    # --check = report only, do not write

Sources: GitHub releases (gh CLI) for binaries, PyPI for pip tools. When run in CI
it writes `changed` and `summary` to $GITHUB_OUTPUT for the update workflow.
"""
import json
import os
import re
import subprocess
import sys
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VERSIONS = os.path.join(ROOT, "versions.env")
CHECK = "--check" in sys.argv


def gh_tag(repo):
    r = subprocess.run(
        ["gh", "api", f"repos/{repo}/releases/latest", "--jq", ".tag_name"],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        raise SystemExit(f"failed to fetch latest release for {repo}: {r.stderr.strip()}")
    return r.stdout.strip()


def pypi(pkg):
    with urllib.request.urlopen(f"https://pypi.org/pypi/{pkg}/json", timeout=30) as f:
        return json.load(f)["info"]["version"]


def strip_v(t):
    return t[1:] if t.startswith("v") else t


def keep_v(t):
    return t if t.startswith("v") else "v" + t


# KEY -> latest stored value (matching the format conventions in versions.env)
latest = {
    "TRIVY_VERSION": keep_v(gh_tag("aquasecurity/trivy")),
    "SEMGREP_VERSION": pypi("semgrep"),
    "HADOLINT_VERSION": strip_v(gh_tag("hadolint/hadolint")),
    "ACTIONLINT_VERSION": strip_v(gh_tag("rhysd/actionlint")),
    "KUSTOMIZE_VERSION": strip_v(gh_tag("kubernetes-sigs/kustomize").split("/")[-1]),
    "TRUFFLEHOG_VERSION": keep_v(gh_tag("trufflesecurity/trufflehog")),
    "CHECKOV_VERSION": pypi("checkov"),
    "PIP_AUDIT_VERSION": pypi("pip-audit"),
    "KUBECONFORM_VERSION": keep_v(gh_tag("yannh/kubeconform")),
    "KUBE_SCORE_VERSION": keep_v(gh_tag("zegl/kube-score")),
}

out_lines, changes = [], []
for line in open(VERSIONS).read().splitlines():
    m = re.match(r"^([A-Z_]+)=(.*)$", line)
    if m and m.group(1) in latest:
        key, cur, new = m.group(1), m.group(2), latest[m.group(1)]
        if new and new != cur:
            changes.append((key, cur or "(unset)", new))
            out_lines.append(f"{key}={new}")
            continue
    out_lines.append(line)

for key, cur, new in changes:
    print(f"  {key}: {cur} -> {new}")
if not changes:
    print("  all tool versions are current")

if changes and not CHECK:
    open(VERSIONS, "w").write("\n".join(out_lines) + "\n")

gho = os.environ.get("GITHUB_OUTPUT")
if gho:
    body = "\n".join(f"- `{k}`: {c} → {n}" for k, c, n in changes) or "none"
    with open(gho, "a") as f:
        f.write(f"changed={'true' if changes else 'false'}\n")
        f.write(f"summary<<__EOF__\n{body}\n__EOF__\n")
