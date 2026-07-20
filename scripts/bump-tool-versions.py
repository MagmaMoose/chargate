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
import sys
import urllib.parse
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VERSIONS = os.path.join(ROOT, "versions.env")
CHECK = "--check" in sys.argv


def gh_tag(repo):
    # Resolve via the github.com /releases/latest redirect rather than the API: no
    # auth, so it isn't subject to org IP allow lists (e.g. aquasecurity/trivy
    # returns 403 to authenticated API calls from GitHub-hosted runner IPs).
    url = f"https://github.com/{repo}/releases/latest"
    with urllib.request.urlopen(url, timeout=30) as r:  # nosemgrep  # noqa: S310 — constant URL
        final = r.geturl()
    if "/tag/" not in final:
        raise SystemExit(f"could not resolve latest release for {repo} (got {final})")
    return urllib.parse.unquote(final.rsplit("/tag/", 1)[-1])


def pypi(pkg):
    url = f"https://pypi.org/pypi/{pkg}/json"  # pkg is a constant tool name, not user input
    with urllib.request.urlopen(url, timeout=30) as f:  # nosemgrep  # noqa: S310
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
