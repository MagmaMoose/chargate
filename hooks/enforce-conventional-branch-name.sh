#!/usr/bin/env bash
set -euo pipefail

branch="$(git symbolic-ref --quiet --short HEAD 2>/dev/null || true)"
if [[ -z "${branch}" ]]; then
  exit 0
fi

if [[ "${branch}" =~ ^(main|master|develop)$ ]] || [[ "${branch}" =~ ^(dependabot|renovate)/ ]]; then
  exit 0
fi

pattern='^(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)(/[A-Za-z0-9._-]+)+$'
if [[ ! "${branch}" =~ ${pattern} ]]; then
  cat >&2 <<EOF
ERROR: Branch '${branch}' violates naming policy.
Required: <type>/<description> or <type>/<scope>/<description>
Allowed types: feat, fix, docs, style, refactor, perf, test, build, ci, chore, revert
Examples:
  feat/auth/login-flow
  fix/isam/null-state
EOF
  exit 1
fi
