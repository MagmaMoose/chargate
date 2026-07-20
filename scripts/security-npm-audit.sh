#!/usr/bin/env bash
# npm / yarn / pnpm audit — JS dependency vulnerabilities. Picks the tool from
# the lockfile present. (Trivy also scans JS lockfiles for CVEs.)
set -uo pipefail
_here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/common.sh
. "$_here/lib/common.sh"

level="${NPM_AUDIT_LEVEL:-high}"

if [ -f package-lock.json ] || [ -f npm-shrinkwrap.json ]; then
  require_tool npm "npm"
  label="npm audit"; cmd=(npm audit "--audit-level=$level")
elif [ -f yarn.lock ]; then
  require_tool corepack "corepack"; corepack enable >/dev/null 2>&1 || true
  label="yarn audit"; cmd=(corepack yarn audit --level "$level")
elif [ -f pnpm-lock.yaml ]; then
  require_tool corepack "corepack"; corepack enable >/dev/null 2>&1 || true
  label="pnpm audit"; cmd=(corepack pnpm audit "--audit-level=$level")
else
  log_skip "npm/yarn/pnpm audit: no lockfile found"
  exit "$CHARGATE_OK"
fi

# Clear our config env so the tool can't re-read it (Trivy-class collision).
unset NPM_AUDIT_LEVEL

gh_group "$label (level: $level)"
"${cmd[@]}"
rc=$?
gh_endgroup

# These tools exit non-zero when advisories at/above the level are present.
case "$rc" in
  0) log_ok "$label: no vulnerabilities at or above '$level'"; exit "$CHARGATE_OK" ;;
  *) log_error "$label reported vulnerabilities (exit $rc)"; gh_error "$label reported vulnerabilities"; exit "$CHARGATE_FINDINGS" ;;
esac
