#!/usr/bin/env bash
# ESLint via the project's own npm lint script (runs when JS/TS changes).
set -uo pipefail
_here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/common.sh
. "$_here/lib/common.sh"

script_name="${ESLINT_SCRIPT:-lint}"

if [ ! -f package.json ]; then
  log_skip "ESLint: no package.json"
  exit "$CHARGATE_OK"
fi
# Cheap presence check so we don't need node just to read package.json.
if ! grep -q "\"$script_name\"[[:space:]]*:" package.json; then
  log_skip "ESLint: no '$script_name' script in package.json"
  exit "$CHARGATE_OK"
fi
require_tool npm "npm"

# Clear our config env so the tool can't re-read it (Trivy-class collision).
unset ESLINT_SCRIPT

gh_group "ESLint (npm run $script_name)"
npm run "$script_name"
rc=$?
gh_endgroup

# ESLint: 1 = lint problems (findings) · 2 = ESLint config/internal error.
case "$rc" in
  0) log_ok "ESLint: clean"; exit "$CHARGATE_OK" ;;
  1) log_error "ESLint reported problems"; gh_error "ESLint reported problems"; exit "$CHARGATE_FINDINGS" ;;
  *) log_warn "ESLint failed to run (exit $rc) — not counted as a finding"; gh_warning "ESLint failed to run (exit $rc)"; exit "$CHARGATE_TOOLERR" ;;
esac
