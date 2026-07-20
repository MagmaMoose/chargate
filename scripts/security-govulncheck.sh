#!/usr/bin/env bash
# govulncheck — Go vulnerability scan (runs when Go files change).
set -uo pipefail
_here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/common.sh
. "$_here/lib/common.sh"

if [ ! -f go.mod ]; then
  log_skip "govulncheck: no go.mod"
  exit "$CHARGATE_OK"
fi
require_tool govulncheck "govulncheck"

gh_group "govulncheck (./...)"
govulncheck ./...
rc=$?
gh_endgroup

# govulncheck: 0 clean · 3 vulnerabilities found · anything else = error.
case "$rc" in
  0) log_ok "govulncheck: no known vulnerabilities"; exit "$CHARGATE_OK" ;;
  3) log_error "govulncheck found vulnerabilities"; gh_error "govulncheck found Go vulnerabilities"; exit "$CHARGATE_FINDINGS" ;;
  *) log_warn "govulncheck failed to run (exit $rc) — not counted as a finding"; gh_warning "govulncheck failed to run (exit $rc)"; exit "$CHARGATE_TOOLERR" ;;
esac
