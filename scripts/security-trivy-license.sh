#!/usr/bin/env bash
# Trivy license-compliance scan — cinnabar (opt-in via the action input).
set -uo pipefail
_here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/common.sh
. "$_here/lib/common.sh"

require_tool trivy "Trivy"

severity="${TRIVY_LICENSE_SEVERITY:-UNKNOWN,HIGH,CRITICAL}"

gh_group "Trivy license scan (severity: $severity)"
# Sentinel exit-code 2 ⇒ flagged licenses; trivy uses 1 for its own errors.
trivy fs --scanners license --severity "$severity" \
  --skip-dirs "node_modules,.git,vendor" --format table --exit-code 2 .
rc=$?
gh_endgroup

case "$rc" in
  0) log_ok "Trivy license: nothing flagged"; exit "$CINNABAR_OK" ;;
  2) log_error "Trivy flagged non-compliant license(s)"; gh_error "Trivy flagged non-compliant license(s)"; exit "$CINNABAR_FINDINGS" ;;
  *) log_warn "Trivy license scan failed (exit $rc) — not counted as a finding"; gh_warning "Trivy license scan failed (exit $rc)"; exit "$CINNABAR_TOOLERR" ;;
esac
