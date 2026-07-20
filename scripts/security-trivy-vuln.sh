#!/usr/bin/env bash
# Trivy filesystem vulnerability scan — chargate security core (always runs).
set -uo pipefail
_here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/common.sh
. "$_here/lib/common.sh"

require_tool trivy "Trivy"

severity="${TRIVY_SEVERITY:-CRITICAL,HIGH}"
findings_mode="${TRIVY_EXIT_CODE:-1}"        # 0 ⇒ warn-only, anything else ⇒ block on findings
ignore_unfixed="${TRIVY_IGNORE_UNFIXED:-true}"
ignorefile="${TRIVY_IGNOREFILE:-.trivyignore}"

# Trivy natively reads TRIVY_* env vars. We capture what we need as explicit
# flags, so clear them here — otherwise trivy re-reads e.g. a missing ignore
# file and dies with a FATAL flag error.
unset TRIVY_SEVERITY TRIVY_EXIT_CODE TRIVY_IGNORE_UNFIXED TRIVY_IGNOREFILE

common=(fs --scanners vuln --severity "$severity" --skip-dirs "node_modules,.git,vendor")
[ "$ignore_unfixed" = "true" ] && common+=(--ignore-unfixed)
[ -f "$ignorefile" ] && common+=(--ignorefile "$ignorefile")

# SARIF for the Security tab (CI only); best-effort, never fails the scan.
if sarif="$(chargate_sarif_path trivy)"; then
  trivy "${common[@]}" --format sarif --output "$sarif" --exit-code 0 . >/dev/null 2>&1 \
    || log_warn "Trivy SARIF generation failed (non-fatal)"
fi

gh_group "Trivy vulnerability scan (severity: $severity)"
# Sentinel: tell trivy to exit 2 when vulnerabilities are found. Trivy uses 1
# for its own operational errors, so 2 vs 1 cleanly separates findings from a
# broken scan.
trivy "${common[@]}" --format table --exit-code 2 .
rc=$?
gh_endgroup

case "$rc" in
  0) log_ok "Trivy: no $severity vulnerabilities found"; exit "$CHARGATE_OK" ;;
  2)
    if [ "$findings_mode" = "0" ]; then
      log_warn "Trivy found vulnerabilities (warn-only: TRIVY_EXIT_CODE=0)"
      exit "$CHARGATE_OK"
    fi
    log_error "Trivy found $severity vulnerabilities"
    gh_error "Trivy found $severity vulnerabilities"
    exit "$CHARGATE_FINDINGS"
    ;;
  *)
    log_warn "Trivy scan failed to run (exit $rc) — not counted as a finding"
    gh_warning "Trivy scan failed to run (exit $rc)"
    exit "$CHARGATE_TOOLERR"
    ;;
esac
