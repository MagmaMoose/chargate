#!/usr/bin/env bash
# pip-audit — Python dependency vulnerabilities. Trivy is the primary source for
# Python CVEs; this adds OSV/PyPI advisory coverage for requirements files.
set -uo pipefail
_here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/common.sh
. "$_here/lib/common.sh"

require_tool pip-audit "pip-audit"

service="${PIP_AUDIT_SERVICE:-osv}"

# Audit requirements files — the environment-independent, reliable path.
reqs=()
for f in requirements.txt requirements-*.txt requirements/*.txt; do
  [ -f "$f" ] && reqs+=(-r "$f")
done
if [ "${#reqs[@]}" -eq 0 ]; then
  log_skip "pip-audit: no requirements*.txt found (Trivy covers other Python manifests)"
  exit "$CINNABAR_OK"
fi

gh_group "pip-audit (service: $service)"
pip-audit --progress-spinner off --vulnerability-service "$service" "${reqs[@]}"
rc=$?
gh_endgroup

case "$rc" in
  0) log_ok "pip-audit: no known vulnerabilities"; exit "$CINNABAR_OK" ;;
  1) log_error "pip-audit found vulnerable dependencies"; gh_error "pip-audit found vulnerable Python dependencies"; exit "$CINNABAR_FINDINGS" ;;
  *) log_warn "pip-audit failed to run (exit $rc) — not counted as a finding"; gh_warning "pip-audit failed to run (exit $rc)"; exit "$CINNABAR_TOOLERR" ;;
esac
