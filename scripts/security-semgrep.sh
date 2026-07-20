#!/usr/bin/env bash
# Semgrep SAST — chargate security core (enabled by default).
set -uo pipefail
_here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/common.sh
. "$_here/lib/common.sh"

require_tool semgrep "Semgrep"

# Space-separated rulesets, mirroring the reusable-workflow default.
config="${SEMGREP_CONFIG:-p/default p/security-audit p/secrets}"
cfg_args=()
for c in $config; do cfg_args+=(--config "$c"); done

# Optional .semgrepignore-style exclude file (auto-detected if present).
excl_args=()
baseline="${SEMGREP_BASELINE:-}"
[ -z "$baseline" ] && [ -f .semgrepignore ] && baseline=.semgrepignore
if [ -n "$baseline" ] && [ -f "$baseline" ]; then
  while IFS= read -r pat || [ -n "$pat" ]; do
    pat="${pat#"${pat%%[![:space:]]*}"}"   # ltrim
    pat="${pat%"${pat##*[![:space:]]}"}"   # rtrim
    case "$pat" in '' | \#*) continue ;; esac
    excl_args+=(--exclude "$pat")
  done < "$baseline"
fi

# Clear our config env so the tool can't re-read it (Trivy-class collision).
unset SEMGREP_CONFIG SEMGREP_BASELINE

# SARIF for the Security tab (CI only); best-effort.
if sarif="$(chargate_sarif_path semgrep)"; then
  semgrep scan "${cfg_args[@]}" "${excl_args[@]}" --sarif --output "$sarif" >/dev/null 2>&1 \
    || log_warn "Semgrep SARIF generation failed (non-fatal)"
fi

gh_group "Semgrep SAST (config: $config)"
semgrep scan "${cfg_args[@]}" "${excl_args[@]}"
rc=$?
gh_endgroup

# Semgrep exit codes: 0 clean · 1 findings · ≥2 error.
case "$rc" in
  0) log_ok "Semgrep: no findings"; exit "$CHARGATE_OK" ;;
  1) log_error "Semgrep found issues"; gh_error "Semgrep found issues"; exit "$CHARGATE_FINDINGS" ;;
  *) log_warn "Semgrep failed to run (exit $rc) — not counted as a finding"; gh_warning "Semgrep failed to run (exit $rc)"; exit "$CHARGATE_TOOLERR" ;;
esac
