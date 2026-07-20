#!/usr/bin/env bash
# TruffleHog verified-secret detection — chargate security core (always runs).
set -uo pipefail
_here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/common.sh
. "$_here/lib/common.sh"

require_tool trufflehog "TruffleHog"

exclude="${TRUFFLEHOG_EXCLUDE:-}"
args=(filesystem . --only-verified --fail --no-update)
if [ -n "$exclude" ] && [ -f "$exclude" ]; then
  args+=(--exclude-paths "$exclude")
fi

# Clear our config env so the tool can't re-read it (Trivy-class collision).
unset TRUFFLEHOG_EXCLUDE

gh_group "TruffleHog secret detection (verified only)"
trufflehog "${args[@]}"
rc=$?
gh_endgroup

# `--fail` makes trufflehog exit 183 when verified secrets are found.
case "$rc" in
  0)   log_ok "TruffleHog: no verified secrets found"; exit "$CHARGATE_OK" ;;
  183) log_error "TruffleHog found verified secret(s)"; gh_error "TruffleHog found verified secret(s)"; exit "$CHARGATE_FINDINGS" ;;
  *)   log_warn "TruffleHog failed to run (exit $rc) — not counted as a finding"; gh_warning "TruffleHog failed to run (exit $rc)"; exit "$CHARGATE_TOOLERR" ;;
esac
