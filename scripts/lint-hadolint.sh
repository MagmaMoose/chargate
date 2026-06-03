#!/usr/bin/env bash
# hadolint — lint Dockerfiles (runs when Dockerfiles change).
set -uo pipefail
_here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/common.sh
. "$_here/lib/common.sh"

require_tool hadolint "hadolint"

threshold="${HADOLINT_FAILURE_THRESHOLD:-error}"
files=()
while IFS= read -r f; do files+=("$f"); done < <(chargate_targets '(^|/)Dockerfile($|\.)|\.dockerfile$' "$@")
if [ "${#files[@]}" -eq 0 ]; then
  log_skip "hadolint: no Dockerfiles"
  exit "$CHARGATE_OK"
fi

# Clear our config env so the tool can't re-read it (Trivy-class collision).
unset HADOLINT_FAILURE_THRESHOLD

gh_group "hadolint (failure-threshold: $threshold, ${#files[@]} file(s))"
hadolint --failure-threshold "$threshold" "${files[@]}"
rc=$?
gh_endgroup

case "$rc" in
  0) log_ok "hadolint: clean"; exit "$CHARGATE_OK" ;;
  1) log_error "hadolint reported problems"; gh_error "hadolint reported problems"; exit "$CHARGATE_FINDINGS" ;;
  *) log_warn "hadolint failed to run (exit $rc) — not counted as a finding"; gh_warning "hadolint failed to run (exit $rc)"; exit "$CHARGATE_TOOLERR" ;;
esac
