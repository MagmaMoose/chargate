#!/usr/bin/env bash
# actionlint — lint GitHub Actions workflows (runs when workflow files change).
set -uo pipefail
_here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/common.sh
. "$_here/lib/common.sh"

require_tool actionlint "actionlint"

files=()
while IFS= read -r f; do files+=("$f"); done < <(chargate_targets '^\.github/workflows/.*\.ya?ml$' "$@")

gh_group "actionlint"
if [ "${#files[@]}" -gt 0 ]; then
  actionlint -color "${files[@]}"
else
  # No explicit files: let actionlint discover every workflow in the repo.
  actionlint -color
fi
rc=$?
gh_endgroup

case "$rc" in
  0) log_ok "actionlint: clean"; exit "$CHARGATE_OK" ;;
  1) log_error "actionlint reported problems"; gh_error "actionlint reported problems"; exit "$CHARGATE_FINDINGS" ;;
  *) log_warn "actionlint failed to run (exit $rc) — not counted as a finding"; gh_warning "actionlint failed to run (exit $rc)"; exit "$CHARGATE_TOOLERR" ;;
esac
