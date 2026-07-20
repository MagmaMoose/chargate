#!/usr/bin/env bash
# ShellCheck — lint shell scripts (runs when shell files change).
set -uo pipefail
_here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/common.sh
. "$_here/lib/common.sh"

require_tool shellcheck "ShellCheck"

severity="${SHELLCHECK_SEVERITY:-warning}"
files=()
while IFS= read -r f; do files+=("$f"); done < <(chargate_targets '\.(sh|bash|zsh)$' "$@")
if [ "${#files[@]}" -eq 0 ]; then
  log_skip "ShellCheck: no shell scripts"
  exit "$CHARGATE_OK"
fi

# Clear our config env so the tool can't re-read it (Trivy-class collision).
unset SHELLCHECK_SEVERITY

gh_group "ShellCheck (severity: $severity, ${#files[@]} file(s))"
shellcheck "--severity=$severity" "${files[@]}"
rc=$?
gh_endgroup

case "$rc" in
  0) log_ok "ShellCheck: clean"; exit "$CHARGATE_OK" ;;
  1) log_error "ShellCheck reported problems"; gh_error "ShellCheck reported problems"; exit "$CHARGATE_FINDINGS" ;;
  *) log_warn "ShellCheck failed to run (exit $rc) — not counted as a finding"; gh_warning "ShellCheck failed to run (exit $rc)"; exit "$CHARGATE_TOOLERR" ;;
esac
