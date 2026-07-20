#!/usr/bin/env bash
# Checkov IaC scan — Terraform / Kubernetes / Dockerfile (runs when IaC changes).
set -uo pipefail
_here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/common.sh
. "$_here/lib/common.sh"

require_tool checkov "Checkov"

frameworks="${CHECKOV_FRAMEWORKS:-terraform,kubernetes,dockerfile}"
args=(--compact --quiet --framework "$frameworks")
[ -n "${CHECKOV_SKIP_CHECKS:-}" ] && args+=(--skip-check "$CHECKOV_SKIP_CHECKS")
for cfg in .checkov.yaml .checkov.yml; do
  if [ -f "$cfg" ]; then args+=(--config-file "$cfg"); break; fi
done

# Clear our config env so the tool can't re-read it (Trivy-class collision).
unset CHECKOV_FRAMEWORKS CHECKOV_SKIP_CHECKS

# Console output always; SARIF additionally when CI asks. Checkov writes
# "<dir>/results_sarif.sarif" under the output path.
out_args=(--output cli)
if [ -n "${CHARGATE_SARIF_DIR:-}" ]; then
  mkdir -p "$CHARGATE_SARIF_DIR"
  out_args+=(--output sarif --output-file-path "$CHARGATE_SARIF_DIR")
fi

# Scope to changed IaC files when provided; otherwise scan the tree.
targets=()
while IFS= read -r f; do
  targets+=(-f "$f")
done < <(chargate_targets '\.(tf|tfvars|hcl|ya?ml|json)$|(^|/)Dockerfile($|\.)' "$@")
[ "${#targets[@]}" -gt 0 ] || targets=(-d .)

gh_group "Checkov (frameworks: $frameworks)"
checkov "${args[@]}" "${out_args[@]}" "${targets[@]}"
rc=$?
gh_endgroup

case "$rc" in
  0) log_ok "Checkov: no failed checks"; exit "$CHARGATE_OK" ;;
  1) log_error "Checkov found policy failures"; gh_error "Checkov found IaC policy failures"; exit "$CHARGATE_FINDINGS" ;;
  *) log_warn "Checkov failed to run (exit $rc) — not counted as a finding"; gh_warning "Checkov failed to run (exit $rc)"; exit "$CHARGATE_TOOLERR" ;;
esac
