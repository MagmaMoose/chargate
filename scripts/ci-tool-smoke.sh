#!/usr/bin/env bash
# Release gate: confirm every pinned scanner actually installs and runs. A
# breaking upstream release (renamed/removed flag, bad binary, missing image
# tag) surfaces here and blocks the release. Assumes ci-install-tools.sh has
# already run. CI-only.
set -uo pipefail
_here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/common.sh
. "$_here/lib/common.sh"
# shellcheck disable=SC1091
[ -f "$_here/../versions.env" ] && . "$_here/../versions.env"

export PATH="$HOME/.local/bin:$PATH"
fail=0

run() { # run <label> <cmd...>
  local label="$1"; shift
  if "$@" >/dev/null 2>&1; then log_ok "$label runs"; else log_error "$label FAILED ($*)"; fail=1; fi
}

run "Trivy"      trivy --version
run "Semgrep"    semgrep --version
run "hadolint"   hadolint --version
run "actionlint" actionlint -version
run "kustomize"  kustomize version
run "TruffleHog" trufflehog --version
run "Checkov"    checkov --version
run "pip-audit"  pip-audit --version
if have govulncheck; then log_ok "govulncheck present"; else log_error "govulncheck missing"; fail=1; fi

# Docker-based validators: confirm the pinned image tags actually exist.
if have docker; then
  for img in "ghcr.io/yannh/kubeconform:${KUBECONFORM_VERSION:-v0.6.7}-alpine" "zegl/kube-score:${KUBE_SCORE_VERSION:-v1.19.0}"; do
    if docker pull "$img" >/dev/null 2>&1; then log_ok "image $img"; else log_error "image $img unavailable"; fail=1; fi
  done
else
  log_skip "docker unavailable — skipping kubeconform/kube-score image check"
fi

if [ "$fail" = 0 ]; then log_ok "tool smoke: all pinned tools OK"; fi
exit "$fail"
