#!/usr/bin/env bash
# chargate/scripts/ci-install-tools.sh
#
# CI-only: install the pinned scanners chargate needs, gated by what the run
# actually requires (domain toggles + detected languages). NOT used locally —
# pre-commit relies on whatever the developer already has installed.
#
# Driven by environment variables set by action.yml:
#   SECURITY LINT ENABLE_SAST                              = true|false
#   DET_PYTHON DET_GO DET_JS DET_IAC DET_DOCKERFILE
#   DET_SHELL DET_WORKFLOWS DET_KUSTOMIZE                  = true|false
#   TRIVY_VERSION TRUFFLEHOG_VERSION SEMGREP_VERSION
#   HADOLINT_VERSION ACTIONLINT_VERSION KUSTOMIZE_VERSION
#   CHECKOV_VERSION PIP_AUDIT_VERSION                      (optional pins)
#
# Install failures are intentionally non-fatal: the per-tool check downstream
# reports a missing tool as a TOOLERR (warning), never as a finding.
set -uo pipefail
_here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/common.sh
. "$_here/lib/common.sh"

# Pinned tool versions — single source of truth (bumped by update-tools.yaml).
# shellcheck disable=SC1091
[ -f "$_here/../versions.env" ] && . "$_here/../versions.env"

want() { [ "${1:-false}" = "true" ]; }

BIN="$HOME/.local/bin"
mkdir -p "$BIN"
export PATH="$BIN:$PATH"
export GOBIN="$BIN"
[ -n "${GITHUB_PATH:-}" ] && printf '%s\n' "$BIN" >> "$GITHUB_PATH"
TMP="${RUNNER_TEMP:-/tmp}"

# Architecture for prebuilt-binary downloads. GitHub-hosted runners are amd64,
# but arm64 self-hosted runners (and local `act` on Apple Silicon) work too.
case "$(uname -m)" in
  x86_64 | amd64) DL_ARCH=amd64; HADOLINT_ARCH=x86_64 ;;
  aarch64 | arm64) DL_ARCH=arm64; HADOLINT_ARCH=arm64 ;;
  *) DL_ARCH=amd64; HADOLINT_ARCH=x86_64; log_warn "unrecognised arch $(uname -m); assuming amd64" ;;
esac

retry() { # retry <attempts> <cmd...>
  local n="$1"; shift; local i=1
  while true; do
    "$@" && return 0
    [ "$i" -ge "$n" ] && return 1
    sleep "$(( i * 3 ))"; i=$(( i + 1 ))
  done
}
pip_install() { python3 -m pip install --user --disable-pip-version-check --quiet "$@"; }
note() { log_warn "could not install $1 — its check will report a tool error, not a finding"; }

install_trivy() {
  have trivy && return 0
  log_info "installing Trivy ${TRIVY_VERSION:-latest}"
  local s="$TMP/install-trivy.sh"
  retry 3 curl -fsSL "https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh" -o "$s" || return 1
  sh "$s" -b "$BIN" "${TRIVY_VERSION:-latest}" >/dev/null 2>&1 || sh "$s" -b "$BIN" latest >/dev/null 2>&1
}
install_trufflehog() {
  have trufflehog && return 0
  log_info "installing TruffleHog ${TRUFFLEHOG_VERSION:-latest}"
  local s="$TMP/install-trufflehog.sh"
  retry 3 curl -fsSL "https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh" -o "$s" || return 1
  sh "$s" -b "$BIN" "${TRUFFLEHOG_VERSION:-}" >/dev/null 2>&1 || sh "$s" -b "$BIN" >/dev/null 2>&1
}
install_semgrep()   { have semgrep   || { log_info "installing Semgrep ${SEMGREP_VERSION:-latest}"; pip_install "semgrep${SEMGREP_VERSION:+==$SEMGREP_VERSION}"; }; }
install_pip_audit() { have pip-audit  || { log_info "installing pip-audit"; pip_install "pip-audit${PIP_AUDIT_VERSION:+==$PIP_AUDIT_VERSION}"; }; }
install_checkov()   { have checkov    || { log_info "installing Checkov"; pip_install "checkov${CHECKOV_VERSION:+==$CHECKOV_VERSION}"; }; }
install_yamllint()  { have yamllint   || { log_info "installing yamllint"; pip_install yamllint; }; }
install_govulncheck() {
  have govulncheck && return 0
  have go || { log_warn "Go toolchain absent; skipping govulncheck"; return 0; }
  log_info "installing govulncheck"
  retry 3 go install golang.org/x/vuln/cmd/govulncheck@latest
}
install_hadolint() {
  have hadolint && return 0
  local v="${HADOLINT_VERSION:-2.12.0}"
  log_info "installing hadolint $v"
  retry 3 curl -fsSL "https://github.com/hadolint/hadolint/releases/download/v${v}/hadolint-Linux-${HADOLINT_ARCH}" -o "$BIN/hadolint" || return 1
  chmod +x "$BIN/hadolint"
}
install_actionlint() {
  have actionlint && return 0
  local v="${ACTIONLINT_VERSION:-1.7.7}"
  log_info "installing actionlint $v"
  local t="$TMP/actionlint.tgz"
  retry 3 curl -fsSL "https://github.com/rhysd/actionlint/releases/download/v${v}/actionlint_${v}_linux_${DL_ARCH}.tar.gz" -o "$t" || return 1
  tar -xzf "$t" -C "$BIN" actionlint && chmod +x "$BIN/actionlint"
}
install_kustomize() {
  have kustomize && return 0
  local v="${KUSTOMIZE_VERSION:-5.8.1}"
  log_info "installing kustomize $v"
  local t="$TMP/kustomize.tgz"
  retry 3 curl -fsSL "https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize%2Fv${v}/kustomize_v${v}_linux_${DL_ARCH}.tar.gz" -o "$t" || return 1
  tar -xzf "$t" -C "$BIN" kustomize && chmod +x "$BIN/kustomize"
}
npm_ci() {
  [ -f package.json ] || return 0
  grep -q "\"${ESLINT_SCRIPT:-lint}\"[[:space:]]*:" package.json || return 0
  have npm || { log_warn "npm absent; ESLint may not run"; return 0; }
  log_info "installing JS dependencies for ESLint"
  if [ -f package-lock.json ] || [ -f npm-shrinkwrap.json ]; then
    retry 3 npm ci --ignore-scripts || log_warn "npm ci failed"
  else
    retry 3 npm install --ignore-scripts --no-audit --no-fund || log_warn "npm install failed"
  fi
}

if want "${SECURITY:-true}"; then
  install_trivy      || note Trivy
  install_trufflehog || note TruffleHog
  want "${ENABLE_SAST:-true}" && { install_semgrep || note Semgrep; }
  want "${DET_PYTHON:-false}" && { install_pip_audit || note pip-audit; }
  want "${DET_GO:-false}"     && { install_govulncheck || note govulncheck; }
  want "${DET_IAC:-false}"    && { install_checkov || note Checkov; }
fi

if want "${LINT:-true}"; then
  want "${DET_DOCKERFILE:-false}" && { install_hadolint || note hadolint; }
  want "${DET_WORKFLOWS:-false}"  && { install_actionlint || note actionlint; }
  want "${DET_KUSTOMIZE:-false}"  && { install_kustomize || note kustomize; install_yamllint || true; }
  if want "${DET_SHELL:-false}" && ! have shellcheck; then
    log_info "installing shellcheck"
    { sudo apt-get update -qq && sudo apt-get install -y -qq shellcheck; } || note shellcheck
  fi
  want "${DET_JS:-false}" && npm_ci
fi

exit 0
