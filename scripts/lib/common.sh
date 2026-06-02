#!/usr/bin/env bash
# cinnabar/scripts/lib/common.sh
#
# Shared helpers for every cinnabar scan script. Source this file; do not run it.
#
# ─── Exit-code contract (every cinnabar script obeys this) ──────────────────
#   0  CINNABAR_OK        clean — no findings
#   1  CINNABAR_FINDINGS  the tool reported real findings (blocking material)
#   2  CINNABAR_TOOLERR   the tool itself failed or was unavailable
#
# The whole point of separating 1 from 2 is that a *broken* scanner must never
# be reported as a *finding*. Orchestrators (action.yml, the pre-commit
# wrapper) apply policy on top:
#   • security domain  → FINDINGS blocks, TOOLERR warns  (fail closed)
#   • lint domain      → FINDINGS is advisory by default  (fail open)
# Where a tool's own exit code can't distinguish "found issues" from "crashed",
# a security script resolves the ambiguity to FINDINGS, a lint script to
# TOOLERR. Security fails safe; noisy linters never block.

# Part of the public contract; CINNABAR_FINDINGS is referenced only by sourcing scripts.
# shellcheck disable=SC2034
CINNABAR_OK=0 CINNABAR_FINDINGS=1 CINNABAR_TOOLERR=2

# ─── Mode (ci | local) ──────────────────────────────────────────────────────
if [ -z "${CINNABAR_MODE:-}" ]; then
  if [ "${GITHUB_ACTIONS:-}" = "true" ]; then CINNABAR_MODE=ci; else CINNABAR_MODE=local; fi
fi
cinnabar_is_ci() { [ "$CINNABAR_MODE" = "ci" ]; }

# ─── Logging (colour only on a TTY, everything to stderr) ────────────────────
if [ -t 2 ]; then
  _C_RED=$'\033[31m'; _C_YEL=$'\033[33m'; _C_GRN=$'\033[32m'; _C_DIM=$'\033[2m'; _C_RST=$'\033[0m'
else
  _C_RED=''; _C_YEL=''; _C_GRN=''; _C_DIM=''; _C_RST=''
fi
log_info()  { printf '%s\n' "${_C_DIM}cinnabar:${_C_RST} $*" >&2; }
log_ok()    { printf '%s\n' "${_C_GRN}✔ $*${_C_RST}" >&2; }
log_warn()  { printf '%s\n' "${_C_YEL}⚠ $*${_C_RST}" >&2; }
log_error() { printf '%s\n' "${_C_RED}✗ $*${_C_RST}" >&2; }
log_skip()  { printf '%s\n' "${_C_DIM}⏭ $* — skipped${_C_RST}" >&2; }

# ─── GitHub Actions annotations / log grouping (no-ops outside Actions) ───────
gh_error()    { [ "${GITHUB_ACTIONS:-}" = "true" ] && printf '::error::%s\n' "$*"; return 0; }
gh_warning()  { [ "${GITHUB_ACTIONS:-}" = "true" ] && printf '::warning::%s\n' "$*"; return 0; }
gh_group()    { if [ "${GITHUB_ACTIONS:-}" = "true" ]; then printf '::group::%s\n' "$*"; else log_info "$*"; fi; }
gh_endgroup() { [ "${GITHUB_ACTIONS:-}" = "true" ] && printf '::endgroup::\n'; return 0; }

# ─── Tool detection ──────────────────────────────────────────────────────────
have() { command -v "$1" >/dev/null 2>&1; }

# need_tool <bin> [human-name]
#   returns 0 present · 1 missing (local, graceful skip) · 2 missing (ci, error)
need_tool() {
  local bin="$1" name="${2:-$1}"
  if have "$bin"; then return 0; fi
  if cinnabar_is_ci; then
    log_error "$name not found on PATH (it should have been installed in CI)"
    return 2
  fi
  log_skip "$name not installed"
  return 1
}

# require_tool <bin> [human-name]
#   single-tool scripts call this; it exits the script with the right code when
#   the tool is absent (OK locally so a missing tool never breaks a commit;
#   TOOLERR in CI so a missing tool surfaces as a warning, not a pass).
require_tool() {
  need_tool "$1" "${2:-$1}"
  case $? in
    0) return 0 ;;
    1) exit "$CINNABAR_OK" ;;
    *) exit "$CINNABAR_TOOLERR" ;;
  esac
}

# ─── SARIF (scripts emit SARIF only when CI asks, via CINNABAR_SARIF_DIR) ─────
# Echoes the path to write to and returns 0, or returns 1 when SARIF is off.
cinnabar_sarif_path() {
  [ -n "${CINNABAR_SARIF_DIR:-}" ] || return 1
  mkdir -p "$CINNABAR_SARIF_DIR" || return 1
  printf '%s/%s.sarif' "$CINNABAR_SARIF_DIR" "$1"
}

# ─── File selection ──────────────────────────────────────────────────────────
# cinnabar_targets <ext-regex> [file...]
#   • args given  → filter them by regex + existence (this is how pre-commit
#     feeds matched staged files in);
#   • no args      → fall back to staged files, else all tracked files; filtered
#     by regex, capped at 2000 so a huge tree can't hang a local run.
cinnabar_targets() {
  local re="$1"; shift
  if [ "$#" -gt 0 ]; then
    local f
    for f in "$@"; do [ -f "$f" ] && printf '%s\n' "$f"; done | grep -E "$re" || true
    return 0
  fi
  local list
  list="$(git diff --cached --name-only --diff-filter=ACM 2>/dev/null || true)"
  [ -n "$list" ] || list="$(git ls-files 2>/dev/null || true)"
  printf '%s\n' "$list" | grep -E "$re" | while IFS= read -r f; do
    [ -f "$f" ] && printf '%s\n' "$f"
  done | head -2000
}
