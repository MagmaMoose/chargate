#!/usr/bin/env bash
# chargate/scripts/ci-report.sh
#
# CI-only: render the scan summary to the job summary and publish the outputs
# the Gate step uses to decide blocking. Consumes RC_* / DET_* / config env set
# by action.yml. NEVER exits non-zero — gating is the Gate step's job, driven by
# the security_blocking / lint_blocking outputs we set here.
set +e
_here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/common.sh
. "$_here/lib/common.sh"

summary="${GITHUB_STEP_SUMMARY:-/dev/stdout}"
out="${GITHUB_OUTPUT:-/dev/stdout}"
emit() { printf '%s\n' "$1" >> "$out"; }

if [ "${DET_ANY:-false}" != "true" ]; then
  {
    echo "## 🔴 Chargate scan report"
    echo ""
    echo "⏭️ No relevant file changes detected — scan skipped."
  } >> "$summary"
  emit "scan_skipped=true"
  emit "security_result=skipped"
  emit "lint_result=skipped"
  emit "security_blocking=false"
  emit "lint_blocking=false"
  exit 0
fi

sec_findings=0; sec_toolerr=0; sec_ran=0
lint_findings=0; lint_toolerr=0; lint_ran=0

{
  echo "## 🔴 Chargate scan report"
  echo ""
  echo "| Check | Domain | Result | Notes |"
  echo "|-------|--------|--------|-------|"
} >> "$summary"

row() { # row <name> <domain> <rc> <notes>
  local name="$1" domain="$2" rc="$3" notes="$4" res
  case "$rc" in
    "") res="⏭️ not run" ;;
    0)  res="✅ pass" ;;
    1)  res="❌ findings" ;;
    2)  res="⚠️ tool error" ;;
    *)  res="⚠️ exit $rc" ;;
  esac
  printf '| %s | %s | %s | %s |\n' "$name" "$domain" "$res" "$notes" >> "$summary"
  if [ "$domain" = "security" ]; then
    case "$rc" in
      0) sec_ran=$((sec_ran + 1)) ;;
      1) sec_ran=$((sec_ran + 1)); sec_findings=$((sec_findings + 1)) ;;
      2) sec_ran=$((sec_ran + 1)); sec_toolerr=$((sec_toolerr + 1)) ;;
    esac
  elif [ "$domain" = "lint" ]; then
    case "$rc" in
      0) lint_ran=$((lint_ran + 1)) ;;
      1) lint_ran=$((lint_ran + 1)); lint_findings=$((lint_findings + 1)) ;;
      2) lint_ran=$((lint_ran + 1)); lint_toolerr=$((lint_toolerr + 1)) ;;
    esac
  fi
}

row "Trivy vulnerabilities"    security "${RC_TRIVY:-}"         "severity ${TRIVY_SEVERITY:-CRITICAL,HIGH}"
row "TruffleHog secrets"       security "${RC_TRUFFLEHOG:-}"    "verified only"
row "Semgrep SAST"             security "${RC_SEMGREP:-}"       "${SEMGREP_CONFIG:-}"
row "pip-audit (Python)"       security "${RC_PIP_AUDIT:-}"     "on Python changes"
row "npm/yarn/pnpm audit (JS)" security "${RC_NPM_AUDIT:-}"     "on JS changes"
row "govulncheck (Go)"         security "${RC_GOVULNCHECK:-}"   "on Go changes"
row "Checkov (IaC)"            security "${RC_CHECKOV:-}"       "on IaC changes"
row "Trivy licenses"           security "${RC_TRIVY_LICENSE:-}" "opt-in"
row "ESLint (JS)"              lint     "${RC_ESLINT:-}"        "npm run ${ESLINT_SCRIPT:-lint}"
row "Kustomize + kubeconform"  lint     "${RC_KUSTOMIZE:-}"     "build + validate"
row "Hadolint (Dockerfile)"    lint     "${RC_HADOLINT:-}"      "on Dockerfile changes"
row "ShellCheck"               lint     "${RC_SHELLCHECK:-}"    "on shell changes"
row "actionlint"               lint     "${RC_ACTIONLINT:-}"    "on workflow changes"

sec_result=pass
[ "$sec_ran" -eq 0 ] && sec_result=skipped
[ "$sec_toolerr" -gt 0 ] && sec_result=error
[ "$sec_findings" -gt 0 ] && sec_result=findings
[ "${SECURITY:-true}" != "true" ] && sec_result=disabled

lint_result=pass
[ "$lint_ran" -eq 0 ] && lint_result=skipped
[ "$lint_toolerr" -gt 0 ] && lint_result=error
[ "$lint_findings" -gt 0 ] && lint_result=findings
[ "${LINT:-true}" != "true" ] && lint_result=disabled

sec_block=false
{ [ "${SECURITY_FAIL:-true}" = "true" ] && [ "$sec_findings" -gt 0 ]; } && sec_block=true
lint_block=false
{ [ "${LINT_FAIL:-false}" = "true" ] && [ "$lint_findings" -gt 0 ]; } && lint_block=true

{
  echo ""
  echo "**Security:** \`$sec_result\` · **Lint:** \`$lint_result\`"
  if [ "$sec_toolerr" -gt 0 ] || [ "$lint_toolerr" -gt 0 ]; then
    echo ""
    echo "> ⚠️ One or more tools failed to *run* and were reported as **tool errors**, not findings. They never block the gate — check the step logs."
  fi
  if [ "$sec_block" = "true" ] || [ "$lint_block" = "true" ]; then
    echo ""
    echo "❌ **Blocking** — see the failed checks above."
  fi
} >> "$summary"

emit "scan_skipped=false"
emit "security_result=$sec_result"
emit "lint_result=$lint_result"
emit "security_blocking=$sec_block"
emit "lint_blocking=$lint_block"
exit 0
