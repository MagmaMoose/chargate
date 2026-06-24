#!/usr/bin/env bash
# Exchange this run's GitHub Actions OIDC token for a short-lived, repo-scoped
# Chargate App installation token, via the Chargate token broker. The action uses
# the result to author PR comments as Chargate[bot].
#
# FAIL-SOFT BY DESIGN: any problem — no `id-token: write` permission, the Chargate
# App not installed on the repo, a broker error — emits an empty token and a
# warning (never `exit 1`), so the action falls back to GITHUB_TOKEN
# (github-actions[bot]) instead of breaking the run.
set -uo pipefail

emit_empty() {
  echo "::warning::Chargate[bot] token unavailable ($1); PR comments fall back to github-actions[bot]."
  echo "token=" >>"${GITHUB_OUTPUT:-/dev/null}"
  exit 0
}

broker_url="${TOKEN_BROKER_URL:-https://api.chargate.magmamoose.com}"
audience="${OIDC_AUDIENCE:-chargate}"
[ -n "${broker_url}" ] || emit_empty "broker disabled"

request_url="${ACTIONS_ID_TOKEN_REQUEST_URL:-}"
request_token="${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}"
{ [ -n "${request_url}" ] && [ -n "${request_token}" ]; } || emit_empty "missing 'id-token: write'"

repository="${GITHUB_REPOSITORY:-}"
[[ "${repository}" == */* ]] || emit_empty "bad GITHUB_REPOSITORY"
owner="${repository%%/*}"
repo="${repository#*/}"

encoded_audience="$(jq -rn --arg v "${audience}" '$v | @uri')"
oidc_response="$(curl -fsS -H "Authorization: bearer ${request_token}" \
  "${request_url}&audience=${encoded_audience}")" || emit_empty "OIDC request failed"
oidc_token="$(jq -er '.value' <<<"${oidc_response}")" || emit_empty "OIDC token missing"

payload="$(jq -n \
  --arg oidcToken "${oidc_token}" \
  --arg owner "${owner}" \
  --arg repo "${repo}" \
  --arg ref "${GITHUB_REF:-}" \
  --arg runId "${GITHUB_RUN_ID:-}" \
  --arg sha "${GITHUB_SHA:-}" \
  '{oidcToken: $oidcToken, owner: $owner, repo: $repo, ref: $ref, runId: $runId, sha: $sha}')"

body_file="$(mktemp)"
trap 'rm -f "${body_file}"' EXIT
status="$(curl -sS -o "${body_file}" -w '%{http_code}' \
  -X POST -H 'Content-Type: application/json' \
  --data "${payload}" "${broker_url%/}/token")" || emit_empty "broker unreachable"
[ "${status}" = "200" ] || emit_empty "broker HTTP ${status}"

installation_token="$(jq -er '.token' "${body_file}")" || emit_empty "broker returned no token"
echo "::add-mask::${installation_token}"
echo "token=${installation_token}" >>"${GITHUB_OUTPUT}"
echo "Chargate[bot] token obtained for ${repository}."
