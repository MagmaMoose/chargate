# Troubleshooting

<!-- sources: src/chargate/gate.py, broker/app/broker.py, broker/app/lambda_handler.py, scripts/request-app-token.sh -->

Symptom, cause, fix. Start with the exit code or the error string you actually saw.

## Gate exit codes

The `chargate` CLI exits with one of three codes. Your CI step's pass or fail comes
straight from these.

| Code | Name | Meaning | What to do |
| --- | --- | --- | --- |
| `0` | `EXIT_OK` | No blocking net-new findings. Pre-existing findings never block. | Nothing. |
| `1` | `EXIT_BLOCKED` | The diff introduced at least one finding at or above `--fail-on`. | Fix the finding, or lower the threshold if the severity is wrong for you. |
| `2` | `EXIT_ERROR` | Setup or tool error. The gate could not scan, so a pass would be meaningless. | Read the step log. A shallow clone and a runs-less SARIF are the two common causes, both below. |

!!! warning "Exit 2 is not a pass"
    A tool error never degrades into a pass. If MegaLinter itself blew up, the gate
    scanned nothing and says so.

## Gate problems

### The gate blocks on findings the PR did not introduce

Net-new classification compares against the merge-base, which needs full history.
With a shallow clone there is no merge-base, so the comparison cannot be made.

Set `fetch-depth: 0` on your checkout step:

```yaml
- uses: actions/checkout@v5
  with:
    fetch-depth: 0
```

Chargate fails loudly rather than guessing. See [Net-new gating](net-new.md) for the
exact classification rules.

### A finding in a SOPS-encrypted file blocks the PR

Chargate reads the working-tree file, not the redacted SARIF snippet, and drops secret
findings whose value is an `ENC[AES256_GCM,...]` ciphertext. Plaintext in the same file
still gates, which is deliberate.

If a genuinely encrypted value still blocks, check that the file is actually SOPS
output and that the finding is classified as a secret.

### A linter runs (or is skipped) and its findings never reach the gate

The gate only ever reads the merged SARIF, so a linter whose descriptor does not set
`can_output_sarif` is invisible to it however cleanly it runs. Standalone mode therefore
skips those by name, with the reason `linter emits no SARIF — it could never reach the
gate`, and lists them in `linters_skipped` and on the PR rather than dropping them
silently.

Three entries used to be missing from that list. `ACTION_ACTIONLINT`, `PYTHON_PYLINT`
and `POWERSHELL_POWERSHELL` carried `sarif=True` in Chargate's registry purely because
that is the `_entry` default — none had ever been probed, and none of them sets
`can_output_sarif` at MegaLinter `v10.0.0`. Each one cost a container pull per run and
contributed nothing the gate could read, which looks exactly like a clean repo. They are
now recorded as `sarif=False` and skipped with that reason.

`tests/test_linters_registry.py` cross-references every `sarif` flag against MegaLinter's
own descriptors at the pinned tag, so the table and upstream cannot drift apart again —
the same way the `arm64` flags are re-probed against the live registry.

If you enabled one of these expecting findings: there are none to have. Use a linter that
emits SARIF (the `quality` set is five of them,
see [The `quality` flavor](setup.md#the-quality-flavor)), or accept that this one gates
only via `strict`, as a tool error.

### The scan reports nothing and the gate passes

A SARIF report with zero `runs` means nothing was scanned. Chargate fails this on its
own rather than behind `--strict`, because a pass on an empty report is meaningless.
If you see it, the linter container failed to start. Read the MegaLinter output above
the gate step.

### A downstream tool read `counts.json` and saw a clean pull request

`chargate ci` writes `--filtered-out` and `--counts-json` *before* it decides its own
exit code. A run whose SARIF carried no `runs` therefore leaves a well-formed counts
document full of zeros on disk and then exits `2` for exactly that reason. A consumer
reading only the file sees `net_new_count: 0` and reports green.

The file's existence is not evidence that anything was scanned. Gate on the step's
outcome (or the CLI's exit code) as well as the document, and treat exit `2` as *no
answer* rather than *no findings*. Full contract:
[Consuming the output](consuming-output.md).

## Chargate[bot] comments are attributed to github-actions[bot]

This is the most common report, and it is almost never the broker being down. The
token exchange is **fail-soft**: on any error `scripts/request-app-token.sh` emits an
empty token and exits `0`, the comment is still posted, and the only symptom is the
byline. Nothing goes red.

The reason is always in the step log as a warning:

```text
::warning::Chargate[bot] token unavailable (<reason>); PR comments fall back to github-actions[bot].
```

| Reason string | Cause | Fix |
| --- | --- | --- |
| `missing 'id-token: write'` | The job cannot request an OIDC token. | Add `id-token: write` to the workflow's `permissions`. See [Setup](setup.md#pr-comments-ghas-style). |
| `curl not installed on this runner` | Minimal self-hosted or ARC image. | Install `curl` and `jq` in the runner image. |
| `jq not installed on this runner` | Same. | Same. |
| `broker disabled` | `token_broker_url` was set to an empty string. | Intentional. Set it to re-enable. |
| `bad GITHUB_REPOSITORY` | The variable is not `owner/name`. | Only happens outside GitHub Actions. |
| `OIDC request failed` | The runner could not reach GitHub's OIDC endpoint. | Network or egress policy on a self-hosted runner. |
| `OIDC token missing` | GitHub returned a response with no `value`. | Retry. Report if it persists. |
| `broker unreachable` | The HTTP request itself failed, so the hostname did not resolve or refused the connection. | Check DNS for the broker hostname. |
| `broker HTTP <status>` | The broker answered with a non-200. Look the status up below. | See the next section. |
| `broker returned no token` | The broker answered 200 with no `token` field. | Report. This should not happen. |

!!! warning "Never read a green build as proof the broker works"
    Every failure above still produces a passing job and a posted comment. The weekly
    `broker-smoke.yml` run and the comment byline are the only signals.

## Broker responses

`POST /token` returns one of these. The body is always `{"error": "<code>"}` except on
success. The Lambda also writes exactly one structured line per request,
`{"outcome": "<code>"}`, which is what to grep for in CloudWatch Logs.

| Status | Code | Cause | Fix |
| --- | --- | --- | --- |
| `200` | (none) | Token minted. Body is `{"token", "expires_at", "repository"}`. | |
| `400` | `invalid_json` | Body was not JSON, or was JSON but not an object. | Client bug. |
| `400` | `missing_fields` | One of `oidcToken`, `owner`, `repo` was absent or empty. | Client bug. |
| `400` | `invalid_repository` | `owner` or `repo` is not a plain GitHub identifier, or is not a string. | Rejected before the value can reach an API URL. |
| `401` | `invalid_oidc` | The OIDC token failed verification: signature, issuer, audience, or expiry. | Check that the workflow requests the same audience the broker expects. |
| `403` | `repo_mismatch` | The token's `repository` claim does not equal the requested `owner/repo`. | This is the control that stops one repo minting a token for another. |
| `403` | `repo_not_allowed` | An allowlist is configured and this repository is not on it. | Add the repository, or clear the allowlist to accept any repo the App is installed on. |
| `403` | `app_not_installed` | GitHub returned 404 for the repository's installation. | Install the Chargate App on that repository. |
| `502` | `mint_failed` | The GitHub API rejected the mint for some other reason. | Check the App's private key and permissions. |
| `503` | `config_unavailable` | The broker could not resolve its own configuration. | The deployment is unfinished: the App ID or private key is missing, or the function cannot read them. |
| `503` | `jwks_unavailable` | GitHub's JWKS could not be fetched. | Upstream. The caller's token may be perfectly valid, which is why this is not a 401. |

Two more the router returns before any of the above:

| Status | Code | Cause |
| --- | --- | --- |
| `404` | `not_found` | Path is not `/healthz`, `/readyz` or `/token`. |
| `405` | `method_not_allowed` | Right path, wrong method. `/token` is POST; the health endpoints are GET. |

### Reading the logs

Every `/token` request emits one line with a fixed vocabulary, so a CloudWatch filter
can count them:

```text
{"outcome": "mint_ok"}
{"outcome": "app_not_installed"}
```

The vocabulary is closed and never contains caller-supplied text. OIDC failures log
the exception class name only, for the same reason.

!!! note "`/healthz` returning 200 proves almost nothing"
    It answers before configuration is read, so it returns 200 on a broker with no
    credentials and no App installed. `/readyz` is the one that resolves
    configuration. A real signed `POST /token` is the only full check.

See [Broker deployment](broker-deployment.md) for the deployment side.
