# Token broker deployment

<!-- sources: broker/app/, broker/scripts/build_lambda_zip.py, .github/workflows/publish-broker.yml -->

The broker exchanges a consumer's GitHub Actions OIDC token for a short-lived, repo-scoped
`Chargate[bot]` installation token, so Chargate's PR comments carry that byline instead of
`github-actions[bot]`.

It runs as an **AWS Lambda behind an API Gateway HTTP API**, in Chargate's own AWS account.
The Terraform lives in [magmamoose/infra](https://github.com/magmamoose/infra) under
`terraform/aws/chargate/`; this repository owns the code that runs on it and the contract for
packaging it.

```text
consumer repo's workflow           any pinned chargate tag
  scripts/request-app-token.sh     POST {oidcToken, owner, repo, ref, runId, sha}
        │
        ▼
  broker-chargate.magmamoose.com   Cloudflare DNS, PROXIED (orange cloud)
        │                          CNAME → the API Gateway custom-domain target
        ▼
  API Gateway HTTP API             $default route + stage · throttle 2 rps / burst 10
        │                          execute-api endpoint disabled: the custom domain is the only door
        ▼
  chargate-broker (Lambda)         python3.12 · x86_64 · app.lambda_handler.handler
        │                          code: s3://<artifacts bucket>/broker/<version>.zip
        ├── SSM Parameter Store    /chargate/prod/{app-id,private-key}  (SecureString)
        └── api.github.com         App JWT → installation → scoped token
```

!!! warning "`GET /healthz` proves nothing"
    It returns 200 on a Lambda with no SSM parameters, no permission to read them, and no
    GitHub App installed. It deliberately answers before configuration is consulted, which is
    what makes "deploy, then seed the secrets" work. Because
    `scripts/request-app-token.sh` fails soft (empty token, `exit 0`), a broken broker
    produces **no red check anywhere**, just comments quietly reverting to
    `github-actions[bot]`. Verify with a real signed `POST`:
    `.github/workflows/broker-smoke.yml`.

## The package contract

`broker/scripts/build_lambda_zip.py` is the one definition of what ships. It is run by CI (so
a bad dependency bump fails the pull request) and by the release workflow (which publishes the
artifact). A local build and a released artifact produced by different means is a difference
nobody discovers until production behaves unlike the test.

```bash
cd broker
uv run python scripts/build_lambda_zip.py \
  --out ../dist/chargate-broker.zip --platform x86_64-manylinux_2_28
```

**What ships:** `app/` minus `main.py`, plus the resolved wheels for `pyjwt[crypto]` and
`httpx`. ~5.3 MB.

- `app/main.py` is **excluded by name**. It is the only module importing FastAPI, which is not
  in the shipped dependency set; including it turns a clean deploy into a cold-start
  `ImportError` on the fail-soft path above.
- `boto3`/`botocore` are never bundled: the runtime supplies them.
- `--platform` is **required and has no default**, because `cryptography` ships compiled
  wheels and a build on a developer's Mac would otherwise deploy and then fail to import.

**The build is deterministic** (fixed timestamps, fixed modes, sorted order, resolution pinned
by `broker/uv.lock`). The release workflow decides whether to publish by comparing against the
previous release tag; a non-reproducible build would mean every chargate release opened an
infra bump PR redeploying byte-identical code until nobody read them.

`broker/tests/test_lambda_package.py` defends all of this. It unzips the artifact
into an empty directory and importing it in a subprocess with a scrubbed path and poisoned
`sys.modules`, so a module that grows an import of something unshipped goes red here rather
than at the first real request.

## Publishing and deploying are different acts

**Publishing** is `.github/workflows/publish-broker.yml`, triggered by the release tag. It builds the zip, gates on whether anything shipped
actually changed since the previous tag, and uploads it with `s3api put-object`, refusing to
overwrite an existing key. It is deliberately NOT in `release.yml`, which caldrith provisions
centrally and overwrites in place.
Auth is GitHub OIDC, no AWS credential is stored in this repository. Two repo **variables**
turn it on; unset, diatreme skips the step and nothing changes:

| Variable | Value |
|---|---|
| `BROKER_ARTIFACT_BUCKET` | `terragrunt output artifact_bucket` from infra's `chargate-artifacts` leaf |
| `BROKER_PUBLISH_ROLE_ARN` | `terragrunt output publish_role_arn` from the same leaf |

The key is `broker/<version>.zip` and **diatreme refuses to overwrite one that exists**:
infra pins that key, so replacing its bytes would swap the running code under a version
somebody already reviewed.

**Deploying** is a reviewed one-line bump of `broker_artifact_version` in infra's
`chargate-broker` leaf. The release job writes the exact line to its step summary.

## Configuration

The broker reads its configuration per request, so a Lambda whose parameters are seeded
after the first deploy recovers without a redeploy.

| Variable | Type | Required | Default | Effect |
| --- | --- | --- | --- | --- |
| `APP_ID` | string | yes | (none) | The Chargate GitHub App's numeric ID. Signs the App JWT. |
| `PRIVATE_KEY` | string, secret | yes | (none) | The App's RSA private key, PEM. A `\n`-escaped PEM is un-escaped on load, so a secret store that escapes newlines works as-is. |
| `SECRET_PATH` | string | no | (unset) | SSM Parameter Store path holding the two values above, for example `/chargate/prod`. Unset means read everything from the environment and never import boto3, which is the local and CI path. |
| `OIDC_AUDIENCE` | string | no | `chargate` | The `aud` the caller's token must carry. Must match what the consumer's workflow requests. |
| `ALLOWED_REPOSITORIES` | string | no | `""` | Comma-separated `owner/repo` allowlist. Empty means any repository the App is installed on, which is what is deployed. |
| `GITHUB_API_URL` | string | no | `https://api.github.com` | API base. Point it at a GitHub Enterprise host to mint there. |
| `TOKEN_PERMISSIONS_JSON` | JSON object | no | `{"pull_requests": "write"}` | Permissions granted to the minted token. Least privilege: comments only. |
| `CHARGATE_LOG_LEVEL` | string | no | `INFO` | Level for the `chargate.broker` logger. An unrecognised value falls back to `INFO` rather than failing at import. |

**Precedence: SSM wins over the environment.** Values are read from the process
environment first, then the SSM overlay is applied on top. That is what keeps the two
secrets out of the function's own configuration.

!!! note "Why the level is set explicitly"
    The Lambda runtime pins the root logger to `WARNING`. Without `CHARGATE_LOG_LEVEL`
    the per-request outcome lines, the only observability this service has, are dropped.

## Secrets

Seeded **by hand**, never by Terraform: a secret in a Terraform resource is a secret in
Terraform state, and magmamoose/infra is public. They are not Lambda environment variables
either, where anything holding `lambda:GetFunctionConfiguration` could read them.

```bash
aws ssm put-parameter --region eu-west-1 --profile mm-prd-chargate \
  --name /chargate/prod/app-id --type String --value "$APP_ID" --overwrite

aws ssm put-parameter --region eu-west-1 --profile mm-prd-chargate \
  --name /chargate/prod/private-key --type SecureString \
  --value "file://chargate-app.private-key.pem" --overwrite

rm chargate-app.private-key.pem
```

No `--key-id`, so the AWS-managed `aws/ssm` key is used, which carries no monthly charge.
Standard-tier parameters are free for both storage and reads. Verify:

```bash
aws ssm get-parameters-by-path --path /chargate/prod --recursive --with-decryption \
  --region eu-west-1 --profile mm-prd-chargate
```

Parameter basenames map to config fields with `-` → `_`, so `private-key` lands on
`BrokerConfig.private_key`.

## Going live

Steps marked **H** need a human with credentials or a console.

1. **H** Confirm the Chargate GitHub App exists, note its **App ID**, confirm it is installed
   on every repo that should get `Chargate[bot]` comments, and download the private key.
   Its absence is invisible, a 404 becomes `app_not_installed`, the client fails soft, silence.
2. Merge infra **#638** (it is what creates `terraform/aws/` at all), then the chargate infra PR.
3. **H** Apply the `chargate-artifacts` leaf. Set `BROKER_ARTIFACT_BUCKET` and
   `BROKER_PUBLISH_ROLE_ARN` as repo variables from its outputs.
4. **H** Seed the two SSM parameters (above).
5. Merge this repo's release changes to `main`; confirm `broker/<version>.zip` exists in the
   bucket. **This is the cold start**, the front door cannot be applied against a key that
   does not exist.
6. **H** Apply `chargate-broker` **phase 1**: `enable_custom_domain = false`. This requests the
   regional ACM certificate and prints the validation record. Nothing resolves yet.
7. Add the ACM validation CNAME to the Cloudflare leaf (grey cloud, a proxied record answers
   with Cloudflare's own value and the certificate never leaves `PENDING_VALIDATION`). Apply,
   wait for `ISSUED`.
8. **H** Apply **phase 2**: `enable_custom_domain = true`, `disable_default_endpoint = true`.
   Applying phase 2 before the certificate is issued fails with a `BadRequestException`.
9. Add the `broker-chargate.magmamoose.com` CNAME → the custom-domain target, **`proxied = true`**
   (orange cloud). The hostname resolves for the first time. Note that consumers pinned to a
   tag released *before* this change still default to the old `chargate.magmamoose.com`, which
   does not resolve. They fail soft to `github-actions[bot]` until they bump.
10. **H** Run `broker-smoke.yml` and confirm a real token is minted and accepted by GitHub.
    Then open a throwaway PR in a consumer repo and check the comment byline.
11. **H** Confirm the SNS subscription email, until clicked it delivers nothing, which
    Terraform reports as "created" either way.
12. **H** Authorise the Slack workspace in the AWS Chatbot console for **this** account.
    Chatbot's workspace authorisation is per-account and cannot be done by Terraform; nievah's
    account being authorised does nothing for chargate's.

**Rollback** before step 9 is "do nothing", nobody is using it. After step 9: delete the CNAME
or set `enable_custom_domain = false`; consumers return to `github-actions[bot]`, which is
exactly the behaviour they have today.

## Cost

Roughly **under a cent a month**. Everything is inside a permanent Always-Free allowance except
API Gateway requests and S3 storage.

Note that Always-Free allowances are **pooled across the AWS organization**, not granted per
account, AWS applies the free tier to total usage across all member accounts. And because
free-tier eligibility dates from the *management* account's creation, the 12-month offers
(including API Gateway's 1M calls) have already expired for this account, so gateway requests
are billed from the first one at $1.00/million.

The controls that actually bound a bad day, in order of how fast they act:

1. **The 2 rps stage throttle**, instantaneous, at the gateway. Deterministically caps Lambda
   invocations, compute, logs and egress at any load.
2. **`disable_execute_api_endpoint`**, the custom domain is the only door.
3. **The Cloudflare proxy**, abusive volume is absorbed at Cloudflare's free edge and never
   becomes an AWS line item. This is what makes the undocumented 429-billing question moot for
   traffic that arrives via the hostname.
4. **The account-level API Gateway throttle.** Default 10,000 rps; lowering it to 50 is a
   support case (magmamoose/infra#642) and is what bounds the one genuinely unresolved
   question, whether API Gateway bills requests it rejects with its own 429. AWS does not
   document this.
5. **CloudWatch alarms and an AWS Budget**, receipts, not controls. Budgets refresh at most
   three times a day and cannot stop spend.
