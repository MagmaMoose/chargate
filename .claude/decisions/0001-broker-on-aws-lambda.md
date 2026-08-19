# 0001 — The token broker runs on AWS Lambda behind an API Gateway HTTP API

**Date:** 2026-08-18
**Status:** Accepted

## Context

The broker exchanges a consumer's GitHub Actions OIDC token for a repo-scoped
`Chargate[bot]` installation token, so PR comments carry that byline instead of
`github-actions[bot]`. `action.yml` has always defaulted `token_broker_url` to
`https://chargate.magmamoose.com`, and that default is frozen into every released tag.

**Nothing was ever actually serving it.** Three deployment attempts existed on paper:

- **Kubernetes on firefly** — landed in magmamoose/infra#427, then removed again in #519
  ("remove backstage, chargate and devlake"). Only a stray `namespace.yaml` survived, and
  chargate was never in `kubernetes/apps/kustomization.yaml`, so Flux never reconciled it.
- **A Cloudflare Python Worker** — `broker/wrangler.toml` + `entry.py`. Every push-to-main
  deploy failed identically: `Your Worker exceeded the size limit of 3 MiB [code: 10027]`
  against a measured 18,388 KiB upload. It never served a request.
- **A container image** — `ghcr.io/magmamoose/chargate`, built but deployed nowhere.

`dig chargate.magmamoose.com` returned no A and no CNAME. Because
`scripts/request-app-token.sh` fails soft on every error path (`emit_empty` → `exit 0`),
this was invisible: every consumer silently fell back to `github-actions[bot]` and nothing
went red anywhere.

## Decision

Deploy as an **AWS Lambda behind an API Gateway HTTP API**, in chargate's own AWS account
(`495408387666`), mirroring the pattern MagmaMoose/nievah established for its webhook front
door. Retire the Kubernetes manifests, the Cloudflare Worker, and the container image.

### API Gateway, not a Lambda Function URL

A Function URL is free where the HTTP API is not, but it has **no throttle**. The stage
throttle (2 rps / burst 10) is what deterministically caps Lambda invocations, compute,
logs and egress under any load. Nievah's `api.tf` also records that a Function URL behind
a CDN returned `InvalidSignatureException` on every POST while `GET /healthz` stayed green
— the exact failure mode this service cannot afford, since its client fails soft.

### No hand-rolled crypto

Reimplementing RSASSA-PKCS1-v1_5, DER parsing and JWS claim validation to save ~4.6 MB of
zip would put ~380 lines of new cryptographic code in the security boundary of a token
minter, in a repository whose product is finding security defects in other people's code.
`pyjwt[crypto]` ships instead.

Also rejected: **AWS KMS asymmetric signing** — $1/month per key plus $0.15/10k `Sign`, i.e.
roughly 100× the entire rest of the stack, to protect a key only one Lambda role can read.

### FastAPI is dropped from the artifact, pyjwt and httpx are kept

`fastapi` + `starlette` + `pydantic` + `pydantic_core` is ~7 MB of an 8.4 MB zip and the
dominant cold-start term, to route three paths and validate six strings. It is replaced by
a dispatch table in `app/lambda_handler.py` and a frozen dataclass in `app/config.py`.

`httpx` stays, because dropping it would mean rewriting `app/github.py` and `app/oidc.py` —
including the `quote(..., safe="")` SSRF barrier and the `httpx.MockTransport` seam that ten
existing tests use. Those two files now change by **zero lines**.

`app/main.py` keeps a FastAPI shell for local development and the existing `TestClient`
suite, and is **excluded from the zip by name**.

Measured result: **5.28 MB zipped**, reproducible (identical sha256 across builds).

### Cloudflare-proxied, on a new hostname

The front door is `broker-chargate.magmamoose.com`, **orange-clouded**. Proxying absorbs
abusive volume at Cloudflare's free edge before AWS meters it, which matters because AWS does
not document whether API Gateway bills the requests it rejects with its own 429 — so a flood
is otherwise somewhere between $1 and ~$864 a day. Combined with
`disable_execute_api_endpoint = true`, the proxy is the only door.

**The accepted trade-off:** proxying terminates TLS at Cloudflare, so the inbound OIDC token
and the outbound live `pull_requests: write` installation token pass through a third party in
plaintext. This was raised, weighed and accepted deliberately — record it here so nobody
"fixes" it later without knowing it was a decision. mTLS / Authenticated Origin Pulls would
close origin bypass but **not** this exposure, so it buys nothing against the risk that was
accepted.

A first-level subdomain was required: Cloudflare's free Universal SSL covers the apex and one
label only, so `hooks.chargate.…` could not be proxied without Advanced Certificate Manager.
`chargate.magmamoose.com` would also have qualified; the rename to `broker-chargate` was a
deliberate choice to free the shorter name, at the cost below.

**Consequence:** `action.yml`'s `token_broker_url` default changes, and that default is frozen
into every tag released before this. Consumers pinned to an older tag keep resolving
`chargate.magmamoose.com`, which does not exist, and fail soft to `github-actions[bot]` until
they bump. Nothing breaks; bylines simply do not change until a consumer updates.

Nievah and caldrith should also proxy (MagmaMoose/nievah#187, MagmaMoose/caldrith#68), and for
them the credential-exposure trade-off does not arise at all — neither returns a credential in
a response body. Both, however, sit two labels deep and need a rename first.

### Secrets in SSM Parameter Store, seeded by hand

Standard-tier `SecureString` is free for both storage and reads; Secrets Manager is
$0.40/secret/month. Terraform never creates them — a secret in a Terraform resource is a
secret in Terraform state, and magmamoose/infra is public. They are not Lambda environment
variables either, where `lambda:GetFunctionConfiguration` would reveal them.

### No automatic circuit breaker

A flood alarm that deletes the API outright was specced and declined. The stage throttle
plus lowering the account-level API Gateway throttle from 10,000 rps to 50 (a support case,
magmamoose/infra#642) reach the same order of magnitude without ~10 extra resources, a
false-positive mode that silently darkens the front door, and a drill to keep the kill
switch honest.

## Consequences

- **Deploying is a two-repo act.** A chargate release publishes `broker/<version>.zip` to S3;
  deploying it is a reviewed one-line bump of `broker_artifact_version` in
  magmamoose/infra. Deliberate — the artifact is immutable and version-scoped, so the pin is
  the only deployment signal Terraform needs.
- **The free-tier reasoning is not what the infra repo says it is.** Chargate's account is a
  member of an organization with consolidated billing, so Always-Free allowances are **pooled
  org-wide** with nievah, and 12-month offers date from the *management* account's creation
  and have already expired. API Gateway is therefore billed from the first request — about
  $0.002/month at real volume. The per-account split is still right, for blast-radius
  isolation and per-account SCPs, not for free-tier multiplication.
- **`GET /healthz` is not evidence.** See `.claude/COMMON_MISTAKES.md`;
  `.github/workflows/broker-smoke.yml` is the real check.
- The `broker` dependency group referenced by older docs never existed; `broker/` has its own
  pyproject and virtualenv.
