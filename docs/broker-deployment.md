# Token broker deployment

The broker under `broker/` has two supported targets from the same source tree and the same
commit: a **Cloudflare Python Worker** (the current one) and a **container** from GHCR. Nothing
in the application code chooses between them — the only runtime-shaped difference is where
configuration comes from, and `app/config.py` handles both.

Consumers are unaffected by which one is live: same hostname, same `POST /token` contract.

| | Cloudflare Worker | Kubernetes |
|---|---|---|
| Runtime | Pyodide, ASGI bridge | `python:3.12-slim`, uvicorn |
| Entry | `broker/entry.py` → `Default.fetch` | `uvicorn app.main:app` |
| Config | `wrangler.toml` `[vars]` + `wrangler secret put` | ExternalSecret → Secret → `envFrom` |
| TLS | Terminated by Cloudflare | Ingress + cert-manager |
| Cost at this volume | Workers Paid — see §1.3 | A cluster |

---

## 1. Cloudflare Worker

### 1.1 Why the deploy is three commands, not one

`pywrangler sync` resolves `broker/pyproject.toml` against the Pyodide build implied by
`compatibility_date` and unpacks the wasm32 wheels into `python_modules/`. Plain `wrangler
deploy` on its own uploads the source and nothing else, so the Worker starts with only the
Python standard library and dies on the first third-party import.

The prune between the two steps is **not** optional. Wrangler bundles every file in the working
directory and honours neither `.wranglerignore` nor a rules exclusion for Python, so the
resolution virtualenvs and the test suite would otherwise ship — and `.venv` holds host-native
wheels that cannot run on wasm32 at all.

```sh
cd broker
uv run --with workers-py==1.16.1 pywrangler sync
rm -rf .venv .venv-workers tests
npx --yes wrangler@4.42.0 deploy --routes "chargate.magmamoose.com/*"
```

`.github/workflows/deploy-cloudflare.yml` does exactly this on a push to `main`. A pull request
runs the same vendor step and then `wrangler deploy --dry-run`, which catches the failure mode
that actually bites here — a dependency with no wasm32 wheel — without uploading anything.

!!! warning "Node 26 cannot run `pywrangler sync`"
    The Pyodide interpreter is resolved through a node shim that still passes
    `--experimental-wasm-stack-switching`, which Node 26 rejects with `bad option`. Use Node 22
    or 24; CI pins 24.

### 1.2 Secrets

Set once per environment, never committed:

```sh
cd broker
npx wrangler secret put APP_ID
npx wrangler secret put PRIVATE_KEY < chargate-app.private-key.pem
```

`PRIVATE_KEY` is multi-line, so pipe the PEM rather than pasting it. **PKCS#1** — the
`BEGIN RSA PRIVATE KEY` form GitHub hands out — is fine as-is: `pyjwt[crypto]` uses
`cryptography`, which reads it directly. The pkcs8 conversion people reach for is a constraint
of the JavaScript `crypto.subtle.importKey` path, not this one.

!!! warning "Deploy first, then set secrets"
    Cloudflare has no API for a secret on a script that was never uploaded, so on a fresh
    account `wrangler secret put` fails until the Worker exists. Deploy once — `/healthz`
    answers without either secret — then set them and deploy again.

`/healthz` and `/readyz` are deliberately not the same check. Configuration is resolved per
request (the Worker requires it — secrets only exist on the invocation's `env`), where it used
to be built when the app was constructed, so a broker missing `APP_ID`/`PRIVATE_KEY` used to
crash-loop and be impossible to miss. To keep that signal:

| | Unconfigured | Configured |
|---|---|---|
| `GET /healthz` (liveness) | `200 {"status": "ok"}` | `200` |
| `GET /readyz` (readiness) | `503 {"status": "misconfigured"}` | `200` |
| `POST /token` | `503 {"error": "config_unavailable"}` | `200` |

So the first Worker deploy comes up healthy with no secrets, while on Kubernetes the readiness
probe still marks a misconfigured pod NotReady rather than letting it report Ready and fail
every token request. A malformed request is still answered `400` before configuration is
consulted at all.

Everything else is non-secret and lives in `wrangler.toml` `[vars]`: `OIDC_AUDIENCE`,
`GITHUB_API_URL`, `TOKEN_PERMISSIONS_JSON`, `ALLOWED_REPOSITORIES`.

### 1.3 Cost and limits

**This Worker requires the Workers Paid plan ($5/month), and the reason is script size, not
traffic.** The vendored bundle measures **4.30 MiB gzipped** (18.3 MiB raw, 1055 modules)
against a **3 MB ceiling on Workers Free** and **10 MB on Paid**. `cryptography` is the bulk of
it — 4.5 MiB of wheel before any application code — and it is not optional: `pyjwt[crypto]`
needs it to verify RS256 and to sign the App JWT.

Getting under 3 MB would mean dropping `cryptography` for the runtime's WebCrypto, which cannot
load the PKCS#1 key GitHub issues without a pkcs8 conversion, and would mean hand-rolling both
the verify and the sign. That is a large rewrite to save $5/month; it is not worth it.

Everything *else* fits Free comfortably, and none of it is close to a paid overage:

| | Included/month | Broker's usage |
|---|---|---|
| Requests | 10,000,000 | ~1.5–15k |
| CPU time | 30,000,000 CPU-ms | ~5 ms per request; the two quotas balance at 3 ms/request |
| Duration | not billed, no limit | two GitHub round-trips of I/O wait, free |

So the marginal cost of this Worker on an account that already has Workers Paid is **zero**.

`/token` is public and unauthenticated at the edge (it authenticates callers itself, by
verifying their Actions OIDC token). There is no account-level spend cap on Workers, and a
rejected request still bills, so put a WAF rate-limiting rule in front of it — blocked requests
never invoke the Worker and are therefore never billed.

`/token` is public and unauthenticated at the edge (it authenticates callers itself, by
verifying their Actions OIDC token). There is no account-level spend cap on Workers, and a
rejected request still bills, so if this ever moves to a paid account put a WAF rate-limiting
rule in front of it — blocked requests never invoke the Worker and are therefore never billed.

### 1.4 JWKS

GitHub's Actions JWKS is fetched with `httpx` rather than `jwt.PyJWKClient`. This is the one
thing in the service that could not follow it to a Worker: `PyJWKClient` fetches over
`urllib.request.urlopen`, a blocking socket call, and the Workers runtime has no blocking
sockets.

The fetched key set is cached in a module-level dict, which a warm isolate reuses across
requests — the closest thing a Worker has to a process cache, and it costs no KV writes. A key
rotation is handled by a single forced refetch on a `kid` miss rather than by waiting out the
TTL, so a rotation does not need a cold isolate to recover.

---

## 2. Kubernetes

Still supported and still built by `release.yml`. The manifests live in `k8s/`, the image is
`ghcr.io/magmamoose/chargate`, and configuration arrives as environment variables through the
ExternalSecret in `k8s/base/externalsecret.yaml` (`APP_ID`, `PRIVATE_KEY`).

```sh
kubectl apply -k k8s/overlays/prod
```

The container needs uvicorn, which the Worker does not, so it is an optional extra rather than a
base dependency: `uvicorn[standard]` drags in `httptools`, which has no wasm32 wheel, and one
unresolvable transitive dependency fails the whole vendor step.

---

## 3. Cutover

A Worker **route** beats both a DNS record and a Cloudflare Tunnel at the edge, so the order is
forced and only one order is safe:

1. Deploy the Worker and set its secrets, but leave the route off.
2. Verify it: `curl https://<workers.dev URL>/healthz`.
3. Add the route for `chargate.magmamoose.com/*`. It now wins over the tunnel immediately.
4. Only then remove the in-cluster Deployment and its tunnel ingress rule.

Doing 4 before 3 is an outage. Rolling back is the same list in reverse: drop the route and the
tunnel serves the pod again.
