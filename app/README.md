# Chargate as a GitHub App

Install Chargate once on an org and **every repository is scanned on every pull
request — with no workflow file in any repo.** New repos are covered the moment
they're created. The Marketplace action still exists for teams who want to wire a
scan step into their own pipelines; the App is the zero-config option for rolling
coverage across a whole org without a PR per repo.

## How it works

```
  PR opened/updated
        │
        ▼
  GitHub App webhook ──────► Cloudflare Worker (app/worker)
                                   │  verify HMAC signature
                                   │  repository_dispatch ──► engine repo
                                   ▼
                       .github/workflows/app-scan.yaml (in magmamoose/chargate)
                                   │  mint App token (scoped to the target repo)
                                   │  open Check Run "Chargate"  (in progress)
                                   │  checkout target @ PR head
                                   │  run magmamoose/chargate@v1  (report mode)
                                   │  SARIF → annotations
                                   ▼
                       Check Run completed on the PR  +  HTML dashboard artifact
```

Two moving parts you deploy:

1. **The webhook worker** (`app/worker`) — a tiny Cloudflare Worker. It verifies
   the webhook is genuinely from GitHub, then fires a `repository_dispatch` at the
   engine repo. It is **keyless**: it never holds the App's private key.
2. **The scan engine** (`.github/workflows/app-scan.yaml`, already in this repo) —
   does the real work on GitHub-hosted runners and reports a Check Run.

### Least privilege

The customer-facing App is **read-only on code**: `Checks: write`, `Contents:
read`, `Pull requests: read`, `Metadata: read`. The engine mints an installation
token scoped to a **single** target repo per scan. The only write-capable
credential in the system is a fine-grained token that can do exactly one thing —
`repository_dispatch` to the engine repo.

---

## Setup

### 1. Create the GitHub App

Either import [`app-manifest.json`](./app-manifest.json) via
`https://github.com/organizations/<org>/settings/apps/new?manifest` (edit the
webhook URL first), or create it by hand with these settings:

- **Webhook URL**: your Worker URL (from step 2 — set a placeholder for now).
- **Webhook secret**: generate a strong random string; keep it for step 2.
- **Repository permissions**: Checks → *Read & write*; Contents → *Read-only*;
  Pull requests → *Read-only*; Metadata → *Read-only*.
- **Subscribe to events**: *Pull request*, *Check run*.
- After creating: note the **App ID**, and **generate a private key** (downloads a
  `.pem`).

### 2. Deploy the webhook worker

```sh
cd app/worker
npm install

# Repo that hosts app-scan.yaml — edit [vars] in wrangler.toml if not this repo.
npx wrangler secret put GITHUB_WEBHOOK_SECRET   # the secret from step 1
npx wrangler secret put ENGINE_DISPATCH_TOKEN   # see below
npx wrangler deploy
```

`ENGINE_DISPATCH_TOKEN` is a **fine-grained personal access token** scoped to the
engine repo (`magmamoose/chargate`) only, with **Contents: read and write**
(required to send a repository dispatch). Nothing else.

Copy the deployed Worker URL (`https://chargate-app.<subdomain>.workers.dev`) back
into the App's **Webhook URL** (step 1).

### 3. Give the engine the App credentials

In the engine repo (`magmamoose/chargate`) → Settings → Secrets and variables →
Actions, add:

- `CHARGATE_APP_ID` — the App ID from step 1.
- `CHARGATE_APP_PRIVATE_KEY` — the full contents of the `.pem` private key.

> The engine workflow needs a chargate release that supports the App (the action
> must accept `enable_dashboard`). Pin `uses: magmamoose/chargate@v1` to such a
> release.

### 4. Install the App

Install the App on the org and choose **All repositories** (or a selection).
That's it — open a PR and the **Chargate** check appears.

### 5. (Optional) Make it blocking

By default the check is **advisory** (report-only): findings show as annotations
and a neutral check, but don't block merges.

- To fail the check on critical/high findings, set repository variable
  `CHARGATE_BLOCKING=true` in the engine repo.
- To enforce on a target repo, add **Chargate** as a required status check in its
  branch protection / ruleset.

---

## Notes & limits

- **Forked PRs** are skipped in v1 (the App isn't installed on the fork, so its
  head can't be fetched). PRs from branches in the same repo are scanned.
- **Re-runs**: clicking *Re-run* on the Chargate check re-dispatches a fresh scan.
- **Findings detail**: inline annotations are capped at 50 by the GitHub API; the
  full set is always in the **chargate-security-dashboard** artifact on the run.
- **Private repos**: no GitHub Advanced Security needed — SARIF upload is off and
  findings surface via the Check Run + dashboard artifact instead.

## Local development

```sh
cd app/worker
npm install
npm test            # unit tests for signature verification + event routing
npx wrangler dev    # local worker; POST signed sample webhooks to it
```
