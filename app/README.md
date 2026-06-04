# Chargate — GitHub App + centralised Security tab

Install the Chargate App once on an org and every repository is scanned on every
pull request, with **no workflow file in any repo**. Findings stream into a
multi-tenant store and a centralised web UI — a "Security tab" that works across
your whole fleet, on private repos, **without GitHub Advanced Security**.

This directory is the product:

| Path | What it is |
|------|------------|
| [`api/`](api/) | FastAPI + Postgres backend — webhooks, GitHub App auth, Check Runs, findings store, query API |
| [`web/`](web/) | React + Vite + TypeScript frontend — the centralised Security tab |
| [`../.github/workflows/app-scan.yaml`](../.github/workflows/app-scan.yaml) | the scan engine (GitHub Actions, runs `magmamoose/chargate@v1`) |
| [`deploy/`](deploy/) | k8s manifests + Cloudflare guide; [`docker-compose.yml`](docker-compose.yml) for local |

## Architecture

```
 PR opened/updated
      │  webhook (HMAC verified)
      ▼
 FastAPI backend (api/) ──── owns the App private key ────────────────┐
      │  create Check Run (in_progress)                               │
      │  repository_dispatch  ──►  app-scan.yaml (GitHub Actions)      │
      │     payload: scan_id, read-only repo_token, one-time ingest_token
      │                              │  checkout target @ PR head      │
      │                              │  run magmamoose/chargate@v1     │
      │                              ▼                                 │
      │◄──── POST SARIF /scans/{id}/results (ingest_token) ────────────┘
      │  parse → findings (Postgres, tenant = installation)
      │  complete Check Run (conclusion + annotations)
      ▼
 React UI (web/)  ◄── GitHub OAuth ── shows findings for the installations you can access
```

The backend holds **all** GitHub credentials. The Actions runner gets only two
short-lived, single-purpose tokens per scan (a read-only checkout token and a
one-time ingest token) and stores nothing.

## Multi-tenant + access control

- **Tenant** = the GitHub account (org/user) that installed the App. Every
  finding row carries its `account_id`.
- Users **sign in with GitHub**; the backend reads `/user/installations` and
  scopes every query to the installations that user can access. One deployment
  serves many orgs without cross-tenant leakage.

## Setup

### 1. Create the GitHub App
- **Permissions**: Checks → *Read & write*; Contents → *Read-only*; Pull
  requests → *Read-only*; Metadata → *Read-only*.
- **Subscribe to events**: Pull request, Check run, Installation,
  Installation repositories.
- **Webhook URL**: `https://<your-backend>/api/v1/webhooks/github`; set a
  **webhook secret**.
- **OAuth**: set the callback URL to `https://<your-backend>/api/v1/auth/callback`;
  note the **client ID/secret** (used for user login).
- Generate a **private key** and note the **App ID**.
- See [`app-manifest.json`](app-manifest.json) to bootstrap most of this.

### 2. Deploy the backend + frontend
Pick a target — all use the same images:
- **Local / testing**: `cp api/.env.example api/.env` (fill in the App + OAuth
  values), then `docker compose up --build` → UI on `:8080`, API on `:8000`.
- **Kubernetes**: `kubectl apply -k deploy/k8s` (edit the Secret + Ingress host).
- **Cloudflare** (first-class): see [`deploy/cloudflare/`](deploy/cloudflare/).

Map `/api/*` to the backend and everything else to the frontend on one hostname
so the session cookie stays first-party.

### 3. Install the App
Install on your org (all repos or a selection). Open a PR → the **Chargate**
check appears, and findings show up in the UI.

By default the check is **advisory** (neutral on findings). Set
`CHARGATE_DEFAULT_BLOCKING=true` to fail on critical/high, and add **Chargate**
as a required check to enforce.

## Local development

```sh
# Backend
cd app/api && pip install -e '.[dev]' && pytest
uvicorn chargate_api.main:app --reload         # needs a local Postgres + .env

# Frontend
cd app/web && npm install && npm run dev        # http://localhost:5173

# Or the whole stack
cd app && docker compose up --build
```

## Limits (v1)
- Forked-PR heads are skipped (the App isn't installed on the fork).
- Inline Check Run annotations are capped at 50 by GitHub; the full set lives in
  the UI and the per-run dashboard artifact.
