# Chargate Web

A GitHub-style "Security tab" UI over the Chargate findings API. React 18 + Vite +
TypeScript, dark theme, no UI component library.

## Views

- **Sign in** — gated on `GET /api/v1/auth/me`; 401 shows a "Sign in with GitHub"
  button that redirects to `${VITE_API_BASE}/api/v1/auth/login`.
- **Overview (`/`)** — fleet dashboard: severity summary cards, by-tool breakdown,
  and a table of repositories sorted by finding count.
- **Repository detail (`/repos/:id`)** — findings (with severity + tool filters)
  and recent scans for one repository.
- **All findings (`/findings`)** — cross-repo findings with filters and pagination.

## Configuration

The API base URL is read from `VITE_API_BASE` at **build time** and defaults to
`http://localhost:8000`. All requests are sent with `credentials: 'include'` so the
backend session cookie is forwarded.

Copy `.env.example` to `.env` to override locally:

```sh
cp .env.example .env
# edit VITE_API_BASE
```

## Local development

```sh
npm install
npm run dev          # http://localhost:5173
```

Point at a non-default API:

```sh
VITE_API_BASE=https://chargate.example.com npm run dev
```

## Build

```sh
npm run build        # runs tsc typecheck, then vite build -> dist/
npm run preview      # serve the production build on :5173
```

## Docker

Multi-stage build (Node build → nginx serving static `dist/`). `VITE_API_BASE` is a
build arg because Vite inlines env vars into the bundle:

```sh
docker build -t chargate-web --build-arg VITE_API_BASE=https://api.example.com .
docker run --rm -p 8080:80 chargate-web   # http://localhost:8080
```

`nginx.conf` provides SPA fallback (client-side routes survive hard refresh),
long-cache headers for fingerprinted `/assets/`, and a `/healthz` endpoint.

## Kubernetes

The image listens on port 80 and exposes `/healthz` for probes:

```yaml
containers:
  - name: web
    image: registry.example.com/chargate-web:latest
    ports:
      - containerPort: 80
    readinessProbe:
      httpGet: { path: /healthz, port: 80 }
    livenessProbe:
      httpGet: { path: /healthz, port: 80 }
```

Because `VITE_API_BASE` is baked in at build time, build a per-environment image
(or set it to a same-origin path and route the API via Ingress).

## Layout

```
src/
  api.ts                 # centralised fetch client (credentials: 'include')
  types.ts               # API types
  useApi.ts              # tiny fetch hook (loading/error/reload)
  auth.tsx               # auth gate + context + sign-in screen
  format.ts              # totals / date / sha helpers
  App.tsx, main.tsx      # router + entry
  components/            # TopBar, Severity, FindingsTable, FindingsFilterBar, states
  pages/                 # Overview, RepoDetail, AllFindings
```
