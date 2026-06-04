// Chargate GitHub App — webhook worker (Cloudflare Workers).
//
// The whole job: receive a GitHub App webhook, verify it's really from GitHub,
// and fan it out to the Chargate scan workflow via repository_dispatch. The
// actual scanning + Check Run reporting happens in that workflow
// (.github/workflows/app-scan.yaml), which holds the App credentials.
//
// Deliberately keyless: this worker never sees the App private key. Its only
// secret beyond the webhook secret is a fine-grained token that can do exactly
// one thing — dispatch to the engine repo. See app/README.md.
//
// Secrets (wrangler secret put):
//   GITHUB_WEBHOOK_SECRET  — the App's webhook secret (HMAC verification)
//   ENGINE_DISPATCH_TOKEN  — fine-grained PAT, Contents:write on ENGINE_REPO only
// Vars (wrangler.toml [vars]):
//   ENGINE_REPO            — "owner/repo" hosting app-scan.yaml (e.g. magmamoose/chargate)
//   DISPATCH_EVENT_TYPE    — repository_dispatch event_type (default "chargate-scan")

const PR_ACTIONS = new Set(["opened", "synchronize", "reopened", "ready_for_review"]);

export default {
  async fetch(request, env) {
    if (request.method === "GET") {
      return new Response("chargate-app: ok\n", { status: 200 });
    }
    if (request.method !== "POST") {
      return new Response("method not allowed\n", { status: 405 });
    }

    const body = await request.text();
    const signature = request.headers.get("x-hub-signature-256");
    if (!(await verifySignature(env.GITHUB_WEBHOOK_SECRET, body, signature))) {
      return json({ error: "invalid signature" }, 401);
    }

    const event = request.headers.get("x-github-event") || "";
    let payload;
    try {
      payload = JSON.parse(body);
    } catch {
      return json({ error: "invalid json" }, 400);
    }

    if (event === "ping") {
      return json({ ok: true, pong: true });
    }

    const dispatch = buildDispatch(event, payload);
    if (!dispatch) {
      // A delivery we don't act on (a label edit, a closed PR, an event we
      // didn't subscribe to). Acknowledge so GitHub doesn't retry.
      return json({ ok: true, ignored: `${event}.${payload.action || ""}` });
    }

    const res = await dispatchScan(env, dispatch);
    if (!res.ok) {
      const detail = await res.text();
      return json({ error: "dispatch failed", status: res.status, detail }, 502);
    }
    return json({ ok: true, dispatched: dispatch }, 202);
  },
};

// Map an incoming webhook to the scan payload, or null if we shouldn't scan.
export function buildDispatch(event, p) {
  if (event === "pull_request" && PR_ACTIONS.has(p.action)) {
    const pr = p.pull_request || {};
    // Forked-PR heads live in a repo we're not installed on. Scanning them
    // safely needs base-repo merge refs; out of scope for v1 — skip with a note.
    if (pr.head?.repo?.full_name && pr.head.repo.full_name !== p.repository?.full_name) {
      return null;
    }
    return base(p, pr.head?.sha, pr.head?.ref, pr.number);
  }
  // A maintainer clicked "Re-run" on the Chargate check.
  if (event === "check_run" && p.action === "rerequested") {
    const cr = p.check_run || {};
    const pr = (cr.pull_requests && cr.pull_requests[0]) || {};
    return base(p, cr.head_sha, pr.head?.ref, pr.number);
  }
  return null;
}

function base(p, head_sha, head_ref, pull_number) {
  if (!head_sha) return null;
  const [owner, repo] = (p.repository?.full_name || "/").split("/");
  if (!owner || !repo) return null;
  return {
    owner,
    repo,
    head_sha,
    head_ref: head_ref || "",
    pull_number: pull_number || 0,
    installation_id: p.installation?.id || 0,
    sender: p.sender?.login || "",
  };
}

async function dispatchScan(env, client_payload) {
  const repo = env.ENGINE_REPO;
  return fetch(`https://api.github.com/repos/${repo}/dispatches`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${env.ENGINE_DISPATCH_TOKEN}`,
      accept: "application/vnd.github+json",
      "x-github-api-version": "2022-11-28",
      "user-agent": "chargate-app",
      "content-type": "application/json",
    },
    body: JSON.stringify({
      event_type: env.DISPATCH_EVENT_TYPE || "chargate-scan",
      client_payload,
    }),
  });
}

// ── Webhook signature verification (HMAC-SHA256, constant-time) ──────────────
export async function verifySignature(secret, body, signature) {
  if (!secret || !signature) return false;
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
  );
  const mac = await crypto.subtle.sign("HMAC", key, enc.encode(body));
  const expected = "sha256=" + [...new Uint8Array(mac)]
    .map((b) => b.toString(16).padStart(2, "0")).join("");
  return timingSafeEqual(expected, signature);
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json" },
  });
}
