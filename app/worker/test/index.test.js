// Unit tests for the webhook worker's pure logic. Run: node --test
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { buildDispatch, verifySignature } from "../src/index.js";

const SECRET = "s3cret";
const sign = (body) => "sha256=" + createHmac("sha256", SECRET).update(body).digest("hex");

test("verifySignature accepts a correct signature", async () => {
  const body = '{"hello":"world"}';
  assert.equal(await verifySignature(SECRET, body, sign(body)), true);
});

test("verifySignature rejects a tampered body", async () => {
  const body = '{"hello":"world"}';
  assert.equal(await verifySignature(SECRET, body + "x", sign(body)), false);
});

test("verifySignature rejects missing/empty inputs", async () => {
  assert.equal(await verifySignature(SECRET, "{}", null), false);
  assert.equal(await verifySignature("", "{}", "sha256=00"), false);
});

test("buildDispatch maps a pull_request.opened event", () => {
  const d = buildDispatch("pull_request", {
    action: "opened",
    repository: { full_name: "acme/widgets" },
    pull_request: { number: 7, head: { sha: "abc123", ref: "feature", repo: { full_name: "acme/widgets" } } },
    installation: { id: 42 },
    sender: { login: "octocat" },
  });
  assert.deepEqual(d, {
    owner: "acme", repo: "widgets", head_sha: "abc123", head_ref: "feature",
    pull_number: 7, installation_id: 42, sender: "octocat",
  });
});

test("buildDispatch ignores unsubscribed PR actions", () => {
  assert.equal(buildDispatch("pull_request", { action: "labeled", repository: {}, pull_request: {} }), null);
});

test("buildDispatch skips forked-PR heads", () => {
  const d = buildDispatch("pull_request", {
    action: "opened",
    repository: { full_name: "acme/widgets" },
    pull_request: { number: 9, head: { sha: "f00", repo: { full_name: "fork/widgets" } } },
  });
  assert.equal(d, null);
});

test("buildDispatch handles check_run.rerequested", () => {
  const d = buildDispatch("check_run", {
    action: "rerequested",
    repository: { full_name: "acme/widgets" },
    check_run: { head_sha: "deadbeef", pull_requests: [{ number: 3 }] },
    installation: { id: 1 },
  });
  assert.equal(d.head_sha, "deadbeef");
  assert.equal(d.owner, "acme");
  assert.equal(d.pull_number, 3);
});

test("buildDispatch returns null when head sha is absent", () => {
  assert.equal(buildDispatch("pull_request", {
    action: "opened", repository: { full_name: "a/b" }, pull_request: { number: 1, head: {} },
  }), null);
});
