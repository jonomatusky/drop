import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { constantTimeEqual, fetchHandler, parseSlug } from "../src/worker.mjs";

if (!globalThis.crypto) globalThis.crypto = webcrypto;

const encoder = new TextEncoder();

function b64(bytes) {
  return Buffer.from(bytes).toString("base64");
}

async function verifier(password, iterations = 1000) {
  const salt = encoder.encode("1234567890123456");
  const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations, hash: "SHA-256" }, key, 256);
  return {
    algorithm: "pbkdf2-sha256",
    iterations,
    salt: b64(salt),
    hash: [...new Uint8Array(bits)].map((byte) => byte.toString(16).padStart(2, "0")).join(""),
  };
}

class KV {
  constructor(seed = {}) {
    this.map = new Map(Object.entries(seed));
  }
  async get(key, opts = {}) {
    const value = this.map.get(key);
    if (value === undefined) return null;
    return opts.type === "json" ? JSON.parse(value) : value;
  }
  async put(key, value) {
    this.map.set(key, value);
  }
  async delete(key) {
    this.map.delete(key);
  }
}

class R2 {
  constructor(objects = {}) {
    this.objects = new Map(Object.entries(objects));
  }
  async get(key) {
    const value = this.objects.get(key);
    if (!value) return null;
    return { body: value, httpMetadata: { contentType: "text/html; charset=utf-8" }, httpEtag: '"test"' };
  }
  async list({ prefix }) {
    return {
      objects: [...this.objects.keys()].filter((key) => key.startsWith(prefix)).map((key) => ({ key })),
      truncated: false,
    };
  }
  async delete(keys) {
    for (const key of Array.isArray(keys) ? keys : [keys]) this.objects.delete(key);
  }
}

class DB {
  constructor(rows = {}) {
    this.rows = rows;
    this.revoked = [];
  }
  prepare(sql) {
    const self = this;
    return {
      values: [],
      bind(...values) {
        this.values = values;
        return this;
      },
      async first() {
        const slug = this.values[0];
        return self.rows[slug] || null;
      },
      async all() {
        return { results: Object.values(self.rows) };
      },
      async run() {
        if (sql.startsWith("UPDATE shares SET revoked_at")) self.revoked.push(this.values[1]);
        return {};
      },
    };
  }
}

function row(slug, overrides = {}) {
  return {
    slug,
    label: null,
    auth_mode: "password",
    sha256: "abc",
    files_json: JSON.stringify([{ path: "index.html", bytes: 2, sha256: "abc" }]),
    bytes: 2,
    scan_result_json: "{}",
    created_at: "2026-06-22T00:00:00+00:00",
    expires_at: null,
    revoked_at: null,
    uploader: "test",
    ...overrides,
  };
}

async function envFor(rows, kvSeed = {}) {
  return {
    ARTIFACTS: new R2({ "s1/index.html": "<h1>ok</h1>", "public/index.html": "<h1>ok</h1>", "expired/index.html": "old" }),
    AUTH_KV: new KV(kvSeed),
    DB: new DB(rows),
    ADMIN_TOKEN: "admin",
    PUBLIC_BASE_URL: "https://share.example.test",
  };
}

const auth = `Basic ${Buffer.from("user:pw").toString("base64")}`;
const badAuth = `Basic ${Buffer.from("user:wrong").toString("base64")}`;

{
  const env = await envFor({ s1: row("s1") }, { "auth:s1": JSON.stringify(await verifier("pw")) });
  const res = await fetchHandler(new Request("https://share.example.test/s1/", { headers: { authorization: auth } }), env);
  assert.equal(res.status, 200);
}

assert.equal(constantTimeEqual("same", "same"), true);
assert.equal(constantTimeEqual("same", "diff"), false);

{
  const env = await envFor({ s1: row("s1") }, { "auth:s1": JSON.stringify(await verifier("pw")) });
  const res = await fetchHandler(new Request("https://share.example.test/s1/", { headers: { authorization: badAuth } }), env);
  assert.equal(res.status, 403);
}

{
  const env = await envFor({ s1: row("s1") }, { "auth:s1": JSON.stringify(await verifier("pw")) });
  env.RATE_LIMIT_MAX = "1";
  env.RATE_LIMIT_WINDOW_SECONDS = "60";
  const first = await fetchHandler(new Request("https://share.example.test/s1/", { headers: { authorization: badAuth, "cf-connecting-ip": "192.0.2.1" } }), env);
  const second = await fetchHandler(new Request("https://share.example.test/s1/", { headers: { authorization: badAuth, "cf-connecting-ip": "192.0.2.1" } }), env);
  assert.equal(first.status, 403);
  assert.equal(second.status, 429);
}

{
  // A legitimate viewer replays valid auth on every asset — RATE_LIMIT_MAX must
  // not throttle successful loads, only failed/unauthenticated attempts.
  const env = await envFor({ s1: row("s1") }, { "auth:s1": JSON.stringify(await verifier("pw")) });
  env.RATE_LIMIT_MAX = "1";
  env.RATE_LIMIT_WINDOW_SECONDS = "60";
  for (let i = 0; i < 3; i += 1) {
    const res = await fetchHandler(new Request("https://share.example.test/s1/", { headers: { authorization: auth, "cf-connecting-ip": "192.0.2.2" } }), env);
    assert.equal(res.status, 200);
  }
}

{
  const env = await envFor({ public: row("public", { auth_mode: "public" }) });
  const res = await fetchHandler(new Request("https://share.example.test/public/"), env);
  assert.equal(res.status, 200);
}

{
  const env = await envFor({ expired: row("expired", { expires_at: "2020-01-01T00:00:00+00:00" }) });
  const res = await fetchHandler(new Request("https://share.example.test/expired/", { headers: { authorization: auth } }), env);
  assert.equal(res.status, 403);
  assert.match(await res.text(), /expired/);
}

{
  const env = await envFor({ s1: row("s1") }, { "deny:s1": "1", "auth:s1": JSON.stringify(await verifier("pw")) });
  const res = await fetchHandler(new Request("https://share.example.test/s1/", { headers: { authorization: auth } }), env);
  assert.equal(res.status, 403);
  assert.match(await res.text(), /revoked/);
}

{
  const env = await envFor({ s1: row("s1") }, { "auth:s1": JSON.stringify(await verifier("pw")) });
  const res = await fetchHandler(new Request("https://share.example.test/admin/list", { headers: { authorization: "Bearer admin" } }), env);
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.shares.length, 1);
}

{
  // Auth must work at the production PBKDF2 iteration count (100k — the Cloudflare
  // Workers WebCrypto cap; the CLI mints verifiers at exactly this value). A higher
  // count (e.g. 210k) throws NotSupportedError on the real runtime and 500s.
  const env = await envFor({ s1: row("s1") }, { "auth:s1": JSON.stringify(await verifier("pw", 100000)) });
  const res = await fetchHandler(new Request("https://share.example.test/s1/", { headers: { authorization: auth } }), env);
  assert.equal(res.status, 200);
}

{
  // Slug routing for the readable slug scheme. The slug is ONE path segment; the
  // rest of the path addresses files inside the artifact.
  const root = parseSlug(new URL("https://share.example.test/ted-page/"));
  assert.deepEqual(root, { slug: "ted-page", path: "index.html" });

  const nested = parseSlug(new URL("https://share.example.test/ted-page/assets/app.css"));
  assert.deepEqual(nested, { slug: "ted-page", path: "assets/app.css" });

  // The clash-suffix form (`ted-page-2`) is a single slug — the hyphen does NOT
  // split it into two segments.
  const suffixed = parseSlug(new URL("https://share.example.test/ted-page-2/"));
  assert.equal(suffixed.slug, "ted-page-2");

  // A multi-word readable slug is likewise one segment.
  const multiHyphen = parseSlug(new URL("https://share.example.test/acme-corp-report/"));
  assert.equal(multiHyphen.slug, "acme-corp-report");

  // Legacy long random slugs (pre-readable) still parse — no break for old shares.
  const legacy = parseSlug(new URL("https://share.example.test/dltl15ctqaabshu2mnyuxa/"));
  assert.equal(legacy.slug, "dltl15ctqaabshu2mnyuxa");

  // Guards: empty slug, and a path-traversal attempt in the file portion.
  assert.equal(parseSlug(new URL("https://share.example.test/")), null);
  const traversal = parseSlug(new URL("https://share.example.test/ted-page/..%2Fsecret"));
  assert.equal(traversal.path, null);
}

{
  // End-to-end: a readable slug serves through the full handler (auth + manifest
  // gate + R2 fetch), proving the slug shape is not just parseable but routable.
  const slug = "ted-page";
  const env = await envFor({ [slug]: row(slug) }, { [`auth:${slug}`]: JSON.stringify(await verifier("pw")) });
  env.ARTIFACTS.objects.set(`${slug}/index.html`, "<h1>ted</h1>");
  const res = await fetchHandler(new Request(`https://share.example.test/${slug}/`, { headers: { authorization: auth } }), env);
  assert.equal(res.status, 200);
  assert.equal(await res.text(), "<h1>ted</h1>");
}

{
  // P2: a stale R2 object absent from the current manifest must 404, never
  // serve — even though the object still exists in the bucket (e.g. left behind
  // by a republish with fewer files). The manifest files still serve normally.
  const env = await envFor({ s1: row("s1") }, { "auth:s1": JSON.stringify(await verifier("pw")) });
  env.ARTIFACTS.objects.set("s1/old.html", "<h1>stale</h1>");
  const stale = await fetchHandler(new Request("https://share.example.test/s1/old.html", { headers: { authorization: auth } }), env);
  assert.equal(stale.status, 404);
  const live = await fetchHandler(new Request("https://share.example.test/s1/", { headers: { authorization: auth } }), env);
  assert.equal(live.status, 200);
}
