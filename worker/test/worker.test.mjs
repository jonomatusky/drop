import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { constantTimeEqual, fetchHandler, parseSlug, shareCookieToken } from "../src/worker.mjs";

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
    this.audit = [];
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
        if (sql.includes("COUNT(*)") && sql.includes("audit_events")) {
          const slug = this.values[0];
          return { count: self.audit.filter((e) => e.slug === slug && e.event === "view").length };
        }
        const slug = this.values[0];
        return self.rows[slug] || null;
      },
      async all() {
        if (sql.includes("audit_events") && sql.includes("GROUP BY slug")) {
          const counts = {};
          for (const e of self.audit) if (e.event === "view") counts[e.slug] = (counts[e.slug] || 0) + 1;
          return { results: Object.entries(counts).map(([slug, views]) => ({ slug, views })) };
        }
        if (sql.includes("audit_events") && sql.includes("ORDER BY")) {
          const slug = this.values[0];
          const limit = this.values[1];
          const results = self.audit
            .filter((e) => e.slug === slug && e.event === "view")
            .sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)))
            .slice(0, limit)
            .map((e) => ({ created_at: e.created_at, details_json: e.details_json }));
          return { results };
        }
        return { results: Object.values(self.rows) };
      },
      async run() {
        if (sql.startsWith("UPDATE shares SET revoked_at")) self.revoked.push(this.values[1]);
        if (sql.includes("INSERT INTO audit_events")) {
          self.audit.push({
            slug: this.values[0],
            event: this.values[1],
            actor: this.values[2],
            details_json: this.values[3],
            created_at: this.values[4],
          });
        }
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

// === Feature 1: password-tier HTML login page (replaces HTTP Basic dialog) ===

{
  // Unauthenticated browser GET → the clean HTML login page, NOT the document,
  // NOT a Basic-Auth challenge. noindex, single password field.
  const env = await envFor({ s1: row("s1", { label: "Acme Proposal" }) }, { "auth:s1": JSON.stringify(await verifier("pw")) });
  const res = await fetchHandler(new Request("https://share.example.test/s1/"), env);
  assert.equal(res.status, 200);
  const body = await res.text();
  assert.match(body, /<form[^>]*method="POST"/i, "login page renders a POST form");
  assert.match(body, /name="password"/, "login page has a password field");
  assert.match(body, /Acme Proposal/, "login page shows the share label");
  assert.doesNotMatch(body, /<h1>ok<\/h1>/, "login page must not leak the document");
  assert.equal(res.headers.get("x-robots-tag"), "noindex");
  assert.equal(res.headers.get("www-authenticate"), null, "no Basic-Auth dialog challenge");
}

{
  // Correct password via the login form → 303 redirect with a hardened cookie,
  // and that cookie then grants access to the document (POST→redirect→GET).
  const env = await envFor({ s1: row("s1") }, { "auth:s1": JSON.stringify(await verifier("pw")) });
  const res = await fetchHandler(
    new Request("https://share.example.test/s1/", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: "password=pw",
    }),
    env,
  );
  assert.equal(res.status, 303);
  const setCookie = res.headers.get("set-cookie");
  assert.match(setCookie, /drop_auth=/);
  assert.match(setCookie, /HttpOnly/);
  assert.match(setCookie, /Secure/);
  assert.match(setCookie, /SameSite=Lax/);
  // Path is /s1 (no trailing slash) so the cookie is sent for both /s1 and
  // /s1/… — see cookieHeader's note on the slash-less login loop.
  assert.match(setCookie, /Path=\/s1(;|$)/);
  const token = setCookie.match(/drop_auth=([^;]+)/)[1];
  const withCookie = await fetchHandler(
    new Request("https://share.example.test/s1/", { headers: { cookie: `drop_auth=${token}` } }),
    env,
  );
  assert.equal(withCookie.status, 200);
  assert.equal(await withCookie.text(), "<h1>ok</h1>");
}

{
  // Regression: logging in from the slash-less URL (/s1, no trailing slash) must
  // not loop. The cookie's Path=/s1 is sent back to /s1, so the post-login GET
  // authenticates and serves instead of re-prompting.
  const env = await envFor({ s1: row("s1") }, { "auth:s1": JSON.stringify(await verifier("pw")) });
  const post = await fetchHandler(
    new Request("https://share.example.test/s1", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: "password=pw",
    }),
    env,
  );
  assert.equal(post.status, 303);
  const token = post.headers.get("set-cookie").match(/drop_auth=([^;]+)/)[1];
  const followup = await fetchHandler(
    new Request("https://share.example.test/s1", { headers: { cookie: `drop_auth=${token}` } }),
    env,
  );
  assert.equal(followup.status, 200, "slash-less login must not loop");
  assert.equal(await followup.text(), "<h1>ok</h1>");
}

{
  // Wrong password via the form → re-render the login page with an error (200,
  // not the document), and the failure is rate-limited like Basic failures.
  const env = await envFor({ s1: row("s1") }, { "auth:s1": JSON.stringify(await verifier("pw")) });
  env.RATE_LIMIT_MAX = "1";
  env.RATE_LIMIT_WINDOW_SECONDS = "60";
  const post = (ip) => fetchHandler(
    new Request("https://share.example.test/s1/", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", "cf-connecting-ip": ip },
      body: "password=wrong",
    }),
    env,
  );
  const first = await post("198.51.100.7");
  assert.equal(first.status, 200);
  const body = await first.text();
  assert.match(body, /Incorrect password/i, "wrong password re-renders with an error");
  assert.match(body, /name="password"/);
  const second = await post("198.51.100.7");
  assert.equal(second.status, 429, "repeated wrong-password attempts are throttled");
}

{
  // A valid cookie minted for THIS slug grants access; a forged cookie and a
  // foreign-slug cookie are both rejected (fall through to the login page).
  const v1 = await verifier("pw");
  const env = await envFor({ s1: row("s1"), s2: row("s2") }, {
    "auth:s1": JSON.stringify(v1),
    "auth:s2": JSON.stringify(await verifier("other")),
  });
  env.ARTIFACTS.objects.set("s2/index.html", "<h1>two</h1>");

  const goodToken = await shareCookieToken(env, "s1", v1);
  const good = await fetchHandler(
    new Request("https://share.example.test/s1/", { headers: { cookie: `drop_auth=${goodToken}` } }),
    env,
  );
  assert.equal(good.status, 200);
  assert.equal(await good.text(), "<h1>ok</h1>");

  const forged = await fetchHandler(
    new Request("https://share.example.test/s1/", { headers: { cookie: "drop_auth=not-a-real-token" } }),
    env,
  );
  assert.equal(forged.status, 200);
  assert.match(await forged.text(), /name="password"/, "forged cookie must not grant access");

  // s1's cookie replayed against s2 must not authenticate s2.
  const foreign = await fetchHandler(
    new Request("https://share.example.test/s2/", { headers: { cookie: `drop_auth=${goodToken}` } }),
    env,
  );
  assert.equal(foreign.status, 200);
  assert.match(await foreign.text(), /name="password"/, "foreign-slug cookie must not grant access");
}

{
  // --public / --unlisted (both auth_mode="public") bypass the login entirely —
  // no login page, no cookie, the document is served directly with no auth.
  const env = await envFor({ public: row("public", { auth_mode: "public" }) });
  const res = await fetchHandler(new Request("https://share.example.test/public/"), env);
  assert.equal(res.status, 200);
  assert.equal(await res.text(), "<h1>ok</h1>", "public shares serve without the login page");
}

{
  // `curl -u x:pw` (Basic, username ignored) still works alongside the HTML page.
  const env = await envFor({ s1: row("s1") }, { "auth:s1": JSON.stringify(await verifier("pw")) });
  const good = await fetchHandler(
    new Request("https://share.example.test/s1/", { headers: { authorization: `Basic ${Buffer.from("ignored:pw").toString("base64")}` } }),
    env,
  );
  assert.equal(good.status, 200);
  assert.equal(await good.text(), "<h1>ok</h1>");
}

// === Feature 2: view tracking (one view per page open, never per asset) ======

async function viewEnv() {
  const env = await envFor(
    { s1: row("s1", { files_json: JSON.stringify([{ path: "index.html" }, { path: "assets/app.css" }, { path: "assets/logo.png" }]) }) },
    { "auth:s1": JSON.stringify(await verifier("pw")) },
  );
  env.ARTIFACTS.objects.set("s1/index.html", "<h1>ok</h1>");
  env.ARTIFACTS.objects.set("s1/assets/app.css", "body{}");
  env.ARTIFACTS.objects.set("s1/assets/logo.png", "PNG");
  return env;
}

{
  // A single page open (document + its many sub-assets) logs exactly ONE view,
  // captured with IP + truncated UA. The CSS/PNG assets do not add rows.
  const env = await viewEnv();
  const headers = { authorization: auth, "cf-connecting-ip": "203.0.113.10", "user-agent": "Mozilla/5.0 test" };
  await fetchHandler(new Request("https://share.example.test/s1/", { headers }), env);
  await fetchHandler(new Request("https://share.example.test/s1/assets/app.css", { headers }), env);
  await fetchHandler(new Request("https://share.example.test/s1/assets/logo.png", { headers }), env);
  const views = env.DB.audit.filter((e) => e.event === "view");
  assert.equal(views.length, 1, "one page open = one view, not one per asset");
  const details = JSON.parse(views[0].details_json);
  assert.equal(details.ip, "203.0.113.10");
  assert.equal(details.ua, "Mozilla/5.0 test");
}

{
  // Refreshes from the same IP within the dedupe window collapse to one row; a
  // different IP is a distinct view.
  const env = await viewEnv();
  for (let i = 0; i < 3; i += 1) {
    await fetchHandler(new Request("https://share.example.test/s1/", { headers: { authorization: auth, "cf-connecting-ip": "203.0.113.20" } }), env);
  }
  await fetchHandler(new Request("https://share.example.test/s1/", { headers: { authorization: auth, "cf-connecting-ip": "203.0.113.21" } }), env);
  const views = env.DB.audit.filter((e) => e.event === "view");
  assert.equal(views.length, 2, "same-IP refreshes dedupe; a new IP is a new view");
}

{
  // HEAD prefetch must not count as a view.
  const env = await viewEnv();
  await fetchHandler(new Request("https://share.example.test/s1/", { method: "HEAD", headers: { authorization: auth, "cf-connecting-ip": "203.0.113.30" } }), env);
  assert.equal(env.DB.audit.filter((e) => e.event === "view").length, 0, "HEAD is not a view");
}

{
  // In production Cloudflare passes a ctx; view tracking is scheduled via
  // ctx.waitUntil so it stays off the serving hot path. Prove that path still
  // records the view (and doesn't block the response) by collecting the deferred
  // promise and awaiting it after the document is served.
  const env = await viewEnv();
  const deferred = [];
  const ctx = { waitUntil: (p) => deferred.push(p) };
  const res = await fetchHandler(
    new Request("https://share.example.test/s1/", { headers: { authorization: auth, "cf-connecting-ip": "203.0.113.50", "user-agent": "ctx test" } }),
    env,
    ctx,
  );
  assert.equal(res.status, 200);
  assert.equal(await res.text(), "<h1>ok</h1>");
  assert.equal(deferred.length, 1, "view tracking is deferred via ctx.waitUntil, not awaited inline");
  await Promise.all(deferred);
  const views = env.DB.audit.filter((e) => e.event === "view");
  assert.equal(views.length, 1, "the deferred tracking records exactly one view");
  assert.equal(JSON.parse(views[0].details_json).ip, "203.0.113.50");
}

{
  // View count is surfaced by the CLI's data source: /admin/list carries a per-
  // share `views` count, and /admin/views returns the count + recent rows.
  const env = await viewEnv();
  const headers = { authorization: auth, "cf-connecting-ip": "203.0.113.40", "user-agent": "curl/8.0" };
  await fetchHandler(new Request("https://share.example.test/s1/", { headers }), env);

  const list = await (await fetchHandler(new Request("https://share.example.test/admin/list", { headers: { authorization: "Bearer admin" } }), env)).json();
  const s1 = list.shares.find((s) => s.slug === "s1");
  assert.equal(s1.views, 1, "/admin/list surfaces a per-share view count");

  const viewsRes = await fetchHandler(new Request("https://share.example.test/admin/views?slug=s1", { headers: { authorization: "Bearer admin" } }), env);
  assert.equal(viewsRes.status, 200);
  const viewsBody = await viewsRes.json();
  assert.equal(viewsBody.count, 1);
  assert.equal(viewsBody.views[0].ip, "203.0.113.40");
  assert.equal(viewsBody.views[0].ua, "curl/8.0");

  // /admin/views requires admin auth and a slug.
  const noAuth = await fetchHandler(new Request("https://share.example.test/admin/views?slug=s1"), env);
  assert.equal(noAuth.status, 403);
  const noSlug = await fetchHandler(new Request("https://share.example.test/admin/views", { headers: { authorization: "Bearer admin" } }), env);
  assert.equal(noSlug.status, 400);
}
