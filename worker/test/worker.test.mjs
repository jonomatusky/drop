import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { constantTimeEqual, contentTypeFor, fetchHandler, parseSlug, shareCookieToken } from "../src/worker.mjs";

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
    this.puts = [];
    this.deletes = [];
  }
  async get(key, opts = {}) {
    const value = this.map.get(key);
    if (value === undefined) return null;
    return opts.type === "json" ? JSON.parse(value) : value;
  }
  async put(key, value, options) {
    this.puts.push({ key, value, options });
    this.map.set(key, value);
  }
  async delete(key) {
    this.deletes.push(key);
    this.map.delete(key);
  }
}

// Mirrors what the CLI actually stored in R2 for years: Python's mimetypes guess,
// which is a BARE type with no charset (`text/html`, not `text/html; charset=utf-8`).
// The old mock hardcoded a charset on every object, which is why the missing-charset
// bug never showed up here. Anything the guess does not cover has no stored type
// at all, the other case the serving path has to handle.
const STORED_CONTENT_TYPES = {
  ".html": "text/html",
  ".htm": "text/html",
  ".css": "text/css",
  ".js": "text/javascript",
  ".json": "application/json",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".pdf": "application/pdf",
};

class R2 {
  constructor(objects = {}) {
    this.objects = new Map(Object.entries(objects));
  }
  async get(key) {
    const value = this.objects.get(key);
    if (!value) return null;
    const dot = key.lastIndexOf(".");
    const stored = STORED_CONTENT_TYPES[dot >= 0 ? key.slice(dot).toLowerCase() : ""];
    return {
      body: value,
      httpMetadata: stored ? { contentType: stored } : {},
      httpEtag: '"test"',
    };
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

function manifestPayload(overrides = {}) {
  return {
    slug: "s1",
    auth_mode: "password",
    sha256: "updated-sha",
    files: [{ path: "index.html", bytes: 2, sha256: "updated-sha" }],
    bytes: 2,
    scan_result: { clean: true },
    created_at: "2026-10-23T00:00:00+00:00",
    uploader: "test-publisher",
    ...overrides,
  };
}

function manifestRequest(payload) {
  return new Request("https://share.example.test/admin/manifest", {
    method: "POST",
    headers: { authorization: "Bearer admin", "content-type": "application/json" },
    body: JSON.stringify(payload),
  });
}

const auth = `Basic ${Buffer.from("user:pw").toString("base64")}`;
const badAuth = `Basic ${Buffer.from("user:wrong").toString("base64")}`;

// === Manifest republish: retain an existing password verifier ===

{
  const oldVerifier = await verifier("pw");
  const serializedVerifier = JSON.stringify(oldVerifier);
  const env = await envFor(
    { s1: row("s1") },
    { "auth:s1": serializedVerifier, "deny:s1": "1" },
  );
  const oldCookie = await shareCookieToken(env, "s1", oldVerifier);

  const res = await fetchHandler(manifestRequest(manifestPayload({ keep_password_verifier: true })), env);
  assert.equal(res.status, 200);
  assert.equal(env.AUTH_KV.map.get("auth:s1"), serializedVerifier, "the existing verifier remains byte-for-byte unchanged");
  assert.equal(
    env.AUTH_KV.puts.filter(({ key }) => key === "auth:s1").length,
    0,
    "the keep path must not rewrite the verifier",
  );
  assert.equal(env.AUTH_KV.map.has("deny:s1"), false, "successful republish still clears the deny marker");

  const publish = env.DB.audit.find((event) => event.event === "publish");
  assert.ok(publish, "successful republish still writes the publish audit event");
  assert.deepEqual(JSON.parse(publish.details_json), {
    auth_mode: "password",
    bytes: 2,
    files: ["index.html"],
    scan_result: { clean: true },
    override_log: [],
    kept_password_verifier: true,
  }, "the existing audit details are preserved and the keep path is marked");

  const followup = await fetchHandler(
    new Request("https://share.example.test/s1/", { headers: { cookie: `drop_auth=${oldCookie}` } }),
    env,
  );
  assert.equal(followup.status, 200);
  assert.equal(await followup.text(), "<h1>ok</h1>", "a cookie bound to the retained verifier remains valid");
}

{
  const existingVerifier = JSON.stringify(await verifier("pw"));
  const refusalCases = [
    {
      name: "existing public share",
      rows: { s1: row("s1", { auth_mode: "public" }) },
      kv: { "auth:s1": existingVerifier, "deny:s1": "1" },
    },
    {
      name: "missing D1 row",
      rows: {},
      kv: { "auth:s1": existingVerifier, "deny:s1": "1" },
    },
    {
      name: "missing KV verifier",
      rows: { s1: row("s1") },
      kv: { "deny:s1": "1" },
    },
  ];

  for (const testCase of refusalCases) {
    const env = await envFor(testCase.rows, testCase.kv);
    const res = await fetchHandler(manifestRequest(manifestPayload({ keep_password_verifier: true })), env);
    assert.equal(res.status, 400, testCase.name);
    assert.equal(await res.text(), "no existing password to keep\n", testCase.name);
    assert.equal(env.AUTH_KV.map.get("deny:s1"), "1", `${testCase.name}: refusal leaves deny state unchanged`);
    assert.equal(env.DB.audit.length, 0, `${testCase.name}: refusal writes no audit event`);
  }
}

{
  const env = await envFor({ s1: row("s1") }, { "deny:s1": "1" });
  const res = await fetchHandler(manifestRequest(manifestPayload()), env);
  assert.equal(res.status, 400);
  assert.equal(await res.text(), "missing password_verifier\n", "the existing missing-verifier error is unchanged without the keep flag");
  assert.equal(env.AUTH_KV.map.get("deny:s1"), "1");
  assert.equal(env.DB.audit.length, 0);
}

{
  const newVerifier = await verifier("new-password");
  const env = await envFor(
    { s1: row("s1", { auth_mode: "public" }) },
    { "auth:s1": JSON.stringify(await verifier("old-password")), "deny:s1": "1" },
  );
  const res = await fetchHandler(manifestRequest(manifestPayload({
    keep_password_verifier: true,
    password_verifier: newVerifier,
  })), env);
  assert.equal(res.status, 200, "a supplied verifier takes precedence over the keep flag");
  assert.equal(env.AUTH_KV.map.get("auth:s1"), JSON.stringify(newVerifier));
  assert.equal(env.AUTH_KV.puts.filter(({ key }) => key === "auth:s1").length, 1);
  assert.equal(env.AUTH_KV.map.has("deny:s1"), false);
  const details = JSON.parse(env.DB.audit.find((event) => event.event === "publish").details_json);
  assert.equal(Object.hasOwn(details, "kept_password_verifier"), false, "audit marks only the actual keep path");
}

{
  const env = await envFor(
    { s1: row("s1", { auth_mode: "public" }) },
    { "auth:s1": JSON.stringify(await verifier("old-password")), "deny:s1": "1" },
  );
  const res = await fetchHandler(manifestRequest(manifestPayload({
    auth_mode: "public",
    keep_password_verifier: true,
  })), env);
  assert.equal(res.status, 200, "public publishing behavior is unchanged when the irrelevant flag is present");
  assert.equal(env.AUTH_KV.map.has("auth:s1"), false);
  assert.equal(env.AUTH_KV.map.has("deny:s1"), false);
  const details = JSON.parse(env.DB.audit.find((event) => event.event === "publish").details_json);
  assert.equal(Object.hasOwn(details, "kept_password_verifier"), false);
}

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

// === Encoding: every text response must name its charset ====================
//
// The bug: R2 stores the content type the CLI guessed (a bare `text/html`), and
// that stored value used to win over the extension table. So drop served
// `content-type: text/html` with no charset, browsers fell back to a locale
// default, and UTF-8 curly quotes/em dashes rendered as mojibake ("â€œ") on any
// page that had no <meta charset> of its own.

{
  // Unit: the served type, for each way a type can arrive.
  const stored = (contentType) => ({ httpMetadata: { contentType } });

  // Known extension wins outright, charset-less R2 metadata notwithstanding.
  assert.equal(contentTypeFor("index.html", stored("text/html")), "text/html; charset=utf-8");
  assert.equal(contentTypeFor("style.css", stored("text/css")), "text/css; charset=utf-8");
  assert.equal(contentTypeFor("app.js", stored("text/javascript")), "application/javascript; charset=utf-8");
  assert.equal(contentTypeFor("data.json", stored("application/json")), "application/json; charset=utf-8");
  assert.equal(contentTypeFor("notes.md", stored("text/markdown")), "text/markdown; charset=utf-8");
  assert.equal(contentTypeFor("rows.csv", stored("text/csv")), "text/csv; charset=utf-8");

  // Unknown extension: fall back to R2's type, and repair it if it is textual.
  assert.equal(contentTypeFor("feed.atom", stored("application/atom+xml")), "application/atom+xml; charset=utf-8");
  assert.equal(contentTypeFor("notes.rst", stored("text/x-rst")), "text/x-rst; charset=utf-8");
  assert.equal(contentTypeFor("f.woff2", stored("font/woff2")), "font/woff2");
  assert.equal(contentTypeFor("clip.mp4", stored("video/mp4")), "video/mp4");

  // A charset already present is respected, never doubled — including a
  // deliberate non-UTF-8 one.
  assert.equal(contentTypeFor("legacy.unknownext", stored("text/html; charset=iso-8859-1")), "text/html; charset=iso-8859-1");
  assert.equal(contentTypeFor("x.unknownext", stored("text/plain;charset=utf-8")), "text/plain;charset=utf-8");

  // Binary types must NOT be given a charset — that would be meaningless at best.
  assert.equal(contentTypeFor("og.png", stored("image/png")), "image/png");
  assert.equal(contentTypeFor("deck.pdf", stored("application/pdf")), "application/pdf");
  // SVG is markup and does carry text, so it does get one.
  assert.equal(contentTypeFor("logo.svg", stored("image/svg+xml")), "image/svg+xml; charset=utf-8");

  // No stored metadata at all, and no known extension: the safe binary default.
  assert.equal(contentTypeFor("blob.unknownext", {}), "application/octet-stream");
  assert.equal(contentTypeFor("blob.unknownext", null), "application/octet-stream");
  // No stored metadata but a known extension: the table still answers.
  assert.equal(contentTypeFor("index.html", {}), "text/html; charset=utf-8");
}

{
  // End-to-end: the served document declares UTF-8, and the UTF-8 bytes survive
  // the round trip. This is the exact repro — a page with NO <meta charset>.
  const env = await envFor({ public: row("public", { auth_mode: "public" }) });
  const body = "<html><body>“curly” — em dash</body></html>";
  env.ARTIFACTS.objects.set("public/index.html", body);
  const res = await fetchHandler(new Request("https://share.example.test/public/"), env);
  assert.equal(res.status, 200);
  assert.equal(
    res.headers.get("content-type"),
    "text/html; charset=utf-8",
    "HTML must be served with an explicit charset — without it browsers guess a locale default and mojibake UTF-8",
  );
  assert.equal(await res.text(), body, "UTF-8 punctuation survives the round trip");
}

{
  // The fix is computed at serve time, so it repairs shares ALREADY in the
  // bucket — objects whose stored metadata is the old charset-less guess. No
  // republish is needed to un-break an existing drop.
  const env = await envFor({ public: row("public", { auth_mode: "public" }) });
  const object = await env.ARTIFACTS.get("public/index.html");
  assert.equal(object.httpMetadata.contentType, "text/html", "the stored metadata is still the old, broken value");
  const res = await fetchHandler(new Request("https://share.example.test/public/"), env);
  assert.match(res.headers.get("content-type"), /charset=utf-8/i, "an existing object is repaired on the way out");
}

{
  // Sub-assets have the same problem: a CSS or JS file with UTF-8 content served
  // without a charset is decoded wrong too, and no meta tag can rescue those.
  const env = await envFor({
    public: row("public", {
      auth_mode: "public",
      files_json: JSON.stringify([{ path: "index.html" }, { path: "app.css" }, { path: "app.js" }, { path: "logo.png" }]),
    }),
  });
  env.ARTIFACTS.objects.set("public/app.css", 'body::after{content:"—"}');
  env.ARTIFACTS.objects.set("public/app.js", 'const dash = "—";');
  env.ARTIFACTS.objects.set("public/logo.png", "PNG");
  const typeOf = async (path) =>
    (await fetchHandler(new Request(`https://share.example.test/public/${path}`), env)).headers.get("content-type");
  assert.equal(await typeOf("app.css"), "text/css; charset=utf-8");
  assert.equal(await typeOf("app.js"), "application/javascript; charset=utf-8");
  assert.equal(await typeOf("logo.png"), "image/png", "images must not be handed a charset");
}

{
  // HEAD returns the same headers as GET, charset included — a client that
  // preflights must not see a different content type than the body it then gets.
  const env = await envFor({ public: row("public", { auth_mode: "public" }) });
  const head = await fetchHandler(new Request("https://share.example.test/public/", { method: "HEAD" }), env);
  assert.equal(head.headers.get("content-type"), "text/html; charset=utf-8");
}

{
  // The login page is generated by the Worker, not read from R2 — it already
  // declares UTF-8 and must keep doing so (its heading echoes the share label,
  // which can be any Unicode the publisher chose).
  const env = await envFor({ s1: row("s1", { label: "Café — Proposal" }) }, { "auth:s1": JSON.stringify(await verifier("pw")) });
  const res = await fetchHandler(new Request("https://share.example.test/s1/"), env);
  assert.equal(res.headers.get("content-type"), "text/html; charset=utf-8");
  assert.match(await res.text(), /Café — Proposal/, "a Unicode label renders intact on the login page");
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
  // The login page must fit a phone. iOS Safari zooms into inputs under 16px on
  // focus and leaves the page scrolling sideways; 100vh overshoots the visible
  // area under Safari's toolbars; an unbroken label can push the card wide.
  const env = await envFor({ s1: row("s1") }, { "auth:s1": JSON.stringify(await verifier("pw")) });
  const body = await (await fetchHandler(new Request("https://share.example.test/s1/"), env)).text();
  assert.match(body, /<meta name="viewport" content="width=device-width,\s*initial-scale=1"/);
  assert.match(body, /@media\s*\(pointer:\s*coarse\)\s*\{[^}]*input[^{}]*\{[^}]*font-size:\s*16px/, "touch inputs are 16px so iOS does not zoom");
  assert.match(body, /min-height:\s*100dvh/, "page height tracks the visible viewport");
  assert.match(body, /h1\s*\{[^}]*overflow-wrap:\s*anywhere/, "a long unbroken label wraps instead of overflowing");
  assert.match(body, /@media[^{]*max-width:\s*480px[^{]*max-height:\s*500px[^{]*\{\s*body\s*\{[^}]*align-items:\s*flex-start/, "phones top-align the card, clear of the keyboard");
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
