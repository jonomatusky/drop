import assert from "node:assert/strict";
import { createHash, webcrypto } from "node:crypto";
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
    // Every write, in order, so a test can assert that none happened.
    this.writes = [];
  }
  async get(key, opts = {}) {
    const value = this.map.get(key);
    if (value === undefined) return null;
    return opts.type === "json" ? JSON.parse(value) : value;
  }
  async put(key, value) {
    this.writes.push(["put", key]);
    this.map.set(key, value);
  }
  async delete(key) {
    this.writes.push(["delete", key]);
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

// Like an R2ObjectBody: `size` before any read, and `arrayBuffer()` to buffer.
// `sizes` overrides the reported size, so a test can claim an object is huge
// without allocating it; `buffered` counts arrayBuffer() calls.
class R2 {
  constructor(objects = {}) {
    this.objects = new Map(Object.entries(objects));
    this.sizes = new Map();
    this.buffered = 0;
  }
  async get(key) {
    const value = this.objects.get(key);
    if (!value) return null;
    const dot = key.lastIndexOf(".");
    const stored = STORED_CONTENT_TYPES[dot >= 0 ? key.slice(dot).toLowerCase() : ""];
    const bytes = typeof value === "string" ? encoder.encode(value) : value;
    const self = this;
    return {
      body: value,
      size: this.sizes.has(key) ? this.sizes.get(key) : bytes.byteLength,
      async arrayBuffer() {
        self.buffered += 1;
        return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
      },
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
    // Each manifest upsert, applied to `rows` the way D1 would, so a later
    // request serves the new manifest and a test can assert none happened.
    this.upserts = [];
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
        if (sql.startsWith("UPDATE shares SET revoked_at")) {
          self.revoked.push(this.values[1]);
          if (self.rows[this.values[1]]) self.rows[this.values[1]].revoked_at = this.values[0];
        }
        if (sql.includes("INSERT INTO shares")) {
          const [slug, label, auth_mode, sha256, files_json, bytes, scan_result_json, created_at, expires_at, uploader] = this.values;
          self.upserts.push(slug);
          const prior = self.rows[slug];
          self.rows[slug] = {
            slug,
            label,
            auth_mode,
            sha256,
            files_json,
            bytes,
            scan_result_json,
            created_at: prior ? prior.created_at : created_at,
            expires_at,
            revoked_at: null,
            uploader,
          };
        }
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

// === Feature 3: opt-in public link preview for password shares =============
//
// A password share is gated on every path, so a chat app that unfurls the link
// gets only the login page. With --public-preview the CLI sends `preview`, the
// Worker writes `scan_result.public_preview` into the D1 manifest row, the login
// page carries og:/twitter: tags, and the share-root og.png — and nothing else —
// loads without the password.

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

const PNG_BYTES = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3]);
const PNG_SHA = sha256(PNG_BYTES);
// Another PNG: a republished card, or the artifact's own og.png under --no-card.
const OTHER_PNG = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 9, 9, 9]);
const OTHER_SHA = sha256(OTHER_PNG);
const PREVIEW = { title: "Project proposal", description: "A short summary", image_sha256: PNG_SHA };
// What upsertManifest stores for PREVIEW: every field, absent ones as null.
const STORED_PREVIEW = { ...PREVIEW, site_name: null, image_alt: null };

// A password share whose D1 row already carries `preview` as its
// scan_result.public_preview (or no record with `preview: null`).
async function previewEnv({ preview = PREVIEW, rowOverrides = {}, kvExtra = {} } = {}) {
  const files = [
    { path: "index.html", sha256: "1".repeat(64) },
    { path: "og.png", sha256: PNG_SHA },
    { path: "hero.png", sha256: "2".repeat(64) },
    { path: "sub/og.png", sha256: "3".repeat(64) },
  ];
  const scan = preview ? { visibility: "password", public_preview: preview } : { visibility: "password" };
  const env = await envFor(
    {
      s1: row("s1", {
        label: "Acme Proposal",
        files_json: JSON.stringify(files),
        scan_result_json: JSON.stringify(scan),
        ...rowOverrides,
      }),
    },
    { "auth:s1": JSON.stringify(await verifier("pw")), ...kvExtra },
  );
  env.ARTIFACTS.objects.set("s1/og.png", PNG_BYTES);
  env.ARTIFACTS.objects.set("s1/hero.png", "HERO");
  env.ARTIFACTS.objects.set("s1/sub/og.png", "SUBCARD");
  return env;
}

function storedScan(env, slug = "s1") {
  return JSON.parse(env.DB.rows[slug].scan_result_json);
}

function get(path, init = {}) {
  return new Request(`https://share.example.test${path}`, init);
}

async function isLoginPage(res) {
  const body = await res.text();
  return res.status === 200 && /text\/html/.test(res.headers.get("content-type")) && /name="password"/.test(body);
}

function hasPreviewTags(page) {
  return /og:|twitter:/.test(page);
}

function manifestRequest(payload) {
  return get("/admin/manifest", {
    method: "POST",
    headers: { authorization: "Bearer admin", "content-type": "application/json" },
    body: JSON.stringify(payload),
  });
}

async function manifestPayload(overrides = {}) {
  return {
    slug: "s1",
    label: "Acme Proposal",
    auth_mode: "password",
    sha256: "abc",
    files: [{ path: "index.html", sha256: "1".repeat(64) }, { path: "og.png", sha256: PNG_SHA }],
    bytes: 2,
    scan_result: { visibility: "password" },
    created_at: "2026-06-22T00:00:00+00:00",
    uploader: "test",
    password_verifier: await verifier("pw"),
    ...overrides,
  };
}

{
  // 1. Password share WITHOUT a preview: og.png is gated like every other path,
  //    and the login page carries no preview tags at all.
  const env = await previewEnv({ preview: null });
  const og = await fetchHandler(get("/s1/og.png"), env);
  assert.ok(await isLoginPage(og), "og.png stays behind the password without --public-preview");
  const page = await (await fetchHandler(get("/s1/"), env)).text();
  assert.doesNotMatch(page, /og:|twitter:/, "no preview tags without a preview");
  // The head is exactly what it was before this feature: robots, then title.
  assert.match(page, /<meta name="robots" content="noindex, nofollow">\n<title>Acme Proposal<\/title>/);
}

{
  // 2. Happy path: the share-root og.png loads without auth, as the exact
  //    image bytes, with the normal headers, and via HEAD.
  const env = await previewEnv();
  const res = await fetchHandler(get("/s1/og.png"), env);
  assert.equal(res.status, 200);
  assert.equal(res.headers.get("content-type"), "image/png");
  assert.equal(res.headers.get("etag"), '"test"');
  assert.equal(res.headers.get("x-robots-tag"), "noindex", "security headers still apply");
  assert.deepEqual(new Uint8Array(await res.arrayBuffer()), PNG_BYTES);
  const head = await fetchHandler(get("/s1/og.png", { method: "HEAD" }), env);
  assert.equal(head.status, 200);
  assert.equal(head.headers.get("content-type"), "image/png");
  assert.equal(head.body, null);
  // The card is not a document open.
  assert.equal(env.DB.audit.filter((e) => e.event === "view").length, 0, "the preview card is not logged as a view");
}

{
  // 3. With a preview: every OTHER path is still gated — the page, another
  //    image, a nested og.png, and the slug root with and without a slash.
  const env = await previewEnv();
  for (const path of ["/s1/", "/s1", "/s1/index.html", "/s1/hero.png", "/s1/sub/og.png"]) {
    const res = await fetchHandler(get(path), env);
    assert.ok(await isLoginPage(res), `${path} must stay behind the password`);
  }
}

{
  // The exemption needs og.png in the CURRENT manifest: a stale og.png left in
  // R2 by an older build is not served.
  const env = await previewEnv({ rowOverrides: { files_json: JSON.stringify([{ path: "index.html" }]) } });
  const res = await fetchHandler(get("/s1/og.png"), env);
  assert.ok(await isLoginPage(res), "og.png outside the manifest is not exempt");
}

{
  // The single-file root fallback never reaches the exemption: a share whose only
  // file is og.png still gates `/<slug>/`.
  const env = await previewEnv({ rowOverrides: { files_json: JSON.stringify([{ path: "og.png", sha256: PNG_SHA }]) } });
  assert.ok(await isLoginPage(await fetchHandler(get("/s1/"), env)), "/s1/ does not fall back to og.png unauthenticated");
  const direct = await fetchHandler(get("/s1/og.png"), env);
  assert.equal(direct.status, 200);
  assert.equal(env.DB.audit.filter((e) => e.event === "view").length, 0, "no view row even for a single-file share");
}

{
  // 4. With a preview: the login page (plain and error variants) carries the
  //    preview tags with absolute URLs built from the request origin.
  const env = await previewEnv();
  const plain = await (await fetchHandler(get("/s1/"), env)).text();
  const error = await (
    await fetchHandler(
      get("/s1/", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: "password=wrong" }),
      env,
    )
  ).text();
  assert.match(error, /Incorrect password/);
  for (const page of [plain, error]) {
    assert.match(page, /<meta property="og:type" content="website">/);
    assert.match(page, /<meta property="og:title" content="Project proposal">/);
    assert.match(page, /<meta property="og:description" content="A short summary">/);
    assert.match(page, /<meta property="og:url" content="https:\/\/share\.example\.test\/s1\/">/);
    assert.match(page, /<meta property="og:image" content="https:\/\/share\.example\.test\/s1\/og\.png">/);
    assert.match(page, /<meta property="og:image:width" content="1200">/);
    assert.match(page, /<meta property="og:image:height" content="630">/);
    assert.match(page, /<meta name="twitter:card" content="summary_large_image">/);
    assert.match(page, /<meta name="twitter:title" content="Project proposal">/);
    assert.match(page, /<meta name="twitter:description" content="A short summary">/);
    assert.match(page, /<meta name="twitter:image" content="https:\/\/share\.example\.test\/s1\/og\.png">/);
    // No site name or alt text in this record, so no tags for them.
    assert.doesNotMatch(page, /og:site_name|image:alt/);
    // The visible page is unchanged: the label heading, the form, no document.
    assert.match(page, /<h1>Acme Proposal<\/h1>/);
    assert.match(page, /name="password"/);
    assert.doesNotMatch(page, /<h1>ok<\/h1>/);
  }

  // The origin is the request's own, not a configured base.
  const other = await (await fetchHandler(new Request("https://other.example.test/s1/"), env)).text();
  assert.match(other, /og:image" content="https:\/\/other\.example\.test\/s1\/og\.png"/);
}

{
  // 4b. Title and description are HTML-escaped; a missing description writes no
  //     description tags.
  const env = await previewEnv({ preview: { title: `<b>"Q3" & 'plan'</b>`, description: `a<b>&"c"'`, image_sha256: PNG_SHA } });
  const page = await (await fetchHandler(get("/s1/"), env)).text();
  assert.match(page, /og:title" content="&lt;b&gt;&quot;Q3&quot; &amp; &#39;plan&#39;&lt;\/b&gt;"/);
  assert.match(page, /twitter:title" content="&lt;b&gt;&quot;Q3&quot; &amp; &#39;plan&#39;&lt;\/b&gt;"/);
  assert.match(page, /og:description" content="a&lt;b&gt;&amp;&quot;c&quot;&#39;"/);
  assert.match(page, /twitter:description" content="a&lt;b&gt;&amp;&quot;c&quot;&#39;"/);
  assert.doesNotMatch(page, /<b>"Q3"/, "no raw title in the page");

  const bare = await previewEnv({ preview: { title: "Project proposal", description: null, image_sha256: PNG_SHA } });
  const barePage = await (await fetchHandler(get("/s1/"), bare)).text();
  assert.match(barePage, /og:title" content="Project proposal"/);
  assert.doesNotMatch(barePage, /description/, "no description tags without a description");
}

{
  // 4c. Site name and alt text, published through the admin API, come out as
  //     og:site_name, og:image:alt and twitter:image:alt, HTML-escaped.
  const env = await previewEnv({ preview: null });
  const preview = { ...PREVIEW, site_name: `Acme & "Co" <x>`, image_alt: `Card: 'Q3' <plan> & more` };
  assert.equal((await fetchHandler(manifestRequest(await manifestPayload({ preview })), env)).status, 200);
  assert.deepEqual(storedScan(env).public_preview, preview);
  const page = await (await fetchHandler(get("/s1/"), env)).text();
  assert.match(page, /<meta property="og:site_name" content="Acme &amp; &quot;Co&quot; &lt;x&gt;">/);
  assert.match(page, /<meta property="og:image:alt" content="Card: &#39;Q3&#39; &lt;plan&gt; &amp; more">/);
  assert.match(page, /<meta name="twitter:image:alt" content="Card: &#39;Q3&#39; &lt;plan&gt; &amp; more">/);
  assert.doesNotMatch(page, /<x>|<plan>/, "no raw site name or alt text in the page");
}

{
  // 5. The record is set by a publish with a preview and dropped by one without.
  //    The audit row records which.
  const env = await previewEnv({ preview: null });
  const withPreview = await fetchHandler(manifestRequest(await manifestPayload({ preview: PREVIEW })), env);
  assert.equal(withPreview.status, 200);
  assert.deepEqual(storedScan(env), { visibility: "password", public_preview: STORED_PREVIEW });
  assert.equal((await fetchHandler(get("/s1/og.png"), env)).status, 200);
  assert.equal(JSON.parse(env.DB.audit.at(-1).details_json).preview, true);

  const without = await fetchHandler(manifestRequest(await manifestPayload()), env);
  assert.equal(without.status, 200);
  assert.deepEqual(storedScan(env), { visibility: "password" }, "republish without preview drops the record");
  assert.ok(await isLoginPage(await fetchHandler(get("/s1/og.png"), env)), "og.png is gated again");
  assert.equal(JSON.parse(env.DB.audit.at(-1).details_json).preview, false);

  // Missing optional fields are stored as null.
  await fetchHandler(manifestRequest(await manifestPayload({ preview: { title: "T", image_sha256: PNG_SHA } })), env);
  assert.deepEqual(storedScan(env).public_preview, {
    title: "T",
    description: null,
    site_name: null,
    image_alt: null,
    image_sha256: PNG_SHA,
  });
  // Only the known fields are stored.
  await fetchHandler(manifestRequest(await manifestPayload({ preview: { ...PREVIEW, extra: "x" } })), env);
  assert.deepEqual(Object.keys(storedScan(env).public_preview).sort(), [
    "description",
    "image_alt",
    "image_sha256",
    "site_name",
    "title",
  ]);
  // The preview never touches KV.
  assert.equal(env.AUTH_KV.writes.some(([, key]) => key.startsWith("preview:")), false, "no KV write for the preview");
}

{
  // 5b. The case a KV-held record got wrong: republish WITHOUT the flag and keep
  //     the identical card. Every hash still agrees, so only the record itself
  //     can turn the preview off, and it goes in the same D1 write. A leftover
  //     `preview:<slug>` KV key (from an older Worker) is ignored.
  const env = await previewEnv({ preview: null });
  assert.equal((await fetchHandler(manifestRequest(await manifestPayload({ preview: PREVIEW })), env)).status, 200);
  assert.equal((await fetchHandler(get("/s1/og.png"), env)).status, 200);
  assert.equal((await fetchHandler(manifestRequest(await manifestPayload()), env)).status, 200);
  env.AUTH_KV.map.set("preview:s1", JSON.stringify(PREVIEW));
  const og = await fetchHandler(get("/s1/og.png"), env);
  assert.ok(await isLoginPage(og), "same card, no flag: og.png is the login page");
  const head = await fetchHandler(get("/s1/og.png", { method: "HEAD" }), env);
  assert.match(head.headers.get("content-type"), /text\/html/, "nor via HEAD");
  assert.equal(hasPreviewTags(await (await fetchHandler(get("/s1/"), env)).text()), false, "and no og tags");
}

{
  // 5c. A client-sent scan_result.public_preview grants nothing: without a valid
  //     `preview` it is stripped, and with one the server-written record wins.
  const env = await previewEnv({ preview: null });
  const smuggled = await manifestPayload({ scan_result: { visibility: "password", public_preview: PREVIEW } });
  assert.equal((await fetchHandler(manifestRequest(smuggled), env)).status, 200);
  assert.deepEqual(storedScan(env), { visibility: "password" }, "a client-sent record is stripped");
  assert.ok(await isLoginPage(await fetchHandler(get("/s1/og.png"), env)), "a client-sent record unlocks nothing");
  assert.equal(hasPreviewTags(await (await fetchHandler(get("/s1/"), env)).text()), false);

  // `preview: null` is the same as no preview.
  const nulled = await manifestPayload({ preview: null, scan_result: { public_preview: PREVIEW } });
  assert.equal((await fetchHandler(manifestRequest(nulled), env)).status, 200);
  assert.deepEqual(storedScan(env), {});

  const both = await manifestPayload({
    preview: { title: "Server title", image_sha256: PNG_SHA },
    scan_result: { public_preview: { title: "Client title", image_sha256: PNG_SHA, site_name: "Client" } },
  });
  assert.equal((await fetchHandler(manifestRequest(both), env)).status, 200);
  assert.equal(storedScan(env).public_preview.title, "Server title");
  assert.equal(storedScan(env).public_preview.site_name, null);

  // A public share strips a client-sent record too, and serves as usual.
  const pub = await manifestPayload({
    auth_mode: "public",
    password_verifier: undefined,
    scan_result: { visibility: "public", public_preview: PREVIEW },
  });
  assert.equal((await fetchHandler(manifestRequest(pub), env)).status, 200);
  assert.deepEqual(storedScan(env), { visibility: "public" });
}

{
  // Republishing as a public share drops the record.
  const env = await previewEnv();
  const res = await fetchHandler(
    manifestRequest(await manifestPayload({ auth_mode: "public", password_verifier: undefined })),
    env,
  );
  assert.equal(res.status, 200);
  assert.equal("public_preview" in storedScan(env), false);
}

{
  // /admin/list still works and returns the stored record inside scan_result.
  const env = await previewEnv({ preview: null });
  assert.equal((await fetchHandler(manifestRequest(await manifestPayload({ preview: PREVIEW })), env)).status, 200);
  const res = await fetchHandler(get("/admin/list", { headers: { authorization: "Bearer admin" } }), env);
  assert.equal(res.status, 200);
  const s1 = (await res.json()).shares.find((share) => share.slug === "s1");
  assert.deepEqual(s1.scan_result.public_preview, STORED_PREVIEW);
}

{
  // 6. Manifest validation: each bad preview is a 400 and writes nothing at all:
  //    no D1 upsert, no KV write, no audit row.
  const card = (sha) => [{ path: "index.html", sha256: "1".repeat(64) }, { path: "og.png", sha256: sha }];
  const t = (extra) => ({ title: "T", image_sha256: PNG_SHA, ...extra });
  const cases = [
    [{ auth_mode: "public", password_verifier: undefined, preview: PREVIEW }, /only to password shares/],
    [{ preview: t({ title: "" }) }, /title/],
    [{ preview: t({ title: "   " }) }, /title/],
    [{ preview: t({ title: 42 }) }, /title/],
    [{ preview: t({ title: "x".repeat(301) }) }, /title/],
    // String.length counts UTF-16 units: 151 emoji are 302.
    [{ preview: t({ title: "\u{1F600}".repeat(151) }) }, /title/],
    [{ preview: t({ description: 7 }) }, /description/],
    [{ preview: t({ description: "x".repeat(1001) }) }, /description/],
    [{ preview: t({ site_name: 7 }) }, /site_name/],
    [{ preview: t({ site_name: ["x"] }) }, /site_name/],
    [{ preview: t({ site_name: "x".repeat(301) }) }, /site_name/],
    [{ preview: t({ site_name: "\u{1F600}".repeat(151) }) }, /site_name/],
    [{ preview: t({ image_alt: false }) }, /image_alt/],
    [{ preview: t({ image_alt: "x".repeat(301) }) }, /image_alt/],
    [{ preview: t({ image_alt: "\u{1F600}".repeat(151) }) }, /image_alt/],
    [{ preview: "Project proposal" }, /object/],
    [{ preview: PREVIEW, scan_result: "clean" }, /scan_result/],
    [{ preview: PREVIEW, scan_result: [] }, /scan_result/],
    [{ preview: PREVIEW, files: [{ path: "index.html" }] }, /og\.png/],
    [{ preview: PREVIEW, files: [{ path: "index.html" }, { path: "sub/og.png", sha256: PNG_SHA }] }, /og\.png/],
    // The card hash: present, 64 lowercase hex, and equal to the og.png row.
    [{ preview: { title: "T" } }, /image_sha256/],
    [{ preview: t({ image_sha256: null }) }, /image_sha256/],
    [{ preview: t({ image_sha256: 7 }) }, /image_sha256/],
    [{ preview: t({ image_sha256: PNG_SHA.toUpperCase() }), files: card(PNG_SHA.toUpperCase()) }, /image_sha256/],
    [{ preview: t({ image_sha256: PNG_SHA.slice(1) }), files: card(PNG_SHA.slice(1)) }, /image_sha256/],
    [{ preview: t({ image_sha256: "g".repeat(64) }), files: card("g".repeat(64)) }, /image_sha256/],
    [{ preview: t({ image_sha256: OTHER_SHA }) }, /does not match/],
    [{ preview: PREVIEW, files: [{ path: "index.html" }, { path: "og.png" }] }, /does not match/],
  ];
  for (const [overrides, message] of cases) {
    const env = await previewEnv({ preview: null });
    const before = { ...env.DB.rows.s1 };
    const res = await fetchHandler(manifestRequest(await manifestPayload(overrides)), env);
    assert.equal(res.status, 400, JSON.stringify(overrides));
    assert.match(await res.text(), message, JSON.stringify(overrides));
    assert.deepEqual(env.DB.upserts, [], "a rejected manifest makes no D1 write");
    assert.deepEqual(env.DB.rows.s1, before, "the live manifest is unchanged");
    assert.deepEqual(env.AUTH_KV.writes, [], "a rejected manifest makes no KV write");
    assert.equal(env.DB.audit.length, 0, "a rejected manifest writes no audit row");
  }
  // At the limits is fine (300 UTF-16 units, 150 emoji included).
  for (const text of ["x".repeat(300), "\u{1F600}".repeat(150)]) {
    const env = await previewEnv({ preview: null });
    const preview = { title: text, description: "y".repeat(1000), site_name: text, image_alt: text, image_sha256: PNG_SHA };
    const ok = await fetchHandler(manifestRequest(await manifestPayload({ preview })), env);
    assert.equal(ok.status, 200);
    assert.deepEqual(env.DB.upserts, ["s1"]);
    assert.deepEqual(storedScan(env).public_preview, preview);
  }
}

{
  // 7. Revoked, denied, and expired checks run before the exemption.
  const denied = await previewEnv({ kvExtra: { "deny:s1": "1" } });
  const d = await fetchHandler(get("/s1/og.png"), denied);
  assert.equal(d.status, 403);
  assert.match(await d.text(), /revoked/);

  const revoked = await previewEnv({ rowOverrides: { revoked_at: "2026-06-23T00:00:00+00:00" } });
  const r = await fetchHandler(get("/s1/og.png"), revoked);
  assert.equal(r.status, 403);
  assert.match(await r.text(), /revoked/);

  const expired = await previewEnv({ rowOverrides: { expires_at: "2020-01-01T00:00:00+00:00" } });
  const e = await fetchHandler(get("/s1/og.png"), expired);
  assert.equal(e.status, 403);
  assert.match(await e.text(), /expired/);
}

{
  // 8. A POST to og.png with no auth goes through the normal login flow; it is
  //    never answered with the image.
  const env = await previewEnv();
  const res = await fetchHandler(
    get("/s1/og.png", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: "x=1" }),
    env,
  );
  assert.ok(await isLoginPage(res), "POST to og.png is the login page, not the image");
  // And wrong Basic credentials are refused as usual.
  const basic = await fetchHandler(get("/s1/og.png", { headers: { authorization: badAuth } }), env);
  assert.equal(basic.status, 403);
}

{
  // 9. Revoke: og.png is 403 revoked afterwards. The D1 row's revoked_at alone
  //    is enough, so a deny key that has not reached this edge yet does not
  //    reopen the card.
  const env = await previewEnv();
  assert.equal((await fetchHandler(get("/s1/og.png"), env)).status, 200);
  const res = await fetchHandler(
    get("/admin/revoke", {
      method: "POST",
      headers: { authorization: "Bearer admin", "content-type": "application/json" },
      body: JSON.stringify({ slug: "s1" }),
    }),
    env,
  );
  assert.equal(res.status, 200);
  const after = await fetchHandler(get("/s1/og.png"), env);
  assert.equal(after.status, 403);
  assert.match(await after.text(), /revoked/);
  env.AUTH_KV.map.delete("deny:s1");
  const staleDeny = await fetchHandler(get("/s1/og.png"), env);
  assert.equal(staleDeny.status, 403, "revoked_at in D1 refuses the card without the deny key");
  assert.match(await staleDeny.text(), /revoked/);
  assert.equal(env.AUTH_KV.writes.some(([, key]) => key.startsWith("preview:")), false, "revoke writes no preview key");
}

{
  // No request reads a `preview:` KV key any more, and cookie- or
  // Basic-authenticated requests serve every path as usual.
  const v1 = await verifier("pw");
  const env = await previewEnv();
  env.AUTH_KV.map.set("auth:s1", JSON.stringify(v1));
  const reads = [];
  const originalGet = env.AUTH_KV.get.bind(env.AUTH_KV);
  env.AUTH_KV.get = (key, opts) => {
    reads.push(key);
    return originalGet(key, opts);
  };
  const cookie = `drop_auth=${await shareCookieToken(env, "s1", v1)}`;
  for (const path of ["/s1/", "/s1/og.png", "/s1/hero.png"]) {
    const res = await fetchHandler(get(path, { headers: { cookie } }), env);
    assert.equal(res.status, 200, path);
    const viaBasic = await fetchHandler(get(path, { headers: { authorization: auth } }), env);
    assert.equal(viaBasic.status, 200, path);
    await fetchHandler(get(path), env);
  }
  assert.equal(reads.some((key) => key.startsWith("preview:")), false, "no request reads a preview KV key");
  // A logged-in viewer still gets the real og.png.
  const og = await fetchHandler(get("/s1/og.png", { headers: { cookie } }), env);
  assert.deepEqual(new Uint8Array(await og.arrayBuffer()), PNG_BYTES);
}

{
  // Public shares are unchanged by a (stray) record: everything serves.
  const env = await envFor({
    public: row("public", { auth_mode: "public", scan_result_json: JSON.stringify({ public_preview: PREVIEW }) }),
  });
  const res = await fetchHandler(get("/public/"), env);
  assert.equal(res.status, 200);
  assert.equal(await res.text(), "<h1>ok</h1>");
}

// --- the preview is bound to exact card bytes --------------------------------
//
// The CLI uploads to R2 before it posts the manifest, so the R2 object can run
// ahead of the D1 manifest. And the record must name the card its own manifest
// lists. These cases fail on a path-only exemption.

{
  // A record whose image_sha256 does not match the manifest's og.png row (here
  // the row names another card) counts as no preview: the og.png does not load,
  // and the login page carries no preview tags.
  const env = await previewEnv({
    rowOverrides: { files_json: JSON.stringify([{ path: "index.html", sha256: "1".repeat(64) }, { path: "og.png", sha256: OTHER_SHA }]) },
  });
  env.ARTIFACTS.objects.set("s1/og.png", OTHER_PNG);
  const og = await fetchHandler(get("/s1/og.png"), env);
  assert.ok(await isLoginPage(og), "a mismatched record does not unlock the manifest's og.png");
  const page = await (await fetchHandler(get("/s1/"), env)).text();
  assert.equal(hasPreviewTags(page), false, "a mismatched record does not decorate the login page");
  const head = await fetchHandler(get("/s1/og.png", { method: "HEAD" }), env);
  assert.notEqual(head.headers.get("content-type"), "image/png", "nor via HEAD");
}

{
  // A record where the manifest has no og.png at all.
  const env = await previewEnv({ rowOverrides: { files_json: JSON.stringify([{ path: "index.html", sha256: "1".repeat(64) }]) } });
  assert.ok(await isLoginPage(await fetchHandler(get("/s1/og.png"), env)));
  assert.equal(hasPreviewTags(await (await fetchHandler(get("/s1/"), env)).text()), false);
}

{
  // A record with no image_sha256, a malformed record, or a manifest row with
  // no sha256 counts as no preview.
  for (const preview of [{ title: "Project proposal", description: null }, "Project proposal", { image_sha256: PNG_SHA }]) {
    const env = await previewEnv({ preview });
    assert.ok(await isLoginPage(await fetchHandler(get("/s1/og.png"), env)), JSON.stringify(preview));
    assert.equal(hasPreviewTags(await (await fetchHandler(get("/s1/"), env)).text()), false);
  }
  const noRowSha = await previewEnv({ rowOverrides: { files_json: JSON.stringify([{ path: "index.html" }, { path: "og.png" }]) } });
  assert.ok(await isLoginPage(await fetchHandler(get("/s1/og.png"), noRowSha)));
  assert.equal(hasPreviewTags(await (await fetchHandler(get("/s1/"), noRowSha)).text()), false);
  // A scan_result that is not an object reads as no preview, without throwing.
  for (const scan of ["null", '"clean"', "[]"]) {
    const env = await previewEnv({ rowOverrides: { scan_result_json: scan } });
    assert.ok(await isLoginPage(await fetchHandler(get("/s1/og.png"), env)), scan);
  }
}

{
  // R2 overwrite: the manifest and its record agree, but the CLI has already
  // uploaded new og.png bytes (a republish whose manifest has not landed, or
  // failed). Those bytes must not load without the password.
  const env = await previewEnv();
  env.ARTIFACTS.objects.set("s1/og.png", OTHER_PNG);
  const og = await fetchHandler(get("/s1/og.png"), env);
  assert.ok(await isLoginPage(og), "R2 bytes that differ from the approved card get the login page");
  const head = await fetchHandler(get("/s1/og.png", { method: "HEAD" }), env);
  assert.equal(head.status, 200);
  assert.match(head.headers.get("content-type"), /text\/html/, "HEAD gets the login page too");
  // The login page itself still carries the tags: the manifest and record agree.
  assert.equal(hasPreviewTags(await (await fetchHandler(get("/s1/"), env)).text()), true);
  // A missing object is the login page as well, not a 404 that says otherwise.
  env.ARTIFACTS.objects.delete("s1/og.png");
  assert.ok(await isLoginPage(await fetchHandler(get("/s1/og.png"), env)));
  // A logged-in viewer is not affected by the check: they get whatever is there.
  env.ARTIFACTS.objects.set("s1/og.png", OTHER_PNG);
  const viaBasic = await fetchHandler(get("/s1/og.png", { headers: { authorization: auth } }), env);
  assert.deepEqual(new Uint8Array(await viaBasic.arrayBuffer()), OTHER_PNG);
}

{
  // Size cap: an object over 2 MB is refused before it is buffered, even when
  // its reported hash would match.
  const env = await previewEnv();
  env.ARTIFACTS.sizes.set("s1/og.png", 2 * 1024 * 1024 + 1);
  assert.ok(await isLoginPage(await fetchHandler(get("/s1/og.png"), env)), "an oversized card gets the login page");
  assert.equal(env.ARTIFACTS.buffered, 0, "an oversized card is never buffered");

  // A real over-cap object whose hash the manifest and record both carry.
  const big = new Uint8Array(2 * 1024 * 1024 + 1);
  const bigSha = sha256(big);
  const bigEnv = await previewEnv({
    preview: { ...PREVIEW, image_sha256: bigSha },
    rowOverrides: { files_json: JSON.stringify([{ path: "index.html" }, { path: "og.png", sha256: bigSha }]) },
  });
  bigEnv.ARTIFACTS.objects.set("s1/og.png", big);
  assert.ok(await isLoginPage(await fetchHandler(get("/s1/og.png"), bigEnv)));
  assert.equal(bigEnv.ARTIFACTS.buffered, 0);

  // At the cap is fine.
  const edge = new Uint8Array(2 * 1024 * 1024);
  const edgeSha = sha256(edge);
  const edgeEnv = await previewEnv({
    preview: { ...PREVIEW, image_sha256: edgeSha },
    rowOverrides: { files_json: JSON.stringify([{ path: "index.html" }, { path: "og.png", sha256: edgeSha }]) },
  });
  edgeEnv.ARTIFACTS.objects.set("s1/og.png", edge);
  const ok = await fetchHandler(get("/s1/og.png"), edgeEnv);
  assert.equal(ok.status, 200);
  assert.equal((await ok.arrayBuffer()).byteLength, edge.byteLength);
}

{
  // A size the object does not report is refused rather than buffered blind.
  const env = await previewEnv();
  env.ARTIFACTS.sizes.set("s1/og.png", undefined);
  assert.ok(await isLoginPage(await fetchHandler(get("/s1/og.png"), env)));
  assert.equal(env.ARTIFACTS.buffered, 0);
}
