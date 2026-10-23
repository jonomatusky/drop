const TEXT_ENCODER = new TextEncoder();

const MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".htm": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".mjs": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".map": "application/json; charset=utf-8",
  ".txt": "text/plain; charset=utf-8",
  ".md": "text/markdown; charset=utf-8",
  ".csv": "text/csv; charset=utf-8",
  ".xml": "application/xml; charset=utf-8",
  ".yaml": "text/plain; charset=utf-8",
  ".yml": "text/plain; charset=utf-8",
  ".log": "text/plain; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".gif": "image/gif",
  ".webp": "image/webp",
  ".pdf": "application/pdf",
};

// Formats a browser decodes as text, and will therefore misdecode if we do not
// say which encoding it is in.
const TEXTUAL_TYPE_RE = /^text\/|^application\/(javascript|ecmascript|json|xml)\b|\+xml\b|\+json\b/i;

function withCharset(contentType) {
  if (!contentType || /;\s*charset=/i.test(contentType)) return contentType;
  return TEXTUAL_TYPE_RE.test(contentType) ? `${contentType}; charset=utf-8` : contentType;
}

// The content type we SERVE, which is not the one the uploader stored.
//
// R2 keeps whatever content type the upload set, and the CLI derives that from
// Python's mimetypes, which returns a bare `text/html` with no charset. That
// stored value used to win outright over the table above, so every HTML page
// drop served went out as `content-type: text/html` — no charset at all. A
// browser that is told nothing falls back to a locale default (Windows-1252 in
// practice), so a genuinely UTF-8 page renders curly quotes and em dashes as
// mojibake: "don't" becomes "donâ€™t". `x-content-type-options: nosniff` closes
// the browser's usual escape hatch, so it cannot recover by sniffing a BOM or a
// <meta charset> either. A page with its own <meta charset> happened to survive;
// one without it did not, which is why this looked intermittent.
//
// So: the extension table is authoritative for the types we know, R2's metadata
// covers the rest, and anything textual that still arrives without a charset
// gets one. Serving is computed per request, so this repairs every share already
// in the bucket — no republish needed.
function contentTypeFor(objectPath, object) {
  const known = MIME_TYPES[extname(objectPath)];
  return withCharset(known || object?.httpMetadata?.contentType || "application/octet-stream");
}

function json(body, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      ...securityHeaders(),
      ...extraHeaders,
    },
  });
}

function securityHeaders(extra = {}) {
  return {
    "x-robots-tag": "noindex",
    "referrer-policy": "no-referrer",
    "x-content-type-options": "nosniff",
    "cache-control": "no-store",
    ...extra,
  };
}

function notFound() {
  return new Response("not found\n", { status: 404, headers: securityHeaders({ "content-type": "text/plain; charset=utf-8" }) });
}

function forbidden(message = "forbidden") {
  return new Response(`${message}\n`, { status: 403, headers: securityHeaders({ "content-type": "text/plain; charset=utf-8" }) });
}

function badRequest(message) {
  return new Response(`${message}\n`, { status: 400, headers: securityHeaders({ "content-type": "text/plain; charset=utf-8" }) });
}

function rateLimited() {
  return new Response("rate limited\n", { status: 429, headers: securityHeaders({ "content-type": "text/plain; charset=utf-8" }) });
}

function extname(path) {
  const i = path.lastIndexOf(".");
  return i >= 0 ? path.slice(i).toLowerCase() : "";
}

function safePath(rawPath) {
  let path = decodeURIComponent(rawPath || "");
  path = path.replace(/^\/+/, "");
  if (!path || path.endsWith("/")) path += "index.html";
  const parts = path.split("/");
  if (parts.some((part) => part === ".." || part === "")) return null;
  return path;
}

function parseSlug(url) {
  const pieces = url.pathname.split("/").filter(Boolean);
  const slug = pieces.shift();
  if (!slug || !/^[a-z0-9][a-z0-9._-]{1,127}$/i.test(slug)) return null;
  return { slug, path: safePath(pieces.join("/")) };
}

function parseBasicAuth(header) {
  if (!header || !header.toLowerCase().startsWith("basic ")) return null;
  try {
    const decoded = atob(header.slice(6));
    const sep = decoded.indexOf(":");
    if (sep < 0) return null;
    return { user: decoded.slice(0, sep), password: decoded.slice(sep + 1) };
  } catch {
    return null;
  }
}

function bytesFromBase64(value) {
  const raw = atob(value);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i += 1) out[i] = raw.charCodeAt(i);
  return out;
}

function toHex(buffer) {
  return [...new Uint8Array(buffer)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function constantTimeEqual(a, b) {
  const left = typeof a === "string" ? TEXT_ENCODER.encode(a) : new Uint8Array(a);
  const right = typeof b === "string" ? TEXT_ENCODER.encode(b) : new Uint8Array(b);
  let diff = left.length ^ right.length;
  const max = Math.max(left.length, right.length);
  for (let i = 0; i < max; i += 1) {
    diff |= (left[i] || 0) ^ (right[i] || 0);
  }
  return diff === 0;
}

async function pbkdf2Hex(password, saltBase64, iterations) {
  const key = await crypto.subtle.importKey(
    "raw",
    TEXT_ENCODER.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: bytesFromBase64(saltBase64), iterations, hash: "SHA-256" },
    key,
    256,
  );
  return toHex(bits);
}

async function verifyPassword(password, verifier) {
  if (!verifier || verifier.algorithm !== "pbkdf2-sha256") return false;
  // Workers' WebCrypto caps PBKDF2 at 100k iterations (throws NotSupportedError
  // above that); the CLI mints verifiers at 100k to match.
  const got = await pbkdf2Hex(password, verifier.salt, verifier.iterations || 100000);
  return constantTimeEqual(got, verifier.hash);
}

// --- password-tier login cookie (stateless MAC, no session store) -----------
// A successful password login mints an HttpOnly cookie scoped to the slug path.
// Its value is an HMAC over the slug AND the current password verifier's hash,
// keyed by the Worker's ADMIN_TOKEN secret. Statelessness: the Worker recomputes
// and constant-time-compares the MAC on every request — nothing is stored server
// side. Binding the verifier hash means rotating the password (a republish with a
// new password) silently invalidates every previously-issued cookie.
const COOKIE_NAME = "drop_auth";
const COOKIE_MAX_AGE_SECONDS = 60 * 60 * 12; // 12h browser lifetime

function base64Url(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 1) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function parseCookies(header) {
  const out = {};
  if (!header) return out;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    const key = part.slice(0, eq).trim();
    if (key) out[key] = part.slice(eq + 1).trim();
  }
  return out;
}

async function shareCookieToken(env, slug, verifier) {
  const key = await crypto.subtle.importKey(
    "raw",
    TEXT_ENCODER.encode(env.ADMIN_TOKEN || ""),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const message = `v1:${slug}:${verifier?.hash || ""}`;
  const sig = await crypto.subtle.sign("HMAC", key, TEXT_ENCODER.encode(message));
  return base64Url(new Uint8Array(sig));
}

async function validShareCookie(env, slug, cookieValue, verifier) {
  if (!cookieValue) return false;
  const expected = await shareCookieToken(env, slug, verifier);
  return constantTimeEqual(cookieValue, expected);
}

function cookieHeader(slug, token) {
  // Path is `/<slug>` WITHOUT a trailing slash on purpose. A `/<slug>/` path
  // would not be sent on a request to the slash-less `/<slug>` (cookie path
  // matching: `/<slug>/` is not a prefix of `/<slug>`), so a recipient who opens
  // the slug without the trailing slash would log in, get redirected back to
  // `/<slug>`, send no cookie, and loop on the login page forever. `/<slug>`
  // matches both `/<slug>` and `/<slug>/...` and still scopes to exactly this
  // slug (a sibling like `/<slug>-2/` is not a path-match).
  return `${COOKIE_NAME}=${token}; Path=/${slug}; Max-Age=${COOKIE_MAX_AGE_SECONDS}; HttpOnly; Secure; SameSite=Lax`;
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// --- public link preview for password shares (--public-preview) -------------
// A password share normally reveals nothing without the password, so chat apps
// show a bare link. A share published with --public-preview carries a
// server-written record in its D1 manifest row:
// `scan_result.public_preview` = {title, description, site_name, image_alt,
// image_sha256}. Then the login page carries og:/twitter: tags, and exactly one
// object is served without the password: the generated title card at
// `<slug>/og.png`. Nothing else is exempt.
//
// The record lives in D1, not KV, so it is written atomically with the manifest
// it belongs to and read with it on every request (readShare). A republish
// without the flag drops it in the same write; a revoke marks the same row.
// upsertManifest writes the field only from a validated `preview` and strips any
// client-sent copy, so a client cannot set it directly.
//
// The entitlement is bound to exact bytes, not to the path. The CLI uploads to
// R2 before it writes the manifest, so the R2 object alone cannot be trusted.
// The card is served only while all three agree: the record's image_sha256, the
// same manifest's og.png row sha256, and the sha256 of the bytes read from R2.
// Any mismatch is the plain login page. So an overwritten object can at most
// serve the card the owner approved.
const PREVIEW_IMAGE_PATH = "og.png";
const PREVIEW_TITLE_MAX = 300;
const PREVIEW_DESCRIPTION_MAX = 1000;
const PREVIEW_SITE_NAME_MAX = 300;
const PREVIEW_IMAGE_ALT_MAX = 300;
// The generated card is a few KB to a few tens of KB. Refuse to buffer more.
const PREVIEW_IMAGE_MAX_BYTES = 2 * 1024 * 1024;
const SHA256_HEX = /^[0-9a-f]{64}$/;

// The sha256 the manifest lists for its share-root og.png, or null.
function manifestCardSha(files) {
  const row = Array.isArray(files) ? files.find((file) => file && file.path === PREVIEW_IMAGE_PATH) : null;
  return row && typeof row.sha256 === "string" && SHA256_HEX.test(row.sha256) ? row.sha256 : null;
}

// The manifest's preview record, but only when it names the card the same
// manifest lists. A record whose image_sha256 does not match counts as no
// preview at all.
function readPreview(share) {
  const scan = share.scan_result;
  const preview = scan && typeof scan === "object" ? scan.public_preview : null;
  if (!preview || typeof preview !== "object" || typeof preview.title !== "string") return null;
  const cardSha = manifestCardSha(share.files);
  if (!cardSha || preview.image_sha256 !== cardSha) return null;
  return preview;
}

async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

// The R2 object's bytes when they hash to the approved card, else null. The size
// is checked before anything is buffered.
async function approvedCardBytes(object, imageSha256) {
  if (typeof object.size !== "number" || object.size > PREVIEW_IMAGE_MAX_BYTES) {
    if (object.body && typeof object.body.cancel === "function") await object.body.cancel();
    return null;
  }
  const bytes = await object.arrayBuffer();
  if (bytes.byteLength > PREVIEW_IMAGE_MAX_BYTES) return null;
  return (await sha256Hex(bytes)) === imageSha256 ? bytes : null;
}

// The share-root og.png only (never `x/og.png`, and never via the single-file
// root fallback, which maps only `index.html`), and only while the current
// manifest lists it.
function isPreviewImageRequest(request, share, path) {
  return (
    (request.method === "GET" || request.method === "HEAD") &&
    path === PREVIEW_IMAGE_PATH &&
    share.files.some((file) => file.path === PREVIEW_IMAGE_PATH)
  );
}

function previewMeta(slug, preview, origin) {
  const pageUrl = escapeHtml(`${origin}/${slug}/`);
  const imageUrl = escapeHtml(`${origin}/${slug}/${PREVIEW_IMAGE_PATH}`);
  const title = escapeHtml(preview.title);
  const description = preview.description ? escapeHtml(preview.description) : null;
  const siteName = preview.site_name ? escapeHtml(preview.site_name) : null;
  const imageAlt = preview.image_alt ? escapeHtml(preview.image_alt) : null;
  const tags = [
    '<meta property="og:type" content="website">',
    `<meta property="og:title" content="${title}">`,
  ];
  if (description) tags.push(`<meta property="og:description" content="${description}">`);
  if (siteName) tags.push(`<meta property="og:site_name" content="${siteName}">`);
  tags.push(
    `<meta property="og:url" content="${pageUrl}">`,
    `<meta property="og:image" content="${imageUrl}">`,
    '<meta property="og:image:width" content="1200">',
    '<meta property="og:image:height" content="630">',
  );
  if (imageAlt) tags.push(`<meta property="og:image:alt" content="${imageAlt}">`);
  tags.push(
    '<meta name="twitter:card" content="summary_large_image">',
    `<meta name="twitter:title" content="${title}">`,
  );
  if (description) tags.push(`<meta name="twitter:description" content="${description}">`);
  tags.push(`<meta name="twitter:image" content="${imageUrl}">`);
  if (imageAlt) tags.push(`<meta name="twitter:image:alt" content="${imageAlt}">`);
  return tags.join("\n");
}

// An error message, or null when the payload's preview (if any) is valid.
function validatePreview(payload) {
  const preview = payload.preview;
  if (preview === undefined || preview === null) return null;
  if (payload.auth_mode !== "password") return "preview applies only to password shares";
  if (typeof preview !== "object" || Array.isArray(preview)) return "preview must be an object";
  if (typeof preview.title !== "string" || !preview.title.trim()) return "preview.title must be a non-empty string";
  if (preview.title.length > PREVIEW_TITLE_MAX) return `preview.title is over ${PREVIEW_TITLE_MAX} characters`;
  for (const [field, max] of [
    ["description", PREVIEW_DESCRIPTION_MAX],
    ["site_name", PREVIEW_SITE_NAME_MAX],
    ["image_alt", PREVIEW_IMAGE_ALT_MAX],
  ]) {
    const value = preview[field];
    if (value === undefined || value === null) continue;
    if (typeof value !== "string") return `preview.${field} must be a string or null`;
    if (value.length > max) return `preview.${field} is over ${max} characters`;
  }
  if (!payload.scan_result || typeof payload.scan_result !== "object" || Array.isArray(payload.scan_result)) {
    return "preview needs scan_result to be an object";
  }
  const cardRow = payload.files.find((file) => file && file.path === PREVIEW_IMAGE_PATH);
  if (!cardRow) return `preview needs ${PREVIEW_IMAGE_PATH} in files`;
  const imageSha = preview.image_sha256;
  if (typeof imageSha !== "string" || !SHA256_HEX.test(imageSha)) return "preview.image_sha256 must be a lowercase hex sha256";
  if (cardRow.sha256 !== imageSha) return `preview.image_sha256 does not match the ${PREVIEW_IMAGE_PATH} sha256 in files`;
  return null;
}

// The scan_result to store: with `scan_result.public_preview` set from a
// validated `preview`, or with any client-sent `public_preview` removed. Every
// publish rewrites the row, so a republish that leaves out --public-preview
// turns the preview off in the same write.
function withPublicPreview(scanResult, preview) {
  if (!scanResult || typeof scanResult !== "object" || Array.isArray(scanResult)) return scanResult;
  const { public_preview: _clientSent, ...rest } = scanResult;
  if (!preview) return rest;
  const { title, description, site_name, image_alt, image_sha256 } = preview;
  return {
    ...rest,
    public_preview: {
      title,
      description: description || null,
      site_name: site_name || null,
      image_alt: image_alt || null,
      image_sha256,
    },
  };
}
// --- end public link preview -------------------------------------------------

// Minimal, unbranded, fully self-contained login page (no external assets). Shows
// the share label as a heading; otherwise reveals nothing. Served instead of the
// old HTTP Basic dialog so browsers get a clean, professional, client-facing page.
// With `preview` (a --public-preview share) the head also carries the share's
// link-preview tags; without it the page is byte-identical to before.
function loginPage(share, { error = false, preview = null, origin = "" } = {}) {
  const heading = escapeHtml(share.label || "Protected document");
  const previewTags = preview ? `\n${previewMeta(share.slug, preview, origin)}` : "";
  const errorBlock = error
    ? '<p class="err" role="alert">Incorrect password. Please try again.</p>'
    : "";
  const body = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">${previewTags}
<title>${heading}</title>
<style>
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body {
    margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
    background: #f3f4f6; color: #111827; padding: 24px;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  }
  .card {
    width: 100%; max-width: 360px; background: #ffffff; border: 1px solid #e5e7eb;
    border-radius: 12px; padding: 32px 28px; box-shadow: 0 1px 3px rgba(0,0,0,.08);
  }
  .lock { font-size: 28px; text-align: center; margin-bottom: 12px; }
  h1 { font-size: 18px; font-weight: 600; text-align: center; margin: 0 0 6px; line-height: 1.3; }
  .sub { font-size: 13px; color: #6b7280; text-align: center; margin: 0 0 20px; }
  label { display: block; font-size: 12px; font-weight: 600; color: #374151; margin-bottom: 6px; }
  input[type=password] {
    width: 100%; padding: 10px 12px; font-size: 15px; border: 1px solid #d1d5db;
    border-radius: 8px; background: #fff; color: #111827;
  }
  input[type=password]:focus { outline: 2px solid #2563eb; outline-offset: 1px; border-color: #2563eb; }
  button {
    width: 100%; margin-top: 16px; padding: 10px 12px; font-size: 15px; font-weight: 600;
    color: #fff; background: #111827; border: 0; border-radius: 8px; cursor: pointer;
  }
  button:hover { background: #374151; }
  .err { font-size: 13px; color: #b91c1c; text-align: center; margin: 0 0 14px; }
  @media (prefers-color-scheme: dark) {
    body { background: #0b0f17; color: #e5e7eb; }
    .card { background: #111827; border-color: #1f2937; box-shadow: none; }
    h1 { color: #f9fafb; }
    label { color: #d1d5db; }
    input[type=password] { background: #0b0f17; border-color: #374151; color: #f9fafb; }
    button { background: #2563eb; }
    button:hover { background: #1d4ed8; }
  }
</style>
</head>
<body>
  <main class="card">
    <div class="lock" aria-hidden="true">&#128274;</div>
    <h1>${heading}</h1>
    <p class="sub">This document is password-protected.</p>
    ${errorBlock}
    <form method="POST" autocomplete="off">
      <label for="password">Password</label>
      <input id="password" name="password" type="password" autofocus required autocomplete="current-password">
      <button type="submit">View</button>
    </form>
  </main>
</body>
</html>
`;
  return new Response(body, {
    status: 200,
    headers: securityHeaders({
      "content-type": "text/html; charset=utf-8",
      "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'",
    }),
  });
}

function loginRedirect(request, slug, token) {
  const url = new URL(request.url);
  return new Response(null, {
    status: 303,
    headers: {
      ...securityHeaders(),
      location: url.pathname,
      "set-cookie": cookieHeader(slug, token),
    },
  });
}

async function readFormPassword(request) {
  const contentType = request.headers.get("content-type") || "";
  try {
    if (contentType.includes("application/x-www-form-urlencoded")) {
      return new URLSearchParams(await request.text()).get("password") || "";
    }
    if (contentType.includes("multipart/form-data")) {
      return (await request.formData()).get("password") || "";
    }
  } catch {
    return "";
  }
  return "";
}

async function readShare(env, slug) {
  const row = await env.DB.prepare(
    "SELECT slug, label, auth_mode, sha256, files_json, bytes, scan_result_json, created_at, expires_at, revoked_at, uploader FROM shares WHERE slug = ?",
  ).bind(slug).first();
  if (!row) return null;
  return {
    ...row,
    files: JSON.parse(row.files_json || "[]"),
    scan_result: JSON.parse(row.scan_result_json || "{}"),
  };
}

async function recordAudit(env, slug, event, actor, details = {}) {
  await env.DB.prepare(
    "INSERT INTO audit_events (slug, event, actor, details_json, created_at) VALUES (?, ?, ?, ?, ?)",
  ).bind(slug, event, actor || "unknown", JSON.stringify(details), new Date().toISOString()).run();
}

async function isDenied(env, slug) {
  const deny = await env.AUTH_KV.get(`deny:${slug}`);
  return deny === "1";
}

function isExpired(share, now = new Date()) {
  return Boolean(share?.expires_at && new Date(share.expires_at).getTime() <= now.getTime());
}

async function enforceRateLimit(env, request, slug) {
  const max = Number(env.RATE_LIMIT_MAX || 10);
  const windowSeconds = Number(env.RATE_LIMIT_WINDOW_SECONDS || 60);
  const ip = request.headers.get("cf-connecting-ip") || "unknown";
  const key = `rl:${slug}:${ip}:${Math.floor(Date.now() / 1000 / windowSeconds)}`;
  const current = Number((await env.AUTH_KV.get(key)) || "0");
  if (current >= max) return false;
  await env.AUTH_KV.put(key, String(current + 1), { expirationTtl: windowSeconds + 5 });
  return true;
}

async function requireShareAuth(env, request, share, path) {
  if (share.auth_mode === "public") return { ok: true };
  const slug = share.slug;
  const verifier = await env.AUTH_KV.get(`auth:${slug}`, { type: "json" });

  // Rate limiting throttles only failed PASSWORD attempts — never a successful
  // load, and never the (assetless) login page itself. Serving the login page or
  // a cookie-authenticated document does no PBKDF2 work and reveals nothing, so
  // there is nothing to throttle there.

  // 1) A valid login cookie (browser already authenticated). Path-scoped to the
  //    slug and MAC-bound to slug + verifier, so a forged or foreign-slug cookie
  //    fails the constant-time compare and falls through to the login page.
  const cookies = parseCookies(request.headers.get("cookie"));
  if (cookies[COOKIE_NAME] && (await validShareCookie(env, slug, cookies[COOKIE_NAME], verifier))) {
    return { ok: true };
  }

  // 2) HTTP Basic Auth, kept so non-browser/API clients (`curl -u x:pw …`) still
  //    work. curl sends Basic preemptively, so no WWW-Authenticate challenge is
  //    needed — and we deliberately never send one (that dialog is what we're
  //    replacing). The username is ignored; only the password is checked.
  const auth = parseBasicAuth(request.headers.get("authorization"));
  if (auth && auth.password) {
    if (await verifyPassword(auth.password, verifier)) return { ok: true };
    if (!(await enforceRateLimit(env, request, slug))) return { ok: false, response: rateLimited() };
    return { ok: false, response: forbidden("forbidden") };
  }

  // 3) Login form submission (browser POST). On success, set the cookie and
  //    redirect (POST→303→GET) so a refresh never re-posts the password.
  if (request.method === "POST") {
    const password = await readFormPassword(request);
    if (password && (await verifyPassword(password, verifier))) {
      const token = await shareCookieToken(env, slug, verifier);
      return { ok: false, response: loginRedirect(request, slug, token) };
    }
    if (!(await enforceRateLimit(env, request, slug))) return { ok: false, response: rateLimited() };
    const preview = readPreview(share);
    return { ok: false, response: loginPage(share, { error: true, preview, origin: new URL(request.url).origin }) };
  }

  // 4) Unauthenticated browser request → serve the clean HTML login page. The
  //    preview record is read only here and in the failed POST above, never on
  //    a cookie- or Basic-authenticated request. With a preview that matches
  //    the current manifest, the share-root og.png is the one object served
  //    without the password, and serveArtifact still checks its bytes
  //    (previewSha256).
  const preview = readPreview(share);
  if (preview && isPreviewImageRequest(request, share, path)) {
    return { ok: true, previewSha256: preview.image_sha256 };
  }
  return { ok: false, response: loginPage(share, { preview, origin: new URL(request.url).origin }) };
}

// One `view` audit row per page open, never per asset. A page load pulls many
// sub-assets (CSS/JS/images) from one IP; only the document itself counts, and a
// short KV dedupe window collapses refreshes and any straggler into one row.
const VIEW_DEDUPE_TTL_SECONDS = 60 * 30; // 30 min
const MAX_UA_LENGTH = 200;

function isDocumentView(share, objectPath) {
  const ext = extname(objectPath);
  if (ext === ".html" || ext === ".htm") return true;
  // A single-file share's only object IS the document (e.g. a lone PDF/image).
  return share.files.length === 1 && objectPath === share.files[0].path;
}

async function logView(env, request, share, objectPath) {
  if (!isDocumentView(share, objectPath)) return;
  const ip = request.headers.get("cf-connecting-ip") || "unknown";
  const dedupeKey = `view:${share.slug}:${ip}`;
  if (await env.AUTH_KV.get(dedupeKey)) return;
  const ua = (request.headers.get("user-agent") || "").slice(0, MAX_UA_LENGTH);
  await env.AUTH_KV.put(dedupeKey, "1", { expirationTtl: VIEW_DEDUPE_TTL_SECONDS });
  await recordAudit(env, share.slug, "view", ip, { ip, ua });
}

async function serveArtifact(request, env, url, ctx) {
  const parsed = parseSlug(url);
  if (!parsed || !parsed.path) return notFound();
  const { slug, path } = parsed;

  if (await isDenied(env, slug)) return forbidden("revoked");
  const share = await readShare(env, slug);
  if (!share) return notFound();
  if (share.revoked_at) return forbidden("revoked");
  if (isExpired(share)) return forbidden("expired");

  const auth = await requireShareAuth(env, request, share, path);
  if (!auth.ok) return auth.response;

  // Gate serving to the CURRENT D1 manifest. R2 objects are not purged on a
  // republish (only revoke purges the whole prefix), so a slug republished with
  // fewer files can leave removed objects in R2. Without this check those stale
  // objects stay reachable by direct URL. Serve only paths listed in share.files.
  const allowed = new Set(share.files.map((file) => file.path));
  let objectPath = path;
  // `/<slug>/` defaults to index.html; if the share is a single non-index file,
  // fall back to that file (preserves the existing single-file convenience).
  if (!allowed.has(objectPath) && path === "index.html" && share.files.length === 1) {
    objectPath = share.files[0].path;
  }
  if (!allowed.has(objectPath)) return notFound();
  const previewImage = Boolean(auth.previewSha256);
  // Belt and braces: the preview exemption only ever serves the root card.
  if (previewImage && objectPath !== PREVIEW_IMAGE_PATH) return notFound();
  const object = await env.ARTIFACTS.get(`${slug}/${objectPath}`);
  // An unauthenticated card request that fails any check gets the same plain
  // login page as a share with no preview.
  if (!object) return previewImage ? loginPage(share) : notFound();
  let body = object.body;
  if (previewImage) {
    // The R2 bytes must be the exact card the manifest approved.
    body = await approvedCardBytes(object, auth.previewSha256);
    if (!body) return loginPage(share);
  }

  const headers = securityHeaders({
    "content-type": contentTypeFor(objectPath, object),
    "etag": object.httpEtag || undefined,
  });
  if (request.method === "HEAD") return new Response(null, { status: 200, headers });
  const response = new Response(body, { status: 200, headers });
  // Count the open only on a real document GET (not HEAD prefetch, not the login
  // POST). Asset requests and refreshes are filtered/deduped inside logView.
  // Keep view tracking fully off the serving hot path: schedule it via
  // ctx.waitUntil so the viewer's bytes never wait on the dedupe read or the
  // audit write. With no ctx (unit tests) await it so the row is observable.
  // The preview card served without the password is not a document open.
  if (request.method === "GET" && !previewImage) {
    const tracking = logView(env, request, share, objectPath);
    if (ctx && typeof ctx.waitUntil === "function") ctx.waitUntil(tracking);
    else await tracking;
  }
  return response;
}

async function requireAdmin(request, env) {
  const header = request.headers.get("authorization") || "";
  const expected = env.ADMIN_TOKEN || "";
  if (!expected || !header.toLowerCase().startsWith("bearer ")) return false;
  return constantTimeEqual(header.slice(7), expected);
}

async function listShares(env) {
  const result = await env.DB.prepare(
    "SELECT slug, label, auth_mode, sha256, files_json, bytes, scan_result_json, created_at, expires_at, revoked_at, uploader FROM shares ORDER BY created_at DESC",
  ).all();
  const viewCounts = await env.DB.prepare(
    "SELECT slug, COUNT(*) AS views FROM audit_events WHERE event = 'view' GROUP BY slug",
  ).all();
  const counts = new Map((viewCounts.results || []).map((row) => [row.slug, row.views]));
  return (result.results || []).map((row) => ({
    ...row,
    files: JSON.parse(row.files_json || "[]"),
    scan_result: JSON.parse(row.scan_result_json || "{}"),
    files_json: undefined,
    scan_result_json: undefined,
    views: counts.get(row.slug) || 0,
  }));
}

async function viewsForSlug(env, slug, limit = 50) {
  const countRow = await env.DB.prepare(
    "SELECT COUNT(*) AS count FROM audit_events WHERE slug = ? AND event = 'view'",
  ).bind(slug).first();
  const recent = await env.DB.prepare(
    "SELECT created_at, details_json FROM audit_events WHERE slug = ? AND event = 'view' ORDER BY created_at DESC LIMIT ?",
  ).bind(slug, limit).all();
  const views = (recent.results || []).map((row) => {
    let details = {};
    try {
      details = JSON.parse(row.details_json || "{}");
    } catch {
      details = {};
    }
    return { at: row.created_at, ip: details.ip || null, ua: details.ua || null };
  });
  return { slug, count: countRow?.count || 0, views };
}

async function upsertManifest(request, env) {
  const payload = await request.json();
  const required = ["slug", "auth_mode", "sha256", "files", "bytes", "scan_result", "created_at", "uploader"];
  for (const key of required) {
    if (payload[key] === undefined || payload[key] === null || payload[key] === "") return badRequest(`missing ${key}`);
  }
  if (!["password", "public"].includes(payload.auth_mode)) return badRequest("invalid auth_mode");
  if (!Array.isArray(payload.files) || payload.files.length === 0) return badRequest("files must be a non-empty array");
  if (payload.auth_mode === "password" && !payload.password_verifier) return badRequest("missing password_verifier");
  // --- public link preview: validate (see validatePreview) ---
  const previewError = validatePreview(payload);
  if (previewError) return badRequest(previewError);
  // --- end public link preview ---
  // --- public link preview: set or strip scan_result.public_preview (see withPublicPreview) ---
  payload.scan_result = withPublicPreview(payload.scan_result, payload.preview);
  // --- end public link preview ---

  await env.DB.prepare(
    `INSERT INTO shares (slug, label, auth_mode, sha256, files_json, bytes, scan_result_json, created_at, expires_at, revoked_at, uploader)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)
     ON CONFLICT(slug) DO UPDATE SET
       label = excluded.label,
       auth_mode = excluded.auth_mode,
       sha256 = excluded.sha256,
       files_json = excluded.files_json,
       bytes = excluded.bytes,
       scan_result_json = excluded.scan_result_json,
       expires_at = excluded.expires_at,
       revoked_at = NULL,
       uploader = excluded.uploader`,
  ).bind(
    payload.slug,
    payload.label || null,
    payload.auth_mode,
    payload.sha256,
    JSON.stringify(payload.files),
    payload.bytes,
    JSON.stringify(payload.scan_result),
    payload.created_at,
    payload.expires_at || null,
    payload.uploader,
  ).run();

  if (payload.auth_mode === "password") {
    await env.AUTH_KV.put(`auth:${payload.slug}`, JSON.stringify(payload.password_verifier));
  } else {
    await env.AUTH_KV.delete(`auth:${payload.slug}`);
  }
  await env.AUTH_KV.delete(`deny:${payload.slug}`);
  await recordAudit(env, payload.slug, "publish", payload.uploader, {
    auth_mode: payload.auth_mode,
    bytes: payload.bytes,
    files: payload.files.map((file) => file.path),
    scan_result: payload.scan_result,
    override_log: payload.override_log || [],
    preview: Boolean(payload.preview),
  });

  return json({ ok: true, slug: payload.slug });
}

async function purgeUrl(env, url) {
  if (!env.CF_API_TOKEN || !env.CF_ZONE_ID || !url) return { skipped: true };
  const res = await fetch(`https://api.cloudflare.com/client/v4/zones/${env.CF_ZONE_ID}/purge_cache`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${env.CF_API_TOKEN}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({ files: [url] }),
  });
  return { status: res.status, ok: res.ok };
}

async function revokeShare(request, env) {
  const payload = await request.json();
  const slug = payload.slug || payload.id;
  if (!slug) return badRequest("missing slug");
  const actor = payload.actor || "publish-cli";
  const share = await readShare(env, slug);
  if (!share) return notFound();

  await env.AUTH_KV.put(`deny:${slug}`, "1");
  await env.DB.prepare("UPDATE shares SET revoked_at = ? WHERE slug = ?").bind(new Date().toISOString(), slug).run();

  const deleted = [];
  let cursor = undefined;
  do {
    const page = await env.ARTIFACTS.list({ prefix: `${slug}/`, cursor });
    const keys = page.objects.map((object) => object.key);
    if (keys.length > 0) {
      await env.ARTIFACTS.delete(keys);
      deleted.push(...keys);
    }
    cursor = page.truncated ? page.cursor : undefined;
  } while (cursor);

  const base = String(env.PUBLIC_BASE_URL || "").replace(/\/+$/, "");
  const purges = [];
  if (base) {
    purges.push(await purgeUrl(env, `${base}/${slug}/`));
    for (const file of share.files) {
      purges.push(await purgeUrl(env, `${base}/${slug}/${file.path}`));
    }
  }

  await recordAudit(env, slug, "revoke", actor, { deleted, purges });
  return json({ ok: true, slug, deleted: deleted.length, purges });
}

async function handleAdmin(request, env, url) {
  if (!(await requireAdmin(request, env))) return forbidden("admin forbidden");
  if (request.method === "GET" && url.pathname === "/admin/list") return json({ shares: await listShares(env) });
  if (request.method === "GET" && url.pathname === "/admin/views") {
    const slug = url.searchParams.get("slug");
    if (!slug) return badRequest("missing slug");
    const limit = Math.min(Math.max(Number(url.searchParams.get("limit")) || 50, 1), 500);
    return json(await viewsForSlug(env, slug, limit));
  }
  if (request.method === "POST" && url.pathname === "/admin/manifest") return upsertManifest(request, env);
  if (request.method === "POST" && url.pathname === "/admin/revoke") return revokeShare(request, env);
  return notFound();
}

async function fetchHandler(request, env, ctx) {
  const url = new URL(request.url);
  if (url.pathname.startsWith("/admin/")) return handleAdmin(request, env, url);
  // POST is allowed so password shares can accept the login form; serveArtifact
  // routes it through requireShareAuth (a POST to a public share just serves).
  if (!["GET", "HEAD", "POST"].includes(request.method)) return new Response("method not allowed\n", { status: 405, headers: securityHeaders() });
  return serveArtifact(request, env, url, ctx);
}

export {
  constantTimeEqual,
  contentTypeFor,
  fetchHandler,
  isExpired,
  parseBasicAuth,
  parseSlug,
  safePath,
  shareCookieToken,
  verifyPassword,
};

export default {
  fetch: fetchHandler,
};
