const TEXT_ENCODER = new TextEncoder();

const MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".htm": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".mjs": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".txt": "text/plain; charset=utf-8",
  ".md": "text/markdown; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".gif": "image/gif",
  ".webp": "image/webp",
  ".pdf": "application/pdf",
};

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

async function requireShareAuth(env, request, share) {
  if (share.auth_mode === "public") return { ok: true };
  // Throttle only failed/unauthenticated attempts — never a successful load.
  // A legitimate viewer's browser replays valid Basic Auth on every asset, so
  // rate-limiting before the password check would 429 a real visitor loading
  // more than RATE_LIMIT_MAX files (CSS/JS/images) from one IP.
  const auth = parseBasicAuth(request.headers.get("authorization"));
  if (!auth || !auth.password) {
    if (!(await enforceRateLimit(env, request, share.slug))) return { ok: false, response: rateLimited() };
    return {
      ok: false,
      response: new Response("authentication required\n", {
        status: 401,
        headers: { ...securityHeaders({ "content-type": "text/plain; charset=utf-8" }), "www-authenticate": `Basic realm="${share.slug}", charset="UTF-8"` },
      }),
    };
  }
  const verifier = await env.AUTH_KV.get(`auth:${share.slug}`, { type: "json" });
  if (!(await verifyPassword(auth.password, verifier))) {
    if (!(await enforceRateLimit(env, request, share.slug))) return { ok: false, response: rateLimited() };
    return { ok: false, response: forbidden("forbidden") };
  }
  return { ok: true };
}

async function serveArtifact(request, env, url) {
  const parsed = parseSlug(url);
  if (!parsed || !parsed.path) return notFound();
  const { slug, path } = parsed;

  if (await isDenied(env, slug)) return forbidden("revoked");
  const share = await readShare(env, slug);
  if (!share) return notFound();
  if (share.revoked_at) return forbidden("revoked");
  if (isExpired(share)) return forbidden("expired");

  const auth = await requireShareAuth(env, request, share);
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
  const object = await env.ARTIFACTS.get(`${slug}/${objectPath}`);
  if (!object) return notFound();

  const headers = securityHeaders({
    "content-type": object.httpMetadata?.contentType || MIME_TYPES[extname(objectPath)] || "application/octet-stream",
    "etag": object.httpEtag || undefined,
  });
  if (request.method === "HEAD") return new Response(null, { status: 200, headers });
  return new Response(object.body, { status: 200, headers });
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
  return (result.results || []).map((row) => ({
    ...row,
    files: JSON.parse(row.files_json || "[]"),
    scan_result: JSON.parse(row.scan_result_json || "{}"),
    files_json: undefined,
    scan_result_json: undefined,
  }));
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
  if (request.method === "POST" && url.pathname === "/admin/manifest") return upsertManifest(request, env);
  if (request.method === "POST" && url.pathname === "/admin/revoke") return revokeShare(request, env);
  return notFound();
}

async function fetchHandler(request, env) {
  const url = new URL(request.url);
  if (url.pathname.startsWith("/admin/")) return handleAdmin(request, env, url);
  if (!["GET", "HEAD"].includes(request.method)) return new Response("method not allowed\n", { status: 405, headers: securityHeaders() });
  return serveArtifact(request, env, url);
}

export {
  constantTimeEqual,
  fetchHandler,
  isExpired,
  parseBasicAuth,
  parseSlug,
  safePath,
  verifyPassword,
};

export default {
  fetch: fetchHandler,
};
