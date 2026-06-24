# drop

**A static-artifact publishing pipeline.** One command turns a local HTML file,
report, or screenshot bundle into a clean public URL on the open internet — with
a password gate, expiry, revocation, a no-index policy, and an audit trail
behind it.

```
drop path/to/report.html   →   https://drop.example.com/report/
```

It's the outbound counterpart to a capture inbox: where a tool like `bin` takes
things *in*, `drop` puts a finished artifact *out*.

This is **personal, self-hostable, open-source infrastructure** — a tool you
deploy to *your own* Cloudflare account. It is **not** a hosted product and there
is nothing to sign up for. The author's deployment runs at
**[drop.jonomatus.ky](https://drop.jonomatus.ky)**, and there's a live writeup of
the design (published with the tool itself) at
**<https://drop.jonomatus.ky/how-drop-works/>** (the source of that page lives in
[`web/index.html`](web/index.html)).

---

## Architecture: a thin CLI and a small Worker

The system is two halves with a clean seam between them. A local command-line
tool does the work that needs your machine — scanning, hashing, uploading. A
Cloudflare Worker at the edge does the work that needs to be live 24/7 — serving
pages, checking passwords, honoring expiry. Neither half holds more power than
its job requires.

```
   you ──▶  drop path/to/artifact               (local · the CLI)
              │  no-leak preflight
              │  resolve a readable slug
              │  upload each file to R2 over S3
              │  POST the canonical manifest to the Worker admin API
              ▼
            R2 bucket  ◀── bytes ──▶  Worker  ──▶  visitor
            D1 database ◀ manifest+audit ┘     GET /<slug>/…
```

- **`cli/drop`** — a zero-dependency Python 3 script (stdlib only). It runs the
  preflight, picks a unique readable slug, uploads each file as an object to R2
  over the S3 API, then calls the Worker's `/admin/*` API to write the canonical
  manifest row.
- **`worker/`** — a small Cloudflare Worker (`src/worker.mjs`). On every request
  it looks up the manifest in D1, enforces the auth mode, checks expiry and
  revocation, sets `no-index` headers, streams the object back from R2, and logs
  the access.

The split is also a security boundary: **the deployed Worker carries no API token
at all.** It reaches R2 and D1 through Cloudflare *bindings*, so no broad
credential is ever left sitting on the edge.

---

## State: R2 for the bytes, D1 for the record

Storage and bookkeeping are kept separate.

- **R2** is the object store — it holds the raw bytes of every published file,
  keyed `"<slug>/<path>"`. The CLI writes them over S3; the Worker reads them over
  a binding. Nothing is ever served from your machine.
- **D1** (Cloudflare's edge SQLite) holds the *metadata*, in two tables (see
  [`worker/schema.sql`](worker/schema.sql)):
  - **`shares`** — one row per share: slug, label, auth mode, content hash, the
    JSON file list, byte count, the preflight scan result, and created / expiry /
    revoked timestamps plus who uploaded it.
  - **`audit_events`** — an append-only history keyed by slug: every publish,
    every revoke, and every `view` (document open) is recorded with actor,
    timestamp, and details. The manifest is mutable (a republish upserts the row);
    the audit log only ever grows.

Because the row carries an expiry and a revocation timestamp, a share can be
switched off (`drop revoke <slug>`) or made to lapse **without touching the
stored files** — the Worker simply refuses to serve a slug the database says is
dead. Revoke additionally deletes the R2 objects and (optionally) purges the edge
cache.

---

## Naming: readable slugs, no random IDs

Shares get short, human-readable URLs — `drop.example.com/ted-page/`, not a wall
of hex. The slug comes from a `--client` or `--label` you pass, or, if you pass
neither, the artifact's own filename (`report.html` → `report`). It's lowercased,
hyphen-joined, and capped at 40 characters.

The interesting part is how name collisions are handled: **at publish time, not
with a random suffix.** The CLI asks the Worker for the list of existing shares
and takes the readable name if it's free. If it's taken, it appends `-2`, `-3`, …
— `ted-page-2`.

- **Every** existing share counts as taken — *including expired and revoked ones*
  — so a new artifact never reuses or silently overwrites a name that was used
  before.
- The Worker stores by slug (an upsert), which is exactly **why the CLI owns
  clash-avoidance**: the edge would happily overwrite, so the client makes sure it
  never has to. (`--slug` forces an exact slug and skips the clash check — that's
  how a known share republishes in place.)

---

## Access: three visibility tiers

Borrowing YouTube's model, a share is one of three things. To the Worker there
are really only two auth modes — `password` and `public` — and the third tier is
purely a difference in how the **slug** is shaped (entirely CLI-side).

| Tier | Flag | Auth | URL shape | Use it for |
|------|------|------|-----------|------------|
| **Private** *(default)* | *(none)* | password | clean `…/acme-proposal/` | drafts, anything you'll gate — send the password out-of-band |
| **Unlisted** | `--unlisted` | none | readable + ~82-bit tail `…/acme-proposal-k7f3m9q2x8p4n6tz/` | a link you want frictionless but not enumerable — the URL *is* the key |
| **Public** | `--public` | none | clean `…/how-drop-works/` | content meant to be discoverable |

- **Private** is the default. The slug is just a label; the password is the lock,
  verified server-side (PBKDF2) and sent out-of-band — so a guessable name leaks
  nothing.
- **Unlisted** drops the password but gives the slug an unguessable ~82-bit random
  tail. The URL is the capability. **Strong entropy matters here** because the
  Worker only rate-limits *failed password attempts* — a no-password share isn't
  throttled, so the tail is the only thing standing between the artifact and
  enumeration.
- **Public** is no-password with a clean, guessable slug, for content meant to be
  found. To the Worker it's identical to unlisted (`auth_mode="public"`).

Pair any tier with `--expire 7d` and `drop revoke <slug>` for time-boxed shares.

---

## Link previews: a generated social card

A URL with no OpenGraph image makes messaging apps (iMessage, Slack, WhatsApp, …)
fall back to *screenshotting* the page — and a tall page renders as a skinny
vertical sliver in the chat bubble. So for any share that contains an HTML page,
`drop` builds a proper **1200×630 landscape card** at publish time, uploads it
alongside the artifact as `…/<slug>/og.png`, and injects `og:`/`twitter:` meta
tags into the published HTML. Shared links then render a clean landscape card —
the page title on a background — instead of a screenshot.

The card title defaults to the page's `<title>`; everything is customizable from
the CLI:

```bash
drop --public path/to/site                       # card auto-generated from <title>
drop --public --card-title "Q3 Board Deck" ...   # override the card title
drop --public --card-bg "#0b0d12" --card-accent "#5ce0c0" ...   # custom colors
drop --public --no-card ...                       # opt out entirely
```

The renderer is **pure Python stdlib** — a small `zlib`/`struct` PNG encoder and
an embedded public-domain 8×8 bitmap font — so it adds no third-party dependency
and the card is byte-for-byte deterministic. (A single HTML file is staged as
`index.html` so the bare `…/<slug>/` URL serves it once the card makes the share
multi-file.)

---

## The load-bearing detail: a bucket-scoped R2 token, over S3

The most deliberate design choice is about **blast radius**. The Cloudflare
account behind a deployment usually runs other things too — other apps' storage,
databases, Workers. So the credential `drop` uses for its constant job —
uploading files on every run — is scoped down to *exactly one bucket and nothing
else*.

That scoping forces an unusual technical path, and it's worth understanding why:

```
# The obvious command won't do:
wrangler r2 object put …
  ↳ hits Cloudflare's REST API
  ↳ which only accepts an R2 *Admin* token
  ↳ and Admin tokens are account-wide — they CANNOT be
    scoped to a single bucket.

# So the CLI uploads a different way:
S3 PUT (SigV4) with an "Object Read & Write" token
  ↳ Object R/W tokens ARE bucket-scopeable
  ↳ their credential is an S3 Access Key ID + Secret
  ↳ scoped to the artifacts bucket only
```

In short: the only Cloudflare token type that can be locked to a single bucket is
an **Object Read & Write** token, and that token speaks **S3**, not Cloudflare's
REST API. So the CLI signs an S3 SigV4 `PUT` itself (no AWS SDK — it's ~40 lines
of stdlib `hmac`/`hashlib`), trading the convenient `wrangler` command for a
credential that simply *cannot* reach anything it shouldn't.

|  | |
|---|---|
| ✓ **Can** | Write objects into the one artifacts bucket this tool owns. |
| ✗ **Cannot** | Touch any other bucket, database, or Worker on the account. A leak of this key exposes only published artifacts. |

There's even a self-test for it:

```bash
drop scope-test
```

It uses the upload key to prove it *can* write the artifacts bucket and is
*denied* (401/403) on a known forbidden bucket (set `DROP_FORBIDDEN_R2_BUCKET`
to a bucket on the same account the upload creds must not reach). If the forbidden
bucket is ever readable, the token is mis-scoped and the check fails loudly.

> The **deploy/provision** side is the opposite: creating the bucket, KV, and D1,
> applying the schema, and `wrangler deploy` are one-time admin actions that *do*
> use a broad account token. But that token is never persisted into the running
> system — the deployed Worker reaches everything through bindings.

---

## Before anything leaves the machine: a no-leak preflight

Publishing is one-way — public, forwardable, cacheable, and able to outlive a
delete. So every run is gated by a local scan **before a single byte is
uploaded**:

- **Secret scan.** A [`gitleaks`](https://github.com/gitleaks/gitleaks) content
  pass (with a small [bundled config](cli/drop-gitleaks.toml)) blocks anything
  that looks like a key or token. **gitleaks is required** — the preflight refuses
  to run without it.
- **Dangerous filenames.** `.env`, private keys (`*.pem`, `id_rsa`, …), and
  credential paths are refused by name.
- **PII.** High-confidence personal data (SSN-shaped values, credential-shaped
  assignments, bulk email lists) blocks unless explicitly overridden with a
  `--allow-pii "<reason>"` that is logged into the audit trail.
- **Images.** OCR-scanned with `tesseract` when available; otherwise you must
  accept the limitation (`--confirm-image-limitation`) after a manual look.
- **Trackers & archives.** External scripts and tracking pixels in HTML warn;
  archive files (`.zip`, `.tar`, …) are blocked outright.
- **Symlink escape.** A symlink that resolves outside the publish root is refused,
  so nothing leaks in under a harmless-looking relative name.
- **Final confirmation.** A last interactive prompt reminds you the artifact is
  public and may survive deletion (`--yes` to skip in automation).

Passwords, when used, are hashed with **PBKDF2-HMAC-SHA256 at 100,000
iterations** — the ceiling Cloudflare's WebCrypto allows inside a Worker (it
throws `NotSupportedError` above that). The CLI mints the verifier and the Worker
checks it at the *same* count, kept in lockstep so a verifier minted on one side
always validates on the other. The Worker compares in constant time.

---

## Repo layout

```
drop/
├── cli/
│   ├── drop                     # the CLI (zero-dependency Python 3)
│   ├── drop-gitleaks.toml       # bundled gitleaks config for the preflight
│   └── test/                    # CLI unit tests (`python3` — stdlib only)
│       ├── card.test.py         #   link-preview card
│       └── drop.test.py         #   list/views output
├── worker/
│   ├── src/worker.mjs           # the edge Worker
│   ├── schema.sql               # D1 schema: shares + audit_events
│   ├── wrangler.toml            # deploy config (genericized placeholders)
│   ├── package.json             # `npm test`, `npm run deploy`
│   └── test/worker.test.mjs     # Worker unit tests (node --test style)
├── web/
│   └── index.html               # the public "how it works" page (no external deps)
├── LICENSE                      # MIT
└── README.md
```

---

## Self-hosting

### 1. CLI configuration (env vars)

The CLI is configured entirely through environment variables. On macOS, an
**optional** keychain fallback is available for the three secrets (see below).

| Variable | Required | Meaning |
|----------|----------|---------|
| `DROP_BASE_URL` | ✅ | base URL of your deployed Worker, e.g. `https://drop.example.com` |
| `DROP_CF_ACCOUNT_ID` | ✅ | your Cloudflare account id (an identifier, not a secret) — used to address R2's S3 endpoint |
| `DROP_R2_ACCESS_KEY_ID` | ✅ | S3 Access Key ID of the bucket-scoped R2 *Object Read & Write* token |
| `DROP_R2_SECRET_ACCESS_KEY` | ✅ | the matching S3 secret |
| `DROP_ADMIN_TOKEN` | ✅ | bearer token gating the Worker's `/admin/*` routes |
| `DROP_R2_BUCKET` | — | artifacts bucket name (default `drop-artifacts`) |
| `DROP_FORBIDDEN_R2_BUCKET` | — | a bucket the upload creds must *not* reach; enables `scope-test`'s deny check |
| `DROP_GITLEAKS_CONFIG` | — | path to a gitleaks config (default: the bundled one) |

Each of the three secrets reads its `$ENV` var first; if unset, it falls back to
the macOS keychain (service names `drop-r2-access-key-id`,
`drop-r2-secret-access-key`, `drop-admin-token`, overridable via the matching
`DROP_*_KEYCHAIN` vars; scope to a keychain account with `DROP_KEYCHAIN_ACCOUNT`).
Env vars are the portable path; the keychain is just a local convenience.

Requirements: Python 3.10+ and `gitleaks` on `PATH` (plus `tesseract` if you
publish images). Symlink `cli/drop` somewhere on your `PATH`.

### 2. Provision Cloudflare (one-time, broad admin token)

1. **R2 upload token** — Cloudflare dash → R2 → *Manage API Tokens* → **Object
   Read & Write**, **Apply to specific buckets only → your artifacts bucket**.
   Store the S3 Access Key ID + Secret as `DROP_R2_ACCESS_KEY_ID` /
   `DROP_R2_SECRET_ACCESS_KEY`.
2. **Admin token** — generate a random bearer; set it as the Worker secret
   `ADMIN_TOKEN` (`wrangler secret put ADMIN_TOKEN`) *and* expose it to the CLI as
   `DROP_ADMIN_TOKEN`. It gates `/admin/*` (manifest write, list, revoke).
3. Create the R2 bucket, the KV namespace, and the D1 database with a broad
   account token; apply `worker/schema.sql` to D1
   (`wrangler d1 execute <db> --file worker/schema.sql`); fill the real KV `id`
   and D1 `database_id` into `worker/wrangler.toml`.
4. **Deploy:** `cd worker && CLOUDFLARE_API_TOKEN=… wrangler deploy`. The deployed
   Worker holds no token — it uses bindings.
5. **(Optional) custom domain** — `wrangler.toml` can declare the public host as a
   Cloudflare **custom domain**; on deploy wrangler creates and manages the DNS
   record + edge cert itself (the zone just has to be active in your account).
   `workers_dev = true` keeps the `*.workers.dev` fallback resolving the same
   Worker. Drop the `routes` block to run on `*.workers.dev` alone.
6. **(Optional) cache purge on revoke** — set Worker secrets `CF_API_TOKEN` and
   `CF_ZONE_ID` to purge the edge cache when a share is revoked. Cache headers are
   conservative (`no-store`) even without them.
7. **Verify the blast radius:** `drop scope-test`.

### 3. Run the tests

```bash
cd worker && npm test            # Worker — or: node test/worker.test.mjs
python3 cli/test/card.test.py    # CLI link-preview card (stdlib only)
python3 cli/test/drop.test.py    # CLI list/views output (offline, no creds)
```

---

## Usage

```bash
drop path/to/artifact                          # private (password-protected) — the default
drop --client "Acme" path/to/report            # password, readable slug "acme-…"
drop --unlisted --client "Acme" path/to/report # secret link: no password, unguessable URL
drop --public path/to/site                     # truly public: no password, guessable URL
drop --password "$pw" --expire 7d path/to/site # explicit password + 7-day expiry
drop --public --card-title "Q3 Deck" path/site # override the generated link-preview card title
drop --public --no-card path/to/site           # skip the link-preview card + meta tags
drop --dry-run path/to/site                    # run preflight + print the manifest, upload nothing
drop list                                      # list every share (with a views=N column)
drop views <slug>                              # who opened it: count + recent timestamps / IPs / UAs
drop revoke <slug>                             # kill a share (deny + delete objects + purge)
drop scope-test                                # blast-radius self-check
```

A successful private share prints the URL and a generated password; send the
password out-of-band.

---

## Password shares: a login page, not a browser dialog

A password-protected share shows a clean, self-contained **HTML login page** — one
password field and a **View** button — instead of the browser's bare two-field
HTTP Basic dialog. The page carries no external assets, is `noindex`, and shows
only the share's label.

- On the correct password the Worker replies `303` and sets an **HttpOnly, Secure,
  SameSite=Lax** cookie scoped to that share's path, so the recipient isn't
  re-prompted on every asset. The cookie value is a **stateless HMAC** —
  `base64url(HMAC-SHA256(ADMIN_TOKEN, "v1:<slug>:<verifierHash>"))` — recomputed
  and constant-time-compared on every request, so there is **no session store**.
  Because it binds the password verifier, rotating a share's password (a republish
  with a new one) silently invalidates every old cookie.
- A wrong password re-renders the page with an error and counts against the same
  failed-attempt rate limit; a successful load or the login page itself is never
  throttled.
- The order of checks is unchanged — **deny → revoke → expiry → auth** — so a
  revoked or expired share never even renders the login page.
- **Non-browser / API clients keep using HTTP Basic Auth:** `curl -u
  anything:<password> https://drop.example.com/<slug>/` still works (the username
  is ignored; only the password is checked). The Worker **never** sends a
  `WWW-Authenticate` challenge — that dialog is exactly what the login page
  replaces.
- `--public` / `--unlisted` shares have no password and skip the login entirely.

---

## View tracking: did the client open it?

Each time a share's document is opened, the Worker logs one `view` — **one row per
page open, never per asset.** Only the document itself counts (an `.html` request,
or a single-file share's lone object such as a lone PDF), and same-IP refreshes
are deduped within 30 minutes, so one visit is one row rather than thirty. Each row
records the client IP (`cf-connecting-ip`) and a truncated (≤200-char) User-Agent;
the write is deferred off the serving hot path so it never delays the viewer's
bytes. It's your own DocSend-style audit trail:

```bash
drop list            # adds a views=N column per share
drop views <slug>    # the total plus recent opens (timestamp / IP / UA)
```

There's no new table — `view` events reuse `audit_events`. The one schema addition
is an index (`idx_audit_events_event_slug`); re-running the idempotent
`worker/schema.sql` against your D1 applies it.

---

## Credits & license

Built by [jonomatusky](https://x.com/jonomatusky). MIT licensed — see
[`LICENSE`](LICENSE).

Live design writeup (published with the tool itself):
<https://drop.jonomatus.ky/how-drop-works/>
