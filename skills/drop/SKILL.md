---
name: drop
description: Publish a local static artifact — an HTML report, generated doc, screenshot bundle, or a directory of files — to a public URL with the `drop` CLI. Use when asked to share, publish, or put something on the web where anyone with the link can reach it. Covers the three visibility tiers, republishing an existing share in place at the same URL (`--slug`), listing/inspecting/revoking shares, and verifying that what's served is the build you just made.
---

# drop

`drop` turns a local file or directory into a clean public URL —
`https://drop.example.com/report/` — with a password gate, expiry, revocation,
no-index headers, and an audit trail behind it. It is the tool to reach for when
an artifact has to be readable by someone who is not on this machine and not on
a private network.

Publishing is one-way. The bytes land on the open internet, where they are
forwardable, cacheable, and may outlive a delete. If the artifact should stay
private, publish it somewhere private instead.

The base URL, bucket, and credentials come from `DROP_*` environment variables —
see the repo `README.md` for self-hosting and the design rationale. This file is
how to *use* the tool correctly.

## Commands

```bash
drop path/to/artifact                          # private: password-protected (the default)
drop --client "Acme" path/to/report            # password, readable slug "acme-…"
drop --unlisted --client "Acme" path/to/report # secret link: no password, unguessable URL
drop --public path/to/site                     # truly public: no password, guessable URL
drop --password "$pw" --expire 7d path/to/site # explicit password + 7-day expiry
drop --slug acme-proposal --password "$pw" path/to/report   # republish IN PLACE (same URL)
drop --public --card-title "Q3 Deck" path/site # override the link-preview card title
drop --public --no-card path/to/site           # skip the card and the preview meta tags
drop --dry-run path/to/site                    # preflight + print the manifest, upload nothing
drop list                                      # every share, with a views=N column
drop views <slug>                              # who opened it: count + recent timestamps / IPs / UAs
drop revoke <slug>                             # deny + delete the objects (cache purge if configured)
drop scope-test                                # blast-radius self-check on the upload creds
```

A private share prints the URL and a generated password. Send the password
out-of-band — not in the same message as the link.

## Visibility tiers

| Tier | Flag | Auth | URL | Use it for |
|------|------|------|-----|-----------|
| **Private** (default) | *(none)* | password | clean readable `…/acme-proposal/` | drafts, anything you'll gate |
| **Unlisted** | `--unlisted` | none | readable + ~82-bit tail `…/acme-proposal-k7f3m9q2x8p4n6tz/` | frictionless but not enumerable — the link *is* the key |
| **Public** | `--public` | none | clean readable `…/demo/` | content meant to be discoverable |

Password-protected is the default: the slug is only a label, the password is the
lock, so a guessable name leaks no content. It does leak *existence* — a live
password share answers with a labeled login page where an unknown slug 404s, so
don't put anything into a label you wouldn't show a stranger. `--unlisted` trades
the password for an
unguessable slug tail — treat that URL as a capability, and don't use the tier
for anything you'd want truly private. Pair any tier with `--expire 7d` and
`drop revoke <slug>` for a time-boxed share.

`--password` on a `--public` or `--unlisted` run is refused rather than silently
ignored, because a flag that looks like a lock and isn't one is worse than no
flag at all.

## Before anything uploads: the preflight

Every publish is gated by a local scan before a single byte leaves the machine:

- **`gitleaks` content scan** blocks secrets. It is **required** — the preflight
  refuses to run without it. Override with `--allow-secret "<reason>"`, which is
  logged into the audit trail.
- **Dangerous filenames** (dotenv files, `*.pem`, `id_rsa`, credential paths) are
  refused by name.
- **High-confidence PII** blocks unless overridden with `--allow-pii "<reason>"`.
- **Images** are OCR-scanned with `tesseract` when it's available; otherwise you
  must accept the limitation (`--confirm-image-limitation`) after looking at them
  yourself.
- **Trackers** (external scripts, tracking pixels) warn; **archives** (`.zip`,
  `.tar`, …) are blocked outright; a **symlink** resolving outside the publish
  root is refused.
- A **final confirmation** reminds you the artifact is public. `--yes` skips it
  in automation.

`--dry-run` runs the whole preflight and prints the manifest without uploading —
the file list, the per-file digests, and the URL. One gap: it never calls the
admin API, so it doesn't resolve the clash suffix. An auto-named dry run prints
`…/report/` while the real publish may land on `…/report-2/`, taking the injected
og URLs and that page's digest with it. Pass an explicit `--slug` when the
dry-run output has to match the publish exactly.

## Slugs and URLs

Shares live at `<DROP_BASE_URL>/<slug>/`. The slug comes from `--client` or
`--label`, or the artifact's own file/dir name (`report.html` → `report`),
lowercased, hyphen-joined, capped at 40 characters.

On a clash the CLI appends `-2`, `-3`, … rather than a random id — and **every**
existing share counts as taken, including expired and revoked ones, so an
auto-named publish never silently overwrites something you published before.

An explicit `--slug` is the deliberate exception. It is the update verb.

## Republishing in place (one stable URL)

There is no `update` subcommand; `--slug` is it. An explicit slug skips the
uniqueness resolver, so there's no `-2` suffix — the bytes upload onto that
slug's own prefix and the manifest upsert updates the row already sitting there,
clearing any revocation. `created_at` and the view history survive.

```bash
drop --slug quarterly-report --password "$pw" --yes build/report.html
```

Four things to know before rerunning it:

- **Pass every flag again, every time.** The manifest is rebuilt from this run's
  flags alone — nothing merges with the row you're replacing. Omit `--password`
  and the CLI mints a fresh random one; omit `--expire` and the expiry clears;
  omit `--client`/`--label` and the label clears; omit `--public` and a public
  share silently reverts to password-gated.
- **No republish keeps recipients logged in.** The password verifier takes a
  fresh random salt on every publish — same password, different hash — and the
  login cookie is a MAC over slug + verifier hash, so every live cookie dies.
  Passing the same `--password` preserves the password they already have; it
  does not spare them the login page.
- **`--slug` is unvalidated.** No existence check, no format check. A typo
  doesn't fail — it silently mints a new share at the misspelled URL while the
  real one goes stale. Worse, the Worker only routes a slug of 2–128 characters
  that starts alphanumeric and is otherwise `[a-z0-9._-]`; a value outside that
  shape still uploads the objects and writes the row, and then every request to
  it 404s. Copy the slug out of `drop list`; don't retype it.
- **`--slug` and `--unlisted` are mutually exclusive.** The CLI refuses the
  combination, because a fixed slug defeats the unguessable tail. To republish an
  existing unlisted share, pass its full secret slug plus `--public`.

A republish does not purge R2; only `drop revoke` does. Rebuilding with fewer
files leaves the removed objects in the bucket, but they stop serving — the
Worker gates every request against the current manifest's file list.

## The footgun: never fake an update with `/admin/manifest`

R2 objects are keyed `<slug>/<path>`, and the Worker derives that key from the
**requested** slug. A manifest row is metadata only — auth mode, file list, sha,
byte count. It carries no pointer to where the bytes live, so **no amount of
manifest surgery can make one slug serve another slug's bytes.**

That makes the tempting pattern —

1. publish to a temp slug,
2. `POST /admin/manifest` to graft that manifest onto the stable slug,
3. `drop revoke <temp>` to tidy up

— a content destroyer. Step 2 repoints nothing; the stable slug still reads from
`<stable>/`. Step 3 then deletes every object under `<temp>/` (revoke lists the
whole prefix and deletes it). What's left is a stable slug whose manifest
advertises a build that lives nowhere: 404 for every path the old prefix doesn't
happen to still hold, and the *previous* build's bytes, served silently as if
fresh, for every path it does. The tell in `drop list` is a long tail of revoked
`<slug>-tmp-*` rows.

Use `--slug`. Hand-call `/admin/manifest` only to change metadata on bytes that
are already uploaded under that same slug.

## Verifying a publish — a 200 proves nothing

On a password share, `curl` against the URL returns **200 for as long as the
manifest row is live — whether or not the bytes behind it still exist.** The
Worker checks auth before it ever looks in R2, so an unauthenticated request gets
the login page (200, ~2.5 KB) and never reaches the missing object; `curl -f`
won't save you. Only the failures that precede auth are visible unauthenticated:
an unknown slug 404s, a revoked or expired share 403s. A destroyed publish looks
exactly like a healthy one, and its 404 appears only once you're past the gate.

So verify past the gate — and compare against the *published* build, not the file
on disk. Any share containing HTML goes through staging first
(`stage_publish_set` in `cli/drop`), which on the default path adds og:/twitter:
meta, renames a lone HTML file to `index.html`, and uploads an extra `og.png` —
plus a `<meta charset="utf-8">` on any page that declares no encoding. So the
served entry page is usually **not** byte-identical to the file you built. (The
exceptions: `--no-card` leaves an already-charset-declaring page untouched, HTML
that isn't valid UTF-8 is copied through byte-for-byte with a warning, and a
share with no HTML in it skips staging entirely.)

The post-staging digest is what to assert against, and `--dry-run` prints it —
the manifest is built from the staged set, so the same flags reproduce the same
sha (pass the same `--slug`; the injected og URLs embed it). The entry is
`index.html` on the default path — with `--no-card` a lone file keeps its own
name, so match whichever manifest path the root actually serves:

```bash
url=https://drop.example.com/$slug/
sha256() { shasum -a 256 "$1" 2>/dev/null || sha256sum "$1"; }   # macOS / Linux

expect=$(drop --slug "$slug" --password "$pw" --dry-run --yes build/report.html \
  | python3 -c 'import json,sys; m=json.load(sys.stdin)["manifest"]
print(next(f["sha256"] for f in m["files"] if f["path"]=="index.html"))')

# Basic auth — the username is ignored, only the password is checked.
# Fetch to a file first: piping curl into the hasher hides curl's exit status,
# so a transport failure would read as a content mismatch.
body=$(mktemp)
curl -fsS -u "x:$pw" "$url" -o "$body" || { echo "fetch failed" >&2; exit 1; }
got=$(sha256 "$body" | cut -d' ' -f1)

[ "$got" = "$expect" ] || { echo "served content is not this build" >&2; exit 1; }
```

For the browser path (or to check the cookie itself), POST the login form and
capture `drop_auth` off the `set-cookie` header. **Fail on an empty cookie before
you fetch** — a wrong password returns the same 200 gate with no `Set-Cookie`, so
a `curl -f` carrying an empty cookie sails through it:

```bash
cookie=$(curl -s -i -X POST "$url" --data-urlencode "password=$pw" \
  | sed -n 's/^[Ss]et-[Cc]ookie: \(drop_auth=[^;]*\).*/\1/p')
[ -n "$cookie" ] || { echo "login failed — no cookie issued" >&2; exit 1; }

curl -fsS -H "Cookie: $cookie" "$url" -o "$body" || { echo "fetch failed" >&2; exit 1; }
got=$(sha256 "$body" | cut -d' ' -f1)
[ "$got" = "$expect" ] || { echo "served content is not this build" >&2; exit 1; }
```

Size alone is not an oracle, in either direction: a byte floor passes a stale
build, and a small report can be smaller than a gate page. If you do want a cheap
smoke check, `curl -w '%{size_download}'` past the gate makes the gap obvious —
a login gate is a couple of KB where a real report is usually hundreds — but the
sha is the check.

Nor does the root URL say anything about the rest of a multi-file share. A
republish writes each object to R2 before the manifest upsert, with no rollback
and no byte-level check against the manifest sha, so a half-failed run leaves a
mixed build that only a per-asset fetch will catch. The dry-run manifest lists
every path; walk them when the share is more than one page.

## Password shares: the login page

A password share serves a clean, self-contained HTML login page — one password
field and a **View** button — not the browser's two-field Basic-Auth dialog. It
carries no external assets, is `noindex`, and shows only the share's label. On
the correct password the Worker sets a stateless, signed, HttpOnly cookie scoped
to that share's path, so the recipient isn't re-prompted on every asset.

Non-browser clients keep using Basic Auth: `curl -u anything:<password>
https://drop.example.com/<slug>/` works, since the username is ignored and only
the password is checked. `--public` and `--unlisted` shares skip the page.

## View tracking

Each time a share's document is opened, the Worker logs one `view` — one row per
page open, never per asset — with the timestamp, client IP, and a truncated
User-Agent. Same-IP refreshes are deduped within 30 minutes.

```bash
drop list            # a views=N column per share
drop views <slug>    # the total plus recent opens (timestamp / IP / UA)
```

## Link previews

For any share containing an HTML page, `drop` generates a 1200×630 landscape
card at publish time, uploads it as `<slug>/og.png`, and injects `og:`/`twitter:`
meta into the published HTML — so a shared link renders as a card instead of a
skinny screenshot of a tall page. The card title defaults to the page `<title>`;
`--card-title`, `--card-bg`, `--card-fg`, and `--card-accent` override it, and
`--no-card` opts out.

These rewrites happen in a temp staging copy. Your source files are never
modified.
