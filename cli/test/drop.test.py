#!/usr/bin/env python3
"""Offline unit tests for the `drop` CLI: list/views output, republish in place
(--slug, --unlisted --slug, `drop update`), and the stale-object purge.

Loads the `drop` script (no .py extension) via SourceFileLoader and stubs the
admin API, R2, the preflight, and secret lookup, so these run with no network
and no creds.

Run: python3 cli/test/drop.test.py   (no third-party deps)
"""

import argparse
import base64
import contextlib
import datetime as dt
import hashlib
import io
import json
import os
import sys
import tempfile
from importlib.machinery import SourceFileLoader
from pathlib import Path

# The CLI is a single executable file named `drop` (no .py extension), so load it
# by path. parents[1] is cli/ (this file lives in cli/test/).
DROP = Path(__file__).resolve().parents[1] / "drop"
drop = SourceFileLoader("drop", str(DROP)).load_module()

# No keychain / env needed: every secret lookup yields a dummy token.
drop.get_secret = lambda env_name, keychain_service, label: "tok"


def test_list_shows_view_count():
    # `drop list` surfaces a views=N column from /admin/list.
    drop.admin_request = lambda method, path, token, payload=None: {
        "shares": [{"slug": "acme", "auth_mode": "password", "bytes": 10, "views": 4}]
    }
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        drop.cmd_list(argparse.Namespace())
    out = buf.getvalue()
    assert "views=4" in out, out
    assert "acme" in out, out


def test_views_prints_count_and_recent_opens():
    # `drop views <slug>` hits /admin/views?slug=… and prints the count + rows
    # (timestamp / IP / UA); a row with no UA still prints.
    def fake(method, path, token, payload=None):
        assert method == "GET", method
        assert "/admin/views?slug=acme" in path, path
        return {
            "slug": "acme",
            "count": 2,
            "views": [
                {"at": "2026-06-23T00:00:00+00:00", "ip": "203.0.113.5", "ua": "curl/8.0"},
                {"at": "2026-06-22T00:00:00+00:00", "ip": "203.0.113.6", "ua": None},
            ],
        }

    drop.admin_request = fake
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        drop.cmd_views(argparse.Namespace(slug="acme"))
    out = buf.getvalue()
    assert "2 views" in out, out
    assert "203.0.113.5" in out and "curl/8.0" in out, out
    assert "203.0.113.6" in out, out


def test_views_singular_count():
    # Count of 1 reads "1 view" (not "1 views").
    drop.admin_request = lambda method, path, token, payload=None: {
        "slug": "acme", "count": 1, "views": [{"at": "t", "ip": "1.2.3.4", "ua": None}],
    }
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        drop.cmd_views(argparse.Namespace(slug="acme"))
    assert "1 view" in buf.getvalue() and "1 views" not in buf.getvalue(), buf.getvalue()


def test_views_requires_a_slug():
    # `drop views` with no slug exits non-zero with a usage message (on stderr).
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            drop.main(["views"])
    except SystemExit as exc:
        assert exc.code == 2, exc.code
    else:
        raise AssertionError("`drop views` with no slug should have exited")


# --- Republish harness -------------------------------------------------------
#
# Everything below drives the real publish path end to end (argv parsing,
# guards, staging, digesting, manifest building) with the network edges stubbed.
# Each fake records into one ordered event log, so a test can assert not just
# what was called but in what order (e.g. the lookup before the slow preflight).

os.environ["DROP_BASE_URL"] = "https://drop.example.com"
os.environ["DROP_CF_ACCOUNT_ID"] = "acct"
os.environ["DROP_R2_BUCKET"] = "drop-artifacts"

NOW = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
FUTURE = (NOW + dt.timedelta(days=5)).isoformat()
PAST = (NOW - dt.timedelta(days=1)).isoformat()

UNLISTED = "acme-k7f3m9q2x8p4n6tz"  # real unlisted shape: 16 base36 chars with digits

_ARTIFACTS = tempfile.TemporaryDirectory(prefix="drop-test-")
PAGE = Path(_ARTIFACTS.name) / "page.html"
PAGE.write_text('<html><head><meta charset="utf-8"><title>Page</title></head><body>hi</body></html>')

S3_NS = "http://s3.amazonaws.com/doc/2006-03-01/"


def list_xml(keys, token=None, ns=S3_NS):
    xmlns = f' xmlns="{ns}"' if ns else ""
    contents = "".join(f"<Contents><Key>{k}</Key><Size>1</Size></Contents>" for k in keys)
    trunc = "true" if token else "false"
    tok = f"<NextContinuationToken>{token}</NextContinuationToken>" if token else ""
    return (
        f'<?xml version="1.0" encoding="UTF-8"?><ListBucketResult{xmlns}><Name>drop-artifacts</Name>'
        f"<KeyCount>{len(keys)}</KeyCount><IsTruncated>{trunc}</IsTruncated>{tok}{contents}</ListBucketResult>"
    ).encode()


def row(slug, auth_mode="public", label=None, expires_at=None, revoked_at=None):
    return {
        "slug": slug, "label": label, "auth_mode": auth_mode, "expires_at": expires_at,
        "revoked_at": revoked_at, "created_at": PAST, "files": [], "bytes": 1, "views": 0,
    }


class Fake:
    """Stands in for the admin API, R2, and the preflight; records calls in order."""

    def __init__(self, rows=(), bucket_keys=(), s3=None):
        self.rows = list(rows)
        self.bucket_keys = list(bucket_keys)
        self.s3_handler = s3
        self.events = []
        self.manifests = []
        self.uploads = []
        self.deletes = []
        self.preflight_files = []

    def admin_request(self, method, path, token, payload=None):
        self.events.append(("admin", method, path))
        if path == "/admin/list":
            return {"shares": self.rows}
        if path == "/admin/manifest":
            self.manifests.append(payload)
            return {"ok": True, "slug": payload["slug"]}
        raise AssertionError(f"unexpected admin call {method} {path}")

    def upload_r2(self, files, slug):
        self.events.append(("upload", slug))
        self.uploads.append((slug, sorted(rel for _, rel in files)))

    def preflight(self, path, files, args):
        self.events.append(("preflight",))
        self.preflight_files.append([rel for _, rel in files])
        return {"status": "passed", "warnings": [], "gitleaks_findings": 0, "secret_filename_hits": [],
                "ocr_scanned": [], "image_limitation_accepted": False, "override_log": []}

    def s3_request(self, method, bucket, key="", *, body=b"", query="", content_type=None, timeout=60):
        self.events.append(("s3", method, key, query))
        if self.s3_handler:
            return self.s3_handler(method, bucket, key, query)
        if method == "GET":
            return 200, list_xml(self.bucket_keys)
        if method == "DELETE":
            self.deletes.append(key)
            return 204, b""
        raise AssertionError(f"unexpected s3 call {method} {key}")

    def kinds(self):
        return [event[0] for event in self.events]

    def index(self, kind):
        return self.kinds().index(kind)


@contextlib.contextmanager
def faked(fake):
    names = ("admin_request", "upload_r2", "preflight", "s3_request")
    saved = {name: getattr(drop, name) for name in names}
    for name in names:
        setattr(drop, name, getattr(fake, name))
    try:
        yield fake
    finally:
        for name, value in saved.items():
            setattr(drop, name, value)


def run_cli(argv, fake):
    """Run drop.main(argv) under the fake; return (exit code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    code = 0
    with faked(fake), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = drop.main(argv)
        except SystemExit as exc:
            code = exc.code
    return code, out.getvalue(), err.getvalue()


def refused(argv, fake, needle):
    code, out, err = run_cli(argv, fake)
    assert code == 1, (code, out, err)
    assert needle in err, err
    # Every refusal is a cheap one: nothing was scanned, uploaded, or written.
    assert "preflight" not in fake.kinds() and "upload" not in fake.kinds(), fake.events
    assert not fake.manifests, fake.manifests
    return err


# --- looks_unlisted ------------------------------------------------------------


def test_looks_unlisted_cases():
    assert drop.looks_unlisted(UNLISTED)
    assert drop.looks_unlisted("how-jono-ai-works-r4lqf6t7nt27drdt")
    assert not drop.looks_unlisted("acme-proposal")  # no tail at all
    assert not drop.looks_unlisted("acme-characterization")  # 16-letter word: no digit
    assert not drop.looks_unlisted("acme-k7f3m9q2x8p4n6t")  # 15 chars
    assert not drop.looks_unlisted("acme-k7f3m9q2x8p4n6tzz")  # 17 chars
    assert not drop.looks_unlisted("acme-K7F3M9Q2X8P4N6TZ")  # uppercase is not the alphabet
    assert not drop.looks_unlisted("acme-k7f3m9q2_8p4n6tz")  # stray char
    assert not drop.looks_unlisted("k7f3m9q2x8p4n6tz")  # no readable base / hyphen
    assert not drop.looks_unlisted("-k7f3m9q2x8p4n6tz")


def test_looks_unlisted_accepts_generated_secret_slugs():
    # A generated tail is all letters ~0.55% of the time, so over 500 draws we
    # expect ~3 rejections; 25 is a bound a correct rule never gets near, while a
    # rule that rejected real tails would blow straight through it.
    slugs = [drop.generated_slug("Acme Proposal", secret=True) for _ in range(500)]
    rejected = [s for s in slugs if not drop.looks_unlisted(s)]
    assert len(rejected) < 25, rejected
    # And every rejection is exactly the all-letters case the digit rule targets.
    assert all(not any(c.isdigit() for c in s.rsplit("-", 1)[1]) for s in rejected), rejected
    with_digit = next(s for s in slugs if any(c.isdigit() for c in s.rsplit("-", 1)[1]))
    assert drop.looks_unlisted(with_digit), with_digit


# --- --slug + --unlisted ---------------------------------------------------------


def test_unlisted_slug_allowed_for_live_unlisted_share():
    fake = Fake(rows=[row(UNLISTED), row("other")])
    code, out, err = run_cli(["--unlisted", "--slug", UNLISTED, "--yes", str(PAGE)], fake)
    assert code == 0, (out, err)
    manifest = fake.manifests[0]
    assert manifest["slug"] == UNLISTED and manifest["auth_mode"] == "public", manifest
    assert "password_verifier" not in manifest, manifest
    assert fake.uploads[0][0] == UNLISTED, fake.uploads
    # The lookup comes first: before the preflight, and so before any upload.
    assert fake.events[0] == ("admin", "GET", "/admin/list"), fake.events
    assert fake.index("admin") < fake.index("preflight") < fake.index("upload"), fake.events
    # Exactly one list call — the lookup. No clash resolver ran.
    assert sum(1 for e in fake.events if e == ("admin", "GET", "/admin/list")) == 1, fake.events
    assert f"url: https://drop.example.com/{UNLISTED}/" in out, out
    assert "password:" not in out, out


def test_unlisted_slug_allowed_in_dry_run_after_lookup():
    fake = Fake(rows=[row(UNLISTED)])
    code, out, err = run_cli(["--unlisted", "--slug", UNLISTED, "--yes", "--dry-run", str(PAGE)], fake)
    assert code == 0, err
    assert fake.events[0] == ("admin", "GET", "/admin/list"), fake.events
    assert "upload" not in fake.kinds() and not fake.manifests, fake.events
    assert "s3" not in fake.kinds(), fake.events  # no purge in a dry run
    data = json.loads(out)
    assert data["dry_run"] and data["manifest"]["slug"] == UNLISTED, data


def test_unlisted_slug_refused_for_unknown_slug():
    refused(["--unlisted", "--slug", "acme-k7f3m9q2x8p4n6tz", "--yes", str(PAGE)], Fake(rows=[]), "unguessable tail")


def test_unlisted_slug_refused_in_dry_run_too():
    refused(["--unlisted", "--slug", UNLISTED, "--yes", "--dry-run", str(PAGE)], Fake(rows=[]), "unguessable tail")


def test_unlisted_slug_refused_for_revoked_share():
    refused(["--unlisted", "--slug", UNLISTED, "--yes", str(PAGE)], Fake(rows=[row(UNLISTED, revoked_at=PAST)]), "revoked")


def test_unlisted_slug_refused_for_expired_share():
    refused(["--unlisted", "--slug", UNLISTED, "--yes", str(PAGE)], Fake(rows=[row(UNLISTED, expires_at=PAST)]), "expired")


def test_unlisted_slug_allowed_for_share_expiring_later():
    fake = Fake(rows=[row(UNLISTED, expires_at=FUTURE)])
    code, out, err = run_cli(["--unlisted", "--slug", UNLISTED, "--yes", str(PAGE)], fake)
    assert code == 0, err
    assert fake.manifests[0]["expires_at"] == FUTURE, fake.manifests


def test_unlisted_slug_refused_for_password_share():
    err = refused(
        ["--unlisted", "--slug", UNLISTED, "--yes", str(PAGE)],
        Fake(rows=[row(UNLISTED, auth_mode="password")]),
        "password share",
    )
    assert "remove its password" in err, err


def test_unlisted_slug_refused_for_public_share_without_tail():
    refused(["--unlisted", "--slug", "acme-proposal", "--yes", str(PAGE)], Fake(rows=[row("acme-proposal")]), "no unguessable tail")


def test_unlisted_slug_refused_for_public_share_with_all_alpha_tail():
    slug = "acme-characterization"
    refused(["--unlisted", "--slug", slug, "--yes", str(PAGE)], Fake(rows=[row(slug)]), "no unguessable tail")


# --- drop update -------------------------------------------------------------------


def test_update_inherits_tier_label_and_expiry():
    fake = Fake(rows=[row(UNLISTED, label="Acme", expires_at=FUTURE)])
    code, out, err = run_cli(["update", UNLISTED, "--yes", str(PAGE)], fake)
    assert code == 0, err
    manifest = fake.manifests[0]
    assert manifest["slug"] == UNLISTED, manifest
    assert manifest["auth_mode"] == "public" and "password_verifier" not in manifest, manifest
    assert manifest["label"] == "Acme", manifest
    assert manifest["expires_at"] == FUTURE, manifest  # the Worker's string, verbatim
    assert fake.uploads[0][0] == UNLISTED, fake.uploads
    assert fake.index("admin") < fake.index("preflight"), fake.events
    assert f"expires: {FUTURE}" in out, out
    assert "password:" not in out, out


def test_update_passed_label_and_expire_win():
    fake = Fake(rows=[row(UNLISTED, label="Acme", expires_at=FUTURE)])
    code, out, err = run_cli(["update", UNLISTED, "--label", "New", "--expire", "1h", "--yes", str(PAGE)], fake)
    assert code == 0, err
    manifest = fake.manifests[0]
    assert manifest["label"] == "New", manifest
    expires = drop.parse_iso(manifest["expires_at"])
    assert NOW < expires <= NOW + dt.timedelta(hours=1, minutes=5), manifest["expires_at"]


def test_update_password_share_with_password_sends_verifier():
    fake = Fake(rows=[row("acme-proposal", auth_mode="password", label="Acme")])
    code, out, err = run_cli(["update", "acme-proposal", "--password", "hunter2hunter2", "--yes", str(PAGE)], fake)
    assert code == 0, err
    manifest = fake.manifests[0]
    assert manifest["auth_mode"] == "password", manifest
    verifier = manifest["password_verifier"]
    digest = hashlib.pbkdf2_hmac("sha256", b"hunter2hunter2", base64.b64decode(verifier["salt"]), verifier["iterations"])
    assert digest.hex() == verifier["hash"], verifier  # the verifier is for THIS password, not a minted one
    assert "password: hunter2hunter2" in out, out


def test_update_password_share_without_password_refused():
    err = refused(["update", "acme-proposal", "--yes", str(PAGE)], Fake(rows=[row("acme-proposal", auth_mode="password")]), "--password")
    assert "lock out" in err, err


def test_update_public_share_with_password_refused():
    refused(["update", UNLISTED, "--password", "x" * 12, "--yes", str(PAGE)], Fake(rows=[row(UNLISTED)]), "no password")


def test_update_refuses_tier_and_slug_flags():
    for flag in (["--public"], ["--unlisted"], ["--slug", "other"]):
        fake = Fake(rows=[row(UNLISTED)])
        refused(["update", UNLISTED, *flag, "--yes", str(PAGE)], fake, "inherited")
        assert not fake.events, fake.events  # refused before even the lookup


def test_update_refuses_unknown_slug():
    refused(["update", "nope", "--yes", str(PAGE)], Fake(rows=[row(UNLISTED)]), "drop list")


def test_update_refuses_revoked_share():
    refused(["update", UNLISTED, "--yes", str(PAGE)], Fake(rows=[row(UNLISTED, revoked_at=PAST)]), "revoke is an ending")


def test_update_refuses_expired_share_without_expire():
    refused(["update", UNLISTED, "--yes", str(PAGE)], Fake(rows=[row(UNLISTED, expires_at=PAST)]), "--expire")


def test_update_expired_share_with_expire_ok():
    fake = Fake(rows=[row(UNLISTED, expires_at=PAST)])
    code, out, err = run_cli(["update", UNLISTED, "--expire", "2d", "--yes", str(PAGE)], fake)
    assert code == 0, err
    assert drop.parse_iso(fake.manifests[0]["expires_at"]) > NOW, fake.manifests


def test_update_dry_run_looks_up_and_uploads_nothing():
    fake = Fake(rows=[row(UNLISTED, label="Acme", expires_at=FUTURE)])
    code, out, err = run_cli(["update", UNLISTED, "--dry-run", "--yes", str(PAGE)], fake)
    assert code == 0, err
    assert fake.events[0] == ("admin", "GET", "/admin/list"), fake.events
    assert "upload" not in fake.kinds() and "s3" not in fake.kinds() and not fake.manifests, fake.events
    data = json.loads(out)
    assert data["manifest"]["label"] == "Acme" and data["manifest"]["expires_at"] == FUTURE, data


def test_update_card_title_falls_back_to_inherited_label():
    untitled = Path(_ARTIFACTS.name) / "untitled.html"
    untitled.write_text('<html><head><meta charset="utf-8"></head><body>x</body></html>')
    fake = Fake(rows=[row(UNLISTED, label="Acme Board")])
    code, out, err = run_cli(["update", UNLISTED, "--dry-run", "--yes", str(untitled)], fake)
    assert code == 0, err
    assert json.loads(out)["card"]["title"] == "Acme Board", out


def test_update_usage_errors():
    for argv in (["update"], ["update", "--yes", str(PAGE)], ["update", UNLISTED]):
        code, out, err = run_cli(argv, Fake())
        assert code == 2, (argv, code, err)
        assert "usage: drop update" in err, err


# --- plain --slug inherits expiry ----------------------------------------------


def test_plain_slug_inherits_future_expiry():
    fake = Fake(rows=[row("demo", expires_at=FUTURE)])
    code, out, err = run_cli(["--public", "--slug", "demo", "--yes", str(PAGE)], fake)
    assert code == 0, err
    assert fake.manifests[0]["expires_at"] == FUTURE, fake.manifests
    assert f"expires: {FUTURE}" in out, out


def test_plain_slug_drops_past_expiry_with_warning():
    fake = Fake(rows=[row("demo", expires_at=PAST)])
    code, out, err = run_cli(["--public", "--slug", "demo", "--yes", str(PAGE)], fake)
    assert code == 0, err
    assert fake.manifests[0]["expires_at"] is None, fake.manifests
    assert "expires:" not in out, out
    assert "had expired" in err, err


def test_plain_slug_expire_flag_wins():
    fake = Fake(rows=[row("demo", expires_at=FUTURE)])
    code, out, err = run_cli(["--public", "--slug", "demo", "--expire", "1h", "--yes", str(PAGE)], fake)
    assert code == 0, err
    assert fake.manifests[0]["expires_at"] != FUTURE, fake.manifests


def test_plain_slug_new_share_still_allowed():
    # Plain --slug keeps its old contract: an unknown slug publishes a new share.
    fake = Fake(rows=[])
    code, out, err = run_cli(["--public", "--slug", "brand-new", "--yes", str(PAGE)], fake)
    assert code == 0, err
    assert fake.manifests[0]["slug"] == "brand-new" and fake.manifests[0]["expires_at"] is None


def test_plain_slug_dry_run_inherits_too():
    fake = Fake(rows=[row("demo", expires_at=FUTURE)])
    code, out, err = run_cli(["--public", "--slug", "demo", "--dry-run", "--yes", str(PAGE)], fake)
    assert code == 0, err
    assert json.loads(out)["manifest"]["expires_at"] == FUTURE, out


def test_fresh_publish_has_no_lookup_before_preflight():
    # A fresh auto-named publish keeps its old order: preflight, then the clash
    # resolver's list call.
    fake = Fake(rows=[row("page")])
    code, out, err = run_cli(["--public", "--yes", str(PAGE)], fake)
    assert code == 0, err
    assert fake.index("preflight") < fake.index("admin"), fake.events
    assert fake.manifests[0]["slug"] == "page-2", fake.manifests


def test_external_card_image_goes_through_preflight():
    image = Path(_ARTIFACTS.name) / "hero.png"
    image.write_bytes(drop._png_encode(4, 2, bytearray(4 * 2 * 3)))
    fake = Fake(rows=[])
    code, out, err = run_cli(["--public", "--card-image", str(image), "--dry-run", "--yes", str(PAGE)], fake)
    assert code == 0, err
    assert fake.preflight_files[0] == ["page.html", "hero.png"], fake.preflight_files
    card = json.loads(out)["card"]
    assert card["image"] == "https://drop.example.com/page/og.png" and card["image_source"] == "staged", card


# --- stale-object purge ----------------------------------------------------------


def test_stale_keys_keeps_new_files_and_other_prefixes():
    keys = ["demo/index.html", "demo/og.png", "demo/old.css", "demo/sub/gone.js", "demo-2/old.css", "demox/a", "other/demo/old.css"]
    stale = drop.stale_keys(keys, "demo", {"index.html", "og.png"})
    assert stale == ["demo/old.css", "demo/sub/gone.js"], stale


def test_s3_query_is_canonical():
    q = drop.s3_query({"prefix": "demo/", "list-type": "2", "continuation-token": "a+b/c=="})
    assert q == "continuation-token=a%2Bb%2Fc%3D%3D&list-type=2&prefix=demo%2F", q


def test_parse_list_objects_namespaced_and_paginated():
    keys, token = drop.parse_list_objects(list_xml(["demo/a", "demo/b"], token="tok1"))
    assert keys == ["demo/a", "demo/b"] and token == "tok1", (keys, token)
    keys, token = drop.parse_list_objects(list_xml(["demo/c"]))
    assert keys == ["demo/c"] and token is None, (keys, token)
    keys, token = drop.parse_list_objects(list_xml(["demo/d"], ns=None))  # no namespace
    assert keys == ["demo/d"] and token is None, (keys, token)
    keys, token = drop.parse_list_objects(list_xml([]))
    assert keys == [] and token is None


def test_parse_list_objects_truncated_without_token_raises():
    body = f'<ListBucketResult xmlns="{S3_NS}"><IsTruncated>true</IsTruncated></ListBucketResult>'.encode()
    try:
        drop.parse_list_objects(body)
    except drop.PublishError:
        pass
    else:
        raise AssertionError("truncated listing with no token should raise")


def test_list_r2_keys_follows_pagination():
    pages = {"": list_xml(["demo/a"], token="t/2"), "t/2": list_xml(["demo/b"])}
    queries = []

    def handler(method, bucket, key, query):
        queries.append(query)
        params = dict(part.split("=", 1) for part in query.split("&"))
        token = drop.urllib.parse.unquote(params.get("continuation-token", ""))
        return 200, pages[token]

    fake = Fake(s3=handler)
    with faked(fake):
        keys = drop.list_r2_keys("drop-artifacts", "demo/")
    assert keys == ["demo/a", "demo/b"], keys
    assert queries == ["list-type=2&prefix=demo%2F", "continuation-token=t%2F2&list-type=2&prefix=demo%2F"], queries


def test_republish_purges_stale_files():
    fake = Fake(rows=[row("demo")], bucket_keys=["demo/index.html", "demo/og.png", "demo/old file.css", "demo-2/x.css"])
    code, out, err = run_cli(["--public", "--slug", "demo", "--yes", str(PAGE)], fake)
    assert code == 0, err
    # Purge runs only after the manifest has landed.
    assert fake.events.index(("admin", "POST", "/admin/manifest")) < fake.index("s3"), fake.events
    assert fake.deletes == ["demo/old%20file.css"], fake.deletes  # encoded; demo-2/ untouched
    assert "purged: 1 stale file" in out, out


def test_update_purges_stale_files():
    fake = Fake(rows=[row(UNLISTED)], bucket_keys=[f"{UNLISTED}/index.html", f"{UNLISTED}/old.js", f"{UNLISTED}/og.png"])
    code, out, err = run_cli(["update", UNLISTED, "--yes", str(PAGE)], fake)
    assert code == 0, err
    assert fake.deletes == [f"{UNLISTED}/old.js"], fake.deletes
    assert "purged: 1 stale file" in out, out


def test_purge_prints_nothing_when_nothing_is_stale():
    fake = Fake(rows=[row("demo")], bucket_keys=["demo/index.html", "demo/og.png"])
    code, out, err = run_cli(["--public", "--slug", "demo", "--yes", str(PAGE)], fake)
    assert code == 0, err
    assert fake.deletes == [] and "purged" not in out, out


def test_purge_list_failure_is_a_warning():
    fake = Fake(rows=[row("demo")], s3=lambda m, b, k, q: (500, b"boom"))
    code, out, err = run_cli(["--public", "--slug", "demo", "--yes", str(PAGE)], fake)
    assert code == 0, err
    assert fake.manifests, "the publish itself must still land"
    assert "purge" in err and "HTTP 500" in err, err
    assert "url: https://drop.example.com/demo/" in out, out


def test_purge_network_error_is_a_warning():
    def boom(method, bucket, key, query):
        raise drop.PublishError("R2 S3 request failed: <urlopen error timed out>")

    fake = Fake(rows=[row("demo")], s3=boom)
    code, out, err = run_cli(["--public", "--slug", "demo", "--yes", str(PAGE)], fake)
    assert code == 0, err
    assert "purge" in err and "timed out" in err, err


def test_purge_delete_failure_is_a_warning():
    def handler(method, bucket, key, query):
        if method == "GET":
            return 200, list_xml(["demo/index.html", "demo/a.css", "demo/b.css"])
        return (204, b"") if key.endswith("a.css") else (403, b"denied")

    fake = Fake(rows=[row("demo")], s3=handler)
    code, out, err = run_cli(["--public", "--slug", "demo", "--yes", str(PAGE)], fake)
    assert code == 0, err
    assert "purged: 1 stale file" in out, out
    assert "could not delete 1 file" in err and "demo/b.css (HTTP 403)" in err, err


def test_purge_skipped_for_fresh_slug():
    fake = Fake(rows=[], bucket_keys=["page/stale.css"])
    code, out, err = run_cli(["--public", "--yes", str(PAGE)], fake)
    assert code == 0, err
    assert "s3" not in fake.kinds(), fake.events


def test_purge_skipped_in_dry_run():
    fake = Fake(rows=[row("demo")], bucket_keys=["demo/stale.css"])
    code, out, err = run_cli(["--public", "--slug", "demo", "--dry-run", "--yes", str(PAGE)], fake)
    assert code == 0, err
    assert "s3" not in fake.kinds(), fake.events


def main():
    tests = [value for name, value in globals().items() if name.startswith("test_") and callable(value)]
    for test in tests:
        test()
        print(f"ok  {test.__name__}")
    print(f"\n{len(tests)} passed")


if __name__ == "__main__":
    main()
