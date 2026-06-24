#!/usr/bin/env python3
"""Offline unit tests for the `drop` CLI's list/views commands.

Loads the `drop` script (no .py extension) via SourceFileLoader and stubs the
admin API + secret lookup, so these run with no network and no creds.

Run: python3 cli/test/drop.test.py   (no third-party deps)
"""

import argparse
import contextlib
import io
import sys
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


def main():
    tests = [
        test_list_shows_view_count,
        test_views_prints_count_and_recent_opens,
        test_views_singular_count,
        test_views_requires_a_slug,
    ]
    for test in tests:
        test()
        print(f"ok  {test.__name__}")
    print(f"\n{len(tests)} passed")


if __name__ == "__main__":
    main()
