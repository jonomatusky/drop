#!/usr/bin/env python3
"""Tests for the drop CLI's link-preview card: PNG encoder, bitmap font, meta
injection, and the title/description/color helpers.

Run: python3 cli/test/card.test.py   (no third-party deps)
"""

import importlib.machinery
import importlib.util
import struct
import sys
import tempfile
import zlib
from pathlib import Path

# The CLI is a single executable file named `drop` (no .py extension), so load it
# by path. Importing only defines symbols — main() is guarded by __main__.
_CLI = Path(__file__).resolve().parents[1] / "drop"
_loader = importlib.machinery.SourceFileLoader("drop_cli", str(_CLI))
_spec = importlib.util.spec_from_loader("drop_cli", _loader)
drop = importlib.util.module_from_spec(_spec)
_loader.exec_module(drop)

passed = 0


def check(name, condition):
    global passed
    if condition:
        passed += 1
        print(f"  ok   {name}")
    else:
        print(f"  FAIL {name}")
        raise SystemExit(1)


def png_dimensions(data):
    """Parse width/height from a PNG IHDR and assert the IDAT decompresses to the
    expected raw size, without any image library."""
    assert data[:8] == b"\x89PNG\r\n\x1a\n", "bad PNG signature"
    width, height = struct.unpack(">II", data[16:24])
    # Walk chunks, concatenate IDAT payloads.
    idat = bytearray()
    pos = 8
    while pos < len(data):
        length = struct.unpack(">I", data[pos : pos + 4])[0]
        tag = data[pos + 4 : pos + 8]
        payload = data[pos + 8 : pos + 8 + length]
        if tag == b"IDAT":
            idat += payload
        pos += 12 + length
    raw = zlib.decompress(bytes(idat))
    assert len(raw) == height * (1 + width * 3), "decompressed size mismatch"
    return width, height


print("font")
check("printable ASCII glyph count is 95 (0x20..0x7E)", len(drop._OG_FONT) == 95)
check("each glyph is 8 rows", all(len(g) == 8 for g in drop._OG_FONT))
# 'A' (0x41) renders a recognizable shape: its third row has set pixels.
A = drop._og_glyph("A")
check("'A' glyph is non-blank", any(A))
check("space glyph is blank", not any(drop._og_glyph(" ")))
check("out-of-range char falls back to '?'", drop._og_glyph("☃") == drop._og_glyph("?"))

print("png encoder + card")
png = drop.render_og_card("Hello World", "drop.example.com/hello", bg=(11, 13, 18), fg=(232, 235, 242), accent=(122, 162, 255))
w, h = png_dimensions(png)
check("card is 1200x630", (w, h) == (1200, 630))
check("card bytes look like a PNG", png[:4] == b"\x89PNG")
long_title = "A very long title that should wrap across several lines " * 4
png2 = drop.render_og_card(long_title, "drop.example.com/x", bg=(0, 0, 0), fg=(255, 255, 255), accent=(255, 0, 0))
check("long title still renders a valid 1200x630 PNG", png_dimensions(png2) == (1200, 630))

print("colors")
check("#rrggbb parses", drop._parse_hex_color("#0b0d12", None) == (11, 13, 18))
check("rrggbb without hash parses", drop._parse_hex_color("0b0d12", None) == (11, 13, 18))
check("#rgb shorthand expands", drop._parse_hex_color("#abc", None) == (0xAA, 0xBB, 0xCC))
check("None returns the default", drop._parse_hex_color(None, (1, 2, 3)) == (1, 2, 3))
try:
    drop._parse_hex_color("nope", None)
    check("invalid color raises", False)
except drop.PublishError:
    check("invalid color raises", True)

print("title / description extraction")
doc = '<html><head><title>  Hello &amp; Welcome\n</title><meta name="description" content="A nice &quot;page&quot;"></head><body>x</body></html>'
check("title extracted + unescaped + collapsed", drop.extract_title(doc) == "Hello & Welcome")
check("description extracted + unescaped", drop.extract_description(doc) == 'A nice "page"')
check("missing title -> None", drop.extract_title("<html><head></head></html>") is None)

print("meta injection")
src = "<html><head><title>T</title></head><body>hi</body></html>"
out = drop.inject_og_meta(src, title="My Title", description="My desc", image_url="https://h/s/og.png", page_url="https://h/s/")
check("og:image injected", 'property="og:image" content="https://h/s/og.png"' in out)
check("twitter summary_large_image injected", 'name="twitter:card" content="summary_large_image"' in out)
check("og:description injected", 'property="og:description" content="My desc"' in out)
check("block sits before </head>", out.index(drop._OG_BLOCK_START) < out.index("</head>"))
check("original body preserved", "<body>hi</body>" in out)
# Idempotency: re-injecting replaces, does not stack.
out2 = drop.inject_og_meta(out, title="My Title", description="My desc", image_url="https://h/s/og.png", page_url="https://h/s/")
check("re-inject keeps exactly one block", out2.count(drop._OG_BLOCK_START) == 1)
check("attribute values are escaped", 'content="&quot;Quoted&quot;"' in drop.inject_og_meta(src, title='"Quoted"', description=None, image_url="i", page_url="p"))
# No <head>: block still ends up in the document.
nohead = drop.inject_og_meta("<html><body>x</body></html>", title="T", description=None, image_url="i", page_url="p")
check("injects even without a <head>", drop._OG_BLOCK_START in nohead)

print("slug prettify")
check("random tail stripped + title-cased", drop._prettify_slug("how-jono-ai-works-r4lqf6t7nt27drdt") == "How Jono Ai Works")
check("plain slug prettified", drop._prettify_slug("acme-proposal") == "Acme Proposal")

print("charset declaration detection")
check("modern <meta charset> detected", drop.declares_charset('<head><meta charset="utf-8"></head>'))
check("unquoted charset detected", drop.declares_charset("<head><meta charset=utf-8></head>"))
check("single-quoted charset detected", drop.declares_charset("<head><meta charset='UTF-8'></head>"))
check(
    "legacy http-equiv Content-Type detected",
    drop.declares_charset('<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">'),
)
check("no declaration -> False", not drop.declares_charset("<html><head><title>T</title></head></html>"))
check("charset in body text is not a declaration", not drop.declares_charset("<p>the charset = utf-8 setting</p>"))

print("charset injection")
out = drop.inject_charset_meta("<html><head><title>T</title></head><body>hi</body></html>")
check("meta charset injected", '<meta charset="utf-8">' in out)
check("injected first in <head>, before the title", out.index('<meta charset="utf-8">') < out.index("<title>"))
check("lands well inside the 1024-byte prescan window", out.index('<meta charset="utf-8">') < 1024)
check("body preserved", "<body>hi</body>" in out)
# An author's own declaration is never overwritten — including a non-UTF-8 one.
latin = '<html><head><meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1"></head></html>'
check("existing declaration left alone", drop.inject_charset_meta(latin) == latin)
already = '<html><head><meta charset="utf-8"><title>T</title></head></html>'
check("idempotent: no second charset meta", drop.inject_charset_meta(already).count("charset=") == 1)
# Documents that do not have a <head> still get the tag, in a position that counts.
nohead = drop.inject_charset_meta("<!DOCTYPE html>\n<html><body>x</body></html>")
check("no <head>: injected after the doctype", nohead.index("<!DOCTYPE html>") < nohead.index('<meta charset="utf-8">'))
check("no <head>: injected before the content", nohead.index('<meta charset="utf-8">') < nohead.index("<body>"))
bare = drop.inject_charset_meta("<p>hi</p>")
check("no doctype and no head: tag leads the document", bare.startswith('<meta charset="utf-8">'))

print("upload content types carry a charset")
check("html gets utf-8", drop.content_type_for("index.html") == "text/html; charset=utf-8")
check("css gets utf-8", drop.content_type_for("a/style.css") == "text/css; charset=utf-8")
check("js gets utf-8", "charset=utf-8" in drop.content_type_for("app.js"))
check("json gets utf-8", "charset=utf-8" in drop.content_type_for("data.json"))
check("svg gets utf-8", "charset=utf-8" in drop.content_type_for("logo.svg"))
check("png does NOT get a charset", drop.content_type_for("og.png") == "image/png")
check("pdf does NOT get a charset", drop.content_type_for("deck.pdf") == "application/pdf")
check("unknown extension falls back to octet-stream", drop.content_type_for("x.unknownext") == "application/octet-stream")

print("staging (stage_publish_set)")


class _Args:
    card_title = None
    card_bg = None
    card_fg = None
    card_accent = None
    client = None
    label = None
    no_card = False


class _NoCardArgs(_Args):
    no_card = True


with tempfile.TemporaryDirectory() as d:
    root = Path(d)
    (root / "index.html").write_text("<html><head><title>Doc</title></head><body>hi</body></html>")
    (root / "style.css").write_text("body{color:red}")
    files = [(root / "index.html", "index.html"), (root / "style.css", "style.css")]
    staged, tmp, note, warns = drop.stage_publish_set(files, "my-slug", "https://drop.example.com", _Args())
    try:
        rels = {rel for _, rel in staged}
        check("og.png added to staged set", "og.png" in rels)
        check("css passed through unchanged", "style.css" in rels)
        injected = next(p for p, rel in staged if rel == "index.html").read_text()
        check("staged index.html has og:image to the resolved slug", "https://drop.example.com/my-slug/og.png" in injected)
        check("staged index.html also got a charset meta", '<meta charset="utf-8">' in injected)
        check("charset precedes the og block", injected.index('<meta charset="utf-8">') < injected.index(drop._OG_BLOCK_START))
        check("card title defaults to page <title>", note["title"] == "Doc")
        check("og.png on disk is a valid PNG", png_dimensions((Path(tmp.name) / "og.png").read_bytes()) == (1200, 630))
        check("charset fix is reported as a warning", any("charset" in w for w in warns))
    finally:
        tmp.cleanup()

# Single non-index HTML file is staged as index.html so /<slug>/ serves it.
with tempfile.TemporaryDirectory() as d:
    root = Path(d)
    (root / "report.html").write_text("<html><head><title>Report</title></head><body>r</body></html>")
    files = [(root / "report.html", "report.html")]
    staged, tmp, note, _ = drop.stage_publish_set(files, "rep", "https://drop.example.com", _Args())
    try:
        rels = {rel for _, rel in staged}
        check("single html file is staged as index.html", "index.html" in rels and "report.html" not in rels)
    finally:
        tmp.cleanup()

# --no-card still fixes the charset: a saved-to-disk copy has no header to lean on.
with tempfile.TemporaryDirectory() as d:
    root = Path(d)
    (root / "report.html").write_text(
        "<html><head><title>R</title></head><body>“quoted” — dash</body></html>", encoding="utf-8"
    )
    files = [(root / "report.html", "report.html")]
    staged, tmp, note, warns = drop.stage_publish_set(files, "rep", "https://drop.example.com", _NoCardArgs())
    try:
        rels = {rel for _, rel in staged}
        check("--no-card adds no og.png", "og.png" not in rels)
        check("--no-card returns no card note", note is None)
        check("--no-card keeps the original filename", "report.html" in rels)
        page = next(p for p, rel in staged if rel == "report.html").read_text(encoding="utf-8")
        check("--no-card still injects the charset meta", '<meta charset="utf-8">' in page)
        check("--no-card injects no og block", drop._OG_BLOCK_START not in page)
        check("curly quotes and em dash survive the rewrite", "“quoted” — dash" in page)
    finally:
        tmp.cleanup()

# A page that already declares UTF-8 is not touched, and produces no warning.
with tempfile.TemporaryDirectory() as d:
    root = Path(d)
    (root / "index.html").write_text('<html><head><meta charset="utf-8"><title>T</title></head><body>x</body></html>')
    files = [(root / "index.html", "index.html")]
    staged, tmp, note, warns = drop.stage_publish_set(files, "s", "https://drop.example.com", _NoCardArgs())
    try:
        page = next(p for p, rel in staged if rel == "index.html").read_text(encoding="utf-8")
        check("already-declared page keeps exactly one charset meta", page.count("charset=") == 1)
        check("no warning for an already-correct page", warns == [])
    finally:
        tmp.cleanup()

# Non-UTF-8 HTML is published byte-for-byte rather than silently mangled.
with tempfile.TemporaryDirectory() as d:
    root = Path(d)
    raw = "<html><head><title>T</title></head><body>café — dash</body></html>".encode("cp1252")
    (root / "index.html").write_bytes(raw)
    files = [(root / "index.html", "index.html")]
    staged, tmp, note, warns = drop.stage_publish_set(files, "s", "https://drop.example.com", _NoCardArgs())
    try:
        out_bytes = next(p for p, rel in staged if rel == "index.html").read_bytes()
        check("non-UTF-8 HTML is copied byte-for-byte", out_bytes == raw)
        check("non-UTF-8 HTML is warned about", any("UTF-8" in w for w in warns))
    finally:
        tmp.cleanup()

print(f"\n{passed} checks passed")
