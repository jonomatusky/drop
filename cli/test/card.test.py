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
    card_image = None
    card_description = None
    card_site_name = None
    card_image_alt = None


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

print("optional preview tags")
src = "<html><head><title>T</title></head><body>hi</body></html>"
out = drop.inject_og_meta(
    src, title="T", description=None, image_url="https://h/s/hero.jpg", page_url="https://h/s/",
    image_size=(800, 400), image_type="image/jpeg", image_alt='A "red" door', site_name="Tokyo Trip",
)
check("og:site_name written", 'property="og:site_name" content="Tokyo Trip"' in out)
check("og:image:alt written and escaped", 'property="og:image:alt" content="A &quot;red&quot; door"' in out)
check("twitter:image:alt written", 'name="twitter:image:alt" content="A &quot;red&quot; door"' in out)
check("og:image:type written", 'property="og:image:type" content="image/jpeg"' in out)
check("real width written", 'property="og:image:width" content="800"' in out)
check("real height written", 'property="og:image:height" content="400"' in out)
bare = drop.inject_og_meta(src, title="T", description=None, image_url="i", page_url="p", image_size=None)
check("unknown size -> no og:image:width", "og:image:width" not in bare)
check("unknown size -> no og:image:height", "og:image:height" not in bare)
check("unset alt -> no alt tags", "image:alt" not in bare)
check("unset site name -> no og:site_name", "og:site_name" not in bare)
check("no type passed -> no og:image:type", "og:image:type" not in bare)
default = drop.inject_og_meta(src, title="T", description=None, image_url="i", page_url="p")
check("generated card keeps its 1200x630 tags", 'content="1200"' in default and 'content="630"' in default)


def make_jpeg(width, height):
    """A minimal JPEG header: SOI, APP0, a fill byte, DHT (a C4 marker that is
    NOT a frame and must be skipped), then a progressive SOF2 frame."""
    app0 = b"\xff\xe0" + struct.pack(">H", 16) + b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    dht = b"\xff\xc4" + struct.pack(">H", 5) + b"\x00\x00\x00"
    sof2 = b"\xff\xc2" + struct.pack(">HBHHB", 11, 8, height, width, 1) + b"\x01\x11\x00"
    return b"\xff\xd8" + app0 + b"\xff" + dht + sof2 + b"\xff\xd9"


def make_gif(width, height):
    return b"GIF89a" + struct.pack("<HH", width, height) + b"\x00\x00\x00;"


def make_webp_vp8x(width, height):
    payload = b"\x00\x00\x00\x00" + (width - 1).to_bytes(3, "little") + (height - 1).to_bytes(3, "little")
    return b"RIFF" + struct.pack("<I", 4 + 8 + len(payload)) + b"WEBP" + b"VP8X" + struct.pack("<I", len(payload)) + payload


print("image dimensions (stdlib header parsing)")
with tempfile.TemporaryDirectory() as d:
    root = Path(d)
    (root / "a.png").write_bytes(drop._png_encode(37, 21, bytearray(37 * 21 * 3)))
    (root / "b.jpg").write_bytes(make_jpeg(1600, 900))
    (root / "c.gif").write_bytes(make_gif(320, 240))
    (root / "d.webp").write_bytes(make_webp_vp8x(1200, 628))
    (root / "e.webp").write_bytes(b"RIFF\x00\x00\x00\x00WEBPjunkjunkjunk")
    (root / "f.jpg").write_bytes(b"\xff\xd8\xff\xe0\x00")  # truncated
    (root / "g.png").write_bytes(b"not an image at all")
    (root / "h.jpg").write_bytes(b"\xff\xd8\xff\xda\x00\x02")  # scan before any frame
    check("PNG IHDR read", drop.image_dimensions(root / "a.png") == (37, 21))
    check("JPEG SOF2 read past APP0, fill byte, and DHT", drop.image_dimensions(root / "b.jpg") == (1600, 900))
    check("GIF header read", drop.image_dimensions(root / "c.gif") == (320, 240))
    check("WebP VP8X canvas read", drop.image_dimensions(root / "d.webp") == (1200, 628))
    check("unknown WebP chunk -> None", drop.image_dimensions(root / "e.webp") is None)
    check("truncated JPEG -> None", drop.image_dimensions(root / "f.jpg") is None)
    check("non-image bytes -> None", drop.image_dimensions(root / "g.png") is None)
    check("JPEG with no frame header -> None", drop.image_dimensions(root / "h.jpg") is None)
    check("missing file -> None", drop.image_dimensions(root / "nope.png") is None)


def card_args(**overrides):
    args = _Args()
    for key, value in overrides.items():
        setattr(args, key, value)
    return args


print("custom card image: external file")
with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as outside:
    root = Path(d)
    (root / "trip.html").write_text('<html><head><title>Tokyo</title><meta name="description" content="page desc"></head><body>t</body></html>')
    hero = Path(outside) / "Hero.JPG"
    hero.write_bytes(make_jpeg(1600, 900))
    files = [(root / "trip.html", "trip.html")]
    args = card_args(card_image=str(hero), card_description="Ten days in Tokyo", card_site_name="Trips", card_image_alt="Shibuya at night")
    staged, tmp, note, warns = drop.stage_publish_set(files, "tokyo", "https://drop.example.com", args)
    try:
        rels = sorted(rel for _, rel in staged)
        check("single HTML still renamed to index.html with an external image", rels == ["index.html", "og.jpg"])
        check("no generated og.png alongside a custom image", "og.png" not in rels)
        page = next(p for p, rel in staged if rel == "index.html").read_text()
        check("og:image points at the staged og.jpg", 'property="og:image" content="https://drop.example.com/tokyo/og.jpg"' in page)
        check("og:image:type is image/jpeg", 'content="image/jpeg"' in page)
        check("real JPEG dims written", 'property="og:image:width" content="1600"' in page and 'property="og:image:height" content="900"' in page)
        check("--card-description overrides the page description", 'property="og:description" content="Ten days in Tokyo"' in page and "page desc" not in page.split(drop._OG_BLOCK_END)[0].split(drop._OG_BLOCK_START)[1])
        check("og:site_name from --card-site-name", 'property="og:site_name" content="Trips"' in page)
        check("og:image:alt from --card-image-alt", 'property="og:image:alt" content="Shibuya at night"' in page)
        check("staged image bytes are the source bytes", (Path(tmp.name) / "og.jpg").read_bytes() == hero.read_bytes())
        check("card note reports the image actually used", note["image"] == "https://drop.example.com/tokyo/og.jpg" and note["image_source"] == "staged")
    finally:
        tmp.cleanup()

print("custom card image: inside the artifact")
with tempfile.TemporaryDirectory() as d:
    root = Path(d)
    (root / "index.html").write_text("<html><head><title>T</title></head><body>x</body></html>")
    (root / "img").mkdir()
    (root / "img" / "hero.gif").write_bytes(make_gif(640, 320))
    files = drop.iter_files(root)
    staged, tmp, note, warns = drop.stage_publish_set(files, "site", "https://drop.example.com", card_args(card_image=str(root / "img" / "hero.gif")))
    try:
        rels = sorted(rel for _, rel in staged)
        check("in-artifact image is referenced, not copied", rels == ["img/hero.gif", "index.html"])
        page = next(p for p, rel in staged if rel == "index.html").read_text()
        check("og:image points at the existing rel", 'property="og:image" content="https://drop.example.com/site/img/hero.gif"' in page)
        check("GIF dims written", 'property="og:image:width" content="640"' in page)
        check("card note marks the artifact source", note["image_source"] == "artifact")
    finally:
        tmp.cleanup()

print("custom card image: unreadable size")
with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as outside:
    root = Path(d)
    (root / "index.html").write_text("<html><head><title>T</title></head><body>x</body></html>")
    odd = Path(outside) / "odd.webp"
    odd.write_bytes(b"RIFF\x00\x00\x00\x00WEBPjunkjunkjunk")
    staged, tmp, note, warns = drop.stage_publish_set([(root / "index.html", "index.html")], "s", "https://drop.example.com", card_args(card_image=str(odd)))
    try:
        page = next(p for p, rel in staged if rel == "index.html").read_text()
        check("unknown dims -> no og:image:width/height", "og:image:width" not in page and "og:image:height" not in page)
        check("unknown dims -> warned", any("size unreadable" in w for w in warns))
        check("webp type still declared", 'content="image/webp"' in page)
    finally:
        tmp.cleanup()

print("custom card image: collision with an artifact file")
with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as outside:
    root = Path(d)
    (root / "index.html").write_text("<html><head><title>T</title></head><body>x</body></html>")
    (root / "og.jpg").write_bytes(make_jpeg(10, 10))
    other = Path(outside) / "other.jpg"
    other.write_bytes(make_jpeg(20, 20))
    try:
        drop.resolve_card_image(str(other), drop.iter_files(root))
        check("external image refused when og.<ext> is taken", False)
    except drop.PublishError as err:
        check("external image refused when og.<ext> is taken", "og.jpg" in str(err))
    try:
        drop.stage_publish_set(drop.iter_files(root), "s", "https://drop.example.com", card_args(card_image=str(other)))
        check("staging refuses the collision too", False)
    except drop.PublishError:
        check("staging refuses the collision too", True)
    # The artifact's own og.jpg is fine: it is referenced in place.
    _, rel, external = drop.resolve_card_image(str(root / "og.jpg"), drop.iter_files(root))
    check("the artifact's own og.jpg is not a collision", rel == "og.jpg" and not external)

print("card flag conflicts (check_card_flags)")
with tempfile.TemporaryDirectory() as outside:
    img = Path(outside) / "hero.png"
    img.write_bytes(drop._png_encode(2, 2, bytearray(12)))
    bad = Path(outside) / "hero.svg"
    bad.write_text("<svg/>")

    def refused_flags(argv, needle):
        args = drop.build_parser().parse_args(argv + ["x.html"])
        try:
            drop.check_card_flags(args)
        except drop.PublishError as err:
            return needle in str(err)
        return False

    for flag, value in (("--card-image", str(img)), ("--card-description", "d"), ("--card-site-name", "s"), ("--card-image-alt", "a")):
        check(f"{flag} refused with --no-card", refused_flags(["--no-card", flag, value], "--no-card"))
    for flag in ("--card-bg", "--card-fg", "--card-accent"):
        check(f"{flag} refused with --card-image", refused_flags(["--card-image", str(img), flag, "#000000"], flag))
    check("--card-image .svg refused", refused_flags(["--card-image", str(bad)], ".png"))
    check("--card-image missing file refused", refused_flags(["--card-image", str(Path(outside) / "none.png")], "not found"))
    ok_args = drop.build_parser().parse_args(["--card-image", str(img), "--card-title", "T", "--card-image-alt", "a", "x.html"])
    drop.check_card_flags(ok_args)
    check("--card-image with title and alt is accepted", True)
    check("colors alone still accepted", not refused_flags(["--card-bg", "#000000"], ""))
    check("--public-preview refused with --no-card", refused_flags(["--public-preview", "--no-card"], "--no-card"))
    check("--public-preview refused with --card-image",
          refused_flags(["--public-preview", "--card-image", str(img)], "only the generated title card"))
    check("--public-preview with card text and colors accepted",
          not refused_flags(["--public-preview", "--card-title", "T", "--card-description", "d", "--card-bg", "#000000"], ""))

print("public preview payload (preview_payload)")
SHA = "0" * 64
CARD_ROWS = [{"path": "index.html", "sha256": "1" * 64}, {"path": "og.png", "sha256": SHA}]
with tempfile.TemporaryDirectory() as d:
    root = Path(d)
    (root / "index.html").write_text('<html><head><title>Doc</title><meta name="description" content="Page desc"></head></html>')
    files = [(root / "index.html", "index.html")]
    staged, tmp, note, _ = drop.stage_publish_set(files, "s", "https://drop.example.com", _Args())
    try:
        _, _, rows = drop.digest_files(staged)
        og_sha = next(r["sha256"] for r in rows if r["path"] == "og.png")
        og_bytes = next(p for p, rel in staged if rel == "og.png").read_bytes()
        check("card note carries the page description", note["description"] == "Page desc")
        check("preview payload is the note's title and description, bound to the staged og.png",
              drop.preview_payload(note, rows)
              == {"title": "Doc", "description": "Page desc", "site_name": None, "image_alt": None, "image_sha256": og_sha})
        check("image_sha256 is the sha256 of the staged card bytes",
              og_sha == __import__("hashlib").sha256(og_bytes).hexdigest())
    finally:
        tmp.cleanup()
    staged, tmp, note, _ = drop.stage_publish_set(
        files, "s", "https://drop.example.com",
        card_args(card_title="T", card_description="D", card_site_name="Acme & Co", card_image_alt="A title card"))
    try:
        _, _, rows = drop.digest_files(staged)
        check("overrides reach the preview payload",
              {k: v for k, v in drop.preview_payload(note, rows).items() if k != "image_sha256"}
              == {"title": "T", "description": "D", "site_name": "Acme & Co", "image_alt": "A title card"})
        page = next(p for p, rel in staged if rel == "index.html").read_text()
        check("the staged page carries the same site name and alt text",
              '<meta property="og:site_name" content="Acme &amp; Co">' in page
              and '<meta property="og:image:alt" content="A title card">' in page
              and '<meta name="twitter:image:alt" content="A title card">' in page)
    finally:
        tmp.cleanup()

    def payload_refused(note, needle, rows=CARD_ROWS):
        try:
            drop.preview_payload(note, rows)
        except drop.PublishError as err:
            return needle in str(err)
        return False

    check("no card note refused", payload_refused(None, "og.png"))
    check("a custom image note refused", payload_refused({"title": "T", "image_source": "staged"}, "og.png"))
    check("no og.png row refused", payload_refused({"title": "T", "image_source": "generated"}, "og.png", rows=CARD_ROWS[:1]))
    check("a blank title refused", payload_refused({"title": "  ", "image_source": "generated"}, "--card-title"))
    check("a BOM-only title refused (JavaScript's trim() strips it)",
          payload_refused({"title": "﻿ ", "image_source": "generated"}, "--card-title"))
    check("a 301-char title refused", payload_refused({"title": "x" * 301, "image_source": "generated"}, "300"))
    check("a 300-char title accepted",
          drop.preview_payload({"title": "x" * 300, "image_source": "generated"}, CARD_ROWS)["title"] == "x" * 300)
    # The Worker counts UTF-16 code units (String.length), not code points.
    check("utf16_length counts an emoji as two units", drop.utf16_length("\U0001F600") == 2)
    check("utf16_length counts a BMP letter as one unit", drop.utf16_length("é") == 1)
    check("150 emoji (300 units) accepted",
          drop.preview_payload({"title": "\U0001F600" * 150, "image_source": "generated"}, CARD_ROWS)["title"] == "\U0001F600" * 150)
    check("151 emoji (151 code points, 302 units) refused before upload",
          payload_refused({"title": "\U0001F600" * 151, "image_source": "generated"}, "302 characters"))
    check("300 accented letters (BMP, 300 units) accepted",
          drop.preview_payload({"title": "é" * 300, "image_source": "generated"}, CARD_ROWS)["title"] == "é" * 300)
    # Site name and alt text: the same 300-unit caps as the Worker, string or null.
    for key, flag in (("site_name", "--card-site-name"), ("image_alt", "--card-image-alt")):
        base = {"title": "T", "image_source": "generated"}
        check(f"{key}: 300 units accepted",
              drop.preview_payload({**base, key: "\U0001F600" * 150}, CARD_ROWS)[key] == "\U0001F600" * 150)
        check(f"{key}: 151 emoji (302 units) refused", payload_refused({**base, key: "\U0001F600" * 151}, f"shorter {flag}"))
        check(f"{key}: 301 ASCII refused", payload_refused({**base, key: "x" * 301}, "301 characters"))
        check(f"{key}: empty is sent as null", drop.preview_payload({**base, key: ""}, CARD_ROWS)[key] is None)
        check(f"{key}: missing is sent as null", drop.preview_payload(base, CARD_ROWS)[key] is None)

print("public preview: card title problems")
check("an ASCII title that fits has no problems", drop.card_title_problems("Project proposal") == [])
problems = drop.card_title_problems("Café plan \U0001F600")
check("a non-ASCII title is one problem", len(problems) == 1)
check("the problem names the undrawable characters", "'é'" in problems[0] and "'\U0001F600'" in problems[0])
check("the problem says they show as ? and asks for an ASCII --card-title",
      '"?"' in problems[0] and "og:title" in problems[0] and "ASCII --card-title" in problems[0])
check("whitespace (tabs, newlines, NBSP) is not undrawable", drop.card_title_problems("A\tB\nC\u00a0D") == [])
long_title = " ".join(["word"] * 120)
check("the renderer clips this title", drop._layout_card_title(long_title)[3] is True)
long_problems = drop.card_title_problems(long_title)
check("a clipped title is a problem",
      len(long_problems) == 1 and "too long" in long_problems[0] and "5 lines" in long_problems[0]
      and "shorter --card-title" in long_problems[0])
# At the smallest scale a line holds 26 characters: five "word"s, five lines.
check("a title that just fits five lines is not clipped",
      drop._layout_card_title(" ".join(["word"] * 25))[3] is False and drop.card_title_problems(" ".join(["word"] * 25)) == [])
check("one more word is clipped", drop._layout_card_title(" ".join(["word"] * 26))[3] is True)
check("both problems are both listed", len(drop.card_title_problems("é " + long_title)) == 2)
# The layout helper is what the renderer uses: same scale and lines as before.
check("layout picks the largest scale for a short title", drop._layout_card_title("Hi")[0] == 11)


def text_refused(text, needle, **arg_overrides):
    args = card_args(allow_pii=None, **arg_overrides)
    try:
        drop.check_public_preview_text({"description": None, "site_name": None, "image_alt": None, **text}, args)
    except drop.PublishError as err:
        return needle in str(err)
    return False


check("check_public_preview_text refuses an undrawable title", text_refused({"title": "Café"}, "ASCII --card-title"))
check("check_public_preview_text refuses a clipped title", text_refused({"title": long_title}, "shorter --card-title"))
check("check_public_preview_text lists both problems", text_refused({"title": "é " + long_title}, "\n  - the title is too long"))

with tempfile.TemporaryDirectory() as d:
    root = Path(d)
    (root / "index.html").write_text('<html><head><meta charset="utf-8"><title>Café</title></head></html>')
    files = [(root / "index.html", "index.html")]
    # Staging no longer warns about the card title: --public-preview refuses
    # before staging instead, and without the flag nothing changes.
    for args in (_Args(), card_args(public_preview=True)):
        staged, tmp, note, warns = drop.stage_publish_set(files, "s", "https://drop.example.com", args)
        tmp.cleanup()
        check("staging adds no card-title warning", not any("ASCII" in w or "too long" in w for w in warns))
    check("public_preview_text resolves the title the staged card uses",
          drop.public_preview_text(files, _Args(), "s")["title"] == "Café")

print(f"\n{passed} checks passed")
