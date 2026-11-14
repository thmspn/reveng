"""Stego: offline hidden-data finder for PNG/BMP (pixel + byte content).

* ``--lsb``     extract least-significant-bit data from pixel samples (PNG/BMP via stdlib
                ``zlib``/``struct``; other formats via optional ``PIL``).
* ``--append``  detect trailing bytes after the image's logical end (PNG IEND, JPEG EOI,
                GIF trailer, BMP declared size).
* ``--carve``   polyglot / embedded-archive scan (reuses ``binextras.MAGICS`` when importable,
                else a local signature table).
* ``--plane``   dump one bit-plane as ASCII art.   ``--palette`` palette anomaly report.

Complements ``forensics`` (metadata). No network, no process execution.

CLI:
    recon.py stego <img> [--lsb] [--append] [--carve] [--palette] [--plane N]
                         [--channels rgba] [--bits N] [--lsb-out FILE]
    recon.py stego selftest
"""
from __future__ import annotations

import argparse
import struct
import sys
import zlib
from typing import Optional

try:  # optional richer decoding
    from PIL import Image  # type: ignore
    HAVE_PIL = True
except ImportError:  # pragma: no cover - depends on host
    Image = None  # type: ignore
    HAVE_PIL = False

try:
    from . import binextras
    _MAGICS = tuple(binextras.MAGICS)
except ImportError:  # pragma: no cover
    try:
        import binextras  # type: ignore
        _MAGICS = tuple(binextras.MAGICS)
    except ImportError:
        binextras = None  # type: ignore
        _MAGICS = (
            ("ELF", b"\x7fELF", 0), ("ZIP", b"PK\x03\x04", 0), ("PNG", b"\x89PNG\r\n\x1a\n", 0),
            ("JPEG", b"\xff\xd8\xff", 0), ("GIF89a", b"GIF89a", 0), ("GZIP", b"\x1f\x8b", 0),
            ("7-Zip", b"7z\xbc\xaf\x27\x1c", 0), ("RAR", b"Rar!\x1a\x07", 0), ("PDF", b"%PDF-", 0),
        )

NAME = "stego"
DESCRIPTION = "Stego: PNG/BMP LSB extract, appended-data finder, polyglot/archive carve, bit-plane + palette report"

MAX_FILE = 64 * 1024 * 1024
MAX_SAMPLES = 128 * 1024 * 1024
PNG_SIG = b"\x89PNG\r\n\x1a\n"


class StegoError(ValueError):
    """Raised for unsupported or malformed images."""


class Image8:
    """Decoded 8-bit image: ``rows`` of raw sample bytes, ``channels`` per pixel, optional palette."""

    def __init__(self, width: int, height: int, channels: str, rows: list[bytes],
                 palette: Optional[list[tuple[int, int, int]]] = None, indexed: bool = False) -> None:
        self.width, self.height, self.channels = width, height, channels
        self.rows, self.palette, self.indexed = rows, palette or [], indexed

    def samples(self) -> bytes:
        """All samples, row-major, channel-interleaved."""
        return b"".join(self.rows)


# --------------------------------------------------------------------------- decoding

def _png_chunks(data: bytes):
    """Yield (type, body, end_offset) for each PNG chunk; stops quietly on truncation."""
    pos = 8
    while pos + 8 <= len(data):
        ln, typ = struct.unpack(">I4s", data[pos:pos + 8])
        end = pos + 12 + ln
        if ln > len(data) or end > len(data):
            return
        yield typ, data[pos + 8:pos + 8 + ln], end
        pos = end
        if typ == b"IEND":
            return


def decode_png(data: bytes) -> Image8:
    """Decode a non-interlaced 8-bit PNG (gray/RGB/palette/gray+alpha/RGBA) with stdlib only."""
    if not data.startswith(PNG_SIG):
        raise StegoError("not a PNG")
    hdr = None
    idat = bytearray()
    plte = b""
    for typ, body, _ in _png_chunks(data):
        if typ == b"IHDR" and len(body) >= 13:
            hdr = struct.unpack(">IIBBBBB", body[:13])
        elif typ == b"PLTE":
            plte = body
        elif typ == b"IDAT":
            idat += body
            if len(idat) > MAX_FILE:
                raise StegoError("IDAT too large")
    if hdr is None:
        raise StegoError("missing IHDR")
    w, h, depth, ctype, _, _, interlace = hdr
    if depth != 8 or interlace != 0 or ctype not in (0, 2, 3, 4, 6):
        raise StegoError(f"unsupported PNG (depth={depth}, color type={ctype}, interlace={interlace}); "
                         "install PIL for broader support")
    names = {0: "L", 2: "rgb", 3: "P", 4: "La", 6: "rgba"}[ctype]
    bpp = len(names) if ctype != 3 else 1
    if w <= 0 or h <= 0 or w * h * bpp > MAX_SAMPLES:
        raise StegoError("image dimensions out of range")
    stride = w * bpp
    try:
        raw = zlib.decompressobj().decompress(bytes(idat), h * (stride + 1))
    except zlib.error as exc:
        raise StegoError(f"bad IDAT stream: {exc}") from exc
    if len(raw) < h * (stride + 1):
        raise StegoError("truncated pixel data")
    rows: list[bytes] = []
    prev = bytearray(stride)
    for y in range(h):
        base = y * (stride + 1)
        ft = raw[base]
        cur = bytearray(raw[base + 1:base + 1 + stride])
        if ft == 1:
            for i in range(bpp, stride):
                cur[i] = (cur[i] + cur[i - bpp]) & 255
        elif ft == 2:
            for i in range(stride):
                cur[i] = (cur[i] + prev[i]) & 255
        elif ft == 3:
            for i in range(stride):
                a = cur[i - bpp] if i >= bpp else 0
                cur[i] = (cur[i] + ((a + prev[i]) >> 1)) & 255
        elif ft == 4:
            for i in range(stride):
                a = cur[i - bpp] if i >= bpp else 0
                b = prev[i]
                c = prev[i - bpp] if i >= bpp else 0
                pa, pb, pc = abs(b - c), abs(a - c), abs(a + b - 2 * c)
                pr = a if pa <= pb and pa <= pc else (b if pb <= pc else c)
                cur[i] = (cur[i] + pr) & 255
        elif ft != 0:
            raise StegoError(f"bad PNG filter type {ft}")
        rows.append(bytes(cur))
        prev = cur
    pal = [tuple(plte[i:i + 3]) for i in range(0, len(plte) - 2, 3)]
    return Image8(w, h, names if ctype != 3 else "P", rows, pal, indexed=ctype == 3)


def decode_bmp(data: bytes) -> Image8:
    """Decode an uncompressed 8/24/32-bit BMP (BGR order is converted to RGB)."""
    if data[:2] != b"BM" or len(data) < 54:
        raise StegoError("not a BMP")
    off = struct.unpack("<I", data[10:14])[0]
    hsz, w, h, _, bpp, comp = struct.unpack("<IiiHHI", data[14:34])
    if comp not in (0, 3) or bpp not in (8, 24, 32) or w <= 0 or h == 0:
        raise StegoError(f"unsupported BMP (bpp={bpp}, compression={comp})")
    top_down = h < 0
    h = abs(h)
    if w * h * (bpp // 8) > MAX_SAMPLES:
        raise StegoError("image dimensions out of range")
    stride = ((w * bpp + 31) // 32) * 4
    if off + stride * h > len(data):
        raise StegoError("truncated BMP pixel data")
    pal: list[tuple[int, int, int]] = []
    if bpp == 8:
        n = min(256, (off - 14 - hsz) // 4)
        for i in range(n):
            b, g, r = data[14 + hsz + 4 * i:14 + hsz + 4 * i + 3]
            pal.append((r, g, b))
    rows = []
    for y in range(h):
        r = data[off + y * stride:off + y * stride + w * (bpp // 8)]
        if bpp in (24, 32):
            step = bpp // 8
            r = b"".join(bytes((r[i + 2], r[i + 1], r[i])) + r[i + 3:i + step] for i in range(0, len(r), step))
        rows.append(r)
    if not top_down:
        rows.reverse()
    ch = {8: "P", 24: "rgb", 32: "rgba"}[bpp]
    return Image8(w, h, ch, rows, pal, indexed=bpp == 8)


def _decode_pil(data: bytes) -> Image8:
    """Fallback decode through optional PIL for formats the stdlib decoders don't handle."""
    if not HAVE_PIL:
        raise StegoError("unsupported format without PIL (install Pillow for richer output)")
    import io
    try:
        im = Image.open(io.BytesIO(data))
        indexed = im.mode == "P"
        if not indexed and im.mode not in ("L", "RGB", "RGBA"):
            im = im.convert("RGBA" if "A" in im.mode else "RGB")
        raw = im.tobytes()
        pal: list[tuple[int, int, int]] = []
        if indexed:
            p = im.getpalette() or []
            pal = [tuple(p[i:i + 3]) for i in range(0, len(p) - 2, 3)]
        names = {"P": "P", "L": "L", "RGB": "rgb", "RGBA": "rgba"}[im.mode]
        n = len(names) if names != "P" else 1
        stride = im.width * n
        rows = [raw[i * stride:(i + 1) * stride] for i in range(im.height)]
        return Image8(im.width, im.height, names, rows, pal, indexed)
    except Exception as exc:  # noqa: BLE001 - PIL raises many types
        raise StegoError(f"PIL could not decode: {exc}") from exc


def load_image(data: bytes) -> Image8:
    """Decode PNG/BMP with stdlib; fall back to PIL (if installed) on unsupported input."""
    try:
        if data.startswith(PNG_SIG):
            return decode_png(data)
        if data[:2] == b"BM":
            return decode_bmp(data)
        raise StegoError("unknown image format")
    except StegoError:
        if HAVE_PIL:
            return _decode_pil(data)
        raise


# --------------------------------------------------------------------------- LSB / planes

def _channel_idx(img: Image8, sel: str) -> list[int]:
    names = img.channels.lower() if img.channels not in ("P",) else "p"
    idx = [i for i, c in enumerate(names) if c in sel.lower()]
    if not idx:
        raise StegoError(f"channels {sel!r} not present in image ({img.channels})")
    return idx


def extract_lsb(img: Image8, channels: str = "rgba", bits: int = 1, msb_first: bool = True,
                max_bytes: int = 1 << 20) -> bytes:
    """Collect the low ``bits`` bits of each selected channel in row-major order and pack to bytes."""
    if not 1 <= bits <= 8:
        raise ValueError("bits must be 1..8")
    n = len(img.channels) if img.channels != "P" else 1
    sel = _channel_idx(img, channels if img.channels not in ("P", "L") else "pl")
    mask = (1 << bits) - 1
    out = bytearray()
    acc = nb = 0
    limit = max_bytes * 8
    total = 0
    for row in img.rows:
        for px in range(0, len(row), n):
            for c in sel:
                v = row[px + c] & mask
                bl = range(bits - 1, -1, -1) if msb_first else range(bits)
                for b in bl:
                    bit = (v >> b) & 1
                    acc = (acc << 1 | bit) if msb_first else (acc | bit << nb)
                    nb += 1
                    total += 1
                    if nb == 8:
                        out.append(acc)
                        acc = nb = 0
                if total >= limit:
                    return bytes(out)
    return bytes(out)


def bitplane_art(img: Image8, plane: int, channel: int = 0, max_w: int = 64, max_h: int = 32) -> str:
    """ASCII rendering (``#`` = bit set) of one bit-plane of one channel, downsampled to fit."""
    if not 0 <= plane <= 7:
        raise ValueError("plane must be 0..7")
    n = len(img.channels) if img.channels != "P" else 1
    if not 0 <= channel < n:
        raise ValueError("channel out of range")
    sx, sy = max(1, img.width // max_w), max(1, img.height // max_h)
    lines = []
    for y in range(0, img.height, sy):
        row = img.rows[y]
        lines.append("".join("#" if (row[x * n + channel] >> plane) & 1 else "." for x in range(0, img.width, sx)))
    return "\n".join(lines)


def printable_ratio(b: bytes) -> float:
    """Fraction of bytes that are printable ASCII/whitespace."""
    if not b:
        return 0.0
    return sum(1 for c in b if 32 <= c < 127 or c in (9, 10, 13)) / len(b)


# --------------------------------------------------------------------------- append / carve / palette

def logical_end(data: bytes) -> Optional[tuple[str, int]]:
    """Return (format, offset just past the image's logical end), or None if unrecognised."""
    if data.startswith(PNG_SIG):
        end = None
        for typ, _, e in _png_chunks(data):
            if typ == b"IEND":
                end = e
        return ("PNG", end) if end else None
    if data[:3] == b"\xff\xd8\xff":
        # walk marker segments to SOS, then the first EOI after entropy data
        pos = 2
        while pos + 4 <= len(data):
            if data[pos] != 0xFF:
                break
            m = data[pos + 1]
            if m == 0xDA:
                i = data.find(b"\xff\xd9", pos + 2)
                while i != -1 and i > 0 and data[i - 1] == 0xFF:
                    i = data.find(b"\xff\xd9", i + 1)
                return ("JPEG", i + 2) if i != -1 else None
            if m == 0xD8 or 0xD0 <= m <= 0xD7 or m == 0x01 or m == 0xFF:
                pos += 1 if m == 0xFF else 2
                continue
            pos += 2 + struct.unpack(">H", data[pos + 2:pos + 4])[0]
        return None
    if data[:6] in (b"GIF87a", b"GIF89a"):
        i = data.rfind(b"\x3b")
        return ("GIF", i + 1) if i > 0 else None
    if data[:2] == b"BM" and len(data) >= 6:
        size = struct.unpack("<I", data[2:6])[0]
        return ("BMP", size) if 0 < size <= len(data) else None
    return None


def find_appended(data: bytes) -> dict:
    """Report trailing bytes after the logical image end: {format, end, trailing, preview}."""
    le = logical_end(data)
    if le is None:
        return {"format": None, "end": None, "trailing": 0, "preview": b""}
    fmt, end = le
    tail = data[end:]
    return {"format": fmt, "end": end, "trailing": len(tail), "preview": tail[:64]}


def carve_hits(data: bytes, min_magic: int = 4) -> list[dict]:
    """Embedded signatures found past offset 0 (polyglots / appended archives).

    Short magics (< ``min_magic`` bytes, e.g. ``MZ``/``BM``) are skipped: too noisy inside pixel data."""
    hits = []
    for name, magic, anchor in _MAGICS:
        if len(magic) < min_magic or anchor:
            continue
        start = 1
        while len(hits) < 500:
            i = data.find(magic, start)
            if i == -1:
                break
            hits.append({"offset": i, "name": name})
            start = i + 1
    hits.sort(key=lambda h: h["offset"])
    return hits


def palette_report(img: Image8) -> list[str]:
    """Heuristic palette anomalies: duplicate entries, unused entries, near-duplicate colours."""
    if not img.indexed:
        return ["image is not palette-based"]
    pal = img.palette
    used = set(img.samples())
    out = [f"palette entries: {len(pal)}, indices used: {len(used)}"]
    dups = len(pal) - len(set(pal))
    if dups:
        out.append(f"anomaly: {dups} duplicate palette entries (index-parity hiding possible)")
    unused = [i for i in range(len(pal)) if i not in used]
    if unused:
        out.append(f"anomaly: {len(unused)} unused palette entries, e.g. {unused[:8]}")
    near = sum(1 for i in range(0, len(pal) - 1, 2)
               if max(abs(a - b) for a, b in zip(pal[i], pal[i + 1])) <= 2 and pal[i] != pal[i + 1])
    if near:
        out.append(f"anomaly: {near} adjacent near-identical colour pairs (palette-LSB stego sign)")
    bad = [i for i in used if i >= len(pal)]
    if bad:
        out.append(f"anomaly: indices beyond palette size: {sorted(bad)[:8]}")
    if len(out) == 1:
        out.append("no palette anomalies detected")
    return out


# --------------------------------------------------------------------------- CLI

USAGE = """usage: recon.py stego <img> [--lsb] [--append] [--carve] [--palette] [--plane N]
                              [--channels rgba] [--bits N] [--lsb-out FILE]
       recon.py stego selftest
With no mode flag, --append --carve and --lsb are all run."""


def _show(b: bytes, n: int = 120) -> str:
    return repr(b[:n]) + (" ..." if len(b) > n else "")


def run(args: list[str]) -> int:
    """CLI entry point."""
    if args[:1] in (["selftest"], ["--selftest"]):
        return 0 if selftest() else 1
    if not args or args[0] in ("-h", "--help"):
        print(USAGE)
        return 0
    if args[0].startswith("-"):
        print(USAGE)
        return 2
    p = argparse.ArgumentParser(prog="recon.py stego", add_help=False)
    p.add_argument("img")
    p.add_argument("--lsb", action="store_true")
    p.add_argument("--append", action="store_true")
    p.add_argument("--carve", action="store_true")
    p.add_argument("--palette", action="store_true")
    p.add_argument("--plane", type=int)
    p.add_argument("--channels", default="rgba")
    p.add_argument("--bits", type=int, default=1)
    p.add_argument("--lsb-out")
    p.add_argument("-h", "--help", action="store_true")
    try:
        a = p.parse_args(args)
    except SystemExit:
        print(USAGE)
        return 2
    if a.help:
        print(USAGE)
        return 0
    try:
        with open(a.img, "rb") as f:
            data = f.read(MAX_FILE + 1)
        if len(data) > MAX_FILE:
            raise ValueError("file too large")
    except (OSError, ValueError) as exc:
        print(f"error: cannot read {a.img}: {exc}", file=sys.stderr)
        return 1
    if not any((a.lsb, a.append, a.carve, a.palette, a.plane is not None)):
        a.lsb = a.append = a.carve = True
    rc = 0
    if a.append:
        r = find_appended(data)
        print("== appended data ==")
        if r["format"] is None:
            print("unrecognised image format; cannot determine logical end")
        elif r["trailing"]:
            print(f"{r['format']} ends at {r['end']}; {r['trailing']} trailing bytes: {_show(r['preview'])}")
        else:
            print(f"{r['format']}: no trailing data")
    if a.carve:
        print("== embedded signatures ==")
        hits = carve_hits(data)
        for h in hits[:50]:
            print(f"  0x{h['offset']:x}: {h['name']}")
        if not hits:
            print("  none")
        elif len(hits) > 50:
            print(f"  ... {len(hits) - 50} more")
    if a.lsb or a.palette or a.plane is not None:
        try:
            img = load_image(data)
            if a.lsb:
                print("== LSB ==")
                if not HAVE_PIL:
                    print("(note: install Pillow for more image formats)")
                found = False
                for ch in dict.fromkeys([a.channels, "r", "g", "b"] if img.channels != "P" else ["p"]):
                    try:
                        for msb in (True, False):
                            bs = extract_lsb(img, ch, a.bits, msb, max_bytes=65536)
                            ratio = printable_ratio(bs[:256])
                            print(f"  channels={ch} {'msb' if msb else 'lsb'}-first: printable={ratio:.0%} {_show(bs, 60)}")
                            found = found or ratio > 0.9
                            if a.lsb_out and ch == a.channels and msb:
                                with open(a.lsb_out, "wb") as f:
                                    f.write(extract_lsb(img, ch, a.bits, msb))
                    except StegoError:
                        continue
                if found:
                    print("  -> readable text likely hidden in LSBs")
            if a.palette:
                print("== palette ==")
                for line in palette_report(img):
                    print("  " + line)
            if a.plane is not None:
                print(f"== bit-plane {a.plane} (channel 0) ==")
                print(bitplane_art(img, a.plane))
        except (StegoError, ValueError, OSError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            rc = 1
    return rc


# --------------------------------------------------------------------------- selftest

def _make_png(w: int, h: int, rgb: bytes, trailer: bytes = b"") -> bytes:
    def chunk(t: bytes, b: bytes) -> bytes:
        return struct.pack(">I", len(b)) + t + b + struct.pack(">I", zlib.crc32(t + b))
    raw = b"".join(b"\x00" + rgb[y * w * 3:(y + 1) * w * 3] for y in range(h))
    return (PNG_SIG + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b"") + trailer)


def _make_bmp(w: int, h: int, rgb: bytes) -> bytes:
    stride = (w * 3 + 3) & ~3
    body = b""
    for y in range(h - 1, -1, -1):
        row = b"".join(bytes((rgb[i + 2], rgb[i + 1], rgb[i])) for i in range(y * w * 3, (y + 1) * w * 3, 3))
        body += row + b"\x00" * (stride - w * 3)
    hdr = struct.pack("<2sIHHI", b"BM", 54 + len(body), 0, 0, 54)
    dib = struct.pack("<IiiHHIIiiII", 40, w, h, 1, 24, 0, len(body), 0, 0, 0, 0)
    return hdr + dib + body


def selftest() -> bool:
    """Verify LSB recovery (PNG+BMP), append detection, carving, palette report, PIL-free behaviour."""
    ok = True

    def check(name: str, cond: bool) -> None:
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] stego: {name}")
        ok = ok and cond

    try:
        msg = b"flag{lsb_hidden}"
        w, h = 16, 16
        cover = bytearray((i * 37 + 11) & 0xFF for i in range(w * h * 3))
        bits = [(byte >> k) & 1 for byte in msg for k in range(7, -1, -1)]
        for i, bit in enumerate(bits):
            cover[i] = (cover[i] & 0xFE) | bit
        png = _make_png(w, h, bytes(cover))
        img = decode_png(png)
        check("PNG decode dims", (img.width, img.height) == (w, h))
        check("PNG LSB recovery", extract_lsb(img, "rgb")[:len(msg)] == msg)
        bmp = _make_bmp(w, h, bytes(cover))
        check("BMP LSB recovery", extract_lsb(decode_bmp(bmp), "rgb")[:len(msg)] == msg)
        check("bit-plane art shape", len(bitplane_art(img, 0).splitlines()) == h)

        clean = find_appended(png)
        check("clean PNG has no trailing data", clean["trailing"] == 0)
        extra = b"PK\x03\x04hidden-zip-body"
        r = find_appended(_make_png(w, h, bytes(cover), extra))
        check("appended-after-IEND detected", r["trailing"] == len(extra) and r["preview"] == extra)
        check("carve finds appended ZIP", any(h_["name"] == "ZIP" for h_ in carve_hits(_make_png(w, h, bytes(cover), extra))))

        pal_png = PNG_SIG  # build tiny palette image with duplicate + unused entries
        def chunk(t: bytes, b: bytes) -> bytes:
            return struct.pack(">I", len(b)) + t + b + struct.pack(">I", zlib.crc32(t + b))
        pal_png += chunk(b"IHDR", struct.pack(">IIBBBBB", 2, 2, 8, 3, 0, 0, 0))
        pal_png += chunk(b"PLTE", bytes([0, 0, 0, 0, 0, 0, 255, 255, 255, 9, 9, 9]))
        pal_png += chunk(b"IDAT", zlib.compress(b"\x00\x00\x01\x00\x01\x00")) + chunk(b"IEND", b"")
        rep = palette_report(decode_png(pal_png))
        check("palette anomalies reported", any("duplicate" in l for l in rep) and any("unused" in l for l in rep))

        # graceful behaviour without PIL: stdlib path works, unsupported data -> clean StegoError
        global HAVE_PIL
        saved = HAVE_PIL
        HAVE_PIL = False
        try:
            try:
                load_image(b"GIF89a-not-supported")
                graceful = False
            except StegoError:
                graceful = True
            check("no-PIL: unsupported format fails cleanly", graceful)
            check("no-PIL: PNG still decodes", load_image(png).width == w)
        finally:
            HAVE_PIL = saved
        check("malformed PNG rejected without traceback", _raises_stego(png[:40]))
        check("run() usage codes", run([]) == 0 and run(["--bogus"]) == 2)
    except Exception as exc:  # noqa: BLE001 - a crash is a selftest failure
        print(f"  [FAIL] stego: unexpected {type(exc).__name__}: {exc}")
        return False
    return ok


def _raises_stego(data: bytes) -> bool:
    try:
        decode_png(data)
    except StegoError:
        return True
    return False
