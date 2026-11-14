"""Forensics: pcap/pcapng parsing + TCP stream reassembly, HTTP extraction, keyword hunting,
JPEG/PNG/PDF metadata (best-effort) and magic-header repair. Pure stdlib, offline."""
from __future__ import annotations

import argparse
import contextlib
import io
import os
import re
import socket  # address formatting only (inet_ntoa/ntop/aton); no socket I/O is ever performed
import struct
import sys
import zlib

NAME = "forensics"
DESCRIPTION = "PCAP parse/streams/HTTP/keyword hunt, JPEG EXIF/PNG/PDF metadata, magic-header repair"

KEYWORDS = (b"flag{", b"ctf{", b"password", b"passwd", b"secret", b"key", b"token", b"BEGIN PRIVATE KEY",
            b"BEGIN RSA", b"aes", b"authorization:")

# --------------------------------------------------------------------------- pcap

PROTOS = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}


def _read_pcap(data: bytes):
    """Yield (ts, linktype, frame) from classic pcap."""
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        e = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        e = ">"
    else:
        raise ValueError("not a classic pcap")
    nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    link = struct.unpack(e + "I", data[20:24])[0]
    off = 24
    while off + 16 <= len(data):
        sec, frac, incl, _orig = struct.unpack(e + "IIII", data[off:off + 16])
        off += 16
        yield sec + frac / (1e9 if nano else 1e6), link, data[off:off + incl]
        off += incl


def _read_pcapng(data: bytes):
    """Yield (ts, linktype, frame) from pcapng (Enhanced/Simple packet blocks)."""
    e = "<"
    off = 0
    links: list[int] = []
    tsres: list[float] = []
    while off + 12 <= len(data):
        btype = struct.unpack(e + "I", data[off:off + 4])[0]
        if data[off:off + 4] == b"\x0a\x0d\x0d\x0a":
            e = "<" if data[off + 8:off + 12] == b"\x4d\x3c\x2b\x1a" else ">"
            links, tsres = [], []
        blen = struct.unpack(e + "I", data[off + 4:off + 8])[0]
        if blen < 12 or off + blen > len(data):
            break
        body = data[off + 8:off + blen - 4]
        if btype == 1:  # IDB
            lt = struct.unpack(e + "H", body[:2])[0]
            res = 1e-6
            o = 8
            while o + 4 <= len(body):
                code, ln = struct.unpack(e + "HH", body[o:o + 4])
                if code == 0:
                    break
                if code == 9 and ln >= 1:
                    v = body[o + 4]
                    res = 2.0 ** -(v & 0x7F) if v & 0x80 else 10.0 ** -v
                o += 4 + (ln + 3) // 4 * 4
            links.append(lt)
            tsres.append(res)
        elif btype == 6 and len(body) >= 20:  # EPB
            ifid, hi, lo, cap, _ = struct.unpack(e + "IIIII", body[:20])
            ts = ((hi << 32) | lo) * (tsres[ifid] if ifid < len(tsres) else 1e-6)
            yield ts, (links[ifid] if ifid < len(links) else 1), body[20:20 + cap]
        elif btype == 3 and len(body) >= 4:  # SPB
            yield 0.0, (links[0] if links else 1), body[4:]
        off += blen


def parse_frame(link: int, fr: bytes) -> dict | None:
    """Decode Ethernet(1)/raw IP(101/12)/Linux SLL(113)/loopback(0) down to TCP/UDP. Returns dict or None."""
    try:
        if link == 1:
            et = struct.unpack(">H", fr[12:14])[0]
            p = 14
            while et in (0x8100, 0x88A8):
                et = struct.unpack(">H", fr[p + 2:p + 4])[0]
                p += 4
        elif link == 113:
            et, p = struct.unpack(">H", fr[14:16])[0], 16
        elif link == 0:
            et, p = (0x0800 if fr[0] == 2 else 0x86DD), 4
        elif link in (101, 12, 14):
            et, p = (0x0800 if fr[0] >> 4 == 4 else 0x86DD), 0
        else:
            return None
        if et == 0x0800:
            ihl = (fr[p] & 15) * 4
            total = struct.unpack(">H", fr[p + 2:p + 4])[0]
            proto = fr[p + 9]
            src, dst = socket.inet_ntoa(fr[p + 12:p + 16]), socket.inet_ntoa(fr[p + 16:p + 20])
            frag = struct.unpack(">H", fr[p + 6:p + 8])[0] & 0x1FFF
            payload = fr[p + ihl:p + total] if total >= ihl else fr[p + ihl:]
        elif et == 0x86DD:
            proto = fr[p + 6]
            src, dst = socket.inet_ntop(socket.AF_INET6, fr[p + 8:p + 24]), socket.inet_ntop(socket.AF_INET6, fr[p + 24:p + 40])
            plen = struct.unpack(">H", fr[p + 4:p + 6])[0]
            payload, frag = fr[p + 40:p + 40 + plen], 0
        else:
            return None
    except (struct.error, IndexError, OSError):
        return None
    d = {"src": src, "dst": dst, "proto": PROTOS.get(proto, str(proto)), "sport": 0, "dport": 0,
         "seq": 0, "flags": 0, "data": b""}
    if frag:
        return d
    if proto == 6 and len(payload) >= 20:
        sp, dp, seq, _ack, offf, fl = struct.unpack(">HHIIBB", payload[:14])
        d.update(sport=sp, dport=dp, seq=seq, flags=fl, data=payload[(offf >> 4) * 4:])
    elif proto == 17 and len(payload) >= 8:
        sp, dp = struct.unpack(">HH", payload[:4])
        d.update(sport=sp, dport=dp, data=payload[8:])
    return d


def parse_pcap(data: bytes) -> list[dict]:
    """Parse pcap/pcapng bytes into packet dicts (no=index, ts, src, dst, proto, length, ...)."""
    if data[:4] == b"\x0a\x0d\x0d\x0a":
        it = _read_pcapng(data)
    else:
        it = _read_pcap(data)
    pkts = []
    try:
        for n, (ts, link, fr) in enumerate(it, 1):
            d = parse_frame(link, fr) or {"src": "?", "dst": "?", "proto": "other", "sport": 0, "dport": 0,
                                           "seq": 0, "flags": 0, "data": b""}
            d.update(no=n, ts=ts, length=len(fr))
            pkts.append(d)
    except (struct.error, IndexError) as exc:  # truncated capture header/record
        raise ValueError(f"truncated/malformed capture: {exc}") from exc
    return pkts


def tcp_streams(pkts: list[dict]) -> dict:
    """Reassemble TCP by flow. Returns {(a,ap,b,bp): {'c2s': bytes, 's2c': bytes}} where a is the first-seen sender
    (the SYN sender if the handshake is captured). Out-of-order/retransmitted segments are ordered by seq."""
    flows: dict = {}
    for p in pkts:
        if p["proto"] != "TCP":
            continue
        a, b = (p["src"], p["sport"]), (p["dst"], p["dport"])
        if (b, a) in flows:
            key, dirn = (b, a), "s2c"
        else:
            key, dirn = (a, b), "c2s"
        f = flows.setdefault(key, {"c2s": [], "s2c": []})
        if p["data"]:
            f[dirn].append((p["seq"], p["data"]))
    out = {}
    for (a, b), f in flows.items():
        res = {}
        for dirn, segs in f.items():
            buf = bytearray()
            nxt = None
            for seq, d in sorted(segs, key=lambda s: s[0]):
                if nxt is None:
                    nxt = seq
                if seq + len(d) <= nxt:
                    continue  # retransmit
                buf += d[max(0, nxt - seq):]
                nxt = seq + len(d)
            res[dirn] = bytes(buf)
        out[(a[0], a[1], b[0], b[1])] = res
    return out


def strings(data: bytes, minlen: int = 6) -> list[str]:
    return [m.decode("latin-1") for m in re.findall(rb"[\x20-\x7e\t]{%d,}" % minlen, data)]


def find_keywords(data: bytes, ctx: int = 1, keywords=KEYWORDS) -> list[tuple[str, str]]:
    """Return (keyword, context lines) for each line containing a keyword (case-insensitive)."""
    lines = re.split(rb"\r?\n", data)
    hits = []
    for i, ln in enumerate(lines):
        low = ln.lower()
        for k in keywords:
            if k.lower() in low:
                chunk = b"\n".join(lines[max(0, i - ctx):i + ctx + 1])
                hits.append((k.decode(), re.sub(rb"[^\x20-\x7e\n\t]", b".", chunk)[:400].decode()))
                break
    return hits


def http_objects(stream_c2s: bytes, stream_s2c: bytes) -> list[dict]:
    """Basic HTTP/1.x extraction: requests (method, host, path) and response bodies (Content-Length or rest)."""
    objs = []
    for m in re.finditer(rb"(GET|POST|PUT|HEAD|DELETE|OPTIONS) (\S+) HTTP/1\.[01]\r\n(.*?)\r\n\r\n", stream_c2s, re.S):
        hdr = m.group(3).decode("latin-1")
        host = re.search(r"(?im)^host:\s*(.+?)\s*$", hdr)
        o = {"kind": "request", "method": m.group(1).decode(), "path": m.group(2).decode("latin-1"),
             "host": host.group(1) if host else "", "body": b""}
        cl = re.search(r"(?im)^content-length:\s*(\d+)", hdr)
        if cl:
            o["body"] = stream_c2s[m.end():m.end() + int(cl.group(1))]
        objs.append(o)
    pos = 0
    for m in re.finditer(rb"HTTP/1\.[01] (\d{3})[^\r\n]*\r\n(.*?)\r\n\r\n", stream_s2c, re.S):
        if m.start() < pos:
            continue
        hdr = m.group(2).decode("latin-1")
        cl = re.search(r"(?im)^content-length:\s*(\d+)", hdr)
        ct = re.search(r"(?im)^content-type:\s*(.+?)\s*$", hdr)
        nxt = re.search(rb"HTTP/1\.[01] \d{3}", stream_s2c[m.end():])
        end = m.end() + int(cl.group(1)) if cl else (m.end() + nxt.start() if nxt else len(stream_s2c))
        body = stream_s2c[m.end():end]
        if re.search(r"(?im)^transfer-encoding:\s*chunked", hdr):
            body = _dechunk(body)
        pos = end
        objs.append({"kind": "response", "status": int(m.group(1)), "ctype": ct.group(1) if ct else "", "body": body})
    return objs


def _dechunk(b: bytes) -> bytes:
    out, i = bytearray(), 0
    while True:
        j = b.find(b"\r\n", i)
        if j < 0:
            break
        try:
            n = int(b[i:j].split(b";")[0], 16)
        except ValueError:
            break
        if n == 0:
            break
        out += b[j + 2:j + 2 + n]
        i = j + 2 + n + 2
    return bytes(out)


def analyze_pcap(data: bytes, ctx: int = 1) -> dict:
    pkts = parse_pcap(data)
    streams = tcp_streams(pkts)
    rep = {"packets": pkts, "streams": streams, "http": {}, "hits": {}}
    for k, s in streams.items():
        h = http_objects(s["c2s"], s["s2c"])
        if h:
            rep["http"][k] = h
        hits = find_keywords(s["c2s"], ctx) + find_keywords(s["s2c"], ctx)
        if hits:
            rep["hits"][k] = hits
    # UDP/other payload keyword hits too
    for p in pkts:
        if p["proto"] == "UDP" and p["data"]:
            hits = find_keywords(p["data"], ctx)
            if hits:
                rep["hits"].setdefault(("udp", p["src"], p["sport"], p["dst"], p["dport"]), []).extend(hits)
    return rep

# --------------------------------------------------------------------------- file metadata (best-effort)

EXIF_TAGS = {0x010F: "Make", 0x0110: "Model", 0x0131: "Software", 0x0132: "DateTime", 0x013B: "Artist",
             0x8298: "Copyright", 0x010E: "ImageDescription", 0x9286: "UserComment", 0x9003: "DateTimeOriginal"}


def jpeg_exif(data: bytes) -> dict:
    """Best-effort EXIF read from JPEG APP1. Returns {} when absent/unparseable (never raises)."""
    out: dict = {}
    try:
        if data[:2] != b"\xff\xd8":
            return out
        i = 2
        while i + 4 <= len(data) and data[i] == 0xFF:
            mk = data[i + 1]
            if mk in (0xD9, 0xDA):
                break
            ln = struct.unpack(">H", data[i + 2:i + 4])[0]
            seg = data[i + 4:i + 2 + ln]
            if mk == 0xE1 and seg[:6] == b"Exif\0\0":
                _parse_tiff(seg[6:], out)
            elif mk == 0xFE:
                out["JPEGComment"] = seg.decode("latin-1")
            i += 2 + ln
    except (struct.error, IndexError):
        out["_warning"] = "truncated/corrupt JPEG"
    return out


def _parse_tiff(t: bytes, out: dict) -> None:
    e = "<" if t[:2] == b"II" else ">"
    sizes = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1}

    def ifd(off: int, depth=0):
        n = struct.unpack(e + "H", t[off:off + 2])[0]
        for k in range(n):
            tag, typ, cnt, val = struct.unpack(e + "HHI4s", t[off + 2 + k * 12:off + 14 + k * 12])
            size = sizes.get(typ, 1) * cnt
            raw = val[:size] if size <= 4 else t[struct.unpack(e + "I", val)[0]:][:size]
            if tag in (0x8769, 0x8825) and depth < 2:
                ifd(struct.unpack(e + "I", val)[0], depth + 1)
            elif tag in EXIF_TAGS:
                out[EXIF_TAGS[tag]] = raw.rstrip(b"\0").decode("latin-1") if typ in (2, 7) else raw.hex()
            elif tag == 0x0112 and typ == 3:
                out["Orientation"] = struct.unpack(e + "H", raw[:2])[0]
    ifd(struct.unpack(e + "I", t[4:8])[0])


def png_chunks(data: bytes) -> list[dict]:
    """List PNG chunks (type, length, crc_ok, text for tEXt)."""
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        return []
    out, i = [], 8
    while i + 12 <= len(data):
        ln = struct.unpack(">I", data[i:i + 4])[0]
        typ = data[i + 4:i + 8]
        body = data[i + 8:i + 8 + ln]
        crc = data[i + 8 + ln:i + 12 + ln]
        ok = len(crc) == 4 and struct.unpack(">I", crc)[0] == zlib.crc32(typ + body) & 0xFFFFFFFF
        c = {"type": typ.decode("latin-1"), "length": ln, "crc_ok": ok}
        if typ == b"tEXt":
            c["text"] = body.replace(b"\0", b"=", 1).decode("latin-1")
        out.append(c)
        i += 12 + ln
        if typ == b"IEND":
            if i < len(data):
                out.append({"type": "TRAILING", "length": len(data) - i, "crc_ok": False})
            break
    return out


def pdf_scan(data: bytes) -> dict:
    """Heuristic PDF scan: object count, embedded-file markers, JS, streams. Not a parser."""
    if not data.startswith(b"%PDF"):
        return {}
    return {"objects": len(re.findall(rb"\d+ \d+ obj", data)),
            "embedded_files": len(re.findall(rb"/EmbeddedFile", data)),
            "filespec_names": [m.decode("latin-1") for m in re.findall(rb"/F\s*\(([^)]{1,80})\)", data)],
            "javascript": bool(re.search(rb"/JS\b|/JavaScript", data)),
            "streams": len(re.findall(rb"\bstream\r?\n", data)),
            "eof_markers": data.count(b"%%EOF")}

# --------------------------------------------------------------------------- header repair

MAGICS = [  # (name, magic, extension)
    ("PNG", b"\x89PNG\r\n\x1a\n", "png"), ("JPEG", b"\xff\xd8\xff\xe0", "jpg"), ("GIF89a", b"GIF89a", "gif"),
    ("PDF", b"%PDF-", "pdf"), ("ZIP", b"PK\x03\x04", "zip"), ("GZIP", b"\x1f\x8b\x08", "gz"),
    ("ELF", b"\x7fELF", "elf"), ("RAR", b"Rar!\x1a\x07", "rar"), ("7z", b"7z\xbc\xaf\x27\x1c", "7z"),
    ("pcap", b"\xd4\xc3\xb2\xa1", "pcap"), ("BMP", b"BM", "bmp"), ("SQLite", b"SQLite format 3\0", "db"),
]


def repair_header(data: bytes, kind: str) -> tuple[bytes, str]:
    """Overwrite/prepend the magic for ``kind`` (name or extension). Heuristic: if the first len(magic) bytes
    differ in few positions, overwrite them; otherwise prepend. Returns (new_data, note)."""
    for name, magic, ext in MAGICS:
        if kind.lower() in (name.lower(), ext):
            head = data[:len(magic)]
            if head == magic:
                return data, "header already correct"
            diff = sum(a != b for a, b in zip(head, magic)) + max(0, len(magic) - len(head))
            if diff <= (len(magic) + 1) // 2:
                return magic + data[len(magic):], f"overwrote {len(magic)} header bytes ({diff} differed)"
            return magic + data, "prepended magic"
    raise ValueError(f"unknown type {kind!r}; known: " + ", ".join(m[0] for m in MAGICS))


def identify(data: bytes) -> str:
    for name, magic, _ in MAGICS:
        if data.startswith(magic):
            return name
    return "unknown"

# --------------------------------------------------------------------------- CLI

def _print_pcap(rep: dict, a) -> None:
    print("== packets ==" if a.packets or not a.streams else "")
    if a.packets or not (a.streams or a.http or a.flags):
        for p in rep["packets"]:
            print(f"{p['no']:>4} {p['ts']:.6f} {p['src']}:{p['sport']} -> {p['dst']}:{p['dport']} {p['proto']} len={p['length']}")
    if a.streams or not (a.packets or a.http or a.flags):
        for i, (k, s) in enumerate(rep["streams"].items()):
            print(f"\n== stream {i}: {k[0]}:{k[1]} <-> {k[2]}:{k[3]}  c2s={len(s['c2s'])}B s2c={len(s['s2c'])}B ==")
            for d in ("c2s", "s2c"):
                if s[d]:
                    print(f"--- {d} ---")
                    print(s[d].decode("latin-1").translate({c: "." for c in range(32) if c not in (9, 10, 13)}))
    if a.http or not (a.packets or a.streams or a.flags):
        for k, objs in rep["http"].items():
            for o in objs:
                if o["kind"] == "request":
                    print(f"[HTTP] {o['method']} {o['host']}{o['path']} body={len(o['body'])}B")
                else:
                    print(f"[HTTP] {o['status']} {o['ctype']} body={len(o['body'])}B")
    if a.flags or not (a.packets or a.streams or a.http):
        for k, hits in rep["hits"].items():
            for kw, c in hits:
                print(f"[KEYWORD {kw!r}] {k}\n    " + c.replace("\n", "\n    "))
    if a.extract:
        os.makedirs(a.extract, exist_ok=True)
        n = 0
        for objs in rep["http"].values():
            for o in objs:
                if o["kind"] == "response" and o["body"]:
                    n += 1
                    with open(os.path.join(a.extract, f"http_obj_{n}.bin"), "wb") as fh:
                        fh.write(o["body"])
        print(f"extracted {n} HTTP bodies to {a.extract}")


def run(args: list[str]) -> int:
    """CLI entry point (registry contract); returns a process exit code."""
    if args[:1] == ["selftest"]:
        return 0 if selftest() else 1
    p = argparse.ArgumentParser(prog="recon.py forensics", description=DESCRIPTION)
    p.add_argument("file", nargs="?")
    p.add_argument("--packets", action="store_true", help="list packets")
    p.add_argument("--streams", action="store_true", help="dump reassembled TCP streams")
    p.add_argument("--http", action="store_true", help="list HTTP objects")
    p.add_argument("--flags", action="store_true", help="keyword hits with context")
    p.add_argument("--extract", metavar="DIR", help="write HTTP response bodies to DIR")
    p.add_argument("--meta", action="store_true", help="JPEG EXIF / PNG chunks / PDF scan (best-effort)")
    p.add_argument("--repair", metavar="TYPE", help="fix magic header to TYPE (e.g. png); needs -o")
    p.add_argument("-o", "--out")
    p.add_argument("--selftest", action="store_true")
    try:
        a = p.parse_args(args)
    except SystemExit as exc:  # -h -> 0, usage error -> 2; return instead of exiting
        return exc.code if isinstance(exc.code, int) else 2
    if a.selftest:
        return 0 if selftest() else 1
    if not a.file:
        p.print_help()
        return 0
    try:
        return _dispatch(a)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def _dispatch(a: argparse.Namespace) -> int:
    """Execute one parsed forensics invocation; I/O and parse errors propagate to run()."""
    with open(a.file, "rb") as fh:
        data = fh.read()
    if a.repair:
        if not a.out:
            print("--repair needs -o OUTPUT", file=sys.stderr)
            return 2
        new, note = repair_header(data, a.repair)
        with open(a.out, "wb") as fh:
            fh.write(new)
        print(f"{note}; wrote {a.out} (detected: {identify(new)})")
        return 0
    if a.meta:
        print(f"detected: {identify(data)}  [best-effort metadata]")
        for k, v in jpeg_exif(data).items():
            print(f"  EXIF {k}: {v}")
        for c in png_chunks(data):
            print(f"  PNG {c}")
        for k, v in pdf_scan(data).items():
            print(f"  PDF {k}: {v}")
        return 0
    try:
        _print_pcap(analyze_pcap(data), a)
    except ValueError as exc:
        print(f"error: {exc} (try --meta / --repair)", file=sys.stderr)
        return 1
    return 0

# --------------------------------------------------------------------------- self-test

def _eth_ip_tcp(src, dst, sp, dp, seq, payload: bytes, flags=0x18) -> bytes:
    tcp = struct.pack(">HHIIBBHHH", sp, dp, seq, 0, 5 << 4, flags, 8192, 0, 0) + payload
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0,
                     socket.inet_aton(src), socket.inet_aton(dst)) + tcp
    return b"\0" * 12 + b"\x08\x00" + ip


def make_test_pcap() -> bytes:
    req = b"GET /login?user=bob HTTP/1.1\r\nHost: ctf.local\r\n\r\n"
    body = b"hello\nflag{pcap_streams_ok}\nbye"
    resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n" % len(body) + body
    half = len(resp) // 2
    frames = [_eth_ip_tcp("10.0.0.1", "10.0.0.2", 4444, 80, 1000, req),
              # server segments delivered out of order to exercise reassembly
              _eth_ip_tcp("10.0.0.2", "10.0.0.1", 80, 4444, 5000 + half, resp[half:]),
              _eth_ip_tcp("10.0.0.2", "10.0.0.1", 80, 4444, 5000, resp[:half])]
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for i, f in enumerate(frames):
        out += struct.pack("<IIII", 1700000000 + i, 500, len(f), len(f)) + f
    return out


def selftest() -> bool:
    """Registry contract self-test: pcap/pcapng/streams/HTTP, metadata and repair on in-memory fixtures."""
    ok: list[bool] = []

    def check(name, cond):
        ok.append(bool(cond))
        print(f"  [{'ok' if cond else 'FAIL'}] {name}")

    pc = make_test_pcap()
    rep = analyze_pcap(pc)
    check("pcap: 3 TCP packets parsed", len(rep["packets"]) == 3 and all(p["proto"] == "TCP" for p in rep["packets"]))
    check("pcap: src/dst/len", rep["packets"][0]["src"] == "10.0.0.1" and rep["packets"][0]["dport"] == 80)
    st = rep["streams"]
    check("stream: single flow", len(st) == 1)
    s = next(iter(st.values()))
    check("stream: c2s request", s["c2s"].startswith(b"GET /login"))
    check("stream: out-of-order s2c reassembled", b"flag{pcap_streams_ok}" in s["s2c"] and s["s2c"].startswith(b"HTTP/1.1 200"))
    http = next(iter(rep["http"].values()), [])
    check("http: request host/path", any(o["kind"] == "request" and o["host"] == "ctf.local" and o["path"].startswith("/login") for o in http))
    check("http: response body", any(o["kind"] == "response" and o["body"].startswith(b"hello") for o in http))
    check("keyword: flag{ found with context", any(k == "flag{" and "hello" in c for h in rep["hits"].values() for k, c in h))
    check("strings: printable hit", any("flag{" in x for x in strings(s["s2c"])))
    # pcapng round trip: wrap same frames in SHB+IDB+EPBs
    def blk(t, body):
        body += b"\0" * (-len(body) % 4)
        return struct.pack("<II", t, len(body) + 12) + body + struct.pack("<I", len(body) + 12)
    ng = blk(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)) + blk(1, struct.pack("<HHI", 1, 0, 65535))
    for _ts, _l, fr in _read_pcap(pc):
        ng += blk(6, struct.pack("<IIIII", 0, 0, 1, len(fr), len(fr)) + fr)
    check("pcapng: parses same packets", [p["length"] for p in parse_pcap(ng)] == [p["length"] for p in rep["packets"]])
    check("pcap: garbage rejected", _raises(lambda: parse_pcap(b"notapcapfile" * 4)))
    try:
        parse_pcap(b"\xd4\xc3\xb2\xa1\x00")
        trunc_ok = False
    except ValueError:
        trunc_ok = True
    check("pcap: truncated header -> ValueError (no struct.error leak)", trunc_ok)

    jpg = b"\xff\xd8\xff\xe1\x00\x10Exif\0\0II*\0\x08\x00\xff\xd9"  # truncated EXIF
    check("exif: truncated JPEG handled gracefully", isinstance(jpeg_exif(jpg), dict))
    check("exif: non-JPEG -> {}", jpeg_exif(b"hello") == {})
    tiff = (b"II*\0\x08\0\0\0" + struct.pack("<H", 1) + struct.pack("<HHI4s", 0x010F, 2, 4, b"ACM\0") + b"\0\0\0\0")
    seg = b"Exif\0\0" + tiff
    good = b"\xff\xd8\xff\xe1" + struct.pack(">H", len(seg) + 2) + seg + b"\xff\xd9"
    check("exif: Make parsed", jpeg_exif(good).get("Make") == "ACM")
    body = b"IHDR" + b"\0" * 13
    png = b"\x89PNG\r\n\x1a\n" + struct.pack(">I", 13) + body + struct.pack(">I", zlib.crc32(body)) + \
        struct.pack(">I", 0) + b"IEND" + struct.pack(">I", zlib.crc32(b"IEND"))
    ch = png_chunks(png)
    check("png: chunks + crc", [c["type"] for c in ch] == ["IHDR", "IEND"] and all(c["crc_ok"] for c in ch))
    check("pdf: scan", pdf_scan(b"%PDF-1.4\n1 0 obj\n<</Type/EmbeddedFile>>\nstream\nx")["embedded_files"] == 1)

    for kind, orig in (("png", png), ("pdf", b"%PDF-1.4 rest of file"), ("zip", b"PK\x03\x04" + b"\0" * 20)):
        broken = b"\0\0\0\0" + orig[4:]
        fixed, _ = repair_header(broken, kind)
        check(f"repair: {kind} round trip", fixed == orig or identify(fixed) != "unknown")
    f, _ = repair_header(png[8:], "png")
    check("repair: missing magic prepended", f == png)
    check("repair: unknown type raises", _raises(lambda: repair_header(b"x", "nope")))
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        codes = (run([]), run(["-h"]), run(["--bogus"]), run(["/nonexistent/x.pcap"]))
    check("cli: bare/-h -> 0, bad flag -> 2, missing file -> 1", codes == (0, 0, 2, 1))
    return all(ok)


def _raises(fn) -> bool:
    try:
        fn()
    except Exception:
        return True
    return False


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
