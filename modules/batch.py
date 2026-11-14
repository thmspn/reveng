"""batch: directory auto-triage. Detects each file's type and routes it to the right module.

    recon.py batch <dir|file> [--quick] [--json] [-r]

Routing (all parsing is delegated to the other modules via the registry, never duplicated):
    ELF            -> triage protections + disasm entry (skipped with --quick)
    pcap/pcapng    -> forensics pcap summary (packets, streams, HTTP objects, keyword hits)
    PNG/JPEG/PDF   -> forensics metadata (--meta equivalent)
    archive        -> zip/tar/gzip member listing (stdlib)
    text / unknown -> triage strings + decode auto-decode attempt + forensics keyword hunt

Output is a table ranked most-interesting first (flag hits, keyword hits, entropy, known magic).
Fully offline; files are treated as untrusted and read with a size cap.
"""
from __future__ import annotations

import gzip
import io
import json
import os
import re
import sys
import tarfile
import tempfile
import zipfile
from types import ModuleType

NAME = "batch"
DESCRIPTION = "Directory auto-triage: detect each file, route to triage/disasm/forensics/decode, ranked table (--json, --quick)"

MAX_READ = 8 * 1024 * 1024      # bytes read per file
MAX_FILES = 2000                # files examined per run
FLAG_RE = re.compile(rb"[A-Za-z0-9_]{2,12}\{[A-Za-z0-9_\-!@#$%^&*+=.,:;?/\\ ]{3,200}\}")
USAGE = """batch usage:
  recon.py batch <dir|file> [--quick] [--json] [-r]
    --quick   skip disassembly (faster)
    --json    emit machine-readable JSON instead of the table
    -r        recurse into subdirectories
  recon.py batch selftest"""


def _mods() -> dict[str, ModuleType]:
    """Fetch sibling modules through the registry."""
    try:
        from modules import discover
    except ImportError:  # imported as a package submodule without toolkit/ on sys.path
        from . import discover  # type: ignore[no-redef]
    return discover()


def _is_pcap(data: bytes) -> bool:
    """True for classic pcap (either endianness/precision) or pcapng magic."""
    return data[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1",
                        b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a")


def classify(data: bytes, mods: dict[str, ModuleType]) -> str:
    """Return a category: elf, pcap, image, pdf, archive, text or data (triage detection + pcap check)."""
    if not data:
        return "empty"
    if _is_pcap(data):
        return "pcap"
    label = mods["triage"].detect_type(data)
    if label.startswith("ELF"):
        return "elf"
    if "image" in label:
        return "image"
    if label.startswith("PDF"):
        return "pdf"
    if any(k in label for k in ("archive", "gzip", "bzip2", "xz")):
        return "archive"
    if label == "ASCII text" or label.startswith("script"):
        return "text"
    if label == "data" and data[:3] in (b"\xef\xbb\xbf",):
        return "text"
    return "data" if label == "data" else "other"


def _list_archive(data: bytes) -> tuple[list[str], bytes]:
    """List archive members; returns (names, extra bytes to keyword-scan e.g. gzip payload)."""
    extra = b""
    bio = io.BytesIO(data)
    if data[:2] == b"PK":
        with zipfile.ZipFile(bio) as z:
            return [f"{i.filename} ({i.file_size}B)" for i in z.infolist()[:50]], extra
    if data[:2] == b"\x1f\x8b":
        with gzip.GzipFile(fileobj=bio) as g:
            extra = g.read(MAX_READ)
        names = [f"<gzip payload {len(extra)}B>"]
        try:  # a gzipped tarball: list the members too
            with tarfile.open(fileobj=io.BytesIO(extra)) as t:
                names = [f"{m.name} ({m.size}B)" for m in t.getmembers()[:50]]
        except tarfile.TarError:
            pass
        return names, extra
    with tarfile.open(fileobj=bio) as t:  # tar / tar.bz2 / tar.xz
        return [f"{m.name} ({m.size}B)" for m in t.getmembers()[:50]], extra


def _kw_hits(forensics: ModuleType, data: bytes) -> tuple[list[str], list[str]]:
    """Return (flag-like strings, keyword names) found in data."""
    flags = sorted({m.group().decode("latin-1") for m in FLAG_RE.finditer(data)})[:5]
    kws = sorted({k for k, _ in forensics.find_keywords(data, 0)})[:8]
    return flags, kws


def analyze_file(path: str, mods: dict[str, ModuleType], quick: bool = False) -> dict:
    """Triage one file and route it; never raises (errors are captured in the 'error' field)."""
    rec: dict = {"file": os.path.basename(path), "path": path, "type": "?", "category": "error",
                 "size": 0, "entropy": 0.0, "flags": [], "keywords": [], "notes": [], "score": 0}
    try:
        rec["size"] = os.path.getsize(path)
        with open(path, "rb") as fh:
            data = fh.read(MAX_READ)
    except OSError as exc:
        rec["error"] = f"unreadable: {exc.strerror or exc}"
        return rec
    tri, fx = mods["triage"], mods["forensics"]
    cat = classify(data, mods)
    rec["category"] = cat
    rec["type"] = "empty file" if cat == "empty" else ("pcap capture" if cat == "pcap" else tri.detect_type(data))
    rec["entropy"] = round(tri.entropy(data[:1 << 20]), 2)
    scan = data
    try:
        if cat == "elf":
            info = tri.parse_elf(data)
            prot = tri.elf_protections(data, info)
            rec["protections"] = prot
            rec["notes"].append("NX=%s PIE=%s RELRO=%s canary=%s" % (
                prot["NX"].split()[0], prot["PIE"].split()[0], prot["RELRO"], prot["Canary"].split()[0]))
            if not quick:
                dis = mods["disasm"]
                rec["entry"] = dis.entry_disasm(data, dis.parse_elf(data), 6).splitlines()[:8]
        elif cat == "pcap":
            rep = fx.analyze_pcap(data)
            rec["summary"] = {"packets": len(rep["packets"]), "streams": len(rep["streams"]),
                              "http_objects": sum(len(v) for v in rep["http"].values()),
                              "keyword_hits": sum(len(v) for v in rep["hits"].values())}
            rec["notes"].append("pcap: %(packets)d pkts, %(streams)d TCP streams, %(http_objects)d HTTP objs" % rec["summary"])
            scan = b"\n".join(s["c2s"] + b"\n" + s["s2c"] for s in rep["streams"].values()) + b"\n".join(
                p["data"] for p in rep["packets"] if p.get("data"))
        elif cat == "image" or cat == "pdf":
            if data.startswith(b"\x89PNG"):
                meta = fx.png_chunks(data)
                rec["meta"] = meta
                rec["notes"].append("PNG chunks: " + ",".join(c["type"] for c in meta[:12]))
                if any(c["type"] == "TRAILING" for c in meta):
                    rec["notes"].append("TRAILING data after IEND")
                    rec["score"] += 20
                if any(not c["crc_ok"] and c["type"] != "TRAILING" for c in meta):
                    rec["notes"].append("bad chunk CRC")
                    rec["score"] += 10
            elif data.startswith(b"\xff\xd8"):
                rec["meta"] = fx.jpeg_exif(data)
                rec["notes"].append("EXIF: %d tags" % len(rec["meta"]))
            elif cat == "pdf":
                rec["meta"] = fx.pdf_scan(data)
                m = rec["meta"]
                rec["notes"].append("PDF objs=%s js=%s embedded=%s" % (m.get("objects"), m.get("javascript"), m.get("embedded_files")))
                rec["score"] += 15 * bool(m.get("javascript") or m.get("embedded_files"))
        elif cat == "archive":
            names, extra = _list_archive(data)
            rec["members"] = names
            rec["notes"].append("members: " + ", ".join(names[:4]) + (" ..." if len(names) > 4 else ""))
            scan = data + extra
        elif cat in ("text", "data", "other"):
            ascii_s, wide_s = tri.extract_strings(data)
            rec["notes"].append("%d strings" % (len(ascii_s) + len(wide_s)))
            cand = data.decode("latin-1").strip() if cat == "text" else (max(ascii_s, key=len) if ascii_s else "")
            if 4 <= len(cand) <= 4096:
                out, chain = mods["decode"].auto_decode(cand)
                if chain:
                    rec["decoded"] = {"chain": chain, "text": out[:200].decode("latin-1")}
                    rec["notes"].append("auto-decode: " + "->".join(chain))
                    scan = data + b"\n" + out
    except Exception as exc:  # noqa: BLE001 - one bad file must not stop the batch
        rec["notes"].append(f"{type(exc).__name__}: {exc}")
    flags, kws = _kw_hits(fx, scan)
    rec["flags"], rec["keywords"] = flags, [k for k in kws if k.lower() not in ("key",)] or kws
    rec["score"] += 100 * bool(flags) + 8 * min(len(rec["keywords"]), 5)
    rec["score"] += 15 * (rec["entropy"] >= 7.2 and rec["size"] >= 64) + 5 * (cat not in ("data", "text", "empty", "error"))
    return rec


def collect(target: str, recurse: bool = False) -> list[str]:
    """Return file paths under target (non-recursive by default), capped at MAX_FILES."""
    if os.path.isfile(target):
        return [target]
    out: list[str] = []
    for root, dirs, files in os.walk(target):
        dirs.sort()
        out += [os.path.join(root, f) for f in sorted(files)]
        if not recurse or len(out) >= MAX_FILES:
            break
    return out[:MAX_FILES]


def run_batch(target: str, quick: bool = False, recurse: bool = False) -> list[dict]:
    """Analyze every file under target and return records ranked most-interesting first."""
    mods = _mods()
    missing = [m for m in ("triage", "forensics", "decode", "disasm") if m not in mods]
    if missing:
        raise RuntimeError("required modules unavailable: " + ", ".join(missing))
    recs = [analyze_file(p, mods, quick) for p in collect(target, recurse)]
    return sorted(recs, key=lambda r: (-r["score"], r["file"]))


def format_table(recs: list[dict]) -> str:
    """Render ranked records as a compact text table."""
    lines = [f"{'#':>2} {'score':>5} {'file':<24} {'type':<20} {'size':>8} {'ent':>4}  verdict"]
    for i, r in enumerate(recs, 1):
        bits = []
        if r["flags"]:
            bits.append("FLAG " + ", ".join(r["flags"][:2]))
        elif r["keywords"]:
            bits.append("kw: " + ",".join(r["keywords"][:3]))
        bits += [r["error"]] if r.get("error") else r["notes"][:2]
        lines.append(f"{i:>2} {r['score']:>5} {r['file'][:24]:<24} {r['type'][:20]:<20} {r['size']:>8} {r['entropy']:>4}  " + "; ".join(bits))
    return "\n".join(lines)


def run(args: list[str]) -> int:
    """CLI entry point."""
    if not args or args[0] in ("-h", "--help"):
        print(USAGE)
        return 0
    if args[0] == "selftest":
        return 0 if selftest() else 1
    opts = {a for a in args if a.startswith("-")}
    unknown = opts - {"--quick", "--json", "-r"}
    paths = [a for a in args if not a.startswith("-")]
    if unknown or len(paths) != 1:
        print(USAGE, file=sys.stderr)
        return 2
    if not os.path.exists(paths[0]):
        print(f"error: no such file or directory: {paths[0]}", file=sys.stderr)
        return 1
    try:
        recs = run_batch(paths[0], "--quick" in opts, "-r" in opts)
    except (OSError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(recs, indent=2, default=str) if "--json" in opts else format_table(recs))
    return 0


def selftest() -> bool:
    """Build a temp dir (ELF, PNG, flag text, gzip, empty, unreadable) and verify classification, ranking, JSON."""
    import contextlib
    import struct
    import zlib
    mods = _mods()
    ok = True

    def check(cond: bool, msg: str) -> None:
        nonlocal ok
        if not cond:
            print(f"  batch selftest failed: {msg}")
            ok = False

    def chunk(t: bytes, b: bytes) -> bytes:
        return struct.pack(">I", len(b)) + t + b + struct.pack(">I", zlib.crc32(t + b) & 0xFFFFFFFF)

    png = (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0))
           + chunk(b"IDAT", zlib.compress(b"\x00\x00")) + chunk(b"IEND", b""))
    with tempfile.TemporaryDirectory() as d:
        files = {"prog.bin": mods["disasm"].build_test_elf(), "pic.png": png,
                 "note.txt": b"nothing here\nthe real answer: flag{batch_works}\n",
                 "pack.gz": gzip.compress(b"hello archive payload " * 4), "empty.dat": b""}
        for n, b in files.items():
            with open(os.path.join(d, n), "wb") as fh:
                fh.write(b)
        locked = os.path.join(d, "locked.bin")
        with open(locked, "wb") as fh:
            fh.write(b"secret")
        os.chmod(locked, 0)
        recs = run_batch(d)
        by = {r["file"]: r for r in recs}
        check(len(recs) == 6, f"expected 6 records, got {len(recs)}")
        check(by["prog.bin"]["category"] == "elf" and "protections" in by["prog.bin"] and "entry" in by["prog.bin"], "ELF routing")
        check(by["pic.png"]["category"] == "image" and by["pic.png"].get("meta"), "PNG routing")
        check(by["note.txt"]["category"] == "text" and by["note.txt"]["flags"] == ["flag{batch_works}"], "text flag hit")
        check(by["pack.gz"]["category"] == "archive" and by["pack.gz"].get("members"), "gzip routing")
        check(by["empty.dat"]["category"] == "empty", "zero-byte file tolerated")
        check("locked.bin" in by, "unreadable file tolerated")
        check(recs[0]["file"] == "note.txt", "flag file ranked first")
        quick = {r["file"]: r for r in run_batch(d, quick=True)}
        check("entry" not in quick["prog.bin"] and "protections" in quick["prog.bin"], "--quick skips disasm")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = run([d, "--json"])
        try:
            parsed = json.loads(buf.getvalue())
            check(rc == 0 and isinstance(parsed, list) and len(parsed) == 6, "--json shape")
        except ValueError:
            check(False, "--json not parseable")
        check("note.txt" in format_table(recs), "table renders")
        os.chmod(locked, 0o600)
    check(run(["/nonexistent-batch-dir"]) == 1, "missing path returns 1")
    check(run(["--bogus", "x"]) == 2, "bad flag returns 2")
    return ok
