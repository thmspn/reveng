"""triage: first-look file analysis (type, hashes, strings, entropy, ELF/PE headers)."""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import math
import os
import re
import struct
import sys

NAME = "triage"
DESCRIPTION = "File type, hashes, strings, entropy, ELF protections / PE headers"

MAGICS: list[tuple[bytes, str]] = [
    (b"\x7fELF", "ELF executable/object"),
    (b"MZ", "DOS/PE executable"),
    (b"\xcf\xfa\xed\xfe", "Mach-O 64-bit"),
    (b"\xce\xfa\xed\xfe", "Mach-O 32-bit"),
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF8", "GIF image"),
    (b"PK\x03\x04", "ZIP archive"),
    (b"\x1f\x8b", "gzip data"),
    (b"BZh", "bzip2 data"),
    (b"\xfd7zXZ\x00", "xz data"),
    (b"7z\xbc\xaf\x27\x1c", "7-zip archive"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"%PDF", "PDF document"),
    (b"SQLite format 3\x00", "SQLite database"),
    (b"#!", "script (shebang)"),
]

ELF_MACHINES = {
    3: "x86", 8: "MIPS", 20: "PowerPC", 21: "PowerPC64", 40: "ARM",
    62: "x86-64", 183: "AArch64", 243: "RISC-V", 22: "S390",
}
ELF_TYPES = {1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}
PE_MACHINES = {0x14C: "x86", 0x8664: "x86-64", 0x1C0: "ARM", 0xAA64: "AArch64", 0x200: "IA-64"}
PE_SUBSYSTEMS = {1: "native", 2: "Windows GUI", 3: "Windows console", 9: "Windows CE", 10: "EFI application"}

PT_LOAD, PT_DYNAMIC, PT_INTERP, PT_GNU_STACK, PT_GNU_RELRO = 1, 2, 3, 0x6474E551, 0x6474E552
DT_NULL, DT_BIND_NOW, DT_FLAGS, DT_FLAGS_1 = 0, 24, 30, 0x6FFFFFFB
DF_BIND_NOW, DF_1_NOW = 0x8, 0x1
SHT_NOBITS = 8


def detect_type(data: bytes) -> str:
    """Identify file type from magic bytes; fall back to text/data by content."""
    for magic, name in MAGICS:
        if data.startswith(magic):
            return name
    if data[:512] and all(b in b"\t\n\r\x0c" or 0x20 <= b < 0x7F for b in data[:512]):
        return "ASCII text"
    return "data"


def hashes(data: bytes) -> dict[str, str]:
    """Return md5/sha1/sha256 hex digests."""
    return {n: hashlib.new(n, data).hexdigest() for n in ("md5", "sha1", "sha256")}


def extract_strings(data: bytes, min_len: int = 4) -> tuple[list[str], list[str]]:
    """Return (ascii_strings, utf16le_strings) with at least ``min_len`` characters."""
    n = max(1, min_len)
    ascii_re = re.compile(rb"[\x20-\x7e\t]{%d,}" % n)
    utf16_re = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % n)
    return (
        [m.group().decode("ascii") for m in ascii_re.finditer(data)],
        [m.group().decode("utf-16le") for m in utf16_re.finditer(data)],
    )


def entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (0.0 - 8.0)."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data)
    return -sum(c / total * math.log2(c / total) for c in counts if c)


def entropy_note(value: float, size: int = 1 << 12) -> str:
    """Heuristic interpretation of an entropy value."""
    if size < 64:
        return "too small to judge"
    if value >= 7.2:
        return "likely packed/encrypted"
    if value >= 6.5:
        return "high (compressed data or dense code)"
    return "normal"


def parse_elf(data: bytes) -> dict:
    """Parse ELF headers. Raises ValueError on truncated/malformed input."""
    if len(data) < 52 or data[:4] != b"\x7fELF":
        raise ValueError("not an ELF file")
    if data[4] not in (1, 2) or data[5] not in (1, 2):
        raise ValueError("invalid ELF class/endianness")
    is64 = data[4] == 2
    e = "<" if data[5] == 1 else ">"
    try:
        if is64:
            (etype, mach, _v, entry, phoff, shoff, _fl, _eh, phentsz, phnum, shentsz, shnum, shstrndx) = \
                struct.unpack_from(e + "HHIQQQIHHHHHH", data, 16)
        else:
            (etype, mach, _v, entry, phoff, shoff, _fl, _eh, phentsz, phnum, shentsz, shnum, shstrndx) = \
                struct.unpack_from(e + "HHIIIIIHHHHHH", data, 16)
    except struct.error as exc:
        raise ValueError(f"truncated ELF header: {exc}") from exc

    segs: list[dict] = []
    for i in range(phnum):
        off = phoff + i * phentsz
        try:
            if is64:
                t, fl, o, va, _pa, fsz, msz, _al = struct.unpack_from(e + "IIQQQQQQ", data, off)
            else:
                t, o, va, _pa, fsz, msz, fl, _al = struct.unpack_from(e + "IIIIIIII", data, off)
        except struct.error as exc:
            raise ValueError(f"truncated program header {i}") from exc
        segs.append({"type": t, "flags": fl, "off": o, "vaddr": va, "filesz": fsz, "memsz": msz})

    secs: list[dict] = []
    if shoff and shnum:
        for i in range(shnum):
            off = shoff + i * shentsz
            try:
                if is64:
                    nm, st, fl, _a, o, sz, *_ = struct.unpack_from(e + "IIQQQQIIQQ", data, off)
                else:
                    nm, st, fl, _a, o, sz, *_ = struct.unpack_from(e + "IIIIIIIIII", data, off)
            except struct.error:
                secs = []  # corrupted section table: report no sections rather than garbage
                break
            secs.append({"name_off": nm, "type": st, "flags": fl, "off": o, "size": sz})
        if secs and shstrndx < len(secs):
            stab = secs[shstrndx]
            blob = data[stab["off"]:stab["off"] + stab["size"]]
            for s in secs:
                end = blob.find(b"\0", s["name_off"])
                s["name"] = blob[s["name_off"]:end if end >= 0 else None].decode("latin-1") if blob else ""
        else:
            for s in secs:
                s["name"] = ""

    interp = None
    for s in segs:
        if s["type"] == PT_INTERP:
            raw = data[s["off"]:s["off"] + s["filesz"]]
            interp = raw.split(b"\0")[0].decode("latin-1")
    return {"is64": is64, "endian": "little" if e == "<" else "big", "type": etype, "machine": mach,
            "entry": entry, "segments": segs, "sections": secs, "interp": interp, "e": e}


def _dynamic_flags(data: bytes, info: dict) -> tuple[bool, bool]:
    """Return (bind_now, found_dynamic) by walking PT_DYNAMIC."""
    e, is64 = info["e"], info["is64"]
    size = 16 if is64 else 8
    fmt = e + ("qQ" if is64 else "iI")
    for s in info["segments"]:
        if s["type"] != PT_DYNAMIC:
            continue
        bind_now = False
        for off in range(s["off"], min(s["off"] + s["filesz"], len(data)) - size + 1, size):
            tag, val = struct.unpack_from(fmt, data, off)
            if tag == DT_NULL:
                break
            if tag == DT_BIND_NOW or (tag == DT_FLAGS and val & DF_BIND_NOW) or (tag == DT_FLAGS_1 and val & DF_1_NOW):
                bind_now = True
        return bind_now, True
    return False, False


def elf_protections(data: bytes, info: dict) -> dict[str, str]:
    """checksec-style protections for a parsed ELF."""
    segs = info["segments"]
    stack = [s for s in segs if s["type"] == PT_GNU_STACK]
    nx = "enabled" if stack and not stack[0]["flags"] & 1 else ("DISABLED (exec stack)" if stack else "DISABLED (no PT_GNU_STACK)")
    if info["type"] == 3:
        pie = "enabled" if info["interp"] else "shared object / static-PIE"
    else:
        pie = "no (fixed address)"
    bind_now, _ = _dynamic_flags(data, info)
    if any(s["type"] == PT_GNU_RELRO for s in segs):
        relro = "Full" if bind_now else "Partial"
    else:
        relro = "None"
    names = b""
    sym_secs = [s for s in info["sections"] if s["name"] in (".dynstr", ".strtab")]
    if sym_secs:
        for s in sym_secs:
            names += data[s["off"]:s["off"] + s["size"]]
        scope = ""
    else:
        names, scope = data, " (whole-file scan, may be inexact)"
    canary = "found" if b"__stack_chk_fail" in names else "not found"
    fortified = sorted({m.group().decode() for m in re.finditer(rb"__\w+_chk\b", names)} - {"__stack_chk"})
    fortified = [f for f in fortified if f != "__stack_chk_fail"]
    fortify = "yes (" + ", ".join(fortified[:6]) + (", ..." if len(fortified) > 6 else "") + ")" if fortified else "no fortified functions seen"
    return {"NX": nx, "PIE": pie, "Canary": canary + scope, "RELRO": relro, "FORTIFY": fortify + scope}


def parse_pe(data: bytes) -> dict:
    """Parse basic PE headers. Raises ValueError if malformed."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError("not a PE file")
    (lfanew,) = struct.unpack_from("<I", data, 0x3C)
    if data[lfanew:lfanew + 4] != b"PE\0\0":
        raise ValueError("MZ without PE signature (plain DOS executable)")
    try:
        mach, nsec, _ts, _sp, _ns, optsz, chars = struct.unpack_from("<HHIIIHH", data, lfanew + 4)
        opt = lfanew + 24
        magic = struct.unpack_from("<H", data, opt)[0]
        entry = struct.unpack_from("<I", data, opt + 16)[0]
        if magic == 0x20B:
            base = struct.unpack_from("<Q", data, opt + 24)[0]
        else:
            base = struct.unpack_from("<I", data, opt + 28)[0]
        subsys = struct.unpack_from("<H", data, opt + 68)[0]
        secs = []
        for i in range(nsec):
            raw = data[opt + optsz + i * 40:opt + optsz + (i + 1) * 40]
            if len(raw) < 40:
                raise ValueError("truncated section table")
            name = raw[:8].rstrip(b"\0").decode("latin-1")
            vsz, va, rsz, roff = struct.unpack_from("<IIII", raw, 8)
            secs.append({"name": name, "off": roff, "size": rsz, "vsize": vsz, "va": va})
    except struct.error as exc:
        raise ValueError(f"truncated PE header: {exc}") from exc
    return {"machine": PE_MACHINES.get(mach, hex(mach)), "plus": magic == 0x20B, "dll": bool(chars & 0x2000),
            "entry": entry, "base": base, "subsystem": PE_SUBSYSTEMS.get(subsys, str(subsys)), "sections": secs}


def _section_table(data: bytes, secs: list[dict], skip_nobits: bool) -> list[str]:
    lines = [f"  {'name':<16}{'offset':>10}{'size':>10}{'entropy':>9}  note"]
    for s in secs:
        if skip_nobits and s.get("type") == SHT_NOBITS:
            continue
        if not s["name"] and s["size"] == 0:
            continue
        chunk = data[s["off"]:s["off"] + s["size"]]
        ent = entropy(chunk)
        lines.append(f"  {s['name']:<16}{s['off']:>#10x}{s['size']:>#10x}{ent:>9.3f}  {entropy_note(ent, len(chunk))}")
    return lines


def analyze(data: bytes, min_len: int = 4, max_strings: int = 200, show_strings: bool = True) -> str:
    """Build the full triage report for a buffer."""
    out = [f"type:    {detect_type(data)}", f"size:    {len(data)} bytes"]
    out += [f"{n:<8} {h}" for n, h in hashes(data).items()]
    total = entropy(data)
    out.append(f"entropy: {total:.3f} bits/byte - {entropy_note(total, len(data))}")

    if data.startswith(b"\x7fELF"):
        out.append("\n-- ELF --")
        try:
            info = parse_elf(data)
        except ValueError as exc:
            out.append(f"ELF parse error: {exc}")
        else:
            out += [
                f"class:   {'ELF64' if info['is64'] else 'ELF32'}",
                f"endian:  {info['endian']}",
                f"machine: {ELF_MACHINES.get(info['machine'], hex(info['machine']))}",
                f"type:    {ELF_TYPES.get(info['type'], hex(info['type']))}",
                f"entry:   {info['entry']:#x}",
                f"interp:  {info['interp'] or '(none)'}",
            ]
            out.append("protections:")
            out += [f"  {k:<8}{v}" for k, v in elf_protections(data, info).items()]
            if info["sections"]:
                out.append(f"sections ({len(info['sections'])}):")
                out += _section_table(data, info["sections"], True)
            else:
                out.append("sections: none readable (stripped/corrupt section headers)")
    elif data.startswith(b"MZ"):
        out.append("\n-- PE --")
        try:
            pe = parse_pe(data)
        except ValueError as exc:
            out.append(f"PE parse error: {exc}")
        else:
            out += [
                f"format:  PE32{'+' if pe['plus'] else ''}{' DLL' if pe['dll'] else ''}",
                f"machine: {pe['machine']}",
                f"subsys:  {pe['subsystem']}",
                f"entry:   RVA {pe['entry']:#x}",
                f"base:    {pe['base']:#x}",
                f"sections ({len(pe['sections'])}):",
            ]
            out += _section_table(data, pe["sections"], False)

    if show_strings:
        a, u = extract_strings(data, min_len)
        for label, items in (("ASCII", a), ("UTF-16LE", u)):
            out.append(f"\n-- {label} strings (min {min_len}): {len(items)} --")
            out += items[:max_strings]
            if len(items) > max_strings:
                out.append(f"... {len(items) - max_strings} more (raise --max-strings)")
    return "\n".join(out)


def run(args: list[str]) -> int:
    """CLI entry point (registry contract); returns a process exit code."""
    if args[:1] in (["selftest"], ["--selftest"]):
        return 0 if selftest() else 1
    p = argparse.ArgumentParser(prog="recon.py triage", description=DESCRIPTION)
    p.add_argument("path", help="file to analyze")
    p.add_argument("-n", "--min-len", type=int, default=4, help="minimum string length (default 4)")
    p.add_argument("--max-strings", type=int, default=200, help="max strings printed per encoding (default 200)")
    p.add_argument("--no-strings", action="store_true", help="skip string extraction")
    if not args:
        p.print_help()
        return 0
    try:
        ns = p.parse_args(args)
    except SystemExit as exc:  # -h -> 0, usage error -> 2; return instead of exiting
        return exc.code if isinstance(exc.code, int) else 2
    try:
        with open(ns.path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(analyze(data, ns.min_len, ns.max_strings, not ns.no_strings))
    return 0


def _build_elf64(*, nx: bool = True, relro_now: bool = True) -> bytes:
    """Construct a minimal ET_DYN ELF64 with interp, GNU_STACK, GNU_RELRO, dynamic, and sections."""
    interp = b"/lib64/ld-linux-x86-64.so.2\0"
    dyn = struct.pack("<qQqQ", DT_FLAGS_1 if relro_now else 1, DF_1_NOW if relro_now else 0, DT_NULL, 0)
    dynstr = b"\0__stack_chk_fail\0__printf_chk\0"
    shstr = b"\0.dynstr\0.shstrtab\0"
    phnum, phoff = 4, 64
    base = phoff + phnum * 56
    interp_off, dyn_off = base, base + len(interp)
    dynstr_off = dyn_off + len(dyn)
    shstr_off = dynstr_off + len(dynstr)
    shoff = shstr_off + len(shstr)
    ph = struct.pack("<IIQQQQQQ", PT_INTERP, 4, interp_off, interp_off, interp_off, len(interp), len(interp), 1)
    ph += struct.pack("<IIQQQQQQ", PT_DYNAMIC, 6, dyn_off, dyn_off, dyn_off, len(dyn), len(dyn), 8)
    ph += struct.pack("<IIQQQQQQ", PT_GNU_STACK, 6 if nx else 7, 0, 0, 0, 0, 0, 16)
    ph += struct.pack("<IIQQQQQQ", PT_GNU_RELRO, 4, 0, 0, 0, 0, 0, 1)
    sh = b"\0" * 64
    sh += struct.pack("<IIQQQQIIQQ", 1, 3, 2, 0, dynstr_off, len(dynstr), 0, 0, 1, 0)
    sh += struct.pack("<IIQQQQIIQQ", 9, 3, 0, 0, shstr_off, len(shstr), 0, 0, 1, 0)
    hdr = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\0" * 8
    hdr += struct.pack("<HHIQQQIHHHHHH", 3, 62, 1, 0x1040, phoff, shoff, 0, 64, 56, phnum, 64, 3, 2)
    return hdr + ph + interp + dyn + dynstr + shstr + sh


def _build_pe64() -> bytes:
    """Construct a minimal PE32+ with one .text section."""
    dos = b"MZ" + b"\0" * 58 + struct.pack("<I", 0x40)
    coff = b"PE\0\0" + struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 240, 0x22)
    opt = bytearray(240)
    struct.pack_into("<HBBIII", opt, 0, 0x20B, 14, 0, 0x200, 0, 0)
    struct.pack_into("<I", opt, 16, 0x1000)
    struct.pack_into("<Q", opt, 24, 0x140000000)
    struct.pack_into("<H", opt, 68, 3)
    sec = b".text\0\0\0" + struct.pack("<IIIIIIHHI", 0x100, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)
    return dos + coff + bytes(opt) + sec + b"\0" * (0x200 - 0x40 - len(coff) - 240 - 40) + b"\x90" * 0x200


def selftest() -> bool:
    """Check triage against synthetic buffers and this toolkit's own files."""
    results: list[tuple[str, bool]] = []

    def check(name: str, cond: bool) -> None:
        results.append((name, cond))
        if not cond:
            print(f"  failed: {name}")

    check("md5 of empty", hashes(b"")["md5"] == "d41d8cd98f00b204e9800998ecf8427e")
    check("sha256 of abc", hashes(b"abc")["sha256"].startswith("ba7816bf"))
    check("entropy zero", entropy(b"\0" * 100) == 0.0)
    check("entropy uniform", abs(entropy(bytes(range(256)) * 4) - 8.0) < 1e-9)
    a, u = extract_strings(b"\x01hello\x02ab\x03w\0o\0r\0l\0d\0\x01", 4)
    check("ascii strings", a == ["hello"])
    check("utf16 strings", u == ["world"])
    check("min_len honored", extract_strings(b"abc\x00abcd", 4)[0] == ["abcd"])
    check("magic png", detect_type(b"\x89PNG\r\n\x1a\n" + b"\0" * 8) == "PNG image")
    check("magic text", detect_type(b"just text\n") == "ASCII text")
    check("magic data", detect_type(b"\xff\x00\xfe") == "data")

    elf = _build_elf64()
    info = parse_elf(elf)
    prot = elf_protections(elf, info)
    check("elf64 class", info["is64"] and info["endian"] == "little")
    check("elf machine", ELF_MACHINES[info["machine"]] == "x86-64" and info["entry"] == 0x1040)
    check("elf interp", info["interp"] == "/lib64/ld-linux-x86-64.so.2")
    check("elf sections named", [s["name"] for s in info["sections"]][1:] == [".dynstr", ".shstrtab"])
    check("elf NX on", prot["NX"] == "enabled")
    check("elf PIE", prot["PIE"] == "enabled")
    check("elf canary", prot["Canary"].startswith("found"))
    check("elf full RELRO", prot["RELRO"] == "Full")
    check("elf fortify", prot["FORTIFY"].startswith("yes") and "__printf_chk" in prot["FORTIFY"])
    weak = elf_protections(*(lambda b: (b, parse_elf(b)))(_build_elf64(nx=False, relro_now=False)))
    check("elf exec stack + partial RELRO", weak["NX"].startswith("DISABLED") and weak["RELRO"] == "Partial")
    check("truncated elf rejected", _raises(lambda: parse_elf(elf[:30])))
    check("truncated elf report no crash", "parse error" in analyze(elf[:30], show_strings=False))
    check("report has protections", "protections:" in analyze(elf, show_strings=False))

    pe = parse_pe(_build_pe64())
    check("pe header", pe["machine"] == "x86-64" and pe["plus"] and pe["entry"] == 0x1000)
    check("pe base/subsys", pe["base"] == 0x140000000 and pe["subsystem"] == "Windows console")
    check("pe section", [s["name"] for s in pe["sections"]] == [".text"])
    check("pe report", "PE32+" in analyze(_build_pe64(), show_strings=False))

    here = os.path.dirname(os.path.abspath(__file__))
    for fname in (os.path.join(here, "..", "recon.py"), os.path.abspath(__file__)):
        with open(fname, "rb") as fh:
            body = fh.read()
        rep = analyze(body, 6)
        check(f"self-analysis {os.path.basename(fname)}",
              ("ASCII text" in rep or "script (shebang)" in rep) and "sha256" in rep and "def " in rep)

    check("packed heuristic", entropy_note(7.9) == "likely packed/encrypted")
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        codes = (run([]), run(["-h"]), run(["--bogus"]), run(["/nonexistent/x"]))
    check("cli: bare/-h -> 0, bad flag -> 2, missing file -> 1", codes == (0, 0, 2, 1))
    return all(ok for _, ok in results)


def _raises(fn) -> bool:
    try:
        fn()
    except ValueError:
        return True
    return False


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
