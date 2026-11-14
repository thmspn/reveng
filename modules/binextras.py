"""Bin-exploitation/RE extras: cyclic (De Bruijn) pattern gen/offset, pure-Python ROP gadget
finder over ELF executable sections, binwalk-style magic-signature scan + carve, and small
pack/unpack + hexdump helpers. Pure stdlib, offline. ropper/ROPgadget are optional
subprocess-wrapped extras (shutil.which-gated) layered on top of the pure-Python gadget scan."""
from __future__ import annotations

import argparse
import shutil
import struct
import subprocess
import sys

NAME = "binextras"
DESCRIPTION = "Cyclic pattern gen/offset, ROP gadget finder, binwalk-style carving, pack/hexdump helpers"

# --------------------------------------------------------------------------- cyclic pattern

def cyclic(length: int, alphabet: bytes = None, n: int = 4) -> bytes:
    """Generate a De Bruijn-style cyclic pattern of ``length`` bytes over ``alphabet`` with
    unique ``n``-byte subsequences (pwntools default: n=4, lowercase a-z alphabet). Every
    n-byte window in the returned bytes is unique until the sequence repeats, so an offset can
    be recovered uniquely from any n-byte slice found in it."""
    if alphabet is None:
        alphabet = bytes(range(ord("a"), ord("z") + 1))
    if n < 1:
        raise ValueError("n must be >= 1")
    k = len(alphabet)
    a = [0] * (k * n)
    seq: list[int] = []

    def db(t: int, p: int) -> None:
        if t > n:
            if n % p == 0:
                seq.extend(a[1:p + 1])
        else:
            a[t] = a[t - p]
            db(t + 1, p)
            for j in range(a[t - p] + 1, k):
                a[t] = j
                db(t + 1, t)

    db(1, 1)
    out = bytes(alphabet[i] for i in seq)
    if not out:
        out = alphabet[:1]
    reps = length // len(out) + 2
    return (out * reps)[:length]


def cyclic_find(subseq, alphabet: bytes = None, n: int = 4) -> int:
    """Inverse of cyclic(): given an n-byte (or int) value taken from a cyclic pattern, return
    the byte offset at which it occurs, or -1 if not found. Accepts bytes/str/int; an int is
    interpreted little-endian (pwntools convention, e.g. a crashed RIP of 0x6161616c)."""
    if alphabet is None:
        alphabet = bytes(range(ord("a"), ord("z") + 1))
    if isinstance(subseq, int):
        width = max(1, (subseq.bit_length() + 7) // 8)
        width = max(width, n) if subseq != 0 else n
        needle = subseq.to_bytes(width, "little")[:n]
    elif isinstance(subseq, str):
        needle = subseq.encode()
    else:
        needle = bytes(subseq)
    # search generously far enough to cover any realistic buffer/register width
    haystack = cyclic(len(alphabet) ** n + n * 4, alphabet, n)
    idx = haystack.find(needle)
    return idx


# --------------------------------------------------------------------------- ELF parsing (minimal)

class ElfSection:
    __slots__ = ("name", "addr", "offset", "size", "flags")

    def __init__(self, name: str, addr: int, offset: int, size: int, flags: int):
        self.name = name
        self.addr = addr
        self.offset = offset
        self.size = size
        self.flags = flags


def parse_elf_sections(data: bytes) -> list[ElfSection]:
    """Minimal ELF32/64 section-header parser using struct only. Returns sections with their
    virtual address, file offset, size and flags (enough to locate executable bytes)."""
    if data[:4] != b"\x7fELF":
        raise ValueError("not an ELF file")
    ei_class = data[4]
    is64 = ei_class == 2
    endian = "<" if data[5] == 1 else ">"
    if is64:
        e_shoff, = struct.unpack_from(endian + "Q", data, 0x28)
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(endian + "HHH", data, 0x3A)
    else:
        e_shoff, = struct.unpack_from(endian + "I", data, 0x20)
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(endian + "HHH", data, 0x2E)
    if e_shoff == 0 or e_shnum == 0:
        return []
    raw = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        if is64:
            name_off, sh_type, flags, addr, offset, size = struct.unpack_from(endian + "IIQQQQ", data, off)
        else:
            name_off, sh_type, flags, addr, offset, size = struct.unpack_from(endian + "IIIIII", data, off)
        raw.append((name_off, sh_type, flags, addr, offset, size))
    strtab_off = raw[e_shstrndx][4] if e_shstrndx < len(raw) else 0
    sections = []
    for name_off, _sh_type, flags, addr, offset, size in raw:
        end = data.find(b"\0", strtab_off + name_off)
        name = data[strtab_off + name_off:end].decode("ascii", "replace") if strtab_off else ""
        sections.append(ElfSection(name, addr, offset, size, flags))
    return sections


SHF_EXECINSTR = 0x4


def executable_regions(data: bytes) -> list[tuple[int, bytes]]:
    """Return (vaddr, bytes) for every ELF section flagged executable (SHF_EXECINSTR)."""
    out = []
    for sec in parse_elf_sections(data):
        if sec.flags & SHF_EXECINSTR and sec.size:
            out.append((sec.addr, data[sec.offset:sec.offset + sec.size]))
    return out


# --------------------------------------------------------------------------- ROP gadget scan

# A gadget is a short byte sequence ending in a control-flow instruction (ret / syscall / jmp).
# x86-64 opcodes used below:
#   pop reg: 0x58-0x5F (rax..rdi); pop r8-15: REX.B(0x41)+0x58-0x5F
#   ret: 0xC3 ; leave;ret: 0xC9 0xC3 ; syscall: 0x0F 0x05 ; int 0x80: 0xCD 0x80
_POP_REG64 = {0x58: "rax", 0x59: "rcx", 0x5A: "rdx", 0x5B: "rbx",
              0x5C: "rsp", 0x5D: "rbp", 0x5E: "rsi", 0x5F: "rdi"}
_POP_REG64_REX = {0x58: "r8", 0x59: "r9", 0x5A: "r10", 0x5B: "r11",
                  0x5C: "r12", 0x5D: "r13", 0x5E: "r14", 0x5F: "r15"}

_GADGET_KINDS = ("pop_ret", "pop_pop_ret", "pop_pop_pop_ret", "ret", "syscall", "leave_ret", "int80")


def _mnemonic(byte: int, rex: bool) -> str | None:
    if byte == 0xC3:
        return "ret"
    reg = (_POP_REG64_REX if rex else _POP_REG64).get(byte)
    return f"pop {reg}" if reg else None


def find_gadgets(data: bytes, base_addr: int = 0, max_len: int = 6) -> list[dict]:
    """Pure-Python scan of a byte blob for small, useful ROP gadgets: chains of `pop reg`
    ending in `ret`, bare `ret`, `leave; ret`, `syscall`, and `int 0x80`. Returns a list of
    dicts: {addr, bytes, asm, kind}, ordered by address. ``base_addr`` is added to the byte
    offset to report a virtual address (pass an ELF section's vaddr for real binaries)."""
    found: list[dict] = []
    n = len(data)
    i = 0
    while i < n:
        b = data[i]
        # syscall: 0F 05
        if b == 0x0F and i + 1 < n and data[i + 1] == 0x05:
            found.append(_mk(base_addr, i, data[i:i + 2], "syscall", "syscall"))
            i += 1
            continue
        # int 0x80
        if b == 0xCD and i + 1 < n and data[i + 1] == 0x80:
            found.append(_mk(base_addr, i, data[i:i + 2], "int80", "int 0x80"))
            i += 1
            continue
        # leave; ret
        if b == 0xC9 and i + 1 < n and data[i + 1] == 0xC3:
            found.append(_mk(base_addr, i, data[i:i + 2], "leave_ret", "leave; ret"))
            i += 1
            continue
        # bare ret
        if b == 0xC3:
            found.append(_mk(base_addr, i, data[i:i + 1], "ret", "ret"))
            i += 1
            continue
        # chains of pop (optionally REX-prefixed) ending in ret, scanned forward from i
        j = i
        ops: list[str] = []
        used_rex = False
        while j < n and len(ops) < (max_len - 1):
            rex = data[j] == 0x41
            k = j + 1 if rex else j
            if k >= n:
                break
            mnem = _mnemonic(data[k], rex)
            if mnem is None or not mnem.startswith("pop"):
                break
            ops.append(mnem)
            used_rex = used_rex or rex
            j = k + 1
        if ops and j < n and data[j] == 0xC3:
            kind = {1: "pop_ret", 2: "pop_pop_ret", 3: "pop_pop_pop_ret"}.get(len(ops), "pop_chain_ret")
            asm = "; ".join(ops) + "; ret"
            found.append(_mk(base_addr, i, data[i:j + 1], kind, asm))
        i += 1
    return found


def _mk(base_addr: int, off: int, raw: bytes, kind: str, asm: str) -> dict:
    return {"addr": base_addr + off, "bytes": raw.hex(), "asm": asm, "kind": kind}


def find_gadgets_elf(data: bytes, max_len: int = 6) -> list[dict]:
    """Run find_gadgets() over every executable section of an ELF file's bytes."""
    out: list[dict] = []
    for addr, section in executable_regions(data):
        out.extend(find_gadgets(section, addr, max_len))
    out.sort(key=lambda g: g["addr"])
    return out


def external_gadget_scan(path: str, tool: str = "ropper") -> str | None:
    """Optional: shell out to ropper or ROPgadget if installed on PATH for richer gadget
    output. Returns the tool's stdout, or None if the tool isn't available. Never installs
    anything and makes no network calls; pure local subprocess invocation."""
    exe = shutil.which(tool)
    if exe is None:
        return None
    cmd = [exe, "--file", path] if tool == "ropper" else [exe, "--binary", path]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return res.stdout
    except (OSError, subprocess.SubprocessError):
        return None


# --------------------------------------------------------------------------- signature carving

# (name, magic bytes, offset within file where the magic must appear)
MAGICS: tuple[tuple[str, bytes, int], ...] = (
    ("ELF", b"\x7fELF", 0),
    ("PE/MZ", b"MZ", 0),
    ("ZIP", b"PK\x03\x04", 0),
    ("ZIP(empty)", b"PK\x05\x06", 0),
    ("PNG", b"\x89PNG\r\n\x1a\n", 0),
    ("JPEG", b"\xff\xd8\xff", 0),
    ("GIF87a", b"GIF87a", 0),
    ("GIF89a", b"GIF89a", 0),
    ("GZIP", b"\x1f\x8b", 0),
    ("BZIP2", b"BZh", 0),
    ("7-Zip", b"7z\xbc\xaf\x27\x1c", 0),
    ("RAR", b"Rar!\x1a\x07", 0),
    ("SQLite", b"SQLite format 3\x00", 0),
    ("PDF", b"%PDF-", 0),
    ("XZ", b"\xfd7zXZ\x00", 0),
    ("ext2/3/4 superblock", b"\x53\xef", 0x438),
    ("BMP", b"BM", 0),
    ("TAR", b"ustar", 0x101),
    ("WAV/RIFF", b"RIFF", 0),
    ("ELF core/obj alt", b"\xcf\xfa\xed\xfe", 0),  # Mach-O 64-bit (bonus, common on carving CTFs)
    ("ZSTD", b"\x28\xb5\x2f\xfd", 0),
    ("LZ4", b"\x04\x22\x4d\x18", 0),
)


def scan_signatures(data: bytes) -> list[dict]:
    """Binwalk-style scan: find every occurrence of every known magic in ``data``. Each magic
    is searched at *every* offset (not just its canonical header offset) so embedded/appended
    blobs are found, except offset-anchored magics (e.g. ext4 superblock, tar magic) which are
    only reported when they land at their expected relative offset. Returns a list of
    {offset, name, magic_hex} sorted by offset."""
    hits: list[dict] = []
    for name, magic, anchor in MAGICS:
        start = 0
        while True:
            idx = data.find(magic, start)
            if idx == -1:
                break
            if anchor == 0 or (idx >= anchor and (idx - anchor) >= 0 and _anchor_ok(data, idx, anchor, magic)):
                hits.append({"offset": idx if anchor == 0 else idx - anchor, "name": name, "magic_hex": magic.hex()})
            start = idx + 1
    hits.sort(key=lambda h: h["offset"])
    return hits


def _anchor_ok(data: bytes, idx: int, anchor: int, magic: bytes) -> bool:
    """For anchored magics (anchor > 0), only accept a hit if subtracting the anchor gives a
    valid, non-negative candidate file start."""
    if anchor == 0:
        return True
    return idx - anchor >= 0


def carve(data: bytes, offset: int, length: int = None) -> bytes:
    """Extract the blob starting at ``offset``. Without ``length``, carves to the start of the
    next detected signature (or end of file) — a reasonable default for 'grab the next
    embedded file'. With ``length``, carves exactly that many bytes."""
    if offset < 0 or offset > len(data):
        raise ValueError("offset out of range")
    if length is not None:
        return data[offset:offset + length]
    hits = [h["offset"] for h in scan_signatures(data) if h["offset"] > offset]
    end = min(hits) if hits else len(data)
    return data[offset:end]


# --------------------------------------------------------------------------- pack/unpack + hexdump

_FMT = {8: "B", 16: "H", 32: "I", 64: "Q"}


def p(value: int, bits: int = 64, endian: str = "little", signed: bool = False) -> bytes:
    """Pack an integer to bytes of the given width (pwntools-style p8/p16/p32/p64 rolled into
    one). ``endian``: 'little' or 'big'."""
    if bits not in _FMT:
        raise ValueError("bits must be one of 8, 16, 32, 64")
    fmt = ("<" if endian == "little" else ">") + _FMT[bits].lower() if signed else \
        ("<" if endian == "little" else ">") + _FMT[bits]
    return struct.pack(fmt, value)


def u(data: bytes, bits: int = 64, endian: str = "little", signed: bool = False) -> int:
    """Unpack bytes to an integer (inverse of p()). Pads/truncates ``data`` to the exact width
    first so short reads (e.g. a 6-byte leak) still unpack cleanly, pwntools-style."""
    width = bits // 8
    if len(data) < width:
        pad = b"\x00" * (width - len(data))
        data = data + pad if endian == "little" else pad + data
    data = data[:width]
    fmt = ("<" if endian == "little" else ">") + _FMT[bits].lower() if signed else \
        ("<" if endian == "little" else ">") + _FMT[bits]
    return struct.unpack(fmt, data)[0]


def hexdump(data: bytes, width: int = 16, start: int = 0) -> str:
    """Classic offset/hex/ASCII hexdump, one line per ``width`` bytes."""
    lines = []
    for off in range(0, len(data), width):
        chunk = data[off:off + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        hexpart = hexpart.ljust(width * 3 - 1)
        ascii_part = "".join(chr(b) if 0x20 <= b < 0x7f else "." for b in chunk)
        lines.append(f"{start + off:08x}  {hexpart}  |{ascii_part}|")
    return "\n".join(lines)


# --------------------------------------------------------------------------- CLI

def run(args: list[str]) -> int:
    p_ = argparse.ArgumentParser(prog="recon.py binextras", description=DESCRIPTION)
    sub = p_.add_subparsers(dest="cmd")

    c = sub.add_parser("cyclic", help="generate a De Bruijn cyclic pattern")
    c.add_argument("length", type=int)
    c.add_argument("-n", type=int, default=4)

    f = sub.add_parser("cyclic-find", help="find the offset of a leaked value in a cyclic pattern")
    f.add_argument("value", help="hex int (0x...), decimal int, or literal subsequence string")
    f.add_argument("-n", type=int, default=4)

    g = sub.add_parser("gadgets", help="scan an ELF's executable sections for ROP gadgets")
    g.add_argument("file")
    g.add_argument("--tool", choices=("ropper", "ROPgadget"), help="also try an optional external scanner")

    s = sub.add_parser("scan", help="binwalk-style signature scan")
    s.add_argument("file")

    cv = sub.add_parser("carve", help="carve a blob out of a file at a given offset")
    cv.add_argument("file")
    cv.add_argument("offset", type=lambda x: int(x, 0))
    cv.add_argument("-o", "--out", required=True)
    cv.add_argument("-l", "--length", type=lambda x: int(x, 0))

    hd = sub.add_parser("hexdump", help="hexdump a file (or a slice of it)")
    hd.add_argument("file")
    hd.add_argument("-o", "--offset", type=lambda x: int(x, 0), default=0)
    hd.add_argument("-l", "--length", type=lambda x: int(x, 0))

    p_.add_argument("--selftest", action="store_true")
    a = p_.parse_args(args)

    if a.selftest or a.cmd is None:
        if a.selftest:
            return 0 if selftest() else 1
        p_.print_help()
        return 1

    if a.cmd == "cyclic":
        sys.stdout.buffer.write(cyclic(a.length, n=a.n))
        sys.stdout.write("\n")
        return 0
    if a.cmd == "cyclic-find":
        v = a.value
        try:
            v = int(v, 0)
        except ValueError:
            pass
        off = cyclic_find(v, n=a.n)
        print(off)
        return 0 if off >= 0 else 1
    if a.cmd == "gadgets":
        with open(a.file, "rb") as fh:
            data = fh.read()
        for gad in find_gadgets_elf(data):
            print(f"0x{gad['addr']:x}: {gad['asm']}  ({gad['bytes']})")
        if a.tool:
            out = external_gadget_scan(a.file, a.tool)
            if out is None:
                print(f"\n[{a.tool} not found on PATH -- skipped optional external scan]")
            else:
                print(f"\n--- {a.tool} output ---\n{out}")
        return 0
    if a.cmd == "scan":
        with open(a.file, "rb") as fh:
            data = fh.read()
        for h in scan_signatures(data):
            print(f"0x{h['offset']:08x}  {h['name']}  ({h['magic_hex']})")
        return 0
    if a.cmd == "carve":
        with open(a.file, "rb") as fh:
            data = fh.read()
        blob = carve(data, a.offset, a.length)
        with open(a.out, "wb") as fh:
            fh.write(blob)
        print(f"carved {len(blob)} bytes to {a.out}")
        return 0
    if a.cmd == "hexdump":
        with open(a.file, "rb") as fh:
            data = fh.read()
        end = a.offset + a.length if a.length else len(data)
        print(hexdump(data[a.offset:end], start=a.offset))
        return 0
    return 1


# --------------------------------------------------------------------------- self-test

def _make_test_elf() -> tuple[bytes, int]:
    """Build a minimal, synthetic 64-bit little-endian ELF with one executable section whose
    bytes contain planted ROP gadgets. Returns (file_bytes, text_vaddr)."""
    text_vaddr = 0x401000
    text = bytearray()
    # pop rdi; ret
    text += bytes([0x5F, 0xC3])
    pop_rdi_off = 0
    # pop rsi; pop rdx; ret
    pop_rsi_rdx_off = len(text)
    text += bytes([0x5E, 0x5A, 0xC3])
    # syscall
    syscall_off = len(text)
    text += bytes([0x0F, 0x05])
    # bare ret
    ret_off = len(text)
    text += bytes([0xC3])
    # leave; ret
    leave_ret_off = len(text)
    text += bytes([0xC9, 0xC3])
    # pop r15 (REX); ret
    pop_r15_off = len(text)
    text += bytes([0x41, 0x5F, 0xC3])
    # pad a bit so section size isn't trivially tiny
    text += b"\x90" * 8
    text = bytes(text)

    shstrtab = b"\0.text\0.shstrtab\0"
    text_name_off = 1
    shstrtab_name_off = 7

    header_size = 0x40
    text_file_off = header_size
    shstrtab_file_off = text_file_off + len(text)
    shoff = shstrtab_file_off + len(shstrtab)
    # pad shoff to 8-byte alignment
    pad = (-shoff) % 8
    shoff += pad

    def sh(name_off, sh_type, flags, addr, offset, size):
        return struct.pack("<IIQQQQIIQQ", name_off, sh_type, flags, addr, offset, size, 0, 0, 0, 0)

    SHF_EXECINSTR_LOCAL = 0x4
    SHF_ALLOC = 0x2
    shdrs = b""
    shdrs += sh(0, 0, 0, 0, 0, 0)  # NULL section
    shdrs += sh(text_name_off, 1, SHF_ALLOC | SHF_EXECINSTR_LOCAL, text_vaddr, text_file_off, len(text))  # .text
    shdrs += sh(shstrtab_name_off, 3, 0, 0, shstrtab_file_off, len(shstrtab))  # .shstrtab

    e_shnum = 3
    e_shstrndx = 2
    ehdr = bytearray(header_size)
    ehdr[0:4] = b"\x7fELF"
    ehdr[4] = 2  # 64-bit
    ehdr[5] = 1  # little-endian
    ehdr[6] = 1  # version
    struct.pack_into("<H", ehdr, 0x10, 2)  # e_type ET_EXEC
    struct.pack_into("<H", ehdr, 0x12, 0x3E)  # e_machine x86-64
    struct.pack_into("<I", ehdr, 0x14, 1)  # e_version
    struct.pack_into("<Q", ehdr, 0x28, shoff)  # e_shoff
    struct.pack_into("<H", ehdr, 0x3A, 64)  # e_shentsize
    struct.pack_into("<H", ehdr, 0x3C, e_shnum)  # e_shnum
    struct.pack_into("<H", ehdr, 0x3E, e_shstrndx)  # e_shstrndx

    data = bytes(ehdr) + text + shstrtab + (b"\0" * pad) + shdrs
    offsets = {
        "pop_rdi": text_vaddr + pop_rdi_off,
        "pop_rsi_rdx": text_vaddr + pop_rsi_rdx_off,
        "syscall": text_vaddr + syscall_off,
        "ret": text_vaddr + ret_off,
        "leave_ret": text_vaddr + leave_ret_off,
        "pop_r15": text_vaddr + pop_r15_off,
    }
    return data, offsets


def selftest() -> bool:
    ok: list[bool] = []

    def check(name, cond):
        ok.append(bool(cond))
        print(f"  [{'ok' if cond else 'FAIL'}] {name}")

    # --- cyclic: round trip both directions
    pat = cyclic(200, n=4)
    check("cyclic: length exact", len(pat) == 200)
    sample_off = 40
    needle = pat[sample_off:sample_off + 4]
    found = cyclic_find(needle, n=4)
    check("cyclic: bytes round-trip (forward->offset)", found == sample_off)
    as_int = int.from_bytes(needle, "little")
    found_int = cyclic_find(as_int, n=4)
    check("cyclic: int round-trip (e.g. leaked RIP)", found_int == sample_off)
    found_str = cyclic_find(needle.decode(), n=4)
    check("cyclic: str round-trip", found_str == sample_off)
    check("cyclic: known pwntools value 'laaa' resolves", cyclic_find("laaa", n=4) >= 0)
    check("cyclic: subsequence outside alphabet -> -1", cyclic_find(b"\x00\x00\x00\x00", n=4) == -1)
    check("cyclic: unique windows (no internal collision in first 500)",
          len({cyclic(2000, n=4)[i:i + 4] for i in range(0, 497)}) == 497)

    # --- ROP gadget scan: synthetic ELF with planted gadgets
    elf_bytes, addrs = _make_test_elf()
    sections = parse_elf_sections(elf_bytes)
    check("elf: .text section found", any(s.name == ".text" for s in sections))
    regions = executable_regions(elf_bytes)
    check("elf: executable region extracted", len(regions) == 1 and regions[0][0] == 0x401000)
    gadgets = find_gadgets_elf(elf_bytes)
    by_addr = {g["addr"]: g for g in gadgets}
    check("gadget: pop rdi; ret found", by_addr.get(addrs["pop_rdi"], {}).get("asm") == "pop rdi; ret")
    check("gadget: pop rsi; pop rdx; ret found",
          by_addr.get(addrs["pop_rsi_rdx"], {}).get("asm") == "pop rsi; pop rdx; ret")
    check("gadget: syscall found", by_addr.get(addrs["syscall"], {}).get("kind") == "syscall")
    check("gadget: bare ret found", by_addr.get(addrs["ret"], {}).get("kind") == "ret")
    check("gadget: leave; ret found", by_addr.get(addrs["leave_ret"], {}).get("kind") == "leave_ret")
    check("gadget: REX pop r15; ret found", by_addr.get(addrs["pop_r15"], {}).get("asm") == "pop r15; ret")
    check("elf: malformed input raises", _raises(lambda: parse_elf_sections(b"not an elf")))
    check("external: unknown tool returns None (optional, no crash)",
          external_gadget_scan("/nonexistent/path", "ropper") is None or shutil.which("ropper") is not None)

    # --- signature scan + carve: synthetic buffer with planted magics
    png_blob = b"\x89PNG\r\n\x1a\n" + b"\x00" * 20
    gz_blob = b"\x1f\x8b" + b"\x08" * 10
    zip_blob = b"PK\x03\x04" + b"\x01" * 15
    buf = b"JUNKJUNK" + png_blob + b"MIDDLE" + gz_blob + b"TAIL" + zip_blob + b"END"
    hits = scan_signatures(buf)
    names = [h["name"] for h in hits]
    check("scan: PNG found", "PNG" in names)
    check("scan: GZIP found", "GZIP" in names)
    check("scan: ZIP found", "ZIP" in names)
    check("scan: offsets ascending", [h["offset"] for h in hits] == sorted(h["offset"] for h in hits))
    png_off = next(h["offset"] for h in hits if h["name"] == "PNG")
    check("scan: PNG offset correct", buf[png_off:png_off + 8] == b"\x89PNG\r\n\x1a\n")

    carved_png = carve(buf, png_off)
    next_sig_off = min(h["offset"] for h in hits if h["offset"] > png_off)
    check("carve: stops at next signature", carved_png == buf[png_off:next_sig_off])
    carved_exact = carve(buf, png_off, length=len(png_blob))
    check("carve: exact length", carved_exact == png_blob)
    check("carve: out-of-range offset raises", _raises(lambda: carve(buf, len(buf) + 10)))

    # ext4 superblock magic at its anchored offset
    ext4_buf = b"\x00" * 0x438 + b"\x53\xef" + b"\x00" * 10
    check("scan: anchored ext4 magic at offset 0", any(h["name"].startswith("ext2") and h["offset"] == 0
                                                        for h in scan_signatures(ext4_buf)))

    # --- pack/unpack + hexdump
    check("p/u: u64 round trip", u(p(0xdeadbeefcafebabe, 64), 64) == 0xdeadbeefcafebabe)
    check("p/u: p32 big-endian", p(0x11223344, 32, "big") == b"\x11\x22\x33\x44")
    check("p/u: short read pads cleanly", u(b"\x41\x42", 32) == 0x4241)
    dump = hexdump(b"flag{hex}", width=8)
    check("hexdump: contains ascii column", "|flag{hex" in dump)
    check("hexdump: contains hex bytes", "66 6c 61 67" in dump)

    return all(ok)


def _raises(fn) -> bool:
    try:
        fn()
    except Exception:
        return True
    return False


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
