"""Bin-exploitation/RE extras: cyclic (De Bruijn) pattern gen/offset, pure-Python ROP gadget
finder over ELF executable sections, binwalk-style magic-signature scan + carve, and small
pack/unpack + hexdump helpers. Pure stdlib, offline. ropper/ROPgadget are optional
subprocess-wrapped extras (shutil.which-gated) layered on top of the pure-Python gadget scan."""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import os
import posixpath
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile
import zlib

NAME = "binextras"
DESCRIPTION = "Cyclic pattern gen/offset, ROP gadget finder, binwalk-style carving, recursive archive extract, pack/hexdump helpers"

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
    try:
        return _parse_elf_sections(data)
    except (struct.error, IndexError) as exc:
        raise ValueError(f"truncated/malformed ELF: {exc}") from exc


def _parse_elf_sections(data: bytes) -> list[ElfSection]:
    """Body of parse_elf_sections(); may raise struct.error on truncated input."""
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


# --------------------------------------------------------------------------- recursive archive extraction

MAX_DEPTH = 10                 # default recursion cap
MAX_FILE_BYTES = 256 << 20     # per extracted file (decompression-bomb guard)
MAX_TOTAL_BYTES = 1 << 30      # per run
MAX_FILES = 2000               # per run
FLAG_RE = re.compile(rb"[A-Za-z0-9_\-]{2,24}\{[\x21-\x7a\x7c\x7e]{1,200}\}")
_EOCD = b"PK\x05\x06"


def _zip_end(data: bytes, start: int, eocds: list[int]) -> int | None:
    """Logical end (exclusive) of the zip beginning at ``start``: locate an end-of-central-directory record whose
    central directory is consistent with ``start`` (cd_pos - cd_offset == start), so zips stored inside the
    archive, or other archives appended later, are not mistaken for this one. Returns None if no valid end."""
    for pos in eocds:
        if pos < start or pos + 22 > len(data):
            continue
        cd_size, cd_off = struct.unpack("<II", data[pos + 12:pos + 20])
        clen = struct.unpack("<H", data[pos + 20:pos + 22])[0]
        cd_pos = pos - cd_size
        if cd_pos - cd_off == start and data[cd_pos:cd_pos + 4] in (b"PK\x01\x02", b"PK\x05\x06"):
            return min(len(data), pos + 22 + clen)
    return None


def _png_end(data: bytes, start: int) -> int | None:
    """End of a PNG starting at ``start`` (after its IEND chunk + CRC), or None if chunks don't reach IEND."""
    i = start + 8
    while i + 12 <= len(data):
        ln = struct.unpack(">I", data[i:i + 4])[0]
        typ = data[i + 4:i + 8]
        if not re.fullmatch(rb"[A-Za-z]{4}", typ) or i + 12 + ln > len(data):
            return None
        i += 12 + ln
        if typ == b"IEND":
            return i
    return None


def _jpeg_end(data: bytes, start: int) -> int | None:
    """End of a JPEG starting at ``start``: walk marker segments to SOS, then scan entropy data for the EOI
    (FFD9 not preceded by a stuffed 00 / restart marker); nested thumbnails sit inside APPn segments so are skipped."""
    i = start + 2
    while i + 4 <= len(data):
        if data[i] != 0xFF:
            return None
        mk = data[i + 1]
        if mk == 0xD9:
            return i + 2
        if mk == 0xFF:
            i += 1
            continue
        ln = struct.unpack(">H", data[i + 2:i + 4])[0]
        i += 2 + ln
        if mk == 0xDA:  # SOS: entropy-coded data follows
            while i + 1 < len(data):
                j = data.find(b"\xff", i)
                if j < 0 or j + 1 >= len(data):
                    return None
                nxt = data[j + 1]
                if nxt == 0xD9:
                    return j + 2
                i = j + 2 if (nxt == 0 or 0xD0 <= nxt <= 0xD7 or nxt == 0xFF) else j
                if not (nxt == 0 or 0xD0 <= nxt <= 0xD7 or nxt == 0xFF):
                    break  # another marker segment (e.g. progressive JPEG): resume segment walk at j
    return None


def _gzip_payload(data: bytes, start: int) -> tuple[bytes, int] | None:
    """Stream-decode a gzip member at ``start``. Returns (decompressed, end_offset) or None when the stream is
    invalid, truncated, or would exceed MAX_FILE_BYTES."""
    d = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        out = d.decompress(memoryview(data)[start:], MAX_FILE_BYTES)
    except zlib.error:
        return None
    if not d.eof:
        return None
    return out, len(data) - len(d.unused_data)


def find_archives(data: bytes) -> list[dict]:
    """Locate embedded archives/images with a verified logical end. Returns [{'kind', 'offset', 'end'[, 'payload']}]
    sorted by offset; ZIP/GZIP at any offset, PNG/JPEG only when embedded (offset > 0). Hits that fall inside an
    earlier hit's span are dropped (their content is reached by recursion)."""
    eocds, i = [], data.find(_EOCD)
    while i != -1:
        eocds.append(i)
        i = data.find(_EOCD, i + 1)
    cands: list[tuple[int, str]] = []
    for kind, magic in (("zip", b"PK\x03\x04"), ("gzip", b"\x1f\x8b\x08"), ("png", b"\x89PNG\r\n\x1a\n"),
                        ("jpg", b"\xff\xd8\xff")):
        j = data.find(magic)
        while j != -1:
            if kind in ("png", "jpg") and j == 0:
                pass
            else:
                cands.append((j, kind))
            j = data.find(magic, j + 1)
    cands.sort()
    out: list[dict] = []
    covered = 0
    for off, kind in cands:
        if off < covered:
            continue
        hit: dict | None = None
        if kind == "zip":
            end = _zip_end(data, off, eocds)
            hit = {"kind": kind, "offset": off, "end": end} if end else None
        elif kind == "gzip":
            g = _gzip_payload(data, off)
            hit = {"kind": kind, "offset": off, "end": g[1], "payload": g[0]} if g else None
        elif kind == "png":
            end = _png_end(data, off)
            hit = {"kind": kind, "offset": off, "end": end} if end else None
        else:
            end = _jpeg_end(data, off)
            hit = {"kind": kind, "offset": off, "end": end} if end else None
        if hit:
            out.append(hit)
            covered = hit["end"]
    return out


def _safe_name(name: str) -> str:
    """Reduce an archive-member name to a harmless basename (no directories, no traversal, no odd chars)."""
    base = posixpath.basename(name.replace("\\", "/")) or "member"
    base = re.sub(r"[^A-Za-z0-9._\-+@]", "_", base).lstrip(".") or "member"
    return base[:100]


def _write_new(outdir: str, name: str, blob: bytes) -> str:
    """Write ``blob`` to a brand-new file in ``outdir`` (O_EXCL: never overwrites, never follows planted symlinks);
    on a name clash a numeric suffix is added before the extension. Returns the path written."""
    stem, dot, ext_ = name.rpartition(".")
    stem, ext_ = (stem, "." + ext_) if dot else (name, "")
    for n in range(10000):
        path = os.path.join(outdir, f"{stem}{'' if n == 0 else '.' + str(n)}{ext_}")
        try:
            with open(path, "xb") as fh:
                fh.write(blob)
            return path
        except FileExistsError:
            continue
    raise OSError(f"could not find a free filename for {name!r} in {outdir}")


class _Extractor:
    """State for one recursive extraction run (sha256 loop guard, size/count budgets, flag collection)."""

    def __init__(self, outdir: str, max_depth: int):
        self.outdir, self.max_depth = outdir, max_depth
        self.seen: set[str] = set()
        self.flags: dict[str, str] = {}  # flag -> path of first file containing it
        self.files = 0
        self.total = 0

    def _emit(self, parent: dict, name: str, blob: bytes, label: str, depth: int, hunt_flags: bool = True) -> None:
        """Record one extracted blob as a child node: dedupe by sha256, write it, hunt flags (unless ``hunt_flags`` is
        False), then recurse."""
        sha = hashlib.sha256(blob).hexdigest()
        node = {"name": name, "label": label, "size": len(blob), "sha": sha[:12], "children": [], "note": ""}
        parent["children"].append(node)
        if sha in self.seen:
            node["note"] = "duplicate sha256, skipped (loop guard)"
            return
        if self.files >= MAX_FILES or self.total + len(blob) > MAX_TOTAL_BYTES:
            node["note"] = "extraction budget exhausted, not written"
            return
        self.seen.add(sha)
        path = _write_new(self.outdir, name, blob)
        node["path"] = path
        self.files += 1
        self.total += len(blob)
        for m in (FLAG_RE.finditer(blob) if hunt_flags else ()):  # zip carves: members are checked individually
            f = m.group().decode("latin-1")
            self.flags.setdefault(f, path)
            node["note"] = (node["note"] + " " if node["note"] else "") + f"FLAG {f}"
        if hunt_flags and b"\x00" in blob[:8192]:  # UTF-16 flags: even/odd byte lanes catch ASCII-range text
            for lane in (blob[0::2], blob[1::2]):
                for m in FLAG_RE.finditer(lane):
                    f = m.group().decode("latin-1")
                    self.flags.setdefault(f, path)
                    node["note"] = (node["note"] + " " if node["note"] else "") + f"FLAG {f} (utf16)"
        self.scan(blob, node, depth + 1, os.path.basename(path))

    def scan(self, data: bytes, node: dict, depth: int, stem: str) -> None:
        """Find archives in ``data`` and extract each into ``node['children']``, recursing up to ``max_depth``."""
        hits = find_archives(data)
        if not hits:
            return
        if depth > self.max_depth:
            node["note"] = (node["note"] + " " if node["note"] else "") + f"depth cap {self.max_depth} reached; not descending"
            return
        for h in hits:
            off, end = h["offset"], h["end"]
            tag = f"{stem}@0x{off:x}"
            if h["kind"] == "gzip":
                self._emit(node, _safe_name(tag) + ".gunzip", h["payload"], f"gzip @0x{off:x}-0x{end:x} (decompressed)", depth)
            elif h["kind"] == "zip":
                if off == 0 and end == len(data):  # whole-file zip: no separate carve, just its members
                    self._zip_members(data, node, depth, tag)
                else:  # carve it; recursing into the carved file then extracts its members
                    self._emit(node, _safe_name(tag) + ".zip", data[off:end], f"zip @0x{off:x}-0x{end:x}", depth,
                               hunt_flags=False)
            else:
                self._emit(node, _safe_name(tag) + "." + h["kind"], data[off:end], f"{h['kind']} @0x{off:x}-0x{end:x}", depth)

    def _zip_members(self, blob: bytes, holder: dict, depth: int, tag: str) -> None:
        """Extract members of the zip ``blob`` as children of ``holder`` (encrypted/oversized/odd members noted)."""
        try:
            zf = zipfile.ZipFile(io.BytesIO(blob))
        except zipfile.BadZipFile as exc:
            holder["note"] = (holder["note"] + " " if holder["note"] else "") + f"unreadable zip ({exc})"
            return
        with zf:
            for zi in zf.infolist():
                if zi.is_dir():
                    continue
                label = f"member {zi.filename!r}"
                if zi.flag_bits & 1:
                    holder["children"].append({"name": _safe_name(zi.filename), "label": label, "size": zi.file_size,
                                               "sha": "", "children": [], "note": "encrypted, skipped"})
                    continue
                if zi.file_size > MAX_FILE_BYTES:
                    holder["children"].append({"name": _safe_name(zi.filename), "label": label, "size": zi.file_size,
                                               "sha": "", "children": [], "note": "too large, skipped"})
                    continue
                try:
                    with zf.open(zi) as fh:
                        content = fh.read(MAX_FILE_BYTES + 1)
                except (zipfile.BadZipFile, NotImplementedError, RuntimeError, zlib.error, OSError) as exc:
                    holder["children"].append({"name": _safe_name(zi.filename), "label": label, "size": zi.file_size,
                                               "sha": "", "children": [], "note": f"unreadable: {exc}"})
                    continue
                if len(content) > MAX_FILE_BYTES:
                    continue
                self._emit(holder, _safe_name(zi.filename), content, label, depth)


def extract_recursive(data: bytes, outdir: str, root_name: str = "input", max_depth: int = MAX_DEPTH) -> dict:
    """Carve every embedded zip/gzip (and embedded png/jpg) out of ``data`` into ``outdir`` and recurse into each
    extracted file (depth cap ``max_depth``, sha256 loop guard). ``outdir`` is created if missing and existing
    files are never overwritten. Returns {'tree': node, 'flags': {flag: path}, 'files': int}."""
    if os.path.exists(outdir) and not os.path.isdir(outdir):
        raise ValueError(f"output path {outdir!r} exists and is not a directory")
    os.makedirs(outdir, exist_ok=True)
    ex = _Extractor(outdir, max_depth)
    root = {"name": root_name, "label": "input", "size": len(data), "sha": hashlib.sha256(data).hexdigest()[:12],
            "children": [], "note": ""}
    ex.seen.add(hashlib.sha256(data).hexdigest())
    ex.scan(data, root, 1, _safe_name(root_name))
    return {"tree": root, "flags": ex.flags, "files": ex.files}


def format_tree(node: dict, prefix: str = "", last: bool = True, top: bool = True) -> str:
    """Render the extraction tree with box-drawing branches."""
    desc = f"{node['name']}  [{node['label']}, {node['size']} B" + (f", sha256:{node['sha']}" if node["sha"] else "") + "]"
    if node["note"]:
        desc += f"  <-- {node['note']}"
    lines = [desc if top else f"{prefix}{'└── ' if last else '├── '}{desc}"]
    kids = node["children"]
    for i, ch in enumerate(kids):
        lines.append(format_tree(ch, "" if top else prefix + ("    " if last else "│   "), i == len(kids) - 1, False))
    return "\n".join(lines)


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
    """CLI entry point (registry contract); returns a process exit code."""
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

    ex = sub.add_parser("extract", help="recursively carve embedded zip/gzip (and png/jpg) archives into OUTDIR")
    ex.add_argument("file")
    ex.add_argument("-o", "--out", required=True, metavar="OUTDIR", help="output directory (created if missing; files are never overwritten)")
    ex.add_argument("--depth", type=int, default=MAX_DEPTH, help=f"recursion cap (default {MAX_DEPTH})")

    hd = sub.add_parser("hexdump", help="hexdump a file (or a slice of it)")
    hd.add_argument("file")
    hd.add_argument("-o", "--offset", type=lambda x: int(x, 0), default=0)
    hd.add_argument("-l", "--length", type=lambda x: int(x, 0))

    sub.add_parser("selftest", help="run the module self-test")
    p_.add_argument("--selftest", action="store_true")
    try:
        a = p_.parse_args(args)
    except SystemExit as exc:  # -h -> 0, usage error -> 2; return instead of exiting
        return exc.code if isinstance(exc.code, int) else 2

    if a.selftest or a.cmd == "selftest":
        return 0 if selftest() else 1
    if a.cmd is None:
        p_.print_help()
        return 0
    try:
        return _dispatch(a)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def _dispatch(a: argparse.Namespace) -> int:
    """Execute one parsed binextras subcommand; I/O and parse errors propagate to run()."""
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
    if a.cmd == "extract":
        with open(a.file, "rb") as fh:
            data = fh.read()
        res = extract_recursive(data, a.out, os.path.basename(a.file), max(1, a.depth))
        if not res["tree"]["children"]:
            print("no embedded zip/gzip archives found (try `scan`, then `carve` by offset)")
            return 0
        print(format_tree(res["tree"]))
        print(f"\n{res['files']} file(s) written to {a.out}")
        for flag, path in res["flags"].items():
            print(f"\n>>> FLAG: {flag}   (in {path})")
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
    """Registry contract self-test: cyclic, gadgets, carving, pack/unpack, hexdump (all in memory)."""
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
    try:
        parse_elf_sections(b"\x7fELF\x02\x01")
        truncated_ok = False
    except ValueError:
        truncated_ok = True
    check("elf: truncated header raises ValueError (no struct.error leak)", truncated_ok)
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        cli_codes = (run([]), run(["-h"]), run(["zzbogus"]), run(["scan", "/nonexistent/x"]))
    check("cli: bare/-h -> 0, unknown -> 2, missing file -> 1", cli_codes == (0, 0, 2, 1))
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


    # --- recursive extraction: matryoshka fixtures synthesized in memory, written only into a temp dir
    def mk_png(extra: bytes = b"") -> bytes:
        def chunk(t: bytes, b: bytes) -> bytes:
            return struct.pack(">I", len(b)) + t + b + struct.pack(">I", zlib.crc32(t + b) & 0xFFFFFFFF)
        return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
                + chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00")) + chunk(b"IEND", b"")) + extra

    def mk_zip(members: dict, compress=zipfile.ZIP_DEFLATED) -> bytes:
        bio = io.BytesIO()
        with zipfile.ZipFile(bio, "w", compress) as z:
            for k, v in members.items():
                z.writestr(k, v)
        return bio.getvalue()

    def mk_gz(payload: bytes) -> bytes:
        c = zlib.compressobj(9, zlib.DEFLATED, 16 + zlib.MAX_WBITS)
        return c.compress(payload) + c.flush()

    flag = b"CTF{matryoshka_depth_3}"
    layer3 = mk_zip({"flag.txt": b"you made it: " + flag + b"\n"})
    layer2 = mk_png(layer3)
    layer1 = mk_zip({"inner/../../evil.png": layer2, "readme.txt": b"nothing here"})
    top_file = mk_png(layer1)
    check("extract: archive ends located (zip end exact)", [h["kind"] for h in find_archives(top_file)] == ["zip"]
          and find_archives(top_file)[0]["end"] == len(top_file))
    with tempfile.TemporaryDirectory() as td:
        out = os.path.join(td, "out", "nested")  # does not exist yet -> created
        res = extract_recursive(top_file, out, "pic.png")
        check("extract: OUTDIR created", os.path.isdir(out))
        check("extract: flag found 3 layers deep", flag.decode() in res["flags"])
        txt = format_tree(res["tree"])
        check("extract: tree shows every layer", txt.count("zip @") == 2 and "flag.txt" in txt and "FLAG " + flag.decode() in txt)
        names = sorted(os.listdir(out))
        check("extract: zip-slip member name flattened inside OUTDIR", "evil.png" in names
              and not os.path.exists(os.path.join(td, "evil.png")) and not os.path.exists(os.path.join(td, "out", "evil.png")))
        before = {n: open(os.path.join(out, n), "rb").read() for n in names}
        res2 = extract_recursive(top_file, out, "pic.png")
        after_names = set(os.listdir(out))
        check("extract: rerun never overwrites (originals intact, new files suffixed)",
              all(open(os.path.join(out, n), "rb").read() == v for n, v in before.items())
              and len(after_names) == 2 * len(names) and res2["files"] == res["files"])
        fpath = os.path.join(td, "afile")
        open(fpath, "wb").write(b"x")
        check("extract: OUTDIR that is a regular file refused", _raises(lambda: extract_recursive(top_file, fpath)))

        # gzip: junk + gzip (with trailing junk after it) -> logical end detected, payload decompressed
        gz = mk_gz(b"hello " + flag + b" bye")
        blob = b"JUNK" * 5 + gz + b"TRAILER-NOT-PART-OF-GZIP"
        hits = find_archives(blob)
        check("extract: gzip logical end via stream decode", len(hits) == 1 and hits[0]["kind"] == "gzip"
              and hits[0]["offset"] == 20 and blob[hits[0]["end"]:] == b"TRAILER-NOT-PART-OF-GZIP")
        out2 = os.path.join(td, "gz")
        r3 = extract_recursive(blob, out2, "blob.bin")
        check("extract: gzip payload written + flag surfaced", flag.decode() in r3["flags"] and r3["files"] == 1)

        # gzip nested in zip nested in gzip (mixed kinds) and loop guard on identical siblings
        mixed = mk_gz(mk_zip({"a.gz": mk_gz(b"deep " + flag)}))
        r4 = extract_recursive(b"HDR" + mixed, os.path.join(td, "mixed"), "m.bin")
        check("extract: gzip -> zip -> gzip chain", flag.decode() in r4["flags"])
        twin = mk_gz(b"same payload twice")
        r5 = extract_recursive(twin + b"--" + twin, os.path.join(td, "dup"), "d.bin")
        check("extract: identical sha256 skipped by loop guard", "duplicate" in format_tree(r5["tree"]) and r5["files"] == 1)

        # depth cap: 6 nested gzips with cap 3 stops descending and says so
        nest = b"core " + flag
        for _ in range(6):
            nest = mk_gz(nest + b"")
            nest = b"PAD" + nest
        r6 = extract_recursive(nest, os.path.join(td, "deep"), "n.bin", max_depth=3)
        check("extract: depth cap honoured (flag unreachable, note printed)",
              not r6["flags"] and "depth cap 3" in format_tree(r6["tree"]) and r6["files"] == 3)
        r7 = extract_recursive(nest, os.path.join(td, "deep10"), "n.bin")
        check("extract: default cap 10 reaches the flag through 6 layers", flag.decode() in r7["flags"])

        # corrupt / truncated archives and sig false positives are skipped, not crashed on
        bad = b"PK\x03\x04" + b"\x00" * 30 + b"\x1f\x8b\x08" + b"\xff" * 10
        check("extract: bogus signatures yield no hits", find_archives(bad) == [])
        enc = bytearray(mk_zip({"s.txt": b"secret"}))
        eo = enc.find(b"PK\x03\x04")
        enc[eo + 6] |= 1  # set encrypted flag in local header
        cd = enc.find(b"PK\x01\x02")
        enc[cd + 8] |= 1
        r8 = extract_recursive(bytes(enc), os.path.join(td, "enc"), "e.zip")
        check("extract: encrypted member noted, no crash", "encrypted" in format_tree(r8["tree"]))
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            src = os.path.join(td, "cli_in.bin")
            open(src, "wb").write(top_file)
            rc = run(["extract", src, "-o", os.path.join(td, "cli_out")])
        check("extract: cli prints tree + FLAG banner", rc == 0 and ">>> FLAG: " + flag.decode() in buf.getvalue())
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            codes = (run(["extract", src]), run(["extract", "/nonexistent/x", "-o", os.path.join(td, "z")]))
        check("extract: cli missing -o -> 2, missing file -> 1", codes == (2, 1))

    return all(ok)


def _raises(fn) -> bool:
    try:
        fn()
    except Exception:
        return True
    return False


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
