"""PWNHELP: offline exploitation arithmetic -- the computation side of ``exploitnotes``.

Four jobs, each a CLI subcommand:

* ``pack``/``unpack`` -- stdlib ``struct`` wrappers for 32/64-bit pointers (p64/u64/p32/u32).
* ``fmtoffset`` -- given a leaked ``%p``/``%x`` dump containing a known marker written into
  the buffer, locate the controlled ``%N$p`` position.
* ``symbols``/``libcbase``/``libcaddr``/``binsh`` -- read the symbol table of a *local* libc
  ELF (``.dynsym``/``.symtab``), then derive the runtime libc base from one leaked symbol
  address and compute the runtime address of any other symbol, a raw offset (e.g. a known
  one-gadget offset looked up elsewhere), or the ``"/bin/sh"`` string -- all simple addition,
  never a network lookup.
* ``gotplt`` -- list ``.rela.plt`` relocations (GOT slot address <-> imported symbol name) on
  an ELF, built on top of ``disasm.parse_elf``.

Pure byte math and local-file reads; no network, no process execution. Reuses
``disasm.parse_elf``/``vaddr_to_offset``/``offset_to_vaddr`` for the ELF <-> vaddr mapping
(sh_link/sh_entsize, needed to walk symbol/relocation tables, are read directly here since
``disasm.parse_elf`` does not keep them).

CLI:
    recon.py pwnhelp pack VALUE [--bits 32|64]
    recon.py pwnhelp unpack HEX [--bits 32|64]
    recon.py pwnhelp fmtoffset DUMP --marker TEXT [--bits 32|64]
    recon.py pwnhelp symbols LIBC [--filter SUBSTR]
    recon.py pwnhelp libcbase LIBC SYMBOL LEAKED_ADDR
    recon.py pwnhelp libcaddr LIBC BASE (SYMBOL | --offset HEX)
    recon.py pwnhelp binsh LIBC [--base HEX]
    recon.py pwnhelp gotplt ELF
    recon.py pwnhelp selftest
"""
from __future__ import annotations

import argparse
import re
import struct
import sys
from typing import Optional

try:  # works both as ``modules.pwnhelp`` and when the package dir is on sys.path
    from . import disasm
except ImportError:  # pragma: no cover
    import disasm  # type: ignore

NAME = "pwnhelp"
DESCRIPTION = "Exploitation arithmetic: fmt-string offset finder, libc base/symbol/one-gadget calc, GOT/PLT lister, p64/u64"

SHT_SYMTAB, SHT_STRTAB, SHT_RELA, SHT_REL, SHT_DYNSYM = 2, 3, 4, 9, 11


# ---------- packing helpers ----------
def p64(v: int) -> bytes:
    """Pack an unsigned 64-bit little-endian value."""
    return struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF)


def u64(b: bytes) -> int:
    """Unpack a little-endian 64-bit value; short input is zero-padded (truncated leak)."""
    return struct.unpack("<Q", bytes(b).ljust(8, b"\0")[:8])[0]


def p32(v: int) -> bytes:
    """Pack an unsigned 32-bit little-endian value."""
    return struct.pack("<I", v & 0xFFFFFFFF)


def u32(b: bytes) -> int:
    """Unpack a little-endian 32-bit value; short input is zero-padded."""
    return struct.unpack("<I", bytes(b).ljust(4, b"\0")[:4])[0]


def pack(v: int, bits: int = 64) -> bytes:
    return p64(v) if bits == 64 else p32(v)


def unpack(b: bytes, bits: int = 64) -> int:
    return u64(b) if bits == 64 else u32(b)


# ---------- format-string offset finder ----------
_HEX_TOKEN = re.compile(r"0x[0-9a-fA-F]+")


def find_fmt_offset(dump: str, marker: str, bits: int = 64) -> Optional[int]:
    """Return the 1-based ``%N$p`` position in ``dump`` whose leaked pointer value's
    little-endian bytes contain ``marker``, or ``None`` if no leaked value matches.

    ``dump`` is the text printed back by the vulnerable program for a payload such as
    ``"<marker>.%p.%p.%p...."`` -- any ``0x``-prefixed hex tokens in it (``%p`` output) are
    read in order; separators (spaces, dots, anything else) are ignored.
    """
    width = bits // 8
    marker_bytes = marker.encode() if isinstance(marker, str) else bytes(marker)
    if not marker_bytes:
        raise ValueError("empty marker")
    mask = (1 << (width * 8)) - 1
    for idx, tok in enumerate(_HEX_TOKEN.findall(dump), start=1):
        try:
            val = int(tok, 16) & mask
        except ValueError:
            continue
        leaked = val.to_bytes(width, "little")
        if marker_bytes[:width] in leaked or leaked in marker_bytes:
            return idx
    return None


# ---------- full section headers (sh_link / sh_entsize, which disasm.parse_elf omits) ----------
def _read_shdrs(data: bytes) -> tuple[list[dict], int]:
    """Full section header table, ordered by section index, plus the ELF word size (32/64)."""
    if len(data) < 0x34 or data[:4] != b"\x7fELF":
        raise disasm.ElfError("not an ELF file")
    bits = {1: 32, 2: 64}.get(data[4])
    if bits is None:
        raise disasm.ElfError("unsupported ELF class (need 32/64-bit)")
    if bits == 64:
        (_et, _m, _v, _e, _ph, shoff, _fl, _eh, _phes, _phn,
         shentsize, shnum, shstrndx) = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)
        shfmt, shsz = "<IIQQQQIIQQ", 64
    else:
        (_et, _m, _v, _e, _ph, shoff, _fl, _eh, _phes, _phn,
         shentsize, shnum, shstrndx) = struct.unpack_from("<HHIIIIIHHHHHH", data, 16)
        shfmt, shsz = "<IIIIIIIIII", 40
    secs: list[dict] = []
    if shoff and shnum and shoff + shnum * shsz <= len(data):
        for i in range(shnum):
            name_off, type_, flags, addr, offset, size, link, info, align, entsize = \
                struct.unpack_from(shfmt, data, shoff + i * max(shentsize, shsz))
            secs.append({"name_off": name_off, "type": type_, "flags": flags, "addr": addr,
                         "offset": offset, "size": size, "link": link, "info": info,
                         "align": align, "entsize": entsize, "name": ""})
    if secs and shstrndx < len(secs):
        st = secs[shstrndx]
        strtab = data[st["offset"]:st["offset"] + st["size"]]
        for s in secs:
            end = strtab.find(b"\0", s["name_off"])
            s["name"] = strtab[s["name_off"]:end if end >= 0 else None].decode("latin1")
    return secs, bits


def _sym_entry(data: bytes, off: int, bits: int) -> tuple[int, int]:
    """Return (st_name offset-into-strtab, st_value) for one symbol table entry."""
    if bits == 64:
        st_name, _info, _other, _shndx, st_value, _size = struct.unpack_from("<IBBHQQ", data, off)
    else:
        st_name, st_value, _size, _info, _other, _shndx = struct.unpack_from("<IIIBBH", data, off)
    return st_name, st_value


def read_symbols(data: bytes) -> dict[str, int]:
    """Symbol name -> value (``st_value``) from ``.dynsym`` (preferred -- what a shared libc
    carries) or ``.symtab``. Empty dict if neither table has entries."""
    secs, bits = _read_shdrs(data)
    by_name = {s["name"]: i for i, s in enumerate(secs)}
    for symname in (".dynsym", ".symtab"):
        idx = by_name.get(symname)
        if idx is None:
            continue
        sym = secs[idx]
        if not (0 <= sym["link"] < len(secs)):
            continue
        strtab = secs[sym["link"]]
        strdata = data[strtab["offset"]:strtab["offset"] + strtab["size"]]
        entsize = sym["entsize"] or (24 if bits == 64 else 16)
        if entsize <= 0:
            continue
        out: dict[str, int] = {}
        for i in range(sym["size"] // entsize):
            name_off, value = _sym_entry(data, sym["offset"] + i * entsize, bits)
            end = strdata.find(b"\0", name_off)
            nm = strdata[name_off:end if end >= 0 else None].decode("latin1")
            if nm:
                out[nm] = value
        if out:
            return out
    return {}


def find_binsh(data: bytes) -> Optional[int]:
    """File offset of a NUL-terminated ``"/bin/sh"`` string, or ``None``."""
    i = data.find(b"/bin/sh\x00")
    return i if i >= 0 else None


class LibcError(ValueError):
    """Raised for a missing/unreadable libc file or an unknown symbol."""


def load_libc(path: str) -> tuple[bytes, dict, dict[str, int]]:
    """Read a local libc/ELF file and return (raw bytes, disasm elf dict, symbol table)."""
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        raise LibcError(f"cannot read libc file {path!r}: {exc}") from None
    elf = disasm.parse_elf(data)
    syms = read_symbols(data)
    return data, elf, syms


def libc_base_from_leak(symbol_offset: int, leaked_addr: int) -> int:
    """Runtime libc base given one symbol's static offset and its leaked runtime address."""
    return leaked_addr - symbol_offset


def libc_runtime_addr(base: int, offset: int) -> int:
    """Runtime address of anything (symbol or a raw offset, e.g. a one-gadget) given the base."""
    return base + offset


# ---------- GOT/PLT lister ----------
def got_plt(data: bytes) -> list[dict]:
    """List ``.rela.plt``/``.rel.plt`` entries: imported symbol name -> GOT slot vaddr.

    Built on the section headers read here (``disasm.parse_elf`` does not expose
    sh_link/sh_entsize); this is the read side only, nothing is written.
    """
    secs, bits = _read_shdrs(data)
    by_name = {s["name"]: i for i, s in enumerate(secs)}
    out: list[dict] = []
    for relname, has_addend in ((".rela.plt", True), (".rel.plt", False)):
        idx = by_name.get(relname)
        if idx is None:
            continue
        rel = secs[idx]
        if not (0 <= rel["link"] < len(secs)):
            continue
        dynsym = secs[rel["link"]]
        if not (0 <= dynsym["link"] < len(secs)):
            continue
        strtab = secs[dynsym["link"]]
        strdata = data[strtab["offset"]:strtab["offset"] + strtab["size"]]
        sym_entsize = dynsym["entsize"] or (24 if bits == 64 else 16)
        rel_entsize = rel["entsize"] or ((24 if has_addend else 16) if bits == 64 else (12 if has_addend else 8))
        if sym_entsize <= 0 or rel_entsize <= 0:
            continue
        for i in range(rel["size"] // rel_entsize):
            o = rel["offset"] + i * rel_entsize
            if bits == 64:
                r_offset, r_info = struct.unpack_from("<QQ", data, o)
                r_sym = r_info >> 32
            else:
                r_offset, r_info = struct.unpack_from("<II", data, o)
                r_sym = r_info >> 8
            sym_off = dynsym["offset"] + r_sym * sym_entsize
            if sym_off + sym_entsize > len(data):
                continue
            name_off, _value = _sym_entry(data, sym_off, bits)
            end = strdata.find(b"\0", name_off)
            nm = strdata[name_off:end if end >= 0 else None].decode("latin1")
            out.append({"symbol": nm, "got": r_offset})
        break  # .rela.plt and .rel.plt are mutually exclusive per ELF class
    return out


# ---------- CLI ----------
def _parse_int(s: str) -> int:
    return int(s, 0)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="recon.py pwnhelp", description=DESCRIPTION)
    sub = p.add_subparsers(dest="cmd")

    sp = sub.add_parser("pack", help="p64/p32: integer -> little-endian hex bytes")
    sp.add_argument("value")
    sp.add_argument("--bits", type=int, choices=(32, 64), default=64)

    sp = sub.add_parser("unpack", help="u64/u32: little-endian hex bytes -> integer")
    sp.add_argument("hexbytes")
    sp.add_argument("--bits", type=int, choices=(32, 64), default=64)

    sp = sub.add_parser("fmtoffset", help="find the %%N$p offset of a marker in a leak dump")
    sp.add_argument("dump", help="leak dump text, or a path when --file is given")
    sp.add_argument("--file", action="store_true", help="treat DUMP as a file path")
    sp.add_argument("--marker", required=True, help="known text written into the buffer")
    sp.add_argument("--bits", type=int, choices=(32, 64), default=64)

    sp = sub.add_parser("symbols", help="list symbol:offset pairs from a local ELF/libc")
    sp.add_argument("libc")
    sp.add_argument("--filter", default=None, help="only show names containing this substring")

    sp = sub.add_parser("libcbase", help="compute the runtime libc base from one leaked symbol")
    sp.add_argument("libc")
    sp.add_argument("symbol")
    sp.add_argument("leaked_addr")

    sp = sub.add_parser("libcaddr", help="runtime address of a symbol or raw offset, given a base")
    sp.add_argument("libc")
    sp.add_argument("base")
    sp.add_argument("symbol", nargs="?", default=None)
    sp.add_argument("--offset", default=None, help="raw offset (e.g. a known one-gadget offset)")

    sp = sub.add_parser("binsh", help="locate \"/bin/sh\" in a local libc (static offset, or runtime with --base)")
    sp.add_argument("libc")
    sp.add_argument("--base", default=None)

    sp = sub.add_parser("gotplt", help="list .rela.plt GOT slots and their imported symbol names")
    sp.add_argument("elf")

    sub.add_parser("selftest", help="run the module self-test")
    return p


def run(args: list[str]) -> int:
    """CLI entry point (registry contract); returns a process exit code."""
    if args[:1] in (["selftest"], ["--selftest"]):
        return 0 if selftest() else 1
    parser = _build_parser()
    try:
        ns = parser.parse_args(args)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 0
    if not ns.cmd:
        parser.print_help()
        return 2
    if ns.cmd == "selftest":
        return 0 if selftest() else 1
    try:
        if ns.cmd == "pack":
            print(pack(_parse_int(ns.value), ns.bits).hex())
            return 0
        if ns.cmd == "unpack":
            print(hex(unpack(bytes.fromhex(ns.hexbytes.replace("0x", "")), ns.bits)))
            return 0
        if ns.cmd == "fmtoffset":
            dump = open(ns.dump, encoding="utf-8", errors="replace").read() if ns.file else ns.dump
            off = find_fmt_offset(dump, ns.marker, ns.bits)
            if off is None:
                print("marker not found in any leaked value", file=sys.stderr)
                return 1
            print(off)
            return 0
        if ns.cmd == "symbols":
            _data, _elf, syms = load_libc(ns.libc)
            for name, val in sorted(syms.items(), key=lambda kv: kv[1]):
                if ns.filter and ns.filter not in name:
                    continue
                print(f"{val:#018x}  {name}")
            return 0
        if ns.cmd == "libcbase":
            _data, _elf, syms = load_libc(ns.libc)
            if ns.symbol not in syms:
                raise LibcError(f"symbol {ns.symbol!r} not found in {ns.libc}")
            base = libc_base_from_leak(syms[ns.symbol], _parse_int(ns.leaked_addr))
            print(hex(base))
            return 0
        if ns.cmd == "libcaddr":
            _data, _elf, syms = load_libc(ns.libc)
            base = _parse_int(ns.base)
            if (ns.symbol is None) == (ns.offset is None):
                raise LibcError("give exactly one of SYMBOL or --offset")
            if ns.offset is not None:
                off = _parse_int(ns.offset)
            else:
                if ns.symbol not in syms:
                    raise LibcError(f"symbol {ns.symbol!r} not found in {ns.libc}")
                off = syms[ns.symbol]
            print(hex(libc_runtime_addr(base, off)))
            return 0
        if ns.cmd == "binsh":
            data, elf, _syms = load_libc(ns.libc)
            off = find_binsh(data)
            if off is None:
                raise LibcError(f'"/bin/sh" not found in {ns.libc}')
            va = disasm.offset_to_vaddr(elf, off)
            if ns.base is not None:
                print(hex(libc_runtime_addr(_parse_int(ns.base), va)))
            else:
                print(hex(va))
            return 0
        if ns.cmd == "gotplt":
            with open(ns.elf, "rb") as fh:
                data = fh.read()
            entries = got_plt(data)
            if not entries:
                print("no .rela.plt/.rel.plt relocations found")
                return 0
            for e in entries:
                print(f"{e['got']:#018x}  {e['symbol']}")
            return 0
    except (OSError, ValueError, LibcError, disasm.ElfError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    parser.print_help()
    return 2


# ---------- selftest ----------
def build_test_libc() -> bytes:
    """Minimal ELF64 shaped like a tiny libc: one PT_LOAD, ``.text``, ``.rodata`` (holding
    ``"/bin/sh\\0"``), ``.dynsym``/``.dynstr`` (``system``, ``puts``), ``.rela.plt`` (one
    relocation importing ``puts`` into a GOT slot), ``.symtab`` (reuses ``.dynstr``), and
    ``.shstrtab``.
    """
    base = 0x400000
    code = b"\xc3"  # ret
    rodata = b"/bin/sh\x00"
    dynstr = b"\0system\0puts\0"
    sys_name_off, puts_name_off = 1, 8

    def sym64(name_off: int, value: int, shndx: int = 1) -> bytes:
        return struct.pack("<IBBHQQ", name_off, 0x12, 0, shndx, value, 0)

    dynsym = sym64(0, 0, 0) + sym64(sys_name_off, 0x1234) + sym64(puts_name_off, 0x5678)
    puts_sym_idx = 2
    got_slot_va = base + 0x4000
    r_info = (puts_sym_idx << 32) | 7  # r_type is irrelevant to the lister
    rela_plt = struct.pack("<QQq", got_slot_va, r_info, 0)
    shstr = b"\0.text\0.rodata\0.dynsym\0.dynstr\0.rela.plt\0.symtab\0.shstrtab\0"

    def off_of(tag: bytes) -> int:
        return shstr.index(tag)

    layout = [
        ("text", code, 1),
        ("rodata", rodata, 1),
        ("dynsym", dynsym, 8),
        ("dynstr", dynstr, 1),
        ("rela_plt", rela_plt, 8),
    ]
    header_len = 64 + 56  # Ehdr + one Phdr
    pos = header_len
    offsets = {}
    for key, blob, align in layout:
        if align > 1:
            pos = (pos + align - 1) & ~(align - 1)
        offsets[key] = pos
        pos += len(blob)
    shstr_off = pos
    pos += len(shstr)
    sh_off = (pos + 7) & ~7

    body = bytearray(sh_off)
    body[0:4] = b"\x7fELF"
    body[4:8] = bytes([2, 1, 1, 0])
    struct.pack_into("<HHIQQQIHHHHHH", body, 16, 2, 0x3E, 1, base + offsets["text"], 64, sh_off,
                      0, 64, 56, 1, 64, 8, 7)
    struct.pack_into("<IIQQQQQQ", body, 64, 1, 5, 0, base, base, shstr_off, shstr_off, 0x1000)
    for key, blob, _align in layout:
        body[offsets[key]:offsets[key] + len(blob)] = blob
    body[shstr_off:shstr_off + len(shstr)] = shstr

    def sh(name_tag: bytes, type_: int, flags: int, addr: int, offset: int, size: int,
           link: int, info: int, align: int, entsize: int) -> bytes:
        return struct.pack("<IIQQQQIIQQ", off_of(name_tag), type_, flags, addr, offset, size,
                            link, info, align, entsize)

    secs = bytearray()
    secs += sh(b"\0", 0, 0, 0, 0, 0, 0, 0, 0, 0)
    secs += sh(b".text", 1, 0, base + offsets["text"], offsets["text"], len(code), 0, 0, 1, 0)
    secs += sh(b".rodata", 1, 0, base + offsets["rodata"], offsets["rodata"], len(rodata), 0, 0, 1, 0)
    # .dynsym (idx 3) links to .dynstr (idx 4)
    secs += sh(b".dynsym", SHT_DYNSYM, 0, 0, offsets["dynsym"], len(dynsym), 4, 1, 8, 24)
    secs += sh(b".dynstr", SHT_STRTAB, 0, 0, offsets["dynstr"], len(dynstr), 0, 0, 1, 0)
    # .rela.plt (idx 5) links to .dynsym (idx 3)
    secs += sh(b".rela.plt", SHT_RELA, 0, 0, offsets["rela_plt"], len(rela_plt), 3, 0, 8, 24)
    # .symtab (idx 6) reuses .dynstr (idx 4) as its string table
    secs += sh(b".symtab", SHT_SYMTAB, 0, 0, offsets["dynsym"], len(dynsym), 4, 1, 8, 24)
    secs += sh(b".shstrtab", SHT_STRTAB, 0, 0, shstr_off, len(shstr), 0, 0, 1, 0)
    body[sh_off:sh_off + len(secs)] = secs
    return bytes(body)


def selftest() -> bool:
    """Registry contract self-test: p64/u64 round-trip, fmt-string offset, libc symbol/base
    math on a synthetic ELF, GOT/PLT listing, and clean errors for a missing libc file."""
    ok = True

    def check(name: str, cond: bool) -> None:
        nonlocal ok
        if not cond:
            print(f"  FAIL: {name}")
            ok = False

    # packing round-trip
    for v in (0, 1, 0x4141414141414141, 0xFFFFFFFFFFFFFFFF, 0x7FFD12345678):
        check(f"p64/u64 round-trip {v:#x}", u64(p64(v)) == v & 0xFFFFFFFFFFFFFFFF)
    for v in (0, 1, 0x41414141, 0xFFFFFFFF):
        check(f"p32/u32 round-trip {v:#x}", u32(p32(v)) == v & 0xFFFFFFFF)
    check("p64 length", len(p64(1)) == 8)
    check("u64 short-leak pad", u64(b"\x41\x41") == 0x4141)

    # format-string offset finder: marker at a known %N$p position
    marker = "AAAAAAAA"
    marker_val = u64(marker.encode())
    leaks = [0x7ffd00000010, 0x00005500000820, marker_val, 0x7f0000001000, 0x7ffd00000090]
    dump = "." .join(hex(x) for x in leaks)
    check("fmtoffset finds marker", find_fmt_offset(dump, marker) == 3)
    check("fmtoffset no match -> None", find_fmt_offset(dump, "ZZZZZZZZ") is None)
    noisy_dump = "garbage." + ".".join(hex(x) for x in leaks) + ".trailer"
    check("fmtoffset ignores non-hex noise", find_fmt_offset(noisy_dump, marker) == 3)

    # synthetic libc: symbol table + base/offset math
    data = build_test_libc()
    syms = read_symbols(data)
    check("dynsym has system", syms.get("system") == 0x1234)
    check("dynsym has puts", syms.get("puts") == 0x5678)

    leaked_puts = 0x7F1234565678  # pretend runtime address of puts
    base = libc_base_from_leak(syms["puts"], leaked_puts)
    check("libc base math", base == leaked_puts - 0x5678)
    check("libc addr math (symbol)", libc_runtime_addr(base, syms["system"]) == base + 0x1234)
    check("libc addr math (raw offset)", libc_runtime_addr(base, 0xE3B01) == base + 0xE3B01)

    elf = disasm.parse_elf(data)
    binsh_off = find_binsh(data)
    check("binsh found", binsh_off is not None)
    if binsh_off is not None:
        binsh_va = disasm.offset_to_vaddr(elf, binsh_off)
        check("binsh static vaddr", binsh_va == 0x400000 + binsh_off)
        check("binsh runtime addr", libc_runtime_addr(base, binsh_va) == base + binsh_va)

    # GOT/PLT lister
    entries = got_plt(data)
    check("gotplt found one entry", len(entries) == 1)
    if entries:
        check("gotplt symbol name", entries[0]["symbol"] == "puts")
        check("gotplt got vaddr", entries[0]["got"] == 0x400000 + 0x4000)

    # CLI round trips
    check("cli pack/unpack", run(["pack", "4660", "--bits", "64"]) == 0)
    check("cli symbols rc", run(["symbols", "-"]) == 1)  # "-" is not a readable file -> clean error

    import os
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        libc_path = os.path.join(d, "libc.so.6")
        with open(libc_path, "wb") as fh:
            fh.write(data)
        check("cli libcbase", run(["libcbase", libc_path, "puts", hex(leaked_puts)]) == 0)
        check("cli libcaddr by symbol", run(["libcaddr", libc_path, hex(base), "system"]) == 0)
        check("cli libcaddr by offset", run(["libcaddr", libc_path, hex(base), "--offset", "0xe3b01"]) == 0)
        check("cli binsh", run(["binsh", libc_path, "--base", hex(base)]) == 0)
        check("cli unknown symbol errors cleanly", run(["libcbase", libc_path, "nope", "0x1000"]) == 1)

    # missing-libc path errors cleanly (no traceback -- a plain rc=1)
    check("missing libc errors cleanly", run(["libcbase", "/nonexistent/path/libc.so.6", "system", "0x1000"]) == 1)
    try:
        load_libc("/nonexistent/path/libc.so.6")
        check("load_libc raises on missing file", False)
    except LibcError:
        pass

    return ok


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
