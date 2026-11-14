"""ELFPATCH: write-side ELF patching (bytes, NOPs, jcc flip, entry redirect, section dump/replace).

Read-write counterpart to the read-only ``disasm``/``triage``. Parsing and the
vaddr<->offset mapping are reused from ``disasm`` (no re-parsing here). Output always
goes to a NEW file (``-o``); overwriting the input requires an explicit ``--force``.
A patch outside any known section only produces a warning. Fully offline, pure byte math.
"""
from __future__ import annotations

import argparse
import os
import struct
import sys
import tempfile
from typing import Optional

try:  # works both as ``modules.elfpatch`` and when the package dir is on sys.path
    from . import disasm
except ImportError:  # pragma: no cover
    import disasm  # type: ignore

NAME = "elfpatch"
DESCRIPTION = "ELF patching: bytes/NOP/jcc flip/entry redirect/section dump+replace (new output file)"

NOP = 0x90


class PatchError(ValueError):
    """Raised for any refused or malformed patch request."""


def parse_int(s: str) -> int:
    """Parse a decimal or 0x-prefixed integer."""
    try:
        return int(s, 0)
    except ValueError:
        raise PatchError(f"bad integer: {s!r}") from None


def parse_hex_bytes(s: str) -> bytes:
    """Parse '90 90', '9090', or '\\x90\\x90' into bytes."""
    t = s.replace("\\x", "").replace("0x", "").replace(" ", "").replace(",", "")
    try:
        return bytes.fromhex(t)
    except ValueError:
        raise PatchError(f"bad hex bytes: {s!r}") from None


def resolve_offset(elf: dict, data: bytes, at: Optional[int], offset: Optional[int]) -> int:
    """Return a file offset from a vaddr (``at``) or a raw file offset."""
    if (at is None) == (offset is None):
        raise PatchError("give exactly one of --at (vaddr) or --offset (file offset)")
    if offset is not None:
        off = offset
    else:
        off = disasm.vaddr_to_offset(elf, at)
        if off is None:
            raise PatchError(f"vaddr {at:#x} is not mapped by any segment/section")
    if off < 0 or off > len(data):
        raise PatchError(f"offset {off:#x} outside file (size {len(data):#x})")
    return off


def warnings_for(elf: dict, off: int, n: int) -> list[str]:
    """Warn (never block) when [off, off+n) is not fully inside one file-backed section."""
    for s in elf["sections"]:
        if s["name"] and s["type"] != 8 and s["offset"] <= off and off + n <= s["offset"] + s["size"]:
            return []
    return [f"warning: patch at file offset {off:#x} (+{n}) is outside any known section"]


def patch_bytes(data: bytes, off: int, new: bytes) -> bytes:
    """Return ``data`` with ``new`` written at ``off`` (length preserved)."""
    if off + len(new) > len(data):
        raise PatchError("patch extends past end of file")
    return data[:off] + new + data[off + len(new):]


def flip_jcc(data: bytes, off: int) -> tuple[bytes, str]:
    """Invert the conditional jump at ``off`` (je<->jne, jl<->jge ...). Returns (data, description)."""
    if off >= len(data):
        raise PatchError("offset past end of file")
    b = data[off]
    if 0x70 <= b <= 0x7F:
        return patch_bytes(data, off, bytes([b ^ 1])), f"short jcc {b:#04x} -> {b ^ 1:#04x}"
    if b == 0x0F and off + 1 < len(data) and 0x80 <= data[off + 1] <= 0x8F:
        c = data[off + 1]
        return patch_bytes(data, off + 1, bytes([c ^ 1])), f"near jcc 0f {c:02x} -> 0f {c ^ 1:02x}"
    raise PatchError(f"no conditional jump opcode at offset {off:#x} (found {b:#04x})")


def set_entry(data: bytes, elf: dict, va: int) -> bytes:
    """Rewrite e_entry (offset 0x18; 8 bytes on ELF64, 4 on ELF32)."""
    if elf["bits"] == 64:
        return patch_bytes(data, 0x18, struct.pack("<Q", va))
    if va > 0xFFFFFFFF:
        raise PatchError("entry does not fit ELF32")
    return patch_bytes(data, 0x18, struct.pack("<I", va))


def section_slice(elf: dict, data: bytes, name: str) -> tuple[dict, int, int]:
    """Return (section, offset, size) for a named file-backed section."""
    s = disasm.get_section(elf, name)
    if s is None:
        raise PatchError(f"no section named {name!r}")
    if s["type"] == 8:
        raise PatchError(f"section {name!r} is NOBITS (no file content)")
    if s["offset"] + s["size"] > len(data):
        raise PatchError(f"section {name!r} extends past end of file")
    return s, s["offset"], s["size"]


def replace_section(data: bytes, elf: dict, name: str, new: bytes) -> bytes:
    """Replace a section's contents in place; shorter content is zero-padded, longer is refused."""
    _, off, size = section_slice(elf, data, name)
    if len(new) > size:
        raise PatchError(f"replacement ({len(new)} B) larger than section {name!r} ({size} B)")
    return patch_bytes(data, off, new + b"\0" * (size - len(new)))


def write_output(src: str, out: Optional[str], data: bytes, force: bool) -> str:
    """Write ``data`` to ``out``; refuse overwriting ``src`` (or no -o) unless ``force``."""
    dest = out if out else src
    if os.path.exists(dest) and os.path.exists(src) and os.path.samefile(src, dest) and not force:
        raise PatchError("refusing in-place patch (output is the input); use a new -o file or --force")
    if not out and not force:
        raise PatchError("no -o given; refusing in-place patch without --force")
    with open(dest, "wb") as fh:
        fh.write(data)
    try:
        if os.path.exists(src):
            os.chmod(dest, os.stat(src).st_mode)
    except OSError:
        pass
    return dest


def _load(path: str) -> tuple[bytes, dict]:
    with open(path, "rb") as fh:
        data = fh.read()
    return data, disasm.parse_elf(data)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="recon.py elfpatch", description=DESCRIPTION)
    sub = p.add_subparsers(dest="cmd")

    def common(sp, loc=True):
        sp.add_argument("elf")
        if loc:
            sp.add_argument("--at", help="virtual address")
            sp.add_argument("--offset", help="file offset")
        sp.add_argument("-o", "--output", help="new output file")
        sp.add_argument("--force", action="store_true", help="allow overwriting the input in place")

    sp = sub.add_parser("patch", help="write bytes at vaddr/offset")
    common(sp)
    sp.add_argument("--bytes", required=True, help="hex bytes, e.g. 90909090")
    sp = sub.add_parser("nop", help="NOP out a range")
    common(sp)
    sp.add_argument("--len", type=str, required=True, dest="length")
    sp = sub.add_parser("flip", help="invert a conditional jump (je<->jne ...)")
    common(sp)
    sp = sub.add_parser("entry", help="redirect the entry point")
    common(sp, loc=False)
    sp.add_argument("--to", required=True, help="new entry vaddr")
    sp = sub.add_parser("dump", help="dump a named section to a file")
    sp.add_argument("elf")
    sp.add_argument("--section", required=True)
    sp.add_argument("-o", "--output", required=True)
    sp = sub.add_parser("replace", help="replace a named section from a file")
    common(sp, loc=False)
    sp.add_argument("--section", required=True)
    sp.add_argument("--file", required=True, help="file with the new section content")
    sub.add_parser("selftest", help="run the module self-test")
    return p


def run(args: list[str]) -> int:
    """CLI entry point: ``elfpatch <patch|nop|flip|entry|dump|replace|selftest> ...``."""
    if args[:1] in (["selftest"], ["--selftest"]):
        return 0 if selftest() else 1
    parser = _build_parser()
    try:
        ns = parser.parse_args(args)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 0
    if not ns.cmd:  # bare invocation: usage + 0 (PLAN.md quality bar)
        parser.print_help()
        return 0
    if ns.cmd == "selftest":
        return 0 if selftest() else 1
    try:
        data, elf = _load(ns.elf)
        if ns.cmd == "dump":
            _, off, size = section_slice(elf, data, ns.section)
            with open(ns.output, "wb") as fh:
                fh.write(data[off:off + size])
            print(f"dumped {ns.section} ({size} B @ file {off:#x}) -> {ns.output}")
            return 0
        warns: list[str] = []
        if ns.cmd in ("patch", "nop", "flip"):
            at = parse_int(ns.at) if ns.at else None
            fo = parse_int(ns.offset) if ns.offset else None
            off = resolve_offset(elf, data, at, fo)
            if ns.cmd == "patch":
                new = parse_hex_bytes(ns.bytes)
                if not new:
                    raise PatchError("empty --bytes")
                warns = warnings_for(elf, off, len(new))
                data = patch_bytes(data, off, new)
                msg = f"patched {len(new)} B at file {off:#x}"
            elif ns.cmd == "nop":
                n = parse_int(ns.length)
                if n <= 0:
                    raise PatchError("--len must be positive")
                warns = warnings_for(elf, off, n)
                data = patch_bytes(data, off, bytes([NOP]) * n)
                msg = f"NOPed {n} B at file {off:#x}"
            else:
                warns = warnings_for(elf, off, 1)
                data, desc = flip_jcc(data, off)
                msg = f"flipped {desc} at file {off:#x}"
        elif ns.cmd == "entry":
            va = parse_int(ns.to)
            if disasm.vaddr_to_offset(elf, va) is None:
                warns = [f"warning: new entry {va:#x} is not mapped by any segment"]
            old = elf["entry"]
            data = set_entry(data, elf, va)
            msg = f"entry {old:#x} -> {va:#x}"
        else:  # replace
            with open(ns.file, "rb") as fh:
                new = fh.read()
            data = replace_section(data, elf, ns.section, new)
            msg = f"replaced {ns.section} with {len(new)} B from {ns.file}"
        for w in warns:
            print(w, file=sys.stderr)
        dest = write_output(ns.elf, ns.output, data, ns.force)
        print(f"{msg} -> {dest}")
        return 0
    except (PatchError, disasm.ElfError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def selftest() -> bool:
    """Patch/NOP/flip/entry/section checks on disasm.build_test_elf(); in-place refusal."""
    ok = True

    def check(name: str, cond: bool) -> None:
        nonlocal ok
        if not cond:
            print(f"  FAIL: {name}")
            ok = False

    base = disasm.build_test_elf()
    elf = disasm.parse_elf(base)
    text = disasm.get_section(elf, ".text")
    check("text section found", text is not None)
    if text is None:
        return False
    va, off = text["addr"], text["offset"]
    check("vaddr<->offset agrees with disasm",
          resolve_offset(elf, base, va, None) == disasm.vaddr_to_offset(elf, va) == off
          and disasm.offset_to_vaddr(elf, off) == va)

    with tempfile.TemporaryDirectory() as d:
        src, out = os.path.join(d, "in.elf"), os.path.join(d, "out.elf")
        with open(src, "wb") as fh:
            fh.write(base)
        rc = run(["patch", src, "--at", hex(va + 12), "--bytes", "90", "-o", out])
        new = open(out, "rb").read()
        check("patch rc", rc == 0)
        check("byte changed", base[off + 12] != NOP and new[off + 12] == NOP)
        check("rest identical", new[:off + 12] == base[:off + 12] and new[off + 13:] == base[off + 13:]
              and len(new) == len(base))
        # nop
        rc = run(["nop", src, "--offset", hex(off), "--len", "3", "-o", out])
        check("nop", rc == 0 and open(out, "rb").read()[off:off + 3] == b"\x90" * 3)
        # jump flip (je 0x74 <-> jne 0x75; near 0f 84 <-> 0f 85)
        j = patch_bytes(base, off, b"\x74\x05\x0f\x84")
        f1, _ = flip_jcc(j, off)
        f2, _ = flip_jcc(f1, off)
        f3, _ = flip_jcc(j, off + 2)
        check("short jcc toggles", f1[off] == 0x75 and f2 == j)
        check("near jcc toggles", f3[off + 3] == 0x85)
        try:
            flip_jcc(base, off + 12)  # ret
            check("non-jcc refused", False)
        except PatchError:
            pass
        # entry
        e = disasm.parse_elf(set_entry(base, elf, va + 7))
        check("entry redirected", e["entry"] == va + 7)
        # section dump/replace
        dump = os.path.join(d, "text.bin")
        check("dump", run(["dump", src, "--section", ".text", "-o", dump]) == 0
              and open(dump, "rb").read() == base[off:off + text["size"]])
        repl = os.path.join(d, "r.bin")
        with open(repl, "wb") as fh:
            fh.write(b"\xcc\xcc")
        rc = run(["replace", src, "--section", ".text", "--file", repl, "-o", out])
        got = open(out, "rb").read()
        check("replace pads", rc == 0 and got[off:off + 2] == b"\xcc\xcc"
              and got[off + 2:off + text["size"]] == b"\0" * (text["size"] - 2)
              and got[off + text["size"]:] == base[off + text["size"]:])
        with open(repl, "wb") as fh:
            fh.write(b"A" * (text["size"] + 1))
        check("oversize replace refused", run(["replace", src, "--section", ".text", "--file", repl, "-o", out]) == 1)
        # outside-section warning (ELF header byte), not blocked
        check("warns outside section", bool(warnings_for(elf, 1, 1)) and not warnings_for(elf, off, 1))
        check("outside patch still allowed", run(["patch", src, "--offset", "0x8", "--bytes", "00", "-o", out]) == 0)
        # in-place refusal
        check("in-place refused (same -o)", run(["nop", src, "--offset", hex(off), "--len", "1", "-o", src]) == 1
              and open(src, "rb").read() == base)
        check("in-place refused (no -o)", run(["nop", src, "--offset", hex(off), "--len", "1"]) == 1
              and open(src, "rb").read() == base)
        check("--force allows in-place", run(["nop", src, "--offset", hex(off), "--len", "1", "--force"]) == 0
              and open(src, "rb").read()[off] == NOP)
    # CLI exit-code contract: bare/-h -> 0, unknown subcommand -> 2 (help text silenced)
    import contextlib
    import io as _io
    with contextlib.redirect_stdout(_io.StringIO()), contextlib.redirect_stderr(_io.StringIO()):
        codes = (run([]), run(["-h"]), run(["--bogus-flag"]))
    check("cli: bare/-h -> 0, unknown -> 2", codes == (0, 0, 2))
    return ok


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
