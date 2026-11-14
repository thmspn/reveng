"""disasm: x86/x64 ELF disassembly helpers (offline; capstone optional)."""
from __future__ import annotations

import contextlib
import io
import shutil
import struct
import subprocess
import sys

try:  # optional
    import capstone  # type: ignore
except Exception:  # noqa: BLE001
    capstone = None

NAME = "disasm"
DESCRIPTION = "x86/x64 ELF disassembly, entry look, call/string xrefs, syscall & opcode tables"

NO_CAPSTONE_MSG = "capstone not installed - hex view only"

SYSCALLS = {
    0: "read", 1: "write", 2: "open", 3: "close", 4: "stat", 5: "fstat", 6: "lstat", 7: "poll",
    8: "lseek", 9: "mmap", 10: "mprotect", 11: "munmap", 12: "brk", 13: "rt_sigaction",
    14: "rt_sigprocmask", 15: "rt_sigreturn", 16: "ioctl", 17: "pread64", 18: "pwrite64",
    19: "readv", 20: "writev", 21: "access", 22: "pipe", 23: "select", 24: "sched_yield",
    25: "mremap", 28: "madvise", 32: "dup", 33: "dup2", 34: "pause", 35: "nanosleep",
    39: "getpid", 41: "socket", 42: "connect", 43: "accept", 44: "sendto", 45: "recvfrom",
    49: "bind", 50: "listen", 56: "clone", 57: "fork", 58: "vfork", 59: "execve", 60: "exit",
    61: "wait4", 62: "kill", 63: "uname", 72: "fcntl", 79: "getcwd", 80: "chdir",
    82: "rename", 83: "mkdir", 87: "unlink", 89: "readlink", 90: "chmod", 101: "ptrace",
    102: "getuid", 105: "setuid", 158: "arch_prctl", 217: "getdents64", 231: "exit_group",
    257: "openat", 262: "newfstatat", 267: "readlinkat", 318: "getrandom", 322: "execveat",
}
SYSCALL_BY_NAME = {v: k for k, v in SYSCALLS.items()}

OPCODES = [
    ("55", "push rbp"), ("5d", "pop rbp"), ("c3", "ret"), ("c9", "leave"), ("90", "nop"),
    ("cc", "int3 (breakpoint)"), ("cd 80", "int 0x80 (32-bit syscall)"), ("0f 05", "syscall"),
    ("e8 rel32", "call rel32"), ("e9 rel32", "jmp rel32"), ("eb rel8", "jmp rel8"),
    ("74 rel8", "je/jz"), ("75 rel8", "jne/jnz"), ("7c/7f rel8", "jl / jg"),
    ("48 89 e5", "mov rbp, rsp"), ("48 8d .. disp32", "lea r64,[rip+disp32] (string refs)"),
    ("31 c0", "xor eax, eax"), ("f3 0f 1e fa", "endbr64"), ("ff d0", "call rax"),
    ("ff 25 disp32", "jmp [rip+disp32] (PLT stub)"), ("50-57 / 58-5f", "push / pop r64"),
]


# ---------- reference tables ----------
def syscall_lookup(q) -> str | int | None:
    """number -> name, or name -> number."""
    if isinstance(q, int) or (isinstance(q, str) and q.strip().lstrip("-").isdigit()):
        return SYSCALLS.get(int(q))
    return SYSCALL_BY_NAME.get(str(q).strip())


# ---------- ELF parsing ----------
class ElfError(ValueError):
    pass


def parse_elf(data: bytes) -> dict:
    if len(data) < 0x34 or data[:4] != b"\x7fELF":
        raise ElfError("not an ELF file")
    bits = {1: 32, 2: 64}.get(data[4])
    if bits is None or data[5] != 1:
        raise ElfError("unsupported ELF class/endianness (need little-endian 32/64)")
    if bits == 64:
        if len(data) < 0x40:
            raise ElfError("truncated ELF64 header")
        (etype, machine, _v, entry, phoff, shoff, _fl, _eh, phentsize, phnum,
         shentsize, shnum, shstrndx) = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)
        shfmt, shsz = "<IIQQQQIIQQ", 64
    else:
        (etype, machine, _v, entry, phoff, shoff, _fl, _eh, phentsize, phnum,
         shentsize, shnum, shstrndx) = struct.unpack_from("<HHIIIIIHHHHHH", data, 16)
        shfmt, shsz = "<IIIIIIIIII", 40
    sections = []
    if shoff and shnum and shoff + shnum * shsz <= len(data):
        for i in range(shnum):
            f = struct.unpack_from(shfmt, data, shoff + i * max(shentsize, shsz))
            sections.append({"name_off": f[0], "type": f[1], "addr": f[3], "offset": f[4], "size": f[5]})
        if shstrndx < len(sections):
            st = sections[shstrndx]
            strtab = data[st["offset"]:st["offset"] + st["size"]]
            for s in sections:
                end = strtab.find(b"\0", s["name_off"])
                s["name"] = strtab[s["name_off"]:end if end >= 0 else None].decode("latin1")
    for s in sections:
        s.setdefault("name", "")
    segments = []
    if phoff and phnum:
        for i in range(phnum):
            o = phoff + i * phentsize
            if bits == 64 and o + 56 <= len(data):
                t, _fl2, off, va, _pa, fsz, msz, _al = struct.unpack_from("<IIQQQQQQ", data, o)
            elif bits == 32 and o + 32 <= len(data):
                t, off, va, _pa, fsz, msz, _fl2, _al = struct.unpack_from("<IIIIIIII", data, o)
            else:
                continue
            segments.append({"type": t, "offset": off, "vaddr": va, "filesz": fsz})
    arch = {0x3E: "x86_64", 0x03: "x86"}.get(machine, f"machine_{machine:#x}")
    return {"bits": bits, "type": etype, "machine": machine, "arch": arch, "entry": entry,
            "sections": sections, "segments": segments}


def vaddr_to_offset(elf: dict, va: int) -> int | None:
    for sg in elf["segments"]:
        if sg["type"] == 1 and sg["vaddr"] <= va < sg["vaddr"] + sg["filesz"]:
            return va - sg["vaddr"] + sg["offset"]
    for s in elf["sections"]:
        if s["addr"] and s["addr"] <= va < s["addr"] + s["size"] and s["type"] != 8:
            return va - s["addr"] + s["offset"]
    return None


def offset_to_vaddr(elf: dict, off: int) -> int:
    for sg in elf["segments"]:
        if sg["type"] == 1 and sg["offset"] <= off < sg["offset"] + sg["filesz"]:
            return off - sg["offset"] + sg["vaddr"]
    for s in elf["sections"]:
        if s["addr"] and s["offset"] <= off < s["offset"] + s["size"]:
            return off - s["offset"] + s["addr"]
    return off


def get_section(elf: dict, name: str) -> dict | None:
    return next((s for s in elf["sections"] if s["name"] == name), None)


# ---------- disassembly ----------
def hexdump(data: bytes, base: int = 0, width: int = 16) -> str:
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{base + i:08x}  {chunk.hex(' '):<{width * 3 - 1}}  |{asc}|")
    return "\n".join(lines)


def disassemble(code: bytes, vaddr: int, elf: dict, max_insn: int = 0) -> str:
    """Capstone disassembly if available, else hex view with a clear notice."""
    if capstone is None:
        return NO_CAPSTONE_MSG + "\n" + hexdump(code, vaddr)
    mode = capstone.CS_MODE_64 if elf["bits"] == 64 else capstone.CS_MODE_32
    md = capstone.Cs(capstone.CS_ARCH_X86, mode)
    out = []
    for n, i in enumerate(md.disasm(code, vaddr)):
        if max_insn and n >= max_insn:
            break
        out.append(f"{i.address:08x}  {i.bytes.hex():<20} {i.mnemonic} {i.op_str}".rstrip())
    return "\n".join(out) or "(no instructions decoded)"


def disasm_range(data: bytes, elf: dict, start: int | None = None, length: int = 256,
                 is_vaddr: bool = True) -> str:
    """Disassemble .text (start=None) or a vaddr/file-offset range."""
    if start is None:
        t = get_section(elf, ".text")
        if not t:
            return "no .text section found; give an explicit range"
        off, va, ln = t["offset"], t["addr"], t["size"] if length <= 0 else min(length, t["size"])
    else:
        off = vaddr_to_offset(elf, start) if is_vaddr else start
        if off is None or off >= len(data):
            return f"address {start:#x} not mapped in file"
        va, ln = (start if is_vaddr else offset_to_vaddr(elf, start)), length
    return disassemble(data[off:off + ln], va, elf)


def entry_disasm(data: bytes, elf: dict, n: int = 10) -> str:
    off = vaddr_to_offset(elf, elf["entry"])
    if off is None:
        return f"entry {elf['entry']:#x} not mapped"
    code = data[off:off + n * 15]
    if capstone is None:
        return f"entry {elf['entry']:#x}\n" + NO_CAPSTONE_MSG + "\n" + hexdump(code[:64], elf["entry"])
    return f"entry {elf['entry']:#x}\n" + disassemble(code, elf["entry"], elf, max_insn=n)


# ---------- xrefs (heuristic byte scan; no capstone required) ----------
def find_xrefs(data: bytes, elf: dict) -> dict:
    """Heuristics: E8 rel32 call targets, and RIP-relative LEA (x64) pointing at printable strings."""
    t = get_section(elf, ".text")
    if not t:
        return {"calls": {}, "strings": []}
    code = data[t["offset"]:t["offset"] + t["size"]]
    base = t["addr"]
    calls: dict[int, int] = {}
    strs = []
    for i in range(len(code) - 4):
        if code[i] == 0xE8 and i + 5 <= len(code):
            tgt = (base + i + 5 + struct.unpack_from("<i", code, i + 1)[0]) & 0xFFFFFFFFFFFFFFFF
            if t["addr"] <= tgt < t["addr"] + t["size"]:  # in-.text only, cuts false positives
                calls[tgt] = calls.get(tgt, 0) + 1
        if elf["bits"] == 64 and code[i] in (0x48, 0x4C) and i + 7 <= len(code) \
                and code[i + 1] == 0x8D and (code[i + 2] & 0xC7) == 0x05:
            tgt = base + i + 7 + struct.unpack_from("<i", code, i + 3)[0]
            o = vaddr_to_offset(elf, tgt)
            if o is not None:
                raw = data[o:o + 80].split(b"\0", 1)[0]
                if len(raw) >= 3 and all(32 <= b < 127 or b in (9, 10) for b in raw):
                    strs.append((base + i, tgt, raw.decode("ascii")))
    return {"calls": calls, "strings": strs}


def format_xrefs(x: dict) -> str:
    out = [f"call targets ({len(x['calls'])}, heuristic E8 scan; may include false positives):"]
    for tgt, c in sorted(x["calls"].items(), key=lambda kv: -kv[1])[:30]:
        out.append(f"  {tgt:#010x}  x{c}")
    out.append(f"string refs ({len(x['strings'])}, rip-relative lea):")
    for at, tgt, s in x["strings"][:30]:
        out.append(f"  {at:#010x} -> {tgt:#010x}  {s!r}")
    return "\n".join(out)


# ---------- external tool shortcuts ----------
def external_shortcuts(path: str) -> list[str]:
    cmds = []
    if shutil.which("objdump"):
        cmds.append(f"objdump -d -M intel {path}")
    if shutil.which("r2"):
        cmds.append(f"r2 -q -c 'aaa; pdf @ entry0' {path}")
    return cmds


def run_external(tool: str, path: str) -> int:
    """EXTERNAL-TOOL MODE: shells out to objdump/r2 if present. Never required."""
    cmds = {"objdump": ["objdump", "-d", "-M", "intel", path],
            "r2": ["r2", "-q", "-c", "aaa; pdf @ entry0", path]}
    if tool not in cmds or not shutil.which(tool):
        print(f"[external-tool mode] {tool} not available")
        return 1
    print(f"[external-tool mode] running: {' '.join(cmds[tool])}")
    return subprocess.run(cmds[tool], check=False).returncode


# ---------- CLI ----------
USAGE = """disasm usage:
  text <elf> [len]          disassemble .text
  range <elf> <addr|0xaddr> <len> [--offset]   disassemble vaddr (or file offset) range
  entry <elf> [n]           first n instructions at entry (default 10)
  xrefs <elf>               call targets + string refs
  syscall <num|name>        syscall lookup
  opcodes                   opcode quick reference
  ext <objdump|r2> <elf>    external-tool mode
  selftest"""


def _load(path: str):
    with open(path, "rb") as f:
        d = f.read()
    return d, parse_elf(d)


def run(args: list[str]) -> int:
    """CLI entry point (registry contract); returns a process exit code."""
    if not args or args[0] in ("-h", "--help"):
        print(USAGE)
        return 0
    cmd, rest = args[0], args[1:]
    try:
        if cmd == "selftest":
            return 0 if selftest() else 1
        if cmd == "opcodes":
            for b, d in OPCODES:
                print(f"  {b:<18} {d}")
            return 0
        if cmd == "syscall" and rest:
            r = syscall_lookup(rest[0])
            print(r if r is not None else "unknown")
            return 0 if r is not None else 1
        if cmd == "ext" and len(rest) == 2:
            return run_external(rest[0], rest[1])
        if cmd in ("text", "range", "entry", "xrefs") and rest:
            data, elf = _load(rest[0])
            if capstone is None:
                print(f"[{NO_CAPSTONE_MSG}]")
            if cmd == "text":
                print(disasm_range(data, elf, None, int(rest[1], 0) if len(rest) > 1 else 256))
            elif cmd == "range" and len(rest) >= 3:
                print(disasm_range(data, elf, int(rest[1], 0), int(rest[2], 0), "--offset" not in rest))
            elif cmd == "entry":
                print(entry_disasm(data, elf, int(rest[1], 0) if len(rest) > 1 else 10))
            elif cmd == "xrefs":
                print(format_xrefs(find_xrefs(data, elf)))
                for c in external_shortcuts(rest[0]):
                    print(f"[external-tool mode] try: {c}")
            else:
                print(USAGE)
                return 2
            return 0
    except (OSError, ElfError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(USAGE)
    return 2


# ---------- selftest ----------
def build_test_elf() -> bytes:
    """Minimal ELF64: one PT_LOAD, .text/.rodata/.shstrtab; code = lea rdi,[str]; call f; mov eax,60; syscall; f: ret."""
    base = 0x400000
    shstr = b"\0.text\0.rodata\0.shstrtab\0"
    rodata = b"hello ctf\0"
    code_off = 0x78
    # code layout
    lea_at = 0
    call_at = 7
    f_at = 7 + 5 + 5 + 2  # after call, mov eax, syscall
    code_len = f_at + 1
    ro_off = code_off + code_len
    ro_va = base + ro_off
    lea = b"\x48\x8d\x3d" + struct.pack("<i", ro_va - (base + code_off + lea_at + 7))
    call = b"\xe8" + struct.pack("<i", f_at - (call_at + 5))
    code = lea + call + b"\xb8\x3c\x00\x00\x00" + b"\x0f\x05" + b"\xc3"
    assert len(code) == code_len
    shstr_off = ro_off + len(rodata)
    sh_off = (shstr_off + len(shstr) + 7) & ~7
    total_load = shstr_off - 0
    hdr = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\0" * 8
    hdr += struct.pack("<HHIQQQIHHHHHH", 2, 0x3E, 1, base + code_off, 64, sh_off, 0, 64, 56, 1, 64, 4, 3)
    ph = struct.pack("<IIQQQQQQ", 1, 5, 0, base, base, total_load, total_load, 0x1000)
    body = hdr + ph
    body += b"\0" * (code_off - len(body)) + code + rodata + shstr
    body += b"\0" * (sh_off - len(body))

    def sh(n, t, a, o, s):
        return struct.pack("<IIQQQQIIQQ", n, t, 6, a, o, s, 0, 0, 1, 0)
    body += sh(0, 0, 0, 0, 0)
    body += sh(1, 1, base + code_off, code_off, code_len)
    body += sh(7, 1, ro_va, ro_off, len(rodata))
    body += sh(15, 3, 0, shstr_off, len(shstr))
    return body


def selftest() -> bool:
    """Registry contract self-test: syscall table, ELF parse, disasm/entry/xref paths on an in-memory ELF."""
    ok = True

    def check(name, cond):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
        ok &= bool(cond)

    print(f"capstone: {'available' if capstone else NO_CAPSTONE_MSG}")
    check("syscall 59 -> execve", syscall_lookup(59) == "execve")
    check("syscall 'write' -> 1", syscall_lookup("write") == 1)
    check("syscall '231' -> exit_group", syscall_lookup("231") == "exit_group")
    check("unknown syscall -> None", syscall_lookup("nope") is None)
    data = build_test_elf()
    elf = parse_elf(data)
    check("ELF64 x86_64 parsed", elf["bits"] == 64 and elf["arch"] == "x86_64")
    check("entry == 0x400078", elf["entry"] == 0x400078)
    check("sections named", get_section(elf, ".text") is not None and get_section(elf, ".rodata") is not None)
    check("vaddr->offset", vaddr_to_offset(elf, elf["entry"]) == 0x78)
    out = disasm_range(data, elf)
    check("disasm .text path", ("syscall" in out) if capstone else (NO_CAPSTONE_MSG in out and "48 8d 3d" in out))
    e = entry_disasm(data, elf, 3)
    check("entry path", ("lea" in e) if capstone else NO_CAPSTONE_MSG in e)
    x = find_xrefs(data, elf)
    check("call target found (0x40008b)", 0x40008b in x["calls"])
    check("string xref 'hello ctf'", any(s == "hello ctf" for _, _, s in x["strings"]))
    try:
        parse_elf(b"MZ" + b"\0" * 100)
        check("reject non-ELF", False)
    except ElfError:
        check("reject non-ELF", True)
    check("external shortcuts returns list", isinstance(external_shortcuts("x"), list))
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        codes = (run([]), run(["-h"]), run(["zzbogus"]), run(["text", "/nonexistent/x"]))
    check("cli: bare/-h -> 0, unknown -> 2, missing file -> 1", codes == (0, 0, 2, 1))
    print("selftest:", "OK" if ok else "FAILED")
    return ok


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
