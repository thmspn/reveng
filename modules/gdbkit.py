"""GDBKIT: gdb / gef / pwndbg command recipes plus a ``gdb -x`` batch-script driver.

Two modes:

- **Cheatsheet** (pure text, no gdb needed): copy-paste recipes for common CTF moves,
  with gef and pwndbg variants side by side. ``find <keyword>`` searches them.
- **Driver**: ``script`` renders a ``gdb -x`` batch script from a template (args,
  breakpoints, per-breakpoint commands, ``run``, auto-dump). ``run-gdb`` is the
  **external-tool mode**: only if ``gdb`` is on PATH it executes that script against a
  local target via ``subprocess`` (argument list, no shell, with a timeout). It is
  never required; when gdb is absent it reports so and returns 1.

Offline: this module performs no socket I/O and never downloads anything. The only
external process is a local ``gdb`` binary, opt-in and guarded by ``shutil.which``.
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from typing import NamedTuple, Optional, Sequence

NAME = "gdbkit"
DESCRIPTION = "gdb/gef/pwndbg CTF command recipes (searchable) + gdb -x batch-script generator/driver"

DUMP_TIMEOUT = 60  # seconds; bound for the optional external gdb run
MAX_OUTPUT = 1_000_000  # cap on captured gdb output echoed back


class Recipe(NamedTuple):
    """One cheatsheet entry. ``gef``/``pwndbg`` are empty when no variant-specific form exists."""

    key: str
    title: str
    tags: tuple[str, ...]
    gdb: str
    gef: str
    pwndbg: str
    note: str


RECIPES: tuple[Recipe, ...] = (
    Recipe("break-main", "Break at main and run", ("break", "main", "start", "entry"),
           "break main\nrun", "start            # temp bp on main + run",
           "start            # or: entry (break at entry point, for stripped bins)",
           "Stripped binary? use `info files` for 'Entry point', then `break *0x<entry>`."),
    Recipe("break-entry", "Break at entry point (stripped / no main)", ("break", "entry", "stripped", "starti"),
           "info files\nbreak *0x<entry>\nrun", "entry-break",
           "entry", "`starti` stops at the very first instruction and works everywhere."),
    Recipe("find-win", "Find the win / flag function", ("win", "function", "symbol", "ret2win", "flag"),
           "info functions win\ninfo functions flag\ninfo functions ^[a-z_]*$\np &win\nx/20i win",
           "functions          # list; then: x/20i win", "info functions win\nx/20i win",
           "Also try `info address win`, and `disassemble win`. Stripped: use the disasm module."),
    Recipe("got-plt", "Dump GOT / PLT", ("got", "plt", "relocation", "import"),
           "info functions @plt\nx/20gx 0x<got_addr>\nmaintenance info sections .got .got.plt",
           "got               # GOT entries with resolved targets\nplt  # (gef: `got` + `vmmap`)",
           "gotplt             # or: got / plt", "Partial RELRO => GOT is writable; check `checksec` first."),
    Recipe("pattern-create", "Cyclic pattern: create", ("pattern", "cyclic", "create", "offset", "overflow"),
           "# no builtin; use: python3 recon.py binextras cyclic 200",
           "pattern create 200", "cyclic 200",
           "Feed the output as stdin / argv to crash the program."),
    Recipe("pattern-offset", "Cyclic pattern: find offset after crash", ("pattern", "cyclic", "offset", "overflow", "rip", "eip"),
           "# python3 recon.py binextras cyclic-find 0x6161616c",
           "pattern search $rsp      # or: pattern offset 0x6161616c",
           "cyclic -l 0x6161616c     # 64-bit: cyclic -l $rsp (after crash: x/gx $rsp)",
           "Offset to saved RIP = offset found from the value at the crash/ret site."),
    Recipe("tele", "Telescope the stack / dereference chain", ("tele", "telescope", "stack", "dereference", "rsp"),
           "x/32gx $rsp", "telescope $rsp 32   # alias: dereference $rsp 32", "telescope $rsp 32   # alias: tele, stack 32",
           "Shows each word plus the chain of pointers it references."),
    Recipe("heap", "Heap overview / chunks / bins", ("heap", "bins", "tcache", "chunks", "fastbin"),
           "# no builtin heap view; use gef or pwndbg",
           "heap chunks\nheap bins\nheap arenas", "heap\nbins\ntcache\nvis_heap_chunks",
           "pwndbg: `vis` is a compact heap map; gef: `heap bins tcache`."),
    Recipe("vmmap", "Memory map (find libc/stack/PIE base)", ("vmmap", "memory", "map", "libc", "base", "pie"),
           "info proc mappings", "vmmap\nvmmap libc", "vmmap\nvmmap libc",
           "libc base = lowest mapping of the libc file; subtract from a leak to get offset."),
    Recipe("search-memory", "Search memory for a string / value", ("search", "find", "memory", "string", "bin/sh"),
           "find &$rsp, +0x1000, \"AAAA\"\nfind /b 0x400000, 0x401000, 0x90, 0x90",
           "search-pattern \"/bin/sh\"   # alias: grep", "search \"/bin/sh\"\nsearch -t bytes 4141\nsearch -p 0xdeadbeef",
           "Plain gdb `find` needs explicit start/end; gef/pwndbg scan all mappings."),
    Recipe("deref-args", "Dereference function arguments at a call", ("args", "arguments", "dereference", "rdi", "rsi", "call"),
           "break puts\nrun\nx/s $rdi\nx/gx $rsi\ninfo registers rdi rsi rdx rcx r8 r9",
           "context            # shows resolved args at call sites\nx/s $rdi", "x/s $rdi\ntele $rdi\ncontext   # args shown on call",
           "SysV x86-64 arg order: rdi, rsi, rdx, rcx, r8, r9. x86 (cdecl): on stack at $esp+4...."),
    Recipe("checksec", "Show binary protections", ("checksec", "nx", "pie", "canary", "relro"),
           "# use: python3 recon.py triage <elf>", "checksec", "checksec",
           "Decides the exploit path: canary => leak; PIE => leak base; NX => ROP."),
    Recipe("break-syscall", "Catch syscalls / breakpoints on call sites", ("catch", "syscall", "break", "strcpy", "read"),
           "catch syscall execve\nbreak read\nbreak *0x<addr>\ntbreak *0x<addr>", "", "",
           "`catch syscall write` is great for spotting where output is produced."),
    Recipe("registers", "Registers, flags, stepping", ("registers", "step", "next", "finish", "context"),
           "info registers\nstepi\nnexti\nfinish\ncontinue", "registers\ncontext", "regs\ncontext\nnearpc",
           "`display/i $pc` shows the next instruction after every stop in plain gdb."),
    Recipe("set-args", "Set args, stdin and environment", ("args", "run", "stdin", "input", "env"),
           "set args AAAA BBBB\nrun < payload.bin\nrun $(python3 -c 'print(\"A\"*72)')\nset env FOO=bar",
           "gef config\nrun < payload.bin", "run < payload.bin", "`unset env LINES` / `unset env COLUMNS` keep stack addresses equal to a non-gdb run."),
    Recipe("rop-gadgets", "Find ROP gadgets / jmp rsp", ("rop", "gadget", "ropper", "jmp", "pop"),
           "# python3 recon.py binextras gadgets <elf>", "ropper --search \"pop rdi\"", "rop --grep \"pop rdi\"",
           "gef's `ropper` and pwndbg's `rop` shell out to the respective local tools."),
    Recipe("anti-debug", "Bypass ptrace / anti-debug checks", ("anti-debug", "antidebug", "ptrace", "debugger", "detect", "bypass", "catch"),
           "catch syscall ptrace\nrun\n# when it fires: step over the syscall, then:\nset $rax = 0\ncontinue",
           "catch syscall ptrace\n# after each hit: set $rax = 0",
           "catch syscall ptrace\n# after each hit: set $rax = 0",
           "ptrace(PTRACE_TRACEME) returns nonzero under a debugger; forcing $rax=0 hides gdb. Repeat per check. Static alternative: NOP the call site with `python3 recon.py elfpatch`. Also watch for int3 (0xCC) scans and timing checks (rdtsc)."),
    Recipe("patch-memory", "Write memory / patch registers live", ("write", "patch", "set", "memory", "register"),
           "set {int}0x<addr> = 0x1\nset $rax = 0\nset $eflags |= 0x40", "patch byte 0x<addr> 0x90", "patch 0x<addr> 'nop'  # or: set *(char*)0x<addr> = 0x90",
           "Flip ZF: `set $eflags ^= 0x40` to bypass a single compare."),
)


# --------------------------------------------------------------------------- cheatsheet


def search_recipes(keyword: str, recipes: Sequence[Recipe] = RECIPES) -> list[Recipe]:
    """Return recipes whose key/title/tags/commands/note contain ``keyword`` (case-insensitive)."""
    needle = keyword.strip().lower()
    if not needle:
        return []
    out: list[Recipe] = []
    for r in recipes:
        hay = " ".join((r.key, r.title, " ".join(r.tags), r.gdb, r.gef, r.pwndbg, r.note)).lower()
        if needle in hay:
            out.append(r)
    return out


def _indent(text: str, prefix: str = "    ") -> str:
    return "\n".join(prefix + ln for ln in text.splitlines())


def format_recipe(r: Recipe) -> str:
    """Render a recipe as text with gdb / gef / pwndbg blocks side by side (stacked)."""
    parts = [f"## {r.title}   [{r.key}]  tags: {', '.join(r.tags)}"]
    for label, body in (("gdb", r.gdb), ("gef", r.gef), ("pwndbg", r.pwndbg)):
        if body:
            parts.append(f"  {label}:\n{_indent(body)}")
    if r.note:
        parts.append(f"  note: {r.note}")
    return "\n".join(parts)


# --------------------------------------------------------------------------- batch driver


def _check_line(value: str, what: str) -> str:
    """Reject values that would break out of a single gdb script line."""
    if "\n" in value or "\r" in value or "\0" in value:
        raise ValueError(f"{what} must not contain newlines or NUL")
    return value


def build_script(target: Optional[str] = None, args: Sequence[str] = (),
                 breakpoints: Sequence[str] = (), commands: Sequence[str] = (),
                 bp_commands: Sequence[str] = (), dump: bool = True, run: bool = True,
                 stdin_file: Optional[str] = None) -> str:
    """Render a ``gdb -x`` batch script.

    ``breakpoints`` are location specs (``main``, ``*0x401136``, ``file.c:12``). ``bp_commands``
    are gdb commands attached to *every* breakpoint (e.g. ``x/s $rdi``). ``commands`` run once
    before ``run``. ``dump`` appends registers/stack/backtrace/mappings after the stop.
    """
    lines = ["# generated by recon.py gdbkit -- run with: gdb -q -batch -x <this file>",
             "set pagination off", "set confirm off", "set width 0", "set height 0"]
    if target:
        lines.append(f"file {_check_line(target, 'target')}")
    if args:
        lines.append("set args " + " ".join(_check_line(a, "arg") for a in args))
    for c in commands:
        lines.append(_check_line(c, "command"))
    for bp in breakpoints:
        lines.append(f"break {_check_line(bp, 'breakpoint')}")
        if bp_commands:
            lines.append("commands")
            lines.extend("  " + _check_line(c, "bp command") for c in bp_commands)
            lines.append("end")
    if run:
        suffix = f" < {_check_line(stdin_file, 'stdin file')}" if stdin_file else ""
        lines.append("run" + suffix)
    if dump:
        lines += ["echo \\n=== registers ===\\n", "info registers",
                  "echo \\n=== stack ===\\n", "x/32gx $sp",
                  "echo \\n=== backtrace ===\\n", "bt",
                  "echo \\n=== mappings ===\\n", "info proc mappings"]
    lines.append("kill")
    return "\n".join(lines) + "\n"


def execute_script(script: str, target: Optional[str] = None, timeout: int = DUMP_TIMEOUT,
                   which=shutil.which) -> tuple[int, str]:
    """EXTERNAL-TOOL MODE: run ``script`` with a local ``gdb`` if present.

    Returns ``(rc, output)``. If gdb is not on PATH returns ``(1, message)`` -- never raises
    for that case. ``which`` is injectable for tests.
    """
    exe = which("gdb")
    if not exe:
        return 1, "gdb not found on PATH -- external-tool mode unavailable (cheatsheet/script still work)"
    fd, path = tempfile.mkstemp(prefix="gdbkit_", suffix=".gdb")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(script)
        cmd = [exe, "-q", "-batch", "-x", path]
        if target:
            cmd.append(target)
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                                  stdin=subprocess.DEVNULL, check=False)
        except subprocess.TimeoutExpired:
            return 1, f"gdb timed out after {timeout}s"
        except OSError as exc:
            return 1, f"could not run gdb: {exc}"
        return proc.returncode, ((proc.stdout or "") + (proc.stderr or ""))[:MAX_OUTPUT]
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


# --------------------------------------------------------------------------- CLI


def _list_text() -> str:
    return "\n".join(f"  {r.key:<16} {r.title}" for r in RECIPES)


def _add_script_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("target", nargs="?", help="local target binary")
    p.add_argument("-a", "--arg", action="append", default=[], help="program argument (repeatable)")
    p.add_argument("-b", "--break", dest="breakpoints", action="append", default=[],
                   help="breakpoint location (repeatable), e.g. main or *0x401136")
    p.add_argument("-c", "--cmd", dest="pre_cmds", action="append", default=[], help="gdb command run before `run` (repeatable)")
    p.add_argument("--bp-cmd", action="append", default=[], help="gdb command attached to every breakpoint")
    p.add_argument("--stdin", dest="stdin_file", help="redirect stdin from this file")
    p.add_argument("--no-dump", action="store_true", help="skip the auto-dump section")


def _script_from(ns: argparse.Namespace) -> str:
    return build_script(ns.target, ns.arg, ns.breakpoints, ns.pre_cmds, ns.bp_cmd,
                        dump=not ns.no_dump, stdin_file=ns.stdin_file)


def run(args: list[str]) -> int:
    """CLI entry point: ``list`` / ``show`` / ``find`` / ``script`` / ``run-gdb`` / ``selftest``."""
    p = argparse.ArgumentParser(prog="recon.py gdbkit", description=DESCRIPTION)
    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("list", help="list recipe keys")
    sh = sub.add_parser("show", help="show one recipe (or all with no key)")
    sh.add_argument("key", nargs="?")
    fd = sub.add_parser("find", help="search recipes by keyword")
    fd.add_argument("keyword", nargs="+")
    sc = sub.add_parser("script", help="generate a gdb -x batch script (stdout or -o FILE)")
    _add_script_args(sc)
    sc.add_argument("-o", "--output", help="write script to this file")
    rg = sub.add_parser("run-gdb", help="EXTERNAL-TOOL MODE: generate and execute via local gdb, if installed")
    _add_script_args(rg)
    rg.add_argument("--timeout", type=int, default=DUMP_TIMEOUT)
    sub.add_parser("selftest", help="run the module self-test")
    p.add_argument("--selftest", action="store_true")

    try:
        ns = p.parse_args(args)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2

    if ns.selftest or ns.cmd == "selftest":
        return 0 if selftest() else 1
    if ns.cmd is None:
        p.print_help()
        print("\nrecipes:\n" + _list_text())
        return 0

    try:
        if ns.cmd == "list":
            print(_list_text())
        elif ns.cmd == "show":
            if ns.key:
                hit = [r for r in RECIPES if r.key == ns.key]
                if not hit:
                    print(f"error: no recipe '{ns.key}' (try `list` or `find`)", file=sys.stderr)
                    return 1
                print(format_recipe(hit[0]))
            else:
                print("\n\n".join(format_recipe(r) for r in RECIPES))
        elif ns.cmd == "find":
            kw = " ".join(ns.keyword)
            hits = search_recipes(kw)
            if not hits:
                print(f"no recipes match '{kw}'", file=sys.stderr)
                return 1
            print("\n\n".join(format_recipe(r) for r in hits))
        elif ns.cmd == "script":
            text = _script_from(ns)
            if ns.output:
                with open(ns.output, "w", encoding="utf-8") as fh:
                    fh.write(text)
                print(f"wrote {ns.output}")
            else:
                sys.stdout.write(text)
        elif ns.cmd == "run-gdb":
            print("[external-tool mode: local gdb]", file=sys.stderr)
            rc, out = execute_script(_script_from(ns), None, ns.timeout)
            print(out, file=sys.stdout if rc == 0 else sys.stderr)
            return 0 if rc == 0 else 1
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


# --------------------------------------------------------------------------- selftest


def selftest() -> bool:
    """Offline self-test; does not require gdb."""
    ok = True

    def check(cond: bool, msg: str) -> None:
        nonlocal ok
        if not cond:
            ok = False
            print(f"  FAIL: {msg}")

    check(len(RECIPES) > 0, "recipe store non-empty")
    check(len({r.key for r in RECIPES}) == len(RECIPES), "recipe keys unique")
    check(all(r.key and r.title and r.tags and (r.gdb or r.gef or r.pwndbg) for r in RECIPES),
          "every recipe has key/title/tags/commands")
    hits = search_recipes("offset")
    check(len(hits) > 0 and any("pattern" in r.key for r in hits), "find('offset') returns pattern recipes")
    check(search_recipes("OFFSET") == hits, "find is case-insensitive")
    check(search_recipes("zzz-no-such-keyword") == [], "find with no match returns empty")
    for kw in ("tele", "heap", "vmmap"):
        r = search_recipes(kw)
        check(bool(r) and bool(r[0].gef) and bool(r[0].pwndbg), f"{kw}: gef and pwndbg variants present")
    check("gef:" in format_recipe(hits[0]) if hits else False, "format_recipe shows gef block")

    script = build_script("./chal", ["A", "B"], ["main", "*0x401136"], ["set disassembly-flavor intel"],
                          ["x/s $rdi"], stdin_file="in.txt")
    lines = script.splitlines()
    check(isinstance(script, str) and script.endswith("\n") and "\0" not in script, "script is well-formed text")
    check("break main" in lines and "break *0x401136" in lines, "script contains requested breakpoints")
    check("file ./chal" in lines and "set args A B" in lines, "script sets target and args")
    check("run < in.txt" in lines, "script has run with stdin")
    check(lines.count("commands") == 2 and lines.count("end") == 2, "bp commands blocks balanced")
    check(lines.index("break main") < lines.index("run < in.txt") < lines.index("info registers"),
          "order: breakpoints, run, dump")
    check("info registers" not in build_script("./chal", dump=False), "--no-dump omits dump")
    try:
        build_script("./x", breakpoints=["main\nshell id"])
        check(False, "newline injection rejected")
    except ValueError:
        pass

    # External path: simulate gdb absent -> graceful (no exception, rc 1, clear message).
    try:
        rc, msg = execute_script(script, "./chal", which=lambda _n: None)
        check(rc == 1 and "not found" in msg, "missing gdb is skipped gracefully")
    except Exception as exc:  # noqa: BLE001 - selftest must report, not crash
        check(False, f"missing-gdb path raised {exc!r}")
    # CLI paths
    check(run(["-h"]) == 0 and run(["bogus"]) == 2, "usage exit codes (0 help / 2 unknown)")
    check(run(["find", "offset"]) == 0, "CLI find returns 0")
    with tempfile.TemporaryDirectory() as td:
        out = os.path.join(td, "o.gdb")
        check(run(["script", "./chal", "-b", "main", "-c", "set x 1", "-o", out]) == 0
              and "break main" in open(out, encoding="utf-8").read(), "CLI script writes file with breakpoint")
    print("  (gdb on PATH: %s; real gdb is never run by the selftest -- offline)" % ("yes" if shutil.which("gdb") else "no"))
    return ok


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
