"""Terminal styling helpers for recon.py's interactive menu (raw ANSI, stdlib only).

This is a helper, not a toolkit module: it has no NAME/DESCRIPTION/run/selftest, so the
registry in ``modules/__init__.py`` skips it. Colors are emitted only when stdout is a TTY
and ``NO_COLOR`` is unset; otherwise every helper returns plain text.
"""
from __future__ import annotations

import os
import sys

RESET = "\033[0m"
BOLD = "\033[1m"
BLUE = "\033[34m"
CYAN = "\033[36m"
YELLOW = "\033[33m"
GREEN = "\033[32m"
RED = "\033[31m"
WHITE = "\033[97m"

RULE_WIDTH = 80

BANNER = (
    "██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗",
    "██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║",
    "██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║",
    "██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║",
    "██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║",
    "╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝",
)
SUBTITLE = "CTF Reverse-Engineering Toolkit - offline"


def use_color() -> bool:
    """True when stdout is a TTY and NO_COLOR is not set."""
    return sys.stdout.isatty() and "NO_COLOR" not in os.environ


def _unicode_ok() -> bool:
    """True when stdout's encoding can render the box/symbol characters used here."""
    try:
        "─▶▸✓✗⚠ℹ█╗".encode(sys.stdout.encoding or "ascii")
    except (UnicodeEncodeError, LookupError):
        return False
    return True


def paint(text: str, *codes: str) -> str:
    """Wrap ``text`` in ANSI ``codes`` when color is enabled, else return it unchanged."""
    if not codes or not use_color():
        return text
    return "".join(codes) + text + RESET


def rule() -> str:
    """A horizontal rule, cyan when color is enabled."""
    return paint(("─" if _unicode_ok() else "-") * RULE_WIDTH, CYAN)


def header(title: str) -> str:
    """Section header: rule, ``▶ TITLE``, rule."""
    arrow = "▶" if _unicode_ok() else ">"
    return f"{rule()}\n{paint(f'{arrow} {title}', BOLD, YELLOW)}\n{rule()}"


def banner() -> str:
    """Blue block-letter banner with a cyan subtitle (plain text when color is off)."""
    if not _unicode_ok():
        return f"RECON\n{SUBTITLE}"
    lines = [paint(line, BOLD, BLUE) for line in BANNER]
    lines.append(paint(SUBTITLE, CYAN))
    return "\n".join(lines)


def category(title: str) -> str:
    """Yellow ``▸ CATEGORY`` heading."""
    return paint(f"{'▸' if _unicode_ok() else '>'} {title}", BOLD, YELLOW)


def menu_row(key: str, name: str, desc: str, name_width: int = 12, num_width: int = 3) -> str:
    """One menu row: cyan right-aligned key, padded name, white description cut to fit the rule."""
    room = RULE_WIDTH - (2 + num_width + 2 + name_width + 1)
    if len(desc) > room:
        desc = desc[: room - 1].rstrip() + ("…" if _unicode_ok() else ".")
    return f"  {paint(key.rjust(num_width), CYAN)}  {name:<{name_width}} {paint(desc, WHITE)}".rstrip()


def _status(symbol: str, ascii_symbol: str, color: str, msg: str) -> str:
    return f"{paint(symbol if _unicode_ok() else ascii_symbol, color)} {msg}"


def success(msg: str) -> str:
    """Green ``✓`` status line."""
    return _status("✓", "[ok]", GREEN, msg)


def error(msg: str) -> str:
    """Red ``✗`` status line."""
    return _status("✗", "[x]", RED, msg)


def warning(msg: str) -> str:
    """Yellow ``⚠`` status line."""
    return _status("⚠", "[!]", YELLOW, msg)


def info(msg: str) -> str:
    """Blue ``ℹ`` status line."""
    return _status("ℹ", "[i]", BLUE, msg)


# --------------------------------------------------------------------------- beginner guidance
# name -> (plain-English purpose, example for the ``args>`` prompt). Examples are arguments only (no module name);
# tests/test_ui.py runs every one through the real module parser. File names are placeholders to replace.
GUIDE: dict[str, tuple[str, str]] = {
    "apk": ("Look inside an Android .apk: manifest, strings, certificates.", "app.apk --strings"),
    "asmeval": ("Work out what a pasted assembly listing returns for given inputs.", "func.S --func check --arg 5"),
    "autosolve": ("Find the 'correct/wrong' check in an ELF and try to derive the input it wants.", "chall"),
    "batch": ("Run quick triage on every file in a folder and show one table.", "challenge_folder --quick"),
    "binextras": ("Small binary helpers: cyclic patterns, ROP gadgets, hexdump, file carving.", "hexdump chall -l 64"),
    "crypto": ("Attack classic ciphers (XOR, Vigenere, substitution) and simple RSA.", 'freq "Uryyb Jbeyq"'),
    "decode": ("Decode or encode base64/hex/url/rot and guess layered encodings.", '"SGVsbG8gV29ybGQ="'),
    "disasm": ("Disassemble an ELF: entry point, ranges, calls and strings.", "entry chall 10"),
    "elfpatch": ("Write a patched COPY of an ELF (flip a jump, NOP bytes). Never edits the input.", "flip chall --at 0x401136 -o chall_patched"),
    "exploitnotes": ("Read short offline notes on common pwn techniques.", "ret2win"),
    "forensics": ("Inspect a packet capture or file: streams, HTTP objects, metadata, magic bytes.", "capture.pcap --http"),
    "gdbkit": ("Look up gdb/gef command recipes and generate gdb batch scripts.", "find breakpoint"),
    "go": ("Easiest start: detect the input type, run the right tools, print ranked candidates.", "chall"),
    "hashid": ("Guess a hash's type; try a local wordlist against it.", "id 5f4dcc3b5aa765d61d8327deb882cf99"),
    "pwnhelp": ("Exploit arithmetic: pack/unpack addresses, libc base, format-string offsets.", "pack 0x401136"),
    "pyrun": ("Read a Python challenge script safely; --run only in a no-network sandbox.", "script.py"),
    "revauto": ("Auto-analyze a script or binary: unwrap obfuscation layers, list strings and flags.", "chall.py"),
    "shellcode": ("Check shellcode for bad bytes, XOR-encode it, convert between formats.", "badchars 00112233 --format hex"),
    "stego": ("Look for data hidden in an image (appended bytes, LSBs, palette).", "image.png --lsb"),
    "triage": ("First look at any file: type, hashes, strings, entropy, ELF protections.", "chall"),
    "vaultdoor": ("Solve picoCTF VaultDoor*.java password checkers without running Java.", "VaultDoor3.java"),
    "webkit": ("Offline web helpers: decode JWTs and cookies, build fuzz wordlists.", "cookie b64decode SGVsbG8"),
}


def start_here() -> str:
    """The START HERE panel: the three easiest entry points, the two prompts, and the safety facts."""
    lines = [
        category("START HERE"),
        "  One file:     select> go       then  args> chall.bin",
        "  A folder:     select> batch    then  args> challenge_folder",
        '  Pasted text:  select> go       then  args> --text "paste the challenge text"',
        "                (paste ONLY an encoded token; prose around it hides it)",
        "  select> takes a module name or number (q quits).",
        "  args> takes arguments only, not the command (type  go chall  and it fails).",
        '  Quote paths with spaces: "my folder/chall bin".',
        "  Type -h at args> to see that module's usage.",
        "  Results are candidates to verify, not answers.",
        "  No candidate is NOT success: it means nothing was found. Try another module.",
        "  A step ok only means the tool ran. go -v shows cut-off output.",
        "  The menu only waits for your choice. Nothing uses the network.",
        "  CAUTION: go on a .py file (or a folder containing .py) runs guarded Python:",
        "  review the code first; non-hostile CTF scripts only;",
        "  the sandbox is not a security boundary; no network.",
    ]
    return "\n".join(lines)


GO_PY_WARNING = "review the code first; non-hostile CTF scripts only; sandbox is not a security boundary."


def start_here_short() -> str:
    """Compact reminder shown on later menu redraws."""
    return (f"{category('REMINDER')}\n"
            "  go <file> | batch <folder> | go --text \"...\"   args> = arguments only\n"
            "  quote paths with spaces; results are candidates; ok = tool ran, not solved\n"
            "  go -v = full output; go on .py runs guarded Python (review code first)")


def batch_tip() -> str:
    """Tip printed after an interactive batch run (display only)."""
    return info("tip: the batch table is a quick first look; truncated cells are previews. Use go on a chosen file "
                "for deeper analysis (for Python files, review the code first).")


def go_warning() -> str:
    """Warning printed before the go args prompt."""
    return warning("go on a .py file (or a folder with .py files) RUNS it in a guarded sandbox: " + GO_PY_WARNING
                   + " No network.")


def module_guide(name: str, desc: str) -> str:
    """Purpose + example shown after a module is selected, before the ``args>`` prompt."""
    purpose, example = GUIDE.get(name, (desc, ""))
    out = [info(purpose)]
    if example:
        out.append(f"  example  args> {paint(example, WHITE)}")
    out.append("  (-h shows usage; arguments only, not the module name)")
    return "\n".join(out)
