#!/usr/bin/env python3
"""Offline CTF reverse-engineering toolkit: master script.

    python3 recon.py                  interactive menu
    python3 recon.py <module> [args]  run one module
    python3 recon.py --selftest       run every module's self-test

No network access is used anywhere in this toolkit.
"""
from __future__ import annotations

import os
import shlex
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules import IMPORT_ERRORS, discover, ui  # noqa: E402


def selftest(mods: dict) -> int:
    """Run every module self-test, print a summary, return exit code (0 = all passed)."""
    passed = 0
    for name, err in IMPORT_ERRORS.items():  # modules that failed to import count as failures
        print(f"  error: import failed: {err}")
        print(f"[FAIL] {name}")
    for name, mod in mods.items():
        try:
            ok = bool(mod.selftest())
        except Exception as exc:  # a crashing self-test is a failure, not a toolkit crash
            print(f"  error: {type(exc).__name__}: {exc}")
            ok = False
        print(f"[{'PASS' if ok else 'FAIL'}] {name}")
        passed += ok
    total = len(mods) + len(IMPORT_ERRORS)
    print(f"\n{passed}/{total} modules passed")
    return 0 if passed == total else 1


def run_module(mod, args: list[str]) -> int:
    """Run one module's CLI; an unexpected exception prints 'error: ...' instead of a traceback."""
    try:
        rc = mod.run(args)
    except SystemExit as exc:  # a module that still lets argparse exit
        return exc.code if isinstance(exc.code, int) else (0 if exc.code is None else 1)
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    except Exception as exc:  # noqa: BLE001 - no stack traces to the user
        print(f"error: {mod.NAME}: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    return rc if isinstance(rc, int) else 0


# Display-only grouping for the menu; numbers still follow registry order. Unlisted modules land in "Other".
CATEGORIES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("REVERSE / PWN", ("triage", "disasm", "elfpatch", "asmeval", "binextras", "pwnhelp",
                       "shellcode", "gdbkit", "apk", "vaultdoor", "pyrun")),
    ("CRYPTO / HASH", ("crypto", "hashid", "decode")),
    ("FORENSICS / STEGO", ("forensics", "stego")),
    ("WEB", ("webkit",)),
    ("AUTOMATION", ("go", "autosolve", "revauto", "batch")),
    ("REFERENCE", ("exploitnotes",)),
)


def print_menu(mods: dict, guide: bool = True) -> None:
    """Print the categorized menu. Numbers follow registry order, so choices are unchanged.

    The full START HERE panel is shown on first display; later redraws show a compact reminder.
    """
    names = list(mods)
    number = {name: i for i, name in enumerate(names, 1)}
    width = max([len(n) for n in names] + [10]) + 1
    listed = {n for _, members in CATEGORIES for n in members}
    groups = [(title, [n for n in members if n in mods]) for title, members in CATEGORIES]
    groups.append(("OTHER", [n for n in names if n not in listed]))
    print()
    print(ui.header("RE TOOLKIT"))
    print(ui.start_here() if guide else ui.start_here_short())
    print()
    for title, members in groups:
        if not members:
            continue
        print(ui.category(title))
        for name in members:
            print(ui.menu_row(str(number[name]), name, mods[name].DESCRIPTION, width))
        print()
    print(ui.category("SPECIAL"))
    print(ui.menu_row("q", "quit", "exit the toolkit", width))


def path_hint(argline: str, args: list[str], rc: int, module: str = "") -> str:
    """Display-only advice after a failed run when an unquoted path with spaces may have been split."""
    if rc == 0 or len(args) < 2 or '"' in argline or "'" in argline:
        return ""
    for i in range(len(args)):
        for j in range(i + 1, len(args)):
            joined = " ".join(args[i:j + 1])
            if os.path.exists(joined):
                return f'"{joined}" exists but was split at the spaces: quote the ENTIRE path, e.g. "{joined}"'
    if rc == 2 and args[0] != module:
        return 'hint: if a path contains spaces, quote the ENTIRE path, e.g. "my folder/chall bin"'
    return ""


def menu(mods: dict) -> int:
    """Interactive numbered menu; empty input or 'q' quits."""
    names = list(mods)
    print(ui.banner())
    first = True
    while True:
        print_menu(mods, guide=first)
        first = False
        try:
            choice = input("select> ").strip()
        except EOFError:
            return 0
        if choice in ("", "q", "quit"):
            return 0
        if choice.isdigit() and 1 <= int(choice) <= len(names):
            name = names[int(choice) - 1]
        elif choice in mods:
            name = choice
        else:
            if choice.lower() in ("help", "?"):
                print(ui.start_here())
            print(ui.warning("invalid choice: type a module name (e.g. go) or its number from the list, or q to quit"))
            continue
        print(ui.module_guide(name, mods[name].DESCRIPTION))
        if name == "go":
            print(ui.go_warning())
        try:
            argline = input(f"{name} args> ")
        except EOFError:
            return 0
        try:
            args = shlex.split(argline)
        except ValueError as exc:  # e.g. unbalanced quotes
            print(ui.error(f"error: {exc}"))
            continue
        if args and args[0] == name:
            print(ui.info(f"hint: you typed the module name '{name}' at args>. It is already selected, so args> takes "
                          "arguments only. Submitted as written; if it fails, retry without it."))
        rc = run_module(mods[name], args)
        if name == "batch":
            print(ui.batch_tip())
        hint = path_hint(argline, args, rc, name)
        if hint:
            print(ui.info(hint))


def main(argv: list[str]) -> int:
    """Dispatch to selftest, a direct module run, or the menu."""
    mods = discover()
    for name, err in IMPORT_ERRORS.items():
        print(f"warning: module '{name}' failed to import ({err}); skipped", file=sys.stderr)
    if not argv:
        return menu(mods)
    if argv[0] == "--selftest":
        return selftest(mods)
    if argv[0] in ("-h", "--help"):
        print(__doc__)
        print("modules: " + ", ".join(mods))
        return 0
    if argv[0] not in mods:
        print(f"unknown module '{argv[0]}'. available: {', '.join(mods)}", file=sys.stderr)
        return 2
    return run_module(mods[argv[0]], argv[1:])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
