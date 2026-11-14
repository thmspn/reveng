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

from modules import discover  # noqa: E402


def selftest(mods: dict) -> int:
    """Run every module self-test, print a summary, return exit code (0 = all passed)."""
    passed = 0
    for name, mod in mods.items():
        try:
            ok = bool(mod.selftest())
        except Exception as exc:  # a crashing self-test is a failure, not a toolkit crash
            print(f"  error: {type(exc).__name__}: {exc}")
            ok = False
        print(f"[{'PASS' if ok else 'FAIL'}] {name}")
        passed += ok
    print(f"\n{passed}/{len(mods)} modules passed")
    return 0 if passed == len(mods) else 1


def menu(mods: dict) -> int:
    """Interactive numbered menu; empty input or 'q' quits."""
    names = list(mods)
    while True:
        print("\n=== RE toolkit ===")
        for i, name in enumerate(names, 1):
            print(f"  {i}. {name:<10} {mods[name].DESCRIPTION}")
        print("  q. quit")
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
            print("invalid choice")
            continue
        try:
            argline = input(f"{name} args> ")
        except EOFError:
            return 0
        try:
            mods[name].run(shlex.split(argline))
        except SystemExit:
            pass  # argparse exits on bad args; stay in the menu


def main(argv: list[str]) -> int:
    """Dispatch to selftest, a direct module run, or the menu."""
    mods = discover()
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
    return mods[argv[0]].run(argv[1:])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
