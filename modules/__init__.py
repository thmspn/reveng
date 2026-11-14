"""Module registry: any ``modules/<name>.py`` exposing the module contract is auto-registered.

Contract (module-level names):
    NAME: str            short CLI name
    DESCRIPTION: str     one-line summary shown in the menu
    run(args: list[str]) -> int     entry point; returns a process exit code
    selftest() -> bool   True when all internal checks pass
"""
from __future__ import annotations

import importlib
import pkgutil
from types import ModuleType

_REQUIRED = ("NAME", "DESCRIPTION", "run", "selftest")


def discover() -> dict[str, ModuleType]:
    """Import every submodule of this package and return those meeting the contract, keyed by NAME."""
    found: dict[str, ModuleType] = {}
    for info in sorted(pkgutil.iter_modules(__path__), key=lambda i: i.name):
        mod = importlib.import_module(f"{__name__}.{info.name}")
        if all(hasattr(mod, attr) for attr in _REQUIRED):
            found[mod.NAME] = mod
    return found
