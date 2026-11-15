"""PYRUN: guarded execution lane for "run this Python script" challenges.

Guardrails (encoded in the tool, not just documented):

* READ BEFORE RUN   -- Phase 1 (default, never executes anything) parses the script with ``ast``
  and prints a mechanical report; Phase 2 (``--run``) always prints that report first.
* NOTHING RUNS BLIND -- ``--run`` REFUSES (exit 2) when the scan found network, subprocess,
  shell, out-of-cwd file-write calls, obfuscated imports, or when the script does not parse.
  ``--force`` overrides the scan findings (never a syntax error) and prints a loud warning.
* NO NETWORK        -- the generated shim replaces ``socket.socket`` / ``create_connection`` /
  DNS lookups with a ``RuntimeError("network blocked by pyrun")`` *even with --force*.
* SANDBOXED         -- the script runs in a child interpreter (``-I``), in a fresh temp dir,
  with RLIMIT_CPU 10s / RLIMIT_AS 512MB / RLIMIT_FSIZE 64MB where the platform allows, a
  minimal environment, and a parent-enforced wall-clock timeout (default 15s). Without
  ``--force`` the shim also blocks process spawning (os.system, subprocess, exec*, fork).

Honest limits: this is a guard rail for *non-hostile* challenge scripts, not a security
boundary against malicious code (ctypes, ``_socket`` tricks, absolute-path writes built at
runtime are not all caught). The static scan cannot see paths/imports computed at runtime;
those are reported as ``write-unresolved`` / refused as ``obf-import`` where detectable.
The static folder never executes script code: it only evaluates a whitelist of constant
expressions (chr/ord/arithmetic/join/slicing/comprehensions over literals).

Exit codes: 0 done (scan printed / run finished), 1 file unreadable, 2 REFUSED or usage,
124 wall-clock timeout (like timeout(1)).

Fully offline; pure stdlib.
"""
from __future__ import annotations

import argparse
import ast
import base64
import binascii
import concurrent.futures
import contextlib
import io
import operator
import os
import posixpath
import re
import shutil
import signal
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

try:
    from . import batch
except ImportError:  # run outside the package
    import batch  # type: ignore[no-redef]

NAME = "pyrun"
DESCRIPTION = "Guarded Python-script lane: static scan + derived passwords; --run in a no-network sandbox"

FLAG_RE = batch.FLAG_RE
DEFAULT_TIMEOUT = 15.0
OUTPUT_CAP = 1_000_000          # bytes of child stdout/stderr read back
SHOW_CAP = 4000                 # chars of child output echoed
MAX_AUTO_CANDIDATES = 24
MAX_SOLO_RUNS = 8
MAX_SWEEP = 5000                # candidates (source literals + wordlist lines) tried one-per-run
SWEEP_WORKERS = 8
SWEEP_BUDGET = 180.0            # wall-clock seconds for the whole sweep
DEFAULT_INPUTS = ["", "password"]
REFUSE_CATS = ("network", "subprocess", "shell", "write-outside", "obf-import")

NET_ROOTS = {"socket", "requests", "urllib", "urllib2", "urllib3", "http", "httplib", "ftplib",
             "smtplib", "telnetlib", "poplib", "imaplib", "xmlrpc", "httpx", "aiohttp",
             "websocket", "websockets", "paramiko", "scapy", "socketserver"}
NET_BENIGN = {"socket.inet_aton", "socket.inet_ntoa", "socket.inet_pton", "socket.inet_ntop",
              "socket.htons", "socket.ntohs", "socket.htonl", "socket.ntohl", "socket.gethostname"}
NET_BENIGN_PREFIX = ("urllib.parse.", "urllib.error.", "http.cookies.", "http.HTTPStatus")
PROC_FUNCS = {"os.fork", "os.forkpty", "os.posix_spawn", "os.posix_spawnp", "commands.getoutput",
              "commands.getstatusoutput"}
SHELL_FUNCS = {"os.system", "os.popen", "pty.spawn", "commands.getoutput"}
WRITE_FUNCS = {"os.remove", "os.unlink", "os.rmdir", "os.removedirs", "os.rename", "os.replace",
               "os.mkdir", "os.makedirs", "os.chmod", "os.chown", "os.symlink", "os.link",
               "os.truncate", "shutil.rmtree", "shutil.copy", "shutil.copy2", "shutil.copyfile",
               "shutil.copytree", "shutil.move"}
PATH_WRITE_METHODS = {"write_text", "write_bytes", "unlink", "rmdir", "touch", "mkdir", "rename",
                      "replace", "chmod", "symlink_to", "hardlink_to"}


# --------------------------------------------------------------------------- constant folder

class _NoFold(Exception):
    """Expression is not a statically known constant."""


_BINOPS: dict[type, Callable[[Any, Any], Any]] = {
    ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
    ast.FloorDiv: operator.floordiv, ast.Mod: operator.mod, ast.BitXor: operator.xor,
    ast.BitAnd: operator.and_, ast.BitOr: operator.or_,
}


def _range_list(*a: int) -> list[int]:
    r = range(*a)
    if len(r) > 10_000:
        raise _NoFold
    return list(r)


def _int(x: Any, base: int = 10) -> int:
    if isinstance(x, int):
        return x
    return int(x, base) if isinstance(x, (str, bytes)) else (_ for _ in ()).throw(_NoFold())


def _chr(x: int) -> str:
    if not isinstance(x, int) or not 0 <= x <= 0x10FFFF:
        raise _NoFold
    return chr(x)


def _bytes(x: Any) -> bytes:
    if isinstance(x, (list, tuple)) and all(isinstance(i, int) for i in x):
        return bytes(x)
    if isinstance(x, bytes):
        return x
    raise _NoFold


_FUNCS: dict[str, Callable[..., Any]] = {
    "chr": _chr, "ord": ord, "str": str, "int": _int, "len": len, "bytes": _bytes,
    "bytearray": _bytes, "hex": hex, "bin": bin, "oct": oct, "abs": abs, "sum": sum,
    "list": list, "tuple": tuple, "reversed": lambda x: list(reversed(x)), "sorted": sorted,
    "range": _range_list, "min": min, "max": max, "zip": lambda *a: list(zip(*a)),
    "enumerate": lambda x: list(enumerate(x)),
}
_DOTTED: dict[str, Callable[..., Any]] = {
    "bytes.fromhex": bytes.fromhex, "base64.b64decode": base64.b64decode,
    "base64.b64encode": base64.b64encode, "base64.b32decode": base64.b32decode,
    "base64.b16decode": base64.b16decode, "binascii.unhexlify": binascii.unhexlify,
    "binascii.hexlify": binascii.hexlify, "os.path.join": posixpath.join,
    "posixpath.join": posixpath.join,
}
_METHODS = {"join", "upper", "lower", "strip", "lstrip", "rstrip", "replace", "decode", "encode",
            "hex", "zfill", "title", "swapcase", "capitalize", "split", "format", "count",
            "index", "find"}


def _dotted_plain(node: ast.AST) -> Optional[str]:
    """``a.b.c`` -> "a.b.c" for pure Name/Attribute chains, else None."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_plain(node.value)
        return None if base is None else f"{base}.{node.attr}"
    return None


def fold(node: ast.AST, env: dict[str, Any], depth: int = 0) -> Any:
    """Evaluate ``node`` as a constant using a whitelist; raise ``_NoFold`` otherwise.

    Never executes script code: only literals, ``env`` names, a fixed set of pure builtins,
    arithmetic and string/bytes methods are evaluated.
    """
    if depth > 60:
        raise _NoFold
    try:
        return _fold(node, env, depth + 1)
    except _NoFold:
        raise
    except Exception as exc:  # noqa: BLE001 - any evaluation failure means "not constant"
        raise _NoFold from exc


def _fold(node: ast.AST, env: dict[str, Any], d: int) -> Any:
    if isinstance(node, ast.Constant):
        if isinstance(node.value, (str, bytes, int)):
            return node.value
        raise _NoFold
    if isinstance(node, ast.Name):
        if node.id in env:
            return env[node.id]
        raise _NoFold
    if isinstance(node, (ast.List, ast.Tuple)):
        items = [fold(e, env, d) for e in node.elts if not isinstance(e, ast.Starred)]
        if len(items) != len(node.elts):
            raise _NoFold
        return items if isinstance(node, ast.List) else tuple(items)
    if isinstance(node, ast.UnaryOp):
        v = fold(node.operand, env, d)
        if not isinstance(v, int):
            raise _NoFold
        if isinstance(node.op, ast.USub):
            return -v
        if isinstance(node.op, ast.UAdd):
            return v
        if isinstance(node.op, ast.Invert):
            return ~v
        raise _NoFold
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        # Flatten the left spine iteratively: ``chr(1) + chr(2) + ... + chr(90)`` is a
        # left-nested chain whose depth would otherwise exceed the recursion budget.
        spine: list[ast.AST] = []
        cur: ast.AST = node
        while isinstance(cur, ast.BinOp) and isinstance(cur.op, ast.Add):
            spine.append(cur.right)
            cur = cur.left
        acc = fold(cur, env, d)
        for right in reversed(spine):
            acc = _check(acc + fold(right, env, d))
        return acc
    if isinstance(node, ast.BinOp):
        a, b = fold(node.left, env, d), fold(node.right, env, d)
        op = type(node.op)
        if op is ast.LShift and isinstance(a, int) and isinstance(b, int) and 0 <= b <= 4096:
            return a << b
        if op is ast.RShift and isinstance(a, int) and isinstance(b, int) and 0 <= b <= 4096:
            return a >> b
        if op is ast.Pow and isinstance(a, int) and isinstance(b, int) and 0 <= b <= 64 \
                and abs(a) <= 2 ** 64:
            return a ** b
        if op is ast.Mult and isinstance(a, (str, bytes, list)) and isinstance(b, int) \
                and len(a) * max(b, 0) > _MAXLEN:
            raise _NoFold
        if op is ast.Mod and isinstance(a, (str, bytes)):
            return a % (tuple(b) if isinstance(b, list) else b)
        if op in _BINOPS:
            return _BINOPS[op](a, b)
        raise _NoFold
    if isinstance(node, ast.Subscript):
        v = fold(node.value, env, d)
        sl = node.slice
        if isinstance(sl, ast.Slice):
            parts = [None if p is None else fold(p, env, d) for p in (sl.lower, sl.upper, sl.step)]
            return v[slice(*parts)]
        return v[fold(sl, env, d)]
    if isinstance(node, (ast.ListComp, ast.GeneratorExp)):
        return _fold_comp(node, env, d)
    if isinstance(node, ast.Call):
        return _fold_call(node, env, d)
    raise _NoFold


_MAXLEN = 100_000


def _bind(target: ast.AST, value: Any, env: dict[str, Any]) -> None:
    """Bind a comprehension target (Name or tuple of Names) into ``env``."""
    if isinstance(target, ast.Name):
        env[target.id] = value
    elif isinstance(target, (ast.Tuple, ast.List)) and len(target.elts) == len(value):
        for t, v in zip(target.elts, value):
            _bind(t, v, env)
    else:
        raise _NoFold


def _fold_comp(node: Any, env: dict[str, Any], d: int) -> list[Any]:
    if len(node.generators) != 1 or node.generators[0].ifs or node.generators[0].is_async:
        raise _NoFold
    gen = node.generators[0]
    it = fold(gen.iter, env, d)
    if not isinstance(it, (str, bytes, list, tuple)) or len(it) > 10_000:
        raise _NoFold
    out = []
    for item in it:
        local = dict(env)
        _bind(gen.target, item, local)
        out.append(fold(node.elt, local, d))
    return out


def _fold_call(node: ast.Call, env: dict[str, Any], d: int) -> Any:
    if node.keywords:
        raise _NoFold
    f = node.func
    if isinstance(f, ast.Name):
        if f.id in _FUNCS and f.id not in env:
            return _check(_FUNCS[f.id](*[fold(a, env, d) for a in node.args]))
        raise _NoFold
    if isinstance(f, ast.Attribute):
        dn = _dotted_plain(f)
        if dn in _DOTTED:
            return _check(_DOTTED[dn](*[fold(a, env, d) for a in node.args]))
        if f.attr in _METHODS:
            recv = fold(f.value, env, d)
            if isinstance(recv, (str, bytes)):
                return _check(getattr(recv, f.attr)(*[fold(a, env, d) for a in node.args]))
    raise _NoFold


def _check(v: Any) -> Any:
    if isinstance(v, (str, bytes, list, tuple)) and len(v) > _MAXLEN:
        raise _NoFold
    if isinstance(v, int) and abs(v) > 2 ** 4200:
        raise _NoFold
    return v


def try_fold(node: ast.AST, env: dict[str, Any]) -> tuple[bool, Any]:
    """``(True, value)`` if ``node`` folds to a constant, else ``(False, None)``."""
    try:
        return True, fold(node, env)
    except _NoFold:
        return False, None


# --------------------------------------------------------------------------- scan data

@dataclass
class Finding:
    """One mechanical scan finding."""
    cat: str
    line: int
    text: str


@dataclass
class Candidate:
    """A statically derived candidate input / secret."""
    value: str
    conf: str          # HIGH / MEDIUM / LOW
    why: str
    line: int


@dataclass
class Scan:
    """Phase-1 result."""
    path: str
    syntax_error: Optional[str] = None
    imports: list[tuple[int, str]] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    blobs: list[Finding] = field(default_factory=list)
    candidates: list[Candidate] = field(default_factory=list)
    derived: list[Candidate] = field(default_factory=list)      # xor / arithmetic derived values

    def refusals(self) -> list[Finding]:
        """Findings that block ``--run`` (and a syntax error always does)."""
        return [f for f in self.findings if f.cat in REFUSE_CATS]


_FILE_EXT_RE = re.compile(r"\.(txt|bin|enc|py|pyc|md|json|csv|log|dat|hash|key|pem|png|jpg|gif|zip|gz|tar|"
                          r"elf|exe|so|dll|html?|xml|ya?ml|cfg|ini|sh|c|h|out|flag)$", re.I)


def password_shaped(s: str) -> bool:
    """Plausible password: printable ASCII, 2-32 chars, no whitespace, not a filename/path/option."""
    if not 2 <= len(s) <= 32 or any(not 32 < ord(c) < 127 for c in s):
        return False
    if _FILE_EXT_RE.search(s) or s.startswith(("/", "./", "../", "-", "~")):
        return False
    return not ("%" in s and re.search(r"%[sdrx]", s)) and not re.search(r"\{\w*\}", s)


_CONF_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def _printable_ratio(s: str) -> float:
    return sum(32 <= ord(c) < 127 for c in s) / len(s) if s else 0.0


def _show(v: Any, n: int = 70) -> str:
    r = repr(v)
    return r if len(r) <= n else r[: n - 3] + "..."


def _xor_apply(secret: Any, key: Any) -> str:
    """Char-wise xor of ``secret`` with ``key`` repeated to len(secret) (str_xor semantics)."""
    s = secret.decode("latin-1") if isinstance(secret, bytes) else secret
    k = key.decode("latin-1") if isinstance(key, bytes) else key
    if not k:
        raise _NoFold
    return "".join(chr(ord(c) ^ ord(k[i % len(k)])) for i, c in enumerate(s))


# --------------------------------------------------------------------------- scanner

_INPUT_FUNCS = {"input", "raw_input"}
_UNWRAP_FUNCS = {"int", "str", "float", "bytes", "bytearray", "repr", "hex"}
_UNWRAP_METHODS = {"strip", "lstrip", "rstrip", "lower", "upper", "encode", "decode", "casefold"}


class _Scanner:
    """AST walker producing a ``Scan``."""

    def __init__(self, tree: ast.Module, scan: Scan) -> None:
        self.tree = tree
        self.scan = scan
        self.alias: dict[str, str] = {}
        self.star: set[str] = set()
        self.env: dict[str, Any] = {}
        self.tainted: set[str] = set()
        self.xor_funcs: set[str] = set()
        self.loop_lists: list[tuple[int, list[Any]]] = []

    # -- helpers
    def add(self, cat: str, line: int, text: str) -> None:
        self.scan.findings.append(Finding(cat, line, text))

    def cand(self, value: Any, conf: str, why: str, line: int) -> None:
        if isinstance(value, bytes):
            value = value.decode("latin-1")
        elif isinstance(value, int):
            value = str(value)
        if not isinstance(value, str) or "\n" in value or "\r" in value or value == "":
            return
        if any(c.value == value for c in self.scan.candidates):
            return
        self.scan.candidates.append(Candidate(value, conf, why, line))

    def resolve(self, node: ast.AST) -> Optional[str]:
        """Dotted name of a call target with import aliases expanded (``__import__`` aware)."""
        if isinstance(node, ast.Name):
            return self.alias.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            base = self.resolve(node.value)
            return None if base is None else f"{base}.{node.attr}"
        if isinstance(node, ast.Call):
            fn = self.resolve(node.func)
            if fn in ("__import__", "importlib.import_module") and node.args:
                ok, v = try_fold(node.args[0], self.env)
                if ok and isinstance(v, str):
                    return v
        return None

    # -- passes
    def run(self) -> None:
        self.collect_imports()
        self.build_env()
        self.collect_taint()
        self.collect_xor_funcs()
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call):
                self.check_call(node)
            if isinstance(node, ast.Compare):
                self.check_compare(node)
            if isinstance(node, (ast.Constant,)):
                self.check_blob(node)
            if isinstance(node, ast.For):
                ok, v = try_fold(node.iter, self.env)
                if ok and isinstance(v, (list, tuple)) and all(isinstance(i, str) for i in v):
                    self.loop_lists.append((node.lineno, list(v)))
                    for item in v:
                        self.cand(item, "LOW", "literal list iterated in for-loop", node.lineno)
        self.collect_source_passwords()
        self.check_xor_calls()
        self.scan.candidates.sort(key=lambda c: (_CONF_ORDER[c.conf], c.line))
        self.scan.findings.sort(key=lambda f: f.line)

    def collect_source_passwords(self) -> None:
        """LOW candidates: password-shaped strings in top-level list/tuple/set constants."""
        mods = {a.split(".")[0] for a in self.alias.values()} | set(self.alias)
        for st in self.tree.body:
            value = st.value if isinstance(st, (ast.Assign, ast.AnnAssign)) else None
            if not isinstance(value, (ast.List, ast.Tuple, ast.Set)):
                continue
            for elt in value.elts:
                ok, v = try_fold(elt, self.env)
                if ok and isinstance(v, str) and password_shaped(v) and v not in mods:
                    self.cand(v, "LOW", "string literal in top-level list/tuple/set", st.lineno)

    def collect_imports(self) -> None:
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.scan.imports.append((node.lineno, f"import {a.name}" + (f" as {a.asname}" if a.asname else "")))
                    self.alias[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
            elif isinstance(node, ast.ImportFrom):
                mod = ("." * node.level) + (node.module or "")
                for a in node.names:
                    self.scan.imports.append((node.lineno, f"from {mod} import {a.name}" + (f" as {a.asname}" if a.asname else "")))
                    if a.name == "*":
                        self.star.add(mod)
                    else:
                        self.alias[a.asname or a.name] = f"{mod}.{a.name}"
        self.scan.imports.sort()

    def build_env(self) -> None:
        """Fold top-level ``NAME = expr`` assignments (single-assignment names only)."""
        counts: dict[str, int] = {}
        for st in self.tree.body:
            if isinstance(st, ast.Assign):
                for t in st.targets:
                    if isinstance(t, ast.Name):
                        counts[t.id] = counts.get(t.id, 0) + 1
            elif isinstance(st, ast.AugAssign) and isinstance(st.target, ast.Name):
                counts[st.target.id] = counts.get(st.target.id, 0) + 2
        for st in self.tree.body:
            if isinstance(st, ast.Assign) and len(st.targets) == 1 \
                    and isinstance(st.targets[0], ast.Name) and counts[st.targets[0].id] == 1:
                ok, v = try_fold(st.value, self.env)
                if not ok:
                    continue
                name = st.targets[0].id
                self.env[name] = v
                if not isinstance(st.value, ast.Constant) and isinstance(v, (int, str, bytes)) \
                        and not (isinstance(v, (str, bytes)) and len(v) == 0):
                    self.scan.derived.append(Candidate(
                        f"{name} = {_show(v)}", "MEDIUM", "arith-fold (top-level constant expression)", st.lineno))

    def is_input_call(self, node: ast.AST) -> bool:
        if not isinstance(node, ast.Call):
            return False
        r = self.resolve(node.func) or ""
        return r in _INPUT_FUNCS or r.endswith("getpass") or r.endswith("stdin.readline") \
            or r.endswith("stdin.read") or r.endswith("stdin.buffer.readline")

    def collect_taint(self) -> None:
        for _ in range(3):
            for node in ast.walk(self.tree):
                if isinstance(node, ast.Assign):
                    uses = any(self.is_input_call(n) or (isinstance(n, ast.Name) and n.id in self.tainted)
                               for n in ast.walk(node.value))
                    if uses:
                        for t in node.targets:
                            for n in ast.walk(t):
                                if isinstance(n, ast.Name):
                                    self.tainted.add(n.id)

    def input_like(self, node: ast.AST) -> bool:
        """True for a tainted name / input() call, possibly wrapped in int()/strip()/lower()..."""
        while True:
            if isinstance(node, ast.Call) and not self.is_input_call(node):
                if isinstance(node.func, ast.Name) and node.func.id in _UNWRAP_FUNCS and len(node.args) >= 1:
                    node = node.args[0]
                    continue
                if isinstance(node.func, ast.Attribute) and node.func.attr in _UNWRAP_METHODS:
                    node = node.func.value
                    continue
                return False
            break
        return self.is_input_call(node) or (isinstance(node, ast.Name) and node.id in self.tainted)

    def collect_xor_funcs(self) -> None:
        for st in self.tree.body:
            if isinstance(st, ast.FunctionDef) and len(st.args.args) >= 2 \
                    and any(isinstance(n, ast.BinOp) and isinstance(n.op, ast.BitXor) for n in ast.walk(st)):
                self.xor_funcs.add(st.name)

    # -- checks
    def check_call(self, node: ast.Call) -> None:
        line = node.lineno
        name = self.resolve(node.func)
        if name is None:
            if isinstance(node.func, ast.Attribute) and node.func.attr in PATH_WRITE_METHODS:
                self.check_path_method(node)
            return
        root = name.split(".")[0]
        # obfuscated import: __import__/import_module with non-constant argument
        if name in ("__import__", "importlib.import_module") and node.args:
            ok, _v = try_fold(node.args[0], self.env)
            if not ok:
                self.add("obf-import", line, f"{name}(<non-constant>)")
        if name in ("eval", "exec", "compile"):
            self.add("dynamic", line, f"{name}(...)")
        if root in NET_ROOTS and name not in NET_BENIGN and not name.startswith(NET_BENIGN_PREFIX):
            self.add("network", line, f"call {name}(...)")
        elif name.split(".")[-1] == "remote" and any(m.startswith("pwn") for m in list(self.star) + list(self.alias.values())):
            self.add("network", line, "call remote(...) (pwntools)")
        if root == "subprocess" or name in PROC_FUNCS or re.match(r"os\.(exec|spawn)\w*$", name):
            self.add("subprocess", line, f"call {name}(...)")
        if name in SHELL_FUNCS or (root == "subprocess" and any(
                k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True
                for k in node.keywords)):
            self.add("shell", line, f"call {name}(...)" + (" shell=True" if root == "subprocess" else ""))
        if name == "open" or name == "io.open" or name == "os.open" or name == "codecs.open":
            self.check_open(node, name)
        elif name in WRITE_FUNCS and node.args:
            self.classify_path(node.args[0], line, name)
            if name in ("shutil.copy", "shutil.copy2", "shutil.copyfile", "shutil.copytree",
                        "shutil.move", "os.rename", "os.replace", "os.link", "os.symlink") and len(node.args) > 1:
                self.classify_path(node.args[1], line, name)
        elif name.split(".")[-1] in ("Path", "PurePath") and False:  # pragma: no cover
            pass

    def classify_path(self, arg: ast.AST, line: int, what: str) -> None:
        ok, v = try_fold(arg, self.env)
        if not ok or not isinstance(v, (str, bytes)):
            self.add("write-unresolved", line, f"{what}: path not statically known")
            return
        p = v.decode("latin-1") if isinstance(v, bytes) else v
        if p.startswith(("/", "~", "\\")) or re.match(r"^[A-Za-z]:[\\/]", p) \
                or ".." in re.split(r"[\\/]", p):
            self.add("write-outside", line, f"{what}: path {p!r} is outside cwd")

    def check_open(self, node: ast.Call, name: str) -> None:
        if not node.args:
            return
        mode_node: Optional[ast.AST] = node.args[1] if len(node.args) > 1 else None
        for k in node.keywords:
            if k.arg in ("mode", "flags"):
                mode_node = k.value
        if name == "os.open":
            dump = ast.dump(mode_node) if mode_node is not None else ""
            writing = any(t in dump for t in ("O_WRONLY", "O_RDWR", "O_CREAT", "O_APPEND", "O_TRUNC"))
        else:
            if mode_node is None:
                return
            ok, m = try_fold(mode_node, self.env)
            if not ok:
                self.add("write-unresolved", node.lineno, f"{name}: mode not statically known")
                return
            writing = isinstance(m, str) and any(c in m for c in "wax+")
        if writing:
            self.classify_path(node.args[0], node.lineno, f"{name}(write)")

    def check_path_method(self, node: ast.Call) -> None:
        assert isinstance(node.func, ast.Attribute)
        recv = node.func.value
        if isinstance(recv, ast.Call) and (self.resolve(recv.func) or "").split(".")[-1] in ("Path", "PurePath") \
                and recv.args:
            self.classify_path(recv.args[0], node.lineno, f"Path.{node.func.attr}")
        else:
            self.add("write-unresolved", node.lineno, f".{node.func.attr}(): receiver path not statically known")

    def check_compare(self, node: ast.Compare) -> None:
        if len(node.ops) != 1:
            return
        op, left, right = node.ops[0], node.left, node.comparators[0]
        line = node.lineno
        if isinstance(op, (ast.Eq, ast.NotEq)):
            for const_side, other in ((left, right), (right, left)):
                ok, v = try_fold(const_side, self.env)
                okf, _ = try_fold(other, self.env)
                if not ok or okf or not isinstance(v, (str, bytes, int)):
                    continue
                if isinstance(other, ast.Call) and not self.input_like(other):
                    continue          # e.g. len(x) == 8, ord(c) == 5: not an input value
                if self.input_like(other):
                    self.cand(v, "HIGH", "literal compare against input", line)
                elif isinstance(other, ast.Name):
                    self.cand(v, "MEDIUM", f"literal compare against name '{other.id}'", line)
        elif isinstance(op, ast.In) and self.input_like(left):
            ok, v = try_fold(right, self.env)
            if ok and isinstance(v, (list, tuple)):
                for item in v:
                    if isinstance(item, (str, bytes, int)):
                        self.cand(item, "LOW", "member of literal list tested with 'in'", line)

    def check_blob(self, node: ast.Constant) -> None:
        v = node.value
        if isinstance(v, bytes):
            try:
                v = v.decode("ascii")
            except UnicodeDecodeError:
                return
        if not isinstance(v, str) or len(v) < 16 or any(f.line == node.lineno and v[:12] in f.text for f in self.scan.blobs):
            return
        s = v.strip()
        kind, raw = "", b""
        if re.fullmatch(r"(?:[0-9a-fA-F]{2}){8,}", s):
            kind, raw = "hex", bytes.fromhex(s)
        elif re.fullmatch(r"[A-Za-z0-9+/]{16,}={0,2}", s) and len(s) % 4 == 0 and (
                s.endswith("=") or (re.search(r"[A-Z]", s) and re.search(r"[a-z]", s) and re.search(r"\d", s))):
            try:
                kind, raw = "base64", base64.b64decode(s, validate=True)
            except (binascii.Error, ValueError):
                return
        if not kind:
            return
        txt = raw.decode("latin-1")
        prev = f"decodes to {_show(txt, 50)}" if _printable_ratio(txt) >= 0.85 else f"{len(raw)} bytes, non-printable"
        self.scan.blobs.append(Finding(kind, node.lineno, f"{_show(s, 40)} ({kind}, {prev})"))

    # -- xor derivations
    def check_xor_calls(self) -> None:
        """Find ``xor_func(a, b)`` calls anywhere (module level and inside functions)."""
        if self.xor_funcs:
            self._xor_scope(self.tree, self.env)

    def local_env(self, fn: ast.AST, outer: dict[str, Any]) -> dict[str, Any]:
        """``outer`` plus the foldable single-assignment locals of function ``fn``.

        Names the function binds in any other way (params, loops, multiple assignments)
        shadow outer constants and are therefore removed.
        """
        stores: dict[str, int] = {}
        for n in ast.walk(fn):
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
                stores[n.id] = stores.get(n.id, 0) + 1
            elif isinstance(n, ast.arg):
                stores[n.arg] = stores.get(n.arg, 0) + 2
        env = {k: v for k, v in outer.items() if k not in stores}
        for st in getattr(fn, "body", []):
            if isinstance(st, ast.Assign) and len(st.targets) == 1 \
                    and isinstance(st.targets[0], ast.Name) and stores.get(st.targets[0].id) == 1:
                ok, v = try_fold(st.value, env)
                if ok:
                    env[st.targets[0].id] = v
        return env

    def _xor_scope(self, scope: ast.AST, env: dict[str, Any]) -> None:
        stack: list[ast.AST] = [scope]
        while stack:
            for child in ast.iter_child_nodes(stack.pop()):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self._xor_scope(child, self.local_env(child, env))
                    continue
                if isinstance(child, ast.Call):
                    self._xor_call(child, env)
                stack.append(child)

    def _xor_call(self, node: ast.Call, env: dict[str, Any]) -> None:
        if not (isinstance(node.func, ast.Name) and node.func.id in self.xor_funcs
                and len(node.args) == 2 and not node.keywords):
            return
        vals = [try_fold(a, env) for a in node.args]
        fn = node.func.id
        if all(ok for ok, _ in vals):
            self.add_xor(fn, vals[0][1], vals[1][1], node.lineno, "xor-fold (both args constant)")
        elif sum(ok for ok, _ in vals) == 1:
            secret = next(v for ok, v in vals if ok)
            if not isinstance(secret, (str, bytes)):
                return
            for c in list(self.scan.candidates):
                self.add_xor(fn, secret, c.value, node.lineno, f"xor-decrypt with {c.conf} candidate")

    def add_xor(self, fn: str, secret: Any, key: Any, line: int, why: str) -> None:
        try:
            out = _xor_apply(secret, key)
        except _NoFold:
            return
        if len(out) < 4 or _printable_ratio(out) < 0.9:
            return
        conf = "HIGH" if FLAG_RE.search(out.encode("latin-1")) else "LOW"
        item = Candidate(f"{fn}(secret, {_show(key, 30)}) -> {out}", conf, why, line)
        if all(d.value != item.value for d in self.scan.derived):
            self.scan.derived.append(item)


def scan_source(source: str, path: str = "<string>") -> Scan:
    """Phase 1: parse ``source`` and return a ``Scan``. Never executes anything."""
    scan = Scan(path=path)
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError as exc:
        scan.syntax_error = f"line {exc.lineno}, col {exc.offset}: {exc.msg}"
        return scan
    except ValueError as exc:  # e.g. null bytes
        scan.syntax_error = f"line ?, col ?: {exc}"
        return scan
    _Scanner(tree, scan).run()
    _offline_hash_crack(source, path, scan)
    return scan


_WORDLIST_CAP = 200_000  # lines tried by the offline hash crack


def _offline_hash_crack(source: str, path: str, scan) -> None:
    """Static dictionary attack: source uses hashlib + reads a sibling ``*.hash.bin`` and a
    sibling wordlist exists -> crack offline with stdlib hashlib, no execution (battery ic-34).
    Emits the password as a HIGH candidate so --auto-input feeds it first."""
    import hashlib
    if "hashlib" not in source:
        return
    srcdir = os.path.dirname(os.path.abspath(path)) if path not in ("<string>",) else ""
    if not srcdir or not os.path.isdir(srcdir):
        return
    try:
        names = os.listdir(srcdir)
    except OSError:
        return
    hashes = []
    for n in names:
        p = os.path.join(srcdir, n)
        if os.path.isfile(p) and ("hash" in n.lower() or n.endswith(".hash.bin")):
            try:
                blob = open(p, "rb").read()
            except OSError:
                continue
            if blob:
                hashes.append((n, blob))
    if not hashes:
        return
    wordlists = [n for n in names
                 if os.path.isfile(os.path.join(srcdir, n)) and n.endswith(".txt")
                 and not n.endswith((".enc", ".flag.txt")) and "flag" not in n.lower()]
    algos = [a for a in ("md5", "sha1", "sha256") if a in source]
    for wl in wordlists:
        wpath = os.path.join(srcdir, wl)
        try:
            fh = open(wpath, "rb")
        except OSError:
            continue
        with fh:
            for i, line in enumerate(fh):
                if i >= _WORDLIST_CAP:
                    break
                pw = line.strip()
                if not pw:
                    continue
                for algo in algos:
                    dig = hashlib.new(algo, pw).digest()
                    for hn, blob in hashes:
                        if dig == blob or dig.hex() == blob.decode("latin-1").strip():
                            scan.derived.append(Candidate(
                                f"{wl} line {i + 1}: password {pw.decode('latin-1')!r} matches {hn} ({algo})",
                                "HIGH", "offline hash crack (no execution)", 0))
                            scan.candidates.insert(0, Candidate(pw.decode("latin-1"), "HIGH",
                                                                f"cracks {hn} via {algo}", 0))
                            return


def format_scan(scan: Scan) -> str:
    """Render the Phase-1 report (mechanical labels, no intent calls)."""
    out = [f"=== pyrun static scan: {scan.path} (nothing executed) ==="]
    if scan.syntax_error:
        out.append(f"[syntax-error] {scan.syntax_error}")
        return "\n".join(out)
    out.append(f"[imports] {len(scan.imports)}")
    out += [f"  line {ln}: {text}" for ln, text in scan.imports]
    out.append(f"[calls] {len(scan.findings)}")
    out += [f"  [{f.cat}] line {f.line}: {f.text}" for f in scan.findings]
    out.append(f"[encoded-blobs] {len(scan.blobs)}")
    out += [f"  [{f.cat}] line {f.line}: {f.text}" for f in scan.blobs]
    out.append(f"[candidate-inputs] {len(scan.candidates)}")
    out += [f"  [{c.conf}] line {c.line}: {c.value!r}  ({c.why})" for c in scan.candidates]
    out.append(f"[derived-values] {len(scan.derived)}")
    for c in scan.derived:
        tag = "derived-xor" if c.why.startswith("xor") else "derived-arith"
        out.append(f"  [{tag}] [{c.conf}] line {c.line}: {c.value}  ({c.why})")
    refs = scan.refusals()
    out.append("[run-guard] " + ("WOULD REFUSE --run: " + ", ".join(sorted({f.cat for f in refs}))
                                 if refs else "no refusal findings"))
    return "\n".join(out)


# --------------------------------------------------------------------------- sandboxed run

SHIM = r'''
import os, sys, runpy
target, workdir, allow_proc = sys.argv[1], sys.argv[2], sys.argv[3] == "1"
extra_argv = sys.argv[4:]

def _blocked(*a, **k):
    raise RuntimeError("network blocked by pyrun")

class _BlockedSocket(object):
    def __init__(self, *a, **k):
        raise RuntimeError("network blocked by pyrun")

import socket, _socket
for _m in (socket, _socket):
    _m.socket = _BlockedSocket
for _n in ("create_connection", "create_server", "getaddrinfo", "gethostbyname", "gethostbyname_ex",
           "gethostbyaddr", "socketpair", "fromfd"):
    for _m in (socket, _socket):
        if hasattr(_m, _n):
            setattr(_m, _n, _blocked)

if not allow_proc:
    def _noproc(*a, **k):
        raise RuntimeError("process spawning blocked by pyrun")
    for _n in ("system", "popen", "fork", "forkpty", "posix_spawn", "posix_spawnp",
               "execl", "execle", "execlp", "execlpe", "execv", "execve", "execvp", "execvpe",
               "spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnv", "spawnve", "spawnvp", "spawnvpe"):
        if hasattr(os, _n):
            setattr(os, _n, _noproc)
    import subprocess
    class _NoPopen(object):
        def __init__(self, *a, **k):
            raise RuntimeError("process spawning blocked by pyrun")
    subprocess.Popen = _NoPopen
    import _posixsubprocess
    _posixsubprocess.fork_exec = _noproc

try:
    import resource
    for _name, _lim in (("RLIMIT_CPU", 10), ("RLIMIT_AS", 512 * 1024 * 1024), ("RLIMIT_FSIZE", 64 * 1024 * 1024)):
        try:
            resource.setrlimit(getattr(resource, _name), (_lim, _lim))
        except (ValueError, OSError, AttributeError):
            pass
except ImportError:
    pass

os.chdir(workdir)
sys.path.insert(0, os.path.dirname(target))
sys.argv = [target] + extra_argv
runpy.run_path(target, run_name="__main__")
'''


@dataclass
class RunResult:
    """Outcome of one sandboxed execution."""
    returncode: Optional[int]
    stdout: str
    stderr: str
    timed_out: bool
    timeout: float


def _read_capped(path: str) -> str:
    with open(path, "rb") as fh:
        return fh.read(OUTPUT_CAP).decode("utf-8", "replace")


def sandbox_run(target: str, lines: list[str], timeout: float, allow_proc: bool = False, argv: list[str] | None = None) -> RunResult:
    """Run ``target`` in the shim (child interpreter, fresh temp cwd, rlimits, no network)."""
    target = os.path.abspath(target)
    base = tempfile.mkdtemp(prefix="pyrun-")
    try:
        work = os.path.join(base, "cwd")
        os.mkdir(work)
        # Sibling data files (level1.flag.txt.enc, codebook.txt, ...) must be visible to
        # scripts that open them relatively - copy the script's own directory into the
        # sandbox cwd (capped; skips subdirs and >16 MB members).
        srcdir = os.path.dirname(target)
        for name in os.listdir(srcdir):
            sp = os.path.join(srcdir, name)
            try:
                if os.path.isfile(sp) and os.path.getsize(sp) <= 16 << 20:
                    shutil.copy(sp, os.path.join(work, name))
            except OSError:
                pass
        shim = os.path.join(base, "shim.py")
        with open(shim, "w", encoding="utf-8") as fh:
            fh.write(SHIM)
        stdin_p, out_p, err_p = (os.path.join(base, n) for n in ("stdin", "stdout", "stderr"))
        with open(stdin_p, "w", encoding="utf-8") as fh:
            fh.write("".join(l + "\n" for l in lines))
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": work, "LANG": "C.UTF-8",
               "PYTHONIOENCODING": "utf-8", "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1"}
        timed_out = False
        with open(stdin_p, "rb") as fin, open(out_p, "wb") as fout, open(err_p, "wb") as ferr:
            proc = subprocess.Popen([sys.executable, "-I", shim, target, work, "1" if allow_proc else "0"] + list(argv or []),
                                    stdin=fin, stdout=fout, stderr=ferr, env=env, cwd=work,
                                    start_new_session=True)
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                with contextlib.suppress(ProcessLookupError, PermissionError):
                    os.killpg(proc.pid, signal.SIGKILL)
                proc.kill()
                proc.wait()
        return RunResult(None if timed_out else proc.returncode, _read_capped(out_p), _read_capped(err_p),
                         timed_out, timeout)
    finally:
        shutil.rmtree(base, ignore_errors=True)


def find_flags(text: str) -> list[str]:
    """Flag-shaped strings (toolkit ``FLAG_RE``) in ``text``, in order, deduplicated."""
    seen: list[str] = []
    for m in FLAG_RE.finditer(text.encode("latin-1", "replace")):
        s = m.group().decode("latin-1")
        if s not in seen:
            seen.append(s)
    return seen


def auto_inputs(scan: Scan) -> list[str]:
    """Derived candidates (HIGH first), then the common defaults; capped and deduplicated."""
    vals: list[str] = []
    for c in scan.candidates:
        if c.value not in vals and len(vals) < MAX_AUTO_CANDIDATES:
            vals.append(c.value)
    for d in DEFAULT_INPUTS:
        if d not in vals:
            vals.append(d)
    return vals


def wordlist_candidates(path: str, limit: int = MAX_SWEEP) -> tuple[Optional[str], list[str]]:
    """Lines of a small sibling wordlist (name has dict/word/pass, else any ``*.txt``).

    The script's own ``.enc``/``.bin``/``.py`` companions are never used. Returns
    ``(file name, lines)``; at most ``limit`` non-empty lines of <= 256 chars.
    """
    srcdir = os.path.dirname(os.path.abspath(path))
    me = os.path.basename(path)
    stem = me.rsplit(".", 1)[0]
    ranked: list[tuple[int, str]] = []
    try:
        names = sorted(os.listdir(srcdir))
    except OSError:
        return None, []
    for name in names:
        low = name.lower()
        full = os.path.join(srcdir, name)
        if name == me or low.endswith((".enc", ".bin", ".py", ".pyc")) or name.startswith(stem + ".") \
                or not os.path.isfile(full):
            continue
        if any(k in low for k in ("dict", "word", "pass")):
            ranked.append((0, name))
        elif low.endswith(".txt"):
            ranked.append((1, name))
    for _rank, name in sorted(ranked):
        full = os.path.join(srcdir, name)
        try:
            if os.path.getsize(full) > 4 << 20:
                continue
            with open(full, "rb") as fh:
                raw = fh.read()
        except OSError:
            continue
        if b"\0" in raw[:4096]:
            continue
        out: list[str] = []
        for ln in raw.decode("utf-8", "replace").splitlines():
            ln = ln.strip()
            if ln and len(ln) <= 256 and ln not in out:
                out.append(ln)
                if len(out) >= limit:
                    break
        if out:
            return name, out
    return None, []


def sweep(path: str, pool: list[str], explicit: list[str], timeout: float, force: bool,
          argv: list[str] | None) -> Optional[tuple[str, RunResult]]:
    """Try each candidate as the sole stdin line (parallel, one sandbox per run).

    Stops at the first run whose output contains a flag; bounded by ``SWEEP_BUDGET``.
    Returns ``(candidate, result)`` or None.
    """
    import time
    deadline = time.monotonic() + SWEEP_BUDGET

    def one(cand: str) -> Optional[tuple[str, RunResult]]:
        if time.monotonic() > deadline:
            return None
        res = sandbox_run(path, explicit + [cand], timeout, allow_proc=force, argv=list(argv or []))
        return (cand, res) if find_flags(res.stdout + "\n" + res.stderr) else None

    ex = concurrent.futures.ThreadPoolExecutor(max_workers=SWEEP_WORKERS)
    try:
        futs = [ex.submit(one, c) for c in pool]
        for f in concurrent.futures.as_completed(futs):
            hit = f.result()
            if hit:
                return hit
        return None
    finally:
        ex.shutdown(wait=True, cancel_futures=True)


def _report_run(res: RunResult, label: str) -> list[str]:
    print(f"--- run ({label}) ---")
    if res.timed_out:
        print(f"TIMEOUT: killed after {res.timeout:g}s wall-clock limit")
    else:
        print(f"exit status: {res.returncode}")
    for name, text in (("stdout", res.stdout), ("stderr", res.stderr)):
        if text.strip():
            shown = text if len(text) <= SHOW_CAP else text[:SHOW_CAP] + "\n...[truncated]"
            print(f"--- {name} ---\n{shown.rstrip()}")
    flags = find_flags(res.stdout + "\n" + res.stderr)
    for f in flags:
        print(f"[FLAG?] {f}")
    return flags


def guarded_run(path: str, scan: Scan, explicit: list[str], auto: bool, force: bool, timeout: float, argv: list[str] | None = None) -> int:
    """Phase 2: apply the refusal guardrail, then run. Returns the exit code."""
    if scan.syntax_error:
        print(f"REFUSED: script does not parse ({scan.syntax_error}); nothing was run")
        return 2
    refs = scan.refusals()
    if refs:
        reasons = "; ".join(f"[{f.cat}] line {f.line}: {f.text}" for f in refs)
        if not force:
            print(f"REFUSED (exit 2): static scan found {reasons}")
            print("nothing was run. Read the script; re-run with --force only if you accept the risk "
                  "(network stays blocked either way).")
            return 2
        print(f"!!! WARNING: --force given: running despite scan findings: {reasons} !!!")
        print("!!! network is still blocked by the shim; process spawning is permitted !!!")
    runs: list[tuple[str, list[str]]] = []
    if auto:
        autos = auto_inputs(scan)
        runs.append(("all derived candidates + defaults, line by line", explicit + autos))
        runs += [(f"single input {a!r}", explicit + [a]) for a in autos[:MAX_SOLO_RUNS]]
    else:
        runs.append(("explicit input" if explicit else "no stdin input", explicit))
    last: Optional[RunResult] = None
    for label, lines in runs:
        last = sandbox_run(path, lines, timeout, allow_proc=force, argv=list(argv or []))
        flags = _report_run(last, label)
        if flags or last.timed_out:
            break
    assert last is not None
    if last.timed_out:
        return 124
    if find_flags(last.stdout + "\n" + last.stderr):
        return 0
    if auto:
        # Scripts that read one password per run: try every remaining candidate (source
        # literals, sibling wordlist) as the sole stdin line. The 24/8 budgets above are
        # unchanged; this is a separate, bounded sweep (MAX_SWEEP runs, SWEEP_BUDGET s).
        tried = {a for a in auto_inputs(scan)[:MAX_SOLO_RUNS]}
        pool = [c.value for c in scan.candidates]
        wl_name, wl = wordlist_candidates(path)
        if wl_name:
            print(f"[wordlist] {wl_name}: {len(wl)} lines")
            pool += wl
        pool = [c for i, c in enumerate(pool) if c not in tried and c not in pool[:i]][:MAX_SWEEP]
        if pool:
            if wl_name:
                whole = sandbox_run(path, explicit + wl, timeout, allow_proc=force, argv=list(argv or []))
                if find_flags(whole.stdout + "\n" + whole.stderr):
                    _report_run(whole, f"{wl_name} streamed as stdin")
                    return 0
            hit = sweep(path, pool, explicit, timeout, force, argv)
            if hit:
                _report_run(hit[1], f"sweep input {hit[0]!r} ({len(pool)} candidates)")
                return 0
            print(f"sweep: {len(pool)} candidates tried, no flag")
    print("no flag-shaped output")
    return 0


# --------------------------------------------------------------------------- CLI

def run(args: list[str]) -> int:
    """CLI entry point: ``pyrun <script> [--run] [--force] [--timeout S] [--input T]... [--auto-input]``."""
    ap = argparse.ArgumentParser(prog="recon.py pyrun", description=DESCRIPTION)
    ap.add_argument("script", help="Python script to scan (and optionally run)")
    ap.add_argument("--run", action="store_true", help="Phase 2: run in the guarded sandbox after the scan")
    ap.add_argument("--force", action="store_true", help="run despite refusal findings (loud warning; network stays blocked)")
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help=f"wall-clock seconds (default {DEFAULT_TIMEOUT:g})")
    ap.add_argument("--input", action="append", default=[], metavar="TEXT", help="stdin line (repeatable)")
    ap.add_argument("--auto-input", action="store_true", help="also feed Phase-1 derived candidates, then '' and 'password'")
    ap.add_argument("--argv", action="append", default=[], metavar="ARG", help="extra argv passed to the script (repeatable; battery ic-6 needs -e flag.txt)")
    ns = ap.parse_args(args)
    if (ns.force or ns.auto_input or ns.input) and not ns.run:
        print("note: --force/--input/--auto-input only apply with --run; static scan only", file=sys.stderr)
    if ns.timeout <= 0:
        print("error: --timeout must be > 0", file=sys.stderr)
        return 2
    try:
        with open(ns.script, "rb") as fh:
            source = fh.read().decode("utf-8", "replace")
    except OSError as exc:
        print(f"error: cannot read {ns.script}: {exc.strerror or exc}", file=sys.stderr)
        return 1
    scan = scan_source(source, ns.script)
    print(format_scan(scan))
    if not ns.run:
        return 0
    return guarded_run(ns.script, scan, list(ns.input), ns.auto_input, ns.force, ns.timeout, argv=list(ns.argv or []))


# --------------------------------------------------------------------------- selftest

def _xor_literal(text: str, key: str) -> str:
    """Source expression ``chr(0x..)+chr(0x..)+...`` for ``text`` xor repeated ``key``."""
    return "+".join(f"chr({ord(c) ^ ord(key[i % len(key)]):#x})" for i, c in enumerate(text))


def _benign_sample(flag: str, pw: str) -> str:
    return (
        "def str_xor(secret, key):\n"
        "    new_key = key\n"
        "    i = 0\n"
        "    while len(new_key) < len(secret):\n"
        "        new_key = new_key + key[i]\n"
        "        i = (i + 1) % len(key)\n"
        "    return ''.join([chr(ord(a) ^ ord(b)) for (a, b) in zip(secret, new_key)])\n"
        f"flag_enc = {_xor_literal(flag, pw)}\n"
        "open('ran.marker', 'w').write('x')\n"
        "user_pw = input('password? ')\n"
        f"if user_pw == chr({ord(pw[0]):#x}) + chr({ord(pw[1]):#x}) + {pw[2:-1]!r} + str({int(pw[-1])}):\n"
        "    print(str_xor(flag_enc, user_pw))\n"
        "else:\n"
        "    print('wrong password')\n"
    )


def _call(argv: list[str]) -> tuple[int, str]:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        rc = run(argv)
    return rc, buf.getvalue()


def selftest() -> bool:
    """Self-contained checks: static derivation, refusal, shim network block, timeout, no-exec default."""
    flag, pw = "picoCTF{pyrun_xor_ok}", "abc1"
    ok = True

    def check(cond: bool, msg: str) -> None:
        nonlocal ok
        if not cond:
            print(f"  FAIL: {msg}")
            ok = False

    cwd = os.getcwd()
    tmp = tempfile.mkdtemp(prefix="pyrun-selftest-")
    try:
        os.chdir(tmp)

        def write(name: str, text: str) -> str:
            p = os.path.join(tmp, name)
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(text)
            return p

        benign = write("benign.py", _benign_sample(flag, pw))
        # folder sanity (pure evaluation)
        expr = ast.parse("''.join([chr(ord(c) ^ 1) for c in 'ab']) + str(2 * 3 + 1)", mode="eval").body
        check(try_fold(expr, {}) == (True, "`c7"), "constant folder")

        # static-only default: derives the password, executes nothing
        rc, out = _call([benign])
        check(rc == 0, f"static rc {rc}")
        check(repr(pw) in out and "[HIGH]" in out, "static scan derives password with HIGH tag")
        check(flag in out and "[derived-xor]" in out, "static scan derives xor-decrypted flag")
        check("[FLAG?]" not in out, "static mode prints no run-phase [FLAG?]")
        check(not os.path.exists(os.path.join(tmp, "ran.marker")), "static default must not execute (marker absent)")

        # guarded run with auto-input
        rc, out = _call([benign, "--run", "--auto-input"])
        check(rc == 0 and f"[FLAG?] {flag}" in out, f"--run --auto-input prints flag (rc {rc})")
        check(not os.path.exists(os.path.join(tmp, "ran.marker")), "script ran in a fresh tempdir, not cwd")
        rc, out = _call([benign, "--run"])
        check(rc == 0 and "no flag-shaped output" in out, "--run without input: no flag, exit 0")

        # network: refused, then forced but blocked by the shim
        net = write("net.py", "import socket\ns = socket.create_connection(('127.0.0.1', 1))\nprint('connected')\n")
        rc, out = _call([net, "--run"])
        check(rc == 2 and "REFUSED" in out and "[network]" in out, f"network sample refused (rc {rc})")
        rc, out = _call([net, "--run", "--force"])
        check("WARNING" in out and "network blocked by pyrun" in out and "connected" not in out.replace(
            "network blocked", ""), "forced network sample: shim raises RuntimeError")
        raw = write("rawsock.py", "import socket\nsocket.socket()\nprint('connected')\n")
        rc, out = _call([raw, "--run", "--force"])
        check("network blocked by pyrun" in out and "connected" not in out.replace("network blocked", ""),
              "socket.socket() blocked")

        # other refusal classes
        for name, src, cat in (("sub.py", "import subprocess\nsubprocess.run(['id'])\n", "subprocess"),
                               ("sh.py", "import os\nos.system('id')\n", "shell"),
                               ("wr.py", "open('/tmp/pyrun_x', 'w').write('x')\n", "write-outside"),
                               ("up.py", "open('../x', 'a')\n", "write-outside")):
            rc, out = _call([write(name, src), "--run"])
            check(rc == 2 and f"[{cat}]" in out, f"{name} refused as {cat} (rc {rc})")
        rc, out = _call([write("rel.py", "open('local.txt', 'w').write('x')\nprint('ok')\n"), "--run"])
        check(rc == 0 and "REFUSED" not in out, "relative write allowed")

        # timeout
        spin = write("spin.py", "while True: pass\n")
        rc, out = _call([spin, "--run", "--timeout", "1"])
        check(rc == 124 and "TIMEOUT: killed after 1s" in out, f"timeout sample (rc {rc})")

        # syntax error: location reported, never run
        bad = write("bad.py", "x = 1\nif x\n    print(x)\n")
        rc, out = _call([bad])
        check(rc == 0 and "[syntax-error] line 2" in out, "syntax error location reported")
        rc, out = _call([bad, "--run", "--force"])
        check(rc == 2 and "REFUSED" in out, "syntax error never runs, even with --force")

        # arithmetic compare + blob detection
        ar = write("ar.py", "import base64\nb = 'cGljb0NURntibG9ifQ=='\nv = int(input())\nif v == 6 * 7 + 1:\n    print('ok')\n")
        rc, out = _call([ar])
        check("'43'" in out and "[base64]" in out and "picoCTF{blob}" in out, "arith candidate + base64 blob")

        # fix 1: >60-term chr() chain + xor call in a function with function-local assignment
        long_flag = "picoCTF{" + "x" * 90 + "}"
        ser = write("ser.py", _benign_sample("A", "abc1").split("flag_enc")[0]
                    + f"flag_enc = {_xor_literal(long_flag, 'enkidu')}\n"
                    + "def go():\n    k = 'enk' + 'idu'\n    print(str_xor(flag_enc, k))\n")
        rc, out = _call([ser])
        check(f"-> {long_flag}" in out and "[HIGH]" in out, "long chr() chain + function-local key folds to flag")

        # fix 2: source-literal password list (md5 compare, never a literal compare) swept past the 8 solo runs
        import hashlib
        pws = [f"cand{i:02d}" for i in range(20)] + ["notes.txt", "has space", "x"]
        good = pws[15]
        l3 = write("lvl3.py", "import hashlib\npos_pw_list = %r\n"
                   "h = hashlib.md5(input('pw: ').encode()).hexdigest()\n"
                   "if h == %r:\n    print('%s')\nelse:\n    print('no')\n"
                   % (pws, hashlib.md5(good.encode()).hexdigest(), flag))
        rc, out = _call([l3])
        check("'cand00'" in out and "notes.txt" not in out and "has space" not in out and "'x'" not in out,
              "source-literal candidates filtered (filename/whitespace/too short)")
        rc, out = _call([l3, "--run", "--auto-input"])
        check(rc == 0 and f"[FLAG?] {flag}" in out, "source-literal candidate beyond solo-run budget found by sweep")

        # fix 3: sibling wordlist streamed one-per-run; .bin companion ignored
        wdir = os.path.join(tmp, "wl")
        os.mkdir(wdir)
        words = [f"w{i}" for i in range(40)]
        with open(os.path.join(wdir, "dictionary.txt"), "w") as fh:
            fh.write("\n".join(words) + "\n")
        with open(os.path.join(wdir, "lvl5.hash.bin"), "wb") as fh:
            fh.write(hashlib.md5(b"w31").digest())
        l5 = os.path.join(wdir, "lvl5.py")
        with open(l5, "w") as fh:
            fh.write("import hashlib\nh = open('lvl5.hash.bin','rb').read()\n"
                     "if hashlib.md5(input().encode()).digest() == h:\n    print('%s')\n" % flag)
        check(wordlist_candidates(l5)[0] == "dictionary.txt" and len(wordlist_candidates(l5)[1]) == 40, "wordlist picked")
        rc, out = _call([l5, "--run", "--auto-input"])
        # The offline hash crack may feed the password as a candidate before the wordlist
        # sweep runs - either path finding the flag satisfies this check.
        check(rc == 0 and f"[FLAG?] {flag}" in out
              and ("[wordlist] dictionary.txt: 40 lines" in out or "offline hash crack" in out),
              "wordlist auto-input finds flag")
        rc, out = _call([l5, "--run"])
        check("[FLAG?]" not in out, "wordlist only used with --auto-input")
    finally:
        os.chdir(cwd)
        shutil.rmtree(tmp, ignore_errors=True)
    return ok


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
