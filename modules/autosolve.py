"""autosolve - automatic flag-checker solver (spec: toolkit/PLAN-autosolve.md).

Junior analyst for one job: given an x86 / x86-64 ELF flag checker it finds the
verdict strings, traces back to the deciding branch, walks the checker with a
small bounded abstract interpreter (built-in x86 decoder; capstone is a
presentation-only upgrade) and ends with ONE headline: a derived answer, an
exact patch target, or the next manual step.  Optional Lane 2 hands the
addresses to angr in a timeout-bounded child process.

Hard rules: fully offline, the target binary is never executed, the only child
process is the angr helper (``sys.executable -c``).
"""
from __future__ import annotations

import argparse
import ast
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import random
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from typing import Any, Callable

if __package__:
    from . import batch, disasm, elfpatch, gdbkit, pwnhelp, revauto
else:  # python3 modules/autosolve.py
    import batch, disasm, elfpatch, gdbkit, pwnhelp, revauto  # type: ignore[no-redef]

NAME = "autosolve"
DESCRIPTION = ("Flag-checker auto-solver: verdict strings -> deciding branch -> constraints -> "
               "derived flag / exact patch / next step; optional angr lane")

# ---------- constants (spec 2.3)
MAX_INPUT = 64 * 1024 * 1024
MAX_FUNC_BYTES = 64 * 1024
MAX_FUNCS = 64
MAX_CALL_DEPTH = 3
MAX_STEPS = 200_000
MAX_PATHS = 256
MAX_LOOP_ITERS = 4096
MAX_SYM_LEN = 512
MAX_SEARCH = 1_000_000
MAX_VERDICT_STRINGS = 64
MAX_LISTING = 120
STATIC_BUDGET = 15.0
ANGR_TIMEOUT = 60

FAIL_PATTERNS = [r"\bwrong\b", r"\bincorrect\b", r"\bnot (?:the )?(?:right|correct|flag)\b",
                 r"\bnope\b", r"\btry again\b", r"\bfail(?:ed|ure)?\b", r"\binvalid\b",
                 r"\bdenied\b", r"\bbad\b", r"\bsorry\b", r"\bno+[.!]*$", r"\brejected\b",
                 r"\bunauthori[sz]ed\b", r"\bnot quite\b", r":\(", r"\blength\b.*\b(?:wrong|bad|invalid)\b"]
SUCCESS_PATTERNS = [r"\bcorrect\b", r"\bcongrat", r"\bsuccess", r"\bwell done\b", r"\bgood job\b",
                    r"\byou (?:win|won|got it|did it)\b", r"\baccess granted\b", r"\bgranted\b",
                    r"\bflag is\b", r"\bhere(?:'s| is) (?:your|the) flag\b", r"\bvalid\b",
                    r"\bright\b", r"\bnice\b", r"\baccepted\b", r"\bunlocked\b", r":\)", r"\bok\b"]
_FAIL_RE = [re.compile(p, re.I) for p in FAIL_PATTERNS]
_SUCC_RE = [re.compile(p, re.I) for p in SUCCESS_PATTERNS]
_FAIL_WEAK = {8, 11}          # bad, no+
_SUCC_WEAK = set(range(10, len(SUCCESS_PATTERNS)))
NORETURN = {"exit", "_exit", "abort", "__stack_chk_fail", "__assert_fail", "err", "errx", "_Exit",
            "quick_exit", "pthread_exit", "__chk_fail", "verr", "verrx"}
HASH_NAMES = ("MD5", "SHA1", "SHA256", "SHA512", "SHA224", "SHA384", "EVP_Digest", "crc32", "CRC32")
ANGR_ABSENT_LINE = ("angr: not installed - symbolic lane skipped "
                    "(pre-CTF prep only, needs network: pip install angr)")
M64 = (1 << 64) - 1

_FIND_SPEC: Callable[[str], Any] = importlib.util.find_spec
_WHICH: Callable[[str], Any] = shutil.which
_CS: Any = disasm.capstone
_ANGR_RUNNER: Callable[..., Any] | None = None   # set after _run_angr_child is defined


# ---------- data model (spec 6)
@dataclass
class Op:
    """One decoded operand."""
    kind: str
    size: int
    reg: str | None = None
    sub: str | None = None
    imm: int | None = None
    base: str | None = None
    index: str | None = None
    scale: int = 1
    disp: int = 0
    seg: str | None = None
    target: int | None = None


@dataclass
class Insn:
    """One decoded instruction."""
    addr: int
    size: int
    raw: bytes
    mnem: str
    cc: str | None
    ops: tuple
    flow: str
    modelled: bool
    clob: tuple = ()          # GPR families an unmodelled instruction may write
    mstore: bool = False      # unmodelled instruction may store to its memory operand


@dataclass
class VerdictRef:
    site: int
    via: str
    func: int | None
    printer: str | None
    conf: str


@dataclass
class Verdict:
    addr: int
    text: str
    polarity: str
    matched: str
    conf: str
    refs: list = field(default_factory=list)
    stack_built: bool = False


@dataclass
class Gate:
    n: int
    addr: int
    kind: str
    cc: str
    cmp_addr: int | None
    func: int
    success_edge: str
    success_to: int | None
    fail_to: int | None
    in_loop: bool
    hits: int
    deciding: bool
    label: str
    conf: str


@dataclass
class Constraint:
    n: int
    kind: str
    text: str
    site: int
    conf: str
    positions: tuple
    expr: Any = None


@dataclass
class Solution:
    candidate: bytes | None
    text: str | None
    conf: str
    method: str
    unknown: list
    ambiguous: list
    verified: str
    trace: list
    flag_match: bool


@dataclass
class Patch:
    site: int
    offset: int
    old: bytes
    new: bytes
    strategy: str
    desc: str
    elfpatch: str
    primary: bool
    conf: str


@dataclass
class AngrResult:
    status: str
    input: bytes | None
    detail: str
    seconds: float
    agrees: bool | None


@dataclass
class Report:
    target: dict
    verdicts: list
    gates: list
    constraints: list
    solution: Solution | None
    patches: list
    listing: list
    input_model: dict
    outcome: str
    next_steps: list
    angr: AngrResult | None
    notes: list
    errors: list


@dataclass
class Options:
    """Analysis options (CLI flags map 1:1)."""
    success_re: list = field(default_factory=list)
    fail_re: list = field(default_factory=list)
    flag_re: re.Pattern | None = None
    func: int | None = None
    deep: bool = False
    as_json: bool = False
    angr: str = "auto"
    angr_timeout: int = ANGR_TIMEOUT
    max_steps: int = MAX_STEPS
    input_mode: str = "auto"


def _stage(report: Report, name: str, fn: Callable[..., Any], *a: Any) -> Any:
    """Run one stage; any Exception becomes ``report.errors`` and yields None."""
    try:
        return fn(*a)
    except (Exception, RecursionError, MemoryError) as exc:  # noqa: BLE001
        report.errors.append(f"{name}: {type(exc).__name__}: {exc}")
        return None


# ---------- x86 decoder (xdec)
_FAM = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"] + [f"r{i}" for i in range(8, 16)]
_R32 = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"] + [f"r{i}d" for i in range(8, 16)]
_R16 = ["ax", "cx", "dx", "bx", "sp", "bp", "si", "di"] + [f"r{i}w" for i in range(8, 16)]
_R8X = ["al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil"] + [f"r{i}b" for i in range(8, 16)]
_R8L = ["al", "cl", "dl", "bl", "ah", "ch", "dh", "bh"]
_CCN = ["o", "no", "b", "ae", "e", "ne", "be", "a", "s", "ns", "p", "np", "l", "ge", "le", "g"]
_ALU = ["add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"]
_SHF = ["rol", "ror", "rcl", "rcr", "shl", "shr", "shl", "sar"]
_PFX = {0xF0, 0xF2, 0xF3, 0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65, 0x66, 0x67}
_SEGN = {0x2E: "cs", 0x36: "ss", 0x3E: "ds", 0x26: "es", 0x64: "fs", 0x65: "gs"}
_INV64 = {0x06, 0x07, 0x0E, 0x16, 0x17, 0x1E, 0x1F, 0x27, 0x2F, 0x37, 0x3F, 0x60, 0x61, 0x82,
          0x9A, 0xCE, 0xD4, 0xD5, 0xD6, 0xEA}
_NOMODRM_0F = {0x05, 0x06, 0x07, 0x08, 0x09, 0x0B, 0x0E, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x37,
               0x77, 0xA0, 0xA1, 0xA2, 0xA8, 0xA9, 0xAA} | set(range(0xC8, 0xD0)) | set(range(0x80, 0x90))
_IMM8_0F = {0x70, 0x71, 0x72, 0x73, 0xA4, 0xAC, 0xBA, 0xC2, 0xC4, 0xC5, 0xC6, 0x0F}
_STORE_0F = {0x11, 0x13, 0x17, 0x29, 0x2B, 0x7F, 0xD6, 0xE7, 0xB0, 0xB1, 0xC0, 0xC1, 0xAB, 0xB3, 0xBB, 0xC3}
_SIZE_NAME = {1: "byte", 2: "word", 4: "dword", 8: "qword", 16: "xmmword"}


def _sx(v: int, bits: int) -> int:
    """Interpret the low ``bits`` of v as signed."""
    v &= (1 << bits) - 1
    return v - (1 << bits) if v >> (bits - 1) else v


def _reg(idx: int, size: int, rex: int) -> Op:
    if size == 1:
        if rex or idx >= 8 or idx < 4:
            return Op("reg", 1, _FAM[idx], _R8X[idx] if (rex or idx >= 8) else _R8L[idx])
        return Op("reg", 1, _FAM[idx - 4], _R8L[idx])
    return Op("reg", size, _FAM[idx], {2: _R16, 4: _R32, 8: _FAM}[size][idx])


def decode(code: bytes, off: int, addr: int, bits: int) -> "Insn | None":
    """Decode one x86 / x86-64 instruction at ``code[off]`` (virtual address ``addr``).

    Returns None when the bytes are invalid or truncated.  Length decoding is
    complete (prefixes, REX, VEX/EVEX, 0F/0F38/0F3A maps, x87); operands are
    decoded for the semantic subset the walker models.
    """
    try:
        return _decode(code, off, addr, bits)
    except (IndexError, struct.error):
        return None


def _decode(code: bytes, off: int, addr: int, bits: int) -> "Insn | None":
    n = len(code)
    pos = off
    opsz16 = addr32 = False
    rep = 0
    seg: str | None = None
    rex = 0
    npfx = 0
    while True:
        b = code[pos]
        if b in _PFX:
            if b == 0x66:
                opsz16 = True
            elif b == 0x67:
                addr32 = True
            elif b in (0xF2, 0xF3):
                rep = b
            elif b in _SEGN:
                seg = _SEGN[b]
            rex = 0
            pos += 1
            npfx += 1
            if npfx > 14:
                return None
            continue
        if bits == 64 and 0x40 <= b <= 0x4F:
            rex = b
            pos += 1
            npfx += 1
            if npfx > 14:
                return None
            continue
        break
    rw, rr, rx, rb = bool(rex & 8), (rex & 4) << 1, (rex & 2) << 2, (rex & 1) << 3
    osz = 8 if rw else (2 if opsz16 else 4)
    op = code[pos]
    pos += 1
    st = {"pos": pos}

    def u8() -> int:
        v = code[st["pos"]]
        st["pos"] += 1
        return v

    def imm(size: int, signed_to: int = 0) -> int:
        p = st["pos"]
        if p + size > n:
            raise IndexError
        v = int.from_bytes(code[p:p + size], "little")
        st["pos"] = p + size
        if signed_to:
            v = _sx(v, size * 8) & ((1 << (signed_to * 8)) - 1)
        return v

    def modrm(size: int, rsize: int | None = None):
        """-> (reg field incl. REX.R, rm Op, mod)."""
        m = u8()
        mod, reg, rm = m >> 6, ((m >> 3) & 7) | rr, m & 7
        if mod == 3:
            return reg, _reg(rm | rb, size, rex), 3
        if bits == 32 and addr32:
            raise IndexError  # 16-bit addressing: treated as invalid
        base = index = None
        scale, disp = 1, 0
        if rm == 4:
            sib = u8()
            scale = 1 << (sib >> 6)
            ix = ((sib >> 3) & 7) | rx
            bs = sib & 7
            if ix != 4:
                index = _FAM[ix]
            if bs == 5 and mod == 0:
                disp = imm(4, 4)
            else:
                base = _FAM[bs | rb]
        elif rm == 5 and mod == 0:
            disp = imm(4, 4)
            base = "rip" if bits == 64 else None
        else:
            base = _FAM[rm | rb]
        if mod == 1:
            disp = imm(1, 8)
        elif mod == 2:
            disp = imm(4, 4)
        d = _sx(disp, 64 if bits == 64 else 32) if disp else 0
        return reg, Op("mem", size, base=base, index=index, scale=scale, disp=d, seg=seg), mod

    mnem, cc, flow, ops, modelled = "other", None, "seq", (), False
    clob: tuple = ()
    mstore = False

    def other_modrm(extra_imm: int = 0, clobber: tuple = (), store: bool = False) -> None:
        nonlocal clob, mstore
        r, rmop, mod = modrm(osz)
        if extra_imm:
            imm(extra_imm)
        res = []
        for c in clobber:
            if c == "*reg":
                res.append(_FAM[r])
            elif c == "*rm" and rmop.kind == "reg":
                res.append(rmop.reg)
            elif not c.startswith("*"):
                res.append(c)
        clob, mstore = tuple(res), store and mod != 3
        st["mem"] = rmop if mod != 3 else None

    mp = 0  # opcode map: 0 one-byte, 1 0F, 2 0F38, 3 0F3A
    vex = False
    if op in (0xC4, 0xC5, 0x62) and (bits == 64 or (code[pos] >> 6) == 3):
        vex = True
        if op == 0xC5:
            u8()
            vmap = 1
        elif op == 0xC4:
            vmap = u8() & 0x1F
            u8()
        else:
            p0 = u8()
            u8()
            u8()
            vmap = p0 & 7
        vop = u8()
        _r, _rm, _mod = modrm(osz)
        if vmap == 3 or (vmap == 1 and vop in (0x70, 0x71, 0x72, 0x73, 0xC2, 0xC4, 0xC5, 0xC6)):
            imm(1)
        mnem = "other"
    elif op == 0x0F:
        op2 = u8()
        mp = 1
        if op2 == 0x38:
            op3 = u8()
            other_modrm(0, ("*reg",) if (rep == 0xF2 and op3 in (0xF0, 0xF1)) else ())
            mp = 2
        elif op2 == 0x3A:
            u8()
            other_modrm(1)
            mp = 3
        elif op2 == 0x05 and bits == 64:
            mnem = "syscall"
            modelled = True
        elif op2 == 0x0B:
            mnem, flow = "ud2", "stop"
        elif op2 == 0x1E and rep == 0xF3 and code[st["pos"]] in (0xFA, 0xFB):
            u8()
            mnem, modelled = "endbr64" if code[st["pos"] - 1] == 0xFA else "endbr32", True
        elif op2 in (0x1E, 0x1F, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x0D):
            _r, _rm, _m = modrm(osz)
            mnem, modelled = "nop", True
        elif 0x80 <= op2 <= 0x8F:
            rel = imm(4, 8)
            rel = _sx(rel, 32)
            tgt = (addr + (st["pos"] - off) + rel) & (M64 if bits == 64 else 0xFFFFFFFF)
            mnem, cc, flow, modelled = "jcc", _CCN[op2 & 15], "jcc", True
            ops = (Op("rel", 4, target=tgt),)
        elif 0x90 <= op2 <= 0x9F:
            _r, rmop, _m = modrm(1)
            mnem, cc, ops, modelled = "setcc", _CCN[op2 & 15], (rmop,), True
        elif 0x40 <= op2 <= 0x4F:
            reg, rmop, _m = modrm(osz)
            mnem, cc, ops, modelled = "cmovcc", _CCN[op2 & 15], (_reg(reg, osz, rex), rmop), True
        elif op2 == 0xAF:
            reg, rmop, _m = modrm(osz)
            mnem, ops, modelled = "imul", (_reg(reg, osz, rex), rmop), True
        elif op2 in (0xB6, 0xB7, 0xBE, 0xBF):
            ssz = 1 if op2 in (0xB6, 0xBE) else 2
            reg, rmop, _m = modrm(ssz)
            mnem = "movzx" if op2 < 0xB8 else "movsx"
            ops, modelled = (_reg(reg, osz, rex), rmop), True
        elif op2 in _NOMODRM_0F:
            if op2 == 0x31:
                clob = ("rax", "rdx")
            elif op2 == 0xA2:
                clob = ("rax", "rbx", "rcx", "rdx")
        elif 0xC8 <= op2 <= 0xCF:
            mnem = "other"   # bswap: length only
        else:
            ck: tuple = ()
            if op2 in (0xD7, 0x50, 0xC5, 0x2C, 0x2D, 0xBC, 0xBD, 0xB8):
                ck = ("*reg",)
            elif op2 in (0x7E, 0xC0, 0xC1, 0xB0, 0xB1):
                ck = ("*rm",)
            other_modrm(1 if op2 in _IMM8_0F else 0, ck, op2 in _STORE_0F)
    else:
        if op in _INV64 and bits == 64:
            return None
        if op < 0x40 and (op & 7) < 6 and op not in (0x0F,):
            mnem = _ALU[op >> 3]
            f = op & 7
            if f < 4:
                sz = 1 if f % 2 == 0 else osz
                reg, rmop, _m = modrm(sz)
                r = _reg(reg, sz, rex)
                ops = (rmop, r) if f < 2 else (r, rmop)
            else:
                sz = 1 if f == 4 else osz
                v = imm(1 if f == 4 else (2 if osz == 2 else 4), sz)
                ops = (_reg(0, sz, rex), Op("imm", sz, imm=v & ((1 << (8 * sz)) - 1)))
            modelled = True
        elif 0x40 <= op <= 0x4F:  # x86 inc/dec
            mnem = "inc" if op < 0x48 else "dec"
            ops, modelled = (_reg(op & 7, osz, 0),), True
        elif 0x50 <= op <= 0x5F:
            ps = 2 if opsz16 else (8 if bits == 64 else 4)
            mnem = "push" if op < 0x58 else "pop"
            ops, modelled = (_reg((op & 7) | rb, ps, rex),), True
        elif op in (0x60, 0x61, 0x06, 0x07, 0x0E, 0x16, 0x17, 0x1E, 0x1F, 0x27, 0x2F, 0x37, 0x3F):
            mnem = "other"   # valid single-byte x86 forms (invalid in 64-bit mode, filtered above)
        elif op == 0x62 or op == 0xC4 or op == 0xC5:  # bound / les / lds (x86, non-VEX)
            other_modrm()
        elif op == 0x63:
            reg, rmop, _m = modrm(4)
            if bits == 64:
                mnem, ops, modelled = "movsxd", (_reg(reg, osz, rex), rmop), True
            else:
                mnem = "other"
        elif op in (0x68, 0x6A):
            ps = 2 if opsz16 else (8 if bits == 64 else 4)
            v = imm(1, ps) if op == 0x6A else imm(2 if opsz16 else 4, ps)
            mnem, ops, modelled = "push", (Op("imm", ps, imm=v),), True
        elif op in (0x69, 0x6B):
            reg, rmop, _m = modrm(osz)
            v = imm(1, osz) if op == 0x6B else imm(2 if osz == 2 else 4, osz)
            mnem, modelled = "imul", True
            ops = (_reg(reg, osz, rex), rmop, Op("imm", osz, imm=v))
        elif 0x6C <= op <= 0x6F:
            mnem = "other"   # ins/outs: length only
        elif 0x70 <= op <= 0x7F:
            rel = _sx(imm(1), 8)
            tgt = (addr + (st["pos"] - off) + rel) & (M64 if bits == 64 else 0xFFFFFFFF)
            mnem, cc, flow, modelled = "jcc", _CCN[op & 15], "jcc", True
            ops = (Op("rel", 1, target=tgt),)
        elif op in (0x80, 0x81, 0x82, 0x83):
            sz = 1 if op in (0x80, 0x82) else osz
            reg, rmop, _m = modrm(sz)
            if op == 0x83:
                v = imm(1, sz)
            elif sz == 1:
                v = imm(1)
            else:
                v = imm(2 if sz == 2 else 4, sz)
            mnem, modelled = _ALU[reg & 7], True
            ops = (rmop, Op("imm", sz, imm=v))
        elif op in (0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B):
            sz = 1 if op % 2 == 0 else osz
            reg, rmop, _m = modrm(sz)
            r = _reg(reg, sz, rex)
            mnem = {0x84: "test", 0x86: "xchg", 0x88: "mov", 0x85: "test", 0x87: "xchg", 0x89: "mov"}.get(op, "mov")
            ops, modelled = ((r, rmop) if op >= 0x8A else (rmop, r)), True
        elif op == 0x8D:
            reg, rmop, mod = modrm(osz)
            if mod == 3:
                return None
            mnem, ops, modelled = "lea", (_reg(reg, osz, rex), rmop), True
        elif op in (0x8C, 0x8E):
            other_modrm()
        elif op == 0x8F:
            _r, rmop, _m = modrm(8 if bits == 64 else 4)
            mnem, ops, modelled = "pop", (rmop,), True
        elif op == 0x90:
            mnem, modelled = "nop", True
        elif 0x91 <= op <= 0x97:
            clob = ("rax", _FAM[(op & 7) | rb])
        elif op == 0x98:
            mnem, modelled = {2: "cbw", 4: "cwde", 8: "cdqe"}[osz], True
        elif op == 0x99:
            mnem, modelled = {2: "cwd", 4: "cdq", 8: "cqo"}[osz], True
        elif op == 0x9A:
            imm(2 if osz == 2 else 4)
            imm(2)
        elif op in (0x9B, 0x9C, 0x9D, 0x9E, 0x9F):
            if op == 0x9F:
                clob = ("rax",)
        elif 0xA0 <= op <= 0xA3:
            asz = (4 if addr32 else 8) if bits == 64 else (2 if addr32 else 4)
            d = imm(asz)
            sz = 1 if op % 2 == 0 else osz
            m = Op("mem", sz, disp=d, seg=seg)
            a = _reg(0, sz, rex)
            mnem, modelled = "mov", True
            ops = (a, m) if op < 0xA2 else (m, a)
        elif op in (0xA4, 0xA5, 0xA6, 0xA7, 0xAC, 0xAD, 0xAE, 0xAF):
            clob = ("rax", "rcx", "rsi", "rdi")
            mstore = True
        elif op in (0xAA, 0xAB):
            sz = 1 if op == 0xAA else osz
            mnem, modelled = "stos", True
            ops = (Op("reg", sz, reg="rax", sub={1: "al", 2: "ax", 4: "eax", 8: "rax"}[sz]),)
            clob = ()
            cc = "rep" if rep else None
        elif op == 0xA8:
            mnem, modelled = "test", True
            ops = (_reg(0, 1, rex), Op("imm", 1, imm=imm(1)))
        elif op == 0xA9:
            mnem, modelled = "test", True
            ops = (_reg(0, osz, rex), Op("imm", osz, imm=imm(2 if osz == 2 else 4, osz)))
        elif 0xB0 <= op <= 0xB7:
            mnem, modelled = "mov", True
            ops = (_reg((op & 7) | rb, 1, rex), Op("imm", 1, imm=imm(1)))
        elif 0xB8 <= op <= 0xBF:
            mnem, modelled = "mov", True
            v = imm(8) if rw else imm(2 if osz == 2 else 4)
            ops = (_reg((op & 7) | rb, osz, rex), Op("imm", osz, imm=v))
        elif op in (0xC0, 0xC1, 0xD0, 0xD1, 0xD2, 0xD3):
            sz = 1 if op % 2 == 0 else osz
            reg, rmop, _m = modrm(sz)
            if op in (0xC0, 0xC1):
                cnt = Op("imm", 1, imm=imm(1))
            elif op in (0xD0, 0xD1):
                cnt = Op("imm", 1, imm=1)
            else:
                cnt = Op("reg", 1, "rcx", "cl")
            mnem, ops, modelled = _SHF[reg & 7], (rmop, cnt), True
        elif op in (0xC2, 0xC3):
            if op == 0xC2:
                imm(2)
            mnem, flow, modelled = "ret", "ret", True
        elif op in (0xC6, 0xC7):
            sz = 1 if op == 0xC6 else osz
            reg, rmop, mod = modrm(sz)
            if reg & 7 == 7 and mod == 3:   # xabort / xbegin
                imm(1 if op == 0xC6 else 4)
            else:
                v = imm(1) if sz == 1 else imm(2 if sz == 2 else 4, sz)
                if (reg & 7) == 0:
                    mnem, ops, modelled = "mov", (rmop, Op("imm", sz, imm=v)), True
        elif op == 0xC8:
            imm(2)
            imm(1)
            mnem, modelled = "enter", True
        elif op == 0xC9:
            mnem, modelled = "leave", True
        elif op in (0xCA, 0xCB):
            if op == 0xCA:
                imm(2)
            flow = "stop"
        elif op == 0xCC:
            mnem, flow = "int3", "stop"
        elif op == 0xCD:
            v = imm(1)
            mnem, ops, modelled = "int", (Op("imm", 1, imm=v),), True
        elif op in (0xCE, 0xCF):
            flow = "stop" if op == 0xCF else "seq"
        elif op in (0xD4, 0xD5):
            imm(1)
        elif 0xD8 <= op <= 0xDF:
            other_modrm()
        elif op in (0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7):
            imm(1)
        elif op in (0xE8, 0xE9):
            rel = _sx(imm(4), 32)
            tgt = (addr + (st["pos"] - off) + rel) & (M64 if bits == 64 else 0xFFFFFFFF)
            mnem, flow, modelled = ("call", "call", True) if op == 0xE8 else ("jmp", "jmp", True)
            ops = (Op("rel", 4, target=tgt),)
        elif op == 0xEA:
            imm(2 if osz == 2 else 4)
            imm(2)
            flow = "stop"
        elif op == 0xEB:
            rel = _sx(imm(1), 8)
            tgt = (addr + (st["pos"] - off) + rel) & (M64 if bits == 64 else 0xFFFFFFFF)
            mnem, flow, modelled = "jmp", "jmp", True
            ops = (Op("rel", 1, target=tgt),)
        elif op == 0xF4:
            mnem, flow = "hlt", "stop"
        elif op in (0xF6, 0xF7):
            sz = 1 if op == 0xF6 else osz
            reg, rmop, _m = modrm(sz)
            g = reg & 7
            if g in (0, 1):
                v = imm(1) if sz == 1 else imm(2 if sz == 2 else 4, sz)
                mnem, ops, modelled = "test", (rmop, Op("imm", sz, imm=v)), True
            elif g in (2, 3):
                mnem, ops, modelled = ("not" if g == 2 else "neg"), (rmop,), True
            else:
                mnem, ops, modelled = ("mul", "imul", "div", "idiv")[g - 4], (rmop,), g in (4, 5)
                if g >= 6:
                    clob, modelled = ("rax", "rdx"), False
        elif op in (0xFE, 0xFF):
            sz = 1 if op == 0xFE else osz
            if op == 0xFF:
                g = (code[st["pos"]] >> 3) & 7
                if g in (2, 4, 6):
                    sz = 8 if bits == 64 else 4
            reg, rmop, _m = modrm(sz)
            g = reg & 7
            if g in (0, 1):
                mnem, ops, modelled = ("inc" if g == 0 else "dec"), (rmop,), True
            elif op == 0xFF and g == 2:
                mnem, flow, ops, modelled = "call", "call-ind", (rmop,), True
            elif op == 0xFF and g == 4:
                mnem, flow, ops, modelled = "jmp", "jmp-ind", (rmop,), True
            elif op == 0xFF and g == 6:
                mnem, ops, modelled = "push", (rmop,), True
            elif op == 0xFF and g in (3, 5):
                flow = "stop" if g == 5 else "seq"
            elif op == 0xFF:
                return None
            else:
                return None
        else:
            pass  # F1, F5, F8-FD, 98.. single-byte leftovers: length 1, unmodelled
    size = st["pos"] - off
    if size > 15:
        return None
    mask = M64 if bits == 64 else 0xFFFFFFFF
    fixed = []
    if not modelled and st.get("mem") is not None:
        ops = (st["mem"],)
    for o in ops:
        if o.kind == "mem" and o.base == "rip":
            o.target = (addr + size + o.disp) & mask
        fixed.append(o)
    return Insn(addr, size, bytes(code[off:off + size]), mnem, cc, tuple(fixed), flow, modelled, clob, mstore)


# ---------- formatter
def _rname(fam: str, size: int) -> str:
    i = _FAM.index(fam) if fam in _FAM else 0
    return {1: _R8X, 2: _R16, 4: _R32, 8: _FAM}.get(size, _FAM)[i]


def _hx(v: int) -> str:
    return f"-{-v:#x}" if v < 0 else f"{v:#x}"


def _fmt_op(o: Op, bits: int, mem_size: bool = True) -> str:
    if o.kind == "reg":
        return o.sub or o.reg or "?"
    if o.kind == "imm":
        return _hx(o.imm or 0)
    if o.kind == "rel":
        return f"{o.target:#x}"
    parts = []
    if o.base:
        parts.append(_rname(o.base, 8 if bits == 64 else 4) if o.base != "rip" else "rip")
    if o.index:
        parts.append(_rname(o.index, 8 if bits == 64 else 4) + (f"*{o.scale}" if o.scale != 1 else ""))
    s = "+".join(parts)
    if o.disp or not parts:
        s += (("+" + _hx(o.disp)) if parts and o.disp > 0 else (_hx(o.disp) if parts else f"{o.disp & M64:#x}"))
    pre = (_SIZE_NAME.get(o.size, "") + " ") if mem_size else ""
    return f"{pre}{o.seg + ':' if o.seg else ''}[{s}]"


def fmt(insn: Insn, bits: int = 64) -> str:
    """Intel-syntax text for modelled instructions; ``db ..`` for the rest."""
    if not insn.modelled:
        return "db " + " ".join(f"{b:02x}" for b in insn.raw[:8]) + ("…" if insn.size > 8 else "") + "  ; unmodelled"
    m = insn.mnem
    if m in ("jcc", "setcc", "cmovcc"):
        m = {"jcc": "j", "setcc": "set", "cmovcc": "cmov"}[m] + (insn.cc or "")
    elif m == "stos" and insn.cc == "rep":
        m = "rep stos"
    txt = ", ".join(_fmt_op(o, bits, m != "lea") for o in insn.ops)
    s = f"{m} {txt}".strip()
    for o in insn.ops:
        if o.kind == "mem" and o.base == "rip" and o.target is not None:
            s += f"  ; {o.target:#x}"
    return s


# ---------- ELF context
@dataclass
class _Sec:
    name: str
    type: int
    flags: int
    addr: int
    off: int
    size: int

    @property
    def alloc(self) -> bool:
        return bool(self.flags & 2)

    @property
    def exec(self) -> bool:
        return bool(self.flags & 4)


@dataclass
class Block:
    """Basic block of a recovered function."""
    start: int
    end: int
    insns: list
    succ: list           # jcc: [fallthrough, taken]; jmp: [target]; seq: [next]
    term: Insn | None = None


class Func:
    """A recovered function: recursive-descent instruction map + basic blocks."""

    def __init__(self, start: int) -> None:
        self.start = start
        self.insns: dict[int, Insn] = {}
        self.blocks: dict[int, Block] = {}
        self.block_of: dict[int, int] = {}
        self.preds: dict[int, list[int]] = {}
        self.calls: list[tuple[int, int | None, str | None]] = []
        self.loops: list[tuple[int, int]] = []
        self.notes: list[str] = []
        self.truncated = False

    def in_loop(self, addr: int) -> bool:
        return any(a <= addr <= b for a, b in self.loops)


class BinCtx:
    """Parsed target + decode caches (not serialised)."""

    def __init__(self, data: bytes, name: str = "<input>") -> None:
        self.data = data
        self.name = name
        self.elf = disasm.parse_elf(data)
        self.bits: int = self.elf["bits"]
        self.arch: str = self.elf["arch"]
        self.x86 = self.arch in ("x86_64", "x86")
        self.pie = self.elf["type"] == 3
        self.sections = self._read_sections()
        self.stripped = not any(s.name == ".symtab" for s in self.sections)
        self.static = not any(sg["type"] == 3 for sg in self.elf["segments"]) and \
            not any(s.name == ".dynamic" for s in self.sections)
        self.syms: dict[int, str] = {}
        self.sym_addr: dict[str, int] = {}
        self.plt: dict[int, str] = {}
        self.got: dict[int, str] = {}
        self.funcs: dict[int, Func] = {}
        self._icache: dict[int, Insn | None] = {}
        self._starts: list[int] | None = None
        self.notes: list[str] = []
        self.rodata_flags: list[tuple[int, bytes]] = []
        self.unref_strings: list[tuple[int, str]] = []
        self.main: int | None = None
        self.exec_secs = [s for s in self.sections if s.alloc and s.exec and s.type != 8]
        self.data_secs = [s for s in self.sections if s.alloc and not s.exec and s.type != 8
                          and s.name not in (".dynstr", ".dynsym", ".interp", ".gnu.version", ".gnu.version_r",
                                             ".rela.dyn", ".rela.plt", ".eh_frame", ".eh_frame_hdr", ".note.gnu.build-id",
                                             ".note.ABI-tag", ".gnu.hash", ".hash", ".dynamic", ".got", ".got.plt")]
        if not self.sections:
            for sg in self.elf["segments"]:
                if sg["type"] == 1 and sg["filesz"]:
                    s = _Sec("LOAD", 1, 6, sg["vaddr"], sg["offset"], sg["filesz"])
                    self.exec_secs.append(s)
                    self.data_secs.append(s)
        if self.x86:
            self._load_symbols()
            self._scan_plt()
            self.main = self._find_main()

    # -- parsing helpers
    def _read_sections(self) -> list:
        d, e = self.data, self.elf
        out = []
        try:
            if self.bits == 64:
                shoff, shent = struct.unpack_from("<Q", d, 0x28)[0], struct.unpack_from("<H", d, 0x3A)[0]
            else:
                shoff, shent = struct.unpack_from("<I", d, 0x20)[0], struct.unpack_from("<H", d, 0x2E)[0]
            for i, s in enumerate(e["sections"]):
                fl = 0
                o = shoff + i * max(shent, 40)
                if o + 12 <= len(d):
                    fl = struct.unpack_from("<Q" if self.bits == 64 else "<I", d, o + 8)[0] \
                        if o + (16 if self.bits == 64 else 12) <= len(d) else 0
                out.append(_Sec(s["name"], s["type"], fl, s["addr"], s["offset"], s["size"]))
        except struct.error:
            return []
        return out

    def _load_symbols(self) -> None:
        try:
            alias: dict[int, list] = {}
            for s in revauto.elf_symbols(self.data):
                if s["type"] in ("FUNC", "IFUNC") and s["value"] and s["shndx"] != 0 and s["name"]:
                    alias.setdefault(s["value"], []).append(s["name"])
                    self.sym_addr.setdefault(s["name"], s["value"])
            for a, names in alias.items():   # prefer the alias libc-call models know (fgets over _IO_fgets)
                self.syms[a] = next((n for n in names if _norm(n) in _LIBFUNCS), names[0])
        except Exception as exc:  # noqa: BLE001
            self.notes.append(f"symbols: {type(exc).__name__}: {exc}")

    def _scan_plt(self) -> None:
        try:
            self.got = {g["got"]: g["symbol"] for g in pwnhelp.got_plt(self.data) if g["symbol"]}
        except Exception as exc:  # noqa: BLE001
            self.notes.append(f"plt: {type(exc).__name__}: {exc}")
            return
        gp = next((s.addr for s in self.sections if s.name == ".got.plt"), 0)
        if self.bits == 64:   # static binaries: IRELATIVE slots -> resolver symbol (e.g. strlen)
            for sec in self.sections:
                if sec.name in (".rela.plt", ".rela.iplt") and sec.size % 24 == 0:
                    for k in range(sec.size // 24):
                        r_off, r_info, addend = struct.unpack_from("<QQq", self.data, sec.off + 24 * k)
                        nm = self.syms.get(addend) if (r_info & 0xFFFFFFFF) == 37 else None
                        if nm:
                            self.got.setdefault(r_off, nm)
        for sec in self.sections:
            if sec.name not in (".plt", ".plt.sec", ".plt.got", ".plt.bnd", ".iplt"):
                continue
            code = self.data[sec.off:sec.off + sec.size]
            stride = 8 if sec.name == ".plt.got" else 16
            for m in re.finditer(rb"\xff\x25(....)|\xff\xa3(....)", code, re.S):
                if self.bits == 64:
                    if m.group(1) is None:
                        continue
                    slot = sec.addr + m.start() + 6 + int.from_bytes(m.group(1), "little", signed=True)
                elif m.group(1) is not None:
                    slot = int.from_bytes(m.group(1), "little")
                else:
                    slot = gp + int.from_bytes(m.group(2), "little", signed=True)
                nm = self.got.get(slot)
                if nm:
                    self.plt[sec.addr + (m.start() // stride) * stride] = nm

    def _find_main(self) -> int | None:
        if "main" in self.sym_addr:
            return self.sym_addr["main"]
        a = self.elf["entry"]
        last = None
        for _ in range(48):
            i = self.insn(a)
            if i is None:
                return None
            if i.mnem == "lea" and i.ops[0].reg == "rdi" and i.ops[1].base == "rip":
                last = i.ops[1].target
            elif i.mnem == "mov" and i.ops[0].kind == "reg" and i.ops[0].reg == "rdi" and i.ops[1].kind == "imm":
                last = i.ops[1].imm
            elif i.mnem == "push" and i.ops[0].kind == "imm" and self.bits == 32:
                last = i.ops[0].imm
            elif i.flow in ("call", "call-ind"):
                nm = _norm(self.call_name(i) or "")
                if nm == "__libc_start_main" or (i.flow == "call-ind" and nm == ""):
                    return last if last and self.in_exec(last) else None
            elif i.flow in ("jmp", "ret", "stop", "jmp-ind"):
                return None
            a += i.size
        return None

    # -- memory / decode access
    def in_exec(self, va: int) -> bool:
        return any(s.addr <= va < s.addr + s.size for s in self.exec_secs)

    def read(self, va: int, n: int = 1) -> bytes | None:
        """File-backed bytes at vaddr (``.bss``-style NOBITS reads as zeros); None when unmapped."""
        o = disasm.vaddr_to_offset(self.elf, va)
        if o is not None and o + n <= len(self.data):
            return self.data[o:o + n]
        for s in self.sections:
            if s.type == 8 and s.alloc and s.addr <= va and va + n <= s.addr + s.size:
                return bytes(n)
        return None

    def insn(self, addr: int) -> Insn | None:
        if addr in self._icache:
            return self._icache[addr]
        o = disasm.vaddr_to_offset(self.elf, addr)
        r = None
        if o is not None:
            r = decode(self.data[o:o + 16], 0, addr, self.bits)
        self._icache[addr] = r
        return r

    def name_of(self, addr: int) -> str | None:
        return self.plt.get(addr) or self.syms.get(addr)

    def call_name(self, i: Insn) -> str | None:
        """Callee name of a call instruction (PLT / symbol / GOT slot), else None."""
        if i.flow == "call" and i.ops and i.ops[0].kind == "rel":
            return self.name_of(i.ops[0].target)
        if i.flow == "call-ind" and i.ops and i.ops[0].kind == "mem" and i.ops[0].target is not None:
            return self.got.get(i.ops[0].target)
        return None

    def sec_name(self, va: int) -> str:
        for s in self.sections:
            if s.addr <= va < s.addr + s.size and s.alloc:
                return s.name
        return ""

    # -- function recovery
    def starts(self) -> list[int]:
        if self._starts is not None:
            return self._starts
        st = set(a for a in self.syms if self.in_exec(a))
        if self.main:
            st.add(self.main)
        if self.in_exec(self.elf["entry"]):
            st.add(self.elf["entry"])
        for s in self.exec_secs:
            code = self.data[s.off:s.off + s.size]
            for m in re.finditer(rb"\xe8(....)", code, re.S):
                t = s.addr + m.start() + 5 + int.from_bytes(m.group(1), "little", signed=True)
                if self.in_exec(t & (M64 if self.bits == 64 else 0xFFFFFFFF)):
                    st.add(t & (M64 if self.bits == 64 else 0xFFFFFFFF))
            for m in re.finditer(rb"\xf3\x0f\x1e[\xfa\xfb]", code):
                if (s.addr + m.start()) % 16 == 0:
                    st.add(s.addr + m.start())
        self._starts = sorted(st)
        return self._starts

    def func(self, start: int) -> Func:
        f = self.funcs.get(start)
        if f is None:
            f = _build_func(self, start)
            self.funcs[start] = f
        return f

    def func_for(self, site: int) -> int | None:
        """Function start whose CFG contains ``site`` (greatest candidate start <= site)."""
        import bisect
        ss = self.starts()
        i = bisect.bisect_right(ss, site)
        tried = 0
        while i > 0 and tried < 8:
            i -= 1
            tried += 1
            if site - ss[i] > MAX_FUNC_BYTES:
                break
            if site in self.func(ss[i]).insns:
                return ss[i]
        self.notes.append(f"[L] no recovered function contains site {site:#x}")
        return None

    def is_internal(self, target: int) -> bool:
        if not self.in_exec(target) or target in self.plt:
            return False
        nm = self.syms.get(target)
        return not (nm and _norm(nm) in _LIBFUNCS)

    def fname(self, addr: int) -> str:
        return self.syms.get(addr) or self.plt.get(addr) or f"sub_{addr:x}"


def _norm(name: str) -> str:
    """Strip PLT/version/``__isoc99_``/``__*_chk`` decorations."""
    n = name.split("@")[0]
    n = re.sub(r"^(?:__isoc\d+_|_IO_|__GI_)", "", n)
    m = re.match(r"^__(.+)_chk$", n)
    if m:
        n = m.group(1)
    if n.startswith("_ZStlsISt11char_traits"):
        return "operator<<"
    return n


_LIBFUNCS = {"strlen", "strcmp", "strncmp", "memcmp", "bcmp", "strcspn", "fgets", "gets", "scanf", "sscanf",
             "read", "write", "fread", "getline", "getchar", "puts", "printf", "fputs", "putchar", "fprintf",
             "exit", "_exit", "abort", "malloc", "calloc", "free", "memcpy", "memmove", "strcpy", "strncpy",
             "strcat", "toupper", "tolower", "atoi", "strtol", "strtoul", "ptrace", "memset", "open", "close",
             "fopen", "fclose", "setvbuf", "sleep", "rand", "srand", "time", "system", "isalpha", "isdigit",
             "isalnum", "__stack_chk_fail", "__libc_start_main", "operator<<", "perror", "fflush", "strchr",
             "strrchr", "strstr", "snprintf", "sprintf", "vprintf", "dprintf", "err", "errx", "__assert_fail",
             "MD5", "SHA1", "SHA256", "SHA512", "crc32", "EVP_DigestInit_ex", "EVP_DigestUpdate"}
_OUTPUT = {"puts", "printf", "fputs", "write", "putchar", "fprintf", "operator<<", "vprintf", "dprintf", "perror"}


def _build_func(ctx: BinCtx, start: int) -> Func:
    f = Func(start)
    work = [start]
    leaders = {start}
    total = 0
    mask = M64 if ctx.bits == 64 else 0xFFFFFFFF
    stops: set[int] = set()
    while work:
        a = work.pop()
        while True:
            if a in f.insns or not ctx.in_exec(a):
                break
            i = ctx.insn(a)
            if i is None:
                f.notes.append(f"decode failed at {a:#x}")
                stops.add(a)
                break
            total += i.size
            if total > MAX_FUNC_BYTES:
                f.truncated = True
                f.notes.append(f"function {start:#x} truncated at {MAX_FUNC_BYTES} bytes")
                return _finish_func(ctx, f, leaders, stops)
            f.insns[a] = i
            nxt = a + i.size
            if i.flow == "jcc":
                t = i.ops[0].target
                leaders.update((t, nxt))
                work.append(t)
                work.append(nxt)
                if t <= a:
                    f.loops.append((t, a))
                break
            if i.flow == "jmp":
                t = i.ops[0].target
                if t in ctx.plt or (t != start and t in ctx.syms and not (start < t < start + 1)):
                    f.calls.append((a, t, ctx.name_of(t)))
                    stops.add(a)
                    break
                leaders.add(t)
                work.append(t)
                if t <= a:
                    f.loops.append((t, a))
                break
            if i.flow in ("jmp-ind", "ret", "stop"):
                break
            if i.flow in ("call", "call-ind"):
                tgt = i.ops[0].target if i.flow == "call" else None
                nm = ctx.call_name(i)
                f.calls.append((a, tgt, nm))
                if nm and _norm(nm) in NORETURN:
                    stops.add(a)
                    break
            a = nxt
    return _finish_func(ctx, f, leaders, stops)


def _finish_func(ctx: BinCtx, f: Func, leaders: set, stops: set) -> Func:
    addrs = sorted(f.insns)
    cur: list[Insn] = []

    def close(nxt_ok: bool) -> None:
        if not cur:
            return
        last = cur[-1]
        end = last.addr + last.size
        if last.addr in stops or last.flow in ("ret", "stop", "jmp-ind"):
            succ: list[int] = []
        elif last.flow == "jcc":
            succ = [end, last.ops[0].target]
        elif last.flow == "jmp":
            succ = [last.ops[0].target]
        else:
            succ = [end] if end in f.insns else []
        b = Block(cur[0].addr, end, list(cur), [s for s in succ if s in f.insns], last)
        f.blocks[b.start] = b
        for x in cur:
            f.block_of[x.addr] = b.start
        cur.clear()

    for a in addrs:
        i = f.insns[a]
        if cur and (a in leaders or cur[-1].addr + cur[-1].size != a):
            close(True)
        cur.append(i)
        if i.flow in ("jcc", "jmp", "jmp-ind", "ret", "stop") or a in stops:
            close(True)
    close(True)
    for s, b in f.blocks.items():
        for t in b.succ:
            f.preds.setdefault(t, []).append(s)
    return f


# ---------- stage 1: verdicts
def _classify(text: str, opts: Options) -> tuple[str, str, str] | None:
    """-> (polarity, matched pattern, conf) or None."""
    for rx in opts.fail_re:
        if rx.search(text):
            return "failure", rx.pattern, "high"
    for rx in opts.success_re:
        if rx.search(text):
            return "success", rx.pattern, "high"
    for i, rx in enumerate(_FAIL_RE):
        if rx.search(text):
            return "failure", FAIL_PATTERNS[i], "low" if i in _FAIL_WEAK else "high"
    for i, rx in enumerate(_SUCC_RE):
        if rx.search(text):
            return "success", SUCCESS_PATTERNS[i], "low" if i in _SUCC_WEAK else "high"
    return None


def _is_flag(text: bytes, opts: Options) -> bool:
    return bool(batch.FLAG_RE.search(text)) or bool(opts.flag_re and opts.flag_re.search(text.decode("latin-1")))


def _data_ranges(ctx: BinCtx) -> list[tuple[int, int, int]]:
    return [(s.addr, s.off, s.size) for s in ctx.data_secs]


_RUN = re.compile(rb"[\x20-\x7e\t\n\r]{2,}(?=\x00)")


def _find_strings(ctx: BinCtx, opts: Options) -> dict[int, tuple]:
    """Candidate verdict strings: addr -> (text, polarity, matched, conf, is_full)."""
    cands: dict[int, tuple] = {}
    for va, off, size in _data_ranges(ctx):
        blob = ctx.data[off:off + size]
        for m in _RUN.finditer(blob):
            raw = m.group()
            if len(raw) > 300:
                continue
            addr = va + m.start()
            text = raw.decode("latin-1")
            if _is_flag(raw, opts):
                ctx.rodata_flags.append((addr, raw))
                continue
            c = _classify(text, opts)
            if c is None:
                ctx.unref_strings.append((addr, text))
                continue
            cands[addr] = (text, c[0], c[1], c[2], True)
            added = 0
            for j in range(1, len(text)):
                if added >= 6:
                    break
                if text[j - 1] in " \n\t:,;.!" and text[j].isalnum():
                    c2 = _classify(text[j:], opts)
                    if c2 and c2[0] == c[0]:
                        cands[addr + j] = (text[j:], c2[0], c2[1], c2[2], False)
                        added += 1
    return cands


def _scan_refs(ctx: BinCtx, cands: dict[int, tuple]) -> dict[int, list[tuple[int, str]]]:
    """target addr -> [(site, via)] over every executable section (decoder-confirmed)."""
    refs: dict[int, list[tuple[int, str]]] = {}
    if not cands:
        return refs
    targets = dict.fromkeys(cands)
    # pointer tables (aligned words in data sections equal to a candidate address)
    ptr_slots: dict[int, int] = {}
    wsz = 8 if ctx.bits == 64 else 4
    for va, off, size in _data_ranges(ctx):
        blob = ctx.data[off:off + size]
        for t in cands:
            pk = t.to_bytes(wsz, "little")
            p = blob.find(pk)
            while p >= 0:
                if (va + p) % wsz == 0:
                    ptr_slots[va + p] = t
                p = blob.find(pk, p + 1)
    allt = dict.fromkeys(list(cands) + list(ptr_slots))
    for s in ctx.exec_secs:
        code = ctx.data[s.off:s.off + s.size]
        base = s.addr
        if ctx.bits == 64:
            for m in re.finditer(rb"[\x40-\x4f]?[\x8b\x8d][\x05\x0d\x15\x1d\x25\x2d\x35\x3d]", code, re.S):
                i = decode(code, m.start(), base + m.start(), 64)
                if i and i.mnem in ("lea", "mov") and len(i.ops) == 2 and i.ops[1].kind == "mem" \
                        and i.ops[1].base == "rip" and i.ops[1].target in allt:
                    t = i.ops[1].target
                    if t in ptr_slots:
                        refs.setdefault(ptr_slots[t], []).append((i.addr, "ptr-table"))
                    else:
                        refs.setdefault(t, []).append((i.addr, "rip-rel"))
        else:
            gp = next((x.addr for x in ctx.sections if x.name in (".got.plt", ".got")), 0)
            for m in re.finditer(rb"\x8d[\x83\x8b\x93\x9b\xa3\xab\xb3\xbb]", code):
                i = decode(code, m.start(), base + m.start(), 32)
                if i and i.mnem == "lea" and i.ops[1].kind == "mem" and i.ops[1].base == "rbx" \
                        and not i.ops[1].index and (gp + i.ops[1].disp) in allt:
                    t = gp + i.ops[1].disp
                    refs.setdefault(ptr_slots.get(t, t), []).append((i.addr, "got-rel"))
        for t in allt:
            pk = (t & 0xFFFFFFFF).to_bytes(4, "little")
            p = code.find(pk)
            while p >= 0:
                for st in range(p - 1, max(-1, p - 9), -1):
                    i = decode(code, st, base + st, ctx.bits)
                    if i and st + i.size == p + 4 and i.mnem in ("mov", "push") and \
                            any(o.kind == "imm" and (o.imm or 0) & 0xFFFFFFFF == (t & 0xFFFFFFFF) for o in i.ops):
                        via = "push-imm32" if i.mnem == "push" else (
                            "esp-store" if i.ops[0].kind == "mem" and i.ops[0].base == "rsp" else "abs-imm32")
                        if i.ops[0].kind == "mem" and i.ops[0].base != "rsp" and via != "push-imm32":
                            break
                        refs.setdefault(ptr_slots.get(t, t), []).append((i.addr, via))
                        break
                p = code.find(pk, p + 1)
    try:
        for site, tgt, _s in disasm.find_xrefs(ctx.data, ctx.elf)["strings"]:
            have = refs.get(tgt, [])
            if tgt in cands and not any(x[0] == site for x in have):
                refs.setdefault(tgt, []).append((site, "byte-scan"))
    except Exception:  # noqa: BLE001
        pass
    return refs


def _printer(ctx: BinCtx, site: int) -> str | None:
    a = site
    for _ in range(9):
        i = ctx.insn(a)
        if i is None:
            return None
        if i.flow in ("call", "call-ind"):
            nm = ctx.call_name(i)
            if nm:
                return _norm(nm) if nm.startswith("_ZStls") else nm.split("@")[0]
            return f"sub_{i.ops[0].target:x}" if i.flow == "call" and i.ops[0].target else "indirect"
        if i.flow in ("jmp", "jmp-ind", "ret", "stop", "jcc"):
            return None
        a += i.size
    return None


def find_verdicts(ctx: BinCtx, opts: Options) -> list:
    """Stage 1: classify strings, find their code references, rank and cap per polarity."""
    ctx.rodata_flags.clear()
    ctx.unref_strings.clear()
    cands = _find_strings(ctx, opts)
    refs = _scan_refs(ctx, cands) if ctx.x86 else {}
    out: list[Verdict] = []
    for addr, (text, pol, matched, conf, full) in cands.items():
        rl = []
        seen = set()
        for site, via in sorted(refs.get(addr, [])):
            if site in seen:
                continue
            seen.add(site)
            pr = _printer(ctx, site)
            rc = "high" if (pr and via in ("rip-rel", "abs-imm32", "push-imm32", "esp-store")) else \
                ("medium" if pr or via in ("rip-rel", "abs-imm32", "push-imm32") else "low")
            rl.append(VerdictRef(site, via, ctx.func_for(site), pr, rc))
        if rl or full:
            out.append(Verdict(addr, text, pol, matched, conf, rl))
    rank = {"high": 0, "medium": 1, "low": 2}
    res: list[Verdict] = []
    for pol in ("success", "failure"):
        vs = sorted((v for v in out if v.polarity == pol),
                    key=lambda v: (not v.refs, rank[v.conf], v.addr))
        res += vs[:MAX_VERDICT_STRINGS]
    return res


# ---------- stage 2: functions, reachability, gates, deciding branch
@dataclass
class Trace:
    """Stage-2 result: analysed functions, success/fail reachability, static gates."""
    funcs: dict = field(default_factory=dict)
    entry: int | None = None
    vfunc: int | None = None
    main: int | None = None
    s_sites: set = field(default_factory=set)
    f_sites: set = field(default_factory=set)
    rs: set = field(default_factory=set)
    rf: set = field(default_factory=set)
    gates: list = field(default_factory=list)
    deleg: dict = field(default_factory=dict)       # caller gate addr -> callee start
    deleg_pred: dict = field(default_factory=dict)  # callee start -> (success values, caller gate addr)
    ret_label: dict = field(default_factory=dict)   # jcc addr -> "return value of f@0x.."
    cmov: dict = field(default_factory=dict)        # cmovcc addr -> "true" | "false" (move happens on success?)
    cmov_sites: set = field(default_factory=set)    # verdict ref sites that a cmovcc chooses between
    notes: list = field(default_factory=list)
    only_side: str = ""


def _reach(ctx: BinCtx, root: int, depth: int = MAX_CALL_DEPTH) -> list:
    order = [root]
    seen = {root}
    frontier = [root]
    for _ in range(depth):
        nxt = []
        for fs in frontier:
            for _site, tgt, _nm in ctx.func(fs).calls:
                if tgt and tgt not in seen and ctx.is_internal(tgt) and len(seen) < MAX_FUNCS:
                    seen.add(tgt)
                    order.append(tgt)
                    nxt.append(tgt)
        frontier = nxt
    return order


def _back_reach(f: Func, seeds: set, barrier: set) -> set:
    """Blocks from which a seed block is reachable without passing through a barrier block."""
    out = set(seeds)
    work = list(seeds)
    while work:
        b = work.pop()
        for p in f.preds.get(b, []):
            if p not in out and p not in barrier:
                out.add(p)
                work.append(p)
    return out


def _flag_setter(blk: Block, upto: int) -> int | None:
    for k in range(upto - 1, max(-1, upto - 9), -1):
        i = blk.insns[k]
        if i.mnem in ("cmp", "test", "and", "or", "xor", "add", "sub", "inc", "dec", "neg", "shl", "shr", "sar") and i.modelled:
            return k
        if i.flow in ("call", "call-ind"):
            return None
    return None


def _ret_call(ctx: BinCtx, blk: Block, setter: int) -> Insn | None:
    """If the flag setter tests rax-family computed by a preceding direct internal call -> that call insn."""
    s = blk.insns[setter]
    if not any(o.kind == "reg" and o.reg == "rax" for o in s.ops):
        return None
    for k in range(setter - 1, -1, -1):
        i = blk.insns[k]
        if i.flow == "call":
            return i if (i.ops[0].target and ctx.is_internal(i.ops[0].target)) else None
        if i.flow == "call-ind":
            return None
        if i.ops and i.ops[0].kind == "reg" and i.ops[0].reg == "rax" and i.mnem not in ("cmp", "test"):
            return None
    return None


def _cc_holds(cc: str, w: int, x: int, y: int) -> bool | None:
    """Truth of condition ``cc`` for ``cmp x, y`` at width w (None for unmodelled conditions)."""
    m = (1 << w) - 1
    x &= m
    y &= m
    sx, sy = _sx(x, w), _sx(y, w)
    r = {"e": x == y, "ne": x != y, "b": x < y, "ae": x >= y, "be": x <= y, "a": x > y,
         "l": sx < sy, "ge": sx >= sy, "le": sx <= sy, "g": sx > sy,
         "s": _sx((x - y) & m, w) < 0, "ns": _sx((x - y) & m, w) >= 0}
    return r.get(cc)


def _delegate_pred(blk: Block, setter: int, jcc: Insn, success_taken: bool) -> dict | None:
    """Success predicate over the callee's return value: {0: bool, 1: bool} (None when not understood)."""
    s = blk.insns[setter]
    if s.mnem == "test" and s.ops[0].kind == "reg" and s.ops[1].kind == "reg" and s.ops[0].reg == s.ops[1].reg:
        pairs = {v: (v, 0) for v in (0, 1)}
    elif s.mnem == "cmp" and s.ops[0].kind == "reg" and s.ops[1].kind == "imm":
        pairs = {v: (v, s.ops[1].imm) for v in (0, 1)}
    else:
        return None
    w = s.ops[0].size * 8
    out = {}
    for v, (x, y) in pairs.items():
        h = _cc_holds(jcc.cc or "", w, x, y)
        if h is None:
            return None
        out[v] = (h == success_taken)
    return out


def _ret_value(blk: Block) -> Any:
    """Block-local constant propagation of eax at a ``ret``: int | ('set', addr, cc) | None."""
    e: Any = None
    for i in blk.insns[:-1]:
        if i.mnem == "xor" and i.ops[0].kind == "reg" and i.ops[1].kind == "reg" and i.ops[0].reg == i.ops[1].reg == "rax":
            e = 0
        elif i.mnem == "mov" and i.ops[0].kind == "reg" and i.ops[0].reg == "rax":
            e = i.ops[1].imm if i.ops[1].kind == "imm" else None
        elif i.mnem == "setcc" and i.ops[0].kind == "reg" and i.ops[0].reg == "rax":
            e = ("set", i.addr, i.cc)
        elif i.mnem in ("movzx", "movsx") and i.ops[0].kind == "reg" and i.ops[0].reg == "rax":
            continue
        elif i.flow in ("call", "call-ind") or (i.ops and i.ops[0].kind == "reg" and i.ops[0].reg == "rax"
                                                 and i.mnem not in ("cmp", "test")):
            e = None
    return e


def _mk_gates(ctx: BinCtx, f: Func, rs: set, rf: set) -> list:
    out = []
    for bs in sorted(f.blocks):
        b = f.blocks[bs]
        t = b.term
        if t is None or t.flow != "jcc" or len(b.succ) != 2:
            continue
        fall, taken = b.succ
        s_t, s_f = taken in rs, fall in rs
        conf = "high"
        if s_t == s_f:
            if not (s_t and s_f) or ((taken in rf) == (fall in rf)):
                continue
            s_t = taken not in rf
            s_f = not s_t
            conf = "medium"
        if t.ops[0].target <= t.addr:
            continue  # loop latch: "loop bound", never a gate in compact mode
        k = _flag_setter(b, len(b.insns) - 1)
        out.append(Gate(0, t.addr, "jcc", t.cc or "", b.insns[k].addr if k is not None else None, f.start,
                        "taken" if s_t else "fallthrough", taken if s_t else fall, fall if s_t else taken,
                        f.in_loop(t.addr), 0, False, "unknown condition", conf))
    return out


def _cmov_gates(f: Func, tr: Trace) -> list:
    """cmovcc gates: a cmov whose two register operands carry a success and a failure verdict pointer."""
    out = []
    for b in f.blocks.values():
        regs: dict[str, int] = {}
        for k, i in enumerate(b.insns):
            if i.addr in tr.s_sites or i.addr in tr.f_sites:
                if i.ops and i.ops[0].kind == "reg":
                    regs[i.ops[0].reg] = i.addr
            elif i.ops and i.ops[0].kind == "reg" and i.mnem in ("mov", "lea", "xor", "pop", "movzx"):
                regs.pop(i.ops[0].reg, None)
            if i.mnem == "cmovcc" and len(i.ops) == 2 and i.ops[0].kind == "reg" and i.ops[1].kind == "reg":
                d, sv = regs.get(i.ops[0].reg), regs.get(i.ops[1].reg)
                if d is not None and sv is not None and (d in tr.s_sites) != (sv in tr.s_sites):
                    edge = "false" if d in tr.s_sites else "true"   # dst already holds success: the move must not happen
                    ks = _flag_setter(b, k)
                    out.append(Gate(0, i.addr, "cmovcc", i.cc or "", b.insns[ks].addr if ks is not None else None,
                                    f.start, edge, None, None, f.in_loop(i.addr), 0, False, "unknown condition", "high"))
                    tr.cmov[i.addr] = edge
                    tr.cmov_sites |= {d, sv}
    return out


def _static_label(ctx: BinCtx, f: Func, g: Gate, tr: Trace) -> str:
    b = f.blocks[f.block_of[g.addr]]
    k = _flag_setter(b, len(b.insns) - 1)
    if k is not None:
        rc = _ret_call(ctx, b, k)
        if rc is not None:
            lab = f"return value of {ctx.fname(rc.ops[0].target)}@{rc.ops[0].target:#x}"
            tr.ret_label[g.addr] = lab
            return lab
        if any(o.size == 1 for o in b.insns[k].ops):
            return "byte compare"
    return "unknown condition"


def trace(ctx: BinCtx, verdicts: list, opts: Options) -> Trace:
    """Stage 2: analysed functions, reachability of the success side, gates, deciding branch."""
    tr = Trace(main=ctx.main)
    if not ctx.x86:
        return tr
    s_refs = [r for v in verdicts if v.polarity == "success" for r in v.refs]
    f_refs = [r for v in verdicts if v.polarity == "failure" for r in v.refs]
    if not s_refs and not f_refs:
        if verdicts:
            tr.notes.append("verdict strings have no code references: nothing to trace")
        return tr
    ffuncs = {r.func for r in f_refs if r.func is not None}
    pool = s_refs or f_refs
    if not s_refs:
        tr.only_side = "failure"
        tr.notes.append("[L] only failure verdicts found: success = any path that avoids them and returns")
    elif not f_refs:
        tr.only_side = "success"
        tr.notes.append("[L] only success verdicts found: failure = any path that does not reach them")
    best = sorted([r for r in pool if r.func is not None],
                  key=lambda r: (r.func not in ffuncs, r.conf != "high", r.site))
    if opts.func is not None:
        vf = ctx.func_for(opts.func)
        if vf is None:
            tr.notes.append(f"--func {opts.func:#x}: no function contains that address")
            return tr
    elif best:
        vf = best[0].func
    else:
        tr.notes.append("verdict references are not inside any recoverable function")
        return tr
    tr.vfunc = vf
    order: list[int] = []
    from_main = opts.func is None and ctx.main is not None and ctx.in_exec(ctx.main)
    if from_main:
        order = _reach(ctx, ctx.main)
    if vf not in order:
        for x in _reach(ctx, vf):
            if x not in order:
                order.append(x)
        from_main = False if vf not in order[:1] and ctx.main not in order else from_main
    order = order[:MAX_FUNCS]
    tr.entry = ctx.main if (from_main and vf in order) else vf
    for fs in order:
        tr.funcs[fs] = ctx.func(fs)
        for n in tr.funcs[fs].notes:
            if n not in tr.notes:
                tr.notes.append(n)
    tr.s_sites = {r.site for r in s_refs if any(r.site in f.insns for f in tr.funcs.values())}
    tr.f_sites = {r.site for r in f_refs if any(r.site in f.insns for f in tr.funcs.values())}
    hasS = {fs: any(s in f.insns for s in tr.s_sites) for fs, f in tr.funcs.items()}
    hasF = {fs: any(s in f.insns for s in tr.f_sites) for fs, f in tr.funcs.items()}
    for _ in range(MAX_CALL_DEPTH + 1):
        for fs, f in tr.funcs.items():
            for _site, tgt, _nm in f.calls:
                if tgt in hasS:
                    hasS[fs] = hasS[fs] or hasS[tgt]
                    hasF[fs] = hasF[fs] or hasF[tgt]
    gates: list[Gate] = []
    sbk: tuple | None = None
    for fs, f in list(tr.funcs.items()):
        sb = {f.block_of[s] for s in tr.s_sites if s in f.insns}
        fb = {f.block_of[s] for s in tr.f_sites if s in f.insns}
        for site, tgt, _nm in f.calls:
            if hasS.get(tgt) and site in f.block_of:
                sb.add(f.block_of[site])
            if hasF.get(tgt) and site in f.block_of:
                fb.add(f.block_of[site])
        if tr.only_side == "failure":
            sb = {bs for bs, b in f.blocks.items() if b.term and b.term.flow == "ret" and bs not in fb}
        both = sb & fb
        rs = _back_reach(f, sb, fb - both)
        rf = _back_reach(f, fb, sb - both)
        tr.rs |= rs
        tr.rf |= rf
        if sb and (fs == vf or sbk is None):
            sbk = (f, min(sb))
        gs = _mk_gates(ctx, f, rs, rf)
        for g in gs:
            g.label = _static_label(ctx, f, g, tr)
        gates += gs + _cmov_gates(f, tr)
    for g in list(gates):   # delegated decisions: the gate tests an internal call's return value
        if g.addr not in tr.ret_label:
            continue
        f = tr.funcs[g.func]
        b = f.blocks[f.block_of[g.addr]]
        k = _flag_setter(b, len(b.insns) - 1)
        rc = _ret_call(ctx, b, k) if k is not None else None
        if rc is None:
            continue
        x = rc.ops[0].target
        pred = _delegate_pred(b, k, b.term, g.success_edge == "taken")
        if pred is None or pred[0] == pred[1] or hasS.get(x):
            continue
        tr.deleg[g.addr] = x
        fx = ctx.func(x)
        tr.funcs.setdefault(x, fx)
        tr.deleg_pred[x] = (pred, g.addr)
        sx, fxb, setg = set(), set(), []
        for bs, bb in fx.blocks.items():
            if bb.term and bb.term.flow == "ret":
                v = _ret_value(bb)
                if isinstance(v, int):
                    ok = pred.get(1 if v else 0, False) if v in (0, 1) else pred[1]
                elif isinstance(v, tuple):
                    ok = True
                    if pred[0] != pred[1]:
                        setg.append((v, bs))
                else:
                    ok = False
                (sx if ok else fxb).add(bs)
        rsx = _back_reach(fx, sx, fxb)
        tr.rs |= rsx
        tr.rf |= _back_reach(fx, fxb, sx)
        for g2 in _mk_gates(ctx, fx, rsx, set()):
            g2.label = _static_label(ctx, fx, g2, tr)
            gates.append(g2)
        for v, _bs in setg:
            gates.append(Gate(0, v[1], "setcc", v[2] or "", None, x, "true" if pred[1] else "false", None, None,
                              fx.in_loop(v[1]), 0, False, f"return value of {ctx.fname(x)}@{x:#x}", "high"))
    order_ix = {fs: i for i, fs in enumerate(tr.funcs)}
    gates.sort(key=lambda g: (order_ix.get(g.func, 99), g.addr))
    for i, g in enumerate(gates, 1):
        g.n = i
    tr.gates = gates
    if sbk and gates:
        f, sblock = sbk
        by = {g.addr: g for g in gates if g.func == f.start and g.kind == "jcc"}
        b, seen, dec = sblock, set(), None
        while b not in seen:
            seen.add(b)
            ps = f.preds.get(b, [])
            if len(ps) == 1:
                t = f.blocks[ps[0]].term
                if t is not None and t.addr in by:
                    dec = by[t.addr]
                    break
                b = ps[0]
            elif len(ps) > 1:
                cands = [g for g in by.values() if g.addr < sblock]
                dec = max(cands, key=lambda g: (g.in_loop, g.addr)) if cands else None
                break
            else:
                break
        if dec is None and by:
            dec = max(by.values(), key=lambda g: g.addr)
        if dec:
            dec.deciding = True
    if not gates:
        tr.notes.append("no deciding branch recovered (no conditional edge separates success from failure)")
    return tr


# ---------- expression algebra (immutable tuples)
_PUSH = {"add", "sub", "xor", "and", "or", "mul", "shl"}
_SYM = {"add": "+", "sub": "-", "xor": "^", "and": "&", "or": "|", "shl": "<<", "shr": ">>", "sar": ">>s", "mul": "*"}
_CCSYM = {"e": "==", "ne": "!=", "b": "<u", "ae": ">=u", "be": "<=u", "a": ">u", "l": "<s", "ge": ">=s",
          "le": "<=s", "g": ">s"}


def _c(v: int, w: int, prov: int | None = None) -> tuple:
    v &= (1 << w) - 1
    return ("c", v, w) if prov is None else ("c", v, w, prov)


def _w(e: tuple) -> int:
    k = e[0]
    if k in ("c", "op", "un"):
        return e[2]
    if k == "in":
        return 8
    if k == "cc":
        return 8
    if k == "scmp":
        return 32
    return 64


def _calc(name: str, w: int, a: int, b: int) -> int:
    m = (1 << w) - 1
    a &= m
    b &= m
    cnt = b & (63 if w == 64 else 31)
    if name == "add":
        return (a + b) & m
    if name == "sub":
        return (a - b) & m
    if name == "xor":
        return a ^ b
    if name == "and":
        return a & b
    if name == "or":
        return a | b
    if name == "mul":
        return (a * b) & m
    if name == "shl":
        return (a << cnt) & m
    if name == "shr":
        return a >> cnt
    if name == "sar":
        return (_sx(a, w) >> cnt) & m
    if name in ("rol", "ror"):
        c = b % w
        if name == "ror":
            c = (w - c) % w
        return ((a << c) | (a >> (w - c))) & m if c else a
    raise ValueError(name)


def _unkof(*es: tuple) -> tuple | None:
    """First unknown operand as a plain ``unk`` expression (canary values are opaque unknowns)."""
    for e in es:
        if e[0] == "unk":
            return e
        if e[0] == "canary":
            return ("unk", "canary")
    return None


def S_un(name: str, w: int, a: tuple) -> tuple:
    """Simplifying unary/width-change constructor (trunc, zx, sx, not, neg)."""
    if a[0] in ("unk", "canary"):
        return _unkof(a)  # type: ignore[return-value]
    if a[0] == "c":
        v, aw = a[1], a[2]
        if name in ("trunc", "zx"):
            return _c(v, w, a[3] if len(a) > 3 and v < (1 << min(w, aw)) else None)
        if name == "sx":
            return _c(_sx(v, aw), w)
        if name == "not":
            return _c(~v, w)
        if name == "neg":
            return _c(-v, w)
    if name in ("trunc", "zx", "sx") and a[0] == "ptr":
        return a
    wa = _w(a)
    if name == "trunc":
        if w == wa:
            return a
        if a[0] == "un" and a[1] in ("zx", "sx"):
            inner = a[3]
            wi = _w(inner)
            if w == wi:
                return inner
            return S_un("trunc", w, inner) if w < wi else S_un(a[1], w, inner)
        if a[0] == "un" and a[1] == "trunc":
            return S_un("trunc", w, a[3])
        if w < wa and a[0] == "un" and a[1] in ("not", "neg"):
            return S_un(a[1], w, S_un("trunc", w, a[3]))
        if w < wa and a[0] == "op" and a[1] in _PUSH:
            return S_op(a[1], w, S_un("trunc", w, a[3]), S_un("trunc", w, a[4]))
        if w > wa:
            return S_un("zx", w, a)
    if name == "zx":
        if w == wa:
            return a
        if a[0] == "un" and a[1] == "zx":
            return ("un", "zx", w, a[3])
    if name == "sx" and w == wa:
        return a
    return ("un", name, w, a)


def _fit(e: tuple, w: int) -> tuple:
    """Width-adjust an expression to w bits (pointers are left alone)."""
    if e[0] == "ptr" or e[0] in ("unk", "canary"):
        return e if e[0] != "canary" else ("unk", "canary")
    cw = _w(e)
    if cw == w:
        return e
    return S_un("trunc" if cw > w else "zx", w, e)


def _ptr_arith(name: str, a: tuple, b: tuple) -> tuple:
    if a[0] == "ptr" and b[0] == "ptr":
        if name == "sub" and a[1] == b[1]:
            return S_op("sub", 64, a[2], b[2])
        return ("unk", "pointer arithmetic")
    if a[0] == "ptr":
        return ("ptr", a[1], S_op(name, 64, a[2], b))
    if name == "add":
        return ("ptr", b[1], S_op("add", 64, b[2], a))
    return ("unk", "pointer arithmetic")


def S_op(name: str, w: int, a: tuple, b: tuple) -> tuple:
    """Simplifying binary constructor (folds constants, identities, add/xor chains, a^a)."""
    if a == b and name in ("xor", "sub") and a[0] != "ptr":
        return _c(0, w)
    if a == b and name in ("and", "or"):
        return a
    u = _unkof(a, b)
    if u:
        return u
    if (a[0] == "ptr" or b[0] == "ptr"):
        if name in ("add", "sub"):
            return _ptr_arith(name, a, b)
        if name == "and" and a[0] == "ptr" and b[0] == "c" and a[2][0] == "c":
            return ("ptr", a[1], _c(a[2][1] & b[1], 64))
        return ("unk", "pointer op " + name)
    if a[0] == "c" and b[0] == "c":
        return _c(_calc(name, w, a[1], b[1]), w)
    if name in ("add", "xor", "and", "or", "mul") and a[0] == "c":
        a, b = b, a
    if b[0] == "c":
        v = b[1]
        full = (1 << w) - 1
        if name in ("add", "sub", "xor", "or", "shl", "shr", "sar", "rol", "ror") and v == 0:
            return a
        if name == "and":
            if v == full:
                return a
            if v == 0:
                return _c(0, w)
            if a[0] == "un" and a[1] == "zx":
                wi = _w(a[3])
                if v & ((1 << wi) - 1) == (1 << wi) - 1 and wi <= w:
                    return a
            if a[0] == "op" and a[1] == "and" and a[4][0] == "c":
                return S_op("and", w, a[3], _c(a[4][1] & v, w))
        if name == "mul":
            if v == 1:
                return a
            if v == 0:
                return _c(0, w)
        if name == "sub":
            return S_op("add", w, a, _c(-v, w))
        if name == "or" and v == full:
            return b
        if a[0] == "op" and a[1] == name and a[4][0] == "c":
            if name == "add":
                return S_op("add", w, a[3], _c(a[4][1] + v, w))
            if name == "xor":
                return S_op("xor", w, a[3], _c(a[4][1] ^ v, w))
            if name == "or":
                return S_op("or", w, a[3], _c(a[4][1] | v, w))
    if a == b and name in ("and", "or"):
        return a
    if name == "or" and a[0] == "c" and a[1] == 0:
        return b
    return ("op", name, w, a, b)


def _neg(e: tuple) -> tuple:
    """Logical negation of a ``cc`` expression."""
    if e[0] == "cc":
        return ("cc", _CCN[_CCN.index(e[1]) ^ 1], e[2], e[3], e[4])
    return ("unk", "negation of non-condition")


def S_cc(cc: str, w: int, a: tuple, b: tuple) -> Any:
    """Condition expression; a Python bool when it folds to a constant."""
    if cc in ("o", "no", "p", "np"):
        return ("unk", f"flag {cc}")
    if a[0] in ("unk", "canary") or b[0] in ("unk", "canary"):
        return _unkof(a, b)
    if a[0] == "ptr" or b[0] == "ptr":
        if a == b:
            return bool(_cc_holds(cc, w, 0, 0))
        other = b if a[0] == "ptr" else a
        if other[0] == "c" and other[1] == 0 and cc in ("e", "ne"):   # tracked pointers are never NULL
            return cc == "ne"
        if a[0] == "ptr" and b[0] == "ptr" and a[1] == b[1] and a[2][0] == "c" and b[2][0] == "c":
            return bool(_cc_holds(cc, 64, a[2][1], b[2][1]))
        return ("unk", "pointer compare")
    if a[0] == "c" and b[0] == "c":
        return bool(_cc_holds(cc, w, a[1], b[1]))
    if a == b:
        return bool(_cc_holds(cc, w, 0, 0))
    return ("cc", cc, w, a, b)


def _ev(e: tuple, env: dict) -> int | None:
    """Evaluate an expression for an env {k: byte, 'len': n}; None when it contains unknowns."""
    k = e[0]
    if k == "c":
        return e[1]
    if k == "in":
        return env.get(e[1])
    if k == "len":
        return env.get("len")
    if k == "op":
        a, b = _ev(e[3], env), _ev(e[4], env)
        return None if a is None or b is None else _calc(e[1], e[2], a, b)
    if k == "un":
        a = _ev(e[3], env)
        if a is None:
            return None
        n, w = e[1], e[2]
        if n in ("trunc", "zx"):
            return a & ((1 << w) - 1)
        if n == "sx":
            return _sx(a, _w(e[3])) & ((1 << w) - 1)
        if n == "not":
            return ~a & ((1 << w) - 1)
        if n == "neg":
            return -a & ((1 << w) - 1)
        if n == "bool":
            return 1 if a else 0
        return None
    if k == "cc":
        a, b = _ev(e[3], env), _ev(e[4], env)
        return None if a is None or b is None else int(bool(_cc_holds(e[1], e[2], a, b)))
    return None


def _free(e: tuple, acc: set | None = None) -> set:
    acc = set() if acc is None else acc
    k = e[0]
    if k == "in":
        acc.add(e[1])
    elif k == "len":
        acc.add("len")
    elif k == "op" or k == "cc":
        _free(e[3], acc)
        _free(e[4], acc)
    elif k == "un":
        _free(e[3], acc)
    elif k == "scmp":
        acc.add("scmp")
    return acc


def _unk_why(e: tuple) -> str | None:
    k = e[0]
    if k == "unk":
        return e[1]
    if k == "canary":
        return "canary"
    if k in ("op", "cc"):
        return _unk_why(e[3]) or _unk_why(e[4])
    if k == "un":
        return _unk_why(e[3])
    return None


def _fe(e: tuple, dec: bool = False, top: bool = True) -> str:
    """Render an expression for constraint text."""
    k = e[0]
    if k == "c":
        if len(e) > 3:
            return f"byte[{e[3]:#x}]"
        return str(e[1]) if (dec and e[1] < 1000) else f"{e[1]:#x}"
    if k == "in":
        return f"IN[{e[1]}]"
    if k == "len":
        return "LEN"
    if k == "un":
        if e[1] in ("zx", "trunc", "sx"):
            return _fe(e[3], dec, top)
        if e[1] == "bool":
            return f"({_fe(e[3], dec, True)})"
        return ("~" if e[1] == "not" else "-") + _fe(e[3], dec, False)
    if k == "op":
        if e[1] in ("rol", "ror"):
            s = f"{_fe(e[3], dec, False)} {e[1]} {_fe(e[4], True, False)}"
        else:
            s = f"{_fe(e[3], dec, False)} {_SYM[e[1]]} {_fe(e[4], dec, False)}"
        return s if top else f"({s})"
    if k == "cc":
        if e[1] in ("s", "ns"):
            return f"({_fe(e[3], dec)} - {_fe(e[4], dec)}) {'<' if e[1] == 's' else '>='}s 0"
        return f"{_fe(e[3], dec)} {_CCSYM[e[1]]} {_fe(e[4], dec)}"
    if k == "scmp":
        return f"strcmp(IN, {e[1][:24]!r})"
    if k == "ptr":
        return f"&{e[1]}"
    return f"?{e[1]}" if len(e) > 1 else "?"


def _strip(e: tuple) -> tuple:
    while e[0] == "un" and e[1] in ("zx", "trunc", "sx"):
        e = e[3]
    return e


def _unwrap(cond: tuple) -> tuple[tuple, int | None]:
    """cc(e/ne, zx(bool C), 0) -> (C or not C, setcc origin)."""
    if cond[0] == "cc" and cond[1] in ("e", "ne") and cond[4][0] == "c" and cond[4][1] == 0:
        a = _strip(cond[3])
        if a[0] == "un" and a[1] == "bool":
            inner = a[3]
            origin = a[4] if len(a) > 4 else None
            if inner[0] == "cc":
                return (inner if cond[1] == "ne" else _neg(inner)), origin
            if inner[0] == "unk":
                return inner, origin
    return cond, None


# ---------- path walker
_ARGREG = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
_CLOBBER = ["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"]


class _St:
    """Abstract machine state of one walker path."""
    __slots__ = ("regs", "mem", "fl", "calls", "rip", "inbuf", "dom", "lend", "conds", "loopc", "zeroheap")

    def copy(self) -> "_St":
        n = _St()
        n.regs, n.mem, n.fl, n.calls, n.rip = dict(self.regs), dict(self.mem), self.fl, list(self.calls), self.rip
        n.inbuf, n.dom, n.lend, n.conds = self.inbuf, dict(self.dom), set(self.lend), list(self.conds)
        n.loopc, n.zeroheap = dict(self.loopc), set(self.zeroheap)
        return n


@dataclass
class WalkResult:
    """Output of the path walker."""
    found: bool = False
    decisions: list = field(default_factory=list)
    input_model: dict = field(default_factory=lambda: {"mode": "unknown", "via": None, "conf": "low"})
    unresolved: list = field(default_factory=list)
    stats: dict = field(default_factory=lambda: {"steps": 0, "paths": 1, "pruned": 0})
    notes: list = field(default_factory=list)
    dom: dict = field(default_factory=dict)
    lend: set = field(default_factory=set)
    fail_at: int | None = None
    s_hit: int | None = None
    prune_reasons: list = field(default_factory=list)
    flags: set = field(default_factory=set)
    forked: bool = False
    inbuf: tuple | None = None
    constraints: list = field(default_factory=list)
    arg0: bool = False
    tr: Any = None
    gates: list = field(default_factory=list)
    patches: list = field(default_factory=list)
    verdict_list: list = field(default_factory=list)


class Walker:
    """Directed abstract interpreter: concrete everywhere except the input bytes and length."""

    def __init__(self, ctx: BinCtx, tr: Trace, opts: Options, concrete: bytes | None = None,
                 mode: str | None = None, descend: bool = True) -> None:
        self.ctx, self.tr, self.opts = ctx, tr, opts
        self.concrete, self.cmode = concrete, mode
        self.descend = descend
        self.wsz = ctx.bits // 8
        self.res = WalkResult()
        self.steps = 0
        self.t0 = time.time()
        self.noted: set = set()

    # -- helpers
    def note(self, key: Any, text: str) -> None:
        if key not in self.noted:
            self.noted.add(key)
            self.res.notes.append(text)

    def inbyte(self, k: int, term: bytes = b"\n") -> tuple:
        if self.concrete is not None:
            buf = self.concrete + term
            return _c(buf[k] if k < len(buf) else 0, 8)
        return ("in", k)

    def init_state(self) -> _St:
        st = _St()
        st.regs = {f: ("unk", f"entry {f}") for f in _FAM}
        st.regs["rsp"] = ("ptr", "stack", _c(0, 64))
        st.regs["rbp"] = ("ptr", "stack", _c(0x2000, 64))
        st.mem, st.fl, st.calls, st.rip = {}, None, [], self.tr.entry
        st.inbuf, st.dom, st.lend, st.conds, st.loopc, st.zeroheap = None, {}, set(range(MAX_SYM_LEN + 1)), [], {}, set()
        if self.concrete is not None:
            st.lend = {len(self.concrete)}
        argv_ok = self.opts.input_mode != "stdin"
        if self.tr.entry == self.tr.main:
            if self.ctx.bits == 64:
                st.regs["rdi"] = _c(2, 64)
                if argv_ok:
                    st.regs["rsi"] = ("ptr", "argvarr", _c(0, 64))
            else:
                self.write(st, ("mem", "stack", 4), _c(2, 32), 4)
                if argv_ok:
                    self.write(st, ("mem", "stack", 8), ("ptr", "argvarr", _c(0, 64)), 4)
        elif self.ctx.bits == 64:
            for i, r in enumerate(_ARGREG):
                st.regs[r] = ("ptr", f"arg{i}", _c(0, 64))
        return st

    # -- memory
    def loc(self, st: _St, o: Op) -> tuple | None:
        if o.seg in ("fs", "gs"):
            return ("canary",)
        if o.base == "rip":
            a = _c(o.target or 0, 64)
        else:
            a = _c(o.disp, 64)
            if o.base:
                a = S_op("add", 64, st.regs[o.base], a)
            if o.index:
                a = S_op("add", 64, a, S_op("mul", 64, st.regs[o.index], _c(o.scale, 64)))
        return self.loc_of(a)

    def loc_of(self, a: tuple) -> tuple | None:
        if a[0] == "c":
            return ("img", a[1] & (M64 if self.ctx.bits == 64 else 0xFFFFFFFF))
        if a[0] == "ptr":
            off = a[2]
            if off[0] == "c":
                return ("mem", a[1], _sx(off[1], 64))
            return ("sym", a[1], off)
        return None

    def rbyte(self, st: _St, reg: str, a: int) -> tuple:
        ent = st.mem.get((reg, a))
        if ent is not None:
            v, n, j = ent
            if n == 1:
                return v
            if v[0] == "c":
                return _c((v[1] >> (8 * j)) & 0xFF, 8)
            return S_un("trunc", 8, S_op("shr", n * 8, _fit(v, n * 8), _c(8 * j, n * 8)))
        if reg == "image":
            b = self.ctx.read(a, 1)
            return ("unk", "unmapped read") if b is None else _c(b[0], 8, a)
        if reg == "input" or reg == "arg0":
            if 0 <= a < MAX_SYM_LEN:
                if reg == "arg0":
                    self.res.arg0 = True
                return self.inbyte(a, b"\0")
            return ("unk", "input beyond tracked length")
        if reg.startswith("heap") and reg in st.zeroheap:
            return _c(0, 8)
        return ("unk", "uninitialised " + reg)

    def read(self, st: _St, l: tuple, size: int) -> tuple:
        if l[0] == "canary":
            return ("canary",)
        if l[0] == "sym":
            return ("unk", "symbolic-offset load")
        reg, off = ("image", l[1]) if l[0] == "img" else (l[1], l[2])
        if reg == "argvarr":
            if size == self.wsz and off == self.wsz:
                self.res.input_model.update(mode="argv", via="argv[1]", conf="high")
                return ("ptr", "input", _c(0, 64))
            return ("unk", "argv slot")
        ent = st.mem.get((reg, off))
        if ent is not None and ent[1] == size and ent[2] == 0 and size > 1:
            if all((m := st.mem.get((reg, off + j))) is not None and m[0] is ent[0] and m[2] == j
                   for j in range(1, size)):
                return ent[0]
        bs = [self.rbyte(st, reg, off + j) for j in range(size)]
        if size == 1:
            return bs[0]
        w = size * 8
        acc = S_un("zx", w, bs[0])
        for j in range(1, size):
            acc = S_op("or", w, acc, S_op("shl", w, S_un("zx", w, bs[j]), _c(8 * j, w)))
        return acc

    def write(self, st: _St, l: tuple | None, val: tuple, size: int) -> None:
        if l is None or l[0] == "canary":
            return
        if l[0] == "sym":
            ib = st.inbuf
            if ib and l[1] == ib[0] and val[0] == "c" and val[1] == 0 and l[2][0] == "op" and l[2][1] == "add" \
                    and l[2][3] == ("len",) and l[2][4][0] == "c" and l[2][4][1] in ((ib[1]) & M64, (ib[1] - 1) & M64):
                self.note("nl", "newline-strip idiom @" + hex(st.rip))
                return
            self.note(("symw", st.rip), f"store through symbolic pointer ignored @{st.rip:#x}")
            return
        reg, off = ("image", l[1]) if l[0] == "img" else (l[1], l[2])
        v = _fit(val, size * 8) if val[0] != "ptr" else val
        for j in range(size):
            st.mem[(reg, off + j)] = (v, size, j)

    def eaexpr(self, st: _St, o: Op) -> tuple:
        if o.base == "rip":
            return _c(o.target or 0, 64)
        a = _c(o.disp, 64)
        if o.base:
            a = S_op("add", 64, st.regs[o.base], a)
        if o.index:
            a = S_op("add", 64, a, S_op("mul", 64, st.regs[o.index], _c(o.scale, 64)))
        return a

    # -- registers / operands
    def getreg(self, st: _St, o: Op) -> tuple:
        v = st.regs[o.reg]
        if o.size == 8:
            return v
        if o.size == 1 and o.sub in ("ah", "ch", "dh", "bh"):
            return S_un("trunc", 8, S_op("shr", 64, _fit(v, 64), _c(8, 64)))
        return _fit(v, o.size * 8)

    def rd(self, st: _St, o: Op) -> tuple:
        if o.kind == "reg":
            return self.getreg(st, o)
        if o.kind == "imm":
            return _c(o.imm or 0, o.size * 8)
        l = self.loc(st, o)
        if l is None:
            return ("unk", "load through unknown pointer")
        return self.read(st, l, o.size)

    def wr(self, st: _St, o: Op, val: tuple) -> None:
        if o.kind == "mem":
            self.write(st, self.loc(st, o), val, o.size)
            return
        fam, v = o.reg, val
        if o.size == 8:
            st.regs[fam] = _fit(v, 64)
        elif o.size == 4:
            st.regs[fam] = v if v[0] == "ptr" else S_un("zx", 64, _fit(v, 32))
        else:
            old = _fit(st.regs[fam], 64)
            if old[0] in ("unk", "canary") and v[0] == "un" and v[1] == "bool":
                st.regs[fam] = S_un("zx", 64, v)
                return
            if o.size == 1 and o.sub in ("ah", "ch", "dh", "bh"):
                keep = S_op("and", 64, old, _c(~0xFF00, 64))
                st.regs[fam] = S_op("or", 64, keep, S_op("shl", 64, S_un("zx", 64, _fit(v, 8)), _c(8, 64)))
            else:
                m = 0xFF if o.size == 1 else 0xFFFF
                st.regs[fam] = S_op("or", 64, S_op("and", 64, old, _c(~m, 64)), S_un("zx", 64, _fit(v, o.size * 8)))

    def push(self, st: _St, val: tuple, size: int) -> None:
        st.regs["rsp"] = S_op("sub", 64, st.regs["rsp"], _c(size, 64))
        self.write(st, self.loc_of(st.regs["rsp"]), val, size)

    def pop(self, st: _St, size: int) -> tuple:
        v = self.read(st, self.loc_of(st.regs["rsp"]) or ("sym", "?", _c(0, 64)), size)
        st.regs["rsp"] = S_op("add", 64, st.regs["rsp"], _c(size, 64))
        return v

    def cond(self, st: _St, cc: str) -> Any:
        fl = st.fl
        if fl is None:
            return ("unk", "flags")
        if fl[0] == "unk":
            return fl
        a, b, w, lim = fl
        if lim and cc not in ("e", "ne", "s", "ns"):
            return ("unk", "flags after arithmetic")
        return S_cc(cc, w, a, b)

    # -- libcall models
    def arg(self, st: _St, i: int) -> tuple:
        if self.ctx.bits == 64:
            return st.regs[_ARGREG[i]] if i < 6 else ("unk", "stack argument")
        rsp = st.regs["rsp"]
        if rsp[0] == "ptr" and rsp[2][0] == "c":
            return self.read(st, ("mem", rsp[1], _sx(rsp[2][1], 64) + 4 * i), 4)
        return ("unk", "argument")

    def inputptr(self, st: _St, p: tuple) -> int | None:
        """Offset of p from the input base when p points into the input buffer."""
        if p[0] != "ptr" or p[2][0] != "c":
            return None
        off = _sx(p[2][1], 64)
        ib = st.inbuf
        if ib and p[1] == ib[0] and 0 <= off - ib[1] < ib[2]:
            return off - ib[1]
        if p[1] == "input" and 0 <= off < MAX_SYM_LEN:
            return off
        if p[1] == "arg0" and 0 <= off < MAX_SYM_LEN:
            self.res.arg0 = True
            return off
        return None

    def cbytes(self, st: _St, p: tuple, n: int | None) -> bytes | None:
        """Concrete bytes at p: a C string (n None) or exactly n bytes; None when any byte is symbolic."""
        l = self.loc_of(p) if p[0] in ("c", "ptr") else None
        if l is None or l[0] == "sym":
            return None
        out = b""
        lim = n if n is not None else 4096
        for j in range(lim):
            l2 = ("img", l[1] + j) if l[0] == "img" else ("mem", l[1], l[2] + j)
            b = self.read(st, l2, 1)
            if b[0] != "c":
                return None
            if n is None and b[1] == 0:
                return out
            out += bytes([b[1]])
        return out if n is not None else None

    def fill_input(self, st: _St, p: tuple, cap: int, via: str, mode: str, term: bytes) -> None:
        l = self.loc_of(p)
        if l is None or l[0] != "mem":
            self.res.unresolved.append(f"input buffer of {via} is not a tracked pointer")
            return
        n = min(cap, MAX_SYM_LEN) if self.concrete is None else cap
        for k in range(n):
            st.mem[(l[1], l[2] + k)] = (self.inbyte(k, term), 1, 0)
        st.inbuf = (l[1], l[2], n)
        im = self.res.input_model
        if im["mode"] in ("unknown", "arg0"):
            self.res.input_model = {"mode": mode, "via": via, "conf": "high",
                                    "buf": f"{l[1]}{l[2]:+#x}".replace("+-", "-"), "cap": cap}

    def libcall(self, st: _St, name: str, site: int, i: Insn) -> str | None:
        nm = _norm(name)
        r = st.regs
        ret: tuple = ("unk", f"call {nm}")
        if nm in NORETURN:
            return "noreturn call to " + nm
        if nm == "fgets":
            n = self.arg(st, 1)
            if n[0] == "c":
                self.fill_input(st, self.arg(st, 0), max(n[1] - 1, 0), f"fgets@{site:#x}", "stdin", b"\n")
                ret = self.arg(st, 0)
        elif nm == "gets":
            self.fill_input(st, self.arg(st, 0), 64, f"gets@{site:#x}", "stdin", b"\0")
            ret = self.arg(st, 0)
        elif nm in ("scanf", "sscanf"):
            fmt = self.cbytes(st, self.arg(st, 0), None) if nm == "scanf" else None
            if nm == "scanf" and fmt is not None and b"s" in fmt:
                m = re.search(rb"%(\d+)s", fmt)
                self.fill_input(st, self.arg(st, 1), int(m.group(1)) if m else 64, f"scanf@{site:#x}", "stdin", b"\0")
                ret = _c(1, 32)
        elif nm == "read":
            fd, n = self.arg(st, 0), self.arg(st, 2)
            if fd[0] == "c" and fd[1] == 0 and n[0] == "c":
                self.fill_input(st, self.arg(st, 1), n[1], f"read@{site:#x}", "stdin", b"\n")
                ret = ("len",) if self.concrete is None else _c(len(self.concrete), 64)
        elif nm == "fread":
            n, c = self.arg(st, 1), self.arg(st, 2)
            if n[0] == "c" and c[0] == "c":
                self.fill_input(st, self.arg(st, 0), n[1] * c[1], f"fread@{site:#x}", "stdin", b"\n")
        elif nm == "getline":
            self.res.unresolved.append("getline: heap buffer not modelled")
        elif nm == "strlen":
            p = self.arg(st, 0)
            k = self.inputptr(st, p)
            s = self.cbytes(st, p, None)
            if k is not None:
                ret = S_op("sub", 64, self.lenexpr(), _c(k, 64))
            elif s is not None:
                ret = _c(len(s), 64)
        elif nm == "strcspn":
            p, rej = self.arg(st, 0), self.cbytes(st, self.arg(st, 1), None)
            k = self.inputptr(st, p)
            s = self.cbytes(st, p, None)
            if s is not None and rej is not None:
                ret = _c(next((j for j, ch in enumerate(s) if ch in rej), len(s)), 64)
            elif k is not None and rej is not None and set(rej) <= {10, 13}:
                ret = S_op("sub", 64, self.lenexpr(), _c(k, 64))
        elif nm in ("strcmp", "strncmp", "memcmp", "bcmp"):
            ret = self.do_cmp(st, nm, self.arg(st, 0), self.arg(st, 1), self.arg(st, 2) if nm != "strcmp" else None)
        elif nm in ("memcpy", "memmove", "strcpy", "strncpy"):
            self.do_copy(st, nm, self.arg(st, 0), self.arg(st, 1), self.arg(st, 2) if nm != "strcpy" else None)
            ret = self.arg(st, 0)
        elif nm in ("malloc", "calloc"):
            reg = f"heap{len(st.zeroheap) + len([1 for k in st.regs if k.startswith('heap')])}{site:x}"
            if nm == "calloc":
                st.zeroheap.add(reg)
            ret = ("ptr", reg, _c(0, 64))
        elif nm in ("atoi", "strtol", "strtoul", "atol"):
            ret = ("unk", "numeric parse")
            self.res.flags.add("numeric")
        elif nm == "ptrace":
            ret = _c(0, 64)
            self.res.flags.add("ptrace")
            self.note("ptrace", f"ptrace import called @{site:#x}: assumed not traced (returns 0)")
        elif any(nm.startswith(h) for h in HASH_NAMES):
            ret = ("unk", f"hash {nm}")
            self.res.flags.add("hash:" + nm)
        elif nm in _OUTPUT:
            ret = ("unk", "output")
        if self.ctx.bits == 64:
            for rg in _CLOBBER:
                r[rg] = ("unk", f"call {nm}")
        else:
            for rg in ("rax", "rcx", "rdx"):
                r[rg] = ("unk", f"call {nm}")
        r["rax"] = ret
        return None

    def lenexpr(self) -> tuple:
        if self.concrete is None:
            self.res.flags.add("len-used")
        return ("len",) if self.concrete is None else _c(len(self.concrete), 64)

    def do_cmp(self, st: _St, nm: str, a: tuple, b: tuple, n: tuple | None) -> tuple:
        kind = {"strcmp": "str", "strncmp": "strn", "memcmp": "mem", "bcmp": "mem"}[nm]
        if n is not None and n[0] != "c":
            return ("unk", nm + " with symbolic length")
        nn = n[1] if n is not None else None
        sa, sb = self.cbytes(st, a, nn if kind == "mem" else None), self.cbytes(st, b, nn if kind == "mem" else None)
        if sa is not None and sb is not None:
            if kind == "strn":
                sa, sb = sa[:nn], sb[:nn]
            return _c((sa > sb) - (sa < sb), 32)
        ia, ib = self.inputptr(st, a), self.inputptr(st, b)
        if ia is not None and sb is not None:
            return ("scmp", sb[:nn] if kind == "strn" else sb, nn, kind, ia)
        if ib is not None and sa is not None:
            return ("scmp", sa[:nn] if kind == "strn" else sa, nn, kind, ib)
        return ("unk", nm + " operands not both resolvable")

    def do_copy(self, st: _St, nm: str, dst: tuple, src: tuple, n: tuple | None) -> None:
        ld, ls = self.loc_of(dst), self.loc_of(src)
        if ld is None or ls is None or ld[0] != "mem":
            return
        cnt = n[1] if n is not None and n[0] == "c" else None
        if cnt is None:
            s = self.cbytes(st, src, None)
            cnt = len(s) + 1 if s is not None else (st.inbuf[2] if st.inbuf and self.inputptr(st, src) is not None else None)
        if cnt is None:
            self.res.unresolved.append(f"{nm} with unknown length not modelled")
            return
        for j in range(min(cnt, 4096)):
            l2 = ("img", ls[1] + j) if ls[0] == "img" else ("mem", ls[1], ls[2] + j)
            st.mem[(ld[1], ld[2] + j)] = (self.read(st, l2, 1), 1, 0)

    # -- one instruction
    def other_name(self, i: Insn) -> str:
        r = i.raw
        if b"\x0f\x38\xf0" in r or b"\x0f\x38\xf1" in r:
            return "crc32"
        return "unmodelled " + r.hex()

    def exec_one(self, st: _St, i: Insn, stack: list) -> str | None:
        """Execute ``i`` on ``st``; returns an end reason, 'found', or None to continue."""
        m, ops = i.mnem, i.ops
        nxt = i.addr + i.size
        st.rip = nxt
        if not i.modelled:
            why = f"{self.other_name(i)} @{i.addr:#x}"
            if i.flow == "stop":
                return "stop instruction"
            for fam in i.clob:
                st.regs[fam] = ("unk", why)
            if i.mstore and ops and ops[0].kind == "mem":
                l = self.loc(st, ops[0])
                if l and l[0] in ("mem", "img"):
                    reg, off = ("image", l[1]) if l[0] == "img" else (l[1], l[2])
                    for j in range(16):
                        st.mem[(reg, off + j)] = (("unk", why), 1, 0)
            st.fl = ("unk", why)
            self.note(("um", i.addr), f"unmodelled {i.raw.hex()} @{i.addr:#x}" + (" (crc32)" if "crc32" in why else ""))
            return None
        if m in ("nop", "endbr64", "endbr32"):
            return None
        if m == "mov":
            self.wr(st, ops[0], self.rd(st, ops[1]))
        elif m in ("movzx", "movsx", "movsxd"):
            self.wr(st, ops[0], S_un("zx" if m == "movzx" else "sx", ops[0].size * 8, self.rd(st, ops[1])))
        elif m == "lea":
            self.wr(st, ops[0], _fit(self.eaexpr(st, ops[1]), ops[0].size * 8))
        elif m == "xchg":
            a, b = self.rd(st, ops[0]), self.rd(st, ops[1])
            self.wr(st, ops[0], b)
            self.wr(st, ops[1], a)
        elif m in ("add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"):
            w = ops[0].size * 8
            a, b = self.rd(st, ops[0]), self.rd(st, ops[1])
            if m == "cmp":
                st.fl = (a, b, w, False)
                return None
            if m in ("adc", "sbb"):
                res, st.fl = ("unk", "carry flag"), ("unk", "carry flag")
            else:
                res = S_op(m, w, a, b)
                st.fl = (a, b, w, False) if m == "sub" else (res, _c(0, w), w, m == "add")
            self.wr(st, ops[0], res)
        elif m == "test":
            w = ops[0].size * 8
            st.fl = (S_op("and", w, self.rd(st, ops[0]), self.rd(st, ops[1])), _c(0, w), w, False)
        elif m in ("inc", "dec", "neg", "not"):
            w = ops[0].size * 8
            a = self.rd(st, ops[0])
            res = {"inc": lambda: S_op("add", w, a, _c(1, w)), "dec": lambda: S_op("sub", w, a, _c(1, w)),
                   "neg": lambda: S_un("neg", w, a), "not": lambda: S_un("not", w, a)}[m]()
            if m != "not":
                st.fl = (res, _c(0, w), w, True)
            self.wr(st, ops[0], res)
        elif m == "imul" and len(ops) >= 2:
            w = ops[0].size * 8
            a = self.rd(st, ops[1])
            b = self.rd(st, ops[2]) if len(ops) == 3 else self.rd(st, ops[0])
            self.wr(st, ops[0], S_op("mul", w, a, b))
            st.fl = ("unk", "imul flags")
        elif m in ("mul", "imul"):
            w = ops[0].size * 8
            st.regs["rax"] = S_un("zx", 64, S_op("mul", w, _fit(st.regs["rax"], w), self.rd(st, ops[0])))
            st.regs["rdx"] = ("unk", "high product")
            st.fl = ("unk", "mul flags")
        elif m in ("shl", "shr", "sar", "rol", "ror"):
            w = ops[0].size * 8
            cnt = self.rd(st, ops[1])
            cnt = S_un("zx", w, cnt) if w > 8 else cnt
            res = S_op(m, w, self.rd(st, ops[0]), cnt)
            st.fl = (res, _c(0, w), w, True) if m in ("shl", "shr", "sar") else st.fl
            self.wr(st, ops[0], res)
        elif m in ("rcl", "rcr"):
            self.wr(st, ops[0], ("unk", m))
        elif m == "cwde" or m == "cbw" or m == "cdqe":
            w = {"cbw": 16, "cwde": 32, "cdqe": 64}[m]
            src = _fit(st.regs["rax"], w // 2)
            v = S_un("sx", w, src)
            st.regs["rax"] = S_un("zx", 64, v) if w < 64 else v
        elif m in ("cwd", "cdq", "cqo"):
            w = {"cwd": 16, "cdq": 32, "cqo": 64}[m]
            st.regs["rdx"] = S_un("zx", 64, S_op("sar", w, _fit(st.regs["rax"], w), _c(w - 1, w)))
        elif m == "push":
            self.push(st, self.rd(st, ops[0]), ops[0].size)
        elif m == "pop":
            v = self.pop(st, ops[0].size)
            self.wr(st, ops[0], v)
        elif m == "leave":
            st.regs["rsp"] = st.regs["rbp"]
            st.regs["rbp"] = self.pop(st, self.wsz)
        elif m == "enter":
            self.push(st, st.regs["rbp"], self.wsz)
            st.regs["rbp"] = st.regs["rsp"]
        elif m == "setcc":
            c = self.cond(st, i.cc or "")
            if isinstance(c, bool):
                v = _c(int(c), 8)
            else:
                v = ("un", "bool", 8, c, i.addr)
            self.wr(st, ops[0], v)
        elif m == "cmovcc":
            c = self.cond(st, i.cc or "")
            if i.addr in self.tr.cmov:
                return self.cmov_decide(st, i, c, self.tr.cmov[i.addr])
            if c is True:
                self.wr(st, ops[0], self.rd(st, ops[1]))
            elif c is not False:
                self.wr(st, ops[0], ("unk", f"cmov @{i.addr:#x}"))
        elif m == "stos":
            w = ops[0].size
            cnt = _c(1, 64)
            if i.cc == "rep":
                cnt = st.regs["rcx"]
            if cnt[0] == "c" and st.regs["rdi"][0] == "ptr":
                for _ in range(min(cnt[1], 4096)):
                    self.write(st, self.loc_of(st.regs["rdi"]), self.rd(st, ops[0]), w)
                    st.regs["rdi"] = S_op("add", 64, st.regs["rdi"], _c(w, 64))
                if i.cc == "rep":
                    st.regs["rcx"] = _c(0, 64)
            else:
                st.regs["rdi"] = ("unk", "rep stos")
        elif m == "syscall" or m == "int":
            return self.syscall(st, i)
        elif m == "ud2" or i.flow == "stop":
            return "stop instruction"
        elif i.flow == "jmp":
            return self.branch(st, i.ops[0].target, i.addr)
        elif i.flow == "jmp-ind":
            return "indirect jump (not modelled)"
        elif i.flow == "call" or i.flow == "call-ind":
            return self.do_call(st, i)
        elif i.flow == "ret":
            if not st.calls:
                return "return from the entry function"
            st.rip = st.calls.pop()
            st.regs["rsp"] = S_op("add", 64, st.regs["rsp"], _c(self.wsz, 64))
        elif i.flow == "jcc":
            return self.jcc(st, i, stack)
        else:
            st.fl = ("unk", f"unmodelled {m}")
            self.note(("um", i.addr), f"unmodelled {m} @{i.addr:#x}")
        return None

    def branch(self, st: _St, tgt: int, frm: int) -> str | None:
        st.rip = tgt
        if tgt <= frm:
            n = st.loopc.get(frm, 0) + 1
            st.loopc[frm] = n
            if n > MAX_LOOP_ITERS:
                return "loop budget"
        return None

    def do_call(self, st: _St, i: Insn) -> str | None:
        nm = self.ctx.call_name(i)
        tgt = i.ops[0].target if i.flow == "call" else None
        if nm and (_norm(nm) in _LIBFUNCS or _norm(nm) in _OUTPUT or self.ctx.name_of(tgt or -1) == nm and tgt in self.ctx.plt):
            return self.libcall(st, nm, i.addr, i)
        if tgt and self.ctx.is_internal(tgt) and self.descend and len(st.calls) < MAX_CALL_DEPTH:
            st.calls.append(i.addr + i.size)
            st.regs["rsp"] = S_op("sub", 64, st.regs["rsp"], _c(self.wsz, 64))
            st.rip = tgt
            return None
        if nm:
            return self.libcall(st, nm, i.addr, i)
        why = f"call {self.ctx.fname(tgt) if tgt else 'indirect'}"
        for rg in (_CLOBBER if self.ctx.bits == 64 else ("rax", "rcx", "rdx")):
            st.regs[rg] = ("unk", why)
        self.note(("uc", i.addr), f"unknown call @{i.addr:#x} ({why}): return value treated as unknown")
        return None

    def syscall(self, st: _St, i: Insn) -> str | None:
        x64 = self.ctx.bits == 64
        if i.mnem == "int" and (i.ops[0].imm != 0x80 or x64):
            st.regs["rax"] = ("unk", "int")
            return None
        num = st.regs["rax"]
        if num[0] != "c":
            st.regs["rax"] = ("unk", "syscall number")
            return None
        n = num[1] & 0xFFFFFFFF
        args = [st.regs[r] for r in (_ARGREG[:3] if x64 else ["rbx", "rcx", "rdx"])]
        sysmap = {0: "read", 1: "write", 60: "exit", 231: "exit", 101: "ptrace"} if x64 else \
            {3: "read", 4: "write", 1: "exit", 252: "exit", 26: "ptrace"}
        nm = sysmap.get(n)
        if nm == "read" and args[0][0] == "c" and args[0][1] == 0 and args[2][0] == "c":
            self.fill_input(st, args[1], args[2][1], f"read(syscall)@{i.addr:#x}", "stdin", b"\n")
            st.regs["rax"] = self.lenexpr()
        elif nm == "exit":
            return "exit syscall"
        elif nm == "ptrace":
            st.regs["rax"] = _c(0, 64)
            self.res.flags.add("ptrace")
            self.note("ptrace", f"ptrace syscall @{i.addr:#x}: assumed not traced (returns 0)")
        else:
            st.regs["rax"] = ("unk", "syscall")
        return None

    # -- conditional branches
    def jcc(self, st: _St, i: Insn, stack: list) -> str | None:
        t, fth = i.ops[0].target, i.addr + i.size
        c = self.cond(st, i.cc or "")
        rs = self.tr.rs
        s_t, s_f = t in rs, fth in rs
        if isinstance(c, bool):
            if self.concrete is not None and s_t != s_f and c == s_f:
                self.res.fail_at = i.addr
            return self._goto(st, t, fth, c, i.addr)
        req, origin = _unwrap(c)
        if s_t and not s_f:
            want = True
        elif s_f and not s_t:
            want = False
        elif s_t and s_f:
            if len(stack) + self.res.stats["paths"] < MAX_PATHS and not self.concrete:
                alt = st.copy()
                self.res.stats["paths"] += 1
                if self.apply(alt, i, req, origin, False):
                    alt.rip = fth
                    stack.append(alt)
                self.res.forked = True
            want = True
        else:
            want = True
            self.note(("ns", i.addr), f"branch @{i.addr:#x} leaves the success side unclear: taking the jump")
        if not self.apply(st, i, req, origin, want):
            self.res.stats["pruned"] += 1
            self.res.prune_reasons.append(f"infeasible at {i.addr:#x}")
            return "infeasible"
        return self._goto(st, t, fth, want, i.addr)

    def _goto(self, st: _St, t: int, fth: int, taken: bool, frm: int) -> str | None:
        if taken:
            return self.branch(st, t, frm)
        st.rip = fth
        return None

    def apply(self, st: _St, i: Insn, cond: tuple, origin: int | None, taken: bool) -> bool:
        """Require the jump to be taken / not taken; refine domains; record the decision."""
        req = cond if taken else (_neg(cond) if cond[0] == "cc" else cond)
        why = _unk_why(req)
        d = {"addr": i.addr, "kind": "cmovcc" if i.mnem == "cmovcc" else "jcc", "cond": req, "taken": taken,
             "origin": origin, "unresolved": bool(why), "why": why, "cc": i.cc,
             "target": i.ops[0].target if i.flow == "jcc" else None, "fall": i.addr + i.size}
        if not why and req[0] == "cc":
            fv = _free(req)
            if fv == {"scmp"} or (req[3][0] == "scmp"):
                if not self.apply_scmp(st, req):
                    return False
            elif fv == {"len"}:
                st.lend = {n for n in st.lend if _ev(req, {"len": n})}
                if not st.lend:
                    return False
            elif len(fv) == 1 and "len" not in fv:
                k = next(iter(fv))
                mask = st.dom.get(k, (1 << 256) - 1)
                nm = 0
                for v in range(256):
                    if mask >> v & 1 and _ev(req, {k: v}):
                        nm |= 1 << v
                st.dom[k] = nm
                if not nm:
                    return False
        if why:
            self.res.unresolved.append(why)
        st.conds.append(d)
        return True

    def apply_scmp(self, st: _St, req: tuple) -> bool:
        sc = req[3]
        _t, s, n, kind, k0 = sc
        if not (req[1] == "e" and req[4][1] == 0):
            self.res.unresolved.append("string compare required to be non-zero (unsupported)")
            return True
        lit = s if kind != "str" else s
        for j, ch in enumerate(lit):
            mask = st.dom.get(k0 + j, (1 << 256) - 1) & (1 << ch)
            st.dom[k0 + j] = mask
            if not mask:
                return False
        if kind == "str":
            st.lend = {n2 for n2 in st.lend if n2 == k0 + len(lit)}
            if not st.lend:
                return False
        return True

    # -- driver
    def run(self) -> WalkResult:
        res = self.res
        stack = [self.init_state()]
        tr = self.tr
        while stack and not res.found:
            st = stack.pop()
            why = self.exec_path(st, stack)
            if why is not None and not res.found:
                res.prune_reasons.append(why)
                res.stats["pruned"] += 1
            if self.steps >= self.opts.max_steps:
                break
        res.stats["steps"] = self.steps
        if not res.found and self.steps >= self.opts.max_steps:
            res.notes.append(f"walker step budget exhausted at {res.stats.get('last', 0):#x}")
        return res

    def exec_path(self, st: _St, stack: list) -> str | None:
        res, tr, ctx = self.res, self.tr, self.ctx
        while True:
            a = st.rip
            if a in tr.s_sites and a not in tr.cmov_sites:
                self.found(st, a)
                return None
            if a in tr.f_sites and a not in tr.cmov_sites:
                return f"reached failure print at {a:#x}"
            if self.steps >= self.opts.max_steps:
                res.stats["last"] = a
                return "step budget"
            self.steps += 1
            if self.steps % 4096 == 0 and time.time() - self.t0 > STATIC_BUDGET:
                self.steps = self.opts.max_steps
                res.notes.append(f"static time budget ({STATIC_BUDGET:.0f}s) exhausted at {a:#x}")
                res.stats["last"] = a
                return "time budget"
            i = ctx.insn(a)
            if i is None:
                res.unresolved.append(f"decode failed at {a:#x}")
                return f"decode failed at {a:#x}"
            try:
                why = self.exec_one(st, i, stack)
            except (KeyError, IndexError, ValueError, TypeError, AttributeError) as exc:
                res.notes.append(f"walker error @{a:#x}: {type(exc).__name__}: {exc}")
                return "walker error"
            if why == "found":
                return None
            if why is not None:
                return why

    def found(self, st: _St, at: int) -> None:
        """Record the solution path (the success print was reached or selected)."""
        res = self.res
        res.found, res.s_hit, res.decisions = True, at, st.conds
        res.dom, res.lend, res.inbuf = st.dom, st.lend, st.inbuf

    def cmov_decide(self, st: _St, i: Insn, c: Any, edge: str) -> str | None:
        """A cmovcc choosing between the success and failure verdict pointer: success needs ``edge`` behaviour."""
        want_move = edge == "true"
        if isinstance(c, bool):
            if c == want_move:
                self.found(st, i.addr)
                return "found"
            self.res.fail_at = i.addr
            return f"cmov at {i.addr:#x} selects the failure verdict"
        req, origin = _unwrap(c)
        if not self.apply(st, i, req, origin, want_move):
            return "infeasible"
        self.found(st, i.addr)
        return "found"


def extract_constraints(ctx: BinCtx, tr: Trace, opts: Options) -> WalkResult:
    """Stage 3: walk from the input read to the success print; returns decisions + domains."""
    if tr.entry is None or not tr.s_sites:
        return WalkResult()
    w = Walker(ctx, tr, opts)
    res = w.run()
    if res.input_model["mode"] == "unknown" and res.arg0:
        res.input_model = {"mode": "arg0", "via": "argument 0 of the entry function", "conf": "medium"}
    return res


def _rewalk(ctx: BinCtx, tr: Trace, opts: Options, wr: WalkResult, cand: bytes) -> tuple[bool, str]:
    """Static re-walk with a concrete candidate (abstract interpretation, never execution)."""
    w = Walker(ctx, tr, opts, concrete=cand, mode=wr.input_model.get("mode"))
    r = w.run()
    bad = [u for u in r.unresolved]
    if r.found and not r.forked and not bad:
        return True, f"re-walk ok ({len(wr.decisions)} gates satisfied)"
    where = f"0x{r.fail_at:x}" if r.fail_at else "?"
    why = (r.prune_reasons or ["no success print reached"])[0]
    return False, f"re-walk failed at {where} ({why})"


# ---------- constraints, gates, solver
_FULL = (1 << 256) - 1
_ALNUM = sum(1 << c for c in range(256) if chr(c).isascii() and (chr(c).isalnum() or chr(c) in "_{}"))
_PRINT = sum(1 << c for c in range(0x20, 0x7F))


def _pop(mask: int) -> int:
    return bin(mask).count("1")


def _dec_kind(d: dict) -> str:
    req = d["cond"]
    if d["unresolved"]:
        return "unresolved"
    fv = _free(req)
    if req[0] == "cc" and req[3][0] == "scmp":
        return "mem-eq" if req[3][3] == "mem" else "str-eq"
    if fv <= {"len"}:
        return "length"
    ks = [k for k in fv if k != "len"]
    if len(ks) >= 2:
        return "multi"
    return "byte-eq" if req[0] == "cc" and req[1] == "e" else "byte-rel"


def _build_constraints(wr: WalkResult) -> list:
    """Ordered constraints from the solution-path decisions, with loop compaction."""
    raw = []
    for n, d in enumerate(wr.decisions, 1):
        kind = _dec_kind(d)
        req = d["cond"]
        site = d["origin"] or d["addr"]
        conf = "medium" if wr.input_model.get("mode") == "arg0" else "high"
        if kind == "unresolved":
            text, pos, conf = f"depends on {d['why']} (unmodelled)", (), "low"
        elif kind in ("str-eq", "mem-eq"):
            _t, s, nn, sk, k0 = req[3]
            pos = tuple(range(k0, k0 + len(s)))
            text = f"IN[{k0}..{k0 + len(s) - 1}] == {s!r}" + (" + NUL" if sk == "str" else "")
        else:
            pos = tuple(sorted(k for k in _free(req) if k != "len"))
            text = _fe(req, dec=kind == "length")
        raw.append(Constraint(n, kind, text, site, conf, pos, req))
    out: list[Constraint] = []
    i = 0
    while i < len(raw):
        c = raw[i]
        j = i + 1
        pv = re.findall(r"byte\[(0x[0-9a-f]+)\]", c.text)
        if c.kind == "byte-eq" and len(c.positions) == 1 and len(pv) == 1:
            shape = re.sub(r"byte\[0x[0-9a-f]+\]", "byte[]", re.sub(r"IN\[\d+\]", "IN[i]", c.text))
            while j < len(raw):
                d2 = raw[j]
                p2 = re.findall(r"byte\[(0x[0-9a-f]+)\]", d2.text)
                if d2.site == c.site and d2.kind == "byte-eq" and len(d2.positions) == 1 and len(p2) == 1 and \
                        re.sub(r"byte\[0x[0-9a-f]+\]", "byte[]", re.sub(r"IN\[\d+\]", "IN[i]", d2.text)) == shape and \
                        d2.positions[0] == raw[j - 1].positions[0] + 1 and \
                        int(p2[0], 16) == int(re.findall(r"byte\[(0x[0-9a-f]+)\]", raw[j - 1].text)[0], 16) + 1:
                    j += 1
                else:
                    break
            if j - i >= 3:
                p0, p1 = c.positions[0], raw[j - 1].positions[0]
                base = int(pv[0], 16) - p0
                txt = shape.replace("byte[]", f"byte[{base:#x} + i]") + f"   for i = {p0}..{p1}   (gate {c.site:#x} x{j - i})"
                out.append(Constraint(c.n, "byte-eq", txt, c.site, c.conf, tuple(range(p0, p1 + 1)), c.expr))
                i = j
                continue
        out.append(c)
        i += 1
    return out


def _gate_label(ctx: BinCtx, tr: Trace, d: dict) -> str:
    if d["addr"] in tr.deleg:
        return tr.ret_label.get(d["addr"], "unknown condition")
    kind = _dec_kind(d)
    req = d["cond"]
    if kind == "unresolved":
        return "unknown condition"
    if kind == "str-eq":
        return "strcmp result"
    if kind == "mem-eq":
        return "memcmp result"
    if kind == "length":
        return "length check"
    if "byte[" in _fe(req):
        return "table compare"
    return "byte compare" if kind in ("byte-eq", "byte-rel") else "multi-byte compare"


def _final_gates(ctx: BinCtx, tr: Trace, wr: WalkResult) -> list:
    """Gates observed as symbolic decisions on the solution path (static gates when no path was found)."""
    if not wr.found or not wr.decisions:
        return tr.gates
    static = {(g.addr, g.kind): g for g in tr.gates}
    order: dict = {}
    for d in wr.decisions:
        keys = []
        if d["origin"]:
            keys.append((d["origin"], "setcc", d))
        keys.append((d["addr"], d["kind"], d))
        for addr, kind, dd in keys:
            g = order.get((addr, kind))
            if g is None:
                sg = static.get((addr, kind))
                fs = next((s for s, f in tr.funcs.items() if addr in f.insns), None) or ctx.func_for(addr) or 0
                f = tr.funcs.get(fs)
                if sg is not None:
                    g = Gate(0, sg.addr, sg.kind, sg.cc, sg.cmp_addr, sg.func, sg.success_edge, sg.success_to,
                             sg.fail_to, sg.in_loop, 0, False, sg.label, sg.conf)
                else:
                    taken = dd["taken"]
                    g = Gate(0, addr, kind, (dd["cc"] or ""), None, fs,
                             ("true" if taken else "false") if kind == "cmovcc" else ("taken" if taken else "fallthrough"),
                             dd["target"] if taken else dd["fall"], dd["fall"] if taken else dd["target"],
                             bool(f and f.in_loop(addr)), 0, False, "unknown condition", "medium")
                if kind in ("jcc", "cmovcc") and (sg is None or g.label == "unknown condition"):
                    g.label = _gate_label(ctx, tr, dd)
                order[(addr, kind)] = g
            g.hits += 1
    gates = list(order.values())
    for i, g in enumerate(gates, 1):
        g.n = i
    last = wr.decisions[-1]
    for g in gates:
        g.deciding = g.addr == last["addr"] and g.kind in ("jcc", "cmovcc")
    return gates


def _flag_prefix(rx: str) -> bytes:
    out = ""
    i = 0
    while i < len(rx):
        ch = rx[i]
        if ch == "\\" and i + 1 < len(rx) and not rx[i + 1].isalnum():
            out += rx[i + 1]
            i += 2
        elif ch in ".^$*+?()[]|{}\\":
            break
        else:
            out += ch
            i += 1
    return out.encode("latin-1", "replace")


def _values(mask: int) -> list:
    return [v for v in range(256) if mask >> v & 1]


def _pick(mask: int, k: int, anchor: bytes) -> tuple[int, bool]:
    """Choose a byte from a domain by rank; returns (value, ambiguous)."""
    if k < len(anchor) and mask >> anchor[k] & 1:
        return anchor[k], False
    for cls in (_ALNUM, _PRINT, _FULL):
        m = mask & cls
        if m:
            vs = _values(m)
            return vs[0], len(vs) > 1
    return 0, False


def _solve_multi(decs: list, dom: dict, lenval: int | None) -> tuple[bool, int]:
    """Propagation (11.2) + bounded backtracking search (11.3). Returns (ok, evaluations)."""
    multis = []
    for d in decs:
        if d["unresolved"] or d["cond"][0] != "cc" or d["cond"][3][0] == "scmp":
            continue
        ks = sorted(k for k in _free(d["cond"]) if k != "len")
        if len(ks) >= 2:
            multis.append((d["cond"], ks))
    evals = 0

    def env_for(assign: dict) -> dict:
        e = dict(assign)
        if lenval is not None:
            e["len"] = lenval
        return e
    for _ in range(64):
        changed = False
        for e, ks in multis:
            op = [k for k in ks if _pop(dom.get(k, _FULL)) > 1]
            if len(op) == 1:
                k = op[0]
                base = {kk: _values(dom.get(kk, _FULL))[0] for kk in ks if kk != k}
                nm = 0
                for v in _values(dom.get(k, _FULL)):
                    evals += 1
                    if _ev(e, env_for({**base, k: v})):
                        nm |= 1 << v
                if nm != dom.get(k, _FULL):
                    dom[k] = nm
                    changed = True
        if not changed:
            break
    openk = sorted({k for _e, ks in multis for k in ks if _pop(dom.get(k, _FULL)) > 1},
                   key=lambda k: -sum(1 for _e, ks in multis if k in ks))
    if not openk:
        return all(_ev(e, env_for({k: _values(dom.get(k, _FULL))[0] for k in ks})) for e, ks in multis) or not multis, evals
    assign: dict = {}
    for k in dom:
        if _pop(dom[k]) == 1:
            assign[k] = _values(dom[k])[0]
    budget = [MAX_SEARCH - evals]

    def rec(ix: int) -> bool:
        if ix == len(openk):
            return True
        k = openk[ix]
        vs = _values(dom.get(k, _FULL))
        vs.sort(key=lambda v: (0 if _ALNUM >> v & 1 else 1 if _PRINT >> v & 1 else 2, v))
        for v in vs:
            assign[k] = v
            ok = True
            for e, ks in multis:
                if k in ks and all(kk in assign for kk in ks):
                    budget[0] -= 1
                    if budget[0] < 0:
                        return False
                    if not _ev(e, env_for(assign)):
                        ok = False
                        break
            if ok and rec(ix + 1):
                return True
        assign.pop(k, None)
        return False
    ok = rec(0)
    if ok:
        for k in openk:
            dom[k] = 1 << assign[k]
    return ok, MAX_SEARCH - budget[0]


def solve(ctx: BinCtx, wr: WalkResult, opts: Options) -> Solution:
    """Stage 5a: derive a candidate input from the path decisions and verify it by static re-walk."""
    sol = Solution(None, None, "low", "none", [], [], "not run", [], False)
    if not wr.found:
        return sol
    tr: Trace = wr.tr
    anchor = _flag_prefix(opts.flag_re.pattern) if opts.flag_re else b""
    decs = wr.decisions
    kinds = [_dec_kind(d) for d in decs]
    dom = dict(wr.dom)
    unresolved = [d for d in decs if d["unresolved"]]
    lend = sorted(wr.lend)
    # trivial win: strcmp/memcmp against a literal and nothing else symbolic
    sc = [d for d, k in zip(decs, kinds) if k in ("str-eq", "mem-eq")]
    other = [k for k in kinds if k not in ("str-eq", "mem-eq", "length")]
    if sc and not other and not unresolved and all(d["cond"][3][4] == 0 for d in sc):
        lit = max((d["cond"][3][1] for d in sc), key=len)
        cand = bytes(lit)
        sol.method = "memcmp-literal" if sc[0]["cond"][3][3] == "mem" else "strcmp-literal"
        return _finish_solution(ctx, tr, opts, wr, sol, cand, [], [], [], anchor)
    multi_used = False
    lenval = lend[0] if len(lend) == 1 else None
    constrained = sorted(k for k, m in dom.items() if m != _FULL)
    len_open = False
    if lenval is not None:
        L = lenval
    else:
        L = (constrained[-1] + 1) if constrained else 0
        if constrained and dom[constrained[-1]] == 1:
            L = constrained[-1]
        else:
            len_open = "len-used" in wr.flags
    if not constrained and lenval is None:
        sol.trace.append("no input byte is constrained on the success path")
        return sol
    ok, evals = _solve_multi(decs, dom, lenval if lenval is not None else L)
    multi_used = "multi" in kinds
    unknown: list = []
    ambiguous: list = []
    free: list = []
    out = bytearray()
    for k in range(L):
        m = dom.get(k, _FULL)
        if m == 0:
            unknown.append(k)
            out.append(0x3F)
            continue
        if m == _FULL:
            free.append(k)
            out.append(0x41)
            continue
        v, amb = _pick(m, k, anchor)
        if multi_used and not ok and _pop(m) > 1:
            unknown.append(k)
            out.append(0x3F)
            continue
        out.append(v)
        if amb:
            ambiguous.append(k)
    if multi_used and not ok:
        sol.trace.append("search exhausted: several-byte constraints left open")
        wr.flags.add("search-exhausted")
    sol.method = "search" if multi_used else "byte-domain"
    if free:
        sol.trace.append(f"positions {free[0]}..{free[-1]} unconstrained on the path: any value accepted (filled 'A')")
    return _finish_solution(ctx, tr, opts, wr, sol, bytes(out), unknown, ambiguous, unresolved, anchor, len_open)


def _finish_solution(ctx: BinCtx, tr: Trace, opts: Options, wr: WalkResult, sol: Solution, cand: bytes,
                     unknown: list, ambiguous: list, unresolved: list, anchor: bytes, len_open: bool = False) -> Solution:
    sol.candidate = cand
    sol.unknown, sol.ambiguous = unknown, ambiguous
    sol.text = "".join(chr(b) if 0x20 <= b < 0x7F else ("?" if b == 0x3F and i in unknown else f"\\x{b:02x}")
                       for i, b in enumerate(cand))
    ok, msg = (False, "re-walk not run (unknown bytes)") if unknown else _rewalk(ctx, tr, opts, wr, cand)
    sol.verified = msg
    for c in wr.constraints:
        pos = [p for p in c.positions if p < len(cand)]
        if c.kind == "length":
            sol.trace.insert(0, f"{c.text}  =>  LEN={len(cand)}")
        elif pos and c.kind != "unresolved":
            seg = cand[pos[0]:pos[-1] + 1].decode("latin-1")
            sol.trace.append(f"{c.text.split('   (gate')[0]}  =>  IN[{pos[0]}..{pos[-1]}] = {seg!r}"
                             if len(pos) > 1 else f"{c.text}  =>  IN[{pos[0]}] = {chr(cand[pos[0]])!r}")
        elif c.kind == "unresolved":
            sol.trace.append(f"{c.text}: assumed to pass")
    if not ok:
        sol.conf = "low"
    elif unknown or unresolved:
        sol.conf = "low"
    elif ambiguous or len_open or wr.input_model.get("mode") == "arg0":
        sol.conf = "medium"
    else:
        sol.conf = "high"
    if not ok and not unknown:
        wr.notes.append(f"candidate rejected: {msg}")
    pat = batch.FLAG_RE.search(cand) is not None or bool(opts.flag_re and opts.flag_re.search(cand.decode("latin-1")))
    sol.flag_match = pat
    # rodata-flag: a flag-shaped string in the image that the checker accepts
    if sol.conf != "high":
        for addr, raw in ctx.rodata_flags[:4]:
            ok2, msg2 = _rewalk(ctx, tr, opts, wr, raw)
            if ok2:
                sol.candidate, sol.text, sol.conf, sol.method = raw, raw.decode("latin-1"), "high", "rodata-flag"
                sol.verified, sol.unknown, sol.ambiguous = msg2, [], []
                sol.flag_match = True
                sol.trace.append(f"flag-shaped string in .rodata @{addr:#x} is accepted by the checker")
                break
            wr.notes.append(f"flag-shaped string in .rodata @{addr:#x} is not accepted by the checker")
    return sol


# ---------- patch planner
def _hexb(b: bytes) -> str:
    return " ".join(f"{x:02x}" for x in b)


def _mk_patch(ctx: BinCtx, g: Gate, src: str, out: str, primary: bool) -> Patch | None:
    i = ctx.insn(g.addr)
    off = disasm.vaddr_to_offset(ctx.elf, g.addr)
    if i is None or off is None:
        return None
    raw = i.raw
    ok_to = g.success_edge in ("taken", "true")
    if g.kind == "jcc" and i.flow == "jcc":
        short = len(raw) == 2
        if not ok_to:
            new, strat = b"\x90" * len(raw), "nop-jcc"
            cmd = f"recon.py elfpatch nop {src} --at {g.addr:#x} --len {len(raw)} -o {out}"
        elif short:
            new, strat = b"\xeb" + raw[1:2], "force-jmp"
            cmd = f"recon.py elfpatch patch {src} --at {g.addr:#x} --bytes eb -o {out}"
        else:
            new, strat = b"\x90\xe9" + raw[2:], "force-jmp"
            cmd = f"recon.py elfpatch patch {src} --at {g.addr:#x} --bytes 90e9 -o {out}"
        desc = f"{g.addr:#x} j{g.cc} ({g.label}): make the {'jump unconditional' if ok_to else 'fallthrough unconditional'}"
    elif g.kind == "setcc" and i.mnem == "setcc" and i.ops[0].kind == "reg" and len(raw) == 3 and (raw[2] & 0xF8) == 0xC0 \
            and (raw[2] & 7) < 4:
        new = bytes([0xB0 + (raw[2] & 7), 1 if ok_to else 0, 0x90])
        strat = "setcc-to-mov1"
        cmd = f"recon.py elfpatch patch {src} --at {g.addr:#x} --bytes {new.hex()} -o {out}"
        desc = f"{g.addr:#x} set{g.cc} ({g.label}): force the result to {1 if ok_to else 0}"
    elif g.kind == "cmovcc" and i.mnem == "cmovcc":
        if ok_to:   # make the move unconditional: [REX] 0F 4x modrm -> [REX] 8B modrm NOP
            rex = raw[:1] if 0x40 <= raw[0] <= 0x4F else b""
            new, strat = rex + b"\x8b" + raw[len(rex) + 2:len(rex) + 3] + b"\x90", "cmov-to-mov"
            cmd = f"recon.py elfpatch patch {src} --at {g.addr:#x} --bytes {new.hex()} -o {out}"
            desc = f"{g.addr:#x} cmov{g.cc}: make the move unconditional"
        else:
            new, strat = b"\x90" * len(raw), "nop-jcc"
            cmd = f"recon.py elfpatch nop {src} --at {g.addr:#x} --len {len(raw)} -o {out}"
            desc = f"{g.addr:#x} cmov{g.cc}: suppress the move"
    else:
        return None
    return Patch(g.addr, off, bytes(raw), new, strat, desc, cmd, primary, g.conf)


def _callers(ctx: BinCtx, target: int) -> int:
    n = 0
    for s in ctx.exec_secs:
        code = ctx.data[s.off:s.off + s.size]
        for m in re.finditer(rb"\xe8(....)", code, re.S):
            if s.addr + m.start() + 5 + int.from_bytes(m.group(1), "little", signed=True) == target:
                n += 1
    return n


def plan_patches(ctx: BinCtx, tr: Trace, wr: WalkResult) -> list:
    """Stage 5b: exact force-patches for the gates (primary plan) plus alternatives."""
    gates = getattr(wr, "gates", None) or tr.gates
    gates = [g for g in gates if g.kind in ("jcc", "setcc", "cmovcc")]
    if not gates:
        return []
    deciding = next((g for g in gates if g.deciding), gates[-1])
    funnel = deciding.label.startswith("return value of") and deciding.kind == "jcc" and \
        all(g is deciding or g.func != deciding.func for g in gates)
    chosen: list[Gate] = [deciding] if funnel else []
    if not funnel:
        seen = set()
        for g in gates:
            if g.addr not in seen and not (g.kind == "setcc" and any(h.kind == "jcc" and h.addr != g.addr
                                                                       and h.func != g.func for h in gates)):
                seen.add(g.addr)
                chosen.append(g)
    n = len(chosen)
    src = ctx.name
    names = [f"{src}.p{k}" for k in range(1, n)] + [f"{src}.patched"]
    plan: list[Patch] = []
    for k, g in enumerate(chosen):
        p = _mk_patch(ctx, g, src if k == 0 else names[k - 1], names[k], True)
        if p:
            plan.append(p)
    if funnel and deciding.addr in tr.deleg:   # alternatives: ret-true at callee, flip
        x = tr.deleg[deciding.addr]
        pred, _ga = tr.deleg_pred.get(x, ({0: False, 1: True}, 0))
        fx = ctx.func(x)
        span = sum(i.size for i in fx.insns.values())
        off = disasm.vaddr_to_offset(ctx.elf, x)
        if span >= 6 and off is not None and _callers(ctx, x) <= 1:
            new = b"\xb8\x01\x00\x00\x00\xc3" if pred.get(1) and not pred.get(0) else b"\x31\xc0\xc3"
            old = ctx.data[off:off + len(new)]
            plan.append(Patch(x, off, old, new, "ret-true", f"{x:#x} {ctx.fname(x)}: return the success value immediately",
                              f"recon.py elfpatch patch {src} --at {x:#x} --bytes {new.hex()} -o {src}.alt", False, "medium"))
    if plan and deciding.kind == "jcc":
        i = ctx.insn(deciding.addr)
        off = disasm.vaddr_to_offset(ctx.elf, deciding.addr)
        if i is not None and off is not None and i.flow == "jcc":
            try:
                flipped, _d = elfpatch.flip_jcc(ctx.data, off)
                new = flipped[off:off + i.size]
                plan.append(Patch(deciding.addr, off, bytes(i.raw), new, "flip",
                                  "alternative: flip makes correct input fail; force is preferred",
                                  f"recon.py elfpatch flip {src} --at {deciding.addr:#x} -o {src}.flip", False, "medium"))
            except elfpatch.PatchError:
                pass
    return plan


def _apply_patches(ctx: BinCtx, patches: list) -> bytes:
    data = ctx.data
    for p in patches:
        if p.primary:
            data = elfpatch.patch_bytes(data, p.offset, p.new)
    return data


def _verify_patch(ctx: BinCtx, patches: list, opts: Options) -> str:
    """Re-run stages 1-3 on the patched bytes: the success print must be reached with 0 symbolic gates."""
    try:
        pctx = BinCtx(_apply_patches(ctx, patches), ctx.name)
        vs = find_verdicts(pctx, opts)
        ptr = trace(pctx, vs, opts)
        w = Walker(pctx, ptr, opts, descend=False)
        r = w.run()
        if r.found and not r.decisions:
            return "patch check: success print reached with 0 input-dependent branches"
        return f"patch check: FAILED ({len(r.decisions)} input-dependent branches remain)" if r.found else \
            "patch check: FAILED (success print not reached)"
    except Exception as exc:  # noqa: BLE001
        return f"patch check: not run ({type(exc).__name__}: {exc})"


# ---------- listing
def _cs_text(i: Insn, bits: int) -> str | None:
    cs = _CS
    if cs is None:
        return None
    try:
        md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64 if bits == 64 else cs.CS_MODE_32)
        for x in md.disasm(i.raw, i.addr):
            return f"{x.mnemonic} {x.op_str}".strip()
    except Exception:  # noqa: BLE001
        return None
    return None


def _cs_crosscheck(ctx: BinCtx, tr: Trace) -> str:
    """--deep: compare built-in instruction lengths with capstone over the analysed functions."""
    n = bad = 0
    for f in tr.funcs.values():
        for i in f.insns.values():
            n += 1
            try:
                md = _CS.Cs(_CS.CS_ARCH_X86, _CS.CS_MODE_64 if ctx.bits == 64 else _CS.CS_MODE_32)
                got = list(md.disasm(i.raw, i.addr))
                bad += 0 if got and got[0].size == i.size else 1
            except Exception:  # noqa: BLE001
                bad += 1
    return f"capstone length cross-check: {n} instructions, {bad} mismatch(es)"


def render_listing(ctx: BinCtx, tr: Trace, wr: WalkResult, deep: bool = False) -> list:
    """Stage 4: annotated verdict-region listing (built-in decoder; capstone text when available)."""
    gates = getattr(wr, "gates", None) or tr.gates
    gmap = {(g.addr): g for g in gates if g.kind != "setcc"}
    smap = {g.addr: g for g in gates if g.kind == "setcc"}
    vmap: dict[int, str] = {}
    for v in getattr(wr, "verdict_list", []):
        for r in v.refs:
            vmap[r.site] = f'VERDICT {v.polarity} "{v.text[:24]}"'
    cons: dict[int, Constraint] = {}
    for c in wr.constraints:
        cons.setdefault(c.site, c)
    tables = {}
    for c in wr.constraints:
        m = re.search(r"byte\[(0x[0-9a-f]+) \+ i\].*i = (\d+)\.\.(\d+)", c.text)
        if m:
            base = int(m.group(1), 16)
            tables[base] = int(m.group(3)) - int(m.group(2)) + 1
    via = re.search(r"@(0x[0-9a-f]+)", str(wr.input_model.get("via") or ""))
    in_site = int(via.group(1), 16) if via else None
    patch_at = {p.site: p for p in getattr(wr, "patches", []) if p.primary}
    lines: list[str] = []
    cap = 600 if deep else MAX_LISTING
    fl = [f for fs, f in tr.funcs.items() if any(a in f.insns for a in (set(tr.s_sites) | set(tr.f_sites) | set(gmap)))] \
        or list(tr.funcs.values())[:1]
    for f in sorted(fl, key=lambda x: x.start):
        addrs = sorted(f.insns)
        if not addrs:
            continue
        lo = in_site if in_site in f.insns else addrs[0]
        marks = [a for a in (set(tr.s_sites) | set(tr.f_sites) | set(gmap) | set(smap)) if a in f.insns]
        hi = max(marks) if marks else addrs[-1]
        hi_ix = addrs.index(hi) if hi in addrs else len(addrs) - 1
        end = addrs[min(hi_ix + 2, len(addrs) - 1)]
        if deep:
            lo, end = addrs[0], addrs[-1]
        prev_end = None
        for a in addrs:
            if a < lo or a > end:
                continue
            i = f.insns[a]
            if prev_end is not None and a != prev_end:
                lines.append("   ...")
            prev_end = a + i.size
            txt = _cs_text(i, ctx.bits) or fmt(i, ctx.bits)
            ann: list[str] = []
            if i.addr == in_site:
                nm = (wr.input_model.get("via") or "").split("@")[0]
                ann.append(f"INPUT <- {nm}(buf={wr.input_model.get('buf', '?')}, {wr.input_model.get('cap', '?')})")
            nmc = ctx.call_name(i) if i.flow in ("call", "call-ind") else None
            if nmc and _norm(nmc) in ("strlen", "strcspn"):
                ann.append(f"LEN <- {_norm(nmc)}(input)")
            g = gmap.get(i.addr) or smap.get(i.addr)
            if g:
                c = cons.get(i.addr)
                ct = (c.text.split("   (gate")[0] if c else "")
                tag = {"high": "H", "medium": "M", "low": "L"}[c.conf if c else g.conf]
                ann.append(f"GATE#{g.n} {g.label}" + (f": {ct}" if ct else "") + f" [{tag}]"
                           + (" *DECIDING*" if g.deciding else ""))
            if i.addr in vmap:
                ann.append(vmap[i.addr])
            for o in i.ops:
                if o.kind == "mem" and o.base == "rip" and o.target in tables:
                    n = tables[o.target]
                    bs = ctx.read(o.target, min(n, 4)) or b""
                    ann.append(f"TABLE {o.target:#x} ({n} B: {_hexb(bs)}{' …' if n > 4 else ''})")
            if i.mnem in ("xor", "add", "sub", "rol", "ror", "shl", "shr", "imul") and any(o.kind == "imm" for o in i.ops):
                bk = f.blocks.get(f.block_of.get(i.addr, -1))
                if bk and any(x.addr in gmap for x in bk.insns if x.addr > i.addr) and \
                        not any(x.mnem in ("xor", "add", "sub", "rol", "ror", "shl", "shr", "imul") and
                                any(o.kind == "imm" for o in x.ops) for x in bk.insns if x.addr < i.addr):
                    imm = next(o.imm for o in i.ops if o.kind == "imm")
                    ann.append(f"xform: {i.mnem} {imm:#x}")
            if i.flow in ("jcc", "jmp") and i.ops[0].target <= i.addr:
                for c in wr.constraints:
                    mm = re.search(r"i = (\d+)\.\.(\d+)", c.text)
                    if mm and f.in_loop(c.site):
                        ann.append(f"loop i={mm.group(1)}..{mm.group(2)}")
                        break
            if not i.modelled:
                ann.append("unmodelled: " + ("crc32" if "crc32" in self_name(i) else i.raw[:3].hex()))
            if i.addr in patch_at:
                ann.append("PATCH -> " + _hexb(patch_at[i.addr].new))
            raw = _hexb(i.raw)
            raw = raw if len(raw) <= 20 else raw[:19] + "…"
            ln = f"  {i.addr:#010x}  {raw:<20}  {txt.split('  ;')[0]:<24}" + (f"  ; {' | '.join(ann)}" if ann else "")
            lines.append(ln.rstrip())
            if len(lines) >= cap:
                lines.append("   ... (truncated)")
                return lines
    return lines


def self_name(i: Insn) -> str:
    """Mechanical name for an unmodelled instruction (used in annotations)."""
    return "crc32" if (b"\x0f\x38\xf0" in i.raw or b"\x0f\x38\xf1" in i.raw) else i.raw.hex()


# ---------- guidance
def _guidance(ctx: BinCtx, rep_verdicts: list, tr: Trace, wr: WalkResult, sol: Solution | None, patches: list) -> list:
    out: list[str] = []
    elf = ctx.name

    def add(s: str) -> None:
        if s not in out:
            out.append(s)
    if not rep_verdicts:
        add("no verdict strings matched; rerun with --success 'TEXT' --fail 'TEXT' (copy the program's output)")
        add(f"recon.py revauto {elf} --deep   (strings + xrefs + function digest)")
    elif not any(v.refs for v in rep_verdicts) and ctx.x86:
        add("verdict strings have no code references (stack-built / encrypted / packed?)")
        add(f"recon.py revauto {elf}   (packer + anti-debug tells)")
    un = [d for d in wr.decisions if d["unresolved"]] if wr.found else []
    gate_at = (un[0]["origin"] or un[0]["addr"]) if un else None
    if un:
        ga = un[0]["addr"] if un[0]["origin"] is None else un[0]["origin"]
        why = un[0]["why"]
        lo = max(ga - 0x40, 0)
        add(f"gate {ga:#x} depends on {why.split(' @')[0]}: inspect with recon.py disasm range {elf} {lo:#x} 0x80")
        brk = f"*(0x555555554000 + {ga:#x})" if ctx.pie else f"*{ga:#x}"
        add(f"gdb {elf}  ->  break {brk}  ->  run  ->  x/2i $pc ; info registers eflags")
        add("force it live: set $eflags ^= 0x40   (recon.py gdbkit find patch-memory)")
        add(f"recon.py gdbkit script {elf} -b '{brk}' --bp-cmd 'info registers' -o gate.gdb")
    hashed = [d["why"] for d in un if d["why"].startswith(("crc32", "hash"))] + \
        [f for f in wr.flags if f.startswith("hash:")]
    if hashed:
        add(f"input is hashed ({(hashed[0].split(' @')[0].replace('hash ', '').replace('hash:', ''))}) before the compare: not "
            "statically invertible -> patch the gate, or recon.py hashid id <hex> if the digest constant is extractable")
    if "numeric" in wr.flags:
        add("input parsed as a number: brute the compare by hand or use the angr lane")
    if "ptrace" in wr.flags or any("ptrace" in v for v in ctx.got.values()):
        add("recon.py gdbkit find ptrace   (debugger check present)")
    if "search-exhausted" in wr.flags or (sol and sol.unknown):
        add("constraints over several bytes left open: angr lane (pip install angr before the CTF)")
    if ctx.pie and (un or not patches):
        add("PIE: gdb breakpoints use break *(0x555555554000 + OFFSET) with ASLR off; recon.py gdbkit find vmmap")
    if _WHICH("objdump") or _WHICH("r2"):
        ext = disasm.external_shortcuts(elf)
        if ext:
            add(f"{ext[0]}   (suggestion; autosolve never runs it)")
    if not out:
        add(f"recon.py revauto {elf} --deep   (strings + xrefs + function digest)")
    return out[:6]


# ---------- analyze
_NEED = {"verdicts": "v", "trace": "vt", "constraints": "vtc", "solve": "vtcs", "patch": "vtcp",
         "listing": "vtcl", "all": "vtcspl"}


def load(data: bytes, name: str = "<input>") -> "BinCtx":
    """Parse ``data`` as an ELF target (raises ``disasm.ElfError`` for non-ELF input)."""
    return BinCtx(data[:MAX_INPUT], name)


def _target_info(ctx: BinCtx, data: bytes, name: str) -> dict:
    return {"name": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
            "format": f"ELF{ctx.bits}", "arch": ctx.arch, "bits": ctx.bits, "pie": ctx.pie,
            "stripped": ctx.stripped, "static": ctx.static, "capstone": _CS is not None, "fnames": {}}


def analyze(data: bytes, name: str = "<input>", opts: Options | None = None, stages: str = "all") -> "Report":
    """Run the staged analysis (Lane 1 only); never raises for any bytes input."""
    return _analyze(data, name, opts, stages)[0]


def _analyze(data: bytes, name: str, opts: Options | None, stages: str) -> tuple:
    """analyze() plus the internal objects (ctx, trace, walk result) the angr lane needs."""
    opts = opts or Options()
    rep = Report({"name": name, "size": len(data)}, [], [], [], None, [], [], {"mode": "unknown", "via": None, "conf": "low"},
                 "guidance", [], None, [], [])
    need = _NEED.get(stages, _NEED["all"])
    t0 = time.time()
    if len(data) > MAX_INPUT:
        rep.notes.append(f"input larger than {MAX_INPUT >> 20} MiB: only the first {MAX_INPUT >> 20} MiB analysed")
    ctx = _stage(rep, "load", load, data, name)
    if ctx is None:
        rep.next_steps = ["not a parsable ELF: recon.py triage <file>   (identify the file type first)"]
        return rep, None, Trace(), WalkResult()
    rep.target = _target_info(ctx, data, name)
    if not ctx.x86:
        rep.notes.append(f"non-x86 ELF ({ctx.arch}): strings-only report (Lane 1 decodes x86 / x86-64)")
    verdicts = _stage(rep, "find-verdicts", find_verdicts, ctx, opts) or []
    rep.verdicts = verdicts
    for a, raw in ctx.rodata_flags[:4]:
        rep.notes.append(f"[M] rodata-flag candidate @{a:#x}: {raw.decode('latin-1')[:60]!r} (present, not proven to be the answer)")
    tr = Trace()
    wr = WalkResult()
    sol: Solution | None = None
    patches: list = []
    if "t" in need and ctx.x86 and time.time() - t0 < STATIC_BUDGET:
        tr = _stage(rep, "trace", trace, ctx, verdicts, opts) or Trace()
        rep.notes += [n for n in tr.notes if n not in rep.notes]
        if opts.deep and _CS is not None:
            rep.notes.append(_cs_crosscheck(ctx, tr))
        rep.gates = list(tr.gates)
    if "c" in need and tr.entry is not None and time.time() - t0 < STATIC_BUDGET:
        wr = _stage(rep, "constraints", extract_constraints, ctx, tr, opts) or WalkResult()
        wr.tr = tr
        wr.verdict_list = verdicts
        wr.constraints = _build_constraints(wr)
        rep.notes += [n for n in wr.notes if n not in rep.notes]
        if wr.found:
            wr.gates = _final_gates(ctx, tr, wr)
            rep.gates = wr.gates
        else:
            wr.gates = tr.gates
        rep.constraints = wr.constraints
        rep.input_model = wr.input_model
        if not wr.found and tr.s_sites:
            rep.notes.append("walker did not reach a success print on any path")
    if "s" in need and wr.found:
        if not wr.decisions:
            rep.notes.append("no input-dependent branch on the success path")
        else:
            sol = _stage(rep, "solve", solve, ctx, wr, opts)
            rep.solution = sol
    if ("p" in need or stages == "trace") and (tr.gates or wr.gates):
        patches = _stage(rep, "patch", plan_patches, ctx, tr, wr) or []
        rep.patches = patches
        wr.patches = patches
        if patches and "p" in need:
            rep.notes.append(_verify_patch(ctx, patches, opts))
    if "l" in need and tr.funcs:
        rep.listing = _stage(rep, "listing", render_listing, ctx, tr, wr, opts.deep) or []
    for f in {r.func for v in verdicts for r in v.refs if r.func} | {g.func for g in rep.gates}:
        rep.target["fnames"][f] = ctx.fname(f)
    rep.next_steps = _guidance(ctx, verdicts, tr, wr, sol, patches)
    if sol and sol.candidate is not None and sol.conf in ("high", "medium"):
        rep.outcome = "derived"
    elif any(p.primary for p in patches):
        rep.outcome = "patch"
    else:
        rep.outcome = "guidance"
    return rep, ctx, tr, wr


# ---------- angr lane (Lane 2)
_ANGR_HELPER = '''import json, sys
cfg = json.loads(sys.stdin.read())
import angr, claripy
proj = angr.Project(cfg["path"], auto_load_libs=False)
delta = proj.loader.main_object.mapped_base - cfg["link_base"]
find = [a + delta for a in cfg["find"]]
avoid = [a + delta for a in cfg["avoid"]]
opts = {angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY, angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS}
syms = []
if cfg["length"]:
    syms = [claripy.BVS("in%d" % i, 8) for i in range(cfg["length"])]
    data = claripy.Concat(*syms)
if cfg["mode"] == "argv":
    if not syms:
        syms = [claripy.BVS("in%d" % i, 8) for i in range(cfg["max_len"])]
        data = claripy.Concat(*syms)
    st = proj.factory.entry_state(args=[cfg["path"], data], add_options=opts)
elif syms:
    stream = angr.SimFileStream(name="stdin", content=claripy.Concat(data, claripy.BVV(b"\\n")), has_end=True)
    st = proj.factory.full_init_state(stdin=stream, add_options=opts)
else:
    st = proj.factory.full_init_state(add_options=opts)
for b in syms:
    if cfg["printable"]:
        st.solver.add(b >= 0x20, b <= 0x7e)
for k, v in cfg["known"].items():
    if int(k) < len(syms):
        st.solver.add(syms[int(k)] == v)
sm = proj.factory.simulation_manager(st)
sm.explore(find=find, avoid=avoid, num_find=1)
if sm.found:
    s = sm.found[0]
    out = s.solver.eval(claripy.Concat(*syms), cast_to=bytes) if syms else s.posix.dumps(0)
    print(json.dumps({"status": "ok", "input_hex": out.hex()}))
else:
    print(json.dumps({"status": "no-solution", "input_hex": None}))
'''


def angr_available(find_spec: Callable[[str], Any] | None = None) -> bool:
    """True when angr and claripy are importable by this interpreter (never imports them)."""
    fs = find_spec or _FIND_SPEC
    try:
        return fs("angr") is not None and fs("claripy") is not None
    except (ImportError, ValueError, AttributeError):
        return False


def _run_angr_child(cfg: dict, timeout: int) -> "subprocess.CompletedProcess":
    """Run the angr helper in a child interpreter (the only subprocess autosolve ever starts)."""
    tmp = tempfile.mkdtemp(prefix="autosolve-")
    try:
        return subprocess.run([sys.executable, "-c", _ANGR_HELPER], input=json.dumps(cfg).encode(),
                              capture_output=True, timeout=timeout, cwd=tmp,
                              env={**os.environ, "PYTHONWARNINGS": "ignore"}, check=False)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


_ANGR_RUNNER = _run_angr_child


def run_angr(ctx: BinCtx, tr: Trace, wr: WalkResult, opts: Options,
             runner: Callable[..., Any] | None = None, sol: Solution | None = None) -> AngrResult:
    """Lane 2: hand Lane 1's find/avoid addresses to angr (child process, bounded by --angr-timeout)."""
    if opts.angr == "off":
        return AngrResult("skipped", None, "angr: skipped (--no-angr)", 0.0, None)
    if not angr_available():
        return AngrResult("absent", None, ANGR_ABSENT_LINE, 0.0, None)
    if not tr.s_sites:
        return AngrResult("skipped", None, "angr: skipped (no success address from Lane 1; pass --success)", 0.0, None)
    lb = min((sg["vaddr"] for sg in ctx.elf["segments"] if sg["type"] == 1), default=0)
    lend = sorted(wr.lend) if wr.found else []
    known = {} if opts.deep else {str(k): _values(m)[0] for k, m in wr.dom.items() if _pop(m) == 1 and k < 512}
    mode = "argv" if wr.input_model.get("mode") == "argv" else "stdin"
    cfg = {"path": os.path.abspath(ctx.name), "link_base": lb, "pie": ctx.pie, "find": sorted(tr.s_sites),
           "avoid": sorted(tr.f_sites), "mode": mode, "length": lend[0] if len(lend) == 1 and lend[0] else None,
           "max_len": 64, "printable": True, "known": known, "max_active": 64}
    t0 = time.time()
    try:
        proc = (runner or _ANGR_RUNNER)(cfg, opts.angr_timeout)
    except subprocess.TimeoutExpired:
        return AngrResult("timeout", None, f"angr: timed out after {opts.angr_timeout} s (static results above unaffected)",
                          time.time() - t0, None)
    except Exception as exc:  # noqa: BLE001
        return AngrResult("error", None, f"angr: error: {type(exc).__name__}: {exc}"[:100], time.time() - t0, None)
    dt = time.time() - t0
    out = getattr(proc, "stdout", b"") or b""
    err = (getattr(proc, "stderr", b"") or b"").decode("latin-1", "replace").strip().splitlines()
    try:
        line = out.decode("latin-1").strip().splitlines()[-1]
        js = json.loads(line)
        if getattr(proc, "returncode", 0) != 0 or "status" not in js:
            raise ValueError("bad helper result")
    except (IndexError, ValueError, TypeError):
        tail = err[-1][:80] if err else "no output"
        return AngrResult("error", None, f"angr: error: {tail}", dt, None)
    if js["status"] == "ok" and js.get("input_hex") is not None:
        data = bytes.fromhex(js["input_hex"])
        agrees = None
        if sol is not None and sol.candidate is not None:
            agrees = data.rstrip(b"\n\0") == sol.candidate
        return AngrResult("ok", data, "ok", dt, agrees)
    return AngrResult("no-solution", None, f"angr: explored, no input reaches {min(tr.s_sites):#x} within limits", dt, None)


# ---------- report rendering
def _jsafe(o: Any) -> Any:
    if isinstance(o, (bytes, bytearray)):
        b = bytes(o)
        return {"hex": b.hex(), "text": b.decode("latin-1") if all(0x20 <= x < 0x7F for x in b) else None}
    if hasattr(o, "__dataclass_fields__"):
        return {k: _jsafe(getattr(o, k)) for k in o.__dataclass_fields__ if k != "expr"}
    if isinstance(o, dict):
        return {str(k) if not isinstance(k, (int, str)) else k: _jsafe(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [_jsafe(x) for x in o]
    if isinstance(o, (set, frozenset)):
        return sorted(_jsafe(x) for x in o)
    return o


def report_to_dict(report: "Report") -> dict:
    """JSON-ready dict (schema autosolve/1)."""
    d = {"schema": "autosolve/1"}
    for k in ("target", "outcome", "verdicts", "gates", "constraints", "solution", "patches", "listing",
              "input_model", "next_steps", "angr", "notes", "errors"):
        d[k] = _jsafe(getattr(report, k))
    return d


_GMN = {"jcc": "j", "setcc": "set", "cmovcc": "cmov"}


def _cut(s: str, n: int = 100) -> str:
    return s if len(s) <= n else s[:n - 1] + "…"


def _tag(c: str) -> str:
    return {"high": "[H]", "medium": "[M]", "low": "[L]"}.get(c, "[?]")


def _sec(label: str, body: list) -> list:
    """Label the first line, indent the rest, cut to 100 columns (ready-to-paste commands are never cut)."""
    out = []
    for i, ln in enumerate(body):
        full = (f"{label:<11}" if i == 0 else " " * 11) + ln
        out.append(full if ln.lstrip().startswith("recon.py ") else _cut(full))
    return out


def _angr_lines(a: AngrResult | None, deep: bool = False, budget: int = ANGR_TIMEOUT) -> list:
    if a is None:
        return []
    if a.status in ("absent", "skipped", "timeout", "error", "no-solution"):
        return [_cut(a.detail)]
    txt = (a.input or b"").decode("latin-1")
    txt = "".join(c if 0x20 <= ord(c) < 0x7F else f"\\x{ord(c):02x}" for c in txt.rstrip("\n"))
    ag = {True: "   agrees with static answer", False: "   DIFFERS from static answer", None: ""}[a.agrees]
    return [f"ANGR   ({budget} s budget, {a.seconds:.1f} s used)", f"  computed input: {txt}   [via angr]{ag}"]


def render_text(report: "Report", deep: bool = False, view: str = "all") -> str:
    """Compact text report (spec 16); ``view`` selects a stage-subcommand subset (16.3)."""
    t = report.target
    names = t.get("fnames", {})
    arch = {"x86_64": "x86-64", "x86": "x86"}.get(t.get("arch", ""), t.get("arch", "?"))
    head = (f"autosolve: {t.get('name', '?')}  {t.get('format', 'ELF?')} {arch}  "
            f"{'PIE' if t.get('pie') else 'non-PIE'}  {'stripped' if t.get('stripped') else 'not stripped'}  "
            f"{'static' if t.get('static') else 'dynamic'}   capstone: {'yes' if t.get('capstone') else 'no'}")
    L: list[str] = [_cut(head)]
    sol, gates = report.solution, report.gates
    cons_by_site: dict[int, Constraint] = {}
    for c in report.constraints:
        cons_by_site.setdefault(c.site, c)
    prim = [p for p in report.patches if p.primary]
    want = {"all": {"HEAD", "VERD", "INPUT", "DEC", "GATES", "SOLVE", "LIST", "PATCH", "NEXT", "ANGR", "NOTES"},
            "verdicts": {"VERD", "NOTES"}, "trace": {"VERD", "DEC", "GATES", "PREVIEW", "NOTES"},
            "constraints": {"VERD", "INPUT", "DEC", "GATES", "CONS", "NOTES"}, "listing": {"LIST"},
            "solve": {"INPUT", "CONS", "SOLVE", "NOTES"}, "patch": {"DEC", "GATES", "PATCH", "NOTES"},
            "angr": {"ANGR"}}[view]
    if "HEAD" in want:
        if report.outcome == "derived" and sol:
            hl = f"DERIVED {_tag(sol.conf)}  {sol.text}"
        elif report.outcome == "patch" and prim:
            p = prim[0]
            hl = (f"PATCH  {p.site:#x} {p.strategy} (off {p.offset:#x}: {_hexb(p.old)} -> {_hexb(p.new)})"
                  + (f"  +{len(prim) - 1} more" if len(prim) > 1 else ""))
        else:
            hl = "NEXT STEP  " + (report.next_steps[0] if report.next_steps else "no verdict strings matched")
        L += _sec("HEADLINE", [hl])
    if "VERD" in want and report.verdicts:
        body = []
        for v in report.verdicts:
            if v.refs:
                for r in v.refs[:2]:
                    fn = names.get(r.func, names.get(str(r.func), f"sub_{r.func:x}" if r.func else "?"))
                    body.append(f'{v.polarity} "{v.text[:30]}" @{v.addr:#x}  <- {r.site:#x} ({fn}, {r.via}, {r.printer or "no call"}) '
                                f'{_tag("high" if v.conf == "high" and r.conf == "high" else "medium" if v.conf == "high" or r.conf == "high" else "low")}')
            else:
                body.append(f'{v.polarity} "{v.text[:30]}" @{v.addr:#x}  (unreferenced) {_tag(v.conf)}')
        L += _sec("VERDICTS", body)
    im = report.input_model
    if "INPUT" in want and im.get("mode") not in (None, "unknown"):
        nl = next((n for n in report.notes if n.startswith("newline-strip")), "")
        s = f"{im['mode']} via {im.get('via')}" + (f" -> {im['buf']} ({im.get('cap')} B)" if im.get("buf") else "")
        L += _sec("INPUT", [s + (f"; {nl}" if nl else "")])
    dec = next((g for g in gates if g.deciding), None)
    if "DEC" in want and dec:
        loop = f", in loop x{dec.hits}" if dec.in_loop and dec.hits else (", in loop" if dec.in_loop else "")
        L += _sec("DECIDING", [f"{dec.addr:#x}  {_GMN[dec.kind]}{dec.cc}  ({dec.label}{loop})  "
                               f"success = {dec.success_edge}"])
    if "GATES" in want and gates:
        body = []
        lim = len(gates) if deep else 12
        for g in gates[:lim]:
            c = cons_by_site.get(g.addr)
            ct = c.text.split("   (gate")[0] if c else ""
            if c and "   for i" in c.text:
                ct = c.text.split("   (gate")[0].replace("   for ", ", ").replace(" + i", "+i").replace("i = ", "i=")
            body.append(f"#{g.n} {g.addr:#x} {_GMN[g.kind]}{g.cc:<3} "
                        f"{g.label + (' *' if g.deciding else ''):<24} {ct} {_tag(c.conf if c else g.conf)}")
        if len(gates) > lim:
            body.append(f"… {len(gates) - lim} more (--deep)")
        L += _sec("GATES", body)
    if "PREVIEW" in want and prim:
        L += _sec("PATCH", [f"preview: {p.site:#x} (off {p.offset:#x}) {_hexb(p.old)} -> {_hexb(p.new)}  {p.strategy}" for p in prim[:3]])
    if "CONS" in want and report.constraints:
        L += _sec("CONSTRAINTS", [f"#{c.n} {c.kind:<10} {c.text} {_tag(c.conf)}" for c in report.constraints])
    if "SOLVE" in want:
        if sol and sol.candidate is not None:
            L += _sec("SOLVE", [f"{sol.text}  {_tag(sol.conf)}  method {sol.method}  {sol.verified}"]
                      + ["trace: " + sol.trace[0]] + ["       " + x for x in sol.trace[1:5]]
                      + ([f"ambiguous positions: {sol.ambiguous}"] if sol.ambiguous else [])
                      + ([f"unknown positions: {sol.unknown}"] if sol.unknown else []))
        else:
            nun = sum(1 for c in report.constraints if c.kind == "unresolved")
            L += _sec("SOLVE", [f"no candidate ({nun} unresolved constraint{'s' if nun != 1 else ''})"])
    if "LIST" in want and report.listing:
        hdr = "(capstone mnemonics)" if t.get("capstone") else "(built-in decoder; install capstone for full mnemonics)"
        lines = report.listing
        if not deep and len(lines) > 40:
            ix = next((k for k, ln in enumerate(lines) if "*DECIDING*" in ln), len(lines) // 2)
            lo = max(0, min(ix - 20, len(lines) - 40))
            lines = lines[lo:lo + 40]
        L.append(_cut(f"{'LISTING':<11}{hdr}"))
        L += [_cut(ln) for ln in lines]
    if "PATCH" in want and report.patches:
        body = [f"primary ({len(prim)} patch{'es' if len(prim) != 1 else ''}"
                + ("; alternative to the derived answer):" if report.outcome == "derived" else "):")]
        for p in prim:
            body += [f"{p.site:#x} (off {p.offset:#x}) {_hexb(p.old)} -> {_hexb(p.new)}   {p.strategy}", "  " + p.elfpatch]
        for n in report.notes:
            if n.startswith("patch check"):
                body.append(n)
        for p in report.patches:
            if not p.primary:
                body += [f"alt {p.strategy}: {p.site:#x} (off {p.offset:#x}) {_hexb(p.old)} -> {_hexb(p.new)}", "  " + p.elfpatch]
        body += ["note: a patched binary prints the success message for any input; if the flag",
                 "      is the input, use the derived answer / angr instead."]
        L += _sec("PATCH", body)
    if "NEXT" in want and report.next_steps:
        L += _sec("NEXT STEPS", [f"{i}. {s}" for i, s in enumerate(report.next_steps, 1)])
    if "ANGR" in want and report.angr is not None:
        L += _angr_lines(report.angr, deep)
    if "NOTES" in want:
        nts = [n for n in report.notes if not n.startswith("patch check") and not n.startswith("newline-strip")]
        if nts:
            L += _sec("NOTES", nts[:(99 if deep else 6)] + ([f"… {len(nts) - 6} more (--deep)"] if len(nts) > 6 and not deep else []))
        if report.errors:
            L += _sec("ERRORS", [f"{len(report.errors)} error(s)"] + report.errors[:3])
    return "\n".join(L)


# ---------- CLI
USAGE = """autosolve usage:
  recon.py autosolve <elf> [options]                full chain: verdicts -> trace -> constraints
                                                     -> listing -> solve -> patch -> angr
  recon.py autosolve find-verdicts <elf> [options]  stage 1: verdict strings + reference sites
  recon.py autosolve trace <elf> [options]          stages 1-2: deciding branch(es) / gates
  recon.py autosolve constraints <elf> [options]    stages 1-3: ordered constraints
  recon.py autosolve listing <elf> [options]        stages 1-3 + annotated verdict region
  recon.py autosolve solve <elf> [options]          stages 1-3 + derived answer
  recon.py autosolve patch <elf> [-o OUT] [options] stages 1-3 + patch plan (writes OUT only with -o)
  recon.py autosolve angr <elf> [options]           stages 1-3 (for find/avoid) + Lane 2 only
  recon.py autosolve selftest                       run self-tests (--selftest also accepted)

options:
  --success REGEX      extra success-verdict pattern (repeatable, case-insensitive)
  --fail REGEX         extra failure-verdict pattern (repeatable, case-insensitive)
  --flag-format REGEX  extra flag regex, e.g. 'CyberSci\\{[^}]+\\}' (anchors ambiguous bytes)
  --func ADDR          analyse only the function containing ADDR (hex or decimal)
  --input stdin|argv   force the input model (default: auto-detect)
  --json               machine-readable report (schema autosolve/1)
  --deep               full listing, all gates, all paths, capstone length cross-check
  --no-angr            skip Lane 2 even if angr is installed
  --angr-timeout SECS  angr wall time (default 60, 5..1800)
  --max-steps N        walker step budget (default 200000)

examples:
  recon.py autosolve ./crackme
  recon.py autosolve ./crackme --success 'Access granted' --fail 'denied'
  recon.py autosolve patch ./crackme -o crackme.patched"""

_SUBS = {"find-verdicts": "verdicts", "trace": "trace", "constraints": "constraints", "listing": "listing",
         "solve": "solve", "patch": "patch", "angr": "constraints"}


class _UsageError(Exception):
    """Raised by the parser instead of exiting."""


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # type: ignore[override]
        raise _UsageError(message)


def _parse_args(rest: list) -> tuple:
    p = _Parser(prog="autosolve", add_help=False, allow_abbrev=False)
    p.add_argument("elf")
    p.add_argument("--success", action="append", default=[])
    p.add_argument("--fail", action="append", default=[])
    p.add_argument("--flag-format")
    p.add_argument("--func")
    p.add_argument("--input", choices=("stdin", "argv"), default="auto")
    p.add_argument("--json", action="store_true")
    p.add_argument("--deep", action="store_true")
    p.add_argument("--no-angr", action="store_true")
    p.add_argument("--angr-timeout", default=str(ANGR_TIMEOUT))
    p.add_argument("--max-steps", default=str(MAX_STEPS))
    p.add_argument("-o", "--output")
    ns = p.parse_args(rest)
    try:
        opts = Options(success_re=[re.compile(x, re.I) for x in ns.success], fail_re=[re.compile(x, re.I) for x in ns.fail],
                       flag_re=re.compile(ns.flag_format) if ns.flag_format else None,
                       func=int(ns.func, 0) if ns.func else None, deep=ns.deep, as_json=ns.json,
                       angr="off" if ns.no_angr else "auto",
                       angr_timeout=max(5, min(1800, int(ns.angr_timeout))), max_steps=int(ns.max_steps),
                       input_mode=ns.input)
        if opts.max_steps < 1:
            raise ValueError("--max-steps must be positive")
    except (re.error, ValueError) as exc:
        raise _UsageError(str(exc)) from exc
    return ns, opts


def _emit(text: str) -> None:
    print(text)
    sys.stdout.flush()


def run(args: list) -> int:
    """Registry entry point; exit codes per spec 5 (0 report, 1 input/patch failure, 2 usage)."""
    if not args or args[0] in ("-h", "--help"):
        print(USAGE)
        return 0
    if args[0] in ("selftest", "--selftest"):
        return 0 if selftest() else 1
    sub = args[0] if args[0] in _SUBS else "all"
    rest = args[1:] if sub != "all" else args
    if "-h" in rest or "--help" in rest:
        print(USAGE)
        return 0
    try:
        ns, opts = _parse_args(rest)
        if ns.output and sub != "patch":
            raise _UsageError("-o is only valid with the patch subcommand")
    except _UsageError as exc:
        print(f"autosolve: {exc}\n{USAGE}", file=sys.stderr)
        return 2
    try:
        with open(ns.elf, "rb") as fh:
            data = fh.read(MAX_INPUT + 1)
    except OSError as exc:
        print(f"autosolve: cannot read {ns.elf}: {exc.strerror or exc}", file=sys.stderr)
        return 1
    if not data:
        print(f"autosolve: {ns.elf} is empty", file=sys.stderr)
        return 1
    if data[:4] != b"\x7fELF":
        print(f"autosolve: {ns.elf} is not an ELF file", file=sys.stderr)
        return 1
    try:
        disasm.parse_elf(data[:MAX_INPUT])
    except disasm.ElfError as exc:
        print(f"autosolve: {ns.elf}: {exc}", file=sys.stderr)
        return 1
    stages = "all" if sub == "all" else _SUBS[sub]
    rep, ctx, tr, wr = _analyze(data, ns.elf, opts, stages)
    view = "all" if sub == "all" else {"find-verdicts": "verdicts"}.get(sub, sub)
    code = 0
    if opts.as_json:
        if sub in ("all", "angr") and ctx is not None:
            rep.angr = run_angr(ctx, tr, wr, opts, sol=rep.solution)
        _emit(json.dumps(report_to_dict(rep), indent=1))
    else:
        if sub != "angr":
            _emit(render_text(rep, opts.deep, view))
        if sub in ("all", "angr") and ctx is not None:
            rep.angr = run_angr(ctx, tr, wr, opts, sol=rep.solution)
            _emit("\n".join(_angr_lines(rep.angr, opts.deep, opts.angr_timeout)))
        if opts.deep and rep.angr is not None and rep.angr.status == "absent":
            _emit("(Kali/PEP 668: python3 -m venv ~/angr-venv && ~/angr-venv/bin/pip install angr, then run "
                  "~/angr-venv/bin/python3 toolkit/recon.py ... - prep only)")
    if sub == "angr" and rep.angr is not None and rep.angr.status in ("absent", "skipped") and opts.angr != "off":
        code = 1
    if sub == "patch" and ns.output:
        prim = [p for p in rep.patches if p.primary]
        try:
            if not prim:
                raise elfpatch.PatchError("no patch plan to apply")
            out = elfpatch.write_output(ns.elf, ns.output, _apply_patches(ctx, rep.patches), force=False)
            print(f"wrote {out} ({len(prim)} patches)")
            print(_verify_patch(ctx, rep.patches, opts))
        except (elfpatch.PatchError, OSError) as exc:
            print(f"autosolve: patch failed: {exc}", file=sys.stderr)
            code = 1
    return code


# ---------- selftest fixtures (in-memory ELF builders)
class _Asm:
    """Two-pass label assembler for fixture code only."""

    def __init__(self, bits: int = 64) -> None:
        self.bits = bits
        self.items: list[tuple] = []

    def raw(self, b: bytes | str) -> None:
        self.items.append(("raw", bytes.fromhex(b.replace(" ", "")) if isinstance(b, str) else b))

    def label(self, name: str) -> None:
        self.items.append(("label", name))

    def rel8(self, op: bytes, label: str) -> None:
        self.items.append(("rel8", op, label))

    def rel32(self, op: bytes, label: str) -> None:
        self.items.append(("rel32", op, label))

    def rip32(self, prefix: bytes, label: str, suffix: bytes = b"") -> None:
        self.items.append(("rip32", prefix, label, suffix))

    def abs32(self, prefix: bytes, label: str) -> None:
        self.items.append(("abs32", prefix, label))

    @staticmethod
    def _size(it: tuple) -> int:
        k = it[0]
        return {"raw": lambda: len(it[1]), "label": lambda: 0, "rel8": lambda: len(it[1]) + 1,
                "rel32": lambda: len(it[1]) + 4, "rip32": lambda: len(it[1]) + 4 + len(it[3]),
                "abs32": lambda: len(it[1]) + 4}[k]()

    def size(self) -> int:
        return sum(self._size(i) for i in self.items)

    def labels(self, base: int) -> dict[str, int]:
        out, pos = {}, base
        for it in self.items:
            if it[0] == "label":
                out[it[1]] = pos
            pos += self._size(it)
        return out

    def assemble(self, base: int, ext: dict[str, int]) -> bytes:
        lab = {**ext, **self.labels(base)}
        out, pos = b"", base
        for it in self.items:
            end = pos + self._size(it)
            k = it[0]
            if k == "raw":
                out += it[1]
            elif k == "rel8":
                out += it[1] + struct.pack("<b", lab[it[2]] - end)
            elif k == "rel32":
                out += it[1] + struct.pack("<i", lab[it[2]] - end)
            elif k == "rip32":
                out += it[1] + struct.pack("<i", lab[it[2]] - end) + it[3]
            elif k == "abs32":
                out += it[1] + struct.pack("<I", lab[it[2]])
            pos = end
        return out


def _build_elf(bits: int, text: _Asm, rodata: list, funcs: dict, plt: list | None = None) -> bytes:
    """Lay out an ET_EXEC ELF (one RX PT_LOAD) with .text/.rodata/.symtab (+ PLT/dynsym when ``plt``)."""
    base = 0x400000 if bits == 64 else 0x8048000
    al = lambda v, a=16: (v + a - 1) // a * a  # noqa: E731
    pos = 0x100
    secs: list[list] = []   # name, type, flags, addr, off, size, link, info, entsize, align
    ext: dict[str, int] = {}
    plt = plt or []
    pltoff = pos
    if plt:
        pos = al(pos + 16 * len(plt))
        for i, nm in enumerate(plt):
            ext[nm + "@plt"] = base + pltoff + 16 * i
    textoff = pos
    pos = al(pos + text.size())
    rodata_blob, roff = b"", pos
    for lab, bts in rodata:
        ext[lab] = base + roff + len(rodata_blob)
        rodata_blob += bts + b"\0"
        rodata_blob += b"\0" * ((-len(rodata_blob)) % 2)
    pos = al(pos + len(rodata_blob))
    gotoff = pos
    wsz = 8 if bits == 64 else 4
    if plt:
        pos = al(pos + wsz * (len(plt) + 3), 8)
    code = text.assemble(base + textoff, ext)
    tl = text.labels(base + textoff)
    blob = bytearray(b"\0" * pos)
    if plt:
        got0 = base + gotoff
        for i in range(len(plt)):
            stub = base + pltoff + 16 * i
            slot = got0 + wsz * (i + 3)
            if bits == 64:
                st = b"\xff\x25" + struct.pack("<i", slot - (stub + 6))
            else:
                st = b"\xff\x25" + struct.pack("<I", slot)
            blob[pltoff + 16 * i:pltoff + 16 * i + len(st)] = st + b"\xcc" * (16 - len(st))
    blob[textoff:textoff + len(code)] = code
    blob[roff:roff + len(rodata_blob)] = rodata_blob
    shn = b"\0"

    def nm(s: str) -> int:
        nonlocal shn
        o = len(shn)
        shn += s.encode() + b"\0"
        return o

    secs.append([0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    if plt:
        secs.append([nm(".plt"), 1, 6, base + pltoff, pltoff, 16 * len(plt), 0, 0, 16, 16])
    secs.append([nm(".text"), 1, 6, base + textoff, textoff, len(code), 0, 0, 0, 16])
    secs.append([nm(".rodata"), 1, 2, base + roff, roff, len(rodata_blob), 0, 0, 0, 2])
    extra = b""
    if plt:
        secs.append([nm(".got.plt"), 1, 3, base + gotoff, gotoff, wsz * (len(plt) + 3), 0, 0, wsz, 8])
        ds = b"\0" + b"".join(p.encode() + b"\0" for p in plt)
        dstr_off = [1]
        for p in plt[:-1]:
            dstr_off.append(dstr_off[-1] + len(p) + 1)
        dsym = b"\0" * (24 if bits == 64 else 16)
        for o in dstr_off:
            dsym += struct.pack("<IBBHQQ", o, 0x12, 0, 0, 0, 0) if bits == 64 else struct.pack("<IIIBBH", o, 0, 0, 0x12, 0, 0)
        rela = b""
        for i in range(len(plt)):
            slot = base + gotoff + wsz * (i + 3)
            rela += struct.pack("<QQq", slot, ((i + 1) << 32) | 7, 0) if bits == 64 else struct.pack("<II", slot, ((i + 1) << 8) | 7)
        extra_start = pos
        relaoff = al(extra_start, 8)
        dsymoff = al(relaoff + len(rela), 8)
        dstroff = dsymoff + len(dsym)
        pos = dstroff + len(ds)
        blob += b"\0" * (pos - len(blob))
        blob[relaoff:relaoff + len(rela)] = rela
        blob[dsymoff:dsymoff + len(dsym)] = dsym
        blob[dstroff:dstroff + len(ds)] = ds
        idx_dsym = len(secs) + 1
        secs.append([nm(".rela.plt"), 4 if bits == 64 else 9, 2, base + relaoff, relaoff, len(rela), idx_dsym, 0,
                     24 if bits == 64 else 8, 8])
        secs[-1][1] = 4 if bits == 64 else 9
        secs.append([nm(".dynsym"), 11, 2, base + dsymoff, dsymoff, len(dsym), idx_dsym + 1, 1,
                     24 if bits == 64 else 16, 8])
        secs.append([nm(".dynstr"), 3, 2, base + dstroff, dstroff, len(ds), 0, 0, 0, 1])
        if bits == 32:
            secs[-3][1] = 9
    textidx = 2 if plt else 1
    strt = b"\0"
    syms = b"\0" * (24 if bits == 64 else 16)
    for fn, lab in funcs.items():
        so = len(strt)
        strt += fn.encode() + b"\0"
        v = tl[lab]
        syms += struct.pack("<IBBHQQ", so, 0x12, 0, textidx, v, 1) if bits == 64 else struct.pack("<IIIBBH", so, v, 1, 0x12, 0, textidx)
    symoff = al(pos, 8)
    stroff = symoff + len(syms)
    blob += b"\0" * (stroff + len(strt) - len(blob))
    blob[symoff:symoff + len(syms)] = syms
    blob[stroff:stroff + len(strt)] = strt
    secs.append([nm(".symtab"), 2, 0, 0, symoff, len(syms), len(secs) + 1, 1, 24 if bits == 64 else 16, 8])
    secs.append([nm(".strtab"), 3, 0, 0, stroff, len(strt), 0, 0, 0, 1])
    secs[-2][7] = textidx
    shs_name = nm(".shstrtab")
    shoff_str = stroff + len(strt)
    secs.append([shs_name, 3, 0, 0, shoff_str, len(shn), 0, 0, 0, 1])
    blob += b"\0" * (shoff_str + len(shn) - len(blob))
    blob[shoff_str:shoff_str + len(shn)] = shn
    shoff = al(len(blob), 8)
    blob += b"\0" * (shoff - len(blob))
    for s in secs:
        n_, t, fl, ad, of, sz, lk, inf, es, aln = s
        blob += struct.pack("<IIQQQQIIQQ", n_, t, fl, ad, of, sz, lk, inf, aln, es) if bits == 64 else \
            struct.pack("<IIIIIIIIII", n_, t, fl, ad, of, sz, lk, inf, aln, es)
    filesz = shoff
    if bits == 64:
        hdr = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\0" * 8 + struct.pack(
            "<HHIQQQIHHHHHH", 2, 0x3E, 1, tl["main"], 64, shoff, 0, 64, 56, 1, 64, len(secs), len(secs) - 1)
        ph = struct.pack("<IIQQQQQQ", 1, 7, 0, base, base, filesz, filesz, 0x1000)
    else:
        hdr = b"\x7fELF" + bytes([1, 1, 1, 0]) + b"\0" * 8 + struct.pack(
            "<HHIIIIIHHHHHH", 2, 0x03, 1, tl["main"], 52, shoff, 0, 52, 32, 1, 40, len(secs), len(secs) - 1)
        ph = struct.pack("<IIIIIIII", 1, 0, base, base, filesz, filesz, 7, 0x1000)
    blob[:len(hdr)] = hdr
    blob[len(hdr):len(hdr) + len(ph)] = ph
    return bytes(blob)


F1_FLAG = b"flag{x0r_t4bl3}"
F2_FLAG = b"ctf{r0l_4dd}"
F4_SECRET = b"s3cr3t!!"
F5_SECRET = b"CyberSci{plt_0k}"


def _rol8(v: int, n: int) -> int:
    return ((v << n) | (v >> (8 - n))) & 0xFF


def _fx_f1(ok: bytes = b"Correct!", bad: bytes = b"Wrong.", extra: bool = True) -> bytes:
    a = _Asm(64)
    a.label("main")
    a.raw("55 4889e5 4883ec60 488d7db0 be40000000 31d2")
    a.rel32(b"\xe8", "fgets")
    a.raw("488d7db0")
    a.rel32(b"\xe8", "strlen")
    a.raw("4883f80f")
    a.rel32(b"\x0f\x85", "fail")
    a.raw("c745ac00000000")
    a.rel8(b"\xeb", "cond")
    a.label("body")
    a.raw("8b45ac 4898 0fb64405b0 83f042 89c2 8b45ac 4898")
    a.rip32(b"\x48\x8d\x0d", "TABLE")
    a.raw("0fb60408 38c2")
    a.rel8(b"\x75", "fail")
    a.raw("8345ac01")
    a.label("cond")
    a.raw("837dac0e")
    a.rel8(b"\x7e", "body")
    a.rip32(b"\x48\x8d\x3d", "S_OK")
    a.rel32(b"\xe8", "puts")
    a.raw("b800000000 c9c3")
    a.label("fail")
    a.rip32(b"\x48\x8d\x3d", "S_BAD")
    a.rel32(b"\xe8", "puts")
    a.raw("b801000000 c9c3")
    for n in ("fgets", "strlen", "puts"):
        a.label(n)
        a.raw("c3")
    table = bytes(c ^ 0x42 for c in F1_FLAG)
    ro = [("TABLE", table), ("S_OK", ok), ("S_BAD", bad)] + ([("S_X", b"Try again later")] if extra else [])
    return _build_elf(64, a, ro, {"main": "main", "fgets": "fgets", "strlen": "strlen", "puts": "puts"})


def _fx_check_main(a: _Asm, ok: bytes, bad: bytes) -> None:
    a.label("main")
    a.raw("4883ec48 4889e7")
    a.rel32(b"\xe8", "gets")
    a.raw("4889e7")
    a.rel32(b"\xe8", "check")
    a.raw("85c0")
    a.rel8(b"\x74", "fail")
    a.rip32(b"\x48\x8d\x3d", "S_OK")
    a.rel32(b"\xe8", "puts")
    a.raw("4883c448 c3")
    a.label("fail")
    a.rip32(b"\x48\x8d\x3d", "S_BAD")
    a.rel32(b"\xe8", "puts")
    a.raw("4883c448 c3")
    for n in ("gets", "puts"):
        a.label(n)
        a.raw("c3")


def _fx_f2() -> bytes:
    a = _Asm(64)
    _fx_check_main(a, b"", b"")
    a.label("check")
    for i, c in enumerate(F2_FLAG):
        k = i % 4
        if k == 0:
            a.raw(bytes([0x80, 0x7F, i, c]))
        else:
            a.raw(bytes([0x0F, 0xB6, 0x47, i]))
            if k == 1:
                a.raw(bytes([0x04, 5, 0x3C, (c + 5) & 0xFF]))
            elif k == 2:
                a.raw(bytes([0xC0, 0xC0, 3, 0x3C, _rol8(c, 3)]))
            else:
                a.raw(bytes([0x34, 0x5A, 0x3C, c ^ 0x5A]))
        a.rel8(b"\x75", "r0")
    a.raw("807f0c00 0f94c0 0fb6c0 c3")
    a.label("r0")
    a.raw("31c0c3")
    return _build_elf(64, a, [("S_OK", b"Access granted"), ("S_BAD", b"Access denied")],
                      {"main": "main", "check": "check", "gets": "gets", "puts": "puts"})


def _fx_f3() -> bytes:
    a = _Asm(64)
    _fx_check_main(a, b"", b"")
    a.label("check")
    a.raw("f20f38f007 3d78563412 0f94c0 0fb6c0 c3")
    return _build_elf(64, a, [("S_OK", b"Correct"), ("S_BAD", b"Incorrect")],
                      {"main": "main", "check": "check", "gets": "gets", "puts": "puts"})


def _fx_f4() -> bytes:
    a = _Asm(32)
    a.label("main")
    a.raw("55 89e5 83ec58 8d45b0 50")
    a.rel32(b"\xe8", "gets")
    a.raw("83c404 8d45b0 50")
    a.rel32(b"\xe8", "strlen")
    a.raw("83c404 83f808")
    a.rel8(b"\x75", "fail")
    a.raw("8d45b0 50")
    a.abs32(b"\x68", "SECRET")
    a.rel32(b"\xe8", "strcmp")
    a.raw("83c408 85c0")
    a.rel8(b"\x75", "fail")
    a.abs32(b"\x68", "S_OK")
    a.rel32(b"\xe8", "puts")
    a.raw("83c404 31c0 c9 c3")
    a.label("fail")
    a.abs32(b"\x68", "S_BAD")
    a.rel32(b"\xe8", "puts")
    a.raw("83c404 b801000000 c9 c3")
    for n in ("gets", "strlen", "strcmp", "puts"):
        a.label(n)
        a.raw("c3")
    return _build_elf(32, a, [("SECRET", F4_SECRET), ("S_OK", b"Nice! correct"), ("S_BAD", b"Nope, try again")],
                      {"main": "main", "gets": "gets", "strlen": "strlen", "strcmp": "strcmp", "puts": "puts"})


def _fx_f5() -> bytes:
    a = _Asm(64)
    a.label("main")
    a.raw("55 4889e5 4883ec60 488d7db0 be40000000 31d2")
    a.rel32(b"\xe8", "fgets@plt")
    a.rip32(b"\x48\x8d\x35", "NL")
    a.raw("488d7db0")
    a.rel32(b"\xe8", "strcspn@plt")
    a.raw("c64405b000")
    a.rip32(b"\x48\x8d\x35", "SECRET")
    a.raw("488d7db0")
    a.rel32(b"\xe8", "strcmp@plt")
    a.raw("85c0")
    a.rel8(b"\x75", "fail")
    a.rip32(b"\x48\x8d\x3d", "S_OK")
    a.rel32(b"\xe8", "puts@plt")
    a.raw("b800000000 c9c3")
    a.label("fail")
    a.rip32(b"\x48\x8d\x3d", "S_BAD")
    a.rel32(b"\xe8", "puts@plt")
    a.raw("b801000000 c9c3")
    return _build_elf(64, a, [("NL", b"\n"), ("SECRET", F5_SECRET), ("S_OK", b"Congratulations!"),
                              ("S_BAD", b"Wrong!")], {"main": "main"}, plt=["fgets", "strcspn", "strcmp", "puts"])


def _fx_f7() -> bytes:
    a = _Asm(64)
    a.label("main")
    a.raw("4883ec48 4889e7")
    a.rel32(b"\xe8", "gets")
    a.raw("4889e7 803f41")
    a.rip32(b"\x48\x8d\x3d", "S_OK")
    a.rip32(b"\x48\x8d\x05", "S_BAD")
    a.raw("480f45f8")
    a.rel32(b"\xe8", "puts")
    a.raw("4883c448 c3")
    for n in ("gets", "puts"):
        a.label(n)
        a.raw("c3")
    return _build_elf(64, a, [("S_OK", b"Correct!"), ("S_BAD", b"Wrong.")],
                      {"main": "main", "gets": "gets", "puts": "puts"})


def _fx_f6() -> bytes:
    return _fx_f1(b"AAAA", b"BBBB", extra=False)


# ---------- selftest
_CORPUS = [  # (mode, hex, length, mnem | None -> invalid | "other" -> unmodelled)
    (64, "55", 1, "push"), (64, "4889e5", 3, "mov"), (64, "f30f1efa", 4, "endbr64"), (64, "4883ec60", 4, "sub"),
    (64, "4881ec00010000", 7, "sub"), (64, "488d3d00000000", 7, "lea"), (64, "4c8d0500000000", 7, "lea"),
    (64, "e800000000", 5, "call"), (64, "e900000000", 5, "jmp"), (64, "ebfe", 2, "jmp"), (64, "0f8500000000", 6, "jcc"),
    (64, "75fe", 2, "jcc"), (64, "c745ac00000000", 7, "mov"), (64, "66c745fe3412", 6, "mov"), (64, "c645ff41", 4, "mov"),
    (64, "48b88877665544332211", 10, "mov"), (64, "0fb64405b0", 5, "movzx"), (64, "0fbe07", 3, "movsx"),
    (64, "4863d0", 3, "movsxd"), (64, "4898", 2, "cdqe"), (64, "488b45f8", 4, "mov"),
    (64, "64488b042528000000", 9, "mov"), (64, "807f0500", 4, "cmp"), (64, "3c63", 2, "cmp"), (64, "3d78563412", 5, "cmp"),
    (64, "38c2", 2, "cmp"), (64, "83f042", 3, "xor"), (64, "345a", 2, "xor"), (64, "0405", 2, "add"),
    (64, "c0c003", 3, "rol"), (64, "d1e0", 2, "shl"), (64, "d3e8", 2, "shr"), (64, "f6c201", 3, "test"),
    (64, "f7c100010000", 6, "test"), (64, "f7d8", 2, "neg"), (64, "f6d0", 2, "not"), (64, "69c039300000", 6, "imul"),
    (64, "6bc007", 3, "imul"), (64, "0fafc2", 3, "imul"), (64, "0f94c0", 3, "setcc"), (64, "480f45f8", 4, "cmovcc"),
    (64, "85c0", 2, "test"), (64, "c3", 1, "ret"), (64, "c20800", 3, "ret"), (64, "c9", 1, "leave"),
    (64, "c8100000", 4, "enter"), (64, "0f05", 2, "syscall"), (64, "ff2500000000", 6, "jmp"), (64, "ffd0", 2, "call"),
    (64, "41ffd4", 3, "call"), (64, "f348ab", 3, "stos"), (64, "660f1f440000", 6, "nop"), (64, "0f1f8000000000", 7, "nop"),
    (64, "662e0f1f840000000000", 10, "nop"), (64, "a10010400000000000", 9, "mov"), (64, "f20f38f007", 5, "other"),
    (64, "660f6f0500000000", 8, "other"), (64, "660f74c1", 4, "other"), (64, "660fd7c0", 4, "other"),
    (64, "660f3a0fc104", 6, "other"), (64, "c5f96f0500000000", 8, "other"), (64, "c4e27900c1", 5, "other"),
    (64, "c4e3790fc104", 6, "other"), (64, "d9ee", 2, "other"), (64, "0f0b", 2, "ud2"), (64, "06", 0, None),
    (64, "60", 0, None), (32, "6800200408", 5, "push"), (32, "c70424 00200408", 7, "mov"),
    (32, "c744240400000000", 8, "mov"), (32, "8d8300e0ffff", 6, "lea"), (32, "65a114000000", 6, "mov"),
    (32, "66b83412", 4, "mov"), (32, "b801000000", 5, "mov"), (32, "cd80", 2, "int"), (32, "83c404", 3, "add"),
    (32, "40", 1, "inc"), (32, "c506", 2, "other"), (32, "c5f96fc1", 4, "other")]


class _FakeProc:
    """Stand-in for a finished child process (selftest only; nothing is spawned)."""

    def __init__(self, stdout: bytes, stderr: bytes = b"", returncode: int = 0) -> None:
        self.stdout, self.stderr, self.returncode = stdout, stderr, returncode


def selftest() -> bool:
    """Registry-contract self-test (S1-S16): fixtures are built in memory; no capstone / angr needed."""
    global _FIND_SPEC, _ANGR_RUNNER, _CS
    t0 = time.time()
    ok = True

    def check(name: str, cond: Any) -> None:
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
        ok &= bool(cond)

    def cap(args: list) -> tuple:
        o, e = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(o), contextlib.redirect_stderr(e):
            try:
                rc = run(args)
            except SystemExit as exc:
                rc = int(exc.code or 0)
        return rc, o.getvalue(), e.getvalue()

    def safe(name: str, fn: Callable[[], Any]) -> None:
        try:
            check(name, fn())
        except Exception as exc:  # noqa: BLE001
            check(f"{name} (raised {type(exc).__name__}: {exc})", False)

    saved = (_FIND_SPEC, _ANGR_RUNNER, _CS)
    tmp = tempfile.mkdtemp(prefix="autosolve-st-")
    try:
        _FIND_SPEC = lambda n: None  # noqa: E731 - hosts differ: detection is injected
        fx = {"f1": _fx_f1(), "f2": _fx_f2(), "f3": _fx_f3(), "f4": _fx_f4(), "f5": _fx_f5(), "f6": _fx_f6()}
        paths = {}
        for k, v in fx.items():
            paths[k] = os.path.join(tmp, k)
            with open(paths[k], "wb") as fh:
                fh.write(v)
        R = {k: analyze(v, paths[k], Options()) for k, v in fx.items()}

        def s1() -> bool:
            src = open(__file__, encoding="utf-8").read()
            tree = ast.parse(src)
            forb = {"socket", "urllib", "http", "requests", "ftplib", "smtplib", "telnetlib", "angr", "claripy"}
            subcalls, bad = [], []
            for n in ast.walk(tree):
                if isinstance(n, ast.Import):
                    bad += [a.name for a in n.names if a.name.split(".")[0] in forb]
                elif isinstance(n, ast.ImportFrom) and (n.module or "").split(".")[0] in forb:
                    bad.append(n.module)
                elif isinstance(n, ast.Call):
                    f = n.func
                    if isinstance(f, ast.Name) and f.id in ("eval", "exec", "compile"):
                        bad.append(f.id)
                    if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name):
                        if (f.value.id == "os" and f.attr in ("system", "popen")) or f.value.id == "ctypes":
                            bad.append(f"{f.value.id}.{f.attr}")
                        if f.value.id == "subprocess":
                            subcalls.append(n)
                    if any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value for k in n.keywords):
                        bad.append("shell=True")
            fn = next(x for x in ast.walk(tree) if isinstance(x, ast.FunctionDef) and x.name == "_run_angr_child")
            inside = [c for c in ast.walk(fn) if c in subcalls]
            a0 = subcalls[0].args[0] if subcalls else None
            argv_ok = isinstance(a0, ast.List) and ast.unparse(a0.elts[0]) == "sys.executable"
            return not bad and len(subcalls) == 1 and len(inside) == 1 and argv_ok
        safe("S1 safety/offline lint (no network, eval, shell; one subprocess = angr helper)", s1)

        def s2() -> bool:
            for mode, h, n, mn in _CORPUS:
                i = decode(bytes.fromhex(h), 0, 0x1000, mode)
                if mn is None:
                    if i is not None:
                        return False
                    continue
                if i is None or i.size != n or (mn == "other" and i.modelled) or \
                        (mn != "other" and mn not in (i.mnem, i.flow.split("-")[0])):
                    return False
            if disasm.capstone is not None:
                ctx = BinCtx(fx["f1"], "f1")
                f = ctx.func(ctx.main)
                for i in f.insns.values():
                    cs = disasm.capstone
                    md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
                    got = list(md.disasm(i.raw, i.addr))
                    if not got or got[0].size != i.size:
                        return False
            return len(_CORPUS) >= 60
        safe("S2 decoder corpus (Appendix C, both modes)", s2)

        def s3() -> bool:
            r = R["f1"]
            su = [v for v in r.verdicts if v.polarity == "success"]
            fa = [v for v in r.verdicts if v.polarity == "failure" and v.refs]
            unref = [v for v in r.verdicts if not v.refs]
            g = {x.n: x for x in r.gates}
            txt = render_text(r)
            lens = [c for c in r.constraints if c.kind == "length"]
            loop = [c for c in r.constraints if "^ 0x42" in c.text and "i = 0..14" in c.text]
            pr = [p for p in r.patches if p.primary]
            return (len(su) == 1 and su[0].conf == "high" and su[0].refs[0].via == "rip-rel" and su[0].refs[0].printer == "puts"
                    and len(fa) == 1 and any(v.text == "Try again later" for v in unref)
                    and len(r.gates) == 2 and g[2].deciding and g[2].in_loop and g[2].hits == 15
                    and lens and lens[0].text == "LEN == 15" and loop
                    and r.solution and r.solution.candidate == F1_FLAG and r.solution.conf == "high"
                    and r.solution.verified.startswith("re-walk ok") and r.outcome == "derived"
                    and len(pr) == 2 and pr[0].old[:2] == b"\x0f\x85" and pr[0].new == b"\x90" * 6
                    and pr[1].old[0] == 0x75 and pr[1].new == b"\x90\x90"
                    and pr[0].elfpatch.startswith("recon.py elfpatch nop ") and "--len 6" in pr[0].elfpatch
                    and len(txt.splitlines()) <= 90
                    and max(len(x) for x in txt.splitlines() if not x.lstrip().startswith("recon.py ")) <= 100)
        safe("S3 F1 end-to-end (xor-table loop, derived [H], 2-patch plan, compact report)", s3)

        def s4() -> bool:
            r = R["f2"]
            dec = [g for g in r.gates if g.deciding]
            inside = [g for g in r.gates if g.func != dec[0].func]
            pr = [p for p in r.patches if p.primary]
            rt = [p for p in r.patches if p.strategy == "ret-true"]
            return (len(dec) == 1 and dec[0].label.startswith("return value of check") and len(inside) == 13
                    and r.solution and r.solution.candidate == F2_FLAG and r.solution.conf == "high"
                    and r.solution.verified.startswith("re-walk ok") and len(pr) == 1 and pr[0].old[0] == 0x74
                    and pr[0].new == b"\x90\x90" and rt and rt[0].new == bytes.fromhex("b801000000c3"))
        safe("S4 F2 check() with mixed transforms + setcc return (funnel = 1 patch, ret-true alt)", s4)

        def s5() -> bool:
            r = R["f3"]
            inc = [v for v in r.verdicts if v.text == "Incorrect"]
            pr = [p for p in r.patches if p.primary]
            nx = "\n".join(r.next_steps)
            global _FIND_SPEC, _ANGR_RUNNER
            _FIND_SPEC = lambda n: object()  # noqa: E731
            _ANGR_RUNNER = lambda cfg, t: _FakeProc(b'{"status":"ok","input_hex":"41"}\n')
            _rc, out, _e = cap([paths["f3"]])
            _FIND_SPEC = lambda n: None  # noqa: E731
            return (inc and inc[0].polarity == "failure"
                    and any(c.kind == "unresolved" and "crc32" in c.text for c in r.constraints)
                    and not (r.solution and r.solution.candidate is not None and r.solution.conf in ("high", "medium"))
                    and r.outcome == "patch" and len(pr) == 1 and pr[0].old[0] == 0x74
                    and "disasm range" in nx and "break *0x" in nx and "computed input: A" in out)
        safe("S5 F3 unmodelled crc32 (fail-first rule, unresolved -> patch + next steps, fake angr)", s5)

        def s6() -> bool:
            r = R["f4"]
            return (r.verdicts[0].refs[0].via == "push-imm32" and any(c.text == "LEN == 8" for c in r.constraints)
                    and any(c.kind == "str-eq" for c in r.constraints) and r.solution.candidate == F4_SECRET
                    and r.solution.conf == "high" and r.solution.method == "strcmp-literal" and r.outcome == "derived")
        safe("S6 F4 i386 push-imm32 + strcmp literal", s6)

        def s7() -> bool:
            r = R["f5"]
            ctx = BinCtx(fx["f5"], "f5")
            r2 = analyze(fx["f5"], "f5", Options(flag_re=re.compile(r"CyberSci\{[^}]+\}")))
            return (set(ctx.plt.values()) == {"fgets", "strcspn", "strcmp", "puts"}
                    and any(n.startswith("newline-strip idiom") for n in r.notes)
                    and r.solution.candidate == F5_SECRET and r.solution.conf == "high" and r2.solution.flag_match)
        safe("S7 F5 dynamic PLT names + newline-strip idiom + --flag-format", s7)

        def s8() -> bool:
            r = R["f6"]
            rc, _o, _e = cap([paths["f6"]])
            r2 = analyze(fx["f6"], "f6", Options(success_re=[re.compile("AAAA", re.I)], fail_re=[re.compile("BBBB", re.I)]))
            return (r.outcome == "guidance" and "--success" in r.next_steps[0] and rc == 0
                    and r2.outcome == "derived" and r2.solution.candidate == F1_FLAG)
        safe("S8 F6 no verdicts -> guidance; --success/--fail recover the answer", s8)

        def s9() -> bool:
            r = R["f1"]
            pd = _apply_patches(BinCtx(fx["f1"], "f1"), r.patches)
            chk = _verify_patch(BinCtx(fx["f1"], "f1"), r.patches, Options())
            out = os.path.join(tmp, "f1.patched")
            rc, o, _e = cap(["patch", paths["f1"], "-o", out])
            data = open(out, "rb").read() if os.path.exists(out) else b""
            prim = [p for p in r.patches if p.primary]
            offs_ok = all(data[p.offset:p.offset + len(p.new)] == p.new for p in prim)
            same = data[:prim[0].offset] == fx["f1"][:prim[0].offset]
            rc2, _o2, _e2 = cap(["patch", paths["f1"], "-o", paths["f1"]])
            untouched = open(paths["f1"], "rb").read() == fx["f1"]
            return ("0 input-dependent" in chk and pd != fx["f1"] and rc == 0 and offs_ok and same and "wrote" in o
                    and rc2 == 1 and untouched)
        safe("S9 patch roundtrip (in-memory check, -o writes, in-place refused)", s9)

        def s10() -> bool:
            global _FIND_SPEC, _ANGR_RUNNER
            strip = lambda t: [l for l in t.splitlines() if not l.startswith("angr:") and not l.startswith("ANGR")]  # noqa: E731
            _rc, absent, _e = cap([paths["f1"]])
            _rc, off, _e = cap([paths["f1"], "--no-angr"])
            line = [l for l in absent.splitlines() if l.startswith("angr:")]
            ok1 = strip(absent) == strip(off) and line == [ANGR_ABSENT_LINE]
            _FIND_SPEC = lambda n: object()  # noqa: E731

            timeout_exc = subprocess.TimeoutExpired

            def boom(cfg: dict, t: int) -> Any:
                raise timeout_exc("x", t)
            _ANGR_RUNNER = boom
            rc_t, ot, _e = cap([paths["f1"]])
            _ANGR_RUNNER = lambda cfg, t: _FakeProc(b"garbage", b"oops")  # noqa: E731
            rc_g, og, _e = cap([paths["f1"]])
            ok2 = rc_t == 0 and "timed out" in ot and strip(ot) == strip(absent) and rc_g == 0 and "angr: error" in og
            _FIND_SPEC = lambda n: None  # noqa: E731
            rc_a, oa, _e = cap(["angr", paths["f1"]])
            ast.parse(_ANGR_HELPER)
            return ok1 and ok2 and rc_a == 1 and oa.strip() == ANGR_ABSENT_LINE and len(_ANGR_HELPER.splitlines()) <= 80
        safe("S10 angr absent / timeout / garbage via injection; helper parses", s10)

        def s11() -> bool:
            res = {}
            for sub in ("find-verdicts", "trace", "constraints", "listing", "solve", "patch"):
                rc, o, _e = cap([sub, paths["f1"]])
                res[sub] = (rc, o)
            g2 = R["f1"].gates[1].addr
            return (all(v[0] == 0 for v in res.values())
                    and "GATES" not in res["find-verdicts"][1] and "HEADLINE" not in res["find-verdicts"][1]
                    and f"{g2:#x}" in res["trace"][1] and "CONSTRAINTS" not in res["trace"][1]
                    and "GATE#2" in res["listing"][1] and "VERDICT success" in res["listing"][1]
                    and "SOLVE" in res["solve"][1] and "PATCH" in res["patch"][1] and "SOLVE" not in res["patch"][1])
        safe("S11 subcommands print only their sections", s11)

        def s12() -> bool:
            for kw in ("ptrace", "patch-memory", "vmmap"):
                if not gdbkit.search_recipes(kw):
                    return False

            def helptxt(m: Any) -> str:
                o = io.StringIO()
                with contextlib.redirect_stdout(o), contextlib.redirect_stderr(o):
                    try:
                        m.run(["-h"])
                    except SystemExit:
                        pass
                return o.getvalue()
            mods = {"elfpatch": elfpatch, "disasm": disasm, "gdbkit": gdbkit, "revauto": revauto,
                    "hashid": sys.modules.get(f"{__package__}.hashid") if __package__ else sys.modules.get("hashid")}
            if mods["hashid"] is None:
                mods["hashid"] = importlib.import_module(f"{__package__}.hashid" if __package__ else "hashid")
            texts = {k: helptxt(m) for k, m in mods.items()}
            lines = list(R["f3"].next_steps) + [p.elfpatch for r in R.values() for p in r.patches]
            lines += ["recon.py elfpatch nop", "recon.py disasm range", "recon.py gdbkit script", "recon.py gdbkit find",
                      "recon.py hashid id", "recon.py revauto"]
            for ln in lines:
                for m in re.finditer(r"recon\.py (\w+) (\w+)", ln):
                    mod, sub = m.groups()
                    if mod in texts and sub in ("nop", "patch", "flip", "range", "script", "find", "id") \
                            and re.search(rf"\b{sub}\b", texts[mod]) is None:
                        return False
            return True
        safe("S12 every referenced toolkit command/recipe exists", s12)

        def s13() -> bool:
            global _CS
            outs = []
            for cs in (None, disasm.capstone):
                _CS = cs
                row = []
                for k in ("f1", "f2"):
                    d = report_to_dict(analyze(fx[k], paths[k], Options()))
                    d.pop("listing")
                    d["target"].pop("capstone")
                    row.append(json.dumps(d, sort_keys=True))
                outs.append(row)
            _CS = None
            return outs[0] == outs[1]
        safe("S13 capstone independence (Lane 1 identical with/without)", s13)

        def s14() -> bool:
            rnd = random.Random(1234)
            f1 = fx["f1"]
            cases = [b"", b"\x7fELF", b"MZ" + b"\0" * 200]
            cases += [f1[:rnd.randrange(8, len(f1))] for _ in range(10)]
            for _ in range(5):
                b = bytearray(f1)
                for j in range(0x100, 0x190):
                    b[j] = rnd.randrange(256)
                cases.append(bytes(b))
            arm = bytearray(f1)
            arm[18:20] = struct.pack("<H", 0x28)
            cases.append(bytes(arm))
            for c in cases:
                analyze(c, "fuzz", Options(max_steps=3000))
            ra = analyze(bytes(arm), "arm", Options())
            return any("non-x86" in n for n in ra.notes) and ra.outcome == "guidance"
        safe("S14 robustness fuzz (truncations, random .text, PE header, ARM ELF)", s14)

        def s15() -> bool:
            bare, _o, _e = cap([])
            hh, uo, _e = cap(["-h"])
            bog, _o, eb = cap([paths["f1"], "--bogus"])
            rx, _o, _e = cap([paths["f1"], "--success", "("])
            miss, _o, _e = cap([os.path.join(tmp, "nope")])
            nonelf = os.path.join(tmp, "junk")
            open(nonelf, "wb").write(b"hello world")
            ne, _o, _e = cap([nonelf])
            rj, oj, _e = cap([paths["f1"], "--json", "--no-angr"])
            js = json.loads(oj)
            return (bare == 0 and hh == 0 and "autosolve usage:" in uo and bog == 2 and "usage" in eb and rx == 2 and miss == 1
                    and ne == 1 and rj == 0 and js["schema"] == "autosolve/1" and js["outcome"] == "derived"
                    and list(js) == ["schema", "target", "outcome", "verdicts", "gates", "constraints", "solution", "patches",
                                     "listing", "input_model", "next_steps", "angr", "notes", "errors"])
        safe("S15 CLI contract (exit codes 0/1/2, --json schema)", s15)

        def s16() -> bool:
            r = analyze(fx["f1"], "f1", Options(max_steps=50))
            return any("walker step budget exhausted" in n for n in r.notes) and r.outcome == "patch"
        safe("S16 budgets (--max-steps note, falls back to patch)", s16)

        def s17() -> bool:
            r = analyze(_fx_f7(), "f7", Options())
            pr = [p for p in r.patches if p.primary]
            return (any(g.kind == "cmovcc" for g in r.gates) and r.solution is not None
                    and r.solution.candidate == b"A" and r.solution.conf == "high"
                    and len(pr) == 1 and pr[0].old == bytes.fromhex("480f45f8") and pr[0].new == b"\x90" * 4)
        safe("S17 F7 cmov verdict select (cmovcc gate, nop-the-move patch, solution 'A')", s17)
    finally:
        _FIND_SPEC, _ANGR_RUNNER, _CS = saved
        shutil.rmtree(tmp, ignore_errors=True)
    dt = time.time() - t0
    check(f"runtime {dt:.1f}s (budget < 4 s, hard limit 20 s)", dt < 20)
    print("selftest:", "OK" if ok else "FAILED")
    return ok


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
