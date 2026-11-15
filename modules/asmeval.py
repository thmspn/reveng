"""ASMEVAL: static x86 assembly evaluator (AT&T and Intel syntax), for "what is in eax after this
runs?" / "what does asm1(0x6fa) return?" style questions.

The listing is *parsed* and then interpreted by a small from-scratch evaluator over a whitelist of
instructions (mov/movzx/movsx, add, sub, imul, xor, and, or, not, neg, shl/sal/shr/sar/rol/ror,
cmp, test, lea, push/pop, inc/dec, xchg, nop, cdq/cdqe/cqo, leave, ret, conditional jumps, jmp,
and call when the target is inside the parsed file).  Nothing is assembled, linked or executed.

Values are either concrete integers or *unknown* (``?``).  Unknown inputs (for example a function
argument you did not supply) propagate through arithmetic; a branch that depends on an unknown flag,
an unsupported instruction, a call to an outside symbol or the step cap stops evaluation and the
result is printed honestly as **PARTIAL** with the last known register state.

Accepted listings: plain ``.S`` / ``.asm`` text, gdb ``disassemble`` dumps (``0x... <+N>:``), and
``objdump -d`` output.  Pure stdlib, fully offline.
"""
from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from typing import Callable, Optional

NAME = "asmeval"
DESCRIPTION = "Static x86 asm evaluator (AT&T/Intel): final registers, or a function's return value for given args"

DEFAULT_MAX_STEPS = 100_000
RET_SENTINEL = 0x0DEAD000   # fake return address meaning "returned to the caller"
RET_BASE = 0x0DEAE000       # fake return addresses for in-file calls: RET_BASE + instruction index


class Stop(Exception):
    """Evaluation cannot continue (unsupported/unknown); message explains why."""


# --------------------------------------------------------------------------- registers

def _build_regs() -> dict[str, tuple[str, int, int]]:
    """Map every register alias -> (canonical 64-bit name, bit shift, bit width)."""
    t: dict[str, tuple[str, int, int]] = {}
    for b in "abcd":
        c = f"r{b}x"
        t[c] = (c, 0, 64)
        t[f"e{b}x"] = (c, 0, 32)
        t[f"{b}x"] = (c, 0, 16)
        t[f"{b}l"] = (c, 0, 8)
        t[f"{b}h"] = (c, 8, 8)
    for n in ("si", "di", "bp", "sp"):
        c = f"r{n}"
        t[c] = (c, 0, 64)
        t[f"e{n}"] = (c, 0, 32)
        t[n] = (c, 0, 16)
        t[f"{n}l"] = (c, 0, 8)
    for i in range(8, 16):
        c = f"r{i}"
        t[c] = (c, 0, 64)
        t[f"{c}d"] = (c, 0, 32)
        t[f"{c}w"] = (c, 0, 16)
        t[f"{c}b"] = (c, 0, 8)
    return t


REGS = _build_regs()
CANON = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp"] + [f"r{i}" for i in range(8, 16)]
E_NAME = {"rax": "eax", "rbx": "ebx", "rcx": "ecx", "rdx": "edx", "rsi": "esi", "rdi": "edi",
          "rbp": "ebp", "rsp": "esp"}
ARG_REGS64 = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
FLAGS = ("ZF", "SF", "CF", "OF")

_X64_RE = re.compile(r"%?\b(r[abcd]x|r[sd]i|r[sb]p|r(?:[89]|1[0-5])[dwb]?)\b", re.I)


# --------------------------------------------------------------------------- operands / program

def _try_int(t: str) -> Optional[int]:
    """Parse an integer literal (hex, binary, decimal, trailing-h hex; optional sign)."""
    t = t.strip()
    m = re.fullmatch(r"([+-]?)(0x[0-9a-fA-F]+|0b[01]+|[0-9]+|[0-9][0-9a-fA-F]*h)", t)
    if not m:
        return None
    body = m.group(2).lower()
    if body.startswith("0x"):
        v = int(body, 16)
    elif body.startswith("0b"):
        v = int(body, 2)
    elif body.endswith("h"):
        v = int(body[:-1], 16)
    else:
        v = int(body, 10)
    return -v if m.group(1) == "-" else v


def _split_ops(s: str) -> list[str]:
    """Split an operand string on top-level commas (not inside () or [])."""
    out: list[str] = []
    depth = 0
    cur = ""
    for ch in s:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def _reg_op(name: str) -> tuple:
    c, sh, w = REGS[name.lower()]
    return ("reg", c, sh, w)


def _mem_op(base: Optional[str], index: Optional[str], scale: int, disp: int,
            size: Optional[int], sym: Optional[str]) -> tuple:
    return ("mem", base, index, scale, disp, size, sym)


def _parse_intel_op(tok: str) -> tuple:
    t = tok.strip()
    size = None
    m = re.match(r"(?i)^(byte|word|dword|qword)\s+ptr\s+(.*)$", t)
    if m:
        size = {"byte": 8, "word": 16, "dword": 32, "qword": 64}[m.group(1).lower()]
        t = m.group(2).strip()
    if t.lower() in REGS:
        return _reg_op(t)
    if "[" in t:
        if ":" in t.split("[")[0]:
            raise Stop("segment-override memory operand")
        inner = t[t.index("[") + 1:t.rindex("]")].replace(" ", "")
        base = index = sym = None
        scale = 1
        disp = 0
        for sign, term in re.findall(r"([+-]?)([^+-]+)", inner):
            neg = sign == "-"
            if "*" in term:
                a, b = term.split("*", 1)
                if b.lower() in REGS:
                    a, b = b, a
                index, scale = a.lower(), int(b, 0)
            elif term.lower() in REGS:
                if base is None:
                    base = term.lower()
                else:
                    index = term.lower()
            else:
                n = _try_int(term)
                if n is None:
                    sym = term
                else:
                    disp += -n if neg else n
        return _mem_op(base, index, scale, disp, size, sym)
    n = _try_int(t)
    if n is not None:
        return ("imm", n)
    return ("sym", t)


def _parse_att_op(tok: str) -> tuple:
    t = tok.strip()
    if t.startswith("$"):
        n = _try_int(t[1:])
        if n is None:
            raise Stop("symbolic immediate")
        return ("imm", n)
    if t.startswith("*"):
        raise Stop("indirect branch/call")
    if t.startswith("%") and ":" not in t:
        if t[1:].lower() in REGS:
            return _reg_op(t[1:])
        raise Stop(f"unsupported register {t}")
    if "%" in t and ":" in t.split("(")[0]:
        raise Stop("segment-override memory operand")
    m = re.match(r"^([^()]*)\((.*)\)$", t)
    if m:
        disp_s, inner = m.group(1).strip(), [p.strip() for p in m.group(2).split(",")]
        disp, sym = 0, None
        if disp_s:
            n = _try_int(disp_s)
            if n is None:
                sym = disp_s
            else:
                disp = n
        base = inner[0][1:].lower() if inner and inner[0].startswith("%") else None
        index = inner[1][1:].lower() if len(inner) > 1 and inner[1].startswith("%") else None
        scale = int(inner[2], 0) if len(inner) > 2 and inner[2] else 1
        return _mem_op(base, index, scale, disp, None, sym)
    n = _try_int(t)
    if n is not None:
        return _mem_op(None, None, 1, n, None, None)
    return ("sym", t)


_SIZE_SUFFIX = {"b": 8, "w": 16, "l": 32, "q": 64}

_BASE_MNEMS = {
    "mov", "add", "sub", "imul", "xor", "and", "or", "not", "neg", "shl", "sal", "shr", "sar", "rol", "ror",
    "cmp", "test", "lea", "push", "pop", "inc", "dec", "xchg", "nop", "leave", "ret", "call", "jmp",
    "cdq", "cdqe", "cqo", "cwde", "endbr32", "endbr64", "movzx", "movsx", "movsxd",
}
_JCC = {"e", "z", "ne", "nz", "s", "ns", "o", "no", "b", "c", "nae", "ae", "nb", "nc", "be", "na", "a", "nbe",
        "l", "nge", "ge", "nl", "le", "ng", "g", "nle"}
_ALIASES = {"cltd": "cdq", "cltq": "cdqe", "cqto": "cqo", "cwtl": "cwde", "movabs": "mov", "sal": "shl",
            "retn": "ret", "retq": "ret", "leaveq": "leave", "callq": "call", "pushq": "push", "popq": "pop"}


@dataclass
class Insn:
    """One parsed instruction. ``ops`` are in Intel order (destination first)."""
    mnem: str
    ops: list
    hint: Optional[int]         # operand size from an AT&T suffix
    text: str
    line: int
    srcw: Optional[int] = None  # movzx/movsx source width (AT&T suffix form)
    err: Optional[str] = None   # parse-time problem; reported when execution reaches it


@dataclass
class Program:
    """A parsed listing."""
    insns: list[Insn] = field(default_factory=list)
    labels: dict[str, int] = field(default_factory=dict)
    addr_map: dict[int, int] = field(default_factory=dict)
    symoff: dict[tuple[str, int], int] = field(default_factory=dict)
    syntax: str = "intel"
    bits: int = 32
    funcs: list[str] = field(default_factory=list)


def _norm_mnem(m: str, syntax: str) -> tuple[str, Optional[int], Optional[int]]:
    """Return (base mnemonic, size hint, movx source width); ``base`` is returned unchanged if unknown."""
    m = m.lower()
    if m in _ALIASES and m not in ("sal",):
        base = _ALIASES[m]
        return base, (64 if m.endswith("q") and m != "cltq" else None), None
    if m in _BASE_MNEMS or (m[0] == "j" and m[1:] in _JCC):
        return _ALIASES.get(m, m), None, None
    if syntax == "att":
        mm = re.fullmatch(r"mov([sz])([bwl])([wlq])", m)
        if mm:
            return ("movzx" if mm.group(1) == "z" else "movsx"), _SIZE_SUFFIX[mm.group(3)], _SIZE_SUFFIX[mm.group(2)]
        if m[-1] in _SIZE_SUFFIX and (m[:-1] in _BASE_MNEMS or m[:-1] in _ALIASES):
            return _ALIASES.get(m[:-1], m[:-1]), _SIZE_SUFFIX[m[-1]], None
        if m in ("nopw", "nopl"):
            return "nop", None, None
    return m, None, None


def _parse_insn(line: str, syntax: str, lineno: int) -> Insn:
    """Parse one instruction line; problems are recorded in ``Insn.err`` instead of raising."""
    m = re.match(r"^(\S+)\s*(.*)$", line)
    assert m
    mn_raw, rest = m.group(1), m.group(2).strip()
    while mn_raw.lower() in ("notrack", "bnd") and rest:  # harmless prefixes
        m = re.match(r"^(\S+)\s*(.*)$", rest)
        assert m
        mn_raw, rest = m.group(1), m.group(2).strip()
    mnem, hint, srcw = _norm_mnem(mn_raw, syntax)
    ins = Insn(mnem, [], hint, line, lineno, srcw)
    try:
        if mnem == "call" or mnem == "jmp" or (mnem[0] == "j" and mnem[1:] in _JCC):
            if rest.startswith("*"):
                raise Stop("indirect branch/call")
            tgt = re.sub(r"(?i)^(short|near|far)\s+", "", rest)
            if syntax == "intel" and tgt.lower() in REGS or re.fullmatch(r"\[.*\]", tgt):
                raise Stop("indirect branch/call")
            ins.ops = [("sym", tgt)]
        else:
            parse = _parse_att_op if syntax == "att" else _parse_intel_op
            ops = [parse(o) for o in _split_ops(rest)]
            ins.ops = list(reversed(ops)) if syntax == "att" else ops
    except Stop as exc:
        ins.err = str(exc)
    return ins


def _strip_comment(s: str) -> str:
    for marker in ("#", ";", "//"):
        i = s.find(marker)
        if i >= 0:
            s = s[:i]
    return s


def parse_program(text: str) -> Program:
    """Parse a .S/.asm, gdb ``disassemble`` or objdump listing into a :class:`Program`."""
    lines = text.splitlines()
    cleaned = [_strip_comment(raw).strip() for raw in lines]
    prog = Program()
    # default syntax: first explicit directive wins, else '%' registers mean AT&T
    default = None
    for ln in cleaned:
        d = re.match(r"^\.(intel|att)_syntax", ln)
        if d:
            default = d.group(1)
            break
    if default is None:
        default = "att" if any(re.search(r"%[a-zA-Z]", ln) for ln in cleaned) else "intel"
    syntax = default
    prog.syntax = syntax
    body = "\n".join(cleaned)
    prog.bits = 64 if _X64_RE.search(body) else 32
    cur_func: Optional[str] = None

    def add_label(name: str) -> None:
        nonlocal cur_func
        prog.labels.setdefault(name, len(prog.insns))
        if not name.startswith(".") and not name.startswith("L"):
            cur_func = name
            prog.funcs.append(name)

    for lineno, line in enumerate(cleaned, 1):
        if not line:
            continue
        line = re.sub(r"^=>\s*", "", line)
        m = re.match(r"(?i)^dump of assembler code for function ([^\s:]+):?$", line)
        if m:
            add_label(m.group(1))
            continue
        if line.lower().startswith("end of assembler dump"):
            continue
        m = re.match(r"^([0-9a-fA-F]+)\s+<([^>]+)>:$", line)  # objdump function header
        if m:
            add_label(m.group(2))
            continue
        addr = off = None
        sym = cur_func
        m = re.match(r"^(?:(0x[0-9a-fA-F]+)\s*)?<(?:([\w.$@]+))?\+(\d+)>:\s*(.*)$", line)
        if m:
            addr = int(m.group(1), 16) if m.group(1) else None
            sym = m.group(2) or cur_func
            off = int(m.group(3))
            line = m.group(4)
        else:
            m = re.match(r"^(0x[0-9a-fA-F]+):\s*(.*)$", line)
            if m:
                addr, line = int(m.group(1), 16), m.group(2)
            else:
                m = re.match(r"^([0-9a-fA-F]+):\s+((?:[0-9a-fA-F]{2}\s+)+)(.*)$", line)  # objdump -d
                if m:
                    addr, line = int(m.group(1), 16), m.group(3).strip()
        while True:  # one or more labels, possibly followed by an instruction
            lm = re.match(r"^([A-Za-z_.$][\w.$@]*):\s*(.*)$", line)
            if not lm:
                break
            add_label(lm.group(1))
            line = lm.group(2)
        if not line:
            continue
        if line.startswith("."):
            d = re.match(r"^\.(intel|att)_syntax", line)
            if d:
                syntax = d.group(1)
            b = re.match(r"^\.(?:bits|code)\s*(32|64)", line)
            if b:
                prog.bits = int(b.group(1))
            continue
        idx = len(prog.insns)
        prog.insns.append(_parse_insn(line, syntax, lineno))
        if addr is not None:
            prog.addr_map[addr] = idx
        if off is not None and sym:
            prog.symoff[(sym, off)] = idx
    return prog


# --------------------------------------------------------------------------- machine

def _mask(w: int) -> int:
    return (1 << w) - 1


def _sext(v: int, w: int) -> int:
    v &= _mask(w)
    return v - (1 << w) if v >> (w - 1) else v


def _alu(kind: str, a: Optional[int], b: Optional[int], w: int) -> tuple[Optional[int], dict]:
    """add/sub/and/or/xor on w-bit unsigned values -> (result, flags). Unknown in -> unknown out."""
    unk = {f: None for f in FLAGS}
    if a is None or b is None:
        return None, unk
    mk, sg = _mask(w), 1 << (w - 1)
    cf = of = 0
    if kind == "add":
        r = (a + b) & mk
        cf = int(a + b > mk)
        of = int(bool((a ^ r) & (b ^ r) & sg))
    elif kind == "sub":
        r = (a - b) & mk
        cf = int(a < b)
        of = int(bool((a ^ b) & (a ^ r) & sg))
    elif kind == "and":
        r = a & b
    elif kind == "or":
        r = a | b
    else:
        r = a ^ b
    return r, {"ZF": int(r == 0), "SF": int(bool(r & sg)), "CF": cf, "OF": of}


def _cond(cc: str, f: dict) -> Optional[bool]:
    """Evaluate a Jcc condition code against flags; None if a needed flag is unknown."""
    need = {"e": "ZF", "z": "ZF", "ne": "ZF", "nz": "ZF", "s": "SF", "ns": "SF", "o": "OF", "no": "OF",
            "b": "CF", "c": "CF", "nae": "CF", "ae": "CF", "nb": "CF", "nc": "CF"}.get(cc)
    if need:
        v = f[need]
        if v is None:
            return None
        return bool(v) if cc in ("e", "z", "s", "o", "b", "c", "nae") else not v
    if cc in ("be", "na", "a", "nbe"):
        if f["CF"] is None or f["ZF"] is None:
            return None
        be = bool(f["CF"] or f["ZF"])
        return be if cc in ("be", "na") else not be
    if cc in ("l", "nge", "ge", "nl"):
        if f["SF"] is None or f["OF"] is None:
            return None
        lt = f["SF"] != f["OF"]
        return lt if cc in ("l", "nge") else not lt
    if f["ZF"] is None or f["SF"] is None or f["OF"] is None:  # le/ng/g/nle
        return None
    le = bool(f["ZF"]) or f["SF"] != f["OF"]
    return le if cc in ("le", "ng") else not le


class Machine:
    """Evaluator state: registers, flags, byte memory, instruction pointer."""

    def __init__(self, prog: Program, max_steps: int = DEFAULT_MAX_STEPS) -> None:
        self.p = prog
        self.bits = prog.bits
        self.wb = self.bits // 8
        self.amask = _mask(self.bits)
        self.max_steps = max_steps
        self.regs: dict[str, Optional[int]] = {c: None for c in CANON}
        self.regs["rsp"] = 0xBFFFF000 if self.bits == 32 else 0x7FFFFFFFE000
        self.flags: dict[str, Optional[int]] = {f: None for f in FLAGS}
        self.mem: dict[int, Optional[int]] = {}
        self.ip = 0
        self.steps = 0
        self.status = "running"   # running | returned | finished | partial
        self.reason = ""
        self.stop_at: Optional[Insn] = None

    # -- registers / memory
    def get_reg(self, c: str, sh: int, w: int) -> Optional[int]:
        v = self.regs[c]
        return None if v is None else (v >> sh) & _mask(w)

    def set_reg(self, c: str, sh: int, w: int, val: Optional[int]) -> None:
        if w >= 32:  # 32-bit writes zero-extend; in 32-bit mode the container is 32 bits anyway
            self.regs[c] = None if val is None else val & _mask(w)
            return
        old = self.regs[c]
        if old is None or val is None:
            self.regs[c] = None
            return
        m = _mask(w) << sh
        self.regs[c] = (old & ~m) | ((val & _mask(w)) << sh)

    def mem_read(self, addr: Optional[int], w: int) -> Optional[int]:
        if addr is None:
            return None
        v = 0
        for i in range(w // 8):
            b = self.mem.get((addr + i) & self.amask)
            if b is None:
                return None
            v |= b << (8 * i)
        return v

    def mem_write(self, addr: Optional[int], w: int, val: Optional[int]) -> None:
        if addr is None:
            raise Stop("store to an unknown address (a pointer value is not known)")
        for i in range(w // 8):
            self.mem[(addr + i) & self.amask] = None if val is None else (val >> (8 * i)) & 0xFF

    def ea(self, op: tuple) -> Optional[int]:
        _, base, index, scale, disp, _size, sym = op
        if sym:
            raise Stop(f"memory operand references symbol '{sym}' (data sections are not modelled)")
        a = disp
        for r, mult in ((base, 1), (index, scale)):
            if r:
                if r not in REGS:
                    raise Stop(f"unsupported address register '{r}'")
                v = self.get_reg(*REGS[r])
                if v is None:
                    return None
                a += v * mult
        return a & self.amask

    def rd(self, op: tuple, w: int) -> Optional[int]:
        k = op[0]
        if k == "imm":
            return op[1] & _mask(w)
        if k == "reg":
            return self.get_reg(op[1], op[2], op[3])
        if k == "mem":
            return self.mem_read(self.ea(op), w)
        raise Stop(f"cannot read operand '{op[1]}'")

    def wr(self, op: tuple, w: int, val: Optional[int]) -> None:
        if op[0] == "reg":
            self.set_reg(op[1], op[2], op[3], val)
        elif op[0] == "mem":
            self.mem_write(self.ea(op), w, val)
        else:
            raise Stop("cannot write to this operand")

    def width(self, ins: Insn) -> int:
        """Operand width: destination register/sized memory, then suffix hint, then any register, else 32."""
        if ins.ops:
            d = ins.ops[0]
            if d[0] == "reg":
                return d[3]
            if d[0] == "mem" and d[5]:
                return d[5]
        if ins.hint:
            return ins.hint
        for o in ins.ops:
            if o[0] == "reg":
                return o[3]
            if o[0] == "mem" and o[5]:
                return o[5]
        return 32

    # -- stack
    def push(self, val: Optional[int]) -> None:
        sp = self.regs["rsp"]
        assert sp is not None
        sp = (sp - self.wb) & self.amask
        self.regs["rsp"] = sp
        self.mem_write(sp, self.bits, val)

    def pop(self) -> Optional[int]:
        sp = self.regs["rsp"]
        assert sp is not None
        v = self.mem_read(sp, self.bits)
        self.regs["rsp"] = (sp + self.wb) & self.amask
        return v

    # -- control flow
    def resolve(self, text: str) -> Optional[int]:
        """Branch target text -> instruction index (label, ``<sym+off>``, or a dumped address)."""
        t = text.strip()
        m = re.search(r"<([\w.$@]*)\+(\d+)>", t)
        if m and m.group(1) and (m.group(1), int(m.group(2))) in self.p.symoff:
            return self.p.symoff[(m.group(1), int(m.group(2)))]
        first = t.split()[0] if t.split() else ""
        if first in self.p.labels:
            return self.p.labels[first]
        n = _try_int(first)
        if n is not None and n in self.p.addr_map:
            return self.p.addr_map[n]
        m = re.search(r"<([\w.$@]+)>", t)
        if m and m.group(1) in self.p.labels:
            return self.p.labels[m.group(1)]
        return None

    def set_flags(self, fl: dict, keep_cf: bool = False) -> None:
        for k, v in fl.items():
            if keep_cf and k == "CF":
                continue
            self.flags[k] = v

    # -- execution
    def step(self) -> None:
        ins = self.p.insns[self.ip]
        self.stop_at = ins
        if ins.err:
            raise Stop(f"unsupported operand ({ins.err})")
        fn: Optional[Callable] = getattr(self, "op_" + ins.mnem, None) if ins.mnem.isidentifier() else None
        if fn is None and ins.mnem[0] == "j" and ins.mnem[1:] in _JCC:
            fn = self.op_jcc
        if fn is None:
            raise Stop(f"unsupported instruction '{ins.mnem}'")
        self.ip += 1
        fn(ins)

    def run(self, entry: int, args: Optional[list[int]] = None) -> None:
        """Run from instruction index ``entry`` as if called with ``args`` (SysV x86-64 or cdecl i386)."""
        self.ip = entry
        args = args or []
        if self.bits == 64:
            for r, v in zip(ARG_REGS64, args):
                self.regs[r] = v & _mask(64)
            for v in reversed(args[len(ARG_REGS64):]):
                self.push(v & _mask(64))
        else:
            for v in reversed(args):
                self.push(v & _mask(32))
        self.push(RET_SENTINEL)
        try:
            while self.status == "running":
                if self.ip < 0 or self.ip >= len(self.p.insns):
                    self.status, self.reason = "finished", "reached the end of the listing"
                    break
                if self.steps >= self.max_steps:
                    raise Stop(f"step limit ({self.max_steps}) reached - possible long/infinite loop")
                self.steps += 1
                self.step()
        except Stop as exc:
            self.status, self.reason = "partial", str(exc)

    # -- instruction implementations (Intel operand order: dst, src)
    def op_nop(self, ins: Insn) -> None:
        pass

    op_endbr32 = op_endbr64 = op_nop

    def op_mov(self, ins: Insn) -> None:
        w = self.width(ins)
        self.wr(ins.ops[0], w, self.rd(ins.ops[1], w))

    def op_movzx(self, ins: Insn, signed: bool = False) -> None:
        dst, src = ins.ops[0], ins.ops[1]
        dw = dst[3] if dst[0] == "reg" else 32
        sw = ins.srcw or (src[3] if src[0] == "reg" else src[5] if src[0] == "mem" and src[5] else 8)
        v = self.rd(src, sw)
        if v is not None and signed:
            v = _sext(v, sw) & _mask(dw)
        self.wr(dst, dw, v)

    def op_movsx(self, ins: Insn) -> None:
        self.op_movzx(ins, signed=True)

    def op_movsxd(self, ins: Insn) -> None:
        if ins.srcw is None:
            ins.srcw = 32
        self.op_movzx(ins, signed=True)

    def _binop(self, ins: Insn, kind: str, store: bool = True) -> None:
        w = self.width(ins)
        dst, src = ins.ops[0], ins.ops[1]
        if kind in ("xor", "sub") and dst[0] == "reg" and src[0] == "reg" and dst[1:] == src[1:]:
            r, fl = 0, {"ZF": 1, "SF": 0, "CF": 0, "OF": 0}  # zeroing idiom works even for unknown input
        else:
            r, fl = _alu(kind, self.rd(dst, w), self.rd(src, w), w)
        self.set_flags(fl)
        if store:
            self.wr(dst, w, r)

    def op_add(self, ins: Insn) -> None:
        self._binop(ins, "add")

    def op_sub(self, ins: Insn) -> None:
        self._binop(ins, "sub")

    def op_and(self, ins: Insn) -> None:
        self._binop(ins, "and")

    def op_or(self, ins: Insn) -> None:
        self._binop(ins, "or")

    def op_xor(self, ins: Insn) -> None:
        self._binop(ins, "xor")

    def op_cmp(self, ins: Insn) -> None:
        self._binop(ins, "sub", store=False)

    def op_test(self, ins: Insn) -> None:
        self._binop(ins, "and", store=False)

    def op_imul(self, ins: Insn) -> None:
        if len(ins.ops) == 1:
            raise Stop("one-operand imul (edx:eax result) is not modelled")
        w = self.width(ins)
        a_op, b_op = (ins.ops[0], ins.ops[1]) if len(ins.ops) == 2 else (ins.ops[1], ins.ops[2])
        a, b = self.rd(a_op, w), self.rd(b_op, w)
        if a is None or b is None:
            self.set_flags({f: None for f in FLAGS})
            self.wr(ins.ops[0], w, None)
            return
        full = _sext(a, w) * _sext(b, w)
        r = full & _mask(w)
        ov = int(_sext(r, w) != full)
        self.set_flags({"ZF": None, "SF": None, "CF": ov, "OF": ov})
        self.wr(ins.ops[0], w, r)

    def _shift(self, ins: Insn, kind: str) -> None:
        w = self.width(ins)
        dst = ins.ops[0]
        cnt = self.rd(ins.ops[1], 8) if len(ins.ops) > 1 else 1
        a = self.rd(dst, w)
        if cnt is None or a is None:
            self.set_flags({f: None for f in FLAGS})
            self.wr(dst, w, None)
            return
        cnt &= 63 if w == 64 else 31
        if cnt == 0:
            return
        mk, msb = _mask(w), 1 << (w - 1)
        cf: Optional[int]
        of: Optional[int] = None
        if kind == "shl":
            r = (a << cnt) & mk
            cf = (a >> (w - cnt)) & 1 if cnt <= w else 0
            of = int(bool(r & msb)) ^ cf if cnt == 1 else None
        elif kind == "shr":
            r = a >> cnt
            cf = (a >> (cnt - 1)) & 1
            of = int(bool(a & msb)) if cnt == 1 else None
        elif kind == "sar":
            sa = _sext(a, w)
            r = (sa >> cnt) & mk
            cf = (sa >> (cnt - 1)) & 1
            of = 0 if cnt == 1 else None
        else:  # rol / ror
            c = cnt % w
            r = ((a << c) | (a >> (w - c))) & mk if kind == "rol" else ((a >> c) | (a << (w - c))) & mk
            self.flags["CF"] = (r & 1) if kind == "rol" else int(bool(r & msb))
            self.wr(dst, w, r)
            return
        self.set_flags({"ZF": int(r == 0), "SF": int(bool(r & msb)), "CF": cf, "OF": of})
        self.wr(dst, w, r)

    def op_shl(self, ins: Insn) -> None:
        self._shift(ins, "shl")

    def op_shr(self, ins: Insn) -> None:
        self._shift(ins, "shr")

    def op_sar(self, ins: Insn) -> None:
        self._shift(ins, "sar")

    def op_rol(self, ins: Insn) -> None:
        self._shift(ins, "rol")

    def op_ror(self, ins: Insn) -> None:
        self._shift(ins, "ror")

    def op_lea(self, ins: Insn) -> None:
        dst, src = ins.ops[0], ins.ops[1]
        if src[0] != "mem" or dst[0] != "reg":
            raise Stop("lea with unexpected operands")
        a = self.ea(src)
        self.wr(dst, dst[3], None if a is None else a & _mask(dst[3]))

    def op_push(self, ins: Insn) -> None:
        self.push(self.rd(ins.ops[0], self.bits))

    def op_pop(self, ins: Insn) -> None:
        v = self.pop()
        dst = ins.ops[0]
        self.wr(dst, dst[3] if dst[0] == "reg" else self.bits, v)

    def _incdec(self, ins: Insn, kind: str) -> None:
        w = self.width(ins)
        r, fl = _alu(kind, self.rd(ins.ops[0], w), 1, w)
        self.set_flags(fl, keep_cf=True)
        self.wr(ins.ops[0], w, r)

    def op_inc(self, ins: Insn) -> None:
        self._incdec(ins, "add")

    def op_dec(self, ins: Insn) -> None:
        self._incdec(ins, "sub")

    def op_neg(self, ins: Insn) -> None:
        w = self.width(ins)
        a = self.rd(ins.ops[0], w)
        r, fl = _alu("sub", 0, a, w)
        self.set_flags(fl)
        self.wr(ins.ops[0], w, r)

    def op_not(self, ins: Insn) -> None:
        w = self.width(ins)
        a = self.rd(ins.ops[0], w)
        self.wr(ins.ops[0], w, None if a is None else ~a & _mask(w))

    def op_xchg(self, ins: Insn) -> None:
        w = self.width(ins)
        a, b = self.rd(ins.ops[0], w), self.rd(ins.ops[1], w)
        self.wr(ins.ops[0], w, b)
        self.wr(ins.ops[1], w, a)

    def op_cdq(self, ins: Insn) -> None:
        a = self.get_reg("rax", 0, 32)
        self.set_reg("rdx", 0, 32, None if a is None else (0xFFFFFFFF if a >> 31 else 0))

    def op_cqo(self, ins: Insn) -> None:
        a = self.get_reg("rax", 0, 64)
        self.set_reg("rdx", 0, 64, None if a is None else (_mask(64) if a >> 63 else 0))

    def op_cdqe(self, ins: Insn) -> None:
        a = self.get_reg("rax", 0, 32)
        self.set_reg("rax", 0, 64, None if a is None else _sext(a, 32) & _mask(64))

    def op_cwde(self, ins: Insn) -> None:
        a = self.get_reg("rax", 0, 16)
        self.set_reg("rax", 0, 32, None if a is None else _sext(a, 16) & _mask(32))

    def op_leave(self, ins: Insn) -> None:
        self.regs["rsp"] = self.regs["rbp"]
        if self.regs["rsp"] is None:
            raise Stop("leave with unknown ebp/rbp")
        self.regs["rbp"] = self.pop()

    def _target(self, ins: Insn) -> int:
        text = ins.ops[0][1]
        t = self.resolve(text)
        if t is None:
            raise Stop(f"branch target '{text}' is not in the parsed file")
        return t

    def op_jmp(self, ins: Insn) -> None:
        self.ip = self._target(ins)

    def op_jcc(self, ins: Insn) -> None:
        taken = _cond(ins.mnem[1:], self.flags)
        if taken is None:
            raise Stop(f"'{ins.text}' depends on flags computed from an unknown value "
                       "(supply the missing input with --arg / --init)")
        if taken:
            self.ip = self._target(ins)

    def op_call(self, ins: Insn) -> None:
        tgt = self._target(ins)
        self.push(RET_BASE + self.ip)
        self.ip = tgt

    def op_ret(self, ins: Insn) -> None:
        v = self.pop()
        if v == RET_SENTINEL:
            self.status, self.reason = "returned", "ret to caller"
        elif v is not None and RET_BASE <= v <= RET_BASE + len(self.p.insns):
            self.ip = v - RET_BASE
        else:
            self.status, self.reason = "finished", "ret with no in-file return address"


# --------------------------------------------------------------------------- results / formatting

@dataclass
class EvalResult:
    """Outcome of one evaluation."""
    status: str
    reason: str
    regs: dict
    flags: dict
    steps: int
    bits: int
    stop_text: str = ""
    stop_line: int = 0
    retval: Optional[int] = None

    @property
    def partial(self) -> bool:
        return self.status == "partial"


def evaluate(text: str, args: Optional[list[int]] = None, func: Optional[str] = None,
             max_steps: int = DEFAULT_MAX_STEPS, init: Optional[dict[str, int]] = None) -> EvalResult:
    """Parse ``text`` and evaluate from ``func`` (default: first function/instruction) with ``args``."""
    prog = parse_program(text)
    if not prog.insns:
        raise ValueError("no instructions found in input")
    m = Machine(prog, max_steps)
    for name, val in (init or {}).items():
        c, sh, w = REGS[name.lower()]
        m.set_reg(c, sh, w, val & _mask(w))
    if func:
        if func not in prog.labels:
            raise ValueError(f"function/label '{func}' not found (have: {', '.join(prog.labels) or 'none'})")
        entry = prog.labels[func]
    else:
        entry = prog.labels[prog.funcs[0]] if prog.funcs else 0
    m.run(entry, args)
    rax = m.regs["rax"]
    ret = None if rax is None else rax & _mask(m.bits)
    st = m.stop_at
    return EvalResult(m.status, m.reason, dict(m.regs), dict(m.flags), m.steps, m.bits,
                      st.text if st and m.status == "partial" else "", st.line if st and m.status == "partial" else 0,
                      ret)


def _fmt_val(v: Optional[int], w: int) -> str:
    if v is None:
        return "?"
    s = _sext(v, w)
    dec = str(v) if s == v else f"{v} / {s}"
    return f"0x{v:0{w // 4}x}  ({dec})"


def format_regs(r: EvalResult) -> str:
    """Human-readable register + flag dump."""
    w = r.bits
    names = [(E_NAME[c] if w == 32 else c, c) for c in CANON[:8]]
    if w == 64:
        names += [(c, c) for c in CANON[8:] if r.regs[c] is not None]
    out = []
    for label, c in names:
        v = r.regs[c]
        out.append(f"  {label:<4} = {_fmt_val(None if v is None else v & _mask(w), w)}")
    out.append("  flags: " + " ".join(f"{f}={'?' if r.flags[f] is None else r.flags[f]}" for f in FLAGS))
    return "\n".join(out)


def report(r: EvalResult, label: str = "", args: Optional[list[int]] = None, regs: bool = True) -> str:
    """Full textual report, honest about partial results."""
    out: list[str] = []
    rname = "eax" if r.bits == 32 else "rax"
    if r.partial:
        out.append("*** PARTIAL RESULT - evaluation stopped early ***")
        out.append(f"stopped at line {r.stop_line}: {r.stop_text}")
        out.append(f"reason: {r.reason}")
        out.append(f"steps executed: {r.steps}; last known state:")
    else:
        out.append(f"evaluation complete ({r.reason}); {r.steps} steps")
    if args is not None:
        fn = label or "func"
        call = f"{fn}({', '.join(hex(a) for a in args)})"
        if r.retval is None:
            out.append(f"{call}: {rname} is unknown" + (" (partial)" if r.partial else ""))
        else:
            sv = _sext(r.retval, r.bits)
            dec = str(r.retval) if sv == r.retval else f"{r.retval} unsigned / {sv} signed"
            tag = " [PARTIAL - last known value]" if r.partial else ""
            out.append(f"{call} -> {rname} = 0x{r.retval:x}  decimal {dec}{tag}")
    if regs:
        out.append("registers:" if args is None else "final registers:")
        out.append(format_regs(r))
    return "\n".join(out)


# --------------------------------------------------------------------------- CLI

def _parse_int(s: str) -> int:
    v = _try_int(s)
    if v is None:
        raise argparse.ArgumentTypeError(f"not an integer: {s!r}")
    return v


def run(args: list[str]) -> int:
    """CLI: ``asmeval <file|-> [--arg N ...] [--func NAME] [--init REG=VAL] [--max-steps N] [--regs]``.

    Exit codes: 0 complete, 1 input error, 2 usage error, 3 partial result.
    """
    if args[:1] in (["selftest"], ["--selftest"]):
        return 0 if selftest() else 1
    p = argparse.ArgumentParser(prog="recon.py asmeval", description=DESCRIPTION)
    p.add_argument("file", help="assembly listing (.S/.asm/gdb/objdump text), or - for stdin")
    p.add_argument("--arg", dest="args", action="append", type=_parse_int, default=None, metavar="N",
                   help="call the function with this argument (repeatable, in order)")
    p.add_argument("--func", help="function/label to start at (default: first function)")
    p.add_argument("--init", action="append", default=[], metavar="REG=VAL", help="initial register value")
    p.add_argument("--max-steps", type=int, default=DEFAULT_MAX_STEPS, help="step cap (default 100000)")
    p.add_argument("--regs", action="store_true", help="also dump registers in --arg mode")
    try:
        ns = p.parse_args(args)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    init: dict[str, int] = {}
    for item in ns.init:
        k, _, v = item.partition("=")
        if k.lower() not in REGS or _try_int(v) is None:
            print(f"asmeval: bad --init {item!r} (want REG=VALUE)", file=sys.stderr)
            return 2
        init[k.lower()] = _try_int(v)  # type: ignore[assignment]
    try:
        text = sys.stdin.read() if ns.file == "-" else open(ns.file, encoding="utf-8", errors="replace").read()
    except OSError as exc:
        print(f"asmeval: cannot read {ns.file}: {exc.strerror or exc}", file=sys.stderr)
        return 1
    try:
        res = evaluate(text, ns.args, ns.func, ns.max_steps, init)
    except ValueError as exc:
        print(f"asmeval: {exc}", file=sys.stderr)
        return 1
    label = ns.func or (parse_program(text).funcs[:1] or ["func"])[0]
    print(report(res, label, ns.args, regs=(ns.args is None or ns.regs)))
    return 3 if res.partial else 0


# --------------------------------------------------------------------------- selftest

_ATT_CHAIN = """
.text
start:
    movl $5, %eax
    addl $7, %eax          # eax = 12
    imull $3, %eax, %ebx   # ebx = 36
    subl $1, %ebx          # ebx = 35
    xorl %ecx, %ecx
    leal 4(%ebx,%eax,2), %edx   # 4 + 35 + 24 = 63
    movl $-1, %esi
    addl $1, %esi          # esi = 0, ZF=1, CF=1
"""

_INTEL_LOOP = """
.intel_syntax noprefix
sum:
    xor eax, eax
    mov ecx, 10
.L1:
    add eax, ecx
    dec ecx
    jnz .L1
    ret
"""

_INTEL_BITS = """
.intel_syntax noprefix
    mov eax, 0x12345680
    movsx ebx, al
    movzx ecx, al
    sar ebx, 4
    shr eax, 8
    neg ecx
    not ecx
    and ecx, 0x3c
    or ecx, 3
    shl ecx, 4
"""

_GDB_ATT_FUNC = """Dump of assembler code for function asm1:
   0x0000000000000000 <+0>:	push   %ebp
   0x0000000000000001 <+1>:	mov    %esp,%ebp
   0x0000000000000003 <+3>:	cmpl   $0x3a1,0x8(%ebp)
   0x000000000000000a <+10>:	jg     0x25 <asm1+37>
   0x000000000000000c <+12>:	mov    0x8(%ebp),%eax
   0x000000000000000f <+15>:	add    $0xb,%eax
   0x0000000000000012 <+18>:	jmp    0x2a <asm1+42>
   0x0000000000000025 <+37>:	mov    0x8(%ebp),%eax
   0x0000000000000028 <+40>:	sub    $0xc,%eax
   0x000000000000002a <+42>:	pop    %ebp
   0x000000000000002b <+43>:	ret
End of assembler dump.
"""

_INTEL_PICO = """.intel_syntax noprefix
.global asm2
asm2:
	<+0>:	push   ebp
	<+1>:	mov    ebp,esp
	<+3>:	sub    esp,0x10
	<+6>:	mov    eax,DWORD PTR [ebp+0xc]
	<+9>:	mov    DWORD PTR [ebp-0x4],eax
	<+12>:	mov    eax,DWORD PTR [ebp+0x8]
	<+15>:	mov    DWORD PTR [ebp-0x8],eax
	<+18>:	jmp    0x32 <asm2+32>
	<+20>:	add    DWORD PTR [ebp-0x4],0x1
	<+24>:	add    DWORD PTR [ebp-0x8],0x2e
	<+32>:	cmp    DWORD PTR [ebp-0x8],0x3a98
	<+39>:	jle    0x14 <asm2+20>
	<+41>:	mov    eax,DWORD PTR [ebp-0x4]
	<+44>:	leave
	<+45>:	ret
"""

_INTEL_X64_CALL = """.intel_syntax noprefix
main_fn:
    push rbp
    mov rbp, rsp
    mov DWORD PTR [rbp-4], edi
    mov eax, DWORD PTR [rbp-4]
    mov edi, eax
    call helper
    add eax, 1
    pop rbp
    ret
helper:
    imul eax, edi, 3
    add eax, 7
    ret
"""

_UNSUPPORTED = """.intel_syntax noprefix
    mov eax, 7
    add eax, 1
    bswap eax
    add eax, 1
"""

_UNKNOWN_ARG = """.intel_syntax noprefix
f:
    push ebp
    mov ebp, esp
    mov eax, DWORD PTR [ebp+8]
    cmp eax, 5
    jg .big
    mov eax, 1
    pop ebp
    ret
.big:
    mov eax, 2
    pop ebp
    ret
"""


def selftest() -> bool:
    """Exact-value checks on in-memory AT&T/Intel samples; no files, no optional deps."""
    results: list[bool] = []

    def check(name: str, cond: bool) -> None:
        results.append(bool(cond))
        if not cond:
            print(f"  failed: {name}")

    def reg(r: EvalResult, name: str) -> Optional[int]:
        c, sh, w = REGS[name]
        v = r.regs[c]
        return None if v is None else (v >> sh) & _mask(w)

    r = evaluate(_ATT_CHAIN)
    check("att chain complete", r.status == "finished" and not r.partial)
    check("att eax", reg(r, "eax") == 12)
    check("att imul3 ebx", reg(r, "ebx") == 35)
    check("att xor zero ecx", reg(r, "ecx") == 0)
    check("att lea edx", reg(r, "edx") == 63)
    check("att wrap esi + flags", reg(r, "esi") == 0 and r.flags["ZF"] == 1 and r.flags["CF"] == 1)

    r = evaluate(_INTEL_LOOP)
    check("intel loop sum 1..10", r.status == "returned" and reg(r, "eax") == 55 and r.retval == 55)

    r = evaluate(_INTEL_BITS)
    check("movsx/movzx/sar/shr/neg/not/and/or/shl",
          reg(r, "ebx") == 0xFFFFFFF8 and reg(r, "eax") == 0x123456 and reg(r, "ecx") == 0x3F0)

    r = evaluate(_GDB_ATT_FUNC, [0x6FA])
    check("gdb att branch taken", r.status == "returned" and r.retval == 0x6EE)
    r = evaluate(_GDB_ATT_FUNC, [0x100])
    check("gdb att branch not taken", r.retval == 0x10B)

    r = evaluate(_INTEL_PICO, [0x1, 0x2])
    # a=1(ebp+8), b=2(ebp+c): loop adds 0x2e to a until a>0x3a98; counts iterations in b
    n = 0
    a = 1
    while a <= 0x3A98:
        a += 0x2E
        n += 1
    check("intel pico loop with args", r.status == "returned" and r.retval == 2 + n and not r.partial)

    r = evaluate(_INTEL_X64_CALL, [10], "main_fn")
    check("x64 call in file", r.status == "returned" and r.retval == 38 and r.bits == 64)

    r = evaluate(_UNSUPPORTED)
    check("unsupported insn is partial", r.partial and "bswap" in r.reason and reg(r, "eax") == 8)
    check("partial report labels itself", "PARTIAL" in report(r) and "bswap eax" in report(r))

    r = evaluate(_UNKNOWN_ARG)
    check("unknown arg -> partial at branch", r.partial and "unknown" in r.reason)
    r = evaluate(_UNKNOWN_ARG, [9])
    check("known arg resolves branch", not r.partial and r.retval == 2)
    r = evaluate(_UNKNOWN_ARG, [-3])
    check("negative arg signed compare", r.retval == 1)

    r = evaluate(".intel_syntax noprefix\nl:\n jmp l\n", max_steps=500)
    check("step cap stops infinite loop", r.partial and "step limit" in r.reason)
    r = evaluate(".intel_syntax noprefix\n call printf\n")
    check("call outside file is partial", r.partial and "printf" in r.reason)

    try:
        evaluate("")
        check("empty input rejected", False)
    except ValueError:
        check("empty input rejected", True)

    import contextlib
    import io
    import os
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "a.S")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(_GDB_ATT_FUNC)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = run([path, "--arg", "0x6fa"])
        check("cli arg mode output", rc == 0 and "0x6ee" in buf.getvalue() and "1774" in buf.getvalue())
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = run([path])
        check("cli no-arg is partial (exit 3)", rc == 3 and "PARTIAL" in buf.getvalue())
        with contextlib.redirect_stderr(io.StringIO()):
            check("cli missing file", run([os.path.join(td, "nope")]) == 1)
            check("cli usage error", run(["--bogus"]) == 2)
    return all(results)


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
