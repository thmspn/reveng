"""VAULTDOOR: static solver for picoCTF vault-door style Java password checkers.

Given ``VaultDoor*.java`` source it works out which password ``checkPassword`` accepts and prints it
(with the wrapped ``picoCTF{...}`` flag and a confidence tag) *without* javac, a JVM or executing the
challenge: the source is tokenised and parsed by a small Java-subset parser and "run" by a from-scratch
interpreter written in this file (ints with 32/64-bit wrap, char/byte casts, arrays, String/StringBuilder,
``Integer.parseInt(s, radix)``, ``String.format``, Base64, ``Arrays.equals`` ...).

How the password is derived (all static, all offline):

1. Pick the checker (``checkPassword(String)``) and the likely password length (literal numbers /
   literal string lengths found in the source, scored by how many comparisons they satisfy).
2. Run the interpreter in *probe mode* with a filler password and record every equality comparison
   (``==``, ``!=``, ``equals``, ``Arrays.equals``) as ``(left, right)`` pairs.  In probe mode ``&&``/``||``
   do not short-circuit and ``return false`` does not stop the run, so every comparison is observed.
3. Vary one password character at a time to see which comparison atoms it controls.  Characters that
   own atoms alone are solved together by trying each printable character once; characters that share
   atoms with others (e.g. 4 chars packed into one int) are solved by coordinate hill-climbing on a
   bit-similarity score.
4. Re-run the interpreter in strict mode: if ``checkPassword`` returns ``true`` the answer is HIGH
   confidence (verified by this tool's own evaluator, never by the real JVM).

Pure stdlib; no network; the Java source is only ever read as text.
"""
from __future__ import annotations

import argparse
import base64
import re
import sys
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

NAME = "vaultdoor"
DESCRIPTION = "Static solver for picoCTF VaultDoor*.java checkers (own mini Java evaluator; no javac/JVM)"

MAX_STEPS_PER_RUN = 400_000
MAX_EVENTS = 4000
_CAND_ORDER = ("abcdefghijklmnopqrstuvwxyz0123456789_ABCDEFGHIJKLMNOPQRSTUVWXYZ"
               "{}-!@#$%^&*()+=[]|:;'\",.<>/?`~\\ ")


class ParseError(Exception):
    """The Java source uses syntax outside the supported subset."""


class JavaError(Exception):
    """A Java-level exception raised by the interpreted program (index OOB, NumberFormat, ...)."""


class JavaLimit(Exception):
    """Interpreter step budget exhausted."""


# --------------------------------------------------------------------------- value model

class JChar(int):
    """Java ``char`` (unsigned 16-bit)."""


class JByte(int):
    """Java ``byte`` (signed 8-bit)."""


class JShort(int):
    """Java ``short`` (signed 16-bit)."""


class JLong(int):
    """Java ``long`` (signed 64-bit)."""


class JArray:
    """A Java array: element type name + Python list."""

    def __init__(self, etype: str, items: list) -> None:
        self.etype = etype
        self.a = items


class JSB:
    """StringBuilder / StringBuffer."""

    def __init__(self, s: str = "") -> None:
        self.parts: list[str] = [s] if s else []

    def text(self) -> str:
        s = "".join(self.parts)
        self.parts = [s] if s else []
        return s


class Stub:
    """Inert stand-in for System.out, Scanner and similar objects; every method returns itself."""

    def __init__(self, name: str = "") -> None:
        self.name = name


class ClassRef:
    """Reference to a library class used for static calls/fields (Integer, Math, ...)."""

    def __init__(self, name: str) -> None:
        self.name = name


class SelfObj:
    """The checker class instance (``this`` / ``new VaultDoorN()``)."""


def _s(v: int, bits: int) -> int:
    v &= (1 << bits) - 1
    return v - (1 << bits) if v >> (bits - 1) else v


def coerce(t: str, v: Any) -> Any:
    """Convert ``v`` to Java type ``t`` (narrowing/widening for the primitive types only)."""
    if v is None or isinstance(v, bool):
        return v
    if isinstance(v, float) and t in ("int", "long", "char", "byte", "short"):
        v = int(v)
    if not isinstance(v, int):
        return v
    if t == "int":
        return _s(v, 32)
    if t == "char":
        return JChar(v & 0xFFFF)
    if t == "byte":
        return JByte(_s(v, 8))
    if t == "short":
        return JShort(_s(v, 16))
    if t == "long":
        return JLong(_s(v, 64))
    if t in ("float", "double"):
        return float(v)
    return v


def default_of(t: str) -> Any:
    if t == "boolean":
        return False
    if t in ("int", "char", "byte", "short", "long"):
        return coerce(t, 0)
    if t in ("float", "double"):
        return 0.0
    return None


def jstr(v: Any) -> str:
    """Java string conversion used by ``+`` concatenation / append / valueOf."""
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, JChar):
        return chr(v)
    if isinstance(v, JSB):
        return v.text()
    if isinstance(v, float):
        return repr(v)
    return str(v)


def atoms_of(v: Any) -> Optional[list[int]]:
    """Comparable integer atoms of a value (None if not comparable)."""
    if v is None or isinstance(v, bool):
        return None
    if isinstance(v, int):
        return [int(v)]
    if isinstance(v, str):
        return [ord(c) for c in v]
    if isinstance(v, JSB):
        return [ord(c) for c in v.text()]
    if isinstance(v, JArray):
        out = []
        for x in v.a:
            if isinstance(x, bool) or not isinstance(x, int):
                return None
            out.append(int(x))
        return out
    return None


# --------------------------------------------------------------------------- tokenizer

_TOK = re.compile(r"""
 (?P<ws>\s+|//[^\n]*|/\*.*?\*/)
|(?P<str>"(?:\\.|[^"\\\n])*")
|(?P<chr>'(?:\\.|[^'\\\n])+')
|(?P<num>0[xX][0-9a-fA-F_]+[lL]?|0[bB][01_]+[lL]?|\d[\d_]*(?:\.\d*)?(?:[eE][+-]?\d+)?[lLfFdD]?)
|(?P<id>[A-Za-z_$][\w$]*)
|(?P<op>>>>=|<<=|>>=|>>>|\.\.\.|->|::|\+\+|--|&&|\|\||==|!=|<=|>=|\+=|-=|\*=|/=|%=|&=|\|=|\^=|<<|>>|[{}()\[\];,.<>=+\-*/%&|^~!?:@])
""", re.X | re.S)

_ESC = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "0": "\0", "\\": "\\", "'": "'", '"': '"', "s": " "}


def _unescape(body: str) -> str:
    out = []
    i = 0
    while i < len(body):
        c = body[i]
        if c != "\\":
            out.append(c)
            i += 1
            continue
        i += 1
        c = body[i] if i < len(body) else ""
        if c == "u":
            while i < len(body) and body[i] == "u":
                i += 1
            out.append(chr(int(body[i:i + 4], 16)))
            i += 4
        elif c in "01234567":
            j = i
            while j < len(body) and j < i + 3 and body[j] in "01234567":
                j += 1
            out.append(chr(int(body[i:j], 8) & 0xFF))
            i = j
        else:
            out.append(_ESC.get(c, c))
            i += 1
    return "".join(out)


def _number(text: str) -> Any:
    t = text.replace("_", "")
    is_long = t[-1] in "lL"
    if is_long:
        t = t[:-1]
    low = t.lower()
    if low.startswith("0x"):
        v = int(low, 16)
    elif low.startswith("0b"):
        v = int(low, 2)
    elif re.fullmatch(r"0[0-7]+", t):
        v = int(t, 8)  # octal literal such as 0142
    elif re.fullmatch(r"\d+", t):
        v = int(t, 10)
    else:
        return float(t.rstrip("fFdD"))
    return JLong(_s(v, 64)) if is_long else _s(v, 32)


def tokenize(src: str) -> list[tuple]:
    """Source -> list of (kind, value) tokens; kinds: id, op, num, str, chr, eof."""
    toks: list[tuple] = []
    pos = 0
    while pos < len(src):
        m = _TOK.match(src, pos)
        if not m:
            raise ParseError(f"unexpected character {src[pos]!r}")
        pos = m.end()
        kind = m.lastgroup
        text = m.group(kind)  # type: ignore[arg-type]
        if kind == "ws":
            continue
        if kind == "str":
            toks.append(("str", _unescape(text[1:-1])))
        elif kind == "chr":
            s = _unescape(text[1:-1])
            if len(s) != 1:
                raise ParseError(f"bad char literal {text}")
            toks.append(("chr", JChar(ord(s))))
        elif kind == "num":
            toks.append(("num", _number(text)))
        else:
            toks.append((kind, text))
    toks.append(("eof", ""))
    return toks


# --------------------------------------------------------------------------- parser

_PRIMS = {"byte", "short", "char", "int", "long", "boolean", "float", "double", "void"}
_MODS = {"public", "private", "protected", "static", "final", "abstract", "synchronized", "native",
         "transient", "volatile", "strictfp", "default"}
_ASSIGN = {"=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>=", ">>>="}
_BINPREC = {"||": 1, "&&": 2, "|": 3, "^": 4, "&": 5, "==": 6, "!=": 6, "<": 7, ">": 7, "<=": 7, ">=": 7,
            "<<": 8, ">>": 8, ">>>": 8, "+": 9, "-": 9, "*": 10, "/": 10, "%": 10}
_REF_CASTS = {"String", "Integer", "Object", "Character", "Long", "Byte", "Short"}


@dataclass
class Method:
    name: str
    rtype: str
    params: list[tuple[str, str]]
    body: Optional[tuple]  # None when the body used unsupported syntax
    skipped: str = ""


@dataclass
class ClassInfo:
    methods: list[Method] = field(default_factory=list)
    fields: list[tuple[str, str, Optional[tuple]]] = field(default_factory=list)  # (type, name, init)
    classes: list[str] = field(default_factory=list)


class Parser:
    """Recursive-descent parser for the Java subset vault-door sources use."""

    def __init__(self, toks: list[tuple]) -> None:
        self.t = toks
        self.i = 0

    # -- token helpers
    def peek(self, k: int = 0) -> tuple:
        return self.t[min(self.i + k, len(self.t) - 1)]

    def at(self, val: str, k: int = 0) -> bool:
        tk = self.peek(k)
        return tk[0] in ("op", "id") and tk[1] == val

    def eat(self, val: str) -> bool:
        if self.at(val):
            self.i += 1
            return True
        return False

    def expect(self, val: str) -> None:
        if not self.eat(val):
            raise ParseError(f"expected {val!r}, found {self.peek()[1]!r}")

    def ident(self) -> str:
        tk = self.peek()
        if tk[0] != "id":
            raise ParseError(f"expected identifier, found {tk[1]!r}")
        self.i += 1
        return tk[1]

    def skip_balanced(self, open_: str, close: str) -> None:
        """Skip from an opening token to its matching close (position is at the opener)."""
        depth = 0
        while self.peek()[0] != "eof":
            if self.at(open_):
                depth += 1
            elif self.at(close):
                depth -= 1
                if depth == 0:
                    self.i += 1
                    return
            self.i += 1
        raise ParseError("unbalanced braces")

    # -- declarations
    def parse_file(self) -> ClassInfo:
        info = ClassInfo()
        while self.peek()[0] != "eof":
            if self.at("package") or self.at("import"):
                while not self.eat(";"):
                    self.i += 1
                continue
            self.skip_mods()
            if self.at("class") or self.at("interface") or self.at("enum"):
                self.parse_class(info)
            elif not self.eat(";"):
                raise ParseError(f"unexpected token {self.peek()[1]!r} at top level")
        return info

    def skip_mods(self) -> None:
        while True:
            if self.peek()[0] == "id" and self.peek()[1] in _MODS:
                self.i += 1
            elif self.at("@") and self.peek(1)[0] == "id" and not self.at("interface", 1):
                self.i += 2
                if self.at("("):
                    self.skip_balanced("(", ")")
            else:
                return

    def parse_class(self, info: ClassInfo) -> None:
        self.i += 1  # class / interface / enum
        cname = self.ident()
        info.classes.append(cname)
        while not self.at("{"):
            if self.peek()[0] == "eof":
                raise ParseError("class body not found")
            self.i += 1
        self.expect("{")
        while not self.at("}"):
            if self.peek()[0] == "eof":
                raise ParseError("unterminated class body")
            self.parse_member(info, cname)
        self.expect("}")

    def parse_generic_skip(self) -> None:
        if not self.at("<"):
            return
        depth = 0
        while True:
            tk = self.peek()
            if tk[0] == "eof":
                raise ParseError("unterminated generic")
            if tk[1] == "<":
                depth += 1
            elif tk[1] == ">":
                depth -= 1
            elif tk[1] == ">>":
                depth -= 2
            elif tk[1] == ">>>":
                depth -= 3
            self.i += 1
            if depth <= 0:
                return

    def parse_type(self) -> str:
        name = self.ident()
        while self.at(".") and self.peek(1)[0] == "id":
            self.i += 1
            name = self.ident()  # keep the simple name (java.lang.String -> String)
        self.parse_generic_skip()
        while self.at("[") and self.at("]", 1):
            self.i += 2
            name += "[]"
        return name

    def parse_member(self, info: ClassInfo, cname: str) -> None:
        self.skip_mods()
        if self.eat(";"):
            return
        if self.at("class") or self.at("interface") or self.at("enum"):
            self.parse_class(info)
            return
        if self.at("{"):
            self.skip_balanced("{", "}")
            return
        self.parse_generic_skip()
        if self.peek()[0] == "id" and self.peek()[1] == cname and self.at("(", 1):
            rtype, name = "void", "<init>"
            self.i += 1
        else:
            rtype = self.parse_type()
            name = self.ident()
        if self.at("("):
            params = self.parse_params()
            if self.eat("throws"):
                self.parse_type()
                while self.eat(","):
                    self.parse_type()
            if self.at("{"):
                start = self.i
                try:
                    body = self.parse_block()
                    info.methods.append(Method(name, rtype, params, body))
                except ParseError as exc:
                    self.i = start
                    self.skip_balanced("{", "}")
                    info.methods.append(Method(name, rtype, params, None, str(exc)))
            else:
                self.expect(";")
            return
        # field declarators
        while True:
            t = rtype
            while self.at("[") and self.at("]", 1):
                self.i += 2
                t += "[]"
            init = None
            if self.eat("="):
                init = self.parse_arr_init() if self.at("{") else self.parse_expr()
            info.fields.append((t, name, init))
            if self.eat(","):
                name = self.ident()
                continue
            self.expect(";")
            return

    def parse_params(self) -> list[tuple[str, str]]:
        self.expect("(")
        params = []
        while not self.at(")"):
            self.skip_mods()
            t = self.parse_type()
            if self.eat("..."):
                t += "[]"
            n = self.ident()
            while self.at("[") and self.at("]", 1):
                self.i += 2
                t += "[]"
            params.append((t, n))
            if not self.eat(","):
                break
        self.expect(")")
        return params

    # -- statements
    def parse_block(self) -> tuple:
        self.expect("{")
        stmts = []
        while not self.at("}"):
            if self.peek()[0] == "eof":
                raise ParseError("unterminated block")
            stmts.append(self.parse_stmt())
        self.expect("}")
        return ("block", stmts)

    def looks_like_decl(self) -> bool:
        save = self.i
        try:
            if self.peek()[0] != "id":
                return False
            self.parse_type()
            return self.peek()[0] == "id" and self.peek(1)[1] in ("=", ";", ",", ":", "[")
        except ParseError:
            return False
        finally:
            self.i = save

    def parse_decl(self) -> tuple:
        t = self.parse_type()
        decls = []
        while True:
            n = self.ident()
            tt = t
            while self.at("[") and self.at("]", 1):
                self.i += 2
                tt += "[]"
            init = None
            if self.eat("="):
                init = self.parse_arr_init() if self.at("{") else self.parse_expr()
            decls.append((tt, n, init))
            if not self.eat(","):
                break
        return ("decl", decls)

    def parse_stmt(self) -> tuple:
        tk = self.peek()
        if tk[0] == "op":
            if tk[1] == "{":
                return self.parse_block()
            if tk[1] == ";":
                self.i += 1
                return ("empty",)
        if tk[0] == "id":
            kw = tk[1]
            if kw == "if":
                self.i += 1
                self.expect("(")
                c = self.parse_expr()
                self.expect(")")
                th = self.parse_stmt()
                el = self.parse_stmt() if self.eat("else") else None
                return ("if", c, th, el)
            if kw == "for":
                return self.parse_for()
            if kw == "while":
                self.i += 1
                self.expect("(")
                c = self.parse_expr()
                self.expect(")")
                return ("while", c, self.parse_stmt())
            if kw == "do":
                self.i += 1
                body = self.parse_stmt()
                self.expect("while")
                self.expect("(")
                c = self.parse_expr()
                self.expect(")")
                self.expect(";")
                return ("dowhile", body, c)
            if kw == "return":
                self.i += 1
                e = None if self.at(";") else self.parse_expr()
                self.expect(";")
                return ("return", e)
            if kw in ("break", "continue"):
                self.i += 1
                self.expect(";")
                return (kw,)
            if kw in ("switch", "try", "throw", "synchronized", "assert", "class", "interface"):
                raise ParseError(f"unsupported statement '{kw}'")
            if kw == "final":
                self.i += 1
                return self.parse_stmt()
        if self.looks_like_decl():
            d = self.parse_decl()
            self.expect(";")
            return d
        e = self.parse_expr()
        self.expect(";")
        return ("expr", e)

    def parse_for(self) -> tuple:
        self.i += 1
        self.expect("(")
        self.eat("final")
        if self.looks_like_decl():
            save = self.i
            t = self.parse_type()
            n = self.ident()
            if self.eat(":"):
                it = self.parse_expr()
                self.expect(")")
                return ("foreach", t, n, it, self.parse_stmt())
            self.i = save
        init: list[tuple] = []
        if not self.at(";"):
            if self.looks_like_decl():
                init.append(self.parse_decl())
            else:
                init.append(("expr", self.parse_expr()))
                while self.eat(","):
                    init.append(("expr", self.parse_expr()))
        self.expect(";")
        cond = None if self.at(";") else self.parse_expr()
        self.expect(";")
        upd: list[tuple] = []
        if not self.at(")"):
            upd.append(self.parse_expr())
            while self.eat(","):
                upd.append(self.parse_expr())
        self.expect(")")
        return ("for", init, cond, upd, self.parse_stmt())

    # -- expressions
    def parse_expr(self) -> tuple:
        lhs = self.parse_ternary()
        tk = self.peek()
        if tk[0] == "op" and tk[1] in _ASSIGN:
            if lhs[0] not in ("name", "index", "field"):
                raise ParseError("assignment to non-variable")
            self.i += 1
            return ("assign", tk[1], lhs, self.parse_expr())
        return lhs

    def parse_ternary(self) -> tuple:
        c = self.parse_bin(1)
        if self.eat("?"):
            a = self.parse_expr()
            self.expect(":")
            b = self.parse_expr()
            return ("tern", c, a, b)
        return c

    def parse_bin(self, minprec: int) -> tuple:
        left = self.parse_unary()
        while True:
            tk = self.peek()
            if tk[0] != "op" or tk[1] not in _BINPREC or _BINPREC[tk[1]] < minprec:
                return left
            prec = _BINPREC[tk[1]]
            self.i += 1
            right = self.parse_bin(prec + 1)
            left = ("bin", tk[1], left, right)

    def parse_unary(self) -> tuple:
        tk = self.peek()
        if tk[0] == "op":
            v = tk[1]
            if v in ("+", "-", "!", "~"):
                self.i += 1
                return ("un", v, self.parse_unary())
            if v in ("++", "--"):
                self.i += 1
                return ("pre", v, self.parse_unary())
            if v == "(":
                nxt = self.peek(1)
                if nxt[0] == "id" and nxt[1] in _PRIMS:
                    j = 2
                    while self.peek(j)[1] == "[" and self.peek(j + 1)[1] == "]":
                        j += 2
                    if self.peek(j)[1] == ")":
                        t = nxt[1] + "[]" * ((j - 2) // 2)
                        self.i += j + 1
                        return ("cast", t, self.parse_unary())
                if nxt[0] == "id" and nxt[1] in _REF_CASTS and self.peek(2)[1] == ")" \
                        and (self.peek(3)[0] in ("id", "str", "num", "chr") or self.peek(3)[1] == "("):
                    self.i += 3
                    return self.parse_unary()
        return self.parse_postfix()

    def parse_args(self) -> list[tuple]:
        self.expect("(")
        args = []
        while not self.at(")"):
            args.append(self.parse_expr())
            if not self.eat(","):
                break
        self.expect(")")
        return args

    def parse_postfix(self) -> tuple:
        e = self.parse_primary()
        while True:
            if self.at(".") and self.peek(1)[0] == "id":
                self.i += 1
                name = self.ident()
                if self.at("("):
                    e = ("call", e, name, self.parse_args())
                else:
                    e = ("field", e, name)
            elif self.at("["):
                self.i += 1
                idx = self.parse_expr()
                self.expect("]")
                e = ("index", e, idx)
            elif self.at("++") or self.at("--"):
                op = self.peek()[1]
                self.i += 1
                e = ("post", op, e)
            else:
                return e

    def parse_primary(self) -> tuple:
        tk = self.peek()
        if tk[0] in ("num", "str", "chr"):
            self.i += 1
            return ("lit", tk[1])
        if tk[0] == "id":
            kw = tk[1]
            if kw == "true" or kw == "false":
                self.i += 1
                return ("lit", kw == "true")
            if kw == "null":
                self.i += 1
                return ("lit", None)
            if kw == "this":
                self.i += 1
                return ("this",)
            if kw == "new":
                return self.parse_new()
            self.i += 1
            if self.at("("):
                return ("call", None, kw, self.parse_args())
            return ("name", kw)
        if tk[0] == "op" and tk[1] == "(":
            self.i += 1
            e = self.parse_expr()
            self.expect(")")
            return e
        raise ParseError(f"unexpected token {tk[1]!r} in expression")

    def parse_new(self) -> tuple:
        self.i += 1
        name = self.ident()
        while self.eat("."):
            name = self.ident()
        self.parse_generic_skip()
        if self.at("["):
            dims: list[Optional[tuple]] = []
            while self.at("["):
                self.i += 1
                if self.eat("]"):
                    dims.append(None)
                else:
                    dims.append(self.parse_expr())
                    self.expect("]")
            init = self.parse_arr_init() if self.at("{") else None
            return ("newarr", name, dims, init)
        args = self.parse_args()
        if self.at("{"):
            raise ParseError("anonymous classes are not supported")
        return ("new", name, args)

    def parse_arr_init(self) -> tuple:
        self.expect("{")
        elems = []
        while not self.at("}"):
            elems.append(self.parse_arr_init() if self.at("{") else self.parse_expr())
            if not self.eat(","):
                break
        self.expect("}")
        return ("arrlit", elems)


# --------------------------------------------------------------------------- interpreter

class _Break(Exception):
    pass


class _Continue(Exception):
    pass


class _Return(Exception):
    def __init__(self, v: Any) -> None:
        self.v = v


def _jdiv(a: int, b: int) -> int:
    if b == 0:
        raise JavaError("ArithmeticException: / by zero")
    q = abs(a) // abs(b)
    return q if (a < 0) == (b < 0) else -q


def _jformat(fmt: str, args: list) -> str:
    """Subset of java.lang.String.format: %% %n %d %x %X %o %c %s %b with flags/width."""
    it = iter(args)

    def rep(m: re.Match) -> str:
        flags, width, prec, conv = m.group(1), m.group(2) or "", m.group(3), m.group(4)
        if conv == "%":
            return "%"
        if conv == "n":
            return "\n"
        a = next(it, None)
        if conv in "xXo":
            if isinstance(a, JByte):
                a = int(a) & 0xFF
            elif isinstance(a, JShort):
                a = int(a) & 0xFFFF
            elif isinstance(a, JLong):
                a = int(a) & 0xFFFFFFFFFFFFFFFF
            elif isinstance(a, int):
                a = int(a) & 0xFFFFFFFF
        if conv in "dxXo":
            return ("%" + flags.replace(",", "") + width + conv) % int(a)
        if conv == "c":
            return ("%" + flags + width + "s") % (chr(a) if isinstance(a, int) else jstr(a))
        s = jstr(a).lower() if conv == "b" else jstr(a)
        if prec:
            s = s[:int(prec)]
        return ("%" + flags + width + "s") % s

    return re.sub(r"%([-#+ 0,(]*)(\d+)?(?:\.(\d+))?([a-zA-Z%])", rep, fmt)


class Interp:
    """Tree-walking evaluator for the parsed class; never touches files, network or processes."""

    def __init__(self, info: ClassInfo) -> None:
        self.info = info
        self.methods: dict[str, list[Method]] = {}
        for m in info.methods:
            self.methods.setdefault(m.name, []).append(m)
        self.fields: dict[str, list] = {}
        self.env: dict[str, list] = {}
        self.probe = False
        self.events: list[tuple[list[int], list[int]]] = []
        self.budget = 0
        self.depth = 0
        self._self = SelfObj()
        self._ev: dict[str, Callable] = {k[2:]: getattr(self, k) for k in dir(self) if k.startswith("e_")}
        self._ex: dict[str, Callable] = {k[2:]: getattr(self, k) for k in dir(self) if k.startswith("x_")}

    # -- run control
    def reset(self, probe: bool) -> None:
        self.probe = probe
        self.events = []
        self.budget = MAX_STEPS_PER_RUN
        self.depth = 0
        self.env = {}
        self.fields = {}
        for t, n, init in self.info.fields:  # field initialisers in source order
            self.fields[n] = [t, default_of(t)]
            if init is not None:
                try:
                    self.fields[n][1] = self.init_value(t, init)
                except (JavaError, KeyError, IndexError):
                    pass

    def call(self, name: str, args: list, probe: bool = False) -> Any:
        """Invoke a user method from outside (fresh state)."""
        self.reset(probe)
        return self.invoke(name, args)

    def invoke(self, name: str, args: list) -> Any:
        cands = [m for m in self.methods.get(name, []) if len(m.params) == len(args)]
        if not cands:
            raise JavaError(f"no method {name}/{len(args)}")
        m = cands[0]
        if m.body is None:
            raise JavaError(f"method {name} uses unsupported syntax ({m.skipped})")
        if self.depth > 150:
            raise JavaError("StackOverflowError")
        saved = self.env
        self.env = {pn: [pt, coerce(pt, a)] for (pt, pn), a in zip(m.params, args)}
        self.depth += 1
        try:
            self.x(m.body)
            ret = None
        except _Return as r:
            ret = r.v
        finally:
            self.depth -= 1
            self.env = saved
        return coerce(m.rtype, ret)

    def rec(self, a: Any, b: Any) -> None:
        """Record an equality comparison (for the solver) in probe mode."""
        if not self.probe or len(self.events) >= MAX_EVENTS:
            return
        x, y = atoms_of(a), atoms_of(b)
        if x is not None and y is not None:
            self.events.append((x, y))

    # -- evaluation dispatch
    def ev(self, n: tuple) -> Any:
        self.budget -= 1
        if self.budget < 0:
            raise JavaLimit("step budget exhausted")
        return self._ev[n[0]](n)

    def x(self, n: tuple) -> None:
        self.budget -= 1
        if self.budget < 0:
            raise JavaLimit("step budget exhausted")
        self._ex[n[0]](n)

    # -- statements
    def x_block(self, n: tuple) -> None:
        for s in n[1]:
            self.x(s)

    def x_empty(self, n: tuple) -> None:
        pass

    def x_expr(self, n: tuple) -> None:
        self.ev(n[1])

    def init_value(self, t: str, init: tuple) -> Any:
        if init[0] == "arrlit":
            return self.build_arr(t[:-2] if t.endswith("[]") else t, init)
        return coerce(t, self.ev(init))

    def build_arr(self, etype: str, node: tuple) -> JArray:
        items = []
        for e in node[1]:
            if e[0] == "arrlit":
                items.append(self.build_arr(etype[:-2] if etype.endswith("[]") else etype, e))
            else:
                items.append(coerce(etype, self.ev(e)))
        return JArray(etype, items)

    def x_decl(self, n: tuple) -> None:
        for t, name, init in n[1]:
            self.env[name] = [t, default_of(t) if init is None else self.init_value(t, init)]

    def x_if(self, n: tuple) -> None:
        if self.ev(n[1]):
            self.x(n[2])
        elif n[3] is not None:
            self.x(n[3])

    def x_for(self, n: tuple) -> None:
        for s in n[1]:
            self.x(s)
        while n[2] is None or self.ev(n[2]):
            try:
                self.x(n[4])
            except _Break:
                break
            except _Continue:
                pass
            for u in n[3]:
                self.ev(u)

    def x_foreach(self, n: tuple) -> None:
        it = self.ev(n[3])
        seq = it.a if isinstance(it, JArray) else list(it) if isinstance(it, str) else None
        if seq is None:
            raise JavaError("for-each over unsupported type")
        for v in list(seq):
            self.env[n[2]] = [n[1], coerce(n[1], JChar(ord(v)) if isinstance(v, str) else v)]
            try:
                self.x(n[4])
            except _Break:
                break
            except _Continue:
                continue

    def x_while(self, n: tuple) -> None:
        while self.ev(n[1]):
            try:
                self.x(n[2])
            except _Break:
                break
            except _Continue:
                pass

    def x_dowhile(self, n: tuple) -> None:
        while True:
            try:
                self.x(n[1])
            except _Break:
                break
            except _Continue:
                pass
            if not self.ev(n[2]):
                break

    def x_return(self, n: tuple) -> None:
        # probe mode: "return false" (a failed check) must not hide later comparisons from the solver
        if self.probe and n[1] == ("lit", False):
            return
        raise _Return(None if n[1] is None else self.ev(n[1]))

    def x_break(self, n: tuple) -> None:
        raise _Break()

    def x_continue(self, n: tuple) -> None:
        raise _Continue()

    # -- expressions
    def e_lit(self, n: tuple) -> Any:
        return n[1]

    def e_this(self, n: tuple) -> Any:
        return self._self

    def cell(self, name: str) -> Optional[list]:
        c = self.env.get(name)
        return c if c is not None else self.fields.get(name)

    def e_name(self, n: tuple) -> Any:
        c = self.cell(n[1])
        if c is not None:
            return c[1]
        if n[1][:1].isupper() or n[1] in ("java", "javax"):
            return ClassRef(n[1])
        raise JavaError(f"unknown variable {n[1]}")

    def e_field(self, n: tuple) -> Any:
        obj = self.ev(n[1])
        name = n[2]
        if isinstance(obj, JArray) and name == "length":
            return len(obj.a)
        if isinstance(obj, SelfObj):
            c = self.fields.get(name)
            if c is None:
                raise JavaError(f"unknown field {name}")
            return c[1]
        if isinstance(obj, ClassRef) and obj.name[:1].islower():  # package prefix: java.util.Arrays
            return ClassRef(name) if name[:1].isupper() else obj
        if isinstance(obj, ClassRef):
            consts = {("Integer", "MAX_VALUE"): 2147483647, ("Integer", "MIN_VALUE"): -2147483648,
                      ("Long", "MAX_VALUE"): JLong(2 ** 63 - 1), ("Long", "MIN_VALUE"): JLong(-2 ** 63),
                      ("Byte", "MAX_VALUE"): JByte(127), ("Byte", "MIN_VALUE"): JByte(-128),
                      ("Character", "MAX_VALUE"): JChar(0xFFFF), ("Short", "MAX_VALUE"): JShort(32767)}
            if (obj.name, name) in consts:
                return consts[(obj.name, name)]
            return Stub(f"{obj.name}.{name}")
        if isinstance(obj, Stub):
            return Stub(f"{obj.name}.{name}")
        raise JavaError(f"unsupported field access .{name}")

    def e_index(self, n: tuple) -> Any:
        arr, idx = self.ev(n[1]), self.ev(n[2])
        if not isinstance(arr, JArray):
            raise JavaError("NullPointerException / not an array")
        if not 0 <= idx < len(arr.a):
            raise JavaError(f"ArrayIndexOutOfBoundsException: {idx}")
        return arr.a[idx]

    def e_cast(self, n: tuple) -> Any:
        return coerce(n[1], self.ev(n[2]))

    def e_tern(self, n: tuple) -> Any:
        return self.ev(n[2]) if self.ev(n[1]) else self.ev(n[3])

    def e_newarr(self, n: tuple) -> JArray:
        _, base, dims, init = n
        if init is not None:
            return self.build_arr(base + "[]" * (len(dims) - 1), init)
        sizes = [self.ev(d) for d in dims if d is not None]

        def mk(level: int, et: str) -> JArray:
            if level == len(sizes) - 1:
                return JArray(et, [default_of(et) for _ in range(sizes[level])])
            return JArray(et + "[]" * (len(sizes) - level - 1), [mk(level + 1, et) for _ in range(sizes[level])])

        if any(s < 0 for s in sizes):
            raise JavaError("NegativeArraySizeException")
        if not sizes:
            raise JavaError("array creation without size")
        return mk(0, base + "[]" * (len(dims) - len(sizes)))

    def e_arrlit(self, n: tuple) -> JArray:
        return self.build_arr("int", n)

    def e_new(self, n: tuple) -> Any:
        _, cls, args_n = n
        args = [self.ev(a) for a in args_n]
        if cls in ("StringBuilder", "StringBuffer"):
            return JSB(jstr(args[0]) if args and not isinstance(args[0], int) else "")
        if cls == "String":
            if not args:
                return ""
            a = args[0]
            if isinstance(a, JArray):
                if a.etype == "byte":
                    return bytes(int(x) & 0xFF for x in a.a).decode("latin-1")
                return "".join(chr(int(x)) for x in a.a)
            return jstr(a)
        if cls in self.info.classes:
            return self._self
        return Stub(cls)

    def e_un(self, n: tuple) -> Any:
        v = self.ev(n[2])
        op = n[1]
        if op == "!":
            return not v
        if isinstance(v, float):
            return -v if op == "-" else v
        if isinstance(v, bool) or not isinstance(v, int):
            raise JavaError("bad operand for unary operator")
        if isinstance(v, JLong):
            r = {"-": -int(v), "+": int(v), "~": ~int(v)}[op]
            return JLong(_s(r, 64))
        r = {"-": -int(v), "+": int(v), "~": ~int(v)}[op]
        return _s(r, 32)

    def binop(self, op: str, a: Any, b: Any) -> Any:
        if op == "+" and (isinstance(a, str) or isinstance(b, str)):
            return jstr(a) + jstr(b)
        if isinstance(a, bool) and isinstance(b, bool) and op in ("&", "|", "^"):
            return {"&": a and b, "|": a or b, "^": a != b}[op]
        if a is None or b is None or isinstance(a, bool) or isinstance(b, bool):
            raise JavaError("NullPointerException / bad operand types")
        if isinstance(a, float) or isinstance(b, float):
            a, b = float(a), float(b)
            if op in ("+", "-", "*"):
                return {"+": a + b, "-": a - b, "*": a * b}[op]
            if op == "/":
                return a / b if b else float("inf")
            raise JavaError("unsupported floating-point operator")
        wide = isinstance(a, JLong) or isinstance(b, JLong)
        bits = 64 if wide else 32
        x, y = int(a), int(b)
        if op in ("<<", ">>", ">>>"):
            bits = 64 if isinstance(a, JLong) else 32
            cnt = y & (bits - 1)
            if op == "<<":
                r = x << cnt
            elif op == ">>":
                r = x >> cnt
            else:
                r = (x & ((1 << bits) - 1)) >> cnt
        elif op == "+":
            r = x + y
        elif op == "-":
            r = x - y
        elif op == "*":
            r = x * y
        elif op == "/":
            r = _jdiv(x, y)
        elif op == "%":
            r = x - y * _jdiv(x, y)
        elif op == "&":
            r = x & y
        elif op == "|":
            r = x | y
        elif op == "^":
            r = x ^ y
        else:
            raise JavaError(f"unsupported operator {op}")
        return JLong(_s(r, 64)) if bits == 64 else _s(r, 32)

    def e_bin(self, n: tuple) -> Any:
        op = n[1]
        if op == "&&" or op == "||":
            a = bool(self.ev(n[2]))
            if self.probe:  # evaluate both sides so every comparison is observed
                try:
                    b = bool(self.ev(n[3]))
                except JavaError:
                    b = False
                return (a and b) if op == "&&" else (a or b)
            if op == "&&":
                return a and bool(self.ev(n[3]))
            return a or bool(self.ev(n[3]))
        a, b = self.ev(n[2]), self.ev(n[3])
        if op in ("==", "!="):
            self.rec(a, b)
            eq = (a == b) if not (isinstance(a, JArray) or isinstance(b, JArray)) else a is b
            return eq if op == "==" else not eq
        if op in ("<", ">", "<=", ">="):
            if a is None or b is None:
                raise JavaError("NullPointerException")
            return {"<": a < b, ">": a > b, "<=": a <= b, ">=": a >= b}[op]
        return self.binop(op, a, b)

    def store(self, lv: tuple, v: Any) -> Any:
        if lv[0] == "name":
            c = self.cell(lv[1])
            if c is None:
                raise JavaError(f"assignment to unknown variable {lv[1]}")
            c[1] = coerce(c[0], v)
            return c[1]
        if lv[0] == "index":
            arr, idx = self.ev(lv[1]), self.ev(lv[2])
            if not isinstance(arr, JArray):
                raise JavaError("NullPointerException / not an array")
            if not 0 <= idx < len(arr.a):
                raise JavaError(f"ArrayIndexOutOfBoundsException: {idx}")
            arr.a[idx] = coerce(arr.etype, v)
            return arr.a[idx]
        if lv[0] == "field":
            obj = self.ev(lv[1])
            c = self.fields.get(lv[2]) if isinstance(obj, SelfObj) else None
            if c is None:
                raise JavaError("unsupported field assignment")
            c[1] = coerce(c[0], v)
            return c[1]
        raise JavaError("bad assignment target")

    def e_assign(self, n: tuple) -> Any:
        _, op, lv, rhs = n
        if op == "=":
            return self.store(lv, self.ev(rhs))
        old = self.ev(lv)
        return self.store(lv, self.binop(op[:-1], old, self.ev(rhs)))

    def _incdec(self, n: tuple, post: bool) -> Any:
        old = self.ev(n[2])
        new = self.store(n[2], self.binop("+" if n[1] == "++" else "-", old, 1))
        return old if post else new

    def e_pre(self, n: tuple) -> Any:
        return self._incdec(n, False)

    def e_post(self, n: tuple) -> Any:
        return self._incdec(n, True)

    # -- calls
    def e_call(self, n: tuple) -> Any:
        _, target, name, argn = n
        if target is None:
            return self.invoke(name, [self.ev(a) for a in argn])
        obj = self.ev(target)
        args = [self.ev(a) for a in argn]
        if isinstance(obj, SelfObj):
            return self.invoke(name, args)
        if isinstance(obj, ClassRef):
            return self.static_call(obj.name, name, args)
        if isinstance(obj, str):
            return self.str_method(obj, name, args)
        if isinstance(obj, JSB):
            return self.sb_method(obj, name, args)
        if isinstance(obj, JArray):
            if name == "clone":
                return JArray(obj.etype, list(obj.a))
            if name == "equals":
                return obj is args[0]
        if isinstance(obj, Stub):
            return self.stub_method(obj, name, args)
        if isinstance(obj, int) and not isinstance(obj, bool):
            if name == "equals":
                self.rec(obj, args[0])
                return obj == args[0]
            if name in ("intValue", "charValue", "byteValue", "longValue"):
                return obj
        raise JavaError(f"unsupported method call .{name}() on {type(obj).__name__}")

    def stub_method(self, obj: Stub, name: str, args: list) -> Any:
        if obj.name == "Base64.enc":
            if name == "encodeToString":
                return base64.b64encode(bytes(int(x) & 0xFF for x in args[0].a)).decode("ascii")
            if name == "encode":
                return JArray("byte", [JByte(_s(b, 8)) for b in base64.b64encode(bytes(int(x) & 0xFF for x in args[0].a))])
        if obj.name == "Base64.dec" and name == "decode":
            data = args[0] if isinstance(args[0], str) else bytes(int(x) & 0xFF for x in args[0].a).decode("latin-1")
            try:
                raw = base64.b64decode(data, validate=True)
            except ValueError as exc:
                raise JavaError(f"IllegalArgumentException: {exc}")
            return JArray("byte", [JByte(_s(b, 8)) for b in raw])
        return obj if obj.name not in ("Base64.enc", "Base64.dec") else None

    def str_method(self, s: str, name: str, a: list) -> Any:
        if name == "length":
            return len(s)
        if name == "charAt":
            if not 0 <= a[0] < len(s):
                raise JavaError(f"StringIndexOutOfBoundsException: {a[0]}")
            return JChar(ord(s[a[0]]))
        if name == "substring":
            lo = a[0]
            hi = a[1] if len(a) > 1 else len(s)
            if not 0 <= lo <= hi <= len(s):
                raise JavaError(f"StringIndexOutOfBoundsException: {lo},{hi}")
            return s[lo:hi]
        if name in ("equals", "contentEquals"):
            self.rec(s, a[0])
            return isinstance(a[0], (str, JSB)) and s == jstr(a[0])
        if name == "equalsIgnoreCase":
            self.rec(s.lower(), jstr(a[0]).lower() if a[0] is not None else None)
            return a[0] is not None and s.lower() == jstr(a[0]).lower()
        if name == "getBytes":
            return JArray("byte", [JByte(_s(b, 8)) for b in s.encode("utf-8")])
        if name == "toCharArray":
            return JArray("char", [JChar(ord(c)) for c in s])
        if name == "indexOf":
            return s.find(jstr(a[0]), a[1] if len(a) > 1 else 0)
        if name == "lastIndexOf":
            return s.rfind(jstr(a[0]))
        if name == "startsWith":
            return s.startswith(jstr(a[0]))
        if name == "endsWith":
            return s.endswith(jstr(a[0]))
        if name == "contains":
            return jstr(a[0]) in s
        if name == "isEmpty":
            return not s
        if name == "toUpperCase":
            return s.upper()
        if name == "toLowerCase":
            return s.lower()
        if name == "trim":
            return s.strip()
        if name == "concat":
            return s + jstr(a[0])
        if name == "replace":
            return s.replace(jstr(a[0]), jstr(a[1]))
        if name in ("toString", "intern"):
            return s
        if name == "hashCode":
            h = 0
            for c in s:
                h = (31 * h + ord(c)) & 0xFFFFFFFF
            return _s(h, 32)
        if name == "compareTo":
            return (s > a[0]) - (s < a[0])
        raise JavaError(f"unsupported String method {name}")

    def sb_method(self, sb: JSB, name: str, a: list) -> Any:
        if name == "append":
            sb.parts.append(jstr(a[0]) if not isinstance(a[0], JArray) else "".join(chr(int(x)) for x in a[0].a))
            return sb
        if name == "toString":
            return sb.text()
        if name == "length":
            return len(sb.text())
        if name == "charAt":
            t = sb.text()
            if not 0 <= a[0] < len(t):
                raise JavaError("StringIndexOutOfBoundsException")
            return JChar(ord(t[a[0]]))
        if name == "reverse":
            sb.parts = [sb.text()[::-1]]
            return sb
        if name == "insert":
            t = sb.text()
            sb.parts = [t[:a[0]] + jstr(a[1]) + t[a[0]:]]
            return sb
        if name == "setCharAt":
            t = sb.text()
            sb.parts = [t[:a[0]] + jstr(a[1]) + t[a[0] + 1:]]
            return None
        if name == "deleteCharAt":
            t = sb.text()
            sb.parts = [t[:a[0]] + t[a[0] + 1:]]
            return sb
        raise JavaError(f"unsupported StringBuilder method {name}")

    def static_call(self, cls: str, name: str, a: list) -> Any:
        if cls in ("Integer", "Long", "Short", "Byte"):
            if name in ("parseInt", "valueOf", "parseLong", "parseShort", "parseByte") and isinstance(a[0], str):
                radix = a[1] if len(a) > 1 else 10
                if not re.fullmatch(r"[+-]?[0-9a-zA-Z]+", a[0]):
                    raise JavaError(f"NumberFormatException: {a[0]!r}")
                try:
                    v = int(a[0], radix)
                except ValueError:
                    raise JavaError(f"NumberFormatException: {a[0]!r} radix {radix}")
                bits = {"Integer": 32, "Long": 64, "Short": 16, "Byte": 8}[cls]
                if not -(1 << (bits - 1)) <= v < (1 << (bits - 1)):
                    raise JavaError("NumberFormatException: out of range")
                return coerce({"Integer": "int", "Long": "long", "Short": "short", "Byte": "byte"}[cls], v)
            if name == "valueOf":
                return a[0]
            mask = 0xFFFFFFFF if cls == "Integer" else 0xFFFFFFFFFFFFFFFF
            if name == "toHexString":
                return format(int(a[0]) & mask, "x")
            if name == "toBinaryString":
                return format(int(a[0]) & mask, "b")
            if name == "toOctalString":
                return format(int(a[0]) & mask, "o")
            if name == "toString":
                if len(a) > 1:
                    v, r = int(a[0]), a[1]
                    digits = "0123456789abcdefghijklmnopqrstuvwxyz"
                    out, neg, v = "", v < 0, abs(v)
                    while True:
                        out = digits[v % r] + out
                        v //= r
                        if not v:
                            break
                    return ("-" if neg else "") + out
                return str(int(a[0]))
            if name in ("bitCount",):
                return bin(int(a[0]) & mask).count("1")
            if name in ("compare",):
                return (a[0] > a[1]) - (a[0] < a[1])
        if cls == "Character":
            c = chr(int(a[0])) if a and isinstance(a[0], int) else ""
            if name == "isDigit":
                return c.isdigit()
            if name in ("isLetter", "isAlphabetic"):
                return c.isalpha()
            if name == "isLetterOrDigit":
                return c.isalnum()
            if name == "isUpperCase":
                return c.isupper()
            if name == "isLowerCase":
                return c.islower()
            if name == "toUpperCase":
                return JChar(ord(c.upper()))
            if name == "toLowerCase":
                return JChar(ord(c.lower()))
            if name == "getNumericValue":
                return int(c, 36) if c.isalnum() else -1
            if name == "valueOf":
                return a[0]
            if name == "digit":
                try:
                    return int(c, a[1])
                except ValueError:
                    return -1
        if cls == "Math":
            if name == "abs":
                return type(a[0])(abs(a[0])) if isinstance(a[0], int) else abs(a[0])
            if name == "min":
                return min(a[0], a[1])
            if name == "max":
                return max(a[0], a[1])
        if cls == "String":
            if name == "valueOf" or name == "copyValueOf":
                if isinstance(a[0], JArray):
                    return "".join(chr(int(x)) for x in a[0].a)
                return jstr(a[0])
            if name == "format":
                return _jformat(a[0], a[1:])
            if name == "join":
                items = a[1].a if len(a) == 2 and isinstance(a[1], JArray) else a[1:]
                return jstr(a[0]).join(jstr(x) for x in items)
        if cls == "Arrays":
            if name == "equals":
                self.rec(a[0], a[1])
                if not isinstance(a[0], JArray) or not isinstance(a[1], JArray):
                    return a[0] is a[1]
                return [int(x) for x in a[0].a] == [int(x) for x in a[1].a]
            if name == "copyOf":
                items = list(a[0].a[:a[1]]) + [default_of(a[0].etype)] * max(0, a[1] - len(a[0].a))
                return JArray(a[0].etype, items)
            if name == "copyOfRange":
                return JArray(a[0].etype, list(a[0].a[a[1]:a[2]]))
            if name == "fill":
                a[0].a[:] = [coerce(a[0].etype, a[1])] * len(a[0].a)
                return None
        if cls == "Base64":
            if name == "getEncoder" or name == "getUrlEncoder":
                return Stub("Base64.enc")
            if name == "getDecoder" or name == "getUrlDecoder":
                return Stub("Base64.dec")
        if cls == "URLEncoder" and name == "encode":
            return urllib.parse.quote_plus(a[0])
        if cls == "URLDecoder" and name == "decode":
            return urllib.parse.unquote_plus(a[0])
        if cls == "System":
            return None
        raise JavaError(f"unsupported static call {cls}.{name}")


# --------------------------------------------------------------------------- solver

@dataclass
class Solution:
    """Result of :func:`solve_source`."""
    ok: bool
    password: str = ""
    confidence: str = "none"      # high | medium | low | none
    checker: str = ""
    length: int = 0
    notes: list[str] = field(default_factory=list)
    unconstrained: list[int] = field(default_factory=list)
    error: str = ""

    @property
    def flag(self) -> str:
        return f"picoCTF{{{self.password}}}" if self.ok else ""


def _atom_score(x: int, y: int) -> float:
    if x == y:
        return 1.0
    width = 32 if -(1 << 31) <= x < (1 << 32) and -(1 << 31) <= y < (1 << 32) else 64
    d = bin((x ^ y) & ((1 << width) - 1)).count("1")
    return 0.5 * (1 - d / width)


def _score(events: list[tuple[list[int], list[int]]]) -> float:
    total = 0.0
    for a, b in events:
        for i in range(max(len(a), len(b))):
            if i < len(a) and i < len(b):
                total += _atom_score(a[i], b[i])
        total -= 2 * abs(len(a) - len(b))  # a length mismatch can never be an exact match
    return total


def find_checker(interp: Interp) -> Optional[Method]:
    """``checkPassword`` if present, else any boolean method taking a single String."""
    for m in interp.info.methods:
        if m.name == "checkPassword" and len(m.params) == 1:
            return m
    for m in interp.info.methods:
        if m.rtype == "boolean" and len(m.params) == 1 and m.params[0][0] == "String" and m.name != "main":
            return m
    return None


def _length_candidates(src: str) -> list[int]:
    cands = {int(x) for x in re.findall(r"(?<![\w.])(\d{1,3})(?![\w.])", src) if 1 <= int(x) <= 128}
    cands.update(range(1, 41))  # typical password lengths, also covers lengths implied by array literals
    for lit in re.findall(r'"((?:\\.|[^"\\])*)"', src):
        for div in (1, 2, 3, 4):  # raw, hex pairs, %xx triples, base64 blocks
            if 1 <= len(lit) // div <= 128:
                cands.add(len(lit) // div)
    return sorted(cands)


def solve_source(src: str, length: Optional[int] = None, budget_s: float = 60.0) -> Solution:
    """Statically derive the accepted password from VaultDoor-style Java source text."""
    deadline = time.monotonic() + budget_s
    try:
        info = Parser(tokenize(src)).parse_file()
    except ParseError as exc:
        return Solution(False, error=f"could not parse Java source: {exc}")
    interp = Interp(info)
    chk = find_checker(interp)
    if chk is None:
        return Solution(False, error="no checkPassword(String) method found")
    if chk.body is None:
        return Solution(False, error=f"{chk.name} uses unsupported Java syntax ({chk.skipped})")
    sol = Solution(False, checker=f"{chk.name}(String) in {', '.join(info.classes[:1]) or '?'}")

    def run_probe(pw: str) -> tuple[list, Optional[str]]:
        try:
            interp.call(chk.name, [pw], probe=True)
            return interp.events, None
        except (JavaError, JavaLimit, KeyError, IndexError, TypeError, ValueError, RecursionError) as exc:
            return interp.events, f"{type(exc).__name__}: {exc}"

    def strict(pw: str) -> Optional[bool]:
        try:
            return bool(interp.call(chk.name, [pw], probe=False))
        except (JavaError, JavaLimit, KeyError, IndexError, TypeError, ValueError, RecursionError):
            return None

    # 1. length
    fills = ["A", "0", "a", "_"]
    if length is None:
        best = (-1.0, 0)
        for n in _length_candidates(src):
            ev, _ = run_probe("A" * n)
            sc = _score(ev) + (0.0001 if _ is None else 0.0)
            if sc > best[0] + 1e-9:
                best = (sc, n)
        length = best[1]
        if not length:
            sol.error = "could not determine the password length (try --length N)"
            return sol
        sol.notes.append(f"password length {length} chosen as best-scoring candidate from literals in the source")
    else:
        sol.notes.append(f"password length {length} given by --length")
    sol.length = length

    best_fill = max(fills, key=lambda f: (_score(run_probe(f * length)[0]), -fills.index(f)))
    pw = [best_fill] * length
    cands = [c for c in _CAND_ORDER]

    # 2. dependency scan: which comparison atoms does each position control?
    base_ev, base_err = run_probe("".join(pw))
    if not base_ev:
        sol.error = ("the checker performed no comparisons I can observe"
                     + (f" (evaluator stopped: {base_err})" if base_err else ""))
        return sol
    base_atoms = {(e, i): (a[i] if i < len(a) else None, b[i] if i < len(b) else None)
                  for e, (a, b) in enumerate(base_ev) for i in range(max(len(a), len(b)))}
    alts = []
    for x in (1, 2, 16, 32):
        c = chr(ord(best_fill) ^ x)
        if c.isprintable() and c != best_fill:
            alts.append(c)
    owners: dict[tuple, set] = {}
    owned_by: dict[int, set] = {k: set() for k in range(length)}
    for k in range(length):
        if time.monotonic() > deadline:
            sol.notes.append("time budget hit during dependency scan")
            break
        for alt in alts:
            trial = pw[:]
            trial[k] = alt
            ev, _ = run_probe("".join(trial))
            for e in range(min(len(ev), len(base_ev))):
                a, b = ev[e]
                for i in range(max(len(a), len(b))):
                    cur = (a[i] if i < len(a) else None, b[i] if i < len(b) else None)
                    if base_atoms.get((e, i)) != cur:
                        owners.setdefault((e, i), set()).add(k)
                        owned_by[k].add((e, i))

    # 3. positions that own atoms alone: one pass over all printable characters
    exact: dict[str, set] = {}
    solo = [k for k in range(length) if owned_by[k] and all(owners[a] == {k} for a in owned_by[k])]
    accepted: dict[int, list[str]] = {}
    if solo:
        for c in cands:
            if time.monotonic() > deadline:
                sol.notes.append("time budget hit during the character scan")
                break
            ev, _ = run_probe(c * length)
            ok_atoms = {(e, i) for e, (a, b) in enumerate(ev) for i in range(min(len(a), len(b))) if a[i] == b[i]}
            exact[c] = ok_atoms
        for k in solo:
            accepted[k] = [c for c in cands if c in exact and owned_by[k] <= exact[c]]
    solved_fast = 0
    todo: list[int] = []
    subset: dict[int, list[str]] = {}
    for k in range(length):
        acc = accepted.get(k, [])
        if len(acc) == 1:
            pw[k] = acc[0]
            solved_fast += 1
        elif acc:
            pw[k] = acc[0]
            todo.append(k)
            subset[k] = acc
        elif owned_by[k]:
            todo.append(k)
            subset[k] = cands
    if solved_fast:
        sol.notes.append(f"{solved_fast} position(s) pinned down independently by the comparison scan")

    # 4. coordinate hill-climbing for positions that share/are ambiguous
    def total(p: list[str]) -> float:
        return _score(run_probe("".join(p))[0])

    if todo:
        cur = total(pw)
        for _ in range(3):
            changed = False
            for k in todo:
                if time.monotonic() > deadline:
                    break
                best_c, best_s = pw[k], cur
                for c in subset[k]:
                    if c == pw[k]:
                        continue
                    trial = pw[:]
                    trial[k] = c
                    s = total(trial)
                    if s > best_s + 1e-9:
                        best_c, best_s = c, s
                if best_c != pw[k]:
                    pw[k] = best_c
                    cur = best_s
                    changed = True
            if not changed or time.monotonic() > deadline:
                break
        sol.notes.append(f"{len(todo)} position(s) refined by hill-climbing on comparison similarity")
        if time.monotonic() > deadline:
            sol.notes.append("time budget reached - result may be incomplete (raise --budget)")

    # 5. verify with the strict (normal-semantics) evaluator
    candidate = "".join(pw)
    sol.password = candidate
    sol.unconstrained = [k for k in range(length) if not owned_by[k]]
    verdict = strict(candidate)
    final_ev, _ = run_probe(candidate)
    all_exact = bool(final_ev) and all(a == b for a, b in final_ev if a or b)
    sol.ok = True
    if verdict is True:
        sol.confidence = "high"
        sol.notes.append("verified: this tool's own evaluator runs checkPassword() on the candidate and gets true")
    elif all_exact:
        sol.confidence = "medium"
        sol.notes.append("every observed comparison matches, but the strict re-run did not return true - "
                         "a check outside the model may exist; verify by hand")
    else:
        sol.confidence = "low"
        sol.notes.append("best-effort guess: some comparisons still differ; treat as a lead, not an answer")
    if sol.unconstrained:
        sol.notes.append(f"position(s) {sol.unconstrained} never influenced a comparison; filled with '{best_fill}'")
    return sol


def format_solution(path: str, sol: Solution) -> str:
    """Report text in the toolkit's junior-analyst style: what was found, how sure, what to do next."""
    out = [f"vaultdoor: {path}", "  (static analysis only - the Java source was parsed and interpreted by this tool; "
                                 "nothing was compiled or run)"]
    if not sol.ok:
        out.append(f"  result: no password derived - {sol.error}")
        out.append("  next steps: read checkPassword() by hand; check for syntax this subset parser skips "
                   "(switch/try/anonymous classes), or pass --length N.")
        return "\n".join(out)
    out += [f"  checker: {sol.checker}", f"  password length: {sol.length}",
            f"  candidate password: {sol.password}", f"  flag: {sol.flag}",
            f"  confidence: {sol.confidence.upper()}"]
    for n in sol.notes:
        out.append(f"  - {n}")
    out.append("  next step: submit the flag; if it is rejected, re-read checkPassword() against the password above.")
    return "\n".join(out)


# --------------------------------------------------------------------------- CLI

def run(args: list[str]) -> int:
    """CLI: ``vaultdoor <VaultDoor.java> [--length N] [--budget SECONDS]``; exit 0 solved, 1 not solved, 2 usage."""
    if args[:1] in (["selftest"], ["--selftest"]):
        return 0 if selftest() else 1
    p = argparse.ArgumentParser(prog="recon.py vaultdoor", description=DESCRIPTION)
    p.add_argument("file", help="VaultDoor*.java source file (read as text only), or - for stdin")
    p.add_argument("--length", type=int, default=None, help="password length if it cannot be inferred")
    p.add_argument("--budget", type=float, default=60.0, help="time budget in seconds (default 60)")
    try:
        ns = p.parse_args(args)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        src = sys.stdin.read() if ns.file == "-" else open(ns.file, encoding="utf-8", errors="replace").read()
    except OSError as exc:
        print(f"vaultdoor: cannot read {ns.file}: {exc.strerror or exc}", file=sys.stderr)
        return 1
    sol = solve_source(src, ns.length, ns.budget)
    print(format_solution(ns.file, sol))
    return 0 if sol.ok else 1


# --------------------------------------------------------------------------- selftest

def _enc_bytes(pw: str) -> str:
    """Render pw^0x55 as a mix of hex / decimal / octal / char literals (like VaultDoor6)."""
    styles = [lambda v: f"0x{v:x}", lambda v: str(v), lambda v: f"0{v:o}", lambda v: f"(byte) {v}"]
    return ", ".join(styles[i % 4](ord(c) ^ 0x55) for i, c in enumerate(pw))


_SAMPLE_LITERAL = (
    "public class VaultDoorTraining {\n"
    "    public boolean checkPassword(String password) {\n"
    '        return password.equals("w4rm1ng_Up_w1tH_jAv4");\n'
    "    }\n"
    "}\n"
)

_SAMPLE_CHARAT = (
    "class VaultDoor1 {\n"
    "    // comment with 99 in it\n"
    "    public boolean checkPassword(String password) {\n"
    "        return password.length() == 8 &&\n"
    "               password.charAt(3) == 'l' &&\n"
    "               password.charAt(0) == 'd' && password.charAt(1) == '3' &&\n"
    "               password.charAt(2) == 'b' && password.charAt(4) == 'u' &&\n"
    "               password.charAt(7) == '!' && password.charAt(5) == 'g' && password.charAt(6) == '_';\n"
    "    }\n"
    "}\n"
)

_SAMPLE_CHARARRAY = (  # VaultDoor3: permuted copy into a char[], compared with a literal
    "class VaultDoor3 {\n"
    "    public boolean checkPassword(String password) {\n"
    "        if (password.length() != 8) return false;\n"
    "        char[] buffer = new char[8];\n"
    "        int i;\n"
    "        for (i = 0; i < 4; i++) buffer[i] = password.charAt(i);\n"
    "        for (; i < 8; i++) buffer[i] = password.charAt(11 - i);\n"
    "        String s = new String(buffer);\n"
    '        return s.equals("jU5ts_a_");\n'
    "    }\n"
    "}\n"
)

_PW_XOR = "x0r_k3y!"
_SAMPLE_XOR = (  # VaultDoor6: byte[] literals (hex/dec/octal) with an XOR loop
    "class VaultDoor6 {\n"
    "    public boolean checkPassword(String password) {\n"
    "        if (password.length() != 8) return false;\n"
    "        byte[] passBytes = password.getBytes();\n"
    "        byte[] myBytes = { " + _enc_bytes(_PW_XOR) + " };\n"
    "        for (int i = 0; i < 8; i++) {\n"
    "            if (((passBytes[i] ^ 0x55) - myBytes[i]) != 0) return false;\n"
    "        }\n"
    "        return true;\n"
    "    }\n"
    "}\n"
)

_SAMPLE_RADIX = (  # base conversion: hex string decoded with parseInt(radix 16)
    "class VaultDoorHex {\n"
    "    public boolean checkPassword(String password) {\n"
    '        String hex = "70347373773072645f6f6b21";\n'
    "        byte[] b = new byte[hex.length() / 2];\n"
    "        for (int i = 0; i < b.length; i++) {\n"
    "            b[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);\n"
    "        }\n"
    "        return password.equals(new String(b));\n"
    "    }\n"
    "}\n"
)
_PW_RADIX = bytes.fromhex("70347373773072645f6f6b21").decode()

_SAMPLE_PACK = (  # VaultDoor7: 4 chars packed per int (shared atoms -> hill-climbing path)
    "class VaultDoor7 {\n"
    "    public int[] passwordToIntArray(String hex) {\n"
    "        int[] x = new int[2];\n"
    "        byte[] hexBytes = hex.getBytes();\n"
    "        for (int i = 0; i < 2; i++) {\n"
    "            x[i] = hexBytes[i*4]   << 24\n"
    "                 | hexBytes[i*4+1] << 16\n"
    "                 | hexBytes[i*4+2] << 8\n"
    "                 | hexBytes[i*4+3];\n"
    "        }\n"
    "        return x;\n"
    "    }\n"
    "    public boolean checkPassword(String password) {\n"
    "        if (password.length() != 8) return false;\n"
    "        int[] x = passwordToIntArray(password);\n"
    "        return x[0] == 1936942435 && x[1] == 1969582431;\n"
    "    }\n"
    "}\n"
)
_PW_PACK = (1936942435).to_bytes(4, "big").decode() + (1969582431).to_bytes(4, "big").decode()

_SAMPLE_BITS = (  # VaultDoor8: per-char bit swaps via a helper method
    "class VaultDoor8 {\n"
    "    public char[] scramble(String password) {\n"
    "        char[] a = password.toCharArray();\n"
    "        for (int b = 0; b < a.length; b++) {\n"
    "            char c = a[b];\n"
    "            c = switchBits(c, 1, 2);\n"
    "            c = switchBits(c, 0, 3); /* c = switchBits(c, 14, 3); */\n"
    "            c = switchBits(c, 5, 6);\n"
    "            c = switchBits(c, 4, 7);\n"
    "            a[b] = c;\n"
    "        }\n"
    "        return a;\n"
    "    }\n"
    "    public char switchBits(char c, int p1, int p2) {\n"
    "        char mask1 = (char)(1 << p1);\n"
    "        char mask2 = (char)(1 << p2);\n"
    "        char bit1 = (char)(c & mask1);\n"
    "        char bit2 = (char)(c & mask2);\n"
    "        char rest = (char)(c & ~(mask1 | mask2));\n"
    "        char shift = (char)(p2 - p1);\n"
    "        char result = (char)((bit1 << shift) | (bit2 >> shift) | rest);\n"
    "        return result;\n"
    "    }\n"
    "    public boolean checkPassword(String password) {\n"
    "        char[] scrambled = scramble(password);\n"
    "        char[] expected = { @@EXP@@ };\n"
    "        return java.util.Arrays.equals(scrambled, expected);\n"
    "    }\n"
    "}\n"
)


def _switch_bits(c: int, p1: int, p2: int) -> int:
    m1, m2 = 1 << p1, 1 << p2
    sh = p2 - p1
    return ((c & m1) << sh) | ((c & m2) >> sh) | (c & ~(m1 | m2))


def _scramble(c: int) -> int:
    for p1, p2 in ((1, 2), (0, 3), (5, 6), (4, 7)):
        c = _switch_bits(c, p1, p2)
    return c


_PW_BITS = "b1ts_4r3"

_SAMPLE_URL = (  # VaultDoor5: password -> url-encode -> base64, compared with a literal
    "import java.util.*;\n"
    "class VaultDoor5 {\n"
    "    public String base64Encode(byte[] input) {\n"
    "        return Base64.getEncoder().encodeToString(input);\n"
    "    }\n"
    "    public String urlEncode(byte[] input) {\n"
    "        StringBuffer buf = new StringBuffer();\n"
    "        for (int i = 0; i < input.length; i++) {\n"
    '            buf.append(String.format("%%%2x", input[i]));\n'
    "        }\n"
    "        return buf.toString();\n"
    "    }\n"
    "    public boolean checkPassword(String password) {\n"
    "        String urlEncoded = urlEncode(password.getBytes());\n"
    "        String base64Encoded = base64Encode(urlEncoded.getBytes());\n"
    '        String expected = "@@EXP@@";\n'
    "        return base64Encoded.equals(expected);\n"
    "    }\n"
    "}\n"
)
_PW_URL = "c0nv3rt"


def selftest() -> bool:
    """Derive known passwords from embedded VaultDoor-style samples; nothing is read from disk or run."""
    results: list[bool] = []

    def check(name: str, cond: bool) -> None:
        results.append(bool(cond))
        if not cond:
            print(f"  failed: {name}")

    def solves(name: str, src: str, pw: str, conf: str = "high") -> None:
        sol = solve_source(src, budget_s=30)
        check(f"{name}: password", sol.ok and sol.password == pw)
        check(f"{name}: flag wrapper", sol.flag == f"picoCTF{{{pw}}}")
        check(f"{name}: confidence", sol.confidence == conf)

    solves("literal compare", _SAMPLE_LITERAL, "w4rm1ng_Up_w1tH_jAv4")
    solves("charAt constraints", _SAMPLE_CHARAT, "d3blug_!")
    solves("char-array permutation", _SAMPLE_CHARARRAY, "jU5t_a_s")
    solves("xor byte loop", _SAMPLE_XOR, _PW_XOR)
    solves("parseInt radix 16", _SAMPLE_RADIX, _PW_RADIX)
    solves("int packing (shared atoms)", _SAMPLE_PACK, _PW_PACK)
    bits_expected = ", ".join(str(_scramble(ord(c))) for c in _PW_BITS)
    solves("bit-swap helper methods", _SAMPLE_BITS.replace("@@EXP@@", bits_expected), _PW_BITS)
    url_enc = base64.b64encode("".join(f"%{ord(c):2x}" for c in _PW_URL).encode()).decode()
    solves("url-encode + base64", _SAMPLE_URL.replace("@@EXP@@", url_enc), _PW_URL)

    # interpreter semantics the solver relies on
    it = Interp(Parser(tokenize(
        "class T { int f(int a) { byte b = (byte) 200; char c = 'a'; c += 2; long l = 1L << 40; "
        "return a + b + c + (int)(l >>> 38) + (-7 / 2) + (-7 % 3) + (0x80000000 >>> 28); } }")).parse_file())
    check("interpreter arithmetic", it.call("f", [1]) == 1 + (-56) + ord("c") + 4 + (-3) + (-1) + 8)

    # degrade honestly instead of crashing
    bad = solve_source("class X { void foo() { } }")
    check("no checker -> clean failure", not bad.ok and "checkPassword" in bad.error)
    bad = solve_source("class X { boolean checkPassword(String p) { switch (p.length()) { default: return true; } } }")
    check("unsupported syntax -> clean failure", not bad.ok and "unsupported" in bad.error)
    bad = solve_source("this is not java {{{")
    check("garbage source -> clean failure", not bad.ok)
    text = format_solution("x.java", solve_source(_SAMPLE_LITERAL))
    check("report has flag + confidence", "picoCTF{w4rm1ng_Up_w1tH_jAv4}" in text and "HIGH" in text)
    import contextlib
    import io
    with contextlib.redirect_stderr(io.StringIO()):
        check("run(): missing file exits 1", run(["/nonexistent/VaultDoor.java"]) == 1)
    return all(results)


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
