"""DECODE: encodings, classical ciphers, XOR brute-force and cipher-ID hints for CTF work.

Pure stdlib, fully offline.  Library functions are importable; ``run`` is the CLI.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import contextlib
import io
import re
import string
import sys
import urllib.parse

NAME = "decode"
DESCRIPTION = "Decode/encode (b64/b32/b58/hex/url/bin/dec/oct), rot/atbash/vigenere, XOR brute-force, cipher-ID hints"

# --------------------------------------------------------------------------- scoring

EN_FREQ = {
    "e": .1270, "t": .0906, "a": .0817, "o": .0751, "i": .0697, "n": .0675, "s": .0633, "h": .0609,
    "r": .0599, "d": .0425, "l": .0403, "c": .0278, "u": .0276, "m": .0241, "w": .0236, "f": .0223,
    "g": .0202, "y": .0197, "p": .0193, "b": .0129, "v": .0098, "k": .0077, "j": .0015, "x": .0015,
    "q": .0010, "z": .0007,
}
COMMON_BIGRAMS = {
    "th", "he", "in", "er", "an", "re", "on", "at", "en", "nd", "ti", "es", "or", "te", "of", "ed",
    "is", "it", "al", "ar", "st", "to", "nt", "ng", "se", "ha", "as", "ou", "io", "le", "ve", "co",
    "me", "de", "hi", "ri", "ro", "ic", "ne", "ea", "ra", "ce", "li", "ch", "ll", "be", "ma", "si",
}
_PRINTABLE = set(bytes(string.printable, "ascii")) - {0x0B, 0x0C}


def printable_ratio(data: bytes) -> float:
    """Fraction of bytes that are printable ASCII (incl. tab/newline/CR)."""
    return sum(b in _PRINTABLE for b in data) / len(data) if data else 0.0


def english_score(data: bytes) -> float:
    """Score 0..1 of how English-like ``data`` is (printable ratio + letter frequency + bigrams + spaces)."""
    if not data:
        return 0.0
    pr = printable_ratio(data)
    if pr < 0.85:
        return pr * 0.2
    text = data.decode("latin-1").lower()
    letters = [c for c in text if "a" <= c <= "z"]
    if not letters:
        return pr * 0.3 * 0.5
    n = len(letters)
    obs = {c: 0 for c in EN_FREQ}
    for c in letters:
        obs[c] += 1
    freq = 1.0 - 0.5 * sum(abs(obs[c] / n - EN_FREQ[c]) for c in EN_FREQ)
    pairs = [text[i:i + 2] for i in range(len(text) - 1) if text[i:i + 2].isalpha()]
    big = sum(p in COMMON_BIGRAMS for p in pairs) / len(pairs) if pairs else 0.0
    space = min(text.count(" ") / len(text) / 0.15, 1.0)
    alpha_share = min(n / len(text) / 0.7, 1.0)
    return pr * 0.2 + freq * 0.3 + big * 0.2 + space * 0.15 + alpha_share * 0.15


def plaintext_like(data: bytes) -> bool:
    """Heuristic: is this already human-readable text (so decoding can stop)?"""
    return len(data) > 0 and printable_ratio(data) >= 0.95 and b" " in data and english_score(data) >= 0.55


# --------------------------------------------------------------------------- codecs
# Each decoder takes str, returns bytes or None.  Each encoder takes bytes, returns str.

B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58_encode(data: bytes) -> str:
    num = int.from_bytes(data, "big")
    out = ""
    while num:
        num, r = divmod(num, 58)
        out = B58_ALPHABET[r] + out
    pad = len(data) - len(data.lstrip(b"\0"))
    return "1" * pad + out


def b58_decode(s: str) -> bytes | None:
    s = s.strip()
    if not s or any(c not in B58_ALPHABET for c in s):
        return None
    num = 0
    for c in s:
        num = num * 58 + B58_ALPHABET.index(c)
    body = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    return b"\0" * (len(s) - len(s.lstrip("1"))) + body


def b64_decode(s: str) -> bytes | None:
    s = re.sub(r"\s+", "", s)
    if not s or len(s) % 4 == 1:
        return None
    try:
        if re.fullmatch(r"[A-Za-z0-9+/]+=*", s):
            return base64.b64decode(s + "=" * (-len(s) % 4), validate=True)
        if re.fullmatch(r"[A-Za-z0-9_-]+=*", s):  # urlsafe alphabet
            return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except (binascii.Error, ValueError):
        pass
    return None


def b32_decode(s: str) -> bytes | None:
    s = re.sub(r"\s+", "", s).upper()
    if not s or not re.fullmatch(r"[A-Z2-7]+=*", s):
        return None
    try:
        return base64.b32decode(s + "=" * (-len(s) % 8))
    except (binascii.Error, ValueError):
        return None


def hex_decode(s: str) -> bytes | None:
    s = re.sub(r"0x|\\x|[\s:,-]", "", s.strip())
    if not s or len(s) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", s):
        return None
    return bytes.fromhex(s)


def url_decode(s: str) -> bytes | None:
    if not re.search(r"%[0-9a-fA-F]{2}", s):
        return None
    return urllib.parse.unquote_to_bytes(s)


def bin_decode(s: str) -> bytes | None:
    t = re.sub(r"[\s,]", "", s)
    if not t or len(t) % 8 or not re.fullmatch(r"[01]+", t):
        return None
    return bytes(int(t[i:i + 8], 2) for i in range(0, len(t), 8))


def _tokens(s: str) -> list[str]:
    return [t for t in re.split(r"[\s,;]+", s.strip()) if t]


def dec_decode(s: str) -> bytes | None:
    toks = _tokens(s)
    if not toks or not all(t.isdigit() for t in toks):
        return None
    vals = [int(t) for t in toks]
    return bytes(vals) if all(v < 256 for v in vals) else None


def oct_decode(s: str) -> bytes | None:
    toks = _tokens(s)
    if not toks or not all(re.fullmatch(r"[0-7]{1,3}", t) for t in toks):
        return None
    vals = [int(t, 8) for t in toks]
    return bytes(vals) if all(v < 256 for v in vals) else None


def _txt(b: bytes) -> str:
    return b.decode("latin-1")


DECODERS = {
    "base64": b64_decode,
    "base32": b32_decode,
    "base58": b58_decode,
    "hex": hex_decode,
    "url": url_decode,
    "binary": bin_decode,
    "decimal": dec_decode,
    "octal": oct_decode,
}
ENCODERS = {
    "base64": lambda b: base64.b64encode(b).decode(),
    "base32": lambda b: base64.b32encode(b).decode(),
    "base58": b58_encode,
    "hex": lambda b: b.hex(),
    "url": lambda b: urllib.parse.quote_from_bytes(b, safe=""),
    "binary": lambda b: " ".join(f"{x:08b}" for x in b),
    "decimal": lambda b: " ".join(str(x) for x in b),
    "octal": lambda b: " ".join(f"{x:03o}" for x in b),
    "ascii": lambda b: _txt(b),
}


def auto_decode(text: str, max_rounds: int = 10) -> tuple[bytes, list[str]]:
    """Repeatedly decode ``text`` with the best-scoring applicable decoder.

    Returns (final bytes, chain of encoding names).  Stops when the data looks like plaintext,
    no decoder yields mostly-printable output, or max_rounds is reached.
    """
    cur = text.encode("latin-1", "replace")
    chain: list[str] = []
    seen = {cur}  # fixed-point / cycle guard (in addition to the max_rounds cap)
    for _ in range(max(0, min(max_rounds, 50))):
        if plaintext_like(cur) and not re.fullmatch(rb"\S+", cur.strip()):
            break
        s = _txt(cur).strip()
        best: tuple[float, str, bytes] | None = None
        for name, fn in DECODERS.items():
            out = fn(s)
            if not out or printable_ratio(out) < 0.9:
                continue
            sc = english_score(out)
            if best is None or sc > best[0]:
                best = (sc, name, out)
        if best is None or out_is_noise(best[2]) or best[2] in seen:
            break
        seen.add(best[2])
        chain.append(best[1])
        cur = best[2]
    return cur, chain


def out_is_noise(b: bytes) -> bool:
    """Reject decodes whose result is printable by accident (e.g. 1-2 chars of junk)."""
    return len(b) < 2 or english_score(b) < 0.25


# --------------------------------------------------------------------------- classical ciphers

def rot(text: str, shift: int) -> str:
    """Caesar-shift letters by ``shift`` (digits/punctuation untouched)."""
    out = []
    for c in text:
        if "a" <= c <= "z":
            out.append(chr((ord(c) - 97 + shift) % 26 + 97))
        elif "A" <= c <= "Z":
            out.append(chr((ord(c) - 65 + shift) % 26 + 65))
        else:
            out.append(c)
    return "".join(out)


def rot_bruteforce(text: str) -> list[tuple[float, int, str]]:
    """All 25 shifts as (score, shift, plaintext), best first."""
    res = [(english_score(rot(text, k).encode("latin-1", "replace")), k, rot(text, k)) for k in range(1, 26)]
    return sorted(res, reverse=True)


def atbash(text: str) -> str:
    out = []
    for c in text:
        if "a" <= c <= "z":
            out.append(chr(122 - (ord(c) - 97)))
        elif "A" <= c <= "Z":
            out.append(chr(90 - (ord(c) - 65)))
        else:
            out.append(c)
    return "".join(out)


def vigenere(text: str, key: str, decrypt: bool = True) -> str:
    """Vigenere with an alphabetic key; key advances only on letters, case preserved."""
    ks = [ord(k.lower()) - 97 for k in key if k.isalpha()]
    if not ks:
        raise ValueError("vigenere key must contain letters")
    out, i = [], 0
    for c in text:
        if c.isascii() and c.isalpha():
            base = 97 if c.islower() else 65
            k = ks[i % len(ks)] * (-1 if decrypt else 1)
            out.append(chr((ord(c) - base + k) % 26 + base))
            i += 1
        else:
            out.append(c)
    return "".join(out)


# --------------------------------------------------------------------------- XOR

def xor_repeating(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("empty XOR key")
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def xor_bruteforce(data: bytes) -> list[tuple[float, int, bytes]]:
    """All 256 single-byte keys as (score, key, plaintext), best first."""
    res = []
    for k in range(256):
        pt = bytes(b ^ k for b in data)
        res.append((english_score(pt), k, pt))
    return sorted(res, key=lambda r: (-r[0], r[1]))


# --------------------------------------------------------------------------- hints

def hints(s: str) -> list[str]:
    """Heuristic guesses about what ``s`` is.  These are HINTS only, not certainties."""
    out: list[str] = []
    t = s.strip()
    compact = re.sub(r"\s+", "", t)
    if not compact:
        return out
    n = len(compact)
    if re.fullmatch(r"[01\s]+", t) and n % 8 == 0:
        out.append("binary: only 0/1, length multiple of 8 -> 8-bit ASCII (--decode binary)")
    if re.fullmatch(r"[0-7\s,]+", t) and len(_tokens(t)) > 1 and all(len(x) <= 3 for x in _tokens(t)):
        out.append("octal: space-separated 1-3 digit groups of 0-7 (--decode octal)")
    if re.fullmatch(r"[\d\s,;]+", t) and len(_tokens(t)) > 1 and dec_decode(t) is not None:
        out.append("decimal ASCII codes: numbers all < 256 (--decode decimal)")
    if re.fullmatch(r"(?:0x|\\x)?[0-9a-fA-F]{2}(?:[\s:,-]?(?:0x|\\x)?[0-9a-fA-F]{2})*", t) and n % 2 == 0:
        out.append("hex: only hex digits, even length (--decode hex)")
        if n in (32, 40, 64, 128):
            out.append(f"also {n} hex chars matches a hash: {dict({32: 'MD5', 40: 'SHA-1', 64: 'SHA-256', 128: 'SHA-512'})[n]} (not reversible)")
    if re.search(r"%[0-9a-fA-F]{2}", t):
        out.append("url-encoding: contains %XX escapes (--decode url)")
    if re.fullmatch(r"[A-Z2-7]+=*", compact) and n % 8 == 0:
        out.append("base32: charset A-Z2-7, length multiple of 8" + (", '=' padding" if compact.endswith("=") else ""))
    if re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", compact) and n % 4 == 0:
        why = "ends with '=' padding" if compact.endswith("=") else "charset A-Za-z0-9+/, length multiple of 4"
        out.append(f"base64: {why}")
    elif re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", compact) and n % 4 != 1 and ("-" in compact or "_" in compact):
        out.append("base64 (URL-safe variant): uses - and _")
    if re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]+", compact) and n >= 8:
        out.append("base58: charset excludes 0 O I l (Bitcoin alphabet)")
    if re.fullmatch(r"[A-Za-z\s.,'!?-]+", t) and sum(c.isalpha() for c in t) >= 8:
        letters = [c for c in t.lower() if c.isalpha()]
        if english_score(t.encode()) < 0.55:
            ic = sum(letters.count(c) * (letters.count(c) - 1) for c in set(letters)) / max(len(letters) * (len(letters) - 1), 1)
            if ic > 0.055:
                out.append(f"letters only, index of coincidence {ic:.3f} (English ~0.066): monoalphabetic substitution/Caesar/ROT13/Atbash likely (--rot, --atbash)")
            else:
                out.append(f"letters only, index of coincidence {ic:.3f} (~0.038 = random): polyalphabetic (Vigenere) likely; need a key (--vigenere KEY)")
        else:
            out.append("already reads like English plaintext")
    if re.fullmatch(r"[A-Za-z0-9{}_]+", compact) and re.search(r"\w+\{.+\}", compact):
        out.append("flag-like format word{...}: if gibberish inside, try --rot / --atbash on it")
    if re.fullmatch(r"[0-9a-fA-F]+", compact) and n % 2 == 0 and n >= 4:
        out.append("if hex decodes to unreadable bytes: try --xor-brute (single-byte XOR)")
    if not out:
        out.append("no strong pattern; try --xor-brute on raw bytes or -f with a file")
    return out


# --------------------------------------------------------------------------- CLI

def _show(data: bytes, limit: int = 400) -> str:
    if printable_ratio(data) >= 0.9:
        s = data.decode("latin-1")
    else:
        s = repr(data)[2:-1] + "  [hex " + data.hex()[:80] + ("..." if len(data) > 40 else "") + "]"
    return s if len(s) <= limit else s[:limit] + "..."


def _read_input(ns) -> bytes | None:
    if ns.file:
        try:
            with open(ns.file, "rb") as fh:
                return fh.read()
        except OSError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return None
    if ns.input:
        return " ".join(ns.input).encode("utf-8", "surrogateescape")
    if not sys.stdin.isatty():
        return sys.stdin.buffer.read()
    print("error: no input (give text, -f FILE, or pipe via stdin)", file=sys.stderr)
    return None


def _xor_data(raw: bytes) -> bytes:
    """For XOR modes: treat input as hex text if it is, else raw bytes."""
    h = hex_decode(raw.decode("latin-1").strip()) if len(raw) < 1 << 20 else None
    return h if h is not None else raw


def _parse_key(k: str) -> bytes:
    if k.lower().startswith("0x"):
        return bytes.fromhex(k[2:])
    return k.encode()


def run(args: list[str]) -> int:
    """CLI entry point (registry contract); returns a process exit code."""
    if args[:1] in (["selftest"], ["--selftest"]):
        return 0 if selftest() else 1
    p = argparse.ArgumentParser(prog="recon.py decode", description=DESCRIPTION,
                                epilog="With no mode flag: hints + auto multi-round decode (+ rot/xor fallbacks).")
    p.add_argument("input", nargs="*", help="text to process (or use -f / stdin)")
    p.add_argument("-f", "--file", help="read input from file")
    g = p.add_argument_group("modes")
    g.add_argument("-d", "--decode", choices=sorted(DECODERS), help="decode with this encoding")
    g.add_argument("-e", "--encode", choices=sorted(ENCODERS), help="encode with this encoding")
    g.add_argument("--rounds", type=int, default=10, help="max auto-decode rounds (default 10)")
    g.add_argument("--rot", nargs="?", const="", metavar="N",
                   help="rot N (--rot 5 or --rot=5), or brute-force all 25 (no N)")
    g.add_argument("--atbash", action="store_true")
    g.add_argument("--vigenere", metavar="KEY", help="vigenere decrypt with KEY (--encrypt to encrypt)")
    g.add_argument("--encrypt", action="store_true", help="with --vigenere: encrypt instead")
    g.add_argument("--xor-brute", action="store_true", help="single-byte XOR, all 256 keys (hex text input is auto-decoded)")
    g.add_argument("--xor-key", metavar="KEY", help="repeating-key XOR; KEY text, or 0xHEX")
    g.add_argument("--hints", action="store_true", help="only print cipher-ID hints")
    p.add_argument("--top", type=int, default=5, help="candidates to show (default 5)")
    if not args and sys.stdin.isatty():  # bare invocation, nothing piped: show usage
        p.print_help()
        return 0
    try:
        ns = p.parse_args(args)
    except SystemExit as exc:  # -h -> 0, usage error -> 2; return instead of exiting
        return exc.code if isinstance(exc.code, int) else 2
    if ns.rot is not None:
        # --rot takes an optional value as a string so a following non-numeric
        # token is treated as input (brute-force), while "--rot 5"/"--rot=5" is a shift.
        if ns.rot.lstrip("-").isdigit():
            ns.rot = int(ns.rot)
        else:
            if ns.rot:
                ns.input.insert(0, ns.rot)
            ns.rot = -1

    raw = _read_input(ns)
    if raw is None:
        return 1
    text = raw.decode("latin-1").strip() if not ns.xor_brute and ns.xor_key is None else ""

    try:
        if ns.hints:
            for h in hints(raw.decode("latin-1")):
                print(f"[hint] {h}")
        elif ns.decode:
            out = DECODERS[ns.decode](raw.decode("latin-1"))
            if out is None:
                print(f"error: input is not valid {ns.decode}", file=sys.stderr)
                return 1
            print(_show(out))
        elif ns.encode:
            print(ENCODERS[ns.encode](raw))
        elif ns.rot is not None:
            t = raw.decode("utf-8", "replace")
            if ns.rot == -1:
                print("rank  shift  score  text")
                for i, (sc, k, pt) in enumerate(rot_bruteforce(t), 1):
                    print(f"{i:>4}  {k:>5}  {sc:.3f}  {pt[:100]}")
            else:
                print(rot(t, ns.rot))
        elif ns.atbash:
            print(atbash(raw.decode("utf-8", "replace")))
        elif ns.vigenere:
            print(vigenere(raw.decode("utf-8", "replace"), ns.vigenere, decrypt=not ns.encrypt))
        elif ns.xor_key is not None:
            data = _xor_data(raw)
            print(_show(xor_repeating(data, _parse_key(ns.xor_key))))
        elif ns.xor_brute:
            data = _xor_data(raw)
            print(f"{len(data)} bytes; top {ns.top} of 256 keys")
            for sc, k, pt in xor_bruteforce(data)[:ns.top]:
                print(f"key 0x{k:02x} ({chr(k) if 32 <= k < 127 else '.'})  score {sc:.3f}  {_show(pt, 100)}")
        else:
            _default(raw, text, ns)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


def _default(raw: bytes, text: str, ns) -> None:
    """'Just works' mode for a pasted blob."""
    print("== hints (heuristic guesses, not certainties) ==")
    for h in hints(text):
        print(f"  [hint] {h}")
    print("\n== auto-decode ==")
    final, chain = auto_decode(text, ns.rounds)
    if chain:
        print(f"  chain: {' -> '.join(chain)}")
        print(f"  result: {_show(final)}")
    else:
        print("  no encoding layer detected")
    if plaintext_like(final):
        return
    if printable_ratio(final) >= 0.95:
        print(f"\n== caesar/rot brute-force (top {min(3, ns.top)}) ==")
        for sc, k, pt in rot_bruteforce(_txt(final))[:3]:
            print(f"  rot{k:<2} {sc:.3f}  {pt[:100]}")
        print(f"  atbash: {atbash(_txt(final))[:100]}")
    else:
        print(f"\n== single-byte XOR brute-force (top {ns.top}) ==")
        for sc, k, pt in xor_bruteforce(final)[:ns.top]:
            print(f"  key 0x{k:02x}  {sc:.3f}  {_show(pt, 100)}")


# --------------------------------------------------------------------------- self-test

def selftest() -> bool:
    """Round-trips, known answers and ranking checks, all in memory."""
    results: list[bool] = []

    def check(name: str, cond: bool) -> None:
        results.append(bool(cond))
        if not cond:
            print(f"  failed: {name}")

    sample = b"The quick brown fox jumps over the lazy dog. Flag: CTF{decode_me}"
    binary = bytes([0, 0, 1, 2, 255, 128, 65, 0])
    for name, dec in DECODERS.items():
        for label, payload in (("text", sample), ("binary", binary)):
            if name in ("decimal", "octal", "binary", "hex", "url", "base64", "base32", "base58"):
                enc = ENCODERS[name](payload)
                check(f"roundtrip {name}/{label}", dec(enc) == payload)
    check("ascii conv", ENCODERS["ascii"](b"hi") == "hi")

    check("b64 known", b64_decode("SGVsbG8gV29ybGQ=") == b"Hello World")
    check("b64 no padding", b64_decode("SGVsbG8gV29ybGQ") == b"Hello World")
    check("b32 known", b32_decode("JBSWY3DPEBLW64TMMQ======") == b"Hello World")
    check("b58 known", b58_encode(b"Hello World") == "JxF12TrwUP45BMd")
    check("b58 leading zeros", b58_decode(b58_encode(b"\0\0ab")) == b"\0\0ab")
    check("hex forms", hex_decode("0x48 0x69") == b"Hi" and hex_decode("\\x48\\x69") == b"Hi")
    check("url known", url_decode("a%20b%21") == b"a b!")
    check("binary known", bin_decode("01001000 01101001") == b"Hi")
    check("decimal known", dec_decode("72 105") == b"Hi")
    check("octal known", oct_decode("110 151") == b"Hi")
    check("invalid rejected", b64_decode("!!!!") is None and hex_decode("abc") is None and bin_decode("0102") is None)

    check("rot13 known", rot("Hello, World!", 13) == "Uryyb, Jbeyq!")
    check("rot inverse", rot(rot("Attack at Dawn", 7), 19) == "Attack at Dawn")
    plain = "The quick brown fox jumps over the lazy dog and runs away from the farmer"
    ranked = rot_bruteforce(rot(plain, 5))
    check("rot brute top1", ranked[0][2] == plain and ranked[0][1] == 21 and len(ranked) == 25)
    check("atbash known", atbash("Hello") == "Svool" and atbash(atbash("Round Trip")) == "Round Trip")
    check("vigenere known", vigenere("LXFOPVEFRNHR", "LEMON") == "ATTACKATDAWN")
    check("vigenere roundtrip", vigenere(vigenere("Attack at dawn!", "key", False), "key") == "Attack at dawn!")

    sentence = b"Cooking MCs like a pound of bacon and the rest of the story goes on and on."
    ct = bytes(b ^ 0x58 for b in sentence)
    top = xor_bruteforce(ct)[:5]
    check("xor single-byte recovered", top[0][1] == 0x58 and top[0][2] == sentence)
    check("xor repeating roundtrip", xor_repeating(xor_repeating(sentence, b"ICE"), b"ICE") == sentence)
    check("xor repeating known", xor_repeating(b"Burning", b"ICE").hex() == "0b3637272a2b2e")

    check("score english > random", english_score(sentence) > english_score(bytes(range(256))) + 0.3)
    check("score english > shifted", english_score(plain.encode()) > english_score(rot(plain, 3).encode()))

    b2 = base64.b64encode(base64.b64encode(b"flag is here: the secret message to find"))
    final, chain = auto_decode(b2.decode())
    check("auto base64x2", chain == ["base64", "base64"] and final == b"flag is here: the secret message to find")
    final, chain = auto_decode(ENCODERS["hex"](base64.b64encode(b"hello there, this is a long hidden message")))
    check("auto hex->b64", chain == ["hex", "base64"] and final == b"hello there, this is a long hidden message")
    final, chain = auto_decode("Plain readable English text here.")
    check("auto leaves plaintext", chain == [])

    check("hint b64", any("base64" in h for h in hints("SGVsbG8gV29ybGQ=")))
    check("hint hex", any(h.startswith("hex") for h in hints("48656c6c6f")))
    check("hint binary", any("binary" in h for h in hints("01001000 01101001")))
    check("hint base32", any("base32" in h for h in hints("JBSWY3DPEBLW64TMMQ======")))
    check("hint url", any("url" in h for h in hints("a%20b")))
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        codes = (run(["-h"]), run(["--bogus"]), run(["-f", "/nonexistent/x"]))
    check("cli: -h -> 0, bad flag -> 2, missing file -> 1", codes == (0, 2, 1))
    return all(results)


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
