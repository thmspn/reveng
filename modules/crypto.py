"""crypto: classical/CTF cryptanalysis helpers (offline, stdlib only).

Frequency analysis, repeating-key XOR break, Vigenere auto-break,
AES-ECB detection, substitution-cipher helper.
"""
from __future__ import annotations

import math
import re
import string
import sys
from collections import Counter

NAME = "crypto"
DESCRIPTION = "Cryptanalysis: freq analysis, repeating-XOR/Vigenere break, ECB detect, substitution helper"

ALPHA = string.ascii_uppercase
# English letter frequencies (percent), A..Z
ENGLISH_FREQ = [8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966,
                0.153, 0.772, 4.025, 2.406, 6.749, 7.507, 1.929, 0.095, 5.987,
                6.327, 9.056, 2.758, 0.978, 2.360, 0.150, 1.974, 0.074]
ENGLISH_ORDER = "ETAOINSHRDLCUMWFGYPBVKJXQZ"
COMMON_BIGRAMS = ["TH", "HE", "IN", "ER", "AN", "RE", "ON", "AT", "EN", "ND",
                  "TI", "ES", "OR", "TE", "OF", "ED", "IS", "IT", "AL", "AR"]
COMMON_TRIGRAMS = ["THE", "AND", "ING", "ION", "TIO", "ENT", "ERE", "HER", "ATE",
                   "VER", "TER", "THA", "ATI", "FOR", "HAT", "ERS", "HIS", "RES", "ILL", "ARE"]
ENGLISH_IC = 0.0667
# byte-level scoring weights for XOR breaking: letters by freq, space very common
_SPACE_FREQ = 17.0


# ---------------------------------------------------------------- input
def to_bytes(data: str | bytes) -> bytes:
    """Accept raw text or hex (optionally spaced / 0x-prefixed) and return bytes."""
    if isinstance(data, bytes):
        return data
    s = data.strip()
    h = re.sub(r"(?i)0x|[\s:,-]", "", s)
    if h and len(h) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", h) and len(h) >= 8 and (
            not re.fullmatch(r"[a-fA-F]+", h)):
        return bytes.fromhex(h)
    return s.encode("latin-1", "replace")


def letters_only(data: bytes) -> str:
    return "".join(chr(b).upper() for b in data if chr(b).upper() in ALPHA and b < 128)


# ---------------------------------------------------------------- frequency
def chi_squared(text: str) -> float:
    """Chi-squared of A-Z letters in text vs English (lower = more English)."""
    t = [c for c in text.upper() if c in ALPHA]
    n = len(t)
    if n == 0:
        return float("inf")
    cnt = Counter(t)
    return sum((cnt.get(ALPHA[i], 0) - n * ENGLISH_FREQ[i] / 100) ** 2 / (n * ENGLISH_FREQ[i] / 100)
               for i in range(26))


def index_of_coincidence(text: str) -> float:
    t = [c for c in text.upper() if c in ALPHA]
    n = len(t)
    if n < 2:
        return 0.0
    return sum(v * (v - 1) for v in Counter(t).values()) / (n * (n - 1))


def ngrams(text: str, n: int) -> Counter:
    t = "".join(c for c in text.upper() if c in ALPHA)
    return Counter(t[i:i + n] for i in range(len(t) - n + 1))


def freq_report(data: str | bytes, top: int = 10) -> str:
    b = to_bytes(data)
    text = b.decode("latin-1")
    t = letters_only(b)
    lines = [f"bytes={len(b)} letters={len(t)}"]
    if not t:
        lines.append("no alphabetic content")
        return "\n".join(lines)
    cnt = Counter(t)
    lines.append("letter  count    obs%   eng%")
    for c, k in cnt.most_common(top):
        lines.append(f"  {c}     {k:5d}  {100 * k / len(t):5.2f}  {ENGLISH_FREQ[ALPHA.index(c)]:5.2f}")
    for n, ref in ((2, COMMON_BIGRAMS), (3, COMMON_TRIGRAMS)):
        ng = ngrams(text, n).most_common(top)
        lines.append(f"top {n}-grams: " + ", ".join(f"{g}:{k}" for g, k in ng))
        lines.append(f"  english ref: " + " ".join(ref[:top]))
    ic, chi = index_of_coincidence(t), chi_squared(t)
    lines.append(f"IC={ic:.4f} (english~{ENGLISH_IC}, random~0.0385)  chi2={chi:.1f}")
    lines.append("verdict: " + ("english-like" if chi < 60 and ic > 0.055 else
                                "monoalphabetic-like (IC high, chi2 high)" if ic > 0.055 else
                                "polyalphabetic or random"))
    return "\n".join(lines)


# ---------------------------------------------------------------- repeating-key XOR
def hamming(a: bytes, b: bytes) -> int:
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def xor_keysize_candidates(ct: bytes, lo: int = 2, hi: int = 40, top: int = 5):
    """Rank keysizes by normalized hamming distance across several block pairs."""
    res = []
    for k in range(lo, min(hi, len(ct) // 2) + 1):
        blocks = [ct[i:i + k] for i in range(0, len(ct) - k + 1, k)][:12]
        if len(blocks) < 2:
            continue
        d = [hamming(blocks[i], blocks[j]) / k
             for i in range(len(blocks)) for j in range(i + 1, len(blocks))]
        res.append((sum(d) / len(d), k))
    res.sort()
    return res[:top]


def _byte_score(pt: bytes) -> float:
    """Higher = more English-like plaintext (log-likelihood-ish)."""
    score = 0.0
    for b in pt:
        c = chr(b)
        if c == " ":
            score += math.log(_SPACE_FREQ)
        elif c.isalpha() and b < 128:
            score += math.log(ENGLISH_FREQ[ord(c.upper()) - 65])
        elif c in ".,'\"-;:!?\n" or c.isdigit():
            score += math.log(0.5)
        elif 32 <= b < 127:
            score += math.log(0.05)
        else:
            score += math.log(0.0005)
    return score / max(len(pt), 1)


def best_single_byte(col: bytes) -> tuple[int, float]:
    best = (0, -1e18)
    for k in range(256):
        s = _byte_score(bytes(b ^ k for b in col))
        if s > best[1]:
            best = (k, s)
    return best


def xor_decrypt(ct: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(ct))


def _reduce_key(key: bytes) -> bytes:
    for p in range(1, len(key)):
        if len(key) % p == 0 and key == key[:p] * (len(key) // p):
            return key[:p]
    return key


def _xor_try(ct: bytes, k: int):
    key = bytearray()
    for i in range(k):
        key.append(best_single_byte(ct[i::k])[0])
    key = _reduce_key(bytes(key))
    pt = xor_decrypt(ct, key)
    return {"key": key, "plaintext": pt, "score": _byte_score(pt), "keysize": len(key)}


def break_repeating_xor(ct: bytes, lo: int = 2, hi: int = 40, ncand: int = 5):
    """Return dict(key, plaintext, confidence, keysize, score). Tries top keysize candidates
    plus their divisors, then prefers the shortest key scoring close to the best (avoids
    overfitted multiples of the true key length)."""
    cands = xor_keysize_candidates(ct, lo, hi, ncand)
    sizes = set()
    for _, k in cands:
        sizes.update(d for d in range(1, k + 1) if k % d == 0 and d >= 1)
    results = [_xor_try(ct, k) for k in sorted(sizes)]
    if not results:
        return None
    top = max(r["score"] for r in results)
    best = min((r for r in results if r["score"] >= top - 0.12), key=lambda r: len(r["key"]))
    best["confidence"] = max(0.0, min(1.0, (best["score"] + 6.0) / 3.5))
    return best


# ---------------------------------------------------------------- Vigenere
def vigenere_decrypt(text: str, key: str) -> str:
    out, j = [], 0
    for c in text:
        if c.isalpha() and c.isascii():
            base = 65 if c.isupper() else 97
            out.append(chr((ord(c) - base - (ord(key[j % len(key)].upper()) - 65)) % 26 + base))
            j += 1
        else:
            out.append(c)
    return "".join(out)


def _best_shift(col: str) -> int:
    best, bs = 0, float("inf")
    for s in range(26):
        dec = "".join(chr((ord(c) - 65 - s) % 26 + 65) for c in col)
        x = chi_squared(dec)
        if x < bs:
            best, bs = s, x
    return best


def break_vigenere(text: str, max_key: int = 24):
    """Return dict(key, plaintext, keysize, ic) or None.

    Candidate keysizes come from average column IC; the shortest candidate whose decryption
    is nearly as English-like (chi-squared) as the best is chosen."""
    t = letters_only(text.encode("latin-1", "replace"))
    if len(t) < 20:
        return None
    ics = {}
    for k in range(1, min(max_key, len(t) // 3) + 1):
        ics[k] = sum(index_of_coincidence(t[i::k]) for i in range(k)) / k
    best_ic = max(ics.values())
    results = []
    for k, ic in sorted(ics.items()):
        if ic < best_ic * 0.85:
            continue
        key = "".join(ALPHA[_best_shift(t[i::k])] for i in range(k))
        dec = vigenere_decrypt(t, key)
        results.append((chi_squared(dec), k, key))
    best_chi = min(r[0] for r in results)
    _, k, key = min((r for r in results if r[0] <= max(best_chi * 1.3, best_chi + 15)), key=lambda r: r[1])
    key = _reduce_key(key.encode()).decode()
    return {"key": key, "keysize": len(key), "ic": ics.get(len(key), ics[k]),
            "plaintext": vigenere_decrypt(text, key)}


# ---------------------------------------------------------------- AES-ECB
def detect_ecb(ct: bytes, block: int = 16):
    """Return (repeated_blocks: dict[bytes,int positions], is_ecb_likely)."""
    blocks = [ct[i:i + block] for i in range(0, len(ct) - block + 1, block)]
    pos: dict[bytes, list[int]] = {}
    for i, b in enumerate(blocks):
        pos.setdefault(b, []).append(i)
    rep = {b: p for b, p in pos.items() if len(p) > 1}
    return rep, bool(rep)


# ---------------------------------------------------------------- substitution
def subst_initial_map(ct: str) -> dict[str, str]:
    """Map cipher letters -> plain letters by matching frequency rank."""
    cnt = Counter(c for c in ct.upper() if c in ALPHA)
    ranked = [c for c, _ in cnt.most_common()] + [c for c in ALPHA if c not in cnt]
    return {c: ENGLISH_ORDER[i] for i, c in enumerate(ranked)}


def parse_mapping(spec: str) -> dict[str, str]:
    """Accept 'a=e,b=t' / 'ab=et' style pairs or a 26-char cipher->plain string ('.' / '_' = unknown)."""
    spec = spec.strip()
    m: dict[str, str] = {}
    if re.fullmatch(r"[A-Za-z._?]{26}", spec):
        for c, p in zip(ALPHA, spec.upper()):
            if p in ALPHA:
                m[c] = p
        return m
    for part in re.split(r"[,\s]+", spec):
        if "=" in part:
            a, b = part.split("=", 1)
            for x, y in zip(a.upper(), b.upper()):
                if x in ALPHA and y in ALPHA:
                    m[x] = y
    return m


def subst_apply(ct: str, mapping: dict[str, str], unknown: str = "_") -> str:
    """Apply mapping; mapped letters lower-case, unmapped cipher letters shown as `unknown`."""
    return "".join((mapping[c.upper()].lower() if c.upper() in mapping else unknown) if c.isalpha() and c.isascii() else c
                   for c in ct)


# ---------------------------------------------------------------- selftest
_PLAIN = ("It was the best of times, it was the worst of times, it was the age of wisdom, "
          "it was the age of foolishness, it was the epoch of belief, it was the epoch of "
          "incredulity, it was the season of Light, it was the season of Darkness, it was "
          "the spring of hope, it was the winter of despair, we had everything before us, "
          "we had nothing before us, we were all going direct to Heaven, we were all going "
          "direct the other way. The attacker examined the binary and found the flag hidden "
          "inside a function that decrypted a buffer with a short repeating key before use.")


def _lcg_bytes(n: int, seed: int = 12345) -> bytes:
    out, x = bytearray(), seed
    for _ in range(n):
        x = (1103515245 * x + 12345) & 0x7FFFFFFF
        out.append((x >> 16) & 0xFF)
    return bytes(out)


def selftest() -> bool:
    """Registry contract self-test: XOR/Vigenere breaks, ECB detect, freq stats, substitution helper."""
    ok = True

    def check(name: str, cond: bool, extra: str = "") -> None:
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name} {extra}")
        ok &= bool(cond)

    pt = _PLAIN.encode()
    for key in (b"ICE", b"SecretKey", b"k3y!"):
        r = break_repeating_xor(xor_decrypt(pt, key))
        check(f"repeating-xor key={key!r}", r is not None and (r["key"] == key or r["plaintext"] == pt),
              f"-> {r['key']!r} conf={r['confidence']:.2f}" if r else "")
    # hex input path
    r = break_repeating_xor(to_bytes(xor_decrypt(pt, b"ICE").hex()))
    check("repeating-xor via hex input", r is not None and r["plaintext"] == pt)

    for key in ("LEMON", "CRYPTO", "KEY"):
        r = break_vigenere(vigenere_decrypt(_PLAIN, "".join(chr((26 - (ord(c) - 65)) % 26 + 65) for c in key)))
        check(f"vigenere key={key}", r is not None and r["key"] == key, f"-> {r['key']}" if r else "")

    a, b = bytes(range(16)), bytes(range(16, 32))
    rep, likely = detect_ecb(a + b + a + a)
    check("ecb detect repeated", likely and rep[a] == [0, 2, 3])
    rep, likely = detect_ecb(_lcg_bytes(160))
    check("ecb detect random negative", not likely)

    ch_en, ch_rnd = chi_squared(_PLAIN), chi_squared(letters_only(_lcg_bytes(4000)) or "AB")
    check("freq: chi2 english << random", ch_en < ch_rnd, f"({ch_en:.0f} vs {ch_rnd:.0f})")
    ic_en = index_of_coincidence(_PLAIN)
    ic_rnd = index_of_coincidence("".join(ALPHA[x % 26] for x in _lcg_bytes(3000)))
    check("freq: IC english > random", ic_en > 0.06 > 0.045 > 0 and ic_en > ic_rnd, f"({ic_en:.4f} vs {ic_rnd:.4f})")

    # substitution round trip
    perm = "QWERTYUIOPASDFGHJKLZXCVBNM"
    enc = "".join(perm[ord(c) - 65] if c in ALPHA else c for c in _PLAIN.upper())
    inv = {perm[i]: ALPHA[i] for i in range(26)}
    check("subst apply full mapping", subst_apply(enc, inv).upper() == _PLAIN.upper())
    part = subst_apply(enc, parse_mapping("Z=E"))
    check("subst partial marks unknowns", "_" in part and part.count("_") < len(part))
    g = subst_apply(enc, subst_initial_map(enc))
    check("subst initial guess runs", len(g) == len(enc))
    check("parse_mapping 26-char", parse_mapping("." * 25 + "A") == {"Z": "A"})
    return ok


# ---------------------------------------------------------------- CLI
_USAGE = """usage: crypto <cmd> [args]
  freq <text|hex>             frequency report (letters/bigrams/trigrams, chi2, IC)
  xor <hex|text>              break repeating-key XOR
  vigenere <text>             break Vigenere without key
  ecb <hex>                   detect repeated 16-byte blocks
  subst <text> [mapping]      substitution helper (mapping: 'a=e,b=t' or 26-char string)
  selftest                    run self-tests
Use '-' as the argument to read from stdin."""


def run(args: list[str]) -> int:
    """CLI entry point (registry contract); returns a process exit code."""
    if not args or args[0] in ("-h", "--help"):
        print(_USAGE)
        return 0
    cmd, rest = args[0], args[1:]
    if cmd in ("selftest", "--selftest"):
        return 0 if selftest() else 1
    if not rest:
        print(_USAGE)
        return 2
    data = sys.stdin.read() if rest[0] == "-" else rest[0]
    if cmd == "freq":
        print(freq_report(data))
    elif cmd == "xor":
        r = break_repeating_xor(to_bytes(data))
        if not r:
            print("input too short")
            return 1
        print(f"keysize={r['keysize']} key={r['key']!r} (hex {r['key'].hex()}) confidence={r['confidence']:.2f}")
        print("plaintext:", r["plaintext"][:200].decode("latin-1"))
    elif cmd == "vigenere":
        r = break_vigenere(data)
        if not r:
            print("need >= 20 letters")
            return 1
        print(f"keysize={r['keysize']} key={r['key']} IC={r['ic']:.4f}")
        print("plaintext:", r["plaintext"][:200])
    elif cmd == "ecb":
        rep, likely = detect_ecb(to_bytes(data))
        print("ECB LIKELY" if likely else "no repeated blocks")
        for b, p in rep.items():
            print(f"  {b.hex()} at blocks {p}")
    elif cmd == "subst":
        m = parse_mapping(rest[1]) if len(rest) > 1 else subst_initial_map(data)
        print("mapping:", "".join(m.get(c, ".") for c in ALPHA))
        print(subst_apply(data, m))
    else:
        print(_USAGE)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
