"""crypto: classical/CTF cryptanalysis helpers (offline, stdlib only).

Frequency analysis, repeating-key XOR break, Vigenere auto-break,
AES-ECB detection, substitution-cipher helper, RSA lane (known p/q, small-n factoring,
small-e root, Wiener, dp/dq leak).
"""
from __future__ import annotations

import argparse
import contextlib
import io
import math
import os
import re
import string
import sys
import tempfile
from collections import Counter

NAME = "crypto"
DESCRIPTION = "Cryptanalysis: freq analysis, repeating-XOR/Vigenere break, ECB detect, substitution helper, RSA attacks"

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



# ---------------------------------------------------------------- RSA
RSA_FLAG_RE = re.compile(rb"[A-Za-z0-9_\-]{2,24}\{[\x21-\x7a\x7c\x7e]{1,200}\}")
_SMALL_PRIMES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
TRIAL_LIMIT = 1 << 20
FERMAT_ITERS = 1 << 20
SMALL_E_MAX = 1023  # exact-root attack only makes sense for small public exponents
_RSA_NAMES = {"n": "n", "e": "e", "c": "c", "ct": "c", "ciphertext": "c", "cipher": "c",
              "p": "p", "q": "q", "dp": "dp", "dq": "dq", "d": "d"}


def parse_int(text: str) -> int:
    """Parse a decimal or 0x-hex integer (underscores and a trailing python-2 ``L`` tolerated)."""
    t = text.strip().replace("_", "").rstrip("lL")
    return int(t, 16) if t.lower().startswith(("0x", "-0x")) else int(t, 10)


def parse_rsa_text(text: str) -> dict[str, int]:
    """Pull RSA parameters out of text / python source. Matches ``name = value`` or ``name: value`` for
    n, e, c (also ct/cipher/ciphertext), p, q, dp, dq, d (case-insensitive); value is decimal or 0x hex.
    The first occurrence of each parameter wins. Non-numeric right-hand sides (``n = p * q``) are ignored."""
    out: dict[str, int] = {}
    pat = re.compile(r"(?<![\w.])(ciphertext|cipher|ct|dp|dq|n|e|c|p|q|d)\s*(?<![=!<>])[=:]\s*(?!=)['\"]?"
                     r"(0[xX][0-9a-fA-F_]+|\d[\d_]*)[lL]?(?![\w.])", re.I)
    for m in pat.finditer(text):
        key = _RSA_NAMES[m.group(1).lower()]
        if key not in out:
            out[key] = parse_int(m.group(2))
    return out


def is_probable_prime(n: int) -> bool:
    """Miller-Rabin with the first 12 primes as bases (deterministic below ~3.3e24, overwhelmingly reliable above)."""
    if n < 2:
        return False
    for q in _SMALL_PRIMES:
        if n % q == 0:
            return n == q
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for a in _SMALL_PRIMES:
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def next_prime(n: int) -> int:
    """Smallest prime strictly greater than ``n``."""
    n += 1
    if n <= 2:
        return 2
    n |= 1
    while not is_probable_prime(n):
        n += 2
    return n


def iroot(x: int, k: int) -> int:
    """floor(x ** (1/k)) by Newton iteration on integers (x >= 0, k >= 1)."""
    if x < 2 or k == 1:
        return x
    r = 1 << ((x.bit_length() + k - 1) // k)  # >= true root
    while True:
        nr = ((k - 1) * r + x // r ** (k - 1)) // k
        if nr >= r:
            return r
        r = nr


def int_to_bytes(m: int) -> bytes:
    """Big-endian bytes of a non-negative int (b'\\x00' for 0)."""
    return m.to_bytes(max(1, (m.bit_length() + 7) // 8), "big")


def fermat_factor(n: int, iters: int = FERMAT_ITERS) -> tuple[int, int] | None:
    """Fermat's method for n = p*q with p, q close together; gives up after ``iters`` steps."""
    if n < 4 or n % 2 == 0:
        return None
    a = math.isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(iters):
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:
            p, q = a - b, a + b
            return (p, q) if 1 < p < q else None
        a += 1
    return None


def factor_small(n: int, trial: int = TRIAL_LIMIT, fermat_iters: int = FERMAT_ITERS) -> tuple[dict[int, int], int]:
    """Try to fully factor n: trial division to ``trial``, Miller-Rabin on the cofactor, then Fermat on any
    composite remainder. Returns ({prime: exponent}, unfactored_cofactor); cofactor is 1 on full success."""
    fac: dict[int, int] = {}
    r = n
    d = 2
    while d <= trial and d * d <= r:
        while r % d == 0:
            fac[d] = fac.get(d, 0) + 1
            r //= d
        d += 1 if d == 2 else 2
    stack = [r] if r > 1 else []
    leftover = 1
    while stack:
        x = stack.pop()
        if x < 2:
            continue
        if is_probable_prime(x):
            fac[x] = fac.get(x, 0) + 1
            continue
        root = math.isqrt(x)
        if root * root == x:
            stack += [root, root]
            continue
        f = fermat_factor(x, fermat_iters)
        if f:
            stack += list(f)
        else:
            leftover *= x
    return fac, leftover


def _phi_from_factors(fac: dict[int, int]) -> int:
    phi = 1
    for p, k in fac.items():
        phi *= (p - 1) * p ** (k - 1)
    return phi


def wiener(e: int, n: int) -> tuple[int, int, int] | None:
    """Wiener's attack (small private exponent). Returns (d, p, q) or None."""
    a, b = e, n  # continued fraction expansion of e/n
    h0, h1, k0, k1 = 0, 1, 1, 0
    while b:
        qt = a // b
        a, b = b, a - qt * b
        h0, h1 = h1, qt * h1 + h0
        k0, k1 = k1, qt * k1 + k0
        k, d = h1, k1  # convergent k/d
        if k == 0 or (e * d - 1) % k:
            continue
        phi = (e * d - 1) // k
        s = n - phi + 1  # p + q
        disc = s * s - 4 * n
        if disc >= 0:
            r = math.isqrt(disc)
            if r * r == disc and (s + r) % 2 == 0:
                p, q = (s - r) // 2, (s + r) // 2
                if p > 1 and p * q == n:
                    return d, p, q
    return None


def _decrypt(c: int | None, d: int, n: int) -> int | None:
    return pow(c, d, n) if c is not None else None


def rsa_attack(n: int | None = None, e: int | None = None, c: int | None = None, p: int | None = None,
               q: int | None = None, dp: int | None = None, dq: int | None = None, d: int | None = None,
               trial: int = TRIAL_LIMIT, fermat_iters: int = FERMAT_ITERS) -> dict:
    """Run the RSA attacks in order, stopping at the first that recovers the key/plaintext:
    (a) p/q given, (a2) dp/dq leak, (b) small-n factoring (trial division then Fermat),
    (c) small-e exact e-th root, (d) Wiener. Returns {'ok', 'm', 'd', 'factors', 'method', 'tried'} where
    ``tried`` is a list of (attack, outcome) strings."""
    res: dict = {"ok": False, "m": None, "d": d, "factors": None, "method": None, "tried": []}
    tried = res["tried"]

    def done(method: str, dd: int | None, factors=None) -> dict:
        res.update(ok=True, method=method, d=dd, factors=factors)
        if dd is not None and n is not None:
            res["m"] = _decrypt(c, dd, n)
        return res

    if n is None and p and q:
        n = p * q
    if n is None:
        tried.append(("input", "no modulus n (and no p+q to derive it)"))
        return res
    if p and not q and n % p == 0:
        q = n // p
    if q and not p and n % q == 0:
        p = n // q
    if d is not None:
        tried.append(("(0) d given", "using supplied d"))
        return done("private exponent supplied", d)
    if e is None:
        tried.append(("input", "no public exponent e"))
        return res

    # (a) p and q known
    if p and q:
        if p * q != n:
            tried.append(("(a) p,q given", "p*q != n; supplied values inconsistent"))
        else:
            try:
                dd = pow(e, -1, (p - 1) * (q - 1))
                tried.append(("(a) p,q given", "derived d"))
                return done("p and q given", dd, {p: 1, q: 1})
            except ValueError:
                tried.append(("(a) p,q given", "e not invertible mod phi (gcd(e,phi) != 1)"))
    else:
        tried.append(("(a) p,q given", "skipped (p and q not both known)"))

    # (a2) dp / dq leak: gcd(2^(e*dp) - 2, n) = p
    leak = None
    for name, v in (("dp", dp), ("dq", dq)):
        if v:
            g = math.gcd(pow(2, e * v, n) - 2, n)
            if 1 < g < n:
                leak = (name, g)
                break
    if leak:
        pp = leak[1]
        qq = n // pp
        try:
            dd = pow(e, -1, (pp - 1) * (qq - 1))
            tried.append(("(a2) dp/dq leak", f"{leak[0]} leaked a factor of n"))
            return done(f"{leak[0]} leak", dd, {pp: 1, qq: 1})
        except ValueError:
            tried.append(("(a2) dp/dq leak", "factor found but e not invertible mod phi"))
    else:
        tried.append(("(a2) dp/dq leak", "skipped (no dp/dq)" if not (dp or dq) else "no factor from dp/dq"))

    # (b) factor n
    fac, rest = factor_small(n, trial, fermat_iters)
    if rest == 1 and len(fac) + sum(fac.values()) > 1:
        phi = _phi_from_factors(fac)
        try:
            dd = pow(e, -1, phi)
            tried.append(("(b) factor small n", "factored: " + " * ".join(
                str(f) if k == 1 else f"{f}^{k}" for f, k in sorted(fac.items()))))
            return done("factoring", dd, fac)
        except ValueError:
            tried.append(("(b) factor small n", "factored but gcd(e, phi) != 1 (e.g. e=2 / Rabin); decrypt manually"))
    else:
        known = f" (partial: found {sorted(fac)})" if fac else ""
        tried.append(("(b) factor small n", f"no factorization: trial division to 2^{trial.bit_length() - 1}, "
                      f"Fermat {fermat_iters} iters{known}"))

    # (c) small e: c is a perfect e-th power
    if c is not None and e > SMALL_E_MAX:
        tried.append(("(c) small e root", f"skipped (e > {SMALL_E_MAX}; not a small-exponent key)"))
    elif c is not None:
        r = iroot(c, e)
        if r ** e == c:
            tried.append(("(c) small e root", f"c is a perfect {e}-th power (m^e < n)"))
            res.update(ok=True, method=f"small-e exact {e}-th root", m=r)
            return res
        tried.append(("(c) small e root", f"c is not a perfect {e}-th power (m^e >= n, padding or large e)"))
    else:
        tried.append(("(c) small e root", "skipped (no ciphertext)"))

    # (d) Wiener
    w = wiener(e, n)
    if w:
        tried.append(("(d) Wiener", "small private exponent recovered"))
        return done("Wiener (small d)", w[0], {w[1]: 1, w[2]: 1})
    tried.append(("(d) Wiener", "no convergent yields a valid d"))
    return res


def format_plaintext(m: int) -> tuple[str, str, list[str]]:
    """Return (hex, printable-ascii, flag-shaped strings) for the recovered plaintext integer."""
    b = int_to_bytes(m)
    asc = "".join(chr(x) if 32 <= x < 127 else "." for x in b)
    return b.hex(), asc, [f.decode("latin-1") for f in RSA_FLAG_RE.findall(b)]


_RSA_MANUAL = """  what to try manually:
    - n looks big: factor offline with yafu / msieve / cado-nfs / sage, or look it up in a factor database from a
      networked machine (this toolkit never touches the network)
    - several ciphertexts of one message under e=3 with different n -> Hastad broadcast (CRT + cube root)
    - same n with two coprime e values -> common-modulus attack; shared prime across several n -> gcd(n1, n2)
    - m^e slightly > n: try iroot(c + k*n, e) for small k;  e=2 -> Rabin;  check challenge source for hints (p-q small,
      p or q leaked partially, d bits leaked, weak RNG/prime generation)"""


def _rsa_cli(args: list[str]) -> int:
    """``crypto rsa`` entry: --n/--e/--c (dec or 0x), or -f FILE auto-parse (n,e,c,p,q,dp,dq,d)."""
    ap = argparse.ArgumentParser(prog="recon.py crypto rsa", description="RSA attacks: known p/q, small-n factoring, "
                                 "small-e root, Wiener, dp/dq leak")
    for k in ("n", "e", "c", "p", "q", "dp", "dq", "d"):
        ap.add_argument(f"--{k}", type=parse_int, help=f"{k} (decimal or 0x hex)")
    ap.add_argument("-f", "--file", help="text/python source to auto-parse parameters from")
    try:
        a = ap.parse_args(args)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    params: dict[str, int] = {}
    if a.file:
        try:
            with open(a.file, "r", encoding="utf-8", errors="replace") as fh:
                params = parse_rsa_text(fh.read())
        except OSError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print("parsed from file: " + (", ".join(f"{k}={str(v)[:24]}{'...' if len(str(v)) > 24 else ''}"
                                                 for k, v in params.items()) or "nothing"))
    for k in ("n", "e", "c", "p", "q", "dp", "dq", "d"):
        if getattr(a, k) is not None:
            params[k] = getattr(a, k)
    if not params:
        ap.print_usage()
        return 2
    res = rsa_attack(**params)
    for name, outcome in res["tried"]:
        print(f"  {name}: {outcome}")
    if not res["ok"]:
        print("RSA: no attack succeeded.")
        print(_RSA_MANUAL)
        return 1
    print(f"RSA: recovered via {res['method']}")
    if res["factors"]:
        print("  factors: " + " * ".join(str(f) if k == 1 else f"{f}^{k}" for f, k in sorted(res["factors"].items())))
    if res["d"] is not None:
        print(f"  d = {res['d']}")
    if res["m"] is None:
        print("  (no ciphertext supplied; key material only)")
        return 0
    hx, asc, flags = format_plaintext(res["m"])
    print(f"  m (hex)  : {hx}\n  m (ascii): {asc}")
    for f in flags:
        print(f"  >>> FLAG: {f}")
    return 0


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

    # RSA lane (synthetic keys built from Mersenne primes / next_prime; no fixtures on disk)
    msg = b"flag{rsa_lane_ok}"
    m_int = int.from_bytes(msg, "big")
    p1, q1 = (1 << 127) - 1, (1 << 521) - 1

    def enc(mm: int, ee: int, nn: int) -> int:
        return pow(mm, ee, nn)

    n1 = p1 * q1
    r = rsa_attack(n=n1, e=65537, c=enc(m_int, 65537, n1), p=p1, q=q1)
    check("rsa (a): p,q given", r["ok"] and int_to_bytes(r["m"]) == msg and r["method"] == "p and q given")
    r = rsa_attack(e=65537, c=enc(m_int, 65537, n1), p=p1, q=q1)
    check("rsa (a): n derived from p*q", r["ok"] and int_to_bytes(r["m"]) == msg)
    r = rsa_attack(n=n1, e=65537, c=enc(m_int, 65537, n1), p=p1)
    check("rsa (a): only p given -> q = n/p", r["ok"] and int_to_bytes(r["m"]) == msg)

    sp = 1000003  # small prime below 2^20 -> trial division
    n2 = sp * ((1 << 127) - 1)
    r = rsa_attack(n=n2, e=65537, c=enc(m_int % n2, 65537, n2), fermat_iters=50)
    check("rsa (b): trial division on small factor", r["ok"] and r["method"] == "factoring" and r["m"] == m_int % n2)
    pn = next_prime(1 << 200)
    qn = next_prime(pn + 100000)
    n3 = pn * qn
    r = rsa_attack(n=n3, e=65537, c=enc(m_int, 65537, n3))
    check("rsa (b): Fermat on close primes", r["ok"] and r["method"] == "factoring" and int_to_bytes(r["m"]) == msg)
    r = rsa_attack(n=pn, e=65537, c=enc(m_int, 65537, pn))
    check("rsa (b): n itself prime -> phi = n-1", r["ok"] and int_to_bytes(r["m"]) == msg)
    r = rsa_attack(n=n1, e=3, c=enc(m_int, 3, n1), fermat_iters=100)
    check("rsa (c): small e exact cube root", r["ok"] and "small-e" in r["method"] and int_to_bytes(r["m"]) == msg)
    check("rsa: iroot exactness", iroot(10 ** 60, 3) == 10 ** 20 and iroot(10 ** 60 - 1, 3) == 10 ** 20 - 1)

    pw = next_prime((1 << 128) + (1 << 120))
    qw = next_prime((1 << 128) + (1 << 121))
    nw, phiw = pw * qw, (pw - 1) * (qw - 1)
    dw = next_prime(1 << 40)
    while math.gcd(dw, phiw) != 1:
        dw = next_prime(dw)
    ew = pow(dw, -1, phiw)
    r = rsa_attack(n=nw, e=ew, c=enc(m_int, ew, nw), fermat_iters=100)
    check("rsa (d): Wiener small d", r["ok"] and r["d"] == dw and int_to_bytes(r["m"]) == msg, r["method"] or "")
    r = rsa_attack(n=nw, e=65537, c=enc(m_int, 65537, nw), dp=pow(65537, -1, pw - 1), fermat_iters=100)
    check("rsa (a2): dp leak", r["ok"] and r["method"] == "dp leak" and int_to_bytes(r["m"]) == msg)
    r = rsa_attack(n=nw, e=65537, c=enc(m_int, 65537, nw), fermat_iters=100)
    check("rsa: hard instance fails and lists all attacks tried", (not r["ok"]) and len(r["tried"]) >= 5)

    txt = f"# level1.py\nn = {n3}\ne = 0x10001\nc: {enc(m_int, 65537, n3)}\nx = p * q\nok == 5\n"
    pt = parse_rsa_text(txt)
    check("rsa parse: dec/hex, ':' and '=', ignores p*q and ==",
          pt == {"n": n3, "e": 65537, "c": enc(m_int, 65537, n3)})
    pt2 = parse_rsa_text("N = 0xff\nE = 3\nciphertext = 0x10\np = 3\nq = 5\ndp = 7\ndq=9\n")
    check("rsa parse: uppercase/ciphertext/p/q/dp/dq", pt2 == {"n": 255, "e": 3, "c": 16, "p": 3, "q": 5, "dp": 7, "dq": 9})
    with tempfile.TemporaryDirectory() as td:
        fp = os.path.join(td, "level.py")
        with open(fp, "w") as fh:
            fh.write(txt)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = run(["rsa", "-f", fp])
        check("rsa cli: -f file -> flag highlighted", rc == 0 and ">>> FLAG: flag{rsa_lane_ok}" in buf.getvalue()
              and "m (hex)" in buf.getvalue())
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = run(["rsa", "--n", hex(nw), "--e", "65537", "--c", hex(enc(m_int, 65537, nw))])
        check("rsa cli: failure lists attacks + manual hints", rc == 1 and "(d) Wiener" in buf.getvalue()
              and "what to try manually" in buf.getvalue())
    return ok


# ---------------------------------------------------------------- CLI
_USAGE = """usage: crypto <cmd> [args]
  freq <text|hex>             frequency report (letters/bigrams/trigrams, chi2, IC)
  xor <hex|text>              break repeating-key XOR
  vigenere <text>             break Vigenere without key
  ecb <hex>                   detect repeated 16-byte blocks
  subst <text> [mapping]      substitution helper (mapping: 'a=e,b=t' or 26-char string)
  rsa --n N --e E --c C | -f FILE   RSA attacks: known p/q, factor small n, small-e root, Wiener, dp/dq leak
                              (extra: --p --q --dp --dq --d; values decimal or 0x hex)
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
    if cmd == "rsa":
        return _rsa_cli(rest)
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
