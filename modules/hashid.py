"""HASHID: identify likely hash algorithm(s) from length/charset/format markers, and run an
offline dictionary crack for the fast unsalted ``hashlib`` families (md5/sha1/sha256/sha512/
NTLM), with optional case/leet/suffix mangling rules.

bcrypt / sha*crypt / yescrypt are **identify-only** unless the optional ``bcrypt`` or
``passlib`` package happens to be importable, in which case ``crack`` can also verify
candidates against them (clearly marked optional; never required).

Reads only a local wordlist file (default Kali's ``/usr/share/wordlists/rockyou.txt``) --
never fetches or downloads anything, never opens a socket. Pure stdlib otherwise.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import re
import struct
import sys
import tempfile
from typing import Callable

NAME = "hashid"
DESCRIPTION = "Identify hash type by format/length; offline dictionary crack (md5/sha1/sha256/sha512/ntlm + rules)"

DEFAULT_WORDLIST = "/usr/share/wordlists/rockyou.txt"

HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

# --------------------------------------------------------------------------- optional deps
# Both are identify-only fallbacks: cracking salted/KDF hashes works only if one of these
# happens to be installed locally already. Neither is ever required, nothing is installed
# at runtime, and neither is imported for anything but local hash verification.

try:
    import bcrypt  # type: ignore
except ImportError:
    bcrypt = None

try:
    import passlib.hash as _passlib_hash  # type: ignore
except ImportError:
    _passlib_hash = None


# --------------------------------------------------------------------------- MD4 (for NTLM)

def _md4(data: bytes) -> bytes:
    """Pure-Python MD4 (RFC 1320), used when ``hashlib`` lacks md4 support (common on distros
    whose OpenSSL build disables legacy digests). NTLM = MD4(UTF-16LE(password))."""

    def f(x: int, y: int, z: int) -> int:
        return (x & y) | (~x & z)

    def g(x: int, y: int, z: int) -> int:
        return (x & y) | (x & z) | (y & z)

    def h(x: int, y: int, z: int) -> int:
        return x ^ y ^ z

    def lrot(x: int, n: int) -> int:
        x &= 0xFFFFFFFF
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    mask = 0xFFFFFFFF
    a0, b0, c0, d0 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

    bitlen = (len(data) * 8) & 0xFFFFFFFFFFFFFFFF
    padded = data + b"\x80"
    while len(padded) % 64 != 56:
        padded += b"\x00"
    padded += struct.pack("<Q", bitlen)

    r1_shift = (3, 7, 11, 19)
    r2_order = (0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15)
    r2_shift = (3, 5, 9, 13)
    r3_order = (0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15)
    r3_shift = (3, 9, 11, 15)

    for off in range(0, len(padded), 64):
        x = struct.unpack("<16I", padded[off:off + 64])
        a, b, c, d = a0, b0, c0, d0

        for i in range(16):
            t = (a + f(b, c, d) + x[i]) & mask
            a, b, c, d = d, lrot(t, r1_shift[i % 4]), b, c

        for i, k in enumerate(r2_order):
            t = (a + g(b, c, d) + x[k] + 0x5A827999) & mask
            a, b, c, d = d, lrot(t, r2_shift[i % 4]), b, c

        for i, k in enumerate(r3_order):
            t = (a + h(b, c, d) + x[k] + 0x6ED9EBA1) & mask
            a, b, c, d = d, lrot(t, r3_shift[i % 4]), b, c

        a0 = (a0 + a) & mask
        b0 = (b0 + b) & mask
        c0 = (c0 + c) & mask
        d0 = (d0 + d) & mask

    return struct.pack("<4I", a0, b0, c0, d0)


def _md4_digest(data: bytes) -> bytes:
    """MD4 digest, preferring OpenSSL's via ``hashlib`` and falling back to the pure impl."""
    try:
        return hashlib.new("md4", data).digest()
    except (ValueError, TypeError):
        return _md4(data)


def ntlm_hash(password: str) -> str:
    """NTLM hash of ``password`` as a lowercase hex string: MD4(UTF-16LE(password))."""
    return _md4_digest(password.encode("utf-16-le")).hex()


# --------------------------------------------------------------------------- identify

CRYPT_PREFIXES: dict[str, tuple[str, float, str]] = {
    "$1$": ("MD5 crypt (Unix, $1$)", 0.95, "glibc crypt(3) MD5-based, salted"),
    "$apr1$": ("Apache MD5 crypt ($apr1$)", 0.95, "Apache htpasswd variant of MD5 crypt"),
    "$2a$": ("bcrypt ($2a$)", 0.97, "Blowfish-based, salted, cost factor embedded"),
    "$2b$": ("bcrypt ($2b$)", 0.97, "Blowfish-based, salted, cost factor embedded"),
    "$2x$": ("bcrypt ($2x$)", 0.97, "Blowfish-based, salted, cost factor embedded (buggy variant)"),
    "$2y$": ("bcrypt ($2y$)", 0.97, "Blowfish-based, salted, cost factor embedded"),
    "$5$": ("SHA-256 crypt ($5$)", 0.95, "glibc crypt(3) SHA-256-based, salted"),
    "$6$": ("SHA-512 crypt ($6$)", 0.96, "glibc crypt(3) SHA-512-based, salted"),
    "$y$": ("yescrypt ($y$)", 0.95, "memory-hard KDF, default on recent Debian/Kali /etc/shadow"),
    "$7$": ("scrypt ($7$)", 0.9, "scrypt-based crypt(3) variant"),
    "$P$": ("phpass (WordPress/phpBB3, $P$)", 0.93, "portable hash, iterated MD5"),
    "$H$": ("phpass (phpBB3 legacy, $H$)", 0.93, "portable hash, iterated MD5"),
}

DJANGO_PREFIXES: dict[str, tuple[str, float, str]] = {
    "pbkdf2_sha256$": ("Django PBKDF2-HMAC-SHA256", 0.96, "algorithm$iterations$salt$hash"),
    "pbkdf2_sha1$": ("Django PBKDF2-HMAC-SHA1", 0.96, "algorithm$iterations$salt$hash"),
    "bcrypt$": ("Django bcrypt wrapper", 0.95, "wraps a $2*$ bcrypt hash"),
    "argon2$": ("Django argon2", 0.95, ""),
    "md5$": ("Django salted MD5 (legacy)", 0.9, "algorithm$salt$hash"),
}

# Raw hex digest length -> ranked candidates, most-likely first (ties in the acceptance
# sense are broken by real-world prevalence in CTF/credential-dump contexts).
RAW_HEX_FAMILIES: dict[int, list[tuple[str, float, str]]] = {
    16: [("MySQL323 (old, pre-4.1)", 0.5, "16 hex chars, legacy double 32-bit hash")],
    32: [
        ("MD5", 0.6, "most common 32-hex-char digest"),
        ("NTLM", 0.3, "Windows NTLM = MD4(UTF-16LE(pw)); same length as MD5, no format marker"),
        ("MD4", 0.25, ""),
        ("LM hash (half)", 0.2, "legacy Windows LAN Manager, usually paired with NTLM"),
    ],
    40: [
        ("SHA-1", 0.6, ""),
        ("MySQL 4.1+ (SHA1(SHA1(pw)))", 0.25, "usually prefixed with '*' in mysql.user"),
        ("RIPEMD-160", 0.2, ""),
    ],
    56: [("SHA-224", 0.55, ""), ("SHA3-224", 0.3, "")],
    64: [("SHA-256", 0.6, ""), ("SHA3-256", 0.3, ""), ("BLAKE2s-256", 0.25, "")],
    96: [("SHA-384", 0.55, ""), ("SHA3-384", 0.3, "")],
    128: [("SHA-512", 0.6, ""), ("SHA3-512", 0.3, ""), ("Whirlpool", 0.25, "")],
}


def identify(hashstr: str) -> list[dict]:
    """Rank candidate hash algorithms for ``hashstr`` by format markers/length/charset.

    Returns a list of ``{"name", "score", "note"}`` dicts, highest-confidence first. Purely
    heuristic (hashes of different algorithms can look identical) -- this never claims
    certainty, only a ranking.
    """
    s = hashstr.strip()
    if not s:
        return []
    cands: list[tuple[str, float, str]] = []

    for prefix, info in CRYPT_PREFIXES.items():
        if s.startswith(prefix):
            cands.append(info)
            break
    else:
        for prefix, info in DJANGO_PREFIXES.items():
            if s.startswith(prefix):
                cands.append(info)
                break

    if s.startswith("*") and HEX_RE.match(s[1:]) and len(s) - 1 == 40:
        cands.append(("MySQL 4.1+ (*SHA1(SHA1(pw)))", 0.97, "'*' + 40 hex chars, mysql.user password column"))

    # pwdump/secretsdump-style NTLM line: [user:rid:]LMHEX:NTLMHEX[:::]
    m = re.match(r"^(?:[^:]*:\d+:)?([0-9a-fA-F]{32}):([0-9a-fA-F]{32})(?::::?)?$", s)
    if m:
        cands.append(("NTLM", 0.96, "pwdump/secretsdump LM:NTLM pair format"))
        cands.append(("LM hash", 0.5, "legacy LAN Manager hash, same line"))

    if not cands and HEX_RE.match(s) and len(s) == 32:
        low = s.lower()
        if low == "31d6cfe0d16ae931b73c59d7e0c089c0":
            cands.append(("NTLM", 0.9, "matches the well-known empty-password NTLM constant"))
        elif low == "aad3b435b51404eeaad3b435b51404ee":
            cands.append(("LM hash", 0.9, "matches the well-known empty-password LM constant"))

    if not cands and ":" in s:
        parts = s.split(":")
        if len(parts) == 2 and all(parts):
            for part in parts:
                if HEX_RE.match(part) and len(part) in RAW_HEX_FAMILIES:
                    top = RAW_HEX_FAMILIES[len(part)][0][0]
                    cands.append((f"salted {top} (hash:salt or salt:hash)", 0.6,
                                  f"one colon-separated field is {len(part)} hex chars"))
                    break

    if not cands and HEX_RE.match(s) and len(s) in RAW_HEX_FAMILIES:
        cands.extend(RAW_HEX_FAMILIES[len(s)])

    if not cands:
        charset = "hex" if HEX_RE.match(s) else "mixed/non-hex"
        cands.append(("unknown", 0.1, f"no recognized length/format marker ({len(s)} chars, charset={charset})"))

    cands.sort(key=lambda c: -c[1])
    return [{"name": n, "score": sc, "note": nt} for n, sc, nt in cands]


# --------------------------------------------------------------------------- crack: fast unsalted stdlib families

FAMILY_BY_LEN: dict[int, list[str]] = {32: ["md5", "ntlm"], 40: ["sha1"], 64: ["sha256"], 128: ["sha512"]}

_HASHLIB_FUNCS: dict[str, Callable[[bytes], "hashlib._Hash"]] = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha256": hashlib.sha256,
    "sha512": hashlib.sha512,
}


def compute(family: str, password: str) -> str:
    """Hex digest of ``password`` under ``family`` (one of md5/sha1/sha256/sha512/ntlm)."""
    if family == "ntlm":
        return ntlm_hash(password)
    fn = _HASHLIB_FUNCS.get(family)
    if fn is None:
        raise ValueError(f"unsupported family: {family}")
    return fn(password.encode("utf-8", "surrogateescape")).hexdigest()


_LEET_MAP = str.maketrans("aeios", "43105")
_SUFFIXES = ("1", "2", "3", "7", "01", "12", "21", "69", "99", "007", "123", "1234", "!", "!!", "2024", "2025")


def mangle(word: str, rules: bool) -> list[str]:
    """Candidate strings derived from ``word``: itself, and (if ``rules``) case/leet/suffix
    variants. Deterministic, bounded -- not a combinatorial rule engine, just the handful of
    mutations that pay off fastest in a 4-hour CTF."""
    variants = [word]
    if not rules:
        return variants
    seen = {word}

    def add(v: str) -> None:
        if v and v not in seen:
            seen.add(v)
            variants.append(v)

    add(word.lower())
    add(word.upper())
    add(word.capitalize())
    add(word.translate(_LEET_MAP))
    add(word.lower().translate(_LEET_MAP))
    for suf in _SUFFIXES:
        add(word + suf)
        add(word.lower() + suf)
    return variants


def _open_wordlist(path: str):
    return open(path, "r", encoding="utf-8", errors="replace")


def crack(digest: str, wordlist_path: str, rules: bool = False, max_lines: int | None = None) -> dict:
    """Dictionary-attack ``digest`` (bare hex) over the local wordlist at ``wordlist_path``.

    Supports the fast unsalted stdlib families md5/sha1/sha256/sha512/ntlm, chosen by the hex
    length of ``digest``. Reads the wordlist strictly as a local file path -- never fetches or
    downloads anything; a missing/unreadable wordlist is reported in ``error``, never raised.
    """
    h = digest.strip().lower()
    if not HEX_RE.match(h):
        return {"found": False, "tried": 0,
                "error": f"'{digest}' is not a bare hex digest; crack supports unsalted "
                         "md5/sha1/sha256/sha512/ntlm only (use crack_any/'id' for other formats)"}
    families = FAMILY_BY_LEN.get(len(h))
    if not families:
        return {"found": False, "tried": 0,
                "error": f"{len(h)}-char hex digest does not match a supported unsalted "
                         "family length (32/40/64/128)"}
    try:
        fh = _open_wordlist(wordlist_path)
    except OSError as exc:
        return {"found": False, "tried": 0, "error": f"cannot read wordlist '{wordlist_path}': {exc}"}

    tried = 0
    try:
        with fh:
            for i, line in enumerate(fh):
                if max_lines is not None and i >= max_lines:
                    break
                word = line.rstrip("\r\n")
                if not word:
                    continue
                for cand in mangle(word, rules):
                    for fam in families:
                        tried += 1
                        if compute(fam, cand) == h:
                            return {"found": True, "password": cand, "family": fam, "tried": tried}
    except OSError as exc:
        return {"found": False, "tried": tried, "error": f"error reading wordlist: {exc}"}
    return {"found": False, "tried": tried}


def crack_salted(hashstr: str, wordlist_path: str, rules: bool = False, max_lines: int | None = None) -> dict:
    """Optional crack path for bcrypt/sha*crypt/yescrypt, only if ``bcrypt``/``passlib`` is
    importable locally. Clearly marked optional: returns a clean 'identify-only' error when
    neither is available, rather than failing."""
    h = hashstr.strip()
    verifier: Callable[[str], bool] | None = None

    if h.startswith(("$2a$", "$2b$", "$2x$", "$2y$")) and bcrypt is not None:
        def verifier(pw: str) -> bool:  # noqa: F811
            try:
                return bcrypt.checkpw(pw.encode("utf-8", "replace"), h.encode("ascii"))
            except (ValueError, TypeError):
                return False
    elif _passlib_hash is not None:
        scheme = None
        if h.startswith("$1$"):
            scheme = getattr(_passlib_hash, "md5_crypt", None)
        elif h.startswith("$5$"):
            scheme = getattr(_passlib_hash, "sha256_crypt", None)
        elif h.startswith("$6$"):
            scheme = getattr(_passlib_hash, "sha512_crypt", None)
        elif h.startswith(("$y$", "$7$")):
            scheme = getattr(_passlib_hash, "yescrypt", None) or getattr(_passlib_hash, "scrypt", None)
        elif h.startswith(("$2a$", "$2b$", "$2x$", "$2y$")):
            scheme = getattr(_passlib_hash, "bcrypt", None)
        if scheme is not None:
            def verifier(pw: str) -> bool:  # noqa: F811
                try:
                    return bool(scheme.verify(pw, h))
                except ValueError:
                    return False

    if verifier is None:
        return {"found": False, "tried": 0,
                "error": "optional dependency 'bcrypt'/'passlib' is not importable: this hash "
                         "format is identify-only without it (never required, never auto-installed)"}

    try:
        fh = _open_wordlist(wordlist_path)
    except OSError as exc:
        return {"found": False, "tried": 0, "error": f"cannot read wordlist '{wordlist_path}': {exc}"}

    tried = 0
    try:
        with fh:
            for i, line in enumerate(fh):
                if max_lines is not None and i >= max_lines:
                    break
                word = line.rstrip("\r\n")
                if not word:
                    continue
                for cand in mangle(word, rules):
                    tried += 1
                    if verifier(cand):
                        return {"found": True, "password": cand, "tried": tried}
    except OSError as exc:
        return {"found": False, "tried": tried, "error": f"error reading wordlist: {exc}"}
    return {"found": False, "tried": tried}


_SALTED_RE = re.compile(r"^\$(1|5|6|2a|2b|2x|2y|y|7|apr1)\$")


def crack_any(hashstr: str, wordlist_path: str, rules: bool = False, max_lines: int | None = None) -> dict:
    """Dispatch to :func:`crack` (fast unsalted families) or :func:`crack_salted`
    (optional-dependency families) based on the hash's own format marker."""
    h = hashstr.strip()
    if _SALTED_RE.match(h) or h.startswith(("$P$", "$H$")):
        return crack_salted(h, wordlist_path, rules, max_lines)
    return crack(h, wordlist_path, rules, max_lines)


# --------------------------------------------------------------------------- CLI

def run(args: list[str]) -> int:
    """CLI entry point: ``id <hash>`` / ``crack <hash> [--wordlist P] [--rules]`` / ``selftest``."""
    if args[:1] in (["selftest"], ["--selftest"]):
        return 0 if selftest() else 1
    p = argparse.ArgumentParser(prog="recon.py hashid", description=DESCRIPTION)
    sub = p.add_subparsers(dest="cmd")

    idp = sub.add_parser("id", help="identify likely hash algorithm(s)")
    idp.add_argument("hash")
    idp.add_argument("--top", type=int, default=5, help="candidates to show (default 5)")

    ck = sub.add_parser("crack", help="offline dictionary crack over a local wordlist")
    ck.add_argument("hash")
    ck.add_argument("--wordlist", default=DEFAULT_WORDLIST,
                     help=f"local wordlist path (default {DEFAULT_WORDLIST}); read-only, never downloaded")
    ck.add_argument("--rules", action="store_true", help="apply case/leet/suffix mangling rules")
    ck.add_argument("--limit", type=int, default=None, help="stop after N wordlist lines (useful for quick tests)")

    ns = p.parse_args(args)
    if ns.cmd is None:
        p.print_help()
        return 0

    if ns.cmd == "id":
        cands = identify(ns.hash)
        h = ns.hash.strip()
        print(f"input: {h}  ({len(h)} chars)")
        print(f"{'rank':<5}{'conf':<6}{'algorithm':<40}note")
        for i, c in enumerate(cands[:max(ns.top, 0)], 1):
            print(f"{i:<5}{c['score']:<6.2f}{c['name']:<40}{c['note']}")
        return 0

    # ns.cmd == "crack"
    res = crack_any(ns.hash, ns.wordlist, rules=ns.rules, max_lines=ns.limit)
    if res.get("error"):
        print(f"error: {res['error']}", file=sys.stderr)
        return 1
    if res["found"]:
        fam = f" ({res['family']})" if res.get("family") else ""
        print(f"found: {res['password']!r}{fam}  [{res['tried']} candidates tried]")
        return 0
    print(f"not found in wordlist  [{res['tried']} candidates tried]")
    return 1


# --------------------------------------------------------------------------- self-test

def selftest() -> bool:
    """All fixtures are in-memory/temp-dir; never touches rockyou.txt or the network."""
    results: list[bool] = []

    def check(name: str, cond: bool) -> None:
        results.append(bool(cond))
        if not cond:
            print(f"  failed: {name}")

    # MD4 correctness (RFC 1320 test vectors), independent of hashlib's md4 availability.
    check("md4 empty", _md4(b"").hex() == "31d6cfe0d16ae931b73c59d7e0c089c0")
    check("md4 abc", _md4(b"abc").hex() == "a448017aaf21d8525fc10ae87aa6729d")
    check("md4 message digest", _md4(b"message digest").hex() == "d9130a8164549fe818874806e1c7014b")

    word = "ctf123"
    md5_h = hashlib.md5(word.encode()).hexdigest()
    sha1_h = hashlib.sha1(word.encode()).hexdigest()
    sha256_h = hashlib.sha256(word.encode()).hexdigest()
    sha512_h = hashlib.sha512(word.encode()).hexdigest()
    ntlm_h = ntlm_hash(word)

    # id(): top candidate correctness, one sample each of md5/sha1/sha256/NTLM/$6$.
    check("id md5", identify(md5_h)[0]["name"] == "MD5")
    check("id sha1", identify(sha1_h)[0]["name"] == "SHA-1")
    check("id sha256", identify(sha256_h)[0]["name"] == "SHA-256")
    pwdump_line = f"Administrator:500:aad3b435b51404eeaad3b435b51404ee:{ntlm_h}:::"
    check("id ntlm", identify(pwdump_line)[0]["name"] == "NTLM")
    sha512crypt_sample = "$6$abcdefgh$" + "x" * 86
    check("id sha512crypt ($6$)", identify(sha512crypt_sample)[0]["name"].startswith("SHA-512 crypt"))
    check("id bcrypt format marker", identify("$2y$12$" + "A" * 53)[0]["name"].startswith("bcrypt"))
    check("id unknown non-hex", identify("not-a-hash-at-all!!")[0]["name"] == "unknown")

    # crack(): recover a short word from a tiny embedded wordlist (no external file).
    with tempfile.TemporaryDirectory() as td:
        wl = os.path.join(td, "mini.txt")
        with open(wl, "w") as fh:
            fh.write("password\nletmein\n" + word + "\nqwerty\n")
        for digest, fam in ((md5_h, "md5"), (sha1_h, "sha1"), (sha256_h, "sha256"),
                             (sha512_h, "sha512"), (ntlm_h, "ntlm")):
            res = crack(digest, wl)
            check(f"crack {fam}", res["found"] and res["password"] == word and res["family"] == fam)

        # mangling rules recover a suffix-mutated word not present verbatim.
        mutated = "password123"
        mutated_digest = hashlib.md5(mutated.encode()).hexdigest()
        with open(wl, "w") as fh:
            fh.write("password\n")
        res_rules = crack(mutated_digest, wl, rules=True)
        check("crack rules recovers mutation", res_rules["found"] and res_rules["password"] == mutated)
        res_norules = crack(mutated_digest, wl, rules=False)
        check("crack without rules misses mutation", not res_norules["found"])

        # crack_any() dispatches NTLM (pwdump form) and plain digests the same way.
        with open(wl, "w") as fh:
            fh.write(word + "\n")
        res_any = crack_any(ntlm_h, wl)
        check("crack_any ntlm", res_any["found"] and res_any["password"] == word)

        # missing wordlist: clean error dict, never an exception.
        missing = os.path.join(td, "does-not-exist.txt")
        try:
            res_missing = crack(md5_h, missing)
            check("crack missing wordlist: clean error", not res_missing["found"] and bool(res_missing.get("error")))
        except Exception as exc:  # pragma: no cover - the point of the check is that this never fires
            check(f"crack missing wordlist raised {type(exc).__name__}", False)

        # salted/bcrypt family without optional deps: clean identify-only error, never a crash.
        fake_bcrypt = "$2b$12$" + "A" * 53
        res_salted = crack_any(fake_bcrypt, wl)
        if bcrypt is None and _passlib_hash is None:
            check("crack_any bcrypt without optional dep: clean error",
                  not res_salted["found"] and bool(res_salted.get("error")))
        else:
            check("crack_any bcrypt with optional dep present: no crash", "found" in res_salted)

    return all(results)


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
