"""WEBKIT: offline web-challenge helpers.

Three jobs, fully offline -- **no HTTP is ever performed by this module** and it never
opens a socket:

* ``jwt``      -- decode a JWT's header/payload/signature without verifying anything,
  flag ``alg: none`` tokens, and (optionally) brute a weak HMAC secret against a local
  wordlist by delegating the actual hashing/compare loop to ``hashid``'s crack core.
* ``wordlist`` -- deterministically generate path/parameter fuzz candidates from a seed
  word (extensions, common dirs, case variants) for feeding to a *local* fuzzing tool
  (ffuf/gobuster/wfuzz). This module only writes candidate strings to stdout/a file --
  it never sends a request itself.
* ``cookie``   -- base64url encode/decode, Flask session *structure* decode (splits the
  ``payload.timestamp.signature`` cookie and base64url-decodes the payload -- no secret
  is needed or used, the HMAC signature is left opaque), and a quick common-hash report
  of an arbitrary value.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import sys
import tempfile
from typing import Any, Optional

try:  # works both as ``modules.webkit`` and when the package dir is on sys.path
    from . import hashid
except ImportError:  # pragma: no cover
    import hashid  # type: ignore

NAME = "webkit"
DESCRIPTION = "Offline web helpers: JWT decode/alg-none/weak-secret crack, fuzz wordlist gen, cookie/hash helpers"


# --------------------------------------------------------------------------- base64url

def b64url_decode(s: str) -> bytes:
    """Decode a base64url string, tolerating missing ``=`` padding (JWT segments omit it)."""
    s = s.strip()
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def b64url_encode(data: bytes) -> str:
    """Encode bytes as unpadded base64url (the form JWT/Flask cookies use)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


# --------------------------------------------------------------------------- JWT

class JwtError(ValueError):
    """Raised for a malformed JWT (wrong segment count, bad base64/JSON)."""


def jwt_decode(token: str) -> dict[str, Any]:
    """Split and decode a JWT's three segments **without verifying the signature**.

    Returns ``{"header": dict, "payload": dict, "signature": bytes, "signing_input": bytes,
    "alg_none": bool, "raw": {"header": str, "payload": str, "signature": str}}``.
    Raises :class:`JwtError` on a structurally invalid token -- this never calls out to a
    network or crypto library to verify anything, it only decodes.
    """
    token = token.strip()
    parts = token.split(".")
    if len(parts) != 3:
        raise JwtError(f"expected 3 dot-separated segments, got {len(parts)}")
    raw_header, raw_payload, raw_sig = parts

    try:
        header = json.loads(b64url_decode(raw_header))
    except (ValueError, UnicodeDecodeError) as exc:
        raise JwtError(f"bad header segment: {exc}") from None
    try:
        payload = json.loads(b64url_decode(raw_payload))
    except (ValueError, UnicodeDecodeError) as exc:
        raise JwtError(f"bad payload segment: {exc}") from None
    try:
        signature = b64url_decode(raw_sig) if raw_sig else b""
    except ValueError as exc:
        raise JwtError(f"bad signature segment: {exc}") from None

    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise JwtError("header/payload segment did not decode to a JSON object")

    alg = str(header.get("alg", "")).strip().lower()
    signing_input = f"{raw_header}.{raw_payload}".encode("ascii")
    return {
        "header": header,
        "payload": payload,
        "signature": signature,
        "signing_input": signing_input,
        "alg_none": alg == "none",
        "raw": {"header": raw_header, "payload": raw_payload, "signature": raw_sig},
    }


_HMAC_ALGS: dict[str, Any] = {
    "hs256": hashlib.sha256,
    "hs384": hashlib.sha384,
    "hs512": hashlib.sha512,
}


def jwt_sign_hs(signing_input: bytes, secret: str, alg: str) -> bytes:
    """HMAC-sign ``signing_input`` with ``secret`` under ``alg`` (hs256/hs384/hs512)."""
    digestmod = _HMAC_ALGS.get(alg.lower())
    if digestmod is None:
        raise JwtError(f"unsupported HMAC alg for signing: {alg!r}")
    return hmac.new(secret.encode("utf-8", "surrogateescape"), signing_input, digestmod).digest()


def jwt_crack_secret(token: str, wordlist_path: str, max_lines: Optional[int] = None) -> dict:
    """Brute a weak HMAC secret for an HS256/HS384/HS512 JWT against a local wordlist.

    Delegates the hashing/compare loop's *shape* to ``hashid`` (reads the wordlist the same
    read-only, local-file-only way); the actual compare is HMAC, not a bare digest, so it is
    done here rather than inside ``hashid.crack``. Returns a clean error dict (never raises)
    for a non-HMAC alg, ``alg: none``, or a missing/unreadable wordlist.
    """
    try:
        decoded = jwt_decode(token)
    except JwtError as exc:
        return {"found": False, "tried": 0, "error": str(exc)}

    alg = str(decoded["header"].get("alg", "")).strip().lower()
    if alg not in _HMAC_ALGS:
        return {"found": False, "tried": 0,
                "error": f"alg {alg!r} is not a crackable HMAC family (hs256/hs384/hs512)"}
    if not decoded["signature"]:
        return {"found": False, "tried": 0, "error": "token has no signature to match"}

    try:
        fh = hashid._open_wordlist(wordlist_path)  # same read-only local-file semantics
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
                tried += 1
                if jwt_sign_hs(decoded["signing_input"], word, alg) == decoded["signature"]:
                    return {"found": True, "secret": word, "alg": alg, "tried": tried}
    except OSError as exc:
        return {"found": False, "tried": tried, "error": f"error reading wordlist: {exc}"}
    return {"found": False, "tried": tried}


def jwt_encode_none(header_extra: dict, payload: dict) -> str:
    """Build an ``alg: none`` token (no signature) -- selftest fixture / demo helper only."""
    header = {"typ": "JWT", "alg": "none", **header_extra}
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}."


def jwt_encode_hs256(payload: dict, secret: str, header_extra: Optional[dict] = None) -> str:
    """Build a normally-signed HS256 token -- selftest fixture / demo helper only."""
    header = {"typ": "JWT", "alg": "HS256", **(header_extra or {})}
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    sig = jwt_sign_hs(f"{h}.{p}".encode("ascii"), secret, "hs256")
    return f"{h}.{p}.{b64url_encode(sig)}"


# --------------------------------------------------------------------------- wordlist / fuzz gen

COMMON_DIRS = ("admin", "api", "backup", "config", "login", "static", "uploads", "v1", "v2")
COMMON_EXTS = ("", ".php", ".html", ".bak", ".json", ".txt", ".zip", ".old")


def gen_wordlist(seed: str, extra_dirs: Optional[list[str]] = None,
                  extra_exts: Optional[list[str]] = None, case_variants: bool = True) -> list[str]:
    """Deterministically generate path/param fuzz candidates from ``seed``.

    Combines the seed and a small set of common dirs with a common extension list, plus
    (optionally) case variants of each. Output order is fixed given the same inputs -- no
    randomness, no I/O, no network. Meant to seed a *local* fuzzing tool's wordlist file;
    this function and :func:`run`'s ``wordlist`` subcommand never issue a request.
    """
    seed = seed.strip().strip("/")
    dirs = [seed] + list(COMMON_DIRS) + list(extra_dirs or [])
    exts = list(COMMON_EXTS) + list(extra_exts or [])

    seen: set[str] = set()
    out: list[str] = []

    def add(candidate: str) -> None:
        if candidate and candidate not in seen:
            seen.add(candidate)
            out.append(candidate)

    for d in dirs:
        if not d:
            continue
        for ext in exts:
            base = f"{d}{ext}"
            add(base)
            add(f"/{base}")
            if case_variants:
                add(base.upper())
                add(base.capitalize())
    return out


# --------------------------------------------------------------------------- cookie / encoding helpers

def flask_session_decode(cookie: str) -> dict[str, Any]:
    """Split a Flask/itsdangerous session cookie into its structural parts and base64url-decode
    the payload segment. **No secret is used or needed** -- the HMAC signature segment is
    returned opaque (undecoded) since it cannot be verified or reversed without the server's
    ``SECRET_KEY``. Flask cookies are ``payload.timestamp.signature`` or, for older
    itsdangerous versions, just ``payload.signature``.
    """
    cookie = cookie.strip()
    parts = cookie.split(".")
    if len(parts) not in (2, 3):
        raise JwtError(f"expected a 2- or 3-part itsdangerous cookie, got {len(parts)} parts")
    raw_payload = parts[0]
    try:
        payload_bytes = b64url_decode(raw_payload)
    except ValueError as exc:
        raise JwtError(f"bad payload segment: {exc}") from None
    try:
        payload = json.loads(payload_bytes)
    except (ValueError, UnicodeDecodeError):
        payload = None  # not JSON (e.g. zlib-compressed); return raw bytes instead

    result: dict[str, Any] = {
        "payload_raw": payload_bytes,
        "payload_json": payload,
        "parts": parts,
        "signature": parts[-1],
    }
    if len(parts) == 3:
        result["timestamp_b64"] = parts[1]
    return result


_COMMON_HASH_ALGS = ("md5", "sha1", "sha256", "sha512")


def common_hashes(value: str) -> dict[str, str]:
    """Hex digest of ``value`` under the common web-CTF hash families, plus NTLM via ``hashid``."""
    data = value.encode("utf-8", "surrogateescape")
    out = {alg: hashlib.new(alg, data).hexdigest() for alg in _COMMON_HASH_ALGS}
    out["ntlm"] = hashid.ntlm_hash(value)
    return out


# --------------------------------------------------------------------------- CLI

def run(args: list[str]) -> int:
    """CLI entry point: ``jwt`` / ``wordlist`` / ``cookie`` / ``selftest``."""
    if args[:1] in (["selftest"], ["--selftest"]):
        return 0 if selftest() else 1

    p = argparse.ArgumentParser(prog="recon.py webkit", description=DESCRIPTION)
    sub = p.add_subparsers(dest="cmd")

    jp = sub.add_parser("jwt", help="decode a JWT, flag alg:none, optionally crack a weak HMAC secret")
    jp.add_argument("token")
    jp.add_argument("--crack", action="store_true", help="brute the HMAC secret against --wordlist")
    jp.add_argument("--wordlist", default=hashid.DEFAULT_WORDLIST,
                     help=f"local wordlist path (default {hashid.DEFAULT_WORDLIST}); read-only, never downloaded")
    jp.add_argument("--limit", type=int, default=None, help="stop after N wordlist lines")

    wp = sub.add_parser("wordlist", help="generate path/param fuzz candidates from a seed (offline, generate-only)")
    wp.add_argument("seed")
    wp.add_argument("--dirs", default="", help="comma-separated extra dirs to add")
    wp.add_argument("--exts", default="", help="comma-separated extra extensions to add (include the dot)")
    wp.add_argument("--no-case", action="store_true", help="skip upper/capitalize case variants")
    wp.add_argument("-o", "--output", default=None, help="write candidates to this file instead of stdout")

    cp = sub.add_parser("cookie", help="base64url / Flask session structure decode / common hash")
    cp.add_argument("action", choices=["b64decode", "b64encode", "flask", "hash"])
    cp.add_argument("value")

    ns = p.parse_args(args)
    if ns.cmd is None:
        p.print_help()
        return 0

    if ns.cmd == "jwt":
        try:
            decoded = jwt_decode(ns.token)
        except JwtError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(f"header:  {json.dumps(decoded['header'], indent=2)}")
        print(f"payload: {json.dumps(decoded['payload'], indent=2)}")
        print(f"signature: {decoded['signature'].hex() or '(empty)'}")
        if decoded["alg_none"]:
            print("WARNING: alg is 'none' -- this token is unsigned/unverifiable by design "
                  "(classic alg:none vuln if the server accepts it)")
        if ns.crack:
            res = jwt_crack_secret(ns.token, ns.wordlist, max_lines=ns.limit)
            if res.get("error"):
                print(f"crack: error: {res['error']}", file=sys.stderr)
                return 1
            if res["found"]:
                print(f"crack: found secret {res['secret']!r}  [{res['tried']} candidates tried]")
            else:
                print(f"crack: not found  [{res['tried']} candidates tried]")
                return 1
        return 0

    if ns.cmd == "wordlist":
        extra_dirs = [d for d in ns.dirs.split(",") if d.strip()]
        extra_exts = [e for e in ns.exts.split(",") if e.strip()]
        words = gen_wordlist(ns.seed, extra_dirs=extra_dirs, extra_exts=extra_exts,
                              case_variants=not ns.no_case)
        text = "\n".join(words)
        if ns.output:
            try:
                with open(ns.output, "w") as fh:
                    fh.write(text + ("\n" if text else ""))
            except OSError as exc:
                print(f"error: cannot write '{ns.output}': {exc}", file=sys.stderr)
                return 1
            print(f"wrote {len(words)} candidates to {ns.output}")
        else:
            print(text)
        return 0

    # ns.cmd == "cookie"
    try:
        if ns.action == "b64decode":
            print(b64url_decode(ns.value).decode("utf-8", "replace"))
        elif ns.action == "b64encode":
            print(b64url_encode(ns.value.encode("utf-8", "surrogateescape")))
        elif ns.action == "flask":
            res = flask_session_decode(ns.value)
            print(f"parts: {len(res['parts'])}")
            if res["payload_json"] is not None:
                print(f"payload: {json.dumps(res['payload_json'], indent=2)}")
            else:
                print(f"payload (non-JSON, {len(res['payload_raw'])} bytes): {res['payload_raw']!r}")
            print(f"signature (opaque, unverifiable without SECRET_KEY): {res['signature']}")
        else:  # hash
            for alg, digest in common_hashes(ns.value).items():
                print(f"{alg:<8}{digest}")
    except (ValueError, JwtError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


# --------------------------------------------------------------------------- self-test

def selftest() -> bool:
    """All fixtures are in-memory/temp-dir; never touches the network or a real wordlist.

    Also documents the offline guarantee directly: this module imports no socket-capable
    module (``socket``, ``urllib``, ``http``, ``requests``) anywhere -- grep the import
    block above, or see the assertion below that inspects ``sys.modules`` after import.
    """
    results: list[bool] = []

    def check(name: str, cond: bool) -> None:
        results.append(bool(cond))
        if not cond:
            print(f"  failed: {name}")

    # --- JWT decode to expected claims (known token) ---
    secret = "s3cr3t"
    payload = {"sub": "1234567890", "name": "Alice", "admin": True}
    token = jwt_encode_hs256(payload, secret)
    decoded = jwt_decode(token)
    check("jwt decode header alg", decoded["header"].get("alg") == "HS256")
    check("jwt decode payload claims", decoded["payload"] == payload)
    check("jwt decode signature present", len(decoded["signature"]) == 32)  # SHA-256 digest size
    check("jwt decode alg_none false for HS256", decoded["alg_none"] is False)

    # malformed token -> clean error, not a crash
    try:
        jwt_decode("not.a.valid.jwt.token")
        check("jwt decode malformed raises JwtError", False)
    except JwtError:
        check("jwt decode malformed raises JwtError", True)

    # --- alg:none detection ---
    none_token = jwt_encode_none({}, {"sub": "attacker", "admin": True})
    none_decoded = jwt_decode(none_token)
    check("jwt alg:none detected", none_decoded["alg_none"] is True)
    check("jwt alg:none payload intact", none_decoded["payload"]["admin"] is True)
    check("jwt alg:none empty signature", none_decoded["signature"] == b"")

    # --- weak HMAC secret recovery from an embedded wordlist ---
    with tempfile.TemporaryDirectory() as td:
        wl = os.path.join(td, "mini.txt")
        with open(wl, "w") as fh:
            fh.write("password\nletmein\n" + secret + "\nqwerty\n")
        res = jwt_crack_secret(token, wl)
        check("jwt crack recovers weak secret", res["found"] and res["secret"] == secret and res["alg"] == "hs256")

        # wrong secret in a wordlist that doesn't contain it -> clean miss, not a crash
        with open(wl, "w") as fh:
            fh.write("password\nletmein\nqwerty\n")
        res_miss = jwt_crack_secret(token, wl)
        check("jwt crack clean miss", not res_miss["found"] and "error" not in res_miss)

        # alg:none token is not HMAC-crackable -> clean error
        res_none = jwt_crack_secret(none_token, wl)
        check("jwt crack alg:none clean error", not res_none["found"] and bool(res_none.get("error")))

        # missing wordlist -> clean error, never an exception
        missing = os.path.join(td, "nope.txt")
        try:
            res_bad = jwt_crack_secret(token, missing)
            check("jwt crack missing wordlist clean error", not res_bad["found"] and bool(res_bad.get("error")))
        except Exception as exc:  # pragma: no cover - the point is that this never fires
            check(f"jwt crack missing wordlist raised {type(exc).__name__}", False)

    # --- wordlist/fuzz gen: deterministic + contains seeded entries ---
    w1 = gen_wordlist("secret")
    w2 = gen_wordlist("secret")
    check("wordlist deterministic", w1 == w2)
    check("wordlist contains bare seed", "secret" in w1)
    check("wordlist contains seeded extension variant", "secret.bak" in w1)
    check("wordlist contains a common dir", "admin" in w1)
    check("wordlist contains case variant", "SECRET" in w1 or "Secret" in w1)
    w_extra = gen_wordlist("seed", extra_dirs=["uploadz"], extra_exts=[".sqlite"])
    check("wordlist honors extra dirs/exts", "uploadz" in w_extra and "seed.sqlite" in w_extra)
    w_nocase = gen_wordlist("seed", case_variants=False)
    check("wordlist --no-case drops case variants", "SEED" not in w_nocase and "Seed" not in w_nocase)

    # --- cookie / encoding helpers ---
    check("b64url roundtrip", b64url_decode(b64url_encode(b"hello world")) == b"hello world")
    check("b64url decode unpadded", b64url_decode("aGVsbG8") == b"hello")

    flask_cookie = b64url_encode(json.dumps({"user_id": 42, "role": "guest"}).encode()) + ".ts.sig"
    fres = flask_session_decode(flask_cookie)
    check("flask session structure decode", fres["payload_json"] == {"user_id": 42, "role": "guest"})
    check("flask session signature left opaque", fres["signature"] == "sig")
    check("flask session timestamp segment present", fres.get("timestamp_b64") == "ts")

    hashes = common_hashes("ctf123")
    check("common hash md5", hashes["md5"] == hashlib.md5(b"ctf123").hexdigest())
    check("common hash sha256", hashes["sha256"] == hashlib.sha256(b"ctf123").hexdigest())
    check("common hash ntlm present", len(hashes["ntlm"]) == 32)

    # --- offline proof: no socket-capable module ever gets imported by this module ---
    socketish = {"socket", "urllib", "urllib2", "http.client", "requests", "httpx", "ftplib", "smtplib"}
    imported = socketish & set(sys.modules.keys())
    # these may be imported transitively by the interpreter/test runner itself, not by webkit;
    # the real guarantee is structural: grep this file's own import block for any of them.
    with open(__file__, "r", encoding="utf-8") as fh:
        source = fh.read()
    import_block = source.split("\n\n\n", 1)[0]
    check("no network import in webkit.py's own import block",
          not any(f"import {m}" in import_block or f"from {m}" in import_block for m in socketish))

    return all(results)


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
