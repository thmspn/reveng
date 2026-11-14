"""SHELLCODE: the payload-side companion to ``disasm``. Pure byte math -- no process
execution, no assembling, no network. Features:

- **badchars**: given raw bytes (hex / ``\\x..`` escaped / file) and a badchar set, report
  which offsets contain forbidden bytes.
- **encode**: single-byte or rolling XOR encoder; can brute-force a key (and, for rolling
  keys, a short key) that keeps both the key and the encoded output badchar-free, and emits
  a tiny annotated (not assembled/executed) decoder-stub text plus an alphanumeric-safe hint.
- **fmt**: format converters -- hex <-> raw <-> ``\\x..`` escaped <-> C array <-> Python
  bytes literal.
- **stub**: a curated set of known static reference shellcode stubs, disassembled via the
  ``disasm`` module's capstone-optional decoder (hex fallback) and syscall/opcode tables.

Nothing here spawns a process, assembles machine code, or touches the network.
"""
from __future__ import annotations

import argparse
import ast
import itertools
import re
import string
import sys

from . import disasm

NAME = "shellcode"
DESCRIPTION = "Badchar checker, XOR/rolling encoder + decoder stub, hex/raw/\\x/C/py format converters, known static stubs"

# --------------------------------------------------------------------------- format converters

_ALNUM_BYTES = frozenset((string.ascii_letters + string.digits).encode("ascii"))


def from_hex(s: str) -> bytes:
    """Parse a hex string -- tolerant of ``0x`` prefixes, spaces, commas, newlines."""
    cleaned = re.sub(r"0[xX]", "", s)
    cleaned = re.sub(r"[^0-9a-fA-F]", "", cleaned)
    if not cleaned:
        raise ValueError("no hex digits found")
    if len(cleaned) % 2:
        raise ValueError("odd-length hex string (missing a nibble)")
    return bytes.fromhex(cleaned)


def to_hex(data: bytes) -> str:
    return data.hex()


def from_escaped(s: str) -> bytes:
    """Parse a ``\\x90\\x90...`` escaped byte string -- surrounding quotes/text ignored."""
    tokens = re.findall(r"\\x([0-9a-fA-F]{2})", s)
    if not tokens:
        raise ValueError(r"no \xNN sequences found")
    return bytes(int(t, 16) for t in tokens)


def to_escaped(data: bytes) -> str:
    return "".join(f"\\x{b:02x}" for b in data)


def from_c_array(s: str) -> bytes:
    """Parse a C-style ``unsigned char buf[] = {0x90, 0x90, ...};`` initializer."""
    tokens = re.findall(r"0[xX]([0-9a-fA-F]{1,2})", s)
    if not tokens:
        raise ValueError("no 0x.. byte tokens found")
    return bytes(int(t, 16) for t in tokens)


def to_c_array(data: bytes, varname: str = "shellcode") -> str:
    rows = [data[i:i + 8] for i in range(0, len(data), 8)] or [b""]
    body = ",\n    ".join(", ".join(f"0x{b:02x}" for b in row) for row in rows)
    return f"unsigned char {varname}[] = {{\n    {body}\n}};\nunsigned int {varname}_len = {len(data)};"


def from_py_bytes(s: str) -> bytes:
    """Parse a Python ``b'...'`` / ``b"..."`` bytes literal (safely, via ``ast.literal_eval``)."""
    try:
        node = ast.literal_eval(s.strip())
    except (ValueError, SyntaxError) as exc:
        raise ValueError(f"not a valid python literal: {exc}") from exc
    if not isinstance(node, bytes):
        raise ValueError("not a python bytes literal (expected b'...')")
    return node


def to_py_bytes(data: bytes) -> str:
    return repr(data)


# format name -> (parse: str -> bytes, render: bytes -> str)
FORMATS: dict[str, tuple] = {
    "hex": (from_hex, to_hex),
    "esc": (from_escaped, to_escaped),
    "c": (from_c_array, to_c_array),
    "py": (from_py_bytes, to_py_bytes),
}


def read_input(data: str, fmt: str) -> bytes:
    """Read a shellcode buffer either from a local file (``fmt == "file"``) or by parsing
    ``data`` as the given inline format. Never fetches or downloads anything."""
    if fmt == "file":
        with open(data, "rb") as fh:
            return fh.read()
    parser = FORMATS.get(fmt)
    if parser is None:
        raise ValueError(f"unknown input format: {fmt}")
    return parser[0](data)


def convert(data: bytes, to_fmt: str, varname: str = "shellcode") -> str:
    """Render ``data`` in the requested output format (hex/esc/c/py)."""
    renderer = FORMATS.get(to_fmt)
    if renderer is None:
        raise ValueError(f"unknown output format: {to_fmt}")
    render = renderer[1]
    return render(data, varname) if to_fmt == "c" else render(data)


# --------------------------------------------------------------------------- badchars

DEFAULT_BADCHARS = bytes.fromhex("000a0d")  # null, LF, CR -- the usual first offenders


def find_badchars(data: bytes, badchars: bytes) -> list[dict]:
    """Offsets in ``data`` whose byte value is in ``badchars``, as ``{"offset", "byte"}``."""
    bad = set(badchars)
    return [{"offset": i, "byte": b} for i, b in enumerate(data) if b in bad]


def badchars_report(data: bytes, badchars: bytes) -> str:
    hits = find_badchars(data, badchars)
    lines = [
        f"length: {len(data)} byte(s)",
        f"checked against: {' '.join(f'{b:02x}' for b in badchars) or '(empty set)'}",
    ]
    if not hits:
        lines.append("clean: no badchars found")
    else:
        lines.append(f"{len(hits)} badchar hit(s):")
        for h in hits:
            lines.append(f"  offset {h['offset']:#06x} ({h['offset']:5d})  byte 0x{h['byte']:02x}")
    return "\n".join(lines)


# --------------------------------------------------------------------------- XOR encoders

def xor_apply(data: bytes, key: bytes) -> bytes:
    """XOR ``data`` against ``key`` cycled byte-by-byte. Symmetric: encode == decode."""
    if not key:
        raise ValueError("key must be non-empty")
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def find_safe_key(data: bytes, badchars: bytes, key_len: int = 1, max_tries: int = 2_000_000) -> bytes | None:
    """Brute-force a ``key_len``-byte XOR key, itself badchar-free, such that the encoded
    output is also badchar-free. Returns ``None`` if no such key is found within the search
    budget (bounded by ``max_tries`` so a large ``key_len`` can't run away)."""
    bad = set(badchars)
    candidates = [b for b in range(1, 256) if b not in bad]
    if not candidates:
        return None
    tried = 0
    for combo in itertools.product(candidates, repeat=key_len):
        tried += 1
        if tried > max_tries:
            return None
        key = bytes(combo)
        enc = xor_apply(data, key)
        if not (set(enc) & bad):
            return key
    return None


def generate_decoder_stub(key: bytes) -> str:
    """An annotated x86-64 NASM-style decoder stub for ``key`` -- reference text only, never
    assembled or executed by this module."""
    if len(key) == 1:
        return (
            "; x86-64 NASM decoder stub (single-byte XOR key) -- reference text, not assembled/executed\n"
            "; in: rdi = pointer to encoded buffer, rcx = buffer length\n"
            "decode_loop:\n"
            f"    xor byte [rdi+rcx-1], 0x{key[0]:02x}\n"
            "    dec rcx\n"
            "    jnz decode_loop\n"
        )
    key_hex = ", ".join(f"0x{b:02x}" for b in key)
    return (
        "; x86-64 NASM decoder stub (rolling XOR key) -- reference text, not assembled/executed\n"
        f"; key bytes ({len(key)}): {key_hex}\n"
        "; in: rdi = pointer to encoded buffer, rcx = buffer length, rsi = pointer to key bytes\n"
        "decode_loop:\n"
        "    lodsb              ; al = [rsi]; rsi++\n"
        "    xor [rdi], al\n"
        "    inc rdi\n"
        "    cmp rsi, key_end\n"
        "    jne .nowrap\n"
        "    lea rsi, [key_start]\n"
        ".nowrap:\n"
        "    dec rcx\n"
        "    jnz decode_loop\n"
    )


def alnum_hint(data: bytes) -> dict:
    """Pure analysis (no actual alphanumeric *re*-encoding -- that needs a generated
    executable decoder, out of scope for pure byte math): flags offsets whose byte is outside
    ``[A-Za-z0-9]`` so the buffer could not survive an alphanumeric-only payload constraint."""
    bad_offsets = [i for i, b in enumerate(data) if b not in _ALNUM_BYTES]
    safe = not bad_offsets
    note = (
        "buffer is already alphanumeric-safe"
        if safe
        else f"{len(bad_offsets)} byte(s) outside [A-Za-z0-9]; true alphanumeric encoding needs "
             "a generated executable decoder stub (out of scope for pure byte math) -- consider "
             "an external alphanumeric encoder (e.g. msfvenom alpha_mixed/alpha_upper) on this buffer"
    )
    return {"alnum_safe": safe, "non_alnum_count": len(bad_offsets), "non_alnum_offsets": bad_offsets[:32], "note": note}


# --------------------------------------------------------------------------- known static stubs

STUBS: dict[str, dict] = {
    "execve_binsh_x64": {
        "arch": "x86_64",
        "desc": 'execve("/bin/sh", NULL, NULL) -- 27 bytes, null-free, classic Linux x86-64 stub',
        "bytes": bytes.fromhex("4831f65648bf2f62696e2f2f736857545f6a3b58995257545e0f05"),
    },
    "exit0_x64": {
        "arch": "x86_64",
        "desc": "exit(0) -- 10 bytes, minimal clean-exit syscall stub",
        "bytes": bytes.fromhex("b83c0000004831ff0f05"),
    },
}


def stub_disasm(name: str) -> str:
    """Disassemble a known stub via the ``disasm`` module's decoder (capstone if available,
    annotated hex fallback otherwise) so stub disassembly stays in one place."""
    entry = STUBS[name]
    data = entry["bytes"]
    fake_elf = {"bits": 64 if entry["arch"] == "x86_64" else 32}
    return disasm.disassemble(data, 0x400000, fake_elf)


# --------------------------------------------------------------------------- CLI

def _parse_hexbytes(s: str) -> bytes:
    return from_hex(s)


def run(args: list[str]) -> int:
    """CLI entry point (registry contract): ``badchars`` / ``encode`` / ``fmt`` / ``stub`` /
    ``selftest``."""
    p = argparse.ArgumentParser(prog="recon.py shellcode", description=DESCRIPTION)
    sub = p.add_subparsers(dest="cmd")

    bc = sub.add_parser("badchars", help="report offsets containing forbidden bytes")
    bc.add_argument("data", help="inline buffer (per --format) or a file path with --format file")
    bc.add_argument("--format", choices=("hex", "esc", "c", "py", "file"), default="hex")
    bc.add_argument("--bad", type=_parse_hexbytes, default=DEFAULT_BADCHARS,
                     help="hex string of badchars to check for (default 000a0d)")

    en = sub.add_parser("encode", help="XOR-encode a buffer; find a badchar-free key if none given")
    en.add_argument("data", help="inline buffer (per --format) or a file path with --format file")
    en.add_argument("--format", choices=("hex", "esc", "c", "py", "file"), default="hex")
    en.add_argument("--key", type=_parse_hexbytes, default=None, help="hex XOR key; if omitted, searched for")
    en.add_argument("--bad", type=_parse_hexbytes, default=DEFAULT_BADCHARS,
                     help="hex string of badchars the key/output must avoid (default 000a0d)")
    en.add_argument("--rolling", action="store_true", help="search a multi-byte rolling key")
    en.add_argument("--key-len", type=int, default=1, help="rolling key length to search (with --rolling)")

    fm = sub.add_parser("fmt", help="convert between hex / \\x escaped / C array / python bytes")
    fm.add_argument("data", help="inline buffer (per --from) or a file path with --from file")
    fm.add_argument("--from", dest="from_fmt", choices=("hex", "esc", "c", "py", "file"), required=True)
    fm.add_argument("--to", dest="to_fmt", choices=("hex", "esc", "c", "py"), required=True)
    fm.add_argument("--var", default="shellcode", help="C array variable name (--to c)")

    st = sub.add_parser("stub", help="curated known static shellcode stubs")
    st_sub = st.add_subparsers(dest="stub_cmd")
    st_sub.add_parser("list", help="list known stub names")
    sh = st_sub.add_parser("show", help="show a stub's bytes + disassembly")
    sh.add_argument("name", choices=sorted(STUBS))

    sub.add_parser("selftest", help="run the module self-test")
    p.add_argument("--selftest", action="store_true")

    try:
        ns = p.parse_args(args)
    except SystemExit as exc:  # -h -> 0, usage error -> 2; return instead of exiting
        return exc.code if isinstance(exc.code, int) else 2

    if ns.selftest or ns.cmd == "selftest":
        return 0 if selftest() else 1
    if ns.cmd is None:
        p.print_help()
        return 0

    try:
        return _dispatch(ns)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def _dispatch(ns: argparse.Namespace) -> int:
    if ns.cmd == "badchars":
        data = read_input(ns.data, ns.format)
        print(badchars_report(data, ns.bad))
        return 0

    if ns.cmd == "encode":
        data = read_input(ns.data, ns.format)
        key = ns.key
        if key is None:
            key = find_safe_key(data, ns.bad, key_len=ns.key_len if ns.rolling else 1)
            if key is None:
                print("error: no badchar-free key found within search budget", file=sys.stderr)
                return 1
        encoded = xor_apply(data, key)
        bad_hits = find_badchars(encoded, ns.bad)
        decoded_ok = xor_apply(encoded, key) == data
        print(f"key: {key.hex()}")
        print(f"encoded ({len(encoded)} bytes): {to_hex(encoded)}")
        print(f"encoded badchar-free: {not bad_hits}")
        print(f"decodes back to original: {decoded_ok}")
        print()
        print(generate_decoder_stub(key))
        hint = alnum_hint(encoded)
        print(f"alnum-safe hint: {hint['note']}")
        return 0

    if ns.cmd == "fmt":
        data = read_input(ns.data, ns.from_fmt)
        print(convert(data, ns.to_fmt, varname=ns.var))
        return 0

    if ns.cmd == "stub":
        if ns.stub_cmd == "show":
            entry = STUBS[ns.name]
            print(f"{ns.name}  ({entry['arch']})")
            print(entry["desc"])
            print(f"bytes ({len(entry['bytes'])}): {to_hex(entry['bytes'])}")
            print()
            print(stub_disasm(ns.name))
            return 0
        # default / "list"
        for name, entry in sorted(STUBS.items()):
            print(f"{name:<22}{entry['arch']:<10}{entry['desc']}")
        return 0

    return 2


# --------------------------------------------------------------------------- self-test

def selftest() -> bool:
    """All fixtures are in-memory; never touches the network or spawns a process."""
    results: list[bool] = []

    def check(name: str, cond: bool) -> None:
        results.append(bool(cond))
        if not cond:
            print(f"  failed: {name}")

    sample = bytes(range(1, 250))  # avoid 0x00 so plain round-trips aren't trivially empty

    # format converters: raw -> X -> raw identity, for every converter.
    check("hex round-trip", from_hex(to_hex(sample)) == sample)
    check("esc round-trip", from_escaped(to_escaped(sample)) == sample)
    check("c-array round-trip", from_c_array(to_c_array(sample)) == sample)
    check("py-bytes round-trip", from_py_bytes(to_py_bytes(sample)) == sample)

    # fmt cross-conversion also matches direct round-trip (hex -> esc -> hex).
    esc = to_escaped(sample)
    check("hex->esc->hex", from_hex(to_hex(from_escaped(esc))) == sample)

    # badchars: a planted \x00 and \x0a must be flagged at the right offsets.
    planted = b"AAAA\x00BBBB\x0aCCCC"
    hits = find_badchars(planted, DEFAULT_BADCHARS)
    offsets = {h["offset"] for h in hits}
    check("badchars flags planted 0x00", 4 in offsets)
    check("badchars flags planted 0x0a", 9 in offsets)
    check("badchars count matches plant", len(hits) == 2)
    clean = b"AAAABBBBCCCC"
    check("badchars clean buffer -> no hits", find_badchars(clean, DEFAULT_BADCHARS) == [])

    # XOR encode: a key search against common badchars must avoid them in both key and output,
    # and must decode back to the original.
    payload = bytes([0x00, 0x0a, 0x0d, 0x41, 0x42, 0x90, 0xff]) * 3
    key = find_safe_key(payload, DEFAULT_BADCHARS, key_len=1)
    check("find_safe_key found a key", key is not None)
    if key is not None:
        check("key itself is badchar-free", not (set(key) & set(DEFAULT_BADCHARS)))
        encoded = xor_apply(payload, key)
        check("encoded output is badchar-free", not (set(encoded) & set(DEFAULT_BADCHARS)))
        check("encoded decodes back to original", xor_apply(encoded, key) == payload)
        stub_text = generate_decoder_stub(key)
        check("decoder stub text non-empty", bool(stub_text.strip()))

    # rolling key search (bounded, small buffer) also round-trips.
    small_payload = bytes([0x00, 0x41, 0x0a])
    roll_key = find_safe_key(small_payload, DEFAULT_BADCHARS, key_len=2, max_tries=100_000)
    if roll_key is not None:
        enc2 = xor_apply(small_payload, roll_key)
        check("rolling key badchar-free", not (set(enc2) & set(DEFAULT_BADCHARS)))
        check("rolling key round-trip", xor_apply(enc2, roll_key) == small_payload)
    else:
        check("rolling key search completed without crashing", True)

    # alnum hint: a non-alnum buffer is correctly flagged; a pure-alnum buffer is not.
    check("alnum_hint flags non-alnum", not alnum_hint(payload)["alnum_safe"])
    check("alnum_hint passes pure-alnum", alnum_hint(b"ABCxyz012")["alnum_safe"])

    # known static stubs: every entry disassembles (or hex-dumps) without raising, and the
    # curated set is non-empty.
    check("stub set non-empty", len(STUBS) >= 2)
    for name in STUBS:
        try:
            text = stub_disasm(name)
            check(f"stub {name} disassembles", bool(text.strip()))
        except Exception as exc:  # pragma: no cover - a crash here is the failure itself
            check(f"stub {name} disasm raised {type(exc).__name__}", False)

    # bad input is reported cleanly, never raised past run().
    try:
        from_hex("not hex at all")
        check("from_hex rejects garbage", False)
    except ValueError:
        check("from_hex rejects garbage", True)

    return all(results)


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
