"""go: one-command front door. Detects the input type, runs the matching module chain, ranks flag candidates.

    recon.py go <file-or-dir> [--arg N ...] [--text "challenge description"]
                [--step-timeout S] [--budget S] [-v]

Chain (siblings are called in-process through the registry; their stdout is captured and scanned):
    always first   triage (whole-file flag scan)
    *.java         vaultdoor
    asm text       asmeval (with each --arg list, and zero-arg)       (*.S/*.s/*.asm or gdb/objdump-style text)
    *.py           pyrun --run --auto-input   (pyrun's refusal logic is the guardrail; --force is never passed)
    ELF            autosolve, then revauto
    pcap/pcapng    forensics
    PNG/JPEG/PDF/data blob   forensics + binextras extract into a fresh tempdir, every extracted file is
                   flag-scanned (raw bytes and utf-16-le decode)
    zip/tar/gzip   binextras extract + the same scan of extracted files
    text/unknown   decode -f (files over 200KB skipped)
    --text / -t    decode on the description, plus decode -f on each flag-shaped token alone

Every step has a wall-clock timeout (--step-timeout, default 20s) and the whole run a budget (--budget,
default 180s). Output ends with "== FLAG CANDIDATES ==" (deduped, ranked, each tagged with the step that
saw it) and one status line per step. Exit 0 if any candidate was found, 1 if none, 2 on usage errors.
Fully offline; nothing here opens a socket or executes the input directly (pyrun does its own guarded run).
"""
from __future__ import annotations

import argparse
import contextlib
import io
import os
import re
import shutil
import signal
import sys
import tempfile
import threading
import time
import zipfile
from dataclasses import dataclass, field
from types import ModuleType
from typing import Callable, Optional

NAME = "go"
DESCRIPTION = "One-command front door: detect input type, run the module chain, print ranked flag candidates"

DEFAULT_STEP_TIMEOUT = 20.0
DEFAULT_BUDGET = 180.0
DECODE_MAX_BYTES = 200 * 1024        # text files above this are not fed to `decode -f`
SCAN_MAX_BYTES = 8 * 1024 * 1024     # bytes read per extracted file
SHOW_LINES = 12                      # captured lines echoed per step without -v
SKIP_NAMES = {".placeholder", ".ignore"}

# flag-shaped token as written in the task: used on descriptions and on captured step output.
TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{2,24}\{[^}]{1,200}\}")
TOKEN_LINE_RE = re.compile(r"[A-Za-z0-9_-]{2,24}\{[^}\r\n]{1,200}\}")
TOKEN_BYTES_RE = re.compile(rb"[A-Za-z0-9_-]{2,24}\{[\x20-\x7c\x7e]{1,200}\}")
KNOWN_PREFIX_RE = re.compile(r"^(picoctf|flag|ctf|cybersci|htb|thm|ductf|uiuctf|csaw)\{", re.I)
ASM_TEXT_RE = re.compile(
    r"Dump of assembler code|^\s*(?:0x)?[0-9a-f]{4,16}\s*<\+?\d+>:|^\s*[0-9a-f]{4,16}:\s+(?:[0-9a-f]{2}\s)+\s*\w+|"
    r"^\s*\.(?:globl|global|text|section)\b|^\s*[A-Za-z_]\w*:\s*$.*?^\s+(?:mov|push|add|sub|ldr|stp|ret)\b",
    re.I | re.M | re.S)


class _StepTimeout(BaseException):
    """Raised by the alarm handler; BaseException so a module's ``except Exception`` cannot swallow it."""


@dataclass
class StepResult:
    """Outcome of one chain step."""
    label: str
    status: str                 # ok | exit N | timeout | refused | error | skipped | unavailable
    output: str = ""
    seconds: float = 0.0


@dataclass
class Candidate:
    """A flag-shaped string and every step that saw it."""
    text: str
    sources: list[str] = field(default_factory=list)
    order: int = 0


class _Capture(io.TextIOWrapper):
    """Text sink that also exposes ``.buffer`` (some modules write bytes to sys.stdout.buffer)."""

    def __init__(self) -> None:
        self._raw = io.BytesIO()
        super().__init__(self._raw, encoding="utf-8", errors="replace", write_through=True)

    def getvalue(self) -> str:
        self.flush()
        return self._raw.getvalue().decode("utf-8", "replace")


class Runner:
    """Runs steps with timeouts and a total budget; accumulates results and flag candidates."""

    def __init__(self, mods: dict[str, ModuleType], step_timeout: float, budget: float,
                 verbose: bool, out: Callable[[str], None] = print) -> None:
        self.mods = mods
        self.step_timeout = step_timeout
        self.deadline = time.monotonic() + budget
        self.verbose = verbose
        self.say = out
        self.results: list[StepResult] = []
        self.cands: dict[str, Candidate] = {}

    # ---- candidates -------------------------------------------------------------------------
    def add_text(self, text: str, source: str) -> None:
        """Record every flag-shaped token in ``text`` under ``source``."""
        for m in TOKEN_LINE_RE.finditer(text):
            self._add(m.group(0), source)

    def add_bytes(self, data: bytes, source: str) -> None:
        """Flag-scan raw bytes and their utf-16-le decode (both byte alignments)."""
        for m in TOKEN_BYTES_RE.finditer(data):
            self._add(m.group(0).decode("ascii"), f"{source} (raw)")
        for skew in (0, 1):
            wide = data[skew:len(data) - ((len(data) - skew) % 2)].decode("utf-16-le", "ignore")
            for m in TOKEN_LINE_RE.finditer(wide):
                self._add(m.group(0), f"{source} (utf-16-le)")

    def _add(self, flag: str, source: str) -> None:
        cand = self.cands.get(flag)
        if cand is None:
            cand = self.cands[flag] = Candidate(flag, [], len(self.cands))
        if source not in cand.sources:
            cand.sources.append(source)

    # ---- steps ------------------------------------------------------------------------------
    def step(self, label: str, module: str, argv: list[str], tag: str = "") -> StepResult:
        """Run ``module`` with ``argv`` in-process, capture stdout/stderr, enforce the timeouts."""
        full = f"{label}{(' [' + tag + ']') if tag else ''}"
        remaining = self.deadline - time.monotonic()
        if remaining <= 0.5:
            return self._finish(StepResult(full, "skipped: budget exhausted"))
        mod = self.mods.get(module)
        if mod is None:
            return self._finish(StepResult(full, f"unavailable: module '{module}' not loaded"))
        limit = max(0.5, min(self.step_timeout, remaining))
        buf = _Capture()
        start = time.monotonic()
        status = "ok"
        rc: Optional[int] = None
        try:
            with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
                rc = _call_with_timeout(lambda: mod.run(argv), limit)
        except _StepTimeout:
            status = f"timeout after {limit:g}s"
        except SystemExit as exc:
            rc = exc.code if isinstance(exc.code, int) else (0 if exc.code is None else 1)
        except Exception as exc:  # noqa: BLE001 - a failing module must not stop the chain
            status = f"error: {type(exc).__name__}: {exc}"
        out = buf.getvalue()
        if status == "ok":
            rc = rc if isinstance(rc, int) else 0
            if "REFUSED" in out and module == "pyrun":
                status = "refused (pyrun guard)"
            elif rc != 0:
                status = f"exit {rc}"
        res = StepResult(full, status, out, time.monotonic() - start)
        self.add_text(out, full)
        return self._finish(res)

    def _finish(self, res: StepResult) -> StepResult:
        self.results.append(res)
        self.say(f"--- {res.label}: {res.status} ({res.seconds:.1f}s)")
        lines = [ln for ln in res.output.splitlines() if ln.strip()]
        shown = lines if self.verbose else lines[:SHOW_LINES]
        for ln in shown:
            self.say("    " + ln[:240])
        if len(shown) < len(lines):
            self.say(f"    ... {len(lines) - len(shown)} more line(s) (use -v)")
        return res

    def note(self, label: str, status: str, output: str = "") -> None:
        """Record a step done outside a sibling module (in-process scan)."""
        res = StepResult(label, status, output)
        self.add_text(output, label)
        self._finish(res)


def _call_with_timeout(fn: Callable[[], object], seconds: float) -> object:
    """Run ``fn`` with a wall-clock limit: SIGALRM in the main thread, else a joined daemon thread."""
    if hasattr(signal, "setitimer") and threading.current_thread() is threading.main_thread():
        def on_alarm(signum, frame):  # noqa: ANN001
            raise _StepTimeout()
        old = signal.signal(signal.SIGALRM, on_alarm)
        signal.setitimer(signal.ITIMER_REAL, seconds)
        try:
            return fn()
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, old)
    box: dict[str, object] = {}

    def worker() -> None:
        try:
            box["rc"] = fn()
        except BaseException as exc:  # noqa: BLE001 - re-raised in the caller
            box["exc"] = exc
    t = threading.Thread(target=worker, daemon=True)
    t.start()
    t.join(seconds)
    if t.is_alive():
        raise _StepTimeout()  # the abandoned thread cannot be killed; it is a daemon and its output is dropped
    if "exc" in box:
        raise box["exc"]  # type: ignore[misc]
    return box.get("rc")


# ---------------------------------------------------------------------------------------------
# type detection

def detect_kind(path: str, data: bytes, mods: dict[str, ModuleType]) -> str:
    """Return one of java/asm/py/elf/pcap/blob/archive/text, from extension first, then content."""
    ext = os.path.splitext(path)[1].lower()
    if ext == ".java":
        return "java"
    if ext in (".s", ".asm"):
        return "asm"
    if ext == ".py":
        return "py"
    cat = "text"
    batch = mods.get("batch")
    if batch is not None:
        try:
            cat = batch.classify(data, mods)
        except Exception:  # noqa: BLE001 - fall back to the local checks below
            cat = "text"
    if batch is None:
        if data[:4] == b"\x7fELF":
            cat = "elf"
        elif data[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a"):
            cat = "pcap"
        elif data[:4] in (b"\x89PNG", b"%PDF") or data[:3] == b"\xff\xd8\xff":
            cat = "blob"
        elif data[:2] == b"PK" or data[:2] == b"\x1f\x8b":
            cat = "archive"
    if cat == "elf":
        return "elf"
    if cat == "pcap":
        return "pcap"
    if cat in ("image", "pdf", "data", "other"):
        return "blob"
    if cat == "archive":
        return "archive"
    if cat == "empty":
        return "text"
    if ASM_TEXT_RE.search(data[:200000].decode("utf-8", "replace")):
        return "asm"
    return "text"


# ---------------------------------------------------------------------------------------------
# chains

def extract_and_scan(run: Runner, path: str, tag: str) -> None:
    """binextras extract into a fresh tempdir, then flag-scan every extracted file (raw + utf-16-le)."""
    tmp = tempfile.mkdtemp(prefix="go-extract-")
    try:
        outdir = os.path.join(tmp, "out")
        run.step("binextras extract", "binextras", ["extract", path, "-o", outdir], tag)
        files = 0
        for root, _dirs, names in os.walk(outdir):
            for n in sorted(names):
                fp = os.path.join(root, n)
                try:
                    with open(fp, "rb") as fh:
                        data = fh.read(SCAN_MAX_BYTES)
                except OSError:
                    continue
                files += 1
                rel = os.path.relpath(fp, outdir)
                run.add_bytes(data, f"extracted:{rel} [{tag}]")
        run.note(f"flag-scan extracted files [{tag}]", f"ok ({files} file(s) scanned)")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def chain_file(run: Runner, path: str, arg_vals: list[str]) -> None:
    """Run the full chain for one file."""
    tag = os.path.basename(path)
    try:
        with open(path, "rb") as fh:
            data = fh.read(SCAN_MAX_BYTES)
        size = os.path.getsize(path)
    except OSError as exc:
        run.note(f"read [{tag}]", f"error: {exc.strerror or exc}")
        return
    kind = detect_kind(path, data, run.mods)
    run.say(f"=== {path}: detected {kind} ({size} bytes)")
    run.step("triage", "triage", [path], tag)
    if kind == "java":
        run.step("vaultdoor", "vaultdoor", [path], tag)
    elif kind == "asm":
        if arg_vals:
            argv = [path]
            for v in arg_vals:
                argv += ["--arg", v]
            run.step("asmeval --arg", "asmeval", argv, tag)
        run.step("asmeval", "asmeval", [path], tag)
    elif kind == "py":
        pt = max(1.0, run.step_timeout * 0.75)  # let pyrun time out (and clean up its child) before go does
        run.step("pyrun --run --auto-input", "pyrun",
                 [path, "--run", "--auto-input", "--timeout", f"{pt:g}"], tag)
    elif kind == "elf":
        run.step("autosolve", "autosolve", [path], tag)
        run.step("revauto", "revauto", [path], tag)
    elif kind == "pcap":
        run.step("forensics", "forensics", [path], tag)
    elif kind == "blob":
        run.step("forensics", "forensics", [path], tag)
        extract_and_scan(run, path, tag)
    elif kind == "archive":
        extract_and_scan(run, path, tag)
    else:
        if size > DECODE_MAX_BYTES:
            run.note(f"decode -f [{tag}]", f"skipped: file over {DECODE_MAX_BYTES // 1024}KB")
        else:
            run.step("decode -f", "decode", ["-f", path], tag)


def chain_text(run: Runner, text: str) -> None:
    """Challenge-description chain: decode the text, then decode -f each flag-shaped token alone."""
    run.say("=== --text description")
    run.step("decode (text)", "decode", [text], "text")
    seen: set[str] = set()
    for m in TOKEN_RE.finditer(text):
        tok = m.group(0)
        if tok in seen:
            continue
        seen.add(tok)
        fd, tmp = tempfile.mkstemp(prefix="go-token-")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(tok)
            run.step("decode -f (token)", "decode", ["-f", tmp], tok[:40])
        finally:
            with contextlib.suppress(OSError):
                os.unlink(tmp)


def list_inputs(target: str) -> list[str]:
    """Files to process: the file itself, or a directory's files (sorted; .placeholder/.ignore/subdirs skipped)."""
    if os.path.isdir(target):
        return [os.path.join(target, n) for n in sorted(os.listdir(target))
                if n not in SKIP_NAMES and os.path.isfile(os.path.join(target, n))]
    return [target]


def rank(cands: dict[str, Candidate]) -> list[tuple[int, Candidate]]:
    """Score candidates (mechanical: known prefix, multiple sources, charset) and sort best first."""
    scored = []
    for c in cands.values():
        score = 10
        if KNOWN_PREFIX_RE.match(c.text):
            score += 100
        score += 5 * (len(c.sources) - 1)
        body = c.text[c.text.index("{") + 1:-1]
        score += 3 if re.fullmatch(r"[A-Za-z0-9_!@#$%^&*.+=:-]+", body) else -3
        scored.append((score, c))
    scored.sort(key=lambda sc: (-sc[0], sc[1].order))
    return scored


def report(run: Runner) -> int:
    """Print the FLAG CANDIDATES and STEPS sections; return the exit code."""
    run.say("\n== FLAG CANDIDATES ==")
    ranked = rank(run.cands)
    if not ranked:
        run.say("(none)")
    for i, (score, c) in enumerate(ranked, 1):
        run.say(f"{i:>2}. {c.text}   [score {score}]")
        for s in c.sources:
            run.say(f"      seen by: {s}")
    run.say("\n== STEPS ==")
    for r in run.results:
        run.say(f"{r.status:<28} {r.label}")
    return 0 if ranked else 1


USAGE = """go usage:
  recon.py go <file-or-dir> [--arg N ...] [--text "challenge description"] [--step-timeout S] [--budget S] [-v]
  recon.py go -t "description"        (description only, no file)
  recon.py go selftest"""


def run(args: list[str]) -> int:
    """CLI entry point (registry contract)."""
    if args[:1] in (["selftest"], ["--selftest"]):
        return 0 if selftest() else 1
    p = argparse.ArgumentParser(prog="recon.py go", description=DESCRIPTION)
    p.add_argument("target", nargs="?", help="file or directory")
    p.add_argument("--arg", action="append", default=[], metavar="N", help="argument forwarded to asmeval (repeatable)")
    p.add_argument("-t", "--text", help="pasted challenge description")
    p.add_argument("--step-timeout", type=float, default=DEFAULT_STEP_TIMEOUT, help="seconds per step (default 20)")
    p.add_argument("--budget", type=float, default=DEFAULT_BUDGET, help="total seconds (default 180)")
    p.add_argument("-v", "--verbose", action="store_true", help="echo all captured step output")
    try:
        ns = p.parse_args(args)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    if ns.target is None and ns.text is None:
        print(USAGE)
        return 2
    if ns.step_timeout <= 0 or ns.budget <= 0:
        print("error: --step-timeout and --budget must be > 0", file=sys.stderr)
        return 2
    if ns.target is not None and not os.path.exists(ns.target):
        print(f"error: no such file or directory: {ns.target}", file=sys.stderr)
        return 1
    try:
        from modules import discover
    except ImportError:
        from . import discover  # type: ignore[no-redef]
    mods = discover()
    runner = Runner(mods, ns.step_timeout, ns.budget, ns.verbose)
    if ns.text is not None:
        chain_text(runner, ns.text)
    if ns.target is not None:
        files = list_inputs(ns.target)
        if not files:
            runner.note(f"inputs [{ns.target}]", "skipped: no files")
        for fp in files:
            chain_file(runner, fp, ns.arg)
    return report(runner)


# ---------------------------------------------------------------------------------------------
# selftest

_JAVA = (
    "public class VaultDoorTraining {\n"
    "    public boolean checkPassword(String password) {\n"
    '        return password.equals("w4rm1ng_Up_w1tH_jAv4");\n'
    "    }\n"
    "}\n"
)


def _xor_expr(text: str, key: str) -> str:
    return "+".join(f"chr({ord(c) ^ ord(key[i % len(key)]):#x})" for i, c in enumerate(text))


def _str_xor_py(flag: str, pw: str) -> str:
    return (
        "def str_xor(secret, key):\n"
        "    new_key = key\n"
        "    i = 0\n"
        "    while len(new_key) < len(secret):\n"
        "        new_key = new_key + key[i]\n"
        "        i = (i + 1) % len(key)\n"
        "    return ''.join([chr(ord(a) ^ ord(b)) for (a, b) in zip(secret, new_key)])\n"
        f"flag_enc = {_xor_expr(flag, pw)}\n"
        "user_pw = input('password? ')\n"
        f"if user_pw == {pw!r}:\n"
        "    print(str_xor(flag_enc, user_pw))\n"
        "else:\n"
        "    print('wrong password')\n"
    )


def _rot13(s: str) -> str:
    return s.translate(str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"))


def _go(argv: list[str]) -> tuple[int, str]:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        rc = run(argv)
    return rc, buf.getvalue()


def _cand_section(out: str) -> str:
    """The text between the FLAG CANDIDATES and STEPS headers."""
    return out.split("== FLAG CANDIDATES ==", 1)[-1].split("== STEPS ==", 1)[0]


def selftest() -> bool:
    """Self-contained fixtures: java leg, pyrun leg (benign + refused), rot13 --text, zip extract, utf-16 scan."""
    results: list[bool] = []

    def check(name: str, cond: bool) -> None:
        results.append(bool(cond))
        if not cond:
            print(f"  failed: {name}")

    with tempfile.TemporaryDirectory(prefix="go-selftest-") as tmp:
        def write(name: str, data: bytes | str) -> str:
            path = os.path.join(tmp, name)
            with open(path, "wb") as fh:
                fh.write(data if isinstance(data, bytes) else data.encode("utf-8"))
            return path

        # VaultDoor-style java -> flag surfaces in candidates
        rc, out = _go([write("VaultDoorTraining.java", _JAVA)])
        check(rc == 0 and "picoCTF{w4rm1ng_Up_w1tH_jAv4}" in _cand_section(out), f"java leg (rc {rc})")

        # benign str_xor .py -> found by the pyrun leg
        flag = "picoCTF{str_x0r_via_pyrun_77}"
        rc, out = _go([write("str_xor.py", _str_xor_py(flag, "abc123"))])
        sec = _cand_section(out)
        check(rc == 0 and flag in sec and "pyrun --run --auto-input" in sec, f"pyrun leg (rc {rc})")

        # network-attempting .py -> refusal recorded, chain continues, exits fine
        net = write("net.py", "import socket\ns = socket.create_connection(('127.0.0.1', 1))\nprint('connected')\n")
        rc, out = _go([net])
        steps = out.split("== STEPS ==", 1)[-1]
        check("refused (pyrun guard)" in steps and "connected" not in _cand_section(out), "network .py refusal recorded")
        check(rc in (0, 1) and "== FLAG CANDIDATES ==" in out, f"refusal does not stop go (rc {rc})")

        # rot13'd flag in a pasted description
        hidden = "picoCTF{rot13_in_the_desc}"
        desc = f"Our intern encoded the key as {_rot13(hidden)} before leaving. Can you recover it?"
        rc, out = _go(["--text", desc])
        check(rc == 0 and hidden in _cand_section(out), f"--text rot13 (rc {rc})")

        # zip with embedded flag.txt (deflated, so the raw archive does not contain the flag)
        zflag = "picoCTF{zip_member_flag_1}"
        u16flag = "picoCTF{utf16_inside_zip_2}"
        zpath = os.path.join(tmp, "blob.zip")
        with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("flag.txt", (zflag + "\n") * 40)
            zf.writestr("wide.bin", b"\x00\x01junk" + u16flag.encode("utf-16-le") + b"\x00\x00")
        rc, out = _go([zpath])
        sec = _cand_section(out)
        check(rc == 0 and zflag in sec and "extracted:flag.txt" in sec, f"zip extract leg (rc {rc})")
        check(u16flag in sec and "utf-16-le" in sec, "utf-16-le flag in extracted file")

        # no candidates -> exit 1; directory mode skips .placeholder
        d = os.path.join(tmp, "dir")
        os.mkdir(d)
        write("dir/.placeholder", "picoCTF{should_be_skipped}")
        write("dir/plain.txt", "nothing to see here\n")
        rc, out = _go([d])
        check(rc == 1 and "(none)" in out and "should_be_skipped" not in out, f"dir mode, no candidates (rc {rc})")

        # step timeout: a module that sleeps is recorded and the chain continues
        class _Slow:
            NAME = "slow"

            @staticmethod
            def run(argv: list[str]) -> int:
                time.sleep(5)
                return 0
        r = Runner({"slow": _Slow}, 0.5, 30, False, out=lambda s: None)  # type: ignore[dict-item]
        res = r.step("slow", "slow", [])
        check(res.status.startswith("timeout"), f"step timeout recorded ({res.status})")
        r2 = Runner({}, 1, 30, False, out=lambda s: None)
        check(r2.step("x", "missing", []).status.startswith("unavailable"), "missing module recorded")
        r3 = Runner({}, 1, 0.0, False, out=lambda s: None)
        check(r3.step("x", "missing", []).status.startswith("skipped"), "budget exhaustion recorded")

        rc, _ = _go([])
        check(rc == 2, "no arguments -> usage exit 2")
        rc, _ = _go([os.path.join(tmp, "nope")])
        check(rc == 1, "missing path -> exit 1")
    return all(results)


if __name__ == "__main__":
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    sys.exit(run(sys.argv[1:]))
