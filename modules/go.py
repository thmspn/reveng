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
    zip/gzip       binextras extract + the same scan of extracted files
    tar/bzip2/xz/7z/rar   explicit manual-extraction notice (no extraction attempted)
    text/unknown   decode -f (files over 200KB skipped)
    --text / -t    decode on the description, bounded embedded blobs, then each flag-shaped token alone

Every step has a wall-clock timeout (--step-timeout, default 20s) and the whole run a budget (--budget,
default 180s). Output ends with "== FLAG CANDIDATES ==" (deduped, ranked, each tagged with the step that
saw it), "== DERIVED INPUTS / REGISTER RESULTS ==" (exact evidence quoted from autosolve / pyrun / asmeval,
each with source and confidence; these are NOT flags), one status line per step ("ok" = the tool ran, not
that it solved anything) and, when nothing flag-shaped was found, a short next-step hint.
Exit 0 if any flag candidate was found, 1 if none (derived evidence does not change the exit code), 2 on
usage errors.
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
TOKEN_RE = re.compile(r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{1,64}\{[\x20-\x7a\x7c\x7e]{1,200}\}")
TOKEN_LINE_RE = TOKEN_RE
TOKEN_BYTES_RE = re.compile(rb"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{1,64}\{[\x20-\x7a\x7c\x7e]{1,200}\}")
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
    speculative_only: bool = False  # only seen among brute-force cipher guesses


@dataclass
class Derived:
    """Evidence a sibling printed that is not flag-shaped: a derived input/password or a register result."""
    kind: str                   # "derived input" | "derived value" | "register result"
    text: str                   # exact text as the sibling printed it
    source: str                 # step label
    conf: str                   # HIGH/MEDIUM/LOW (autosolve/pyrun) or complete/PARTIAL (asmeval)
    note: str = ""


_AUTO_SOLVE_RE = re.compile(r"^\s*SOLVE\s+(.+?)\s+\[([HML?])\]\s+method\s+(\S+)", re.M)
_AUTO_HEAD_RE = re.compile(r"^\s*HEADLINE\s+DERIVED\s+\[([HML?])\]\s+(.+?)\s*$", re.M)
_PYRUN_INPUT_RE = re.compile(r"^\s+\[HIGH\] line (\d+): (.+?)  \((.+)\)\s*$")
_PYRUN_DERIVED_RE = re.compile(r"^\s+\[derived-(?:xor|arith)\] \[HIGH\] line (\d+): (.+?)  \((.+)\)\s*$")
_ASM_CALL_RE = re.compile(r"^\s*(\w+\([^)\n]*\)) -> ((?:eax|rax|w0|x0) = .+?)\s*$", re.M)
_ASM_REG_RE = re.compile(r"^\s+(eax|rax|x0)\s+= (0x[0-9a-f]+.*?)\s*$", re.M)
_CONF_WORD = {"H": "HIGH", "M": "MEDIUM", "L": "LOW", "?": "unknown"}
MAX_DERIVED_PER_STEP = 6


def extract_derived(module: str, out: str, source: str) -> list[Derived]:
    """Quote supported derived evidence from a sibling's FULL captured output (never from the truncated echo).

    Only formats the siblings really print are recognized: autosolve ``SOLVE``/``HEADLINE DERIVED`` lines,
    pyrun HIGH ``[candidate-inputs]`` / ``[derived-*]`` lines, asmeval ``f(args) -> eax = ...`` result lines
    and the ``eax``/``rax``/``x0`` register of a zero-argument run. Nothing is guessed or reformatted.
    """
    found: list[Derived] = []
    if module == "autosolve":
        m = _AUTO_SOLVE_RE.search(out)
        if m:
            found.append(Derived("derived input", m.group(1), source, _CONF_WORD[m.group(2)], f"method {m.group(3)}"))
        else:
            h = _AUTO_HEAD_RE.search(out)
            if h:
                found.append(Derived("derived input", h.group(2), source, _CONF_WORD[h.group(1)], "autosolve headline"))
    elif module == "pyrun":
        section = ""
        for ln in out.splitlines():
            if ln.startswith("["):
                section = ln.split("]", 1)[0] + "]"
            elif not ln.startswith(" "):
                section = ""
            if section == "[candidate-inputs]":
                m = _PYRUN_INPUT_RE.match(ln)
                if m:
                    found.append(Derived("derived input", m.group(2), source, "HIGH", f"{m.group(3)}, line {m.group(1)}"))
            elif section == "[derived-values]":
                m = _PYRUN_DERIVED_RE.match(ln)
                if m:
                    found.append(Derived("derived value", m.group(2), source, "HIGH", f"{m.group(3)}, line {m.group(1)}"))
    elif module == "asmeval":
        calls = list(_ASM_CALL_RE.finditer(out))
        for m in calls:
            partial = "[PARTIAL" in m.group(2)
            found.append(Derived("register result", f"{m.group(1)} -> {m.group(2)}", source,
                                 "PARTIAL" if partial else "complete", "value as printed; not a flag"))
        if not calls:
            m = _ASM_REG_RE.search(out)
            if m:
                partial = "PARTIAL RESULT" in out
                found.append(Derived("register result", f"{m.group(1)} = {m.group(2)}", source,
                                     "PARTIAL" if partial else "complete", "return register, no --arg; not a flag"))
    return found[:MAX_DERIVED_PER_STEP]


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
        self.derived: list[Derived] = []
        self.kinds: list[str] = []          # detected input kinds, for the next-step hint
        self.text_only = False              # --text given
        self.text_tokens: list[str] = []    # long base64-looking tokens seen in --text (display-only hint)

    # ---- candidates -------------------------------------------------------------------------
    def add_text(self, text: str, source: str, speculative: bool = False) -> None:
        """Record every flag-shaped token in ``text`` under ``source``."""
        for m in TOKEN_LINE_RE.finditer(text):
            self._add(m.group(0), source, speculative)

    def add_bytes(self, data: bytes, source: str) -> None:
        """Flag-scan raw bytes and their utf-16-le decode (both byte alignments)."""
        for m in TOKEN_BYTES_RE.finditer(data):
            self._add(m.group(0).decode("ascii"), f"{source} (raw)")
        for skew in (0, 1):
            wide = data[skew:len(data) - ((len(data) - skew) % 2)].decode("utf-16-le", "ignore")
            for m in TOKEN_LINE_RE.finditer(wide):
                self._add(m.group(0), f"{source} (utf-16-le)")

    def _add(self, flag: str, source: str, speculative: bool = False) -> None:
        cand = self.cands.get(flag)
        if cand is None:
            cand = self.cands[flag] = Candidate(flag, [], len(self.cands), speculative)
        cand.speculative_only = cand.speculative_only and speculative
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
                if module == "decode" and callable(getattr(mod, "run_candidates", None)):
                    rc = _call_with_timeout(
                        lambda: mod.run_candidates(argv, lambda flag, spec: self._add(flag, full, spec)), limit)
                else:
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
        # decode supplies structured provenance. Never infer it from printed headings
        # or payload text; missing callback support fails closed for that module.
        if module != "decode":
            self.add_text(out, full)
        for d in extract_derived(module, out, full):
            if not any(d.kind == x.kind and d.text == x.text for x in self.derived):
                self.derived.append(d)
        return self._finish(res)

    def _finish(self, res: StepResult) -> StepResult:
        self.results.append(res)
        self.say(f"--- {res.label}: {res.status} ({res.seconds:.1f}s)")
        lines = [ln for ln in res.output.splitlines() if ln.strip()]
        shown = lines if self.verbose else lines[:SHOW_LINES]
        for ln in shown:
            self.say("    " + ln[:240])
        if len(shown) < len(lines):
            self.say(f"    ... {len(lines) - len(shown)} more line(s) (use -v to see them all)")
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
    if data.startswith((b"BZh", b"\xfd7zXZ\x00", b"7z\xbc\xaf\x27\x1c", b"Rar!\x1a\x07")) or data[257:263] in (b"ustar\x00", b"ustar "):
        return "archive-manual"
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


PY_NOTICE = (
    "!!! NOTICE: the next step RUNS this Python file (pyrun --run --auto-input, guarded, no --force).\n"
    "!!! Review the code first. Non-hostile CTF scripts only. The sandbox is NOT a security boundary.\n"
    "!!! Network is blocked; pyrun refuses scripts its scan flags (network, subprocess, obfuscation)."
)


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
    if kind not in run.kinds:
        run.kinds.append(kind)
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
        run.say(PY_NOTICE)
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
    elif kind == "archive-manual":
        run.note(f"archive extraction [{tag}]", "skipped: unsupported archive/compression",
                 "Automatic extraction supports ZIP/GZIP only. Extract this archive manually into a fresh folder, "
                 "inspect the members, then run go on a selected file or batch on that folder. Nothing was extracted here.")
    else:
        if size > DECODE_MAX_BYTES:
            run.note(f"decode -f [{tag}]", f"skipped: file over {DECODE_MAX_BYTES // 1024}KB")
        else:
            run.step("decode -f", "decode", ["-f", path], tag)
            decode_embedded(run, data.decode("utf-8", "replace"), tag)


EMBEDDED_TOKEN_LIMIT = 8
B64_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{12,4096}={0,2}(?![A-Za-z0-9+/=_-])")


def _looks_encoded(tok: str) -> bool:
    """Mechanical check only: long, mixed letters+digits or '='/'+'/'/' padding; used for a display-only hint."""
    return any(c.isdigit() for c in tok) and any(c.isalpha() for c in tok) or tok.endswith("=")


def decode_embedded(run: Runner, text: str, tag: str) -> None:
    """Try bounded embedded base64/hex-shaped tokens using the existing decoder.

    Whole-input decoding is already done. No token contents become a filename or
    an option: a leading '-' is explicitly separated from argparse options.
    """
    seen: set[str] = set()
    count = 0
    scan = text.encode("utf-8", "replace")[:DECODE_MAX_BYTES].decode("utf-8", "ignore")
    for match in B64_TOKEN_RE.finditer(scan):
        token = match.group(0)
        if match.end() == len(scan) and len(scan) < len(text) and text[len(scan)] in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-":
            continue  # the 200KiB boundary cut through a longer token
        if token in seen:
            continue
        seen.add(token)
        if token == text.strip():
            continue
        if count >= EMBEDDED_TOKEN_LIMIT:
            run.note(f"embedded tokens [{tag}]", "skipped: token limit reached; paste a remaining token alone")
            break
        count += 1
        run.step(f"decode embedded token {count}", "decode", ["--", token], tag)


def chain_text(run: Runner, text: str) -> None:
    """Decode whole text, bounded embedded blobs, then each literal flag-shaped token."""
    run.say("=== --text description")
    run.text_only = True
    run.add_text(text, "literal --text input")
    run.text_tokens = [t for t in dict.fromkeys(B64_TOKEN_RE.findall(text)) if _looks_encoded(t)][:3]
    run.step("decode (text)", "decode", ["--", text], "text")
    decode_embedded(run, text, "text")
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
    """Rank by evidence, independent of contest prefix; cipher guesses stay low."""
    scored = []
    for c in cands.values():
        score = 10
        if not c.speculative_only:
            score += 100
        source_bonus = 5 * (len(c.sources) - 1)
        # Corroborating guesses are still guesses, never the strong-evidence tier.
        score += min(20, source_bonus) if c.speculative_only else source_bonus
        body = c.text[c.text.index("{") + 1:-1]
        score += 3 if re.fullmatch(r"[A-Za-z0-9_!@#$%^&*.+=:-]+", body) else -3
        scored.append((score, c))
    scored.sort(key=lambda sc: (-sc[0], sc[1].order))
    return scored


NEXT_STEPS = {
    "java": "vaultdoor <file> (VaultDoor*.java checkers), decode, crypto",
    "asm": "asmeval <file> --func NAME --arg N (see its -h); numeric register values may need wrapping in the contest's flag format by hand",
    "py": "pyrun <file> (read-only scan, no --run), revauto <file>, decode",
    "elf": "autosolve <file> --deep (or autosolve -h), disasm entry <file>, revauto <file> --deep, binextras",
    "pcap": "forensics <file> --http, stego, decode",
    "blob": "stego <file> --lsb, forensics <file>, binextras",
    "archive": "binextras extract (look at every member), forensics, decode",
    "archive-manual": "unsupported archive/compression: extract manually into a fresh folder, inspect the members, then go <file> or batch <folder>; automatic extraction supports ZIP/GZIP only",
    "text": "decode -f <file>, crypto (classic ciphers), hashid id <hash>",
}


def _next_step_hint(run: Runner) -> list[str]:
    """Short, static hints naming existing modules for the input kinds seen. Display only."""
    lines = ["NEXT STEPS: no flag-shaped answer was found. That is not a failure of your setup; try one of:"]
    for k in run.kinds:
        if k in NEXT_STEPS:
            lines.append(f"  - {k}: {NEXT_STEPS[k]}")
    if run.text_only:
        lines.append("  - pasted text: the tool does NOT understand prose. Embedded-token scanning is bounded; copy ONLY that")
        lines.append('    token:  go --text "<token only>"   or   decode "<token>"')
        for t in run.text_tokens:
            lines.append(f"    possible encoded token: {t[:60]}{'...' if len(t) > 60 else ''}   (if missing from results, try this token alone)")
    lines.append("  - rerun go with -v (a go option, not for other modules) to see the step output that was cut off; read the whole log, not just this summary.")
    return lines


def report(run: Runner) -> int:
    """Print FLAG CANDIDATES, DERIVED INPUTS / REGISTER RESULTS, STEPS and a closing hint; return the exit code."""
    run.say("\n== FLAG CANDIDATES ==")
    ranked = rank(run.cands)
    if not ranked:
        if run.derived:
            run.say("(none flag-shaped) - BUT derived evidence WAS found: read the next section.")
        else:
            run.say("(none)")
    for i, (score, c) in enumerate(ranked, 1):
        run.say(f"{i:>2}. {c.text}   [score {score}]" +
                (" [speculative cipher guess]" if c.speculative_only else ""))
        for s in c.sources:
            run.say(f"      seen by: {s}")
    if run.derived:
        run.say("\n== DERIVED INPUTS / REGISTER RESULTS ==")
        run.say("(exact text quoted from the step output; these are NOT flags: verify them, e.g. type a derived input into the")
        run.say(" program, or wrap a register value in the contest's flag format by hand)")
        for i, d in enumerate(run.derived, 1):
            run.say(f"{i:>2}. {d.text}")
            run.say(f"      {d.kind} [{d.conf}] from {d.source}" + (f" ({d.note})" if d.note else ""))
    run.say("\n== STEPS ==")
    run.say("(ok = the tool ran, NOT that it solved anything; -v shows step output that was cut off)")
    for r in run.results:
        run.say(f"{r.status:<28} {r.label}")
    if not ranked:
        run.say("")
        if run.derived:
            run.say("NEXT: no flag-shaped token, but DERIVED INPUTS / REGISTER RESULTS above hold evidence. Use it; do not stop here.")
        else:
            for ln in _next_step_hint(run):
                run.say(ln)
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
    # --text owns the following argument even when it begins with '-'.
    # Preserve the usual missing-value error when no following argument exists.
    args = list(args)
    for i, arg in enumerate(args[:-1]):
        if arg in ("--text", "-t"):
            args[i:i + 2] = [arg + "=" + args[i + 1]]
            break
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

        # derived evidence stays visible in the final summary even when the step echo truncates it
        fake_auto = type("A", (), {"NAME": "autosolve", "run": staticmethod(lambda a: print(
            "\n".join(["autosolve: x"] + [f"NOISE   line {i}" for i in range(30)] +
                       ["HEADLINE   DERIVED [H]  s3cr3t_pw",
                        "SOLVE      s3cr3t_pw  [H]  method strcmp-literal  re-walk ok"])) or 0)})
        r = Runner({"autosolve": fake_auto}, 5, 30, False, out=lambda s: None)  # type: ignore[dict-item]
        r.step("autosolve", "autosolve", ["x"])
        lines: list[str] = []
        r.say = lines.append
        rc = report(r)
        text = "\n".join(lines)
        check(rc == 1 and "== DERIVED INPUTS / REGISTER RESULTS ==" in text and "s3cr3t_pw" in text and "[HIGH]" in text
              and "(none)" not in text.split("== DERIVED")[0] and "NEXT:" in text, "derived password in summary")
        a = extract_derived("asmeval", "check(0x5) -> eax = 0x2a  decimal 42\n", "asmeval")
        check(len(a) == 1 and "eax = 0x2a" in a[0].text and a[0].conf == "complete", "asmeval register result parsed")

        rc, _ = _go([])
        check(rc == 2, "no arguments -> usage exit 2")
        rc, _ = _go([os.path.join(tmp, "nope")])
        check(rc == 1, "missing path -> exit 1")
    return all(results)


if __name__ == "__main__":
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    sys.exit(run(sys.argv[1:]))
