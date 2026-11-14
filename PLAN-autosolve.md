# `autosolve` — Automatic Flag-Checker Solver (spec + acceptance criteria)

Planning artifact for issue #48. **No code in this PR.** A follow-up issue
implements `toolkit/modules/autosolve.py` against this document verbatim. Where
this spec and `PLAN.md` disagree, `PLAN.md`'s hard constraints and quality bar
win; everything else here is binding for `autosolve`.

> **Status: SPECCED (2026-11-14)** — not implemented.

Keywords: **MUST** = required for acceptance (selftest or review gate).
**SHOULD** = expected; omit only with a written reason in the PR body.
**MAY** = stretch, do it if time allows, never at the cost of a MUST.

**Final name: `autosolve`.** Short, says what it does, no collision with an
existing module or a Kali binary. Rejected: `crackme` (sounds like a
generator), `flagcheck` (sounds like a flag-format validator), `solve` (too
generic for the menu).

---

## 0. Contents

1. Purpose and framing
2. Non-negotiables (no execution, offline, resource caps, robustness)
3. File layout, imports, public API
4. Lane split — who does what
5. CLI
6. Data model + JSON schema
7. Built-in x86 decoder (`xdec`)
8. Stage 1 — verdict discovery (`find-verdicts`)
9. Stage 2 — function recovery, CFG, deciding branch (`trace`)
10. Stage 3 — constraint extraction: the path walker (`constraints`)
11. Stage 5a — solver + static re-walk verification (`solve`)
12. Stage 5b — patch planner (`patch`)
13. Stage 4 — annotated verdict-region listing (`listing`)
14. Stage 5c — next-step guidance
15. Lane 2 — angr (`angr`)
16. Report rendering
17. Selftest specification
18. Acceptance criteria (review checklist)
19. Limits and performance budgets
20. Out of scope / stretch
21. Suggested build order inside the implementation PR
22. Docs to update in the implementation PR
- Appendix A — angr helper template (`_ANGR_HELPER`)
- Appendix B — example compact reports (targets, not byte-exact)
- Appendix C — decoder corpus (selftest S2)

---

## 1. Purpose and framing

Owner's ask: automate the flag-checker walk an analyst currently does by hand —
*find "Correct!" / "Wrong." → find who prints them → find the branch that picks
one → read the compares feeding that branch → get the flag, or flip the branch.*

`autosolve` is a **junior analyst for one job**. Given an x86 / x86-64 ELF
flag checker it, in one non-interactive command:

1. locates the **verdict strings** (success / failure) and every code site that
   references them,
2. recovers the functions involved and traces **backward** from the success
   reference to the **deciding branch(es)** — the conditional jumps (or
   `setcc` / `cmovcc`) whose one edge leads to the success print and whose
   other edge leads to the failure print,
3. walks the code from the input read to the success print with a small,
   bounded **path walker** (concrete everywhere except the input bytes) and
   records every input-dependent condition as an ordered **constraint**
   (length checks, expected-byte compares, xor/add/sub/rol/imul chains,
   table lookups, `strcmp`/`memcmp` against literals),
4. prints an **annotated listing** of the verdict region,
5. ends with exactly one **headline outcome**, in this priority:
   - **(a) DERIVED ANSWER** — candidate input, confidence tag, derivation trace,
     and a static re-walk verification result;
   - **(b) EXACT PATCH TARGET** — address + file offset of each branch to force,
     original and patched bytes, and the ready-to-paste `elfpatch` command(s);
   - **(c) NEXT STEPS** — what is missing and the exact toolkit command or
     manual gdb move that comes next,
6. optionally (Lane 2) hands Lane 1's find/avoid addresses to **angr** when it
   is importable and prints the computed input.

Secondary sections are still printed (e.g. a derived answer also shows the
patch plan as "alternative"); only the headline picks one.

Wording rules for all generated text (same discipline as `revauto`):

- Mechanical labels only: "length check", "byte compare", "xor 0x42 then
  compare with table @0x402010" — never "obfuscated", "tricky", "anti-cheat",
  "the author wants". No intent calls.
- Every claim carries a confidence label: `[H]` deterministic (exact decode,
  fully-modelled path, verified by re-walk), `[M]` heuristic with corroboration
  (e.g. input region inferred from a function argument, ambiguous byte picked
  from several printable candidates), `[L]` single weak heuristic (unnamed call
  assumed to be `strlen`, verdict polarity from a weak word like "ok").
- When something could not be resolved statically, say exactly what and where
  ("gate @0x40119e depends on the result of unmodelled instruction `crc32` at
  0x401190") and what to do next (§14).

---

## 2. Non-negotiables

### 2.1 Never execute the target (MUST)

- The target binary is **never** executed, loaded with `ctypes`, `mmap`-ed
  executable, or passed to any process other than the angr helper (§15).
- The only child process `autosolve` may start is
  `[sys.executable, "-c", _ANGR_HELPER]` (§15.3), argv list, no shell, explicit
  `stdin`, explicit `timeout`. angr performs **symbolic emulation** inside that
  Python child (VEX lifting); it does not run the target natively. The helper
  MUST NOT use concrete-execution targets (`angr_targets`, avatar, gdb
  concrete), `Tracer`, or `proj.factory.call_state` against native code.
- No `os.system`, no `subprocess` with `shell=True`, no `eval` / `exec` /
  `compile` builtins anywhere in `autosolve.py` (`ast.parse` of its own
  source for the lint is fine).
- External tools (`objdump`, `r2`, `gdb`) are **printed suggestions only**,
  gated by `shutil.which` for the "on PATH" wording. `autosolve` never runs
  them. (`disasm ext` / `gdbkit run-gdb` exist for the user to run by hand.)
- The selftest proves this with an AST lint (§17, S1).

### 2.2 Offline (MUST)

No `socket` / `urllib` / `http.client` / `ftplib` / `smtplib` / `telnetlib` /
`requests` imports, under any flag. No runtime `pip install`. The angr
install hint is **text** (`pip install angr` — "needs network: prep before the
CTF"), never executed. The angr helper performs no network I/O (angr does not
need any for local analysis).

### 2.3 Resource caps (MUST) — module-level constants

| constant | value | meaning |
|---|---|---|
| `MAX_INPUT` | 64 MiB | bytes read from the target file (rest ignored, note emitted) |
| `MAX_FUNC_BYTES` | 64 KiB | max bytes decoded per recovered function |
| `MAX_FUNCS` | 64 | functions analysed per run (verdict functions + callees) |
| `MAX_CALL_DEPTH` | 3 | walker descent into internal callees |
| `MAX_STEPS` | 200 000 | instructions executed by the walker per run (all paths) |
| `MAX_PATHS` | 256 | forked walker paths per run |
| `MAX_LOOP_ITERS` | 4 096 | executions of one back-edge per path |
| `MAX_SYM_LEN` | 512 | symbolic input bytes tracked (`IN[0..511]`) |
| `MAX_SEARCH` | 1 000 000 | candidate evaluations in the multi-variable search (§11.3) |
| `MAX_VERDICT_STRINGS` | 64 | verdict strings kept per polarity |
| `MAX_LISTING` | 120 | lines in the compact verdict-region listing (`--deep`: 600) |
| `STATIC_BUDGET` | 15 s | wall clock for Lane 1 (checked between stages and every 4 096 walker steps) |
| `ANGR_TIMEOUT` | 60 s | default angr child wall time (`--angr-timeout`, clamp 5–1800) |

Hitting any cap produces a `note` ("walker step budget exhausted at
0x4011c2") and lowers confidence; it never raises.

### 2.4 Robustness (MUST)

Every stage runs inside `_stage(report, name, fn, *a)` which catches
`Exception` (incl. `RecursionError`, `MemoryError`, `struct.error`), appends
`"<stage>: <ExcType>: <msg>"` to `report.errors`, and continues with whatever
earlier stages produced. `analyze()` never raises for any `bytes` input (S14
fuzz). Errors print under `ERRORS` (compact: count + first 3).

### 2.5 Determinism (MUST)

Lane 1 results (verdicts, gates, constraints, candidate, patches) MUST be
identical with and without capstone. Capstone only changes the *text* of the
listing (§4). Selftest S13 forces `capstone = None` and compares.

---

## 3. File layout, imports, public API

### 3.1 Single file

`toolkit/modules/autosolve.py`, expected 1 800–2 600 lines. Sections in this
order with `# ---------- <title>` banners: constants → data model → `_stage` +
helpers → decoder (`xdec`) tables + `decode()` + formatter → ELF context
(sections, symbols, PLT, main) → stage 1 verdicts → stage 2 functions/CFG/trace
→ expression algebra → path walker → libcall models → solver + re-walk →
patch planner → listing → guidance → angr lane → rendering + JSON → CLI →
selftest fixtures (`_Asm`, builders) → selftest → `__main__`.

If the file passes ~2 600 lines the implementer MAY move the decoder tables
into `modules/autosolve_x86.py`. That file MUST NOT define `NAME` / `run` /
`selftest` (so `discover()` imports but does not register it) and MUST import
cleanly standalone.

### 3.2 Sibling imports (reuse, do not duplicate)

Dual-mode import, same as `revauto`:

```python
if __package__:
    from . import batch, disasm, elfpatch, gdbkit, pwnhelp, revauto
else:  # python3 modules/autosolve.py
    import batch, disasm, elfpatch, gdbkit, pwnhelp, revauto  # type: ignore[no-redef]
```

| need | reuse (do not re-implement) |
|---|---|
| ELF header, section map, `vaddr↔offset`, named section | `disasm.parse_elf`, `disasm.vaddr_to_offset`, `disasm.offset_to_vaddr`, `disasm.get_section`, `disasm.ElfError` |
| optional capstone handle, hex fallback, no-capstone notice | `disasm.capstone`, `disasm.hexdump`, `disasm.NO_CAPSTONE_MSG` |
| RIP-relative LEA string-ref byte scan (fallback / cross-check) | `disasm.find_xrefs` |
| objdump / r2 suggestion strings | `disasm.external_shortcuts` |
| test ELF skeleton reference | `disasm.build_test_elf` (layout pattern; fixtures here extend it) |
| syscall numbers (x86-64) | `disasm.SYSCALLS` |
| symbols with type/size/shndx | `revauto.elf_symbols` (public API) |
| import name → GOT slot | `pwnhelp.got_plt` |
| full section headers (flags/link/entsize) | `revauto._elf_sections_full` is private → autosolve reads flags itself from `disasm.parse_elf` output + a 10-line shdr flag reader (do **not** import private names) |
| crypto-constant table scan (hash-based checker detection) | `revauto.scan_crypto_constants` (public API) |
| flag regex | `batch.FLAG_RE` (bytes) and its text twin, as in revauto |
| byte patch math, jcc flip, safe output writing | `elfpatch.patch_bytes`, `elfpatch.flip_jcc`, `elfpatch.write_output`, `elfpatch.PatchError` |
| recipe lookup for printed gdb hints | `gdbkit.search_recipes` (selftest S12 asserts every referenced keyword hits) |

`autosolve` owns: the x86 decoder, verdict classification, function/CFG
recovery for the analysed functions, the expression algebra, the path walker,
libcall models, the solver, the patch planner, the listing, guidance, and the
angr helper. It MUST NOT import any `_private` name from a sibling.

### 3.3 Public API (names are binding)

```python
NAME = "autosolve"
DESCRIPTION = ("Flag-checker auto-solver: verdict strings -> deciding branch -> constraints -> "
               "derived flag / exact patch / next step; optional angr lane")

@dataclass
class Options:
    success_re: list[re.Pattern] = field(default_factory=list)   # added to SUCCESS_PATTERNS
    fail_re: list[re.Pattern] = field(default_factory=list)      # added to FAIL_PATTERNS
    flag_re: re.Pattern | None = None     # from --flag-format; used IN ADDITION to batch.FLAG_RE
    func: int | None = None               # --func ADDR: restrict analysis to this function
    deep: bool = False
    as_json: bool = False
    angr: str = "auto"                    # auto | off | only
    angr_timeout: int = ANGR_TIMEOUT
    max_steps: int = MAX_STEPS
    input_mode: str = "auto"              # auto | stdin | argv  (forces §10.4 / §15)

def decode(code: bytes, off: int, addr: int, bits: int) -> "Insn | None": ...
def find_verdicts(ctx: "BinCtx", opts: Options) -> list["Verdict"]: ...
def trace(ctx: "BinCtx", verdicts: list["Verdict"], opts: Options) -> "Trace": ...
def extract_constraints(ctx: "BinCtx", tr: "Trace", opts: Options) -> "WalkResult": ...
def solve(ctx: "BinCtx", wr: "WalkResult", opts: Options) -> "Solution": ...
def plan_patches(ctx: "BinCtx", tr: "Trace", wr: "WalkResult") -> list["Patch"]: ...
def render_listing(ctx: "BinCtx", tr: "Trace", wr: "WalkResult", deep: bool = False) -> list[str]: ...
def angr_available(find_spec: Callable[[str], Any] | None = None) -> bool: ...
def run_angr(ctx: "BinCtx", tr: "Trace", wr: "WalkResult", opts: Options,
             runner: Callable[..., Any] | None = None) -> "AngrResult": ...
def load(data: bytes, name: str = "<input>") -> "BinCtx": ...
def analyze(data: bytes, name: str = "<input>", opts: Options | None = None,
            stages: str = "all") -> "Report": ...     # stages: verdicts|trace|constraints|solve|patch|listing|all
def render_text(report: "Report", deep: bool = False) -> str: ...
def report_to_dict(report: "Report") -> dict: ...
def run(args: list[str]) -> int: ...
def selftest() -> bool: ...
```

Module-level hooks for testability (selftest swaps them, the CLI uses them):
`_FIND_SPEC = importlib.util.find_spec`, `_WHICH = shutil.which`,
`_ANGR_RUNNER = _run_angr_child`, `_CS = disasm.capstone`.

`analyze()` never runs Lane 2; the CLI (`run`) calls `run_angr` after the
static report is printed (§15.2), so the static lane can never be blocked by
angr.

---

## 4. Lane split — who does what

| capability | Lane 1 built-in (stdlib) | capstone present | Lane 2 angr present |
|---|---|---|---|
| ELF parse, sections, symbols, PLT names | **yes** (disasm / revauto / pwnhelp) | – | – |
| verdict strings + classification | **yes** | – | – |
| verdict reference sites (x64 RIP-rel, abs imm32, push imm32, i386 GOT-relative, pointer tables) | **yes** (built-in decoder, plus `disasm.find_xrefs` byte scan as a cross-check) | – | – |
| instruction lengths, CFG, function bounds | **yes** (`xdec` full length decoder) | cross-check lengths in `--deep`; mismatch → note | – |
| deciding branch / gates | **yes** | – | – |
| constraint extraction (path walker) | **yes** (semantic subset §7.3) | – | – |
| solving + static re-walk verification | **yes** | – | – |
| patch bytes + elfpatch commands | **yes** | – | – |
| listing text | built-in Intel-syntax formatter for the semantic subset; `db ..` + "unmodelled" for the rest | **capstone mnemonics for every line** (upgrade) | – |
| inputs needing path explosion / unmodelled instructions / hashes | guidance (§14) | – | **symbolic search**, find/avoid from Lane 1 |

Rationale: the analysis must give the same answer on a bare Kali Python and a
fully-loaded one, so semantics live in one place (the built-in decoder).
Capstone is a pure presentation upgrade; it MUST NOT be consulted for any
decision.

---

## 5. CLI

Exact usage text (printed for bare / `-h` / `--help`, exit 0):

```
autosolve usage:
  recon.py autosolve <elf> [options]                full chain: verdicts -> trace -> constraints
                                                     -> listing -> solve -> patch -> angr
  recon.py autosolve find-verdicts <elf> [options]  stage 1: verdict strings + reference sites
  recon.py autosolve trace <elf> [options]          stages 1-2: deciding branch(es) / gates
  recon.py autosolve constraints <elf> [options]    stages 1-3: ordered constraints
  recon.py autosolve listing <elf> [options]        stages 1-3 + annotated verdict region
  recon.py autosolve solve <elf> [options]          stages 1-3 + derived answer
  recon.py autosolve patch <elf> [-o OUT] [options] stages 1-3 + patch plan (writes OUT only with -o)
  recon.py autosolve angr <elf> [options]           stages 1-3 (for find/avoid) + Lane 2 only
  recon.py autosolve selftest                       run self-tests (--selftest also accepted)

options:
  --success REGEX      extra success-verdict pattern (repeatable, case-insensitive)
  --fail REGEX         extra failure-verdict pattern (repeatable, case-insensitive)
  --flag-format REGEX  extra flag regex, e.g. 'CyberSci\{[^}]+\}' (anchors ambiguous bytes)
  --func ADDR          analyse only the function containing ADDR (hex or decimal)
  --input stdin|argv   force the input model (default: auto-detect)
  --json               machine-readable report (schema autosolve/1)
  --deep               full listing, all gates, all paths, capstone length cross-check
  --no-angr            skip Lane 2 even if angr is installed
  --angr-timeout SECS  angr wall time (default 60, 5..1800)
  --max-steps N        walker step budget (default 200000)

examples:
  recon.py autosolve ./crackme
  recon.py autosolve ./crackme --success 'Access granted' --fail 'denied'
  recon.py autosolve patch ./crackme -o crackme.patched
```

Parsing: `argparse` with a custom parser class that raises a usage exception
instead of exiting (same as revauto's `_Parser`). Unknown option, bad regex,
bad `--func` / `--angr-timeout` / `--max-steps` value, missing `<elf>` → usage
to stderr, exit **2**. Subcommand names are recognised only as the first
argument; a file literally named `trace` is reached as `./trace`.

Exit codes:

| code | when |
|---|---|
| 0 | report produced — any outcome (derived / patch / guidance), including "no verdict strings" and non-x86 ELF (strings-only report), and angr absent/timeout in the **full chain** |
| 1 | file missing / unreadable / empty; not an ELF; `patch -o OUT` failed (OUT exists and equals input, unwritable, `PatchError`) — report still printed first; `angr` **subcommand** when angr is absent (prints the same one skip line) |
| 2 | usage error |

Menu friendliness: works unchanged through `recon.py`'s `name args>` prompt,
no prompts inside the module, no ANSI colour, every compact-mode line ≤ 100
columns (truncate with `…`).

`patch -o OUT`: applies the **primary** patch plan (§12.4) in memory with
`elfpatch.patch_bytes`, writes with `elfpatch.write_output(src, OUT, data,
force=False)` (so in-place is refused), prints `wrote OUT (N patches)` and a
re-walk check of the patched bytes (§12.5). Without `-o` nothing is written.

---

## 6. Data model + JSON schema

### 6.1 Dataclasses (all `@dataclass`, all fields typed)

```python
@dataclass
class Op:                       # one operand
    kind: str                   # "reg" | "imm" | "mem" | "rel"
    size: int                   # bytes: 1/2/4/8 (16 for xmm when known)
    reg: str | None = None      # canonical 64-bit family name for GPRs ("rax"), "xmm0", ...
    sub: str | None = None      # actual sub-register spelled ("al", "eax", "ah")
    imm: int | None = None      # sign-extended per Intel rules, then masked to `size`
    base: str | None = None     # "rbp" | "rip" | ... (mem)
    index: str | None = None
    scale: int = 1
    disp: int = 0
    seg: str | None = None      # "fs" | "gs" | ...
    target: int | None = None   # rel: absolute branch target; mem rip: absolute address

@dataclass
class Insn:
    addr: int
    size: int
    raw: bytes
    mnem: str                   # "mov", "cmp", "jcc", "setcc", "cmovcc", "other", ...
    cc: str | None              # "e","ne","l","ge","le","g","b","ae","be","a","s","ns","o","no","p","np"
    ops: tuple[Op, ...]
    flow: str                   # "seq" | "jcc" | "jmp" | "call" | "ret" | "jmp-ind" | "call-ind" | "stop"
    modelled: bool              # True when the walker has semantics for it (§7.3)

@dataclass
class VerdictRef:
    site: int                   # vaddr of the referencing instruction
    via: str                    # "rip-rel" | "abs-imm32" | "push-imm32" | "esp-store" | "got-rel" | "ptr-table" | "byte-scan"
    func: int | None            # recovered function start containing site
    printer: str | None         # "puts" / "printf" / "write" / sub_XXXX / None (call within 8 insns)
    conf: str                   # "high" | "medium" | "low"

@dataclass
class Verdict:
    addr: int                   # string vaddr
    text: str
    polarity: str               # "success" | "failure"
    matched: str                # pattern that matched
    conf: str
    refs: list[VerdictRef] = field(default_factory=list)
    stack_built: bool = False   # SHOULD §8.5

@dataclass
class Gate:
    n: int                      # 1-based, in path order
    addr: int                   # jcc / setcc / cmovcc address
    kind: str                   # "jcc" | "setcc" | "cmovcc" | "call-ret" (delegated to callee)
    cc: str
    cmp_addr: int | None        # flag-setting instruction feeding it
    func: int
    success_edge: str           # "taken" | "fallthrough" | "true" | "false"
    success_to: int | None
    fail_to: int | None
    in_loop: bool
    hits: int                   # times the walker crossed it on the solution path
    deciding: bool              # True for the last gate before the success print (the one stage 2 names)
    label: str                  # mechanical: "length check", "byte compare", "strcmp result", ...
    conf: str

@dataclass
class Constraint:
    n: int                      # order of appearance on the solution path
    kind: str                   # "length" | "byte-eq" | "byte-rel" | "multi" | "str-eq" | "mem-eq" | "unresolved"
    text: str                   # "IN[3] rol 3 == 0xdb"
    site: int                   # gate address
    conf: str
    positions: tuple[int, ...]  # input indexes involved
    expr: Any = None            # internal expression tree (not serialised)

@dataclass
class Solution:
    candidate: bytes | None
    text: str | None            # printable rendering, unknown bytes as '?'
    conf: str                   # "high" | "medium" | "low"
    method: str                 # "byte-domain" | "strcmp-literal" | "memcmp-literal" | "search" | "rodata-flag"
    unknown: list[int]          # positions left undetermined
    ambiguous: list[int]        # positions with >1 printable value (lowest-ranked pick shown)
    verified: str               # "re-walk ok" | "re-walk failed at 0x..." | "not run"
    trace: list[str]            # derivation lines, one per constraint group
    flag_match: bool

@dataclass
class Patch:
    site: int
    offset: int
    old: bytes
    new: bytes
    strategy: str               # "nop-jcc" | "force-jmp" | "cmov-to-mov" | "setcc-to-mov1" | "ret-true" | "flip"
    desc: str
    elfpatch: str               # ready-to-paste command line
    primary: bool               # part of the primary plan (§12.4)
    conf: str

@dataclass
class AngrResult:
    status: str                 # "absent" | "skipped" | "ok" | "no-solution" | "timeout" | "error"
    input: bytes | None
    detail: str
    seconds: float
    agrees: bool | None         # vs Lane 1 candidate (None when either missing)

@dataclass
class Report:
    target: dict                # name, size, sha256, format, arch, bits, pie, stripped, static
    verdicts: list[Verdict]
    gates: list[Gate]
    constraints: list[Constraint]
    solution: Solution | None
    patches: list[Patch]
    listing: list[str]
    input_model: dict           # {"mode": "stdin"|"argv"|"arg0"|"unknown", "via": "fgets@0x...", "conf": ...}
    outcome: str                # "derived" | "patch" | "guidance"
    next_steps: list[str]
    angr: AngrResult | None
    notes: list[str]
    errors: list[str]
```

`BinCtx` (internal, public type name, not serialised) holds `data`, `elf`
(`disasm.parse_elf`), `bits`, `pie`, section flags, `syms` (addr→name), `plt`
(stub vaddr→import name), `got` (slot→name), `main`, `funcs` (start→`Func`),
and decode caches. `Trace` holds the analysed functions, CFGs, reachability
sets, gates and the walker entry choice. `WalkResult` holds the solution path
(list of `(addr, note)`), constraints, input model, unresolved reasons, and
stats (`steps`, `paths`, `pruned`).

### 6.2 JSON (`--json`, `report_to_dict`)

`{"schema": "autosolve/1", ...}` with every dataclass converted by a
`_jsafe` walker: `bytes` → `{"hex": ..., "text": <latin-1 printable or null>}`,
ints that are addresses stay ints (no hex strings), `expr` dropped, sets →
sorted lists. Top-level keys exactly: `schema, target, outcome, verdicts,
gates, constraints, solution, patches, listing, input_model, next_steps, angr,
notes, errors`. In JSON mode angr runs before printing (single document) but
still under its own timeout.

---

## 7. Built-in x86 decoder (`xdec`)

Two layers: a **complete length decoder** (so CFG recovery never desyncs on
SSE/AVX/x87 code that gcc emits around the interesting code) and a
**semantic decoder** for the subset the walker models.

### 7.1 Length decoder (MUST cover all of this)

`decode(code, off, addr, bits)` reads at most 15 bytes and returns `Insn` or
`None` (invalid / truncated).

- **Prefixes** (any order, max 14): `F0 F2 F3 2E 36 3E 26 64 65 66 67`. `66`
  sets operand size 16 for `z`-sized immediates; `67` sets address size
  (32 in x64, 16 in x86 → 16-bit ModRM table, MAY treat as invalid in x86).
- **REX** `40–4F` in 64-bit mode only, and only immediately before the
  opcode (a REX followed by a legacy prefix is dropped, per SDM). `REX.W`
  widens operand size; `REX.W` + `B8+r` → `imm64` (movabs, 10 bytes).
- **Maps**: one-byte; `0F` two-byte; `0F 38` (ModRM, no imm); `0F 3A`
  (ModRM + imm8).
- **VEX** `C5` (2-byte) / `C4` (3-byte): always in 64-bit mode; in 32-bit mode
  only when the next byte has `mod == 11` (else `LDS`/`LES`). Map from
  `C4`'s `mmmmm` (1 = 0F, 2 = 0F38, 3 = 0F3A); ModRM always; imm8 for map 3.
- **EVEX** `62` (64-bit; 32-bit when next byte `mod == 11`): 4-byte prefix,
  then map per `mm`, ModRM, imm8 for map 3. Disp8 is *not* scaled for length
  purposes (length only). SHOULD.
- **ModRM / SIB / disp**: standard 32/64-bit table (`mod 00 rm 101` → disp32,
  RIP-relative in x64; `rm 100` → SIB; SIB `base 101` with `mod 00` → disp32).
- **Immediates** — one-byte map table of imm kinds `{0, b, w, z, v(B8–BF with
  REX.W), iw+ib (C8), moffs (A0–A3: 8 bytes in x64 with 67 → 4; 4 in x86)}`.
  Group exceptions: `F6 /0,/1` → imm8, `F7 /0,/1` → imm z; other `/r` none.
  `0F` map: `0F 70–73`, `0F A4`, `0F AC`, `0F BA`, `0F C2`, `0F C4–C6` → imm8;
  `0F 80–8F` → rel32; `0F 0F` (3DNow) → ModRM + imm8 (MAY).
- **x87** `D8–DF`: ModRM, no imm.
- **Invalid in 64-bit** → `None`: `06 07 0E 16 17 1E 1F 27 2F 37 3F 60 61 82
  9A CE D4 D5 D6 EA` (and `C4/C5/62` are VEX/EVEX there).
- `0F 05` syscall, `0F 0B` ud2 (`flow="stop"`), `0F 1E FA` with `F3` → endbr64
  (`mnem="endbr64"`), `0F 1F /0` → multi-byte nop.

Selftest S2 runs the Appendix C corpus (≥ 60 entries, both modes) and asserts
exact lengths; with capstone present it additionally decodes `.text` of every
fixture with both and asserts equal lengths (no assertion when absent).

### 7.2 Desync handling (MUST)

Function decoding is **recursive descent** from the function start (§9.2),
not linear sweep, so inline data after `ret`/`jmp` is skipped. If `decode()`
returns `None` mid-block the block ends with `flow="stop"`, a note
`decode failed at 0x...` is recorded, and any path reaching it is
`unresolved` for the walker.

### 7.3 Semantic subset (MUST — `modelled=True`)

Operand decoding (registers per size/REX incl. `spl/bpl/sil/dil` vs
`ah/ch/dh/bh`, memory operands with base/index/scale/disp/segment, RIP target
computed) for:

| group | encodings |
|---|---|
| moves | `88 89 8A 8B` mov; `C6 /0` `C7 /0` mov imm; `B0–B7` `B8–BF` (incl. imm64); `0F B6 B7` movzx; `0F BE BF` movsx; `63` movsxd (x64); `8D` lea; `98` cbw/cwde/cdqe; `99` cwd/cdq/cqo; `86 87` xchg; `A0–A3` moffs mov; `90` nop |
| ALU | `00–05, 08–0D, 10–15, 18–1D, 20–25, 28–2D, 30–35, 38–3D` (add/or/adc/sbb/and/sub/xor/cmp, all r/m, reg, AL/eAX-imm forms); `80 81 83 /0–/7`; `84 85 A8 A9 F6/0 F7/0` test |
| unary | `FE FF /0 /1` inc/dec; `F6 F7 /2 /3` not/neg; `40–4F` inc/dec in x86 only |
| mul | `0F AF` imul r,r/m; `69` `6B` imul r,r/m,imm; `F6 F7 /4 /5` mul/imul (rdx:rax, low part tracked) |
| shifts | `C0 C1 D0 D1 D2 D3 /0–/5, /7` rol/ror/rcl(→unknown)/rcr(→unknown)/shl/shr/sar (count imm, 1, or `cl`) |
| flags users | `70–7F`, `0F 80–8F` jcc; `0F 90–9F` setcc; `0F 40–4F` cmovcc |
| flow | `E8` call; `E9 EB` jmp; `FF /2` `FF /4` indirect call/jmp; `C3 C2` ret; `C9` leave; `CC` int3 (stop); `F4` hlt (stop) |
| stack | `50–57` push, `58–5F` pop (+REX.B); `6A 68` push imm; `FF /6` push r/m; `8F /0` pop r/m; `C8` enter (frame only) |
| misc | `0F 05` syscall, `CD 80` int 0x80 (§10.6); `F3 0F 1E FA/FB` endbr; `0F 1F` nop; `64/65` segment loads of the canary slot (`fs:0x28`, `gs:0x14`) → opaque `CANARY` value; `F3 AA/AB` / `F3 48 AB` rep stos (zero-fill of locals: `rcx` concrete → write; else invalidate) |

Everything else decodes with `mnem="other", modelled=False`. Walker effect of
an unmodelled instruction (§10.3): GPR destinations named by ModRM (`reg`
field for loads, `rm` when `mod == 11`) become `UNK`, a memory destination
invalidates tracked bytes in `[addr, addr + 16)`, flags become `UNK`. SSE /
AVX instructions only clobber xmm/ymm (not tracked) unless they store to
memory or write a GPR (`pmovmskb`, `movd r32, xmm`, `pextr*`, `cvt*` → GPR
`UNK`).

### 7.4 Formatter

`fmt(insn) -> str` produces Intel syntax for modelled instructions
(`mov eax, dword [rbp-0x54]`, `jne 0x4011a8`, `lea rdi, [rip+0xe5e]  ; 0x402004`)
and `db f2 0f 38 f0 07  ; unmodelled` for the rest. When `_CS` is not `None`
the listing uses capstone text instead for every line (same addresses — the
built-in lengths drive the iteration; capstone is invoked per instruction on
exactly `insn.raw`).

---

## 8. Stage 1 — verdict discovery (`find-verdicts`)

### 8.1 Candidate strings

Scan every **non-executable, allocated, file-backed** section (`.rodata`,
`.data`, `.data.rel.ro`, any custom one) for NUL-terminated runs of
printable ASCII (`\x20–\x7e\t\n\r`), length ≥ 2 (verdicts are often short:
"OK", ":)"). Record `(vaddr, text)` with **start vaddr** (the reference target).
Also record every *suffix start* that is itself referenced (gcc tail-merges
`"Wrong!"` into `"Try again. Wrong!"`) — handled lazily: a reference into the
middle of a string yields the suffix.

### 8.2 Classification (MUST)

Patterns are case-insensitive, compiled at module level. **Failure is checked
first**; a string matching both is `failure` (so `"Incorrect"`, `"not
correct"`, `"Invalid"` never become success).

```python
FAIL_PATTERNS = [r"\bwrong\b", r"\bincorrect\b", r"\bnot (?:the )?(?:right|correct|flag)\b",
                 r"\bnope\b", r"\btry again\b", r"\bfail(?:ed|ure)?\b", r"\binvalid\b",
                 r"\bdenied\b", r"\bbad\b", r"\bsorry\b", r"\bno+[.!]*$", r"\brejected\b",
                 r"\bunauthori[sz]ed\b", r"\bnot quite\b", r":\(", r"\blength\b.*\b(?:wrong|bad|invalid)\b"]
SUCCESS_PATTERNS = [r"\bcorrect\b", r"\bcongrat", r"\bsuccess", r"\bwell done\b", r"\bgood job\b",
                    r"\byou (?:win|won|got it|did it)\b", r"\baccess granted\b", r"\bgranted\b",
                    r"\bflag is\b", r"\bhere(?:'s| is) (?:your|the) flag\b", r"\bvalid\b",
                    r"\bright\b", r"\bnice\b", r"\baccepted\b", r"\bunlocked\b", r":\)", r"\bok\b"]
```

User patterns from `--success` / `--fail` are checked **before** the built-ins
(user intent wins) and tagged `[H]`. Built-in matches are `[H]` for the first
ten success / first twelve failure patterns, `[L]` for the weak tail (`valid`,
`right`, `nice`, `ok`, `:)`, `bad`, `no`).

Strings matching `batch.FLAG_RE` or `--flag-format` (e.g. a plaintext
`flag{...}` in `.rodata`) are not verdicts; they are carried to stage 5 as a
`rodata-flag` candidate (`[M]`: present, not proven to be the answer).

Format-string verdicts (`"Correct! The flag is %s"`) are kept; the `%s`
argument is noted ("success print formats a second argument — may print the
flag").

### 8.3 Reference sites (MUST)

For every executable section, decode functions lazily, but first run a
**byte-level pre-scan** to find candidate sites cheaply (regex over section
bytes), then confirm each with `decode()` at the site:

| arch | form | encodings to pre-scan |
|---|---|---|
| x64 | any ModRM `mod 00 rm 101` RIP-relative operand landing on a verdict string (lea most common, also `mov r, [rip]` loads of `char*` globals) | `[\x40-\x4f]?\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]` (+ confirm other opcodes via decode of the containing function) |
| x64 non-PIE | `mov r32, imm32` / `mov r/m64, imm32` with the absolute string address (`-no-pie` gcc: `mov edi, 0x402004`) | `[\xb8-\xbf]....`, `\x48\xc7[\xc0-\xc7]....`, `\x41[\xb8-\xbf]....` |
| x86 | `push imm32` | `\x68....` |
| x86 | `mov dword [esp+d], imm32` | `\xc7\x04\x24....`, `\xc7\x44\x24.....` |
| x86 | `mov r32, imm32` | `[\xb8-\xbf]....` |
| x86 PIE (SHOULD) | `lea r32, [ebx+disp32]` / `[eax+disp]` after `call __x86.get_pc_thunk.bx` + `add ebx, imm32` (ebx = `.got.plt` vaddr) | decode-time: track the thunk pattern per function |
| both | pointer tables (SHOULD): an aligned 4/8-byte word in a data section equal to a verdict string vaddr → the table slot becomes the target, and refs to the slot are refs to the verdict (`via="ptr-table"`, `[M]`) | aligned scan of `.data`/`.data.rel.ro` |

`disasm.find_xrefs(data, elf)["strings"]` is merged in (`via="byte-scan"`,
`[M]`) for any site the decoder-confirmed scan did not produce.

Each ref gets `func` (§9.1) and `printer`: the first `call` within the next 8
decoded instructions in the same block, named via PLT/symbols (`puts`,
`printf`, `__printf_chk`, `fputs`, `write`, `std::operator<<` mangled
`_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc`) or `sub_XXXX`.
A ref without a call within 8 instructions → `printer=None`, conf one step down.

### 8.4 Verdict selection

- Keep at most `MAX_VERDICT_STRINGS` per polarity, ordered by (has refs,
  confidence, pattern rank).
- **Pairing**: a success verdict and a failure verdict whose refs share a
  function (or caller/callee pair) form a *verdict pair*; stage 2 runs on each
  pair, best pair first (both refs `[H]`, same function).
- If only success **or** only failure strings exist, stage 2 still runs with
  the missing side defined as "any path that does not reach the present
  side and reaches a `ret` from `main` / `exit` call" (`[L]` note).
- No verdicts at all → outcome guidance (§14) — exit 0.

### 8.5 Stack-built verdicts (SHOULD)

Detect runs of `mov dword/qword [rbp±d], imm` (`C7 45 ..`, `48 B8 imm64` +
`48 89 45 ..`) that assemble ≥ 4 printable bytes contiguously in a frame; the
reconstructed text is classified like §8.2 (`stack_built=True`, `[M]`), the
ref site is the first store.

---

## 9. Stage 2 — function recovery, CFG, deciding branch (`trace`)

### 9.1 Function starts and `main`

Candidates, in priority: `.symtab`/`.dynsym` `FUNC` symbols (via
`revauto.elf_symbols`) → `main` from `_start` (pattern: the last `lea rdi,
[rip+X]` / `mov rdi, imm32` / `mov edi, imm32` (x64) or `push imm32` (x86)
before the `call` to `__libc_start_main` — by PLT name, or `call [rip+X]`
where X is its GOT slot) → `E8` call targets in executable sections →
`endbr64` at 16-byte alignment → `push rbp; mov rbp, rsp` / `push ebp; mov
ebp, esp`. A site's function is the greatest candidate start ≤ site whose
recursive-descent CFG actually contains the site; if none contains it, the
function is "decoded backward" by trying starts from the nearest candidate
(note `[L]`).

### 9.2 CFG

Recursive descent per function: blocks split at jcc / jmp / ret / call to a
**noreturn** target (`exit`, `_exit`, `abort`, `__stack_chk_fail`,
`__assert_fail`, `err`, `errx`, `exit_group`/`exit` syscalls) and at every
branch target. Indirect jumps (`FF /4`) end the block (`jmp-ind`); jump tables
are MAY. Block successors: `(fallthrough, taken)` for jcc. `MAX_FUNC_BYTES`
bounds decoding.

Libcall naming: PLT stubs resolved like revauto does (scan `.plt`, `.plt.sec`,
`.plt.got` for `FF 25 disp32` (x64) / `FF A3 disp32` + `FF 25 abs32` (x86),
map the GOT slot through `pwnhelp.got_plt`) plus `FUNC` symbols for static
non-stripped binaries. Unknown targets in executable sections are internal
functions (`sub_XXXX`).

### 9.3 Verdict blocks and reachability

- `S` = blocks containing a success ref site; `F` = blocks containing a
  failure ref site. A block that *calls* a function whose CFG contains `S`
  (resp. `F`) sites is also in `S` (resp. `F`) — computed bottom-up over the
  analysed call graph (depth `MAX_CALL_DEPTH`).
- `R_S` = blocks from which some `S` block is reachable **without passing
  through an `F` block**; `R_F` symmetric. Reverse BFS over the CFG.

### 9.4 Gates and the deciding branch (MUST)

A conditional block-ender `b` with successors `(t, f)` is a **gate** when
exactly one successor is on the success side:

- success side: successor ∈ `R_S`;
- fail side: successor ∉ `R_S`; or, when both successors ∈ `R_S`, the one
  that is also ∈ `R_F` and whose shortest path reaches `F` before `S`
  (tie-break, gate tagged `[M]`).

Branches where both successors are equivalent (neither in `R_F`) are not
gates.

The **deciding branch** is the gate that is the immediate *dominator-chain*
predecessor of the success ref site: walk predecessors backward from the `S`
block along the unique-predecessor chain; the first conditional edge met that
is a gate is `deciding=True`. When the chain merges (several predecessors),
choose the gate whose success successor dominates `S` (simple iterative
dominator computation over the function CFG — Cooper/Harvey/Kennedy is fine).

**setcc / cmovcc gates (MUST):** when the condition is materialised —
`sete al; movzx eax, al; ret` inside a callee, or `cmovne rdi, rax` choosing
between two verdict string pointers before one `call puts` — the `setcc` /
`cmovcc` is the gate (`kind="setcc"`/`"cmovcc"`). For the cmov case, `S` and
`F` refs are both in the same block; the gate is the `cmovcc` whose two source
operands carry the two verdict addresses (found by local constant propagation
within the block).

**Delegated decisions (MUST):** when the deciding branch tests a call's
return value (`call X; test eax, eax; je F` or `cmp eax, 1`), the gate is
recorded in the caller (`kind="jcc"`, `label="return value of check@0x..."`)
**and** stage 2 descends into `X`: there, "success" = blocks ending in `ret`
whose returned `eax` makes the caller's gate take the success edge, computed
by block-local constant propagation of `eax` (`xor eax,eax` → 0, `mov eax,1`
→ 1, `setcc al` → the setcc itself is a gate). Gates inside `X` are added with
`func=X`. Depth ≤ `MAX_CALL_DEPTH`.

Gate labels (mechanical, from the flag-setting instruction feeding it, found
by scanning back ≤ 8 instructions in the block for the last flag writer):
`length check` (compares a value derived from `strlen`/`strcspn`/`read`
return), `byte compare` (8-bit operand involving input), `table compare`,
`strcmp result`, `memcmp result`, `return value of <fn>`, `loop bound`
(concrete; not a gate — listed only with `--deep`), `unknown condition`.

Stage-2 output alone (subcommand `trace`) is useful without stage 3: deciding
branch address, its condition, success/fail edges, and the patch target
preview.

---

## 10. Stage 3 — constraint extraction: the path walker (`constraints`)

A tiny, bounded, directed symbolic walker: **everything is concrete except
the input bytes, the input length, and explicitly-unknown values.** It
"executes" decoded instructions over an abstract state — it never runs code.

### 10.1 Expression algebra

Immutable tuples, hash-consed in a dict to keep memory bounded:

```
("c", v, w)                 constant v, width w bits (8/16/32/64)
("in", k)                   input byte k (8-bit), 0 <= k < MAX_SYM_LEN
("len",)                    input length (64-bit)
("op", name, w, a, b)       name in add sub xor and or shl shr sar rol ror mul
("un", name, w, a)          name in not neg zx sx trunc bool
("cc", cc, w, a, b)         boolean result of flags(a ? b) under condition cc (from cmp/sub/test)
("ptr", region, off)        pointer: region in {"stack","input","argv","arg0..5","heap<n>","image"}, off an expr
("scmp", s, n)              opaque strcmp/strncmp/memcmp result against literal bytes s (n = None for strcmp)
("unk", why)                unknown; why is a short reason string ("call sub_401500", "crc32 @0x401190")
```

`simplify()` folds constants, masks to width, cancels `x ^ c ^ c`, merges
`add` chains, and pushes `trunc` through `zx` — enough that
`(zx8→32(IN[3]) ^ 0x42) & 0xff` prints as `IN[3] ^ 0x42`. Any op on an
`unk` yields `unk` (first reason kept). `free(e)` returns the set of
`in`/`len` leaves.

### 10.2 State

- registers: 16 GPRs (8 in x86) as width-64 expressions; sub-register reads
  / writes follow x86 rules (32-bit writes zero-extend in x64, 8/16-bit
  writes merge).
- flags: the last flag-setting operation recorded as `(op, a, b, w)` (`cmp`,
  `sub`, `test`, `and`, `xor`, `add`, `inc`, `dec` …); `jcc`/`setcc`/`cmovcc`
  build `("cc", cc, w, a, b)` from it — no bit-level flag modelling.
- memory: a dict `(region, concrete_off) -> byte expr`, little-endian
  multi-byte reads/writes split per byte. Region `image` reads come from the
  file bytes (`.rodata`, `.data`, `.bss` = zero); writes to `image` are
  tracked per run. A load/store with a **symbolic** offset returns/stores
  `unk` (except the newline-strip idioms in §10.5).
- `rsp`/`esp` starts as `("ptr","stack",0)`; `rbp` likewise after the
  prologue. Return addresses are pushed as opaque markers.
- path condition: ordered list of `(gate_addr, expr_bool, polarity)`.
- per-byte domains: `dom[k]` = 256-bit int bitmask (all bits set initially);
  `len_dom` = set or interval `[0, MAX_SYM_LEN]`.

### 10.3 Execution rules

- Modelled instruction → exact effect on the abstract state.
- Unmodelled → clobber per §7.3; note `unmodelled <raw hex> @addr` once per
  address.
- `jcc` with a concrete condition → follow it. With a symbolic condition →
  **fork**: the child taking the edge in `R_S` is explored first (DFS); each
  child appends its assumed condition to the path condition and, when the
  condition has exactly one free input byte (or only `len`), immediately
  intersects `dom[k]` by evaluating the expression for all 256 values
  (`len`: its interval). Empty domain → path pruned (`infeasible`).
- `setcc` → writes `("un","bool",8, cc-expr)`; `cmovcc` with symbolic cc →
  fork like a jcc.
- Path end conditions: reaching an `S` ref site → **solution path** (stop
  searching unless `--deep` asks for all); reaching an `F` ref site, a
  noreturn call, `ret` out of the walker's entry function, or a budget →
  pruned (reason recorded).
- Loops: concrete loop counters run concretely; a back-edge crossed more than
  `MAX_LOOP_ITERS` times on one path prunes it (`loop budget`). Loops whose
  bound is `len` are handled once `len_dom` is a singleton; if `len` is still
  open when a `len`-bounded loop is entered, the walker forks on the exit
  condition per iteration up to `MAX_SYM_LEN`.
- Internal `call` → descend with a fresh return marker (depth ≤
  `MAX_CALL_DEPTH`); beyond depth, treat as unknown call.
- Unknown / unmodelled external call → `rax`, `rcx`, `rdx`, `rsi`, `rdi`,
  `r8–r11` (x86: `eax`, `ecx`, `edx`) := `unk("call <name>")`; memory pointed
  to by pointer arguments is **not** invalidated except for the known output
  functions in §10.4 (documented approximation, `[M]` downgrade on any
  constraint that later reads such memory).

### 10.4 Input model and libcall models (MUST)

Arguments are read per ABI: SysV x86-64 (`rdi, rsi, rdx, rcx, r8, r9`) or
cdecl x86 (`[esp+4]`, `[esp+8]`, … at the call, i.e. `[esp]`, `[esp+4]` just
before `call` pushes the return). Names come from PLT/symbols; `__isoc99_`,
`__`*`_chk` and `@plt`/`@GLIBC_*` decorations are stripped.

| function(s) | model |
|---|---|
| `fgets(buf, n, stream)` | `buf` region bytes `[0, n-1)` := `IN[0..]`; input mode `stdin`; `len` gains the implied relation "IN contains '\n' at `len`" (see §10.5) |
| `gets`, `scanf/__isoc99_scanf("%s"/"%Ns", buf)`, `read(0, buf, n)`, `fread(buf,1,n,stdin)`, `getline(&p, ...)` (SHOULD) | same, mode `stdin`; `read` returns `len` (+1 for newline when the next use strips it) |
| `main(argc, argv)` reads `argv[1]` (`[rsi+8]` / `[[ebp+0xc]+4]`) | the loaded pointer is `("ptr","input",0)`; mode `argv`; `argc` concrete 2 |
| `strlen(p)` with `p` input | `len` |
| `strcspn(p, "\n")` / `strcspn(p, "\r\n")` with `p` input | `len` |
| `strcmp(a, b)` / `strncmp(a, b, n)` with one side input and the other a concrete C string `s` | returns `("scmp", s, n)`; a `test`/`cmp 0` + `e`/`ne` on it yields `kind="str-eq"`: `IN[0..len(s)] == s + "\0"` (`strncmp`: first `n` bytes) — domains set directly; any other use of the value → `unk` |
| `memcmp(a, b, n)` / `bcmp` with concrete `n` and a concrete buffer | `kind="mem-eq"`, `n` byte-eq constraints |
| `std::string::compare(const char*)` / `operator==` (mangled names in `LIBCALL_ALIASES`, SHOULD) | as `strcmp` |
| `puts/printf/__printf_chk/fputs/write/putchar/std::operator<<` | output; no state change except return value `unk` |
| `exit/_exit/abort/__stack_chk_fail` | path end |
| `malloc/calloc` | fresh `("ptr","heap<n>",0)`; `calloc` zero-fills |
| `memcpy/strcpy/strncpy(dst, src, n)` with concrete `n` / known src length | byte copy of expressions (so copied input stays symbolic) |
| `toupper/tolower` on an input byte | expression `("op","case",...)` (SHOULD; domain filter still works by brute force) |
| `atoi/strtol/strtoul` on input | `unk("numeric parse")` + guidance note "input parsed as number" (MAY: model decimal digits) |
| `MD5*/SHA*/EVP_Digest*/crc32` (by name) or hits from `revauto.scan_crypto_constants` inside the analysed functions | `unk("hash <name>")`; guidance §14 (`hashid`) |
| `ptrace(PTRACE_TRACEME)` (import or syscall 101) | returns concrete `0` (assume not traced) + note; the gate is still listed so the patch plan can include it |

Input when no reader is seen within the analysed functions: if the walker
entry is not `main`, pointer arguments of the entry function become regions
`arg0..5`; the first one that flows into a gate condition is promoted to the
input (`mode="arg0"`, `[M]`).

Walker entry selection: (1) `main` if the verdict function is `main` or is
reachable from `main` within depth 3; (2) else the verdict function itself;
(3) `--func ADDR` overrides.

### 10.5 Idioms that MUST be special-cased

- **Newline strip**: `buf[strcspn(buf, "\n")] = 0` and
  `buf[strlen(buf) - 1] = 0` — a store of `0` at `input + len` or
  `input + len - 1` is a no-op on the symbolic input (the fgets newline is
  assumed at `len`); note `newline-strip idiom @0x...`.
- **Canary**: `mov rax, fs:0x28; mov [rbp-8], rax … xor rax, fs:0x28; jne
  __stack_chk_fail` — the `CANARY` value cancels (`x ^ x = 0`), so the branch
  is concrete and never a gate.
- **Length via loop**: `while (s[i]) i++` — counter compared to `IN[i]` vs 0 →
  the walker forks per iteration (bounded by `MAX_SYM_LEN`); after the gate
  fixes the counter, `len` is set.
- **Byte loads with `movzx/movsx`** then 32-bit arithmetic then `cmp al/dl`:
  `simplify` must reduce to an 8-bit expression so single-byte domain
  filtering applies.
- **Table index by loop counter**: `lea rcx, [rip+T]; movzx eax, byte
  [rax+rcx]` with concrete `rax` reads `image` bytes → constant.

### 10.6 Raw syscalls (MUST)

`syscall` with concrete `rax` (x64) / `int 0x80` with concrete `eax` (x86):
`read(0, buf, n)` → input model; `write` → output (its `rsi` pointing at a
verdict string makes the site a verdict ref for §9 if it was not already);
`exit`/`exit_group` → path end; `ptrace` → concrete 0 + note; anything else →
`rax := unk`.

### 10.7 Constraint emission

Each symbolic gate on the solution path produces one `Constraint` in path
order:

- `length`: free vars ⊆ {`len`} → `LEN == 15` / `LEN >= 8` (`[H]`).
- `byte-eq`: one free input byte, equality → `IN[3] rol 3 == 0xdb` with the
  solved value next to it in `solve`.
- `byte-rel`: one free byte, inequality (`IN[0] - 0x30 <=u 9`) → domain only.
- `multi`: ≥ 2 free bytes (`IN[2] ^ IN[3] == 0x17`).
- `str-eq` / `mem-eq`: from §10.4.
- `unresolved`: the gate's condition contains `unk` — text names the reason
  (`depends on crc32 @0x401190 (unmodelled)`), `[L]`.

**Loop compaction (MUST):** consecutive constraints produced by the same gate
with the same expression shape over `IN[i]` for i = a..b and constants read
from a contiguous table are rendered as one line:
`IN[i] ^ 0x42 == byte[0x402010 + i]   for i = 0..14   (gate 0x4011c7 x15)`.

Confidence per constraint: `[H]` when every value in it came from modelled
instructions and concrete image bytes; `[M]` when it involves a modelled
libcall approximation (§10.3 last bullet) or an `arg0`-inferred input; `[L]`
for `unresolved`.

---

## 11. Stage 5a — solver + static re-walk verification (`solve`)

### 11.1 Byte domains

After the walker, every position `k < len` has `dom[k]`. `len` must be a
singleton for a full answer; otherwise the answer length is the max position
constrained + 1 and the solution is at most `[M]` with a note.

### 11.2 Propagation

Repeat until fixpoint (≤ 64 rounds): for each `multi` constraint, if all but
one free byte are singletons, substitute and filter the remaining byte's
domain by brute force over 256 values.

### 11.3 Search

Remaining `multi` constraints with ≥ 2 open bytes: backtracking search over
open positions ordered by constraint degree, values tried in **rank order**
(see 11.4), each constraint evaluated as soon as all its bytes are assigned,
total evaluations ≤ `MAX_SEARCH`. Exhausted → positions stay open (`?`).

### 11.4 Choosing a value from a domain

Rank: (1) flag-anchor — if `--flag-format` or `batch.FLAG_RE` has a literal
prefix (`CyberSci{`, `flag{`, `ctf{` …, computed by reading the regex source
up to the first metacharacter) and the domain contains the anchor byte at
that position, pick it; (2) `[A-Za-z0-9_{}]`; (3) other printable; (4)
anything. A position whose domain has > 1 value in the chosen rank class is
`ambiguous` (rendered `[M]`).

### 11.5 Static re-walk verification (MUST)

Re-run the walker from the same entry with the candidate as **concrete**
input bytes (`len` concrete, `'\n'` appended for `stdin` mode). Pass = the
walk reaches an `S` site without forking and without an `unresolved`
condition on the way. Result string: `re-walk ok (15 gates satisfied)` or
`re-walk failed at 0x4011c7 (IN[4] ^ 0x42 != byte[0x402014])`. This is
deterministic abstract interpretation — **not** execution.

### 11.6 Confidence of the derived answer

| tag | condition |
|---|---|
| `[H]` | all positions `< len` singletons (or chosen from a single-value rank class), `len` known, no `unresolved` constraint on the path, re-walk ok |
| `[M]` | re-walk ok but some positions ambiguous, or input region inferred (`arg0`), or `len` not a singleton |
| `[L]` | some positions unknown (`?`) or an `unresolved` constraint was assumed true |

Outcome rule: headline is **derived** iff a candidate exists with confidence
`[H]` or `[M]`. `[L]` candidates are printed in the SOLVE section but the
headline falls to **patch** (if a patch plan exists) else **guidance**.

### 11.7 Trivial wins (MUST, checked first)

- `strcmp`/`strncmp`/`memcmp` with a literal (`str-eq` / `mem-eq`) on the
  solution path and nothing else symbolic → candidate = literal, method
  `strcmp-literal`, `[H]` after re-walk.
- A `rodata-flag` string (§8.2) that the re-walk accepts as input → `[H]`,
  method `rodata-flag`; if the re-walk rejects it, it is listed in NOTES only
  ("flag-shaped string in .rodata @0x... is not accepted by the checker").

---

## 12. Stage 5b — patch planner (`patch`)

### 12.1 Per-gate force patch (MUST)

For each gate the planner computes bytes that make the success edge
unconditional. File offset via `disasm.vaddr_to_offset`.

| gate encoding | success edge | patch | strategy |
|---|---|---|---|
| short jcc `7x rel8` | fallthrough | `90 90` | `nop-jcc` |
| short jcc `7x rel8` | taken | `EB rel8` (same rel8) | `force-jmp` |
| near jcc `0F 8x rel32` | fallthrough | `90 90 90 90 90 90` | `nop-jcc` |
| near jcc `0F 8x rel32` | taken | `90 E9 rel32` (same rel32: `addr+1+5+rel32 == addr+6+rel32`) | `force-jmp` |
| `setcc r/m8` (`0F 9x modrm`) on register `mod==11` | true | `B0+r 01 90` for `al/cl/dl/bl` (3 bytes: `mov r8, 1; nop`); other regs → `MAY` (falls back to the caller gate) | `setcc-to-mov1` |
| `cmovcc r, r/m` (`[REX] 0F 4x modrm`) | move happens | `[REX] 8B modrm 90` | `cmov-to-mov` |
| `cmovcc` | move does not happen | `len(insn)` × `90` (prefixes included) | `nop-jcc` |

`flip` (`elfpatch.flip_jcc`) is shown as the **alternative** for a single
deciding jcc ("flip makes correct input fail; force is preferred").

### 12.2 Return-true patch (SHOULD)

For a delegated decision (`check()` style), offer
`ret-true`: at the callee entry write `B8 01 00 00 00 C3` (`mov eax, 1;
ret`) — or `31 C0 C3` when success requires `0` (e.g. `strcmp`-style
`test eax, eax; je success`). Only when the callee is ≥ 6 bytes and has no
other callers outside the verdict path (else note and skip).

### 12.3 elfpatch command rendering (MUST)

Every patch carries the exact command, using only existing `elfpatch`
subcommands and flags:

- `nop-jcc` → `recon.py elfpatch nop <elf> --at 0x4011a0 --len 6 -o <out>`
- `force-jmp` short → `recon.py elfpatch patch <elf> --at 0x4011c7 --bytes eb -o <out>`
  (only the opcode byte changes)
- `force-jmp` near → `recon.py elfpatch patch <elf> --at 0x4011a0 --bytes 90e9 -o <out>`
- others → `recon.py elfpatch patch <elf> --at ADDR --bytes <hex> -o <out>`
- alternative flip → `recon.py elfpatch flip <elf> --at ADDR -o <out>`

Multi-patch plans chain files: first command `-o <elf>.p1`, next one reads
`<elf>.p1` and writes `<elf>.p2`, …, last writes `<elf>.patched` (the
`autosolve patch -o OUT` subcommand does it in one go). `<elf>` is the path
as given on the command line; `--at` uses vaddrs (elfpatch resolves PIE
vaddrs through the section map like `disasm`).

### 12.4 Primary plan (MUST)

Minimal set that makes **every** path from the input read reach `S`:

1. If there is a single *funnel* gate — the deciding branch post-dominates all
   other gates (e.g. `call check; test eax,eax; je fail`) → primary = that one
   gate.
2. Else all gates on the solution path, deduplicated by address (a loop gate
   crossed 15 times is one patch).
3. Gates with `unresolved` conditions are always included.

Gates whose success edge is concrete-always (loop bounds) are never patched.

### 12.5 Patch verification (MUST)

Apply the primary plan to an in-memory copy (`elfpatch.patch_bytes`), rebuild
`BinCtx`, re-run stages 2–3 with an **all-unknown** input (no domain filtering
needed): pass when the walker reaches `S` with zero symbolic gates. Printed as
`patch check: success print reached with 0 input-dependent branches`.

Note printed with every plan: "a patched binary prints the success message
for any input; if the flag *is* the input, use the derived answer / angr
instead — patching helps when the success path decrypts or prints the flag."

---

## 13. Stage 4 — annotated verdict-region listing (`listing`)

Window: for each analysed function on the solution path, from the block that
reads input (or function start) to the success/failure print blocks + 2
instructions, ordered by address, max `MAX_LISTING` lines (`--deep`: whole
functions, 600). Non-adjacent ranges separated by `   ...`.

Line format (≤ 100 cols):

```
  0x4011a0  0f 85 6a 00 00 00     jne 0x401210            ; GATE#1 length: LEN == 15 [H]
```

`addr` 10 cols, raw hex ≤ 20 cols (longer → `…`), text from §7.4 (capstone
when available), annotation after `;`. Annotations (first that applies, then
others joined with ` | ` if room):

`INPUT <- fgets(buf=stack-0x50, 64)` · `LEN <- strlen(input)` ·
`GATE#n <label>: <constraint> [conf]` (`*DECIDING*` appended for the deciding
gate) · `VERDICT success "Correct!"` / `VERDICT failure "Wrong."` ·
`TABLE 0x402010 (15 B: 24 2e 23 25 …)` · `xform: xor 0x42` (on the first
transform op of a chain feeding a gate) · `loop i=0..14` (on the back-edge) ·
`unmodelled: crc32` · `PATCH -> 90 90` (when the line is in the primary plan).

Without capstone, the header of the section says
`(built-in decoder; install capstone for full mnemonics)` — never a hex-only
dump, because the built-in formatter covers the semantic subset.

---

## 14. Stage 5c — next-step guidance

`next_steps` is always computed (max 6 lines, deduplicated). Each rule maps a
recorded reason to text; `<elf>`, addresses and PIE adjustments filled in.
Every referenced toolkit command MUST exist (selftest S12 checks `gdbkit find`
keywords via `gdbkit.search_recipes`, and `elfpatch`/`disasm`/`hashid`/
`revauto` subcommand names against their `run()` usage text).

| reason | text |
|---|---|
| no verdict strings | `no verdict strings matched; rerun with --success 'TEXT' --fail 'TEXT' (copy the program's output)` · `recon.py revauto <elf> --deep   (strings + xrefs + function digest)` |
| verdicts without refs | `verdict strings have no code references (stack-built / encrypted / packed?)` · `recon.py revauto <elf>   (packer + anti-debug tells)` |
| unresolved gate (unmodelled insn / unknown call) | `gate 0x... depends on <reason>: inspect with recon.py disasm range <elf> <addr-0x40> 0x80` · gdb move (below) |
| hashed input | `input is hashed (<name>) before the compare: not statically invertible -> patch the gate, or recon.py hashid id <hex> if the digest constant is extractable` |
| numeric parse | `input parsed as a number: brute the compare by hand or use the angr lane` |
| anti-debug seen (ptrace import/syscall) | `recon.py gdbkit find ptrace   (debugger check present)` |
| search exhausted / multi-var open | `constraints over several bytes left open: angr lane (pip install angr before the CTF)` |
| PIE | gdb moves use `break *(0x555555554000 + 0x11a0)` (gdb's default PIE base with ASLR disabled) and `recon.py gdbkit find vmmap` |

**gdb move** (printed for unresolved gates, one line each):
`gdb ./<elf>  ->  break *<gate>  ->  run  ->  x/2i $pc ; info registers eflags` and
`force it live: set $eflags ^= 0x40   (recon.py gdbkit find patch-memory)`, and
`recon.py gdbkit script <elf> -b '*<gate>' --bp-cmd 'info registers' -o gate.gdb`.
These are **printed hints** for the analyst; autosolve never runs gdb.

When `objdump`/`r2` are on PATH (via `_WHICH`), one extra line from
`disasm.external_shortcuts(path)` with `(suggestion; autosolve never runs it)`.

---

## 15. Lane 2 — angr (`angr`)

### 15.1 Detection (MUST)

`angr_available()` = `_FIND_SPEC("angr") is not None` (with `claripy` too).
**Never import angr in the toolkit process** (import is slow and may print
warnings). Absent → `AngrResult(status="absent")` and exactly one line:

```
angr: not installed - symbolic lane skipped (pre-CTF prep only, needs network: pip install angr)
```

Nothing else in the report changes (S10 compares the report with and without
the line). Detection uses the interpreter running the toolkit; on Kali
(PEP 668 "externally managed" Python) the `--deep` / README text adds:
`python3 -m venv ~/angr-venv && ~/angr-venv/bin/pip install angr`, then run
the toolkit with `~/angr-venv/bin/python3 toolkit/recon.py ...` — prep only.

### 15.2 When it runs

- Full chain: after the static report is **printed and flushed**, if
  `opts.angr != "off"`, angr is available, and the target arch is x86/x86-64
  (angr also supports others; MAY allow ARM). Runs even when Lane 1 derived
  an `[H]` answer (cross-check), printing `agrees with static answer` /
  `DIFFERS from static answer` (when both exist).
- `--no-angr` → `angr: skipped (--no-angr)`.
- `angr` subcommand → stages 1–3 silently (for addresses), then Lane 2 only.
- No verdict refs → angr skipped with `angr: skipped (no success address from
  Lane 1; pass --success)`.

### 15.3 Child process (MUST)

```python
proc = subprocess.run([sys.executable, "-c", _ANGR_HELPER],
                      input=json.dumps(cfg).encode(), capture_output=True,
                      timeout=opts.angr_timeout, cwd=<fresh tempfile.mkdtemp()>,
                      env={**os.environ, "PYTHONWARNINGS": "ignore"}, check=False)
```

- `-I` is deliberately **not** used: it would hide a `pip install --user angr`
  that `find_spec` sees in the parent. `cwd` is an empty temp dir so the
  child's `sys.path[0]` (cwd for `-c`) contains nothing plantable; removed
  afterwards.
- `TimeoutExpired` → `status="timeout"`, `angr: timed out after 60 s (static
  results above unaffected)`. `subprocess.run` kills the child.
- Non-zero exit / unparsable stdout → `status="error"`, last stderr line
  (≤ 100 chars).
- Stdout's **last line** is a JSON object `{"status": "ok"|"no-solution",
  "input_hex": ..., "steps": ...}`; angr's chatter goes to stderr and is
  ignored except in `--deep` (last 5 lines).
- `_ANGR_RUNNER` hook lets the selftest substitute a fake that returns canned
  `CompletedProcess` objects (no angr, no child).

### 15.4 Config passed to the helper

```json
{"path": "<abs path>", "link_base": 0, "pie": true,
 "find": [<success ref sites>], "avoid": [<failure ref sites>, <noreturn fail calls>],
 "mode": "stdin" | "argv", "length": 15 | null, "max_len": 64,
 "printable": true, "known": {"0": 102}, "max_active": 64}
```

- `find`/`avoid` are **file vaddrs**; the helper rebases with
  `mapped_base - link_base` (PIE: `link_base` = lowest `PT_LOAD` vaddr, 0 for
  typical PIE; angr maps PIE at 0x400000).
- `length` from Lane 1 `len` when a singleton; else null → helper uses an
  unconstrained symbolic stdin and dumps `posix.dumps(0)`.
- `known` = Lane-1 singleton domains for `[H]` constraints only (speeds angr
  up; omitted with `--deep` so angr is an independent check).
- `mode` from §10.4 (`arg0` → `stdin` with a note).

The helper template is Appendix A; it MUST stay ≤ 80 lines, use only stable
angr API (`Project`, `factory.entry_state`/`full_init_state`,
`SimFileStream`, `simulation_manager().explore(find=, avoid=)`, `claripy.BVS`,
`solver.eval`), and set `auto_load_libs=False`.

### 15.5 Output

```
ANGR   (60 s budget, 7.4 s used)
  computed input: flag{x0r_t4bl3}   [H via angr]   agrees with static answer
```

`no-solution` → `angr: explored, no input reaches 0x401196 within limits`.

---

## 16. Report rendering

### 16.1 Compact text (default)

Section order, each omitted when empty except HEADLINE:

```
autosolve: <name>  ELF64 x86-64  PIE  not stripped  dynamic   capstone: no
HEADLINE   DERIVED [H]  flag{x0r_t4bl3}            (or PATCH ... / NEXT STEP ...)
VERDICTS   success "Correct!" @0x402015  <- 0x4011e4 (main, rip-rel, puts) [H]
           failure "Wrong."   @0x40201e  <- 0x401204 (main, rip-rel, puts) [H]
INPUT      stdin via fgets @0x40116f -> stack buffer (64 B); newline-strip @0x401189
DECIDING   0x4011d5  jne  (byte compare, in loop x15)  success = fallthrough
GATES      #1 0x4011a0 jne  length check        LEN == 15                     [H]
           #2 0x4011d5 jne  table compare *     IN[i] ^ 0x42 == byte[0x402004+i], i=0..14 [H]
SOLVE      flag{x0r_t4bl3}  [H]  method byte-domain  re-walk ok (16 gates satisfied)
           trace: LEN=15 (gate#1); IN[i] = byte[0x402004+i] ^ 0x42 (gate#2, table 15 B)
LISTING    (built-in decoder; install capstone for full mnemonics)
           ... ≤ 40 lines in compact mode ...
PATCH      primary (2 patches; alternative to the derived answer):
           0x4011a0 (off 0x11a0) 0f 85 6a 00 00 00 -> 90 90 90 90 90 90   nop-jcc
             recon.py elfpatch nop ./crackme --at 0x4011a0 --len 6 -o ./crackme.p1
           0x4011d5 (off 0x11d5) 75 2d -> 90 90   nop-jcc
             recon.py elfpatch nop ./crackme.p1 --at 0x4011d5 --len 2 -o ./crackme.patched
           patch check: success print reached with 0 input-dependent branches
NEXT STEPS 1. ...
ANGR       angr: not installed - symbolic lane skipped (...)
NOTES / ERRORS
```

Compact mode: LISTING ≤ 40 lines (region around the deciding gate), GATES ≤
12 (rest summarised `… N more (--deep)`), whole report ≤ 90 lines for the
selftest fixtures, every line ≤ 100 cols.

### 16.2 `--deep`

Full listing (§13), all gates incl. concrete loop bounds, all pruned paths
with reasons, per-position domains for ambiguous bytes (`IN[5] ∈ {'0','O'}`),
capstone length cross-check result, angr stderr tail.

### 16.3 Subcommand views

Each stage subcommand prints the header line plus only its sections:
`find-verdicts` → VERDICTS (+ unreferenced verdict strings + `rodata-flag`
candidates); `trace` → VERDICTS, DECIDING, GATES (labels, no constraints),
patch preview line; `constraints` → + INPUT, constraint list in order;
`listing` → LISTING; `solve` → + SOLVE; `patch` → + PATCH; `angr` → ANGR.

---

## 17. Selftest specification

`selftest()` prints `  [PASS] <name>` / `  [FAIL] <name>` per check, a closing
`selftest: OK|FAILED`, returns `bool`. All fixtures are built **in memory**
(temp files only via `tempfile`, for CLI checks). Requires neither capstone
nor angr; detection hooks are injected so results do not depend on the host.
Runtime budget **< 4 s** on the CI runner. `run()` output captured with
`contextlib.redirect_stdout/stderr`.

### 17.1 Fixture assembler

`_Asm(bits)` — a two-pass label assembler for fixture code only:
`a.raw(bytes)`, `a.label(name)`, `a.rel8(op_bytes, label)`,
`a.rel32(op_bytes, label)`, `a.rip32(prefix_bytes, label, suffix=b"")` (x64
RIP-relative disp to a data label), `a.abs32(prefix_bytes, label)` (x86
absolute). `_build_elf(bits, text: _Asm, rodata: list[(label, bytes)],
funcs: dict[name, label], plt: list[name] | None)` lays out
`.text`/`.rodata`/`.symtab`/`.strtab`/`.shstrtab` (+ `.plt`/`.got.plt`/
`.rela.plt`/`.dynsym`/`.dynstr` when `plt` is given) following
`disasm.build_test_elf`'s layout pattern (one RX `PT_LOAD` covering
everything, base `0x400000` x64 / `0x8048000` x86, `ET_EXEC`). Library
functions for non-PLT fixtures are `ret` stubs named by `.symtab` FUNC
symbols (static non-stripped style) — they are never "called", only named.

Flags and tables are **computed** in the builder from constants (e.g.
`TABLE = bytes(c ^ 0x42 for c in F1_FLAG)`), never hand-typed.

### 17.2 Fixtures

**F1 — gcc -O0 style xor-table loop (x86-64)**, `F1_FLAG = b"flag{x0r_t4bl3}"`
(15 B). Exact instruction bytes (rel/rip fields filled by `_Asm`):

```
main:  55                      push rbp
       48 89 e5                mov rbp, rsp
       48 83 ec 60             sub rsp, 0x60
       48 8d 7d b0             lea rdi, [rbp-0x50]
       be 40 00 00 00          mov esi, 0x40
       31 d2                   xor edx, edx
       e8 <fgets>              call fgets
       48 8d 7d b0             lea rdi, [rbp-0x50]
       e8 <strlen>             call strlen
       48 83 f8 0f             cmp rax, 0xf
       0f 85 <fail>            jne fail               ; near jcc, gate #1
       c7 45 ac 00 00 00 00    mov dword [rbp-0x54], 0
       eb <cond>               jmp cond
body:  8b 45 ac                mov eax, [rbp-0x54]
       48 98                   cdqe
       0f b6 44 05 b0          movzx eax, byte [rbp+rax-0x50]
       83 f0 42                xor eax, 0x42
       89 c2                   mov edx, eax
       8b 45 ac                mov eax, [rbp-0x54]
       48 98                   cdqe
       48 8d 0d <TABLE>        lea rcx, [rip+TABLE]
       0f b6 04 08             movzx eax, byte [rax+rcx]
       38 c2                   cmp dl, al
       75 <fail>               jne fail               ; short jcc, gate #2 (deciding)
       83 45 ac 01             add dword [rbp-0x54], 1
cond:  83 7d ac 0e             cmp dword [rbp-0x54], 0xe
       7e <body>               jle body               ; concrete loop bound
       48 8d 3d <S_OK>         lea rdi, [rip+S_OK]
       e8 <puts>               call puts
       b8 00 00 00 00          mov eax, 0
       c9 c3                   leave ; ret
fail:  48 8d 3d <S_BAD>        lea rdi, [rip+S_BAD]
       e8 <puts>               call puts
       b8 01 00 00 00          mov eax, 1
       c9 c3                   leave ; ret
fgets: c3   strlen: c3   puts: c3
.rodata: TABLE (15 B), S_OK "Correct!\0", S_BAD "Wrong.\0", S_X "Try again later\0" (unreferenced)
```

**F2 — check() function, unrolled compares, mixed transforms, setcc return
(x86-64)**, `F2_FLAG = b"ctf{r0l_4dd}"` (12 B). `check(rdi)`: for position `i`
cycle transforms `[none, add 5, rol 3, xor 0x5a]`:
none → `80 7f <i> <c>` (`cmp byte [rdi+i], c`) + `75 <r0>`;
others → `0f b6 47 <i>` (`movzx eax, byte [rdi+i]`) + `04 05` / `c0 c0 03` /
`34 5a` + `3c <t>` + `75 <r0>`; then `80 7f 0c 00` (`cmp byte [rdi+12], 0`),
`0f 94 c0` (`sete al`), `0f b6 c0` (`movzx eax, al`), `c3`;
`r0: 31 c0 c3`. `main`: `48 83 ec 48`, `48 89 e7` (`mov rdi, rsp`),
`e8 <gets>`, `48 89 e7`, `e8 <check>`, `85 c0` (`test eax, eax`),
`74 <fail>` (`je fail`), success `lea rdi, [rip+"Access granted"]; call puts`,
fail `lea rdi, [rip+"Access denied"]; call puts`, each followed by
`48 83 c4 48 c3`.

**F3 — unmodelled transform (x86-64)**: like F2's main, but `check` does
`f2 0f 38 f0 07` (`crc32 eax, byte [rdi]`), `3d <imm32>` (`cmp eax, imm32`),
`0f 94 c0; 0f b6 c0; c3`. Verdicts `"Correct"` / `"Incorrect"` (tests the
fail-first rule).

**F4 — i386 cdecl, push-imm32 refs, strcmp literal**, `F4_SECRET = b"s3cr3t!!"`:

```
main: 55 ; 89 e5 ; 83 ec 58
      8d 45 b0 ; 50 ; e8 <gets> ; 83 c4 04
      8d 45 b0 ; 50 ; e8 <strlen> ; 83 c4 04
      83 f8 08 ; 75 <fail>                       ; gate #1 length
      8d 45 b0 ; 50 ; 68 <SECRET> ; e8 <strcmp> ; 83 c4 08
      85 c0 ; 75 <fail>                          ; gate #2 strcmp result (deciding)
      68 <S_OK "Nice! correct"> ; e8 <puts> ; 83 c4 04 ; 31 c0 ; c9 ; c3
fail: 68 <S_BAD "Nope, try again"> ; e8 <puts> ; 83 c4 04 ; b8 01 00 00 00 ; c9 ; c3
```

**F5 — dynamic PLT + newline strip (x86-64)**: `plt=["fgets","strcspn","strcmp","puts"]`;
`.plt` stubs `ff 25 <got>` + 10 bytes padding, `.got.plt` slots, `.rela.plt`
`R_X86_64_JUMP_SLOT` entries, `.dynsym`/`.dynstr` (enough for
`pwnhelp.got_plt`). Code: fgets into `[rbp-0x50]`; `lea rsi, [rip+NL]` (`"\n"`);
`call strcspn@plt`; `c6 44 05 b0 00` (`mov byte [rbp+rax-0x50], 0`);
`lea rsi, [rip+SECRET]` (`"CyberSci{plt_0k}"`); `lea rdi, [rbp-0x50]`;
`call strcmp@plt`; `85 c0`; `75 <fail>`; verdicts `"Congratulations!"` /
`"Wrong!"`.

**F6 — no verdicts**: F1 with `S_OK` / `S_BAD` replaced by `"AAAA"` / `"BBBB"`
and `S_X` removed (no string in the binary matches a built-in pattern).

**F7 — cmov verdict select (x86-64, SHOULD)**: `cmp byte [rdi], 0x41`;
`48 8d 3d <S_OK>` (lea rdi), `48 8d 05 <S_BAD>` (lea rax), `48 0f 45 f8`
(`cmovne rdi, rax`), `call puts`.

### 17.3 Checks

**S1 — safety/offline lint (MUST).** `ast.parse(open(__file__).read())`:
no `Call` to `eval`/`exec`/`compile`/`os.system`/`os.popen`/`ctypes.*`; no
`Import`/`ImportFrom` of `socket, urllib, http, requests, ftplib, smtplib,
telnetlib, angr, claripy` at module level (angr only inside the helper
**string**); exactly one `subprocess.*` call site in the module, inside
`_run_angr_child`, whose first argv element is `sys.executable`; no
`shell=True` keyword anywhere.

**S2 — decoder corpus (MUST).** Every Appendix C entry decodes with the
expected length and `mnem`; invalid-in-x64 opcodes return `None`; `c5 06`
in 32-bit is a 2-byte non-VEX instruction; with capstone present, lengths of
all fixture `.text` instructions match capstone.

**S3 — F1 end-to-end (MUST).** Verdicts: 1 success `[H]` (`Correct!`, ref
`rip-rel`, printer `puts`), 1 failure `[H]`; `Try again later` listed as
unreferenced. Gates: exactly 2 symbolic gates; gate#2 is `deciding`,
`in_loop`, `hits == 15`; constraints: `length LEN == 15` then one compacted
loop line containing `^ 0x42` and `i = 0..14`. Solution `== F1_FLAG`, `[H]`,
`re-walk ok`. Outcome `derived`. Primary patch plan: 2 patches —
`0f 85 xx xx xx xx → 90*6` and `75 xx → 90 90`, `elfpatch` commands as §12.3.

**S4 — F2 (MUST).** Deciding gate is the `je` in `main` (`return value of
check`); 12+1 gates inside `check`; solution `== F2_FLAG` `[H]` re-walk ok;
primary plan = **one** patch (`74 xx → 90 90`, funnel rule §12.4.1);
`ret-true` alternative present (`b8 01 00 00 00 c3` at `check`).

**S5 — F3 (MUST).** `"Incorrect"` classified failure; constraint list has an
`unresolved` entry naming `crc32`; no `[H]`/`[M]` candidate; outcome `patch`;
primary patch is the `je` in main; NEXT STEPS contain `disasm range` and a
`break *0x` gdb move; with injected `_FIND_SPEC` returning a spec and a fake
runner returning `{"status":"ok","input_hex":"41"}`, ANGR prints
`computed input: A`.

**S6 — F4 i386 (MUST).** Verdict refs `via="push-imm32"`; LEN == 8; `str-eq`
constraint; solution `== F4_SECRET` `[H]` via `strcmp-literal`; outcome
`derived`.

**S7 — F5 PLT + newline strip (MUST).** `plt` names resolved via
`pwnhelp.got_plt`; `newline-strip idiom` note present; solution
`CyberSci{plt_0k}` `[H]`; `--flag-format 'CyberSci\{[^}]+\}'` sets
`flag_match=True`.

**S8 — F6 no verdicts (MUST).** Outcome `guidance`; NEXT STEPS line 1 contains
`--success`; `run([path])` exits 0; with `--success AAAA --fail BBBB` the
outcome becomes `derived` with `F1_FLAG`.

**S9 — patch roundtrip (MUST).** Apply F1's primary plan with
`elfpatch.patch_bytes` → §12.5 check passes (0 symbolic gates). Also
`run(["patch", src, "-o", out])` writes `out` whose bytes at both gate
offsets are the patched bytes, input untouched; `-o src` → exit 1 (elfpatch
in-place refusal), input untouched.

**S10 — angr absent / present via injection (MUST).** `_FIND_SPEC = lambda
n: None`: report text of F1 equals the angr-present-but-`--no-angr` text
except for exactly the one ANGR line, which equals the §15.1 string. Fake
runner raising `subprocess.TimeoutExpired` → `status="timeout"`, static
sections unchanged, exit 0. Fake runner returning garbage → `status="error"`,
exit 0. `angr` subcommand with angr absent → exit 1 and the same single line.
`_ANGR_HELPER` passes `ast.parse` (syntax check only; never executed in
selftest).

**S11 — subcommands (MUST).** On F1: `find-verdicts`, `trace`,
`constraints`, `listing`, `solve`, `patch` each exit 0 and print only their
sections (§16.3); `trace` names the deciding gate address; `listing` contains
`GATE#2` and `VERDICT success`.

**S12 — guidance references exist (MUST).** For every `gdbkit find <kw>`
string in the guidance table, `gdbkit.search_recipes(kw)` is non-empty; every
`recon.py <mod> <sub>` referenced uses a subcommand that appears in that
module's `USAGE` / argparse choices (`elfpatch nop|patch|flip`, `disasm range`,
`gdbkit script|find`, `revauto`, `hashid id`). (Regression guard: commit
5e4330d fixed a printed `gdbkit find ptrace` that pointed at nothing.)

**S13 — capstone independence (MUST).** Run F1 and F2 with `_CS = None` and
with `_CS = disasm.capstone`; `report_to_dict` minus `listing` must be equal.

**S14 — robustness fuzz (MUST).** `analyze()` on: empty bytes, `b"\x7fELF"`,
F1 truncated at 10 random offsets (fixed seed), F1 with `.text` bytes
randomised (fixed seed, 5 variants), a PE header, an ELF with `e_machine`
ARM → no exception, `errors` may be non-empty, non-x86 gives a strings-only
report.

**S15 — CLI contract (MUST).** bare/`-h` → 0; unknown subcommand-like option
`--bogus` → 2; bad regex `--success '('` → 2; missing file → 1; non-ELF temp
file → 1; `--json` on F1 parses with `json.loads`, `schema ==
"autosolve/1"`, `outcome == "derived"`.

**S16 — budgets (MUST).** `--max-steps 50` on F1 → note `walker step budget
exhausted`, no exception, outcome falls to `patch`. Whole selftest < 4 s
(measured, printed; failure only if > 20 s to avoid CI flakiness).

**S17 — F7 cmov (SHOULD).** Gate `kind="cmovcc"`; success requires the
move **not** to happen (`rdi` keeps `S_OK`), so the patch is `48 0f 45 f8 →
90 90 90 90` (last `cmovcc` row of §12.1); solution `"A"` `[H]`.

---

## 18. Acceptance criteria (review checklist for the implementation PR)

1. **Real crackme (maintainer-verified before merge).** On a realistic
   gcc-compiled flag checker (length check + per-byte expected-value
   comparisons, optionally a simple xor transform), compiled on Kali with
   default flags (`gcc -o crackme crackme.c`, PIE, dynamic) **and** with
   `-O2`, `python3 toolkit/recon.py autosolve ./crackme` prints either the
   derived candidate flag (`[H]` or `[M]`) or the exact patch target with
   bytes and a working `elfpatch` command. The implementation PR body MUST
   paste both outputs plus the C source used. Suggested reference sources
   for the maintainer (not committed): the F1 loop in C, the F2 unrolled
   `check()` in C, and a `strcmp` checker.
2. **angr.** Absent → exactly one skip line (§15.1), rest of report
   byte-identical to `--no-angr` (S10). Present → computed input printed
   (maintainer checks on Kali with `pip install angr` done beforehand).
   Timeout / crash in the child never changes the static sections or the exit
   code of the full chain.
3. `python3 toolkit/recon.py --selftest` → `18/18 modules passed` on a host
   **without** capstone and angr (CI) — and on Kali with them.
4. **Zero network** under any flag: S1 lint passes; `grep -nE
   "socket|urllib|http\.client|requests" toolkit/modules/autosolve.py`
   shows only the lint's own name list.
5. Never executes the target: the only subprocess is the angr helper
   (`sys.executable -c`), S1-enforced; no `gdb`/`objdump`/`r2` invocation.
6. All S1–S16 exist with these names and pass; S17 present or reasoned in PR.
7. Exit codes match §5 for every row.
8. No placeholder code: no `pass`-only bodies, no `TODO`, no
   `NotImplementedError`; every public function has type hints + docstring.
9. Compact report for F1 ≤ 90 lines, every line ≤ 100 columns.
10. `python3 toolkit/modules/autosolve.py selftest` works standalone;
    `recon.py autosolve --selftest` too.
11. No change to `recon.py`, `modules/__init__.py`, or other modules (docs
    excepted). If a sibling helper is private, autosolve implements its own.
12. README module table + `PLAN.md` status updated in the implementation PR
    (§22) — **not** in this spec PR.

---

## 19. Limits and performance budgets

| scenario | budget |
|---|---|
| typical crackme (≤ 100 KiB, ≤ 10 functions analysed), no capstone | < 2 s |
| 2 MiB static binary (glibc linked in), verdict in `main` | < 8 s (pre-scan by regex; only verdict functions + callees decoded) |
| walker on a 64-byte xor-table loop | < 0.3 s |
| selftest | < 4 s |
| angr lane | bounded by `--angr-timeout` (default 60 s) |

Hints: decode lazily per function with an `addr -> Insn` cache; pre-compile
regexes; domain filtering is 256 evaluations of a small tuple tree — cache
compiled lambdas per expression shape **without** `eval` (closure builder
over the tuple tree); hash-cons expressions; never walk whole sections in
Python per byte (regex pre-scan, then `decode` at hits).

---

## 20. Out of scope / stretch (MAY, separate issues)

- Vectorised compares (`movdqa xmm, [rip+K]; pcmpeqb; pmovmskb; cmp eax,
  0xffff`): MAY recognise the pattern and emit the 16-byte constant `K` as a
  `[L]` candidate chunk; full SIMD semantics out of scope.
- Jump tables / switch-based VM checkers; custom bytecode VMs (guidance
  only: "dispatcher loop at 0x... — VM-style checker").
- ARM / AArch64 / MIPS static lane (angr lane may still work).
- PE/Mach-O targets (revauto covers PE digest).
- Floating-point compares, `atoi`-based numeric solving beyond the MAY in
  §10.4, multi-stage checkers that re-read input.
- Writing a `gdb -x` script automatically (only the `gdbkit script` command is
  printed).
- `batch` integration (route ELF crackmes through `autosolve`) — its own PR.

---

## 21. Suggested build order inside the implementation PR

1. Constants, data model, `_stage`, CLI + exit codes, S1 lint, S15.
2. Length decoder + corpus (S2), semantic operand decoding, formatter.
3. `_Asm` + `_build_elf` fixtures F1–F6.
4. Stage 1 verdicts (S3 verdict part, S8 first half).
5. Stage 2 functions/CFG/gates/deciding (S11 `trace`).
6. Expression algebra + walker + libcall models (S3, S4, S6, S7 constraints).
7. Solver + re-walk (S3–S7 solutions); patch planner + verification (S9).
8. Listing, guidance (S5, S12), rendering + JSON.
9. Angr lane + helper (S10), budgets/fuzz (S14, S16), capstone parity (S13).
10. Docs (§22); manual real-crackme check (§18.1).

Commit in that order so review can follow the layers.

---

## 22. Docs to update in the implementation PR

- `toolkit/README.md` modules table row:
  `| autosolve | flag-checker auto-solver: finds success/failure verdict strings and their references (x64 RIP-relative, absolute imm32, i386 push), traces back to the deciding branch, walks the checker with a built-in x86 decoder (capstone optional, presentation only) to extract ordered constraints (length, byte compares, xor/add/sub/rol chains, table lookups, strcmp/memcmp literals), prints the derived flag with confidence + static re-walk verification, or the exact jcc patch with ready elfpatch commands, or next steps; optional angr lane (runtime-detected, timeout-bounded child). Never executes the target. \`recon.py autosolve [find-verdicts\|trace\|constraints\|listing\|solve\|patch\|angr] <elf> [--success RE] [--fail RE] [--json] [--deep] [--no-angr]\` |`
- `toolkit/README.md` requirements paragraph: angr as an optional,
  pre-installed extra (`pip install angr` before the event; needs network).
- `toolkit/PLAN.md`: add an `autosolve` row (IMPLEMENTED) under the flagship
  section linking this file, and update the status line to `18/18`.
- This file: status line → `IMPLEMENTED (<date>)`.

---

## Appendix A — angr helper template (`_ANGR_HELPER`)

Embedded verbatim as a string constant (only formatting changes allowed).
Runs only in the child process; never parsed into code objects in the toolkit
process (S10 uses `ast.parse` for a syntax check only).

```python
import json, sys
cfg = json.loads(sys.stdin.read())
import angr, claripy
proj = angr.Project(cfg["path"], auto_load_libs=False)
delta = proj.loader.main_object.mapped_base - cfg["link_base"]
find = [a + delta for a in cfg["find"]]
avoid = [a + delta for a in cfg["avoid"]]
opts = {angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY, angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS}
syms = []
if cfg["length"]:
    syms = [claripy.BVS("in%d" % i, 8) for i in range(cfg["length"])]
    data = claripy.Concat(*syms)
if cfg["mode"] == "argv":
    if not syms:
        syms = [claripy.BVS("in%d" % i, 8) for i in range(cfg["max_len"])]
        data = claripy.Concat(*syms)
    st = proj.factory.entry_state(args=[cfg["path"], data], add_options=opts)
elif syms:
    stream = angr.SimFileStream(name="stdin", content=claripy.Concat(data, claripy.BVV(b"\n")), has_end=True)
    st = proj.factory.full_init_state(stdin=stream, add_options=opts)
else:
    st = proj.factory.full_init_state(add_options=opts)
for b in syms:
    if cfg["printable"]:
        st.solver.add(b >= 0x20, b <= 0x7e)
for k, v in cfg["known"].items():
    if int(k) < len(syms):
        st.solver.add(syms[int(k)] == v)
sm = proj.factory.simulation_manager(st)
sm.explore(find=find, avoid=avoid, num_find=1)
if sm.found:
    s = sm.found[0]
    out = s.solver.eval(claripy.Concat(*syms), cast_to=bytes) if syms else s.posix.dumps(0)
    print(json.dumps({"status": "ok", "input_hex": out.hex()}))
else:
    print(json.dumps({"status": "no-solution", "input_hex": None}))
```

`max_active` from the config MAY be enforced with
`angr.exploration_techniques.LengthLimiter`/a `step_func` that trims
`sm.active`; keep the helper ≤ 80 lines.

---

## Appendix B — example compact reports (targets, not byte-exact)

**B1 — derived (F1-like, PIE build on Kali):**

```
autosolve: ./crackme  ELF64 x86-64  PIE  not stripped  dynamic   capstone: no
HEADLINE   DERIVED [H]  flag{x0r_t4bl3}
VERDICTS   success "Correct!" @0x2015  <- 0x1214 (main, rip-rel, puts) [H]
           failure "Wrong."   @0x201e  <- 0x1234 (main, rip-rel, puts) [H]
INPUT      stdin via fgets @0x11a3 -> stack-0x50 (64 B); newline-strip @0x11c0
DECIDING   0x1205  jne  table compare (loop x15)  success = fallthrough
GATES      #1 0x11dc jne  length check     LEN == 15                                [H]
           #2 0x1205 jne  table compare *  IN[i] ^ 0x42 == byte[0x2004+i], i=0..14  [H]
SOLVE      flag{x0r_t4bl3}  [H]  byte-domain  re-walk ok (16 gates satisfied)
PATCH      primary (2): 0x11dc 0f 85 .. -> 90x6 ; 0x1205 75 2d -> 90 90  (alternative)
             recon.py elfpatch nop ./crackme --at 0x11dc --len 6 -o ./crackme.p1
             recon.py elfpatch nop ./crackme.p1 --at 0x1205 --len 2 -o ./crackme.patched
           patch check: success print reached with 0 input-dependent branches
ANGR       angr: not installed - symbolic lane skipped (pre-CTF prep only, needs network: pip install angr)
```

**B2 — patch (F3-like):**

```
HEADLINE   PATCH  0x401236 je -> nop (off 0x1236: 74 0c -> 90 90)
GATES      #1 0x401236 je  return value of check@0x401126 *        [H]
           #2 0x40112e jne unknown condition: depends on crc32 @0x401126 (unmodelled) [L]
SOLVE      no candidate (1 unresolved constraint)
NEXT STEPS 1. gate 0x40112e depends on crc32: recon.py disasm range ./chk 0x4010ee 0x80
           2. gdb ./chk -> break *0x40112e -> run -> x/2i $pc ; info registers eflags
           3. force it live: set $eflags ^= 0x40   (recon.py gdbkit find patch-memory)
ANGR       computed input: flag{crc}   [via angr]   (static: none)
```

**B3 — guidance (F6-like):**

```
HEADLINE   NEXT STEP  no verdict strings matched
NEXT STEPS 1. rerun with --success 'TEXT' --fail 'TEXT' (copy the program's output)
           2. recon.py revauto ./chk --deep   (strings + xrefs + function digest)
```

---

## Appendix C — decoder corpus (selftest S2)

`(mode, hex, expected_len, expected_mnem)`; `mnem` `other` = unmodelled.
The implementer MUST include at least these; adding more is encouraged.

| mode | bytes | len | mnem / note |
|---|---|---|---|
| 64 | `55` | 1 | push rbp |
| 64 | `48 89 e5` | 3 | mov rbp, rsp |
| 64 | `f3 0f 1e fa` | 4 | endbr64 |
| 64 | `48 83 ec 60` | 4 | sub rsp, 0x60 |
| 64 | `48 81 ec 00 01 00 00` | 7 | sub rsp, 0x100 |
| 64 | `48 8d 3d 00 00 00 00` | 7 | lea rdi, [rip+0] |
| 64 | `4c 8d 05 00 00 00 00` | 7 | lea r8, [rip+0] |
| 64 | `e8 00 00 00 00` | 5 | call |
| 64 | `e9 00 00 00 00` | 5 | jmp |
| 64 | `eb fe` | 2 | jmp |
| 64 | `0f 85 00 00 00 00` | 6 | jcc ne |
| 64 | `75 fe` | 2 | jcc ne |
| 64 | `c7 45 ac 00 00 00 00` | 7 | mov dword [rbp-0x54], 0 |
| 64 | `66 c7 45 fe 34 12` | 6 | mov word [rbp-2], 0x1234 (66 shrinks imm) |
| 64 | `c6 45 ff 41` | 4 | mov byte [rbp-1], 0x41 |
| 64 | `48 b8 88 77 66 55 44 33 22 11` | 10 | mov rax, imm64 |
| 64 | `0f b6 44 05 b0` | 5 | movzx eax, byte [rbp+rax-0x50] |
| 64 | `0f be 07` | 3 | movsx eax, byte [rdi] |
| 64 | `48 63 d0` | 3 | movsxd rdx, eax |
| 64 | `48 98` | 2 | cdqe |
| 64 | `48 8b 45 f8` | 4 | mov rax, [rbp-8] |
| 64 | `64 48 8b 04 25 28 00 00 00` | 9 | mov rax, fs:[0x28] |
| 64 | `80 7f 05 00` | 4 | cmp byte [rdi+5], 0 |
| 64 | `3c 63` | 2 | cmp al, 0x63 |
| 64 | `3d 78 56 34 12` | 5 | cmp eax, imm32 |
| 64 | `38 c2` | 2 | cmp dl, al |
| 64 | `83 f0 42` | 3 | xor eax, 0x42 |
| 64 | `34 5a` | 2 | xor al, 0x5a |
| 64 | `04 05` | 2 | add al, 5 |
| 64 | `c0 c0 03` | 3 | rol al, 3 |
| 64 | `d1 e0` | 2 | shl eax, 1 |
| 64 | `d3 e8` | 2 | shr eax, cl |
| 64 | `f6 c2 01` | 3 | test dl, 1 (F6 /0 imm8) |
| 64 | `f7 c1 00 01 00 00` | 6 | test ecx, 0x100 (F7 /0 imm32) |
| 64 | `f7 d8` | 2 | neg eax (F7 /3, no imm) |
| 64 | `f6 d0` | 2 | not al |
| 64 | `69 c0 39 30 00 00` | 6 | imul eax, eax, 0x3039 |
| 64 | `6b c0 07` | 3 | imul eax, eax, 7 |
| 64 | `0f af c2` | 3 | imul eax, edx |
| 64 | `0f 94 c0` | 3 | setcc e |
| 64 | `48 0f 45 f8` | 4 | cmovcc ne |
| 64 | `85 c0` | 2 | test eax, eax |
| 64 | `c3` | 1 | ret |
| 64 | `c2 08 00` | 3 | ret 8 |
| 64 | `c9` | 1 | leave |
| 64 | `c8 10 00 00` | 4 | enter (iw ib) |
| 64 | `0f 05` | 2 | syscall |
| 64 | `ff 25 00 00 00 00` | 6 | jmp-ind [rip] |
| 64 | `ff d0` | 2 | call-ind rax |
| 64 | `41 ff d4` | 3 | call-ind r12 |
| 64 | `f3 48 ab` | 3 | rep stosq |
| 64 | `66 0f 1f 44 00 00` | 6 | nop |
| 64 | `0f 1f 80 00 00 00 00` | 7 | nop |
| 64 | `66 2e 0f 1f 84 00 00 00 00 00` | 10 | nop |
| 64 | `a1 00 10 40 00 00 00 00 00` | 9 | mov eax, moffs64 |
| 64 | `f2 0f 38 f0 07` | 5 | other (crc32) |
| 64 | `66 0f 6f 05 00 00 00 00` | 8 | other (movdqa) |
| 64 | `66 0f 74 c1` | 4 | other (pcmpeqb) |
| 64 | `66 0f d7 c0` | 4 | other (pmovmskb → GPR clobber) |
| 64 | `66 0f 3a 0f c1 04` | 6 | other (palignr, 0F3A imm8) |
| 64 | `c5 f9 6f 05 00 00 00 00` | 8 | other (VEX2 vmovdqa) |
| 64 | `c4 e2 79 00 c1` | 5 | other (VEX3 map 0F38) |
| 64 | `c4 e3 79 0f c1 04` | 6 | other (VEX3 map 0F3A + imm8) |
| 64 | `d9 ee` | 2 | other (fldz) |
| 64 | `0f 0b` | 2 | ud2 (stop) |
| 64 | `06` | – | None (invalid in 64-bit) |
| 64 | `60` | – | None |
| 32 | `68 00 20 04 08` | 5 | push imm32 |
| 32 | `c7 04 24 00 20 04 08` | 7 | mov dword [esp], imm32 |
| 32 | `c7 44 24 04 00 00 00 00` | 8 | mov dword [esp+4], imm32 |
| 32 | `8d 83 00 e0 ff ff` | 6 | lea eax, [ebx-0x2000] |
| 32 | `65 a1 14 00 00 00` | 6 | mov eax, gs:[0x14] (moffs32) |
| 32 | `66 b8 34 12` | 4 | mov ax, 0x1234 |
| 32 | `b8 01 00 00 00` | 5 | mov eax, 1 |
| 32 | `cd 80` | 2 | int 0x80 |
| 32 | `83 c4 04` | 3 | add esp, 4 |
| 32 | `40` | 1 | inc eax (not REX in 32-bit) |
| 32 | `c5 06` | 2 | other (lds, not VEX: mod != 11) |
| 32 | `c5 f9 6f c1` | 4 | other (VEX2 in 32-bit: mod == 11) |
