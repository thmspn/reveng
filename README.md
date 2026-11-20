# RE toolkit (offline)

Helper scripts for jeopardy CTFs: reversing/pwn, crypto, forensics/stego and web (22 modules, see below).
**100% offline**: no network calls, no telemetry, no runtime installs. Python 3 standard library first.
Design, module boundaries and the quality bar every module meets are in [`PLAN.md`](PLAN.md).

## Requirements
Python 3.9+ (Kali default is fine). Standard library first; optional libs (capstone, pyelftools, pwntools)
are only used via guarded `try/except ImportError` imports with a stdlib fallback (today: `disasm`/`shellcode` use
capstone when present, hex view otherwise; `hashid` verifies bcrypt/sha*crypt only if `bcrypt`/`passlib` is present;
`stego` uses `PIL` for non-PNG/BMP formats when present; `autosolve` has its own x86 decoder and only uses capstone for listing text). External tools (objdump, r2, ropper, ROPgadget, gdb) are opt-in
"external-tool mode", gated by `shutil.which`; `revauto` additionally uses radare2 (`r2pipe` if importable, else `r2 -2` subprocess) and Ghidra `analyzeHeadless` as opt-in binary engines (never required; stdlib fallback otherwise); `apk` only *suggests* apktool/jadx commands, never runs them.
`angr` is an optional, pre-installed extra for `autosolve`'s symbolic lane only: it is runtime-detected (never imported by the toolkit
process; it runs in a timeout-bounded child) and absent by default. Install it **before the event** (needs network):
`pip install angr`, or on Kali (PEP 668) `python3 -m venv ~/angr-venv && ~/angr-venv/bin/pip install angr` and then run the
toolkit with `~/angr-venv/bin/python3 toolkit/recon.py ...`. Without it `autosolve` prints one skip line and everything else is unchanged.

## Beginner quick start
No knowledge of the scripts is needed. From `toolkit/`, run `python3 recon.py` and read the **START HERE** panel:
```
select> go       args> chall.bin                      # one file: detect type, run the right tools
select> batch    args> challenge_folder               # a whole folder, one table
select> go       args> --text "pasted challenge text" # a description with no file
```
- `select>` takes a module name or number; `args>` takes arguments only, never the module name.
- Quote paths with spaces: `"my folder/chall bin"`. `-h` at `args>` shows that module's usage.
- After you pick a module the menu shows what it does and a working example for `args>`.
- Everything printed is a **candidate to verify**. "No candidate" is not success: it means nothing was found,
  so try another module. In `go`'s step list, `ok` only means the tool ran, not that it solved anything; `-v`
  shows step output that was cut off. When nothing is found, `go` ends with next-step hints naming other modules.
- `go` also prints a separate `== DERIVED INPUTS / REGISTER RESULTS ==` section: exact text quoted from
  `autosolve` (derived input), `pyrun` (HIGH derived password/value) and `asmeval` (register result), each with
  its source and confidence. These are **not flags**; verify them. If no flag-shaped token exists but derived
  evidence does, the summary says so and points there. (Human summary only: step output, flags and exit codes
  are unchanged: exit 0 if a flag candidate was found, else 1.)
- **Candidate scores are not proof:** `go` recognizes `prefix{body}` without a contest-name allowlist
  (prefix: 1-64 ASCII letters/digits/underscores/hyphens; body: 1-200 characters, no braces or line breaks).
  Literal `--text` tokens and tokens actually found in module/codec results get +100. Speculative
  ROT/Atbash/XOR guesses do not, even if their prefix says `flag` or `picoCTF`. Decoder candidates use a
  structured callback, never headings or truncated previews from the human log. A simple body gets +3,
  other bodies -3, on a base of 10; each additional source adds 5. Speculative-only source bonuses
  stop at +20 (maximum speculative score 33), so repeated guesses cannot outrank actual results. Cipher guesses remain visible and
  labelled. An unfamiliar prefix is not evidence of gibberish, and a familiar one is not proof of a flag.
  A ROT-encrypted flag can still look flag-shaped before decryption, so inspect the cipher guesses too;
  scores cannot identify the right rotation from shape alone. Bare hashes, numeric answers and other
  unwrapped formats are not automatically flags. Other modules have their own format/length limits;
  `autosolve` and `revauto` offer `--flag-format` for a contest-specific regex.
- **Pasted text:** the tool does not understand prose, but it now tries embedded base64/hex-shaped
  tokens in descriptions and ordinary text files. This is bounded to eight distinct tokens, 12-4096
  alphabet characters each (plus base64 padding), within the first 200KiB. If a blob is missed or a limit is reported, copy ONLY that
  token: `go --text "SGVsbG8="` (or `decode "SGVsbG8="`). Token hints are not proof of a decode.
  Whole-input decoding is still tried first. Full decoded flags remain visible even beyond a truncated preview.
- **Safety:** the menu only waits for your choice; nothing runs by itself and nothing uses the network. But `go` on a
  `.py` file, or on a folder containing `.py` files, runs the script through guarded `pyrun --run` (never
  `--force`): review the code first, use non-hostile CTF scripts only, the sandbox is not a security boundary,
  the network is blocked, and `pyrun` refuses scripts its scan flags. `go` prints a warning before the prompt
  and a notice right before that step.

Honest limits: `asmeval` only evaluates a whitelist of instructions; unknown inputs, outside calls or
unsupported instructions give a **PARTIAL** result, not a guess. Its numeric register values (e.g. `eax = 0x2a`)
sometimes need manual wrapping in the contest's required flag format, such as `picoCTF{0000002a}`; check the task
statement. `pyrun` reads a script before anything runs; `--run` is refused when the scan finds
network/subprocess/obfuscation, executes in a no-network sandbox with resource limits, and is a guard rail for
non-hostile challenge scripts, not a security boundary.

## Run
Run from the `toolkit/` directory (or prefix paths with `toolkit/`).
```
python3 recon.py                    # interactive numbered menu
python3 recon.py triage ./binary    # run one module directly
python3 recon.py triage ./binary -n 8 --no-strings
python3 recon.py --selftest         # run all module self-tests
python3 recon.py <module> selftest  # run one module's self-test (`--selftest` also accepted)
python3 recon.py <module> -h        # module usage (exit 0)
python3 modules/<module>.py [args]  # every module also runs standalone, same CLI
```
The interactive menu is grouped by category with a colored banner and headers (colors only on a TTY with `NO_COLOR` unset; piped and direct CLI output is unchanged).
UI regression tests (stdlib `unittest`, offline): `python3 -m unittest discover -s tests` from `toolkit/`.

Exit codes everywhere: `0` success, `1` runtime/analysis failure (bad input, file missing, not found),
`2` usage error. Self-test output: the global run prints one `[PASS]`/`[FAIL]` line per module and
`N/N modules passed`, exiting non-zero on any failure.

## Modules
| name | description |
|------|-------------|
| triage | magic-byte file type, size, md5/sha1/sha256, ASCII + UTF-16LE strings (`-n` min length), overall/per-section entropy with packed heuristic, ELF headers + NX/PIE/canary/RELRO/FORTIFY, basic PE headers |
| decode | decode/encode base64/base32/base58/hex/url/binary/decimal/octal/ascii, multi-round auto-decode, rot/caesar brute-force, atbash, vigenere (known key), single-byte XOR brute-force, repeating-key XOR, cipher-ID hints. `recon.py decode <text \| -f file>`; `--rot 5` or `--rot=5` for a shift, bare `--rot` brute-forces |
| disasm | x86/x64 ELF `.text` / range / entry disassembly (capstone optional, hex fallback), call + string xrefs, syscall lookup, opcode table, objdump/r2 external-tool mode. `recon.py disasm <text\|range\|entry\|xrefs\|syscall\|opcodes\|ext\|selftest> ...` |
| crypto | frequency analysis (chi², IC), repeating-key XOR break, keyless Vigenere break, ECB block-repeat detect, substitution helper, RSA lane (`crypto rsa --n/--e/--c` or `-f FILE` auto-parse; tries known p/q, dp/dq leak, small-n factoring (trial + Fermat), small-e exact root, Wiener; prints m hex+ascii with flag highlight, or the attacks tried + manual next steps). `recon.py crypto <freq\|xor\|vigenere\|ecb\|subst\|rsa\|selftest> ...` |
| forensics | pcap/pcapng parse, TCP stream reassembly, HTTP objects (`--extract`), keyword hunt (`--flags`), per-stream payload strings (TCP by seq / UDP by time; flag-shaped first, printed after the packet list), `forensics carve <file>` (printable runs + flag-shaped strings from any file's raw bytes), JPEG EXIF / PNG chunks / PDF scan (`--meta`), magic-header repair (`--repair TYPE -o OUT`). `recon.py forensics <file> [flags]` |
| binextras | De Bruijn cyclic pattern + offset find, ROP gadget scan (ropper/ROPgadget optional), binwalk-style signature scan + carve, recursive embedded-archive extraction (`extract <file> -o OUTDIR`: zip via central directory, gzip via stream decode, embedded png/jpg; recurses depth<=10 with sha256 loop guard, prints a tree + highlights flag-shaped strings; never overwrites), pack/unpack, hexdump. `recon.py binextras <cyclic\|cyclic-find\|gadgets\|scan\|carve\|extract\|hexdump\|selftest> ...` |
| hashid | identify a hash by format marker/length (`$1$/$2y$/$6$/$y$`, NTLM pwdump lines, MySQL/Django/phpass prefixes, raw hex 32/40/64/...) and offline dictionary-crack unsalted md5/sha1/sha256/sha512/NTLM against a local wordlist (default Kali `rockyou.txt`, never downloaded) with optional case/leet/suffix mangling rules; bcrypt/yescrypt/sha*crypt are identify-only unless `bcrypt`/`passlib` happens to be installed. `recon.py hashid id <hash>` / `recon.py hashid crack <hash> [--wordlist PATH] [--rules]` |
| shellcode | badchar offset checker, XOR/rolling-key encoder (auto-finds a badchar-free key, emits an annotated decoder-stub text + alphanumeric-safe hint), hex/`\x`-escaped/C-array/python-bytes format converters, curated known static stubs (execve/bin/sh, exit) disassembled via `disasm`. Pure byte math -- no assembling, no execution. `recon.py shellcode <badchars\|encode\|fmt\|stub\|selftest> ...` |
| batch | directory auto-triage: runs `triage` detection per file and routes via the registry (ELF -> protections + disasm entry; pcap -> forensics summary; PNG/JPEG/PDF -> forensics metadata; zip/tar/gzip -> member list; text/unknown -> strings + `decode` auto-decode), flag/keyword hunt, ranked table (flag hits > keywords > entropy/magic). `recon.py batch <dir\|file> [--quick] [--json] [-r]` |
| gdbkit | gdb/gef/pwndbg copy-paste recipes for CTF moves (break main, find win, GOT/PLT, pattern offset, tele/heap/vmmap, memory search, arg dereference; gef & pwndbg variants side by side), searchable, plus a `gdb -x` batch-script generator (args, breakpoints, per-bp commands, run, auto-dump) and an optional external-tool mode that runs it via a local `gdb` only if on PATH (never required, no network). `recon.py gdbkit <list\|show\|find\|script\|run-gdb\|selftest> ...` |
| elfpatch | write-side ELF patching, always to a new `-o` file (in-place refused without `--force`): patch bytes at a vaddr/file offset, NOP a range, flip a conditional jump (je↔jne…), redirect the entry point, dump/replace a named section; warns when a patch lands outside a known section. Reuses `disasm.parse_elf`/`vaddr_to_offset`. `recon.py elfpatch <patch\|nop\|flip\|entry\|dump\|replace\|selftest> <elf> --at 0x.. ... -o out` |
| webkit | offline web-challenge helpers: JWT decode (header/payload/signature, no verification), `alg:none` detection, weak-HMAC-secret crack over a local wordlist (reuses `hashid`'s wordlist handling); deterministic path/param fuzz-wordlist generator from a seed (dirs/extensions/case variants) for feeding a *local* fuzzer; base64url encode/decode, Flask/itsdangerous session structure decode (no secret), common hash of a value. **No HTTP is ever performed.** `recon.py webkit <jwt\|wordlist\|cookie\|selftest> ...` |
| exploitnotes | searchable, embedded offline pwn/RE cheatsheet (nothing read from disk): ret2win, ret2libc/ret2system, ROP chain assembly order + SysV calling convention, format-string read/write primitives and `%N$x` offset math, stack-canary leak patterns, GOT overwrite, heap tcache-dup/fastbin-dup notes, one-gadget constraints, common syscall sequences (execve, ORW, mprotect+shellcode). Pure reference -- complements `gdbkit` (commands) and `pwnhelp` (computation). `recon.py exploitnotes [keyword\|list\|show <key>\|selftest]` |
| pwnhelp | exploitation arithmetic: `p64`/`u64`/`p32`/`u32` packing, format-string offset finder (locates the controlled `%N$p` position from a leaked `%p` dump + known marker), local-libc symbol-table reader (`.dynsym`/`.symtab`) with libc-base-from-leak / symbol-or-raw-offset (one-gadget) / `"/bin/sh"` runtime-address math, GOT/PLT lister (`.rela.plt` symbol -> GOT slot, built on `disasm.parse_elf`). Reads only a *local* libc/ELF file, never downloads one. `recon.py pwnhelp <pack\|unpack\|fmtoffset\|symbols\|libcbase\|libcaddr\|binsh\|gotplt\|selftest> ...` |
| apk | offline Android static analysis via stdlib `zipfile`: confirms `AndroidManifest.xml`, extracts strings from `classes*.dex`/`resources.arsc`/`res`/`assets`, dumps `META-INF` + signing-cert blocks (SHA-256, DN strings), keyword + URL hunt (reuses `forensics.find_keywords`). If `apktool`/`jadx` are on PATH the exact command is only *suggested* (never run, never downloaded). `recon.py apk <file.apk> [--strings] [--certs]` |
| stego | offline hidden-data finder: LSB extraction from PNG/BMP (stdlib `zlib`/`struct`, optional `PIL` for other formats; configurable channels/bits, bit order), appended/trailing-bytes detection after PNG IEND / JPEG EOI / GIF trailer / BMP size, polyglot + embedded-archive carve (reuses `binextras.MAGICS`, local fallback table), bit-plane ASCII dump, palette anomaly report. Complements `forensics` (metadata). `recon.py stego <img> [--lsb] [--append] [--carve] [--palette] [--plane N]` |
| revauto | automated RE analyst: auto-detects and unwraps obfuscated Python/JS/shell layers (base64/zlib/hex/char-code/lambda/marshal/pickle/packer/pipe-to-sh) with pure transforms only -- never executes the payload; labels every function/block with what it does (network, file, exec, crypto, persistence, ...), IOCs, tells with line refs, flag-checker solver; ELF/PE digest via radare2 (r2pipe or r2 -2 subprocess) or ghidra analyzeHeadless when present, else a stdlib fallback (protections, imports by category, functions, strings+xrefs, crypto constants, anti-debug, syscalls). `recon.py revauto <file\|-> [--deep] [--json] [--engine auto\|r2\|ghidra\|none] [--dump-layers DIR]` |
| autosolve | flag-checker auto-solver: finds success/failure verdict strings and their references (x64 RIP-relative, absolute imm32, i386 push), traces back to the deciding branch, walks the checker with a built-in x86 decoder (capstone optional, presentation only) to extract ordered constraints (length, byte compares, xor/add/sub/rol chains, table lookups, strcmp/memcmp literals), prints the derived flag with confidence + static re-walk verification, or the exact jcc patch with ready elfpatch commands, or next steps; optional angr lane (runtime-detected, timeout-bounded child). Never executes the target. `recon.py autosolve [find-verdicts\|trace\|constraints\|listing\|solve\|patch\|angr] <elf> [--success RE] [--fail RE] [--json] [--deep] [--no-angr]` |
| asmeval | static x86 + AArch64 assembly evaluator (AT&T + Intel; `.S`/`.asm`, gdb `disassemble`, objdump text): from-scratch interpreter over a whitelist (mov/movzx/movsx, add/sub/imul, xor/and/or/not/neg, shifts/rotates, cmp/test, lea, push/pop, inc/dec, xchg, jcc/jmp, call/ret to in-file targets). AArch64 lane auto-selected for `.S` files with xN/wN registers (picoCTF ARMssembly): x0-x30/w0-w30/sp/NZCV; stp/ldp (pre/post-index), ldr/str, mov/movz/movk/movn, add/sub/adds/subs/cmp (optional shifts), and/orr/eor, lsl/lsr/asr, mul/sdiv/udiv, b/b.cond/cbz/cbnz/bl/ret; `--arg` maps to w0, w1, ... and the result is w0/x0. Unknown inputs stay unknown; unsupported instruction, outside call, unknown-flag branch or step cap (default 100k) -> labelled **PARTIAL** result with last known registers, exit 3. Never assembles or executes. `recon.py asmeval <file> [--arg N ...] [--func NAME] [--init REG=VAL] [--max-steps N] [--regs]` |
| vaultdoor | static solver for picoCTF vault-door `VaultDoor*.java`: parses the source with a mini Java parser and evaluates `checkPassword` with its own interpreter (int/char/byte wrap, arrays, String/StringBuilder, `parseInt(s, radix)`, `String.format`, Base64, `Arrays.equals`), observes every equality comparison and solves the password per character (literal compares, charAt constraints, permutations, XOR/arith loops, int packing, bit swaps, hex/url/base64 chains). Prints password + `picoCTF{...}` with a confidence tag (HIGH = own evaluator accepts it). No javac/JVM, never runs the source. `recon.py vaultdoor <VaultDoorN.java> [--length N] [--budget SECS]` |
| pyrun | guarded script-execution lane for "run this Python script" challenges. Phase 1 (default, never executes): AST report of imports, network/subprocess/shell/eval/exec calls, out-of-cwd writes, base64/hex blobs, and statically derived passwords (literal compares, folded chr/ord/arithmetic, `str_xor`-style decrypt) with HIGH/MEDIUM/LOW tags. Phase 2 (`--run`): REFUSES (exit 2) on network/subprocess/shell/out-of-cwd-write/obfuscated-import findings or a syntax error (`--force` overrides with a loud warning, never the network block); runs in a child interpreter in a fresh tempdir with socket monkeypatch, CPU/AS/FSIZE rlimits, wall-clock `--timeout` (exit 124); `--input TEXT` / `--auto-input`; `[FLAG?]` scan of output. A guard rail for non-hostile scripts, not a security boundary. `recon.py pyrun <script> [--run] [--force] [--timeout S] [--input T] [--auto-input]` |
| go | one-command front door: `recon.py go <file-or-dir> [--arg N ...] [--text "description"] [--step-timeout S] [--budget S] [-v]`. Always runs `triage` first, then routes by type (`.java` -> vaultdoor; asm text -> asmeval with `--arg` and zero-arg; `.py` -> `pyrun --run --auto-input`, never `--force`; ELF -> autosolve + revauto; pcap -> forensics; PNG/JPEG/PDF/data -> forensics + `binextras extract` into a fresh tempdir with every extracted file flag-scanned raw and as utf-16-le; archives -> extract; text -> `decode -f` up to 200KB). `--text` runs `decode` on the description and `decode -f` on each flag-shaped token. In-process via the registry, per-step timeout (default 20s) and total budget (default 180s). Ends with a ranked, deduped `== FLAG CANDIDATES ==` list tagged by step, a `== DERIVED INPUTS / REGISTER RESULTS ==` section (exact autosolve/pyrun/asmeval evidence with source and confidence; not flags), then one status line per step and, if nothing was found, next-step hints; exit 0 if any flag candidate, else 1. |

## Adding a module
Drop `modules/<name>.py` defining `NAME`, `DESCRIPTION`, `run(args) -> int`, `selftest() -> bool`.
It is discovered automatically (see `modules/__init__.py`).
