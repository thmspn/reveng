# Master Module Plan — Offline CTF RE Toolkit

Planning artifact for `toolkit/`. Sonnet-run issues implement one module per PR
against this plan. **No module code lives in this PR.**

Target event: CyberSci regionals, **Nov 21** — 4-hour jeopardy CTF (reversing,
crypto, forensics, web). Target host: Kali VM, Python 3, stdlib-first.

## Hard constraints (non-negotiable)

- **100% offline.** No network, no API, no telemetry, no runtime `pip install`.
  Anything that would reach the network (rockyou lookup, jadx, gdb) runs a
  **local** binary already on Kali or reads a **local** wordlist path — never
  downloads.
- **Stdlib first.** `capstone`, `pyelftools`, `pwntools`, `PIL` etc. are
  optional only, imported in `try/except` with a working stdlib fallback and a
  clear "install X for richer output" note.
- Every module plugs the registry contract and passes `recon.py --selftest`.

## Registry contract (already shipped — design to it exactly)

Each `modules/<name>.py` exposes module-level:

| name | type | meaning |
|------|------|---------|
| `NAME` | `str` | short CLI name, unique, lower-case |
| `DESCRIPTION` | `str` | one line shown in the menu |
| `run(args: list[str]) -> int` | callable | entry point, returns process exit code |
| `selftest() -> bool` | callable | `True` when every internal check passes |

`modules/__init__.py:discover()` auto-registers any submodule exposing all four.
`recon.py` drives three entry paths: interactive menu, `recon.py <name> [args]`,
and `recon.py --selftest`. A new module needs **zero** changes to `recon.py` —
just drop the file in `modules/`.

## Already built / in flight — DO NOT re-plan; design around

| module | status | owns |
|--------|--------|------|
| `triage` | merged (PR #6 scaffold) | file type, hashes, strings, entropy, ELF/PE headers + checksec-style protections |
| `decode` | merged | base-N / hex / url / rot / atbash / vigenere(key) / XOR brute, multi-round auto-decode |
| `disasm` | merged | x86/x64 ELF `.text` disasm (capstone-opt), entry, call/string xrefs, syscall + opcode tables, objdump/r2 shell-out |
| `crypto` | merged | freq analysis, repeating-XOR / Vigenere break, ECB detect, substitution helper |
| `forensics` | merged | pcap parse / TCP streams / HTTP objects / keyword hunt, JPEG-EXIF / PNG / PDF metadata, magic-header repair |
| `binextras` | in flight | cyclic patterns, ROP gadget finder, binwalk-style carving |

**Boundary rules so the expansion does not collide:**
- Shellcode work goes in `shellcode` (new), not `disasm`. `disasm` reads;
  `shellcode` produces/encodes bytes.
- Hash **identification + cracking** goes in `hashid` (new). `triage` keeps
  *file* hashing; `hashid` handles *credential* hashes.
- ELF **modification** goes in `elfpatch` (new). `disasm`/`triage` stay
  read-only.
- Carving stays in `binextras`. `batch` (new) orchestrates existing modules;
  it never re-implements their logic — it imports and calls them.

---

## Expansion tiers

Priority = competition value per hour of a 4-hour CTF. **P0** = points we will
almost certainly leave on the table without it. **P1** = strong value, common
category. **P2** = nice-to-have / narrower.

### Priority table

| # | module | prio | one-liner | depends on |
|---|--------|------|-----------|-----------|
| 1 | `batch` | **P0** | auto-triage a whole challenge directory, routing each file to the right module | triage, forensics, disasm |
| 2 | `hashid` | **P0** | identify hash type + offline dictionary crack (rockyou path on Kali) | — |
| 3 | `shellcode` | **P0** | badchar checker, XOR/alnum encoder, hex↔raw, skeleton stubs | disasm (tables) |
| 4 | `gdbkit` | **P1** | emit ready-to-paste gdb / gef / pwndbg command recipes + a scripted run driver | — |
| 5 | `elfpatch` | **P1** | byte/NOP/jump patching, entry redirect, section dump/replace | triage, disasm |
| 6 | `webkit` | **P1** | JWT decode + alg-none/weak-secret check, offline fuzz/wordlist gen, hash/cookie helpers | hashid |
| 7 | `exploitnotes` | **P1** | searchable offline cheatsheet: ROP/ret2libc/fmt-string/heap recipes, syscall & one-gadget hints | — |
| 8 | `pwnhelp` | **P2** | format-string offset finder, GOT/PLT lister, libc-offset calculator from a local libc | disasm, elfpatch |
| 9 | `apk` | **P2** | unzip APK, dump manifest/strings/certs, optional apktool/jadx shell-out | triage |
| 10 | `stego` | **P2** | LSB extract, appended-data / polyglot finder, bit-plane + palette dumps | forensics |

---

### 1. `batch` — P0 — directory auto-triage

**Spec.** Point it at a directory of challenge files and get a per-file verdict
in one pass: `recon.py batch ./chal/`. For each file it runs `triage` detection,
then routes: ELF → disasm entry + protections summary; pcap → forensics summary;
image/PDF → forensics `--meta`; archive → list contents; text/unknown → strings +
`decode` auto-decode attempt. Imports the other modules through the registry
(`from modules import discover`); it must **not** duplicate their parsing. Output
is a compact ranked table (most "interesting" first by entropy / known magic /
flag-keyword hits) plus an optional `--json` for scripting. Honors a `--quick`
flag (skip disasm) for speed.

**Acceptance (selftest proves).** Builds a temp dir containing a tiny ELF, a
PNG, a text blob with a `flag{...}` substring, and a gzip; asserts batch
classifies all four correctly, that the flag-bearing file is surfaced/ranked,
and that `--json` emits parseable JSON. Runs fully offline, tolerates an
unreadable/zero-byte file without crashing.

### 2. `hashid` — P0 — hash ID + offline dictionary crack

**Spec.** Two jobs. (a) **Identify:** given a hash string, rank candidate
algorithms by length/charset/format markers (`$1$`,`$2y$`,`$6$`, raw hex
lengths 32/40/64, `:` salted forms, NTLM, MySQL, Django/PHPass prefixes).
(b) **Crack:** dictionary attack over a local wordlist for the fast unsalted
families stdlib can do (md5, sha1, sha256, sha512, ntlm via `hashlib`, plus
optional mangling rules: case, leet, append digits). Default wordlist path is
Kali's `/usr/share/wordlists/rockyou.txt` (**read local file only**, never
download; gracefully report if absent and accept `--wordlist PATH`). bcrypt/
yescrypt are **identify-only** unless `passlib`/`bcrypt` is importable, in which
case verify a candidate — clearly marked optional. CLI:
`recon.py hashid id <hash>` / `recon.py hashid crack <hash> [--wordlist P] [--rules]`.

**Acceptance.** selftest: feeds known digests of a short word and asserts the
cracker recovers it from a tiny embedded wordlist (no external file); asserts
`id` returns the correct top candidate for one sample each of md5/sha1/sha256/
NTLM/`$6$`. Confirms missing-wordlist path yields a clean error, not a crash.

### 3. `shellcode` — P0 — shellcode utilities

**Spec.** The payload-side companion to `disasm`. Features: **badchar check** —
given raw bytes (hex/`\x`/file) and a badchar set, report which offsets contain
forbidden bytes; **encoders** — single/rolling XOR encoder emitting a tiny
self-decoding stub, plus an alphanumeric-safe hint path; **format converters** —
hex ↔ raw ↔ `\x` ↔ C array ↔ Python bytes; **length + null report**; and a
curated set of **known static stubs** (e.g. x86-64 `execve("/bin/sh")`) as
reference bytes with their disassembly from the `disasm` opcode table. All
transforms are pure byte math — no execution. CLI subcommands:
`badchars`, `encode`, `fmt`, `stub`, `selftest`.

**Acceptance.** selftest: round-trips a sample through every format converter
(`raw→hex→raw` identity); XOR-encodes a buffer with a key containing no
badchars and asserts the encoded output is badchar-free and decodes back;
`badchars` correctly flags a planted `\x00`/`\x0a`. No network, no process
exec.

### 4. `gdbkit` — P1 — gdb / gef / pwndbg recipes + driver

**Spec.** Two modes. (a) **Cheatsheet:** print copy-paste command recipes for
common CTF moves — break at main, find the win function, dump GOT/PLT, pattern
create/offset, `tele`/`heap`/`vmmap` (gef & pwndbg variants side by side),
search memory, dereference args. Searchable: `recon.py gdbkit find <keyword>`.
(b) **Driver:** generate a `gdb -x` batch script from a template (set args,
breakpoints, commands, `run`, auto-dump) and, if `gdb` is on PATH, optionally
execute it against a local target — shell-out only, clearly "external-tool
mode", never required. No gdb needed for the cheatsheet half.

**Acceptance.** selftest (no gdb assumed): asserts the recipe store is
non-empty, that `find` returns matching entries for a known keyword (e.g.
"offset"), and that the generated batch script is well-formed text containing
the requested breakpoints. External execution path is skipped when `gdb`
absent, and that skip is asserted to be graceful.

### 5. `elfpatch` — P1 — ELF patching

**Spec.** Read-write counterpart to the read-only `disasm`/`triage`. Operations
on a local ELF: patch bytes at a vaddr or file offset (`--at 0x... --bytes
90909090`), NOP-out a range, flip a conditional jump (je↔jne etc.), redirect
entry point, and dump/replace a named section. Always writes to a **new output
file** (`-o`), never in place by default. Reuses `disasm.parse_elf` /
`vaddr_to_offset` via import rather than re-parsing. Warns (does not block) when
a patch lands outside a known section. CLI:
`recon.py elfpatch nop <elf> --at 0x.. --len N -o out` etc.

**Acceptance.** selftest: builds a tiny ELF (reuse `disasm.build_test_elf`),
patches a known byte, reloads and asserts the byte changed and the rest is
byte-identical; asserts a jump-flip toggles the opcode; asserts vaddr↔offset
mapping agrees with `disasm`; asserts in-place is refused without explicit
`--force`.

### 6. `webkit` — P1 — web-category helpers

**Spec.** Offline web-challenge toolbox. **JWT:** decode header/payload/sig
without verifying, flag `alg:none`, and brute a weak HMAC secret against a small
local wordlist (delegates to `hashid` crack core). **Wordlist/fuzz gen:**
produce path/param candidate lists from a seed (extensions, common dirs, case
variants) for use with a *local* tool — the module only generates, never sends
requests (offline rule). **Cookie/encoding helpers:** base64url, Flask session
*structure* decode (no secret), common hash of a value. CLI subcommands
`jwt`, `wordlist`, `cookie`. **No HTTP is ever performed by this module.**

**Acceptance.** selftest: decodes a known JWT to expected claims, detects an
`alg:none` token, recovers a weak HMAC secret from an embedded wordlist;
asserts wordlist gen is deterministic and contains seeded entries; confirms the
module makes zero socket calls (no network import used for I/O).

### 7. `exploitnotes` — P1 — offline exploitation cheatsheet

**Spec.** A searchable, embedded knowledge base (data baked into the module, no
files to ship) covering the recipes a 4-hour pwn/RE run rewards: ret2win,
ret2libc / ret2system, ROP chain assembly order, format-string read/write
primitives and offset math, stack-canary leak patterns, GOT overwrite, basic
heap (tcache dup, fastbin) notes, one-gadget constraints, common syscall
sequences. `recon.py exploitnotes <keyword>` fuzzy-searches titles+tags;
bare invocation lists topics. Pure reference — complements `gdbkit`
(commands) and `pwnhelp` (computation).

**Acceptance.** selftest: asserts the KB has entries across all core topics,
that search returns the right topic for several keywords (e.g. "canary",
"format", "ret2libc"), and that every entry has non-empty title/body/tags.
Fully offline, no external files.

### 8. `pwnhelp` — P2 — exploitation computation

**Spec.** The arithmetic `exploitnotes` describes. Format-string **offset
finder** (given a leaked `AAAA....%p.%p...` dump, locate the controlled
position); **libc base / symbol offset** calculator from a *local* libc file
(read ELF symbol table, compute `system`/`/bin/sh`/one-gadget deltas from a
leaked address) — local file only; **GOT/PLT lister** (import from `disasm`);
packing helpers (`p64`/`u64` stdlib struct wrappers). CLI subcommands per task.

**Acceptance.** selftest: asserts `p64`/`u64` round-trip; feeds a synthetic
format-string dump with a known marker and asserts the correct offset is found;
builds/loads a tiny ELF with a symbol and asserts offset math is correct;
confirms missing-libc path errors cleanly.

### 9. `apk` — P2 — Android static analysis

**Spec.** APK is a ZIP: unpack with stdlib `zipfile`, list the manifest
presence, extract readable strings from `classes*.dex` and resources, dump
embedded certs/`META-INF`, and surface URLs/secrets via keyword hunt (reuse
`forensics` keyword logic). Optional **external-tool mode**: if `apktool`/`jadx`
are on PATH, offer the exact command to run — shell-out only, never required,
never auto-downloaded. CLI: `recon.py apk <file.apk> [--strings] [--certs]`.

**Acceptance.** selftest: builds a tiny in-memory ZIP mimicking an APK
(`AndroidManifest.xml` + a fake dex blob containing a `flag{...}` string),
asserts the module lists the manifest, extracts the planted string, and that
the jadx/apktool shortcuts are only suggested when those tools exist. Offline.

### 10. `stego` — P2 — stego / hidden data

**Spec.** Offline hidden-data finder for forensics/misc. LSB extraction from
PNG/BMP (stdlib + optional `PIL`), appended-data / trailing-bytes after image
EOF, polyglot / embedded-archive detection (reuse `binextras` carving signatures
if available, else local signature scan), bit-plane dump and palette anomaly
report. CLI: `recon.py stego <img> [--lsb] [--append] [--carve]`. Complements
`forensics` (metadata) — this one digs into pixel/byte content.

**Acceptance.** selftest: generates a small image with a known message hidden in
LSBs and asserts recovery; appends bytes after a PNG IEND and asserts detection;
confirms graceful behavior without `PIL`. Offline, no external files.

---

## Quality bar (every module must meet)

- **CLI consistency.** Subcommand-style modules (`disasm`, `crypto`) and
  flag-style modules (`forensics`) both exist today; new modules **pick the
  style that fits and stay internally consistent**. Required across all:
  bare/`-h`/`--help` prints usage and returns `0`; unknown subcommand prints
  usage and returns `2`; a `selftest` path reachable both as `recon.py <m>
  selftest` *and* via the global `recon.py --selftest`.
- **Exit codes.** `0` success, `1` runtime/analysis failure (bad input, missing
  optional dependency that was required for the asked task), `2` usage error.
- **Error handling.** No stack traces to the user. Wrap file I/O and parsing in
  `try/except (OSError, ValueError, <ParseError>)`, print `error: <msg>` to
  stderr, return non-zero. A crashing path is a selftest failure, not a toolkit
  crash (the runner already isolates each module).
- **Offline proof.** Any module that *could* touch the network
  (`hashid`, `webkit`, `apk`, `gdbkit`) must have a selftest assertion or code
  comment making clear no socket I/O occurs; external binaries are opt-in
  "external-tool mode" guarded by `shutil.which`.
- **Optional deps.** `try/except ImportError` with a stdlib fallback and a
  one-line "install X for richer output" notice. Never hard-fail on a missing
  third-party lib.
- **Type hints + docstrings** on public functions; no placeholder/`pass` stubs.
- **Self-contained selftests.** Build fixtures in-memory or in a temp dir; never
  depend on files outside the repo (no reliance on rockyou being present).
- **Input hygiene.** Treat all analyzed files as untrusted data — parse
  defensively, bound loops, cap memory on huge inputs.

## Menu / README scaling (for a growing module count)

- **Menu grouping.** As the list grows past ~8, `recon.py`'s flat numbered menu
  gets unwieldy. Plan a lightweight `CATEGORY` optional module attribute
  (`"recon" | "crypto" | "exploit" | "forensics" | "web"`); the menu groups by
  category when present and falls back to flat for modules without it. This is
  **backward compatible** — `discover()` stays unchanged, the menu just reads an
  optional attribute. (Spin this as its own tiny scaffold PR before the P1 tier
  lands.)
- **README table** stays the single source of truth: one row per module
  (`name | category | description`), kept alphabetical within category. Each
  module PR adds its own row — reviewers reject a module PR that doesn't.
- **Discoverability.** Add a `recon.py --list` (names + one-liners, no menu) and
  keep `--selftest` output as the at-a-glance health check. A future `recon.py
  help <module>` can just call the module's help path.
- **Selftest as CI gate.** `recon.py --selftest` returning `0` is the merge
  gate for every module PR; the growing count is self-documenting through it.

## Suggested implementation order (for the sonnet issues)

1. `batch`, `hashid`, `shellcode` (the P0 tier — immediate scoring leverage).
2. Menu `CATEGORY` scaffold (tiny, unblocks grouping).
3. `gdbkit`, `elfpatch`, `webkit`, `exploitnotes` (P1).
4. `pwnhelp`, `apk`, `stego` (P2, as time allows before Nov 21).

One module per PR, each green under `recon.py --selftest`, each adding its
README row. Design around the six existing modules; import, don't duplicate.
