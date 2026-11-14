# RE toolkit (offline)

Helper scripts for CTF reversing (ELF crackmes, packed/obfuscated binaries).
**100% offline**: no network calls, no telemetry, no runtime installs. Python 3 standard library first.
Design, module boundaries and the quality bar every module meets are in [`PLAN.md`](PLAN.md).

## Requirements
Python 3.9+ (Kali default is fine). Standard library first; optional libs (capstone, pyelftools, pwntools)
are only used via guarded `try/except ImportError` imports with a stdlib fallback (today: `disasm`/`shellcode` use
capstone when present, hex view otherwise; `hashid` verifies bcrypt/sha*crypt only if `bcrypt`/`passlib` is present). External tools (objdump, r2, ropper, ROPgadget) are opt-in
"external-tool mode", gated by `shutil.which`.

## Run
```
python3 recon.py                    # interactive numbered menu
python3 recon.py triage ./binary    # run one module directly
python3 recon.py triage ./binary -n 8 --no-strings
python3 recon.py --selftest         # run all module self-tests
python3 recon.py <module> selftest  # run one module's self-test (`--selftest` also accepted)
python3 recon.py <module> -h        # module usage (exit 0)
python3 modules/<module>.py [args]  # every module also runs standalone, same CLI
```
Exit codes everywhere: `0` success, `1` runtime/analysis failure (bad input, file missing, not found),
`2` usage error. Self-test output: the global run prints one `[PASS]`/`[FAIL]` line per module and
`N/N modules passed`, exiting non-zero on any failure.

## Modules
| name | description |
|------|-------------|
| triage | magic-byte file type, size, md5/sha1/sha256, ASCII + UTF-16LE strings (`-n` min length), overall/per-section entropy with packed heuristic, ELF headers + NX/PIE/canary/RELRO/FORTIFY, basic PE headers |
| decode | decode/encode base64/base32/base58/hex/url/binary/decimal/octal/ascii, multi-round auto-decode, rot/caesar brute-force, atbash, vigenere (known key), single-byte XOR brute-force, repeating-key XOR, cipher-ID hints. `recon.py decode <text \| -f file>`; `--rot 5` or `--rot=5` for a shift, bare `--rot` brute-forces |
| disasm | x86/x64 ELF `.text` / range / entry disassembly (capstone optional, hex fallback), call + string xrefs, syscall lookup, opcode table, objdump/r2 external-tool mode. `recon.py disasm <text\|range\|entry\|xrefs\|syscall\|opcodes\|ext\|selftest> ...` |
| crypto | frequency analysis (chi², IC), repeating-key XOR break, keyless Vigenere break, ECB block-repeat detect, substitution helper. `recon.py crypto <freq\|xor\|vigenere\|ecb\|subst\|selftest> ...` |
| forensics | pcap/pcapng parse, TCP stream reassembly, HTTP objects (`--extract`), keyword hunt (`--flags`), JPEG EXIF / PNG chunks / PDF scan (`--meta`), magic-header repair (`--repair TYPE -o OUT`). `recon.py forensics <file> [flags]` |
| binextras | De Bruijn cyclic pattern + offset find, ROP gadget scan (ropper/ROPgadget optional), binwalk-style signature scan + carve, pack/unpack, hexdump. `recon.py binextras <cyclic\|cyclic-find\|gadgets\|scan\|carve\|hexdump\|selftest> ...` |
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


## Adding a module
Drop `modules/<name>.py` defining `NAME`, `DESCRIPTION`, `run(args) -> int`, `selftest() -> bool`.
It is discovered automatically (see `modules/__init__.py`).
