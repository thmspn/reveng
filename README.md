# RE toolkit (offline)

Helper scripts for CTF reversing (ELF crackmes, packed/obfuscated binaries).
**100% offline**: no network calls, no telemetry, no runtime installs. Python 3 standard library only.

## Requirements
Python 3.9+ (Kali default is fine). Standard library first; optional libs (capstone, pyelftools, pwntools)
are only used via guarded `try/except ImportError` imports with a stdlib fallback (today: `disasm` uses
capstone when present, hex view otherwise). External tools (objdump, r2, ropper, ROPgadget) are opt-in
"external-tool mode", gated by `shutil.which`.

## Run
```
python3 recon.py                    # interactive numbered menu
python3 recon.py triage ./binary    # run one module directly
python3 recon.py triage ./binary -n 8 --no-strings
python3 recon.py --selftest         # run all module self-tests
python3 recon.py <module> selftest  # run one module's self-test
python3 recon.py <module> -h        # module usage (exit 0)
```

## Modules
| name | description |
|------|-------------|
| triage | magic-byte file type, size, md5/sha1/sha256, ASCII + UTF-16LE strings (`-n` min length), overall/per-section entropy with packed heuristic, ELF headers + NX/PIE/canary/RELRO/FORTIFY, basic PE headers |
| decode | decode/encode base64/base32/base58/hex/url/binary/decimal/octal/ascii, multi-round auto-decode, rot/caesar brute-force, atbash, vigenere (known key), single-byte XOR brute-force, repeating-key XOR, cipher-ID hints. `recon.py decode <text \| -f file>`; `--rot 5` or `--rot=5` for a shift, bare `--rot` brute-forces |
| disasm | x86/x64 ELF `.text` / range / entry disassembly (capstone optional, hex fallback), call + string xrefs, syscall lookup, opcode table, objdump/r2 external-tool mode. `recon.py disasm <text\|range\|entry\|xrefs\|syscall\|opcodes\|ext\|selftest> ...` |
| crypto | frequency analysis (chi², IC), repeating-key XOR break, keyless Vigenere break, ECB block-repeat detect, substitution helper. `recon.py crypto <freq\|xor\|vigenere\|ecb\|subst\|selftest> ...` |
| forensics | pcap/pcapng parse, TCP stream reassembly, HTTP objects (`--extract`), keyword hunt (`--flags`), JPEG EXIF / PNG chunks / PDF scan (`--meta`), magic-header repair (`--repair TYPE -o OUT`). `recon.py forensics <file> [flags]` |
| binextras | De Bruijn cyclic pattern + offset find, ROP gadget scan (ropper/ROPgadget optional), binwalk-style signature scan + carve, pack/unpack, hexdump. `recon.py binextras <cyclic\|cyclic-find\|gadgets\|scan\|carve\|hexdump\|selftest> ...` |

## Adding a module
Drop `modules/<name>.py` defining `NAME`, `DESCRIPTION`, `run(args) -> int`, `selftest() -> bool`.
It is discovered automatically (see `modules/__init__.py`).
