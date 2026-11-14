# RE toolkit (offline)

Helper scripts for CTF reversing (ELF crackmes, packed/obfuscated binaries).
**100% offline**: no network calls, no telemetry, no runtime installs. Python 3 standard library only.

## Requirements
Python 3.9+ (Kali default is fine). Optional libs (capstone, pyelftools, pwntools) may be used by future
modules only via guarded imports with a stdlib fallback.

## Run
```
python3 recon.py                    # interactive numbered menu
python3 recon.py triage ./binary    # run one module directly
python3 recon.py triage ./binary -n 8 --no-strings
python3 recon.py --selftest         # run all module self-tests
```

## Modules
| name | description |
|------|-------------|
| triage | magic-byte file type, size, md5/sha1/sha256, ASCII + UTF-16LE strings (`-n` min length), overall/per-section entropy with packed heuristic, ELF headers + NX/PIE/canary/RELRO/FORTIFY, basic PE headers |
| decode | decode/encode base64/base32/base58/hex/url/binary/decimal/octal/ascii, multi-round auto-decode, rot/caesar brute-force, atbash, vigenere (known key), single-byte XOR brute-force, repeating-key XOR, cipher-ID hints. `recon.py decode <text \| -f file>`; `--rot 5` or `--rot=5` for a shift, bare `--rot` brute-forces |

## Adding a module
Drop `modules/<name>.py` defining `NAME`, `DESCRIPTION`, `run(args) -> int`, `selftest() -> bool`.
It is discovered automatically (see `modules/__init__.py`).
