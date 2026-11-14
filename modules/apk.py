"""APK: offline Android static analysis using only the stdlib ``zipfile``.

* Lists archive contents and reports whether ``AndroidManifest.xml`` is present
  (binary AXML; printable strings are pulled out of it, e.g. package/permission names).
* Extracts readable strings from ``classes*.dex`` and ``resources.arsc`` / ``res`` / ``assets``.
* Dumps ``META-INF`` entries and signing-certificate blocks (size, SHA-256, readable DN strings).
* Keyword hunt (flag{, password, secret, ...) reusing ``forensics.find_keywords``, plus URL/IP hits.
* External-tool mode: if ``apktool``/``jadx`` are on PATH (``shutil.which``), the exact command is
  *suggested* -- never executed, never required, never downloaded.

No network, no process execution.

CLI:
    recon.py apk <file.apk> [--strings] [--certs] [--min N]
    recon.py apk selftest
"""
from __future__ import annotations

import argparse
import hashlib
import io
import re
import shlex
import shutil
import sys
import zipfile
from typing import Callable, Optional

try:  # works both as ``modules.apk`` and when the package dir is on sys.path
    from . import forensics
except ImportError:  # pragma: no cover
    import forensics  # type: ignore

NAME = "apk"
DESCRIPTION = "APK static analysis: unzip, manifest/dex/resource strings, META-INF certs, keyword/URL hunt, apktool/jadx hints"

URL_RE = re.compile(r"(?:https?|ftp|wss?)://[^\s\"'<>\\]+", re.I)
CERT_EXTS = (".rsa", ".dsa", ".ec", ".pem", ".cer", ".crt")
MAX_MEMBER = 64 * 1024 * 1024  # skip pathological members (zip bombs)


def _text_member(name: str) -> bool:
    """True for members whose strings are worth extracting."""
    n = name.lower()
    return (n.startswith("classes") and n.endswith(".dex")) or n == "resources.arsc" \
        or n == "androidmanifest.xml" or n.startswith(("res/", "assets/"))


def tool_suggestions(apk_path: str, which: Callable[[str], Optional[str]] = shutil.which) -> list[str]:
    """Return shell commands for apktool/jadx, only for tools found by ``which``."""
    q = shlex.quote(apk_path)
    out = []
    if which("apktool"):
        out.append(f"apktool d {q} -o apk_out")
    if which("jadx"):
        out.append(f"jadx -d jadx_out {q}")
    return out


def analyze(data: bytes, minlen: int = 6, which: Callable[[str], Optional[str]] = shutil.which,
            path: str = "app.apk") -> dict:
    """Analyze APK bytes; raises ``zipfile.BadZipFile`` if not a ZIP."""
    rep: dict = {"entries": [], "manifest": False, "dex": [], "strings": {}, "certs": [],
                 "meta_inf": [], "hits": [], "urls": [], "tools": []}
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        for info in z.infolist():
            rep["entries"].append((info.filename, info.file_size))
            name = info.filename
            if name == "AndroidManifest.xml":
                rep["manifest"] = True
            if name.lower().startswith("classes") and name.lower().endswith(".dex"):
                rep["dex"].append(name)
            if name.upper().startswith("META-INF/") and not info.is_dir():
                rep["meta_inf"].append(name)
                if name.lower().endswith(CERT_EXTS) and info.file_size <= MAX_MEMBER:
                    blob = z.read(name)
                    rep["certs"].append({"name": name, "size": len(blob),
                                         "sha256": hashlib.sha256(blob).hexdigest(),
                                         "strings": forensics.strings(blob, 4)[:20]})
            if _text_member(name) and not info.is_dir() and info.file_size <= MAX_MEMBER:
                s = forensics.strings(z.read(name), minlen)
                rep["strings"][name] = s
    allstr = [(n, s) for n, ss in rep["strings"].items() for s in ss]
    joined = "\n".join(s for _, s in allstr).encode("latin-1", "replace")
    rep["hits"] = forensics.find_keywords(joined, 0)
    seen = set()
    for _, s in allstr:
        for u in URL_RE.findall(s):
            if u not in seen:
                seen.add(u)
                rep["urls"].append(u)
    rep["tools"] = tool_suggestions(path, which)
    return rep


def _print(rep: dict, a) -> None:
    print(f"entries: {len(rep['entries'])}")
    print(f"AndroidManifest.xml: {'present' if rep['manifest'] else 'MISSING'}")
    print(f"dex files: {', '.join(rep['dex']) or 'none'}")
    for n, sz in rep["entries"]:
        print(f"  {sz:>9}  {n}")
    if a.certs or rep["certs"]:
        print("\n[META-INF]")
        for n in rep["meta_inf"]:
            print(f"  {n}")
        for c in rep["certs"]:
            print(f"  cert {c['name']}: {c['size']} B sha256={c['sha256']}")
            for s in c["strings"]:
                print(f"    {s}")
    if a.strings:
        print("\n[STRINGS]")
        for n, ss in rep["strings"].items():
            print(f"--- {n} ({len(ss)})")
            for s in ss:
                print(s)
    print("\n[KEYWORD HITS]")
    for kw, ctx in rep["hits"]:
        print(f"  [{kw}] {ctx}")
    if not rep["hits"]:
        print("  none")
    print("\n[URLS]")
    for u in rep["urls"]:
        print(f"  {u}")
    if not rep["urls"]:
        print("  none")
    if rep["tools"]:
        print("\n[EXTERNAL TOOLS found on PATH -- run yourself]")
        for c in rep["tools"]:
            print(f"  {c}")


def run(args: list[str]) -> int:
    """CLI entry point."""
    if args[:1] in (["selftest"], ["--selftest"]):
        return 0 if selftest() else 1
    p = argparse.ArgumentParser(prog="recon.py apk", description=__doc__.split("\n")[0])
    p.add_argument("apk", help="path to .apk")
    p.add_argument("--strings", action="store_true", help="print all extracted strings")
    p.add_argument("--certs", action="store_true", help="dump META-INF / certificate info")
    p.add_argument("--min", type=int, default=6, help="minimum string length (default 6)")
    a = p.parse_args(args)
    try:
        with open(a.apk, "rb") as f:
            data = f.read()
    except OSError as exc:
        print(f"error: cannot read {a.apk}: {exc}", file=sys.stderr)
        return 1
    try:
        rep = analyze(data, a.min, path=a.apk)
    except zipfile.BadZipFile:
        print(f"error: {a.apk} is not a valid ZIP/APK", file=sys.stderr)
        return 1
    _print(rep, a)
    return 0


def _make_apk() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00package\x00com.example.ctf\x00")
        z.writestr("classes.dex", b"dex\n035\x00\x00\x01\x02flag{apk_dex_secret}\x00\x00http://evil.example/c2\x00")
        z.writestr("META-INF/CERT.RSA", b"\x30\x82\x01\x00CN=Test Signer\x00")
        z.writestr("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n")
    return buf.getvalue()


def selftest() -> bool:
    """Offline self-test over an in-memory fake APK."""
    ok = True

    def check(label: str, cond: bool) -> None:
        nonlocal ok
        if not cond:
            print(f"  FAIL: {label}")
            ok = False

    data = _make_apk()
    rep = analyze(data, which=lambda n: None)
    check("manifest listed", rep["manifest"] and any(n == "AndroidManifest.xml" for n, _ in rep["entries"]))
    check("dex found", rep["dex"] == ["classes.dex"])
    check("planted flag extracted", any("flag{apk_dex_secret}" in s for s in rep["strings"]["classes.dex"]))
    check("keyword hunt hits flag", any(k == "flag{" for k, _ in rep["hits"]))
    check("url found", rep["urls"] == ["http://evil.example/c2"])
    check("cert dumped", len(rep["certs"]) == 1 and any("CN=Test Signer" in s for s in rep["certs"][0]["strings"]))
    check("no tools suggested when absent", rep["tools"] == [])
    only_jadx = analyze(data, which=lambda n: "/usr/bin/jadx" if n == "jadx" else None, path="a b.apk")
    check("only jadx suggested", only_jadx["tools"] == ["jadx -d jadx_out 'a b.apk'"])
    both = tool_suggestions("x.apk", which=lambda n: "/bin/" + n)
    check("both suggested", both == ["apktool d x.apk -o apk_out", "jadx -d jadx_out x.apk"])
    try:
        analyze(b"not a zip")
        check("bad zip raises", False)
    except zipfile.BadZipFile:
        pass
    return ok


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
