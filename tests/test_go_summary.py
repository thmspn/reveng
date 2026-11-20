"""Regression fixtures for go's final summary: derived evidence must stay visible when step logs truncate it."""
from __future__ import annotations

import os
import sys
import unittest

TOOLKIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, TOOLKIT)

from modules import go  # noqa: E402


def fake(name: str, text: str):
    """A stand-in sibling module whose run() prints ``text`` (noise first so the echo cuts it off)."""
    def _run(argv: list[str]) -> int:
        print(text)
        return 0
    return type("Fake", (), {"NAME": name, "run": staticmethod(_run)})


NOISE = "\n".join(f"noise line {i}" for i in range(40))
AUTOSOLVE = NOISE + "\nHEADLINE   DERIVED [H]  hunter2_pw\nSOLVE      hunter2_pw  [H]  method strcmp-literal  re-walk ok\n"
PYRUN = ("=== pyrun static scan: x.py (nothing executed) ===\n[candidate-inputs] 2\n"
         "  [HIGH] line 10: 'abc123'  (literal compare against input)\n"
         "  [LOW] line 3: 'noise'  (list constant)\n[derived-values] 1\n"
         "  [derived-arith] [MEDIUM] line 8: 99  (arith-fold)\n" + NOISE + "\n")
ASM = NOISE + "\ncheck(0x5) -> eax = 0x2a  decimal 42\n"
ASM_PARTIAL = "*** PARTIAL RESULT - evaluation stopped early ***\ncheck(0x5) -> eax = 0x7  decimal 7 [PARTIAL - last known value]\n"


def summary(mods: dict, steps: list[tuple[str, str]], **attrs) -> tuple[int, str, go.Runner]:
    r = go.Runner(mods, 5, 30, False, out=lambda s: None)
    for k, v in attrs.items():
        setattr(r, k, v)
    for label, module in steps:
        r.step(label, module, ["x"])
    lines: list[str] = []
    r.say = lines.append
    return go.report(r), "\n".join(lines), r


class DerivedSummary(unittest.TestCase):
    def test_autosolve_password_visible_though_echo_truncated(self) -> None:
        shown: list[str] = []
        r = go.Runner({"autosolve": fake("autosolve", AUTOSOLVE)}, 5, 30, False, out=shown.append)
        r.step("autosolve", "autosolve", ["x"])
        self.assertNotIn("hunter2_pw", "\n".join(shown))  # truncated in the step log
        lines: list[str] = []
        r.say = lines.append
        rc = go.report(r)
        text = "\n".join(lines)
        self.assertEqual(rc, 1)  # exit behavior unchanged: no flag-shaped candidate
        self.assertIn("== DERIVED INPUTS / REGISTER RESULTS ==", text)
        self.assertIn("hunter2_pw", text)
        self.assertIn("[HIGH]", text)
        self.assertIn("autosolve", text.split("== DERIVED")[1])
        self.assertNotIn("(none)", text)
        self.assertIn("derived evidence WAS found", text)
        self.assertTrue(text.rstrip().splitlines()[-1].startswith("NEXT:"))
        self.assertNotIn("[score", text)  # never mislabelled as a flag

    def test_pyrun_high_inputs_only(self) -> None:
        rc, text, _ = summary({"pyrun": fake("pyrun", PYRUN)}, [("pyrun", "pyrun")])
        self.assertIn("'abc123'", text)
        self.assertNotIn("'noise'", text)
        self.assertNotIn("arith-fold", text)

    def test_asmeval_register_result_and_partial_label(self) -> None:
        rc, text, _ = summary({"asmeval": fake("asmeval", ASM)}, [("asmeval", "asmeval")])
        self.assertIn("check(0x5) -> eax = 0x2a  decimal 42", text)
        self.assertIn("register result [complete]", text)
        rc, text, _ = summary({"asmeval": fake("asmeval", ASM_PARTIAL)}, [("asmeval", "asmeval")])
        self.assertIn("register result [PARTIAL]", text)

    def test_arbitrary_numbers_are_not_derived(self) -> None:
        rc, text, r = summary({"asmeval": fake("asmeval", "total 42 items\nexit 7\n")}, [("asmeval", "asmeval")])
        self.assertEqual(r.derived, [])
        self.assertNotIn("DERIVED INPUTS", text)

    def test_flag_candidates_still_ranked_and_exit_zero(self) -> None:
        rc, text, _ = summary({"autosolve": fake("autosolve", AUTOSOLVE + "picoCTF{real_flag}\n")}, [("autosolve", "autosolve")])
        self.assertEqual(rc, 0)
        self.assertIn("picoCTF{real_flag}   [score", text)
        self.assertIn("hunter2_pw", text)

    def test_status_legend_and_next_step_hints_when_nothing_found(self) -> None:
        rc, text, _ = summary({}, [("x", "missing")], kinds=["elf", "py"])
        self.assertEqual(rc, 1)
        self.assertIn("== STEPS ==", text)
        self.assertIn("ok = the tool ran, NOT that it solved anything", text)
        self.assertIn("-v", text)
        self.assertIn("autosolve", text)
        self.assertIn("pyrun", text)
        self.assertIn("(none)", text)
        self.assertIn("autosolve <file> --deep", text)
        self.assertNotIn("autosolve <file> -v", text)
        self.assertIn("rerun go with -v", text)

    def test_text_kind_suggests_decode_dash_f(self) -> None:
        rc, text, _ = summary({}, [("x", "missing")], kinds=["text"])
        self.assertIn("decode -f <file>", text)
        self.assertNotIn("decode <file>", text)

    def test_text_hint_names_token_only_and_does_not_claim_prose_understanding(self) -> None:
        rc, text, _ = summary({}, [], text_only=True, text_tokens=["aGVsbG8gd29ybGQxMjM="])
        self.assertIn("does NOT understand prose", text)
        self.assertIn("ONLY that", text)
        self.assertIn("aGVsbG8gd29ybGQxMjM=", text)

    def test_chain_text_finds_candidate_tokens_without_executing(self) -> None:
        r = go.Runner({}, 5, 30, False, out=lambda s: None)
        go.chain_text(r, "The key is aGVsbG8gd29ybGQxMjM= and nothing else, please hurry")
        self.assertEqual(r.text_tokens, ["aGVsbG8gd29ybGQxMjM="])

    def test_python_runtime_notice_precedes_pyrun_step(self) -> None:
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "a.py")
            with open(path, "w") as fh:
                fh.write("print('hi')\n")
            out: list[str] = []
            r = go.Runner({"pyrun": fake("pyrun", "x")}, 5, 30, False, out=out.append)
            go.chain_file(r, path, [])
            joined = "\n".join(out)
            self.assertLess(joined.index("NOTICE: the next step RUNS this Python file"), joined.index("--- pyrun --run"))
            for needle in ("Review the code first", "Non-hostile CTF scripts only", "NOT a security boundary", "Network is blocked"):
                self.assertIn(needle, joined)
            self.assertNotIn("--force", " ".join(go.PY_NOTICE.split()).replace("no --force", ""))


if __name__ == "__main__":
    unittest.main()
