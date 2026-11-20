"""Stdlib regression tests for the recon.py menu guidance (run: python3 -m unittest discover -s toolkit/tests)."""
from __future__ import annotations

import io
import os
import pty
import re
import select
import shlex
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

TOOLKIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RECON = os.path.join(TOOLKIT, "recon.py")
sys.path.insert(0, TOOLKIT)

import recon  # noqa: E402
from modules import discover, ui  # noqa: E402

ANSI = re.compile(r"\033\[[0-9;]*m")


def run_menu(stdin_text: str, env_extra: dict | None = None, cwd: str | None = None) -> subprocess.CompletedProcess:
    """Run the interactive menu with piped stdin (so: no TTY, no color)."""
    env = {k: v for k, v in os.environ.items() if k != "NO_COLOR"}
    env.update(env_extra or {})
    return subprocess.run([sys.executable, "-I", RECON], input=stdin_text, capture_output=True, text=True,
                          env=env, cwd=cwd, timeout=60)


def run_pty(stdin_text: str, env_extra: dict | None = None) -> str:
    """Run the menu on a real pseudo-terminal and return everything it printed."""
    env = {k: v for k, v in os.environ.items() if k != "NO_COLOR"}
    env.update(env_extra or {})
    master, slave = pty.openpty()
    proc = subprocess.Popen([sys.executable, "-I", RECON], stdin=slave, stdout=slave, stderr=slave, env=env)
    os.close(slave)
    os.write(master, stdin_text.encode())
    chunks = []
    while True:
        ready, _, _ = select.select([master], [], [], 30)
        if not ready:
            proc.kill()
            break
        try:
            data = os.read(master, 65536)
        except OSError:  # EIO: child closed the pty
            break
        if not data:
            break
        chunks.append(data)
    proc.wait(timeout=30)
    os.close(master)
    return b"".join(chunks).decode("utf-8", "replace")


class GuideTable(unittest.TestCase):
    def test_guide_covers_exactly_the_registered_modules(self) -> None:
        self.assertEqual(set(ui.GUIDE), set(discover()))

    def test_examples_are_arguments_only(self) -> None:
        for name, (purpose, example) in ui.GUIDE.items():
            self.assertTrue(purpose.endswith("."), name)
            self.assertFalse(example.split()[0] == name or example.startswith("recon"), name)
            self.assertNotIn("\n", example)

    def test_every_example_passes_the_real_module_parser(self) -> None:
        """Run each example through recon.py; placeholder files are absent, so a module that accepts the
        arguments fails later with exit 0/1 (missing file), while a parser rejection exits 2."""
        with tempfile.TemporaryDirectory() as tmp:
            os.mkdir(os.path.join(tmp, "challenge_folder"))
            for name, (_, example) in ui.GUIDE.items():
                with self.subTest(module=name):
                    r = subprocess.run([sys.executable, "-I", RECON, name, *shlex.split(example)],
                                       cwd=tmp, capture_output=True, text=True, timeout=120)
                    self.assertIn(r.returncode, (0, 1), r.stderr)
                    self.assertNotIn("usage:", r.stderr.lower())
                    self.assertNotIn("unrecognized arguments", r.stderr)
                    self.assertNotIn("Traceback", r.stderr)
                    if r.returncode == 1:  # got past the parser: the only problem is the placeholder file
                        self.assertRegex(r.stderr + r.stdout, r"(?i)no such file|cannot read|not found")


class MenuText(unittest.TestCase):
    def test_start_here_precedes_categories_and_covers_guidance(self) -> None:
        out = run_menu("q\n").stdout
        self.assertLess(out.index("START HERE"), out.index("REVERSE / PWN"))
        for needle in ("select> go", "select> batch", "--text", "module name or number", "arguments only, not the command",
                       "Quote paths with spaces", "-h", "candidates to verify", "No candidate is NOT success",
                       "ONLY an encoded token", "only waits for your choice", "go on a .py file",
                       "review the code first", "not a security boundary", "ok only means the tool ran", "-v"):
            self.assertIn(needle, out)
        for line in (ui.start_here() + "\n" + ui.start_here_short()).splitlines():
            self.assertLessEqual(len(line), ui.RULE_WIDTH, line)

    def test_no_status_column_and_numbers_unchanged(self) -> None:
        mods = discover()
        out = run_menu("q\n").stdout
        for i, name in enumerate(mods, 1):
            self.assertRegex(out, rf"(?m)^ +{i}  {name} ")
        self.assertNotIn("status", out.lower().split("START HERE")[0])

    def test_selection_by_name_and_number_shows_guide_before_args_prompt(self) -> None:
        mods = discover()
        names = list(mods)
        for choice, name in (("triage", "triage"), (str(names.index("hashid") + 1), "hashid")):
            with self.subTest(choice=choice):
                out = run_menu(f"{choice}\n-h\nq\n").stdout
                purpose, example = ui.GUIDE[name]
                self.assertLess(out.index(purpose), out.index(f"{name} args>"))
                self.assertIn(f"args> {example}", out)
                self.assertIn("usage:", out)  # -h still prints the module's own usage

    def test_start_here_shown_once_per_session_then_compact_reminder(self) -> None:
        out = run_menu("triage\n\nnope\nq\n").stdout
        self.assertEqual(out.count("START HERE"), 1)
        self.assertEqual(out.count("REMINDER"), 2)  # one per redraw after the first
        self.assertNotIn("Nothing runs by itself", out)

    def test_go_warning_precedes_go_args_prompt_only(self) -> None:
        out = run_menu("go\n\nq\n").stdout
        self.assertLess(out.index("RUNS it in a guarded sandbox"), out.index("go args>"))
        self.assertNotIn("RUNS it in a guarded sandbox", run_menu("triage\n\nq\n").stdout)

    def test_args_prompt_is_unchanged(self) -> None:
        self.assertIn("go args> ", run_menu("go\n\n").stdout)


class MenuFlows(unittest.TestCase):
    def test_quit_forms_and_eof_exit_zero(self) -> None:
        for text in ("q\n", "quit\n", "\n", ""):
            with self.subTest(stdin=text):
                self.assertEqual(run_menu(text).returncode, 0)

    def test_eof_at_args_prompt_exits_zero(self) -> None:
        r = run_menu("triage\n")
        self.assertEqual(r.returncode, 0)
        self.assertIn("triage args> ", r.stdout)

    def test_invalid_choice_then_continue(self) -> None:
        out = run_menu("nope\n999\n0\nq\n").stdout
        self.assertEqual(out.count("invalid choice"), 3)
        self.assertIn("name", out)
        self.assertIn("number", out)
        self.assertIn("q to quit", out)

    def test_help_and_question_mark_recall_start_here(self) -> None:
        for word in ("help", "?"):
            out = run_menu(f"{word}\nq\n")
            self.assertEqual(out.returncode, 0)
            self.assertIn("invalid choice", out.stdout)
            self.assertEqual(out.stdout.count("START HERE"), 2, word)

    def test_batch_tip_only_in_interactive_menu(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            out = run_menu(f"batch\n{shlex.quote(d)}\nq\n").stdout
        self.assertIn("quick first look", out)
        self.assertIn("review the code first", out)
        self.assertNotIn("quick first look", run_menu("triage\nq\n").stdout)

    def test_repeated_module_name_gets_hint_and_args_unchanged(self) -> None:
        r = run_menu("triage\ntriage no_such_file_here\nq\n")
        self.assertEqual(r.returncode, 0)
        self.assertIn("typed the module name 'triage'", r.stdout)
        self.assertIn("no_such_file_here", r.stdout + r.stderr)  # the module still saw and reported the arguments
        self.assertNotIn("typed the module name", run_menu("triage\nno_such_file_here\nq\n").stdout)

    def test_split_path_hint_and_module_errors_not_suppressed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "my folder", "chall bin")
            os.makedirs(os.path.dirname(path))
            with open(path, "wb") as fh:
                fh.write(b"hello\n")
            r = run_menu(f"triage\n{path} --no-strings\nq\n")
            self.assertIn("quote the ENTIRE path", r.stdout)
            self.assertTrue(r.stderr.strip() or "error" in r.stdout.lower())  # module's own error still visible
            r2 = run_menu(f'triage\n"{path}" --no-strings\nq\n')
            self.assertNotIn("quote the ENTIRE path", r2.stdout)

    def test_path_hint_unit(self) -> None:
        self.assertEqual(recon.path_hint("a b", ["a", "b"], 0), "")
        self.assertEqual(recon.path_hint('"a b"', ["a b", "c"], 2), "")
        self.assertIn("quote", recon.path_hint("x y", ["x", "y"], 2))
        self.assertEqual(recon.path_hint("triage y", ["triage", "y"], 2, "triage"), "")

    def test_unbalanced_quote_reports_error_and_returns_to_menu(self) -> None:
        r = run_menu('triage\n"oops\nq\n')
        self.assertEqual(r.returncode, 0)
        self.assertIn("error:", r.stdout)
        self.assertGreaterEqual(r.stdout.count("select> "), 2)

    def test_module_error_does_not_crash_menu(self) -> None:
        r = run_menu("triage\nno_such_file_here\nq\n")
        self.assertEqual(r.returncode, 0)
        self.assertNotIn("Traceback", r.stdout + r.stderr)

    def test_path_with_spaces_reaches_module_intact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "my folder", "chall bin")
            os.makedirs(os.path.dirname(path))
            with open(path, "wb") as fh:
                fh.write(b"hello world, plain text for triage\n")
            r = run_menu(f'triage\n"{path}" --no-strings\nq\n')
            self.assertEqual(r.returncode, 0)
            self.assertNotIn("cannot", r.stdout + r.stderr)
            self.assertIn("chall bin", r.stdout)
            # Unquoted, the same path splits into two arguments and the module rejects it.
            r2 = run_menu(f"triage\n{path} --no-strings\nq\n")
            self.assertTrue("error" in (r2.stdout + r2.stderr).lower() or "usage" in (r2.stdout + r2.stderr).lower())

    def test_go_text_example_flow(self) -> None:
        r = run_menu('go\n--text "the flag is base64 U0dWc2JHOD0="\nq\n')
        self.assertEqual(r.returncode, 0)
        self.assertNotIn("Traceback", r.stdout + r.stderr)

    def test_direct_cli_is_unchanged(self) -> None:
        r = subprocess.run([sys.executable, "-I", RECON, "nosuchmodule"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)
        self.assertNotIn("START HERE", r.stdout + r.stderr)
        r = subprocess.run([sys.executable, "-I", RECON, "-h"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)
        self.assertNotIn("START HERE", r.stdout)


class ColorGating(unittest.TestCase):
    def test_piped_output_has_no_escape_codes(self) -> None:
        self.assertNotIn("\033", run_menu("triage\n\nq\n").stdout)

    def test_real_pty_emits_color(self) -> None:
        out = run_pty("triage\n\nq\n")
        self.assertIn("\033[", out)
        self.assertIn("START HERE", ANSI.sub("", out))
        self.assertIn("example  args> chall", ANSI.sub("", out))

    def test_real_pty_with_no_color_is_plain(self) -> None:
        out = run_pty("triage\n\nq\n", {"NO_COLOR": "1"})
        self.assertNotIn("\033", out)
        self.assertIn("START HERE", out)

    def test_ascii_fallback_on_non_utf8_stdout(self) -> None:
        r = subprocess.run([sys.executable, RECON], input=b"triage\n\nq\n", capture_output=True, timeout=60,
                           env={**{k: v for k, v in os.environ.items() if k != "NO_COLOR"},
                                "PYTHONIOENCODING": "ascii"})
        self.assertEqual(r.returncode, 0, r.stderr)
        out = r.stdout.decode("ascii")  # would raise if any non-ASCII symbol leaked
        self.assertIn("START HERE", out)
        self.assertIn("[i] ", out)
        self.assertIn("> START HERE", out)

    def test_use_color_gating_unit(self) -> None:
        with mock.patch.object(sys.stdout, "isatty", return_value=True, create=True):
            with mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop("NO_COLOR", None)
                self.assertTrue(ui.use_color())
            with mock.patch.dict(os.environ, {"NO_COLOR": ""}):
                self.assertFalse(ui.use_color())
        buf = io.StringIO()
        with redirect_stdout(buf):
            self.assertEqual(ui.paint("x", ui.RED), "x")


if __name__ == "__main__":
    unittest.main()
