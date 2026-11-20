"""Long unbroken inputs must not trap the heuristic in an unbounded regex."""
import os
import subprocess
import sys
import tempfile
import unittest

TOOLKIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, TOOLKIT)
from modules import decode


class DecoderLimits(unittest.TestCase):
    def test_long_non_flag_hint_completes_in_subprocess(self):
        # Isolate this regression: a broken C regex can block Python signal timers.
        p = subprocess.run([sys.executable, '-c',
                            'from modules.decode import hints; print(len(hints("A" * 200000)))'],
                           cwd=TOOLKIT, capture_output=True, text=True, timeout=3)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertTrue(p.stdout.strip().isdigit())

    def test_go_long_text_respects_step_timeout(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'repeated.txt')
            with open(path, 'w') as fh:
                fh.write('A' * 200000)
            p = subprocess.run([sys.executable, os.path.join(TOOLKIT, 'recon.py'),
                                'go', path, '--step-timeout', '0.5', '--budget', '2'],
                               capture_output=True, text=True, timeout=6)
            self.assertEqual(p.returncode, 1, p.stderr)
            self.assertIn('== FLAG CANDIDATES ==', p.stdout)
            self.assertIn('(none)', p.stdout)
            self.assertNotIn('Traceback', p.stdout + p.stderr)

    def test_flag_hint_still_works(self):
        self.assertTrue(any('flag-like format' in h for h in decode.hints('CyberSci{valid_flag}')))
        self.assertFalse(any('flag-like format' in h for h in decode.hints('A' * 10000)))


if __name__ == '__main__':
    unittest.main()
