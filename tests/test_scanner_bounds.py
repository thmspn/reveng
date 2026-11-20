"""Every operational flag scanner uses the same bounded ASCII shape.

The decode ROT language-ranking heuristic is deliberately not a flag scanner;
it does not decide which candidates go collects or their evidence tier.
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from modules import batch, binextras, crypto, decode, forensics, go, pyrun, revauto, triage, discover

SCANNERS = {
    'batch / pyrun / autosolve': batch.FLAG_RE,
    'triage': triage._FLAG_RE,
    'forensics': forensics.FLAG_RE,
    'binextras': binextras.FLAG_RE,
    'crypto': crypto.RSA_FLAG_RE,
    'decode results': decode._RESULT_FLAG_RE,
    'go bytes': go.TOKEN_BYTES_RE,
}


class ScannerBounds(unittest.TestCase):
    def test_operational_patterns_identical(self):
        self.assertEqual(len({p.pattern for p in SCANNERS.values()}), 1)
        self.assertIs(pyrun.FLAG_RE, batch.FLAG_RE)
        self.assertEqual(revauto.FLAG_RE.pattern.encode(), batch.FLAG_RE.pattern)
        self.assertEqual(go.TOKEN_RE.pattern.encode(), batch.FLAG_RE.pattern)

    def test_valid_bounds_and_common_shapes(self):
        values = ['CyberSci{a}', 'x{ok}', 'new-event_2026{ab}', 'P' * 64 + '{ok}',
                  'CyberSci{' + 'a' * 200 + '}', 'CyberSci{hello world}',
                  'CyberSci{pipes|and~tilde}', 'CyberSci{!@#$%^&*()[]:;,.?/\\=+-}']
        for text in values:
            for name, pattern in SCANNERS.items():
                with self.subTest(scanner=name, text=text):
                    self.assertEqual(pattern.findall(b'\x00'+text.encode()+b'\xff'), [text.encode()])
                    self.assertEqual(go.TOKEN_RE.findall(text), [text])

    def test_reject_oversize_prefix_without_suffix_false_flag(self):
        for text in ['P' * 65 + '{answer}', 'P{}', 'P{'+'a'*201+'}', 'P{a\nb}',
                     'P{a\rb}', 'P{\x00}', 'P{\x7f}', 'P{\u00e9}']:
            for name, pattern in SCANNERS.items():
                with self.subTest(scanner=name, text=text):
                    self.assertEqual(pattern.findall(text.encode()), [])
                    self.assertEqual(go.TOKEN_RE.findall(text), [])

    def test_real_batch_triage_forensics_and_go(self):
        for flag in ['CyberSci{a}', 'New-Event{ab}', 'L' * 50 + '{body}', 'CyberSci{hello world}']:
            with self.subTest(flag=flag), tempfile.TemporaryDirectory() as tmp:
                path = os.path.join(tmp, 'message.txt')
                with open(path, 'w') as fh:
                    fh.write('result: '+flag+'\n')
                raw = ('result: '+flag+'\n').encode()
                self.assertIn(flag, batch.analyze_file(path, discover(), quick=True)['flags'])
                self.assertIn('[FLAG?] '+flag, triage.analyze(raw))
                self.assertIn(flag, forensics.carve_strings(raw)['flags'])
                r = go.Runner(discover(), 5, 30, False, out=lambda s: None)
                go.chain_file(r, path, [])
                self.assertEqual(go.rank(r.cands)[0][1].text, flag)
                if len(flag.split('{')[0]) > 24:
                    self.assertNotIn(flag[-(24 + len('{body}')):], r.cands)


if __name__ == '__main__':
    unittest.main()
