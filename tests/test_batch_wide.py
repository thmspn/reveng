"""Wide-string flags should be visible in folder ranking, not only go."""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from modules import batch, forensics, discover


class BatchWide(unittest.TestCase):
    def test_wide_flags_at_both_alignments_and_late_offset(self):
        for prefix in (b'', b'X', b'A' * 9001):
            with self.subTest(prefix_len=len(prefix)):
                flag = 'CyberSci{wide_answer}'
                data = prefix + flag.encode('utf-16-le') + b'\0\0'
                flags, _ = batch._kw_hits(forensics, data)
                self.assertIn(flag, flags)

    def test_actual_batch_file_ranks_wide_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'wide answer.dat')
            with open(path, 'wb') as fh:
                fh.write(b'X' + 'CyberSci{wide_answer}'.encode('utf-16-le'))
            rec = batch.analyze_file(path, discover(), quick=True)
            self.assertEqual(rec['flags'], ['CyberSci{wide_answer}'])
            self.assertGreaterEqual(rec['score'], 100)

    def test_no_false_ascii_by_dropping_nonzero_high_bytes(self):
        data = b'\0' + b''.join(bytes([b, 1]) for b in b'CyberSci{not_a_wide_flag}')
        self.assertEqual(batch._kw_hits(forensics, data)[0], [])

    def test_existing_ascii_dedupe_and_five_flag_cap_preserved(self):
        flags = ['CyberSci{%d}' % i for i in range(8)]
        data = ('\n'.join(flags) + '\n').encode() + flags[0].encode('utf-16-le')
        self.assertEqual(batch._kw_hits(forensics, data)[0], flags[:5])


if __name__ == '__main__':
    unittest.main()
