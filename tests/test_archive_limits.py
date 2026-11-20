"""Unsupported archive inputs must not be sent to the ZIP/GZIP extractor."""
import bz2
import io
import lzma
import os
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from modules import go, discover


class ArchiveLimits(unittest.TestCase):
    def test_real_archives_get_honest_manual_extraction_notice(self):
        b = io.BytesIO()
        with tarfile.open(fileobj=b, mode='w') as t:
            info = tarfile.TarInfo('member.txt')
            data = b'ordinary member text'
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
        cases = {'a.tar': b.getvalue(), 'a.bz2': bz2.compress(b'ordinary data'),
                 'a.xz': lzma.compress(b'ordinary data'), 'a.7z': b'7z\xbc\xaf\x27\x1c',
                 'a.rar': b'Rar!\x1a\x07'}
        for name, raw in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                path = os.path.join(tmp, name)
                with open(path, 'wb') as fh:
                    fh.write(raw)
                r = go.Runner(discover(), 5, 30, False, out=lambda s: None)
                go.chain_file(r, path, [])
                self.assertIn('archive-manual', r.kinds)
                self.assertFalse(any('binextras extract' in s.label for s in r.results))
                self.assertTrue(any('unsupported archive/compression' in s.status for s in r.results))
                hints = '\n'.join(go._next_step_hint(r))
                self.assertIn('extract manually', hints)
                self.assertIn('ZIP/GZIP only', hints)
                self.assertNotIn('binextras extract', hints)

    def test_existing_raw_flags_still_surface_before_notice(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'x.bz2')
            with open(path, 'wb') as fh:
                fh.write(b'BZh raw hint CyberSci{visible_hint}')
            r = go.Runner(discover(), 5, 30, False, out=lambda s: None)
            go.chain_file(r, path, [])
            self.assertIn('CyberSci{visible_hint}', r.cands)


if __name__ == '__main__':
    unittest.main()
