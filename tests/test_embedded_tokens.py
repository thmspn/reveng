"""End-to-end prose/token input tests; no challenge code is executed."""
import base64
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from modules import go, discover


class EmbeddedTokens(unittest.TestCase):
    def runner(self):
        return go.Runner(discover(), 5, 30, False, out=lambda s: None)

    def test_embedded_codec_shapes_and_nesting(self):
        flag = b'CyberSci{embedded_token_2026}'
        for token in (base64.b64encode(flag).decode(), flag.hex(),
                      base64.b64encode(base64.b64encode(flag)).decode(),
                      base64.urlsafe_b64encode(flag).decode().rstrip('=')):
            with self.subTest(token=token):
                r = self.runner()
                go.chain_text(r, 'Please decode this (' + token + '), then submit the result.')
                self.assertEqual(go.rank(r.cands)[0][1].text, flag.decode())
                self.assertEqual(go.rank(r.cands)[0][0], 113)

    def test_flag_beyond_codec_preview_is_not_lost(self):
        flag = b'CyberSci{beyond_preview_2026}'
        message = b'ordinary prose ' * 100 + flag + b' tail'
        token = base64.b64encode(message).decode()
        r = self.runner()
        go.chain_text(r, token)
        self.assertIn(flag.decode(), r.cands)
        self.assertEqual(go.rank(r.cands)[0][1].text, flag.decode())
        self.assertIn('[FLAG?] ' + flag.decode(), r.results[0].output)

    def test_text_file_with_spaces_works(self):
        with tempfile.TemporaryDirectory(prefix='ctf test ') as tmp:
            path = os.path.join(tmp, 'intercepted message.txt')
            flag = b'NewEvent{file_blob_2026}'
            with open(path, 'w') as fh:
                fh.write('A message: ' + base64.b64encode(flag).decode() + ' is the payload.')
            r = self.runner()
            go.chain_file(r, path, [])
            self.assertIn(flag.decode(), r.cands)

    def test_deduplicate_and_cap(self):
        token = base64.b64encode(b'CyberSci{duplicate_blob}').decode()
        r = self.runner()
        go.chain_text(r, 'prefix ' + ' '.join([token] * 30) + ' suffix')
        self.assertEqual(sum(s.label.startswith('decode embedded token') for s in r.results), 1)
        r = self.runner()
        go.chain_text(r, 'prefix ' + ' '.join(base64.b64encode(('CyberSci{blob_%02d}' % i).encode()).decode() for i in range(12)))
        self.assertEqual(sum(s.label.startswith('decode embedded token') for s in r.results), 8)
        self.assertTrue(any('token limit reached' in s.status for s in r.results))

    def test_plain_english_does_not_invent_flag_candidates(self):
        r = self.runner()
        go.chain_text(r, 'This communication intentionally contains extraordinary terminology without encoded content.')
        self.assertEqual(r.cands, {})

    def test_option_like_text_is_literal_not_decoder_options(self):
        r = self.runner()
        go.chain_text(r, '--selftest')
        self.assertNotIn('[PASS]', r.results[0].output)
        self.assertEqual(r.results[0].status, 'ok')

    def test_outer_cli_accepts_option_like_text(self):
        import contextlib
        import io
        for args in (['--text', '--selftest'], ['-t', '--selftest'], ['--text=--selftest']):
            with self.subTest(args=args), contextlib.redirect_stdout(io.StringIO()) as out:
                rc = go.run(args)
            self.assertEqual(rc, 1)  # analyzed, no flag; not argparse's exit 2
            self.assertIn('== FLAG CANDIDATES ==', out.getvalue())
            self.assertNotIn('[PASS]', out.getvalue())

    def test_scan_clip_does_not_accept_partial_oversize_token(self):
        r = self.runner()
        prefix = ' ' * (go.DECODE_MAX_BYTES - 4000)
        go.decode_embedded(r, prefix + 'A' * 5000 + ' tail', 'text')
        self.assertEqual(r.results, [])

    def test_oversize_token_is_not_scanned_as_a_suffix(self):
        r = self.runner()
        go.decode_embedded(r, 'prefix ' + 'A' * 5000 + ' suffix', 'text')
        self.assertEqual(r.results, [])


if __name__ == '__main__':
    unittest.main()
