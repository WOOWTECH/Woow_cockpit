"""Offline cached-image export metadata only, never load/execute catalogue modules."""
from pathlib import Path
import tempfile
import unittest
from emqx_native_runtime import run_native

ROOT=Path(__file__).parent
HASH='DE702B30F75648B1435B584233503E51347F769A39B94DC5A2237781179633D6'


class PublicDescriptorMatchTests(unittest.TestCase):
    def run_match(self,digest):
        with tempfile.TemporaryDirectory(prefix='emqx-public-export-match-') as directory:
            root=Path(directory)
            (root/'match.escript').write_bytes((ROOT/'emqx_public_descriptor_match.escript').read_bytes())
            (root/'match.escript').chmod(0o600)
            with tempfile.TemporaryFile() as output:
                code=run_native(root,'match.escript',args=(digest,),output=output)
                output.seek(0);raw=output.read(32769)
                self.assertEqual(code,0);self.assertLessEqual(len(raw),32768)
                self.assertTrue(raw.endswith(b'MATCHDONE'))
                return raw

    def test_actual_synthetic_descriptor_uniquely_matches_public_export(self):
        raw=self.run_match(HASH)
        lines=raw.removesuffix(b'MATCHDONE').splitlines()
        self.assertEqual(len(lines),1)
        self.assertIn(b'MATCH:ZW1xeF90bHNfcHNr:bG9va3Vw:3:F2653DFD1072A73E2E6FEC1D77865D1F:',lines[0])

    def test_unmatched_descriptor_has_only_eof_no_identity(self):
        self.assertEqual(self.run_match('0'*64),b'MATCHDONE')
