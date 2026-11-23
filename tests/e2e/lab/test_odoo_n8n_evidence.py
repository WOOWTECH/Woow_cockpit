"""odoo_n8n_evidence: only fixed status lines and sanitised summaries are published (synthetic input)."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parent / 'odoo_n8n_evidence.py'


class EvidenceTests(unittest.TestCase):
    def build(self, results, extra=None):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            (d / 'r').mkdir()
            (d / 'r' / 'results.json').write_text(json.dumps(results))
            for name, value in (extra or {}).items():
                (d / 'r' / name).write_text(json.dumps(value))
            (d / 'stdout').write_bytes(b'synthetic stdout')
            argv = [sys.executable, '-I', str(SCRIPT), 'driver', '--results', str(d / 'r'), '--out',
                    str(d / 'out' / 'e.json'), '--label', 'synthetic', '--command', 'ha_import_e2e.py verify',
                    '--rc', '1', '--elapsed', '5', '--stdout', str(d / 'stdout'), '--source-commit', 'a' * 40,
                    '--engine-sha256', 'b' * 64, '--started-utc', '2026-11-23T00:00:00Z', '--private', '/private']
            proc = subprocess.run(argv, capture_output=True)
            out = d / 'out' / 'e.json'
            doc = json.loads(out.read_text()) if out.exists() else None
            again = subprocess.run(argv, capture_output=True)
            return proc.returncode, doc, again.returncode

    def test_details_are_not_copied(self):
        rc, doc, again = self.build({'passed': 1, 'failed': 1, 'results': [
            {'check': 'import: health 200 everywhere', 'ok': True, 'detail': 'SYNTHETIC-DETAIL'},
            {'check': 'import: n8n owner can log in', 'ok': False, 'detail': 'SYNTHETIC-DETAIL'}]})
        self.assertEqual(rc, 0)
        self.assertEqual(doc['status_lines'], ['PASS import: health 200 everywhere',
                                               'FAIL import: n8n owner can log in'])
        self.assertNotIn('SYNTHETIC-DETAIL', json.dumps(doc))
        self.assertEqual(doc['commercial_acceptance'], 'not-complete')
        self.assertNotEqual(again, 0, 'an earlier attempt file is never overwritten')

    def test_credential_like_value_refuses(self):
        rc, doc, _ = self.build({'passed': 1, 'failed': 0, 'results': [
            {'check': 'password=SYNTHETICVALUE1', 'ok': True, 'detail': ''}]})
        self.assertEqual(rc, 2)
        self.assertIsNone(doc)
        rc, doc, _ = self.build({'passed': 1, 'failed': 0, 'results': [
            {'check': 'key AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG', 'ok': True, 'detail': ''}]})
        self.assertEqual(rc, 2)

    def test_sections(self):
        rc, doc, _ = self.build({'passed': 0, 'failed': 0, 'results': []}, {
            'n8n-diagnosis.json': {'login': True, 'listing': {'seconds': 150.0}, 'npm_outdated_seen': [1, 2, 3],
                                   'password_field_never_selected': 'x'},
            'leaks.json': {'scanned': 3, 'journal_bytes': 9, 'hits': {}},
            'capture-compare.json': {'status': 'explained_row_differences', 'identical': 199, 'secret_field': 'x',
                                     'row_evidence': {'all_explained': True, 'binding': 'not copied'}}})
        self.assertEqual(rc, 0)
        self.assertEqual(doc['capcompare'], {'status': 'explained_row_differences', 'identical': 199,
                                             'row_evidence': {'all_explained': True}})
        self.assertEqual(doc['n8n_diagnosis'], {'login': True, 'listing': {'seconds': 150.0},
                                                'npm_outdated_seen': [1, 2, 3]})
        self.assertEqual(doc['leak_scan'], {'files_scanned': 3, 'journal_bytes': 9, 'hits': 0})


if __name__ == '__main__':
    unittest.main()
