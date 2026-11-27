"""Concrete full-flow scanner/cookie gaps only; real local files, no devices."""
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import focus_n8n_instance_acceptance_scan as scan
import focus_n8n_instance_acceptance_run as run


class ScanTests(unittest.TestCase):
    def files(self, folder):
        base = str(Path(folder))+'/'
        for name in ('archives', 'jobs'): (Path(folder)/name).mkdir(mode=0o700)
        for name in ('requests.json', 'ha-imports.json', 'archives/one.json', 'archives/two.json'):
            (Path(folder)/name).write_text('{}')
        return base, [base+p for p in ('jobs', 'archives', 'requests.json', 'ha-imports.json')]

    def test_json_encoding_regular_roots_and_actual_sidecars_scanned_payload_excluded(self):
        with tempfile.TemporaryDirectory() as folder:
            base, roots = self.files(folder); value = 'synthetic-秘密\n"\\cookie'
            encoded = json.dumps({'value':value}, ensure_ascii=True)
            (Path(folder)/'requests.json').write_text(encoded)
            (Path(folder)/'archives/one.tar').write_text(value)
            (Path(folder)/'archives/two.woowbackup').write_text(value)
            report = scan.scan([value], roots, base=base)
            self.assertEqual(report['hits'], 1)
            self.assertEqual(report['regular_json_roots_scanned'], 2)
            self.assertEqual(report['archive_index_sidecars_scanned'], 2)
            self.assertEqual(report['actual_archive_index_sidecars_expected'], 2)
            self.assertEqual(report['scanned'], 4)
            (Path(folder)/'requests.json').write_text('{}')
            self.assertEqual(scan.scan([value], roots, base=base)['hits'], 0)
            self.assertEqual(scan.scan([value], roots, base=base, journal=encoded.encode())['hits'], 1)

    def test_missing_root_read_error_symlink_or_incomplete_coverage_never_passes(self):
        for failure in ('missing', 'read', 'symlink', 'omitted-json'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as folder:
                base, roots = self.files(folder); p = Path(folder)/'requests.json'
                if failure == 'missing': p.unlink()
                if failure == 'symlink': p.unlink(); p.symlink_to(Path(folder)/'ha-imports.json')
                if failure == 'omitted-json': roots.remove(str(p))
                real_open = scan.os.open
                def open_file(path, *args, **kwargs):
                    if failure == 'read' and Path(path) == p: raise PermissionError('synthetic private read failure')
                    return real_open(path, *args, **kwargs)
                with patch.object(scan.os, 'open', side_effect=open_file), self.assertRaises((RuntimeError, PermissionError)):
                    scan.scan(['synthetic-value'], roots, base=base)

    def test_overwritten_and_error_path_cookies_durably_registered_then_json_scanned(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'issued.json'
            program = '''
import http.cookiejar
jar=http.cookiejar.CookieJar()
def cookie(value):
 return http.cookiejar.Cookie(version=0,name='session',value=value,port=None,port_specified=False,
  domain='localhost',domain_specified=False,domain_initial_dot=False,path='/',path_specified=True,
  secure=False,expires=None,discard=True,comment=None,comment_url=None,rest={})
jar.set_cookie(cookie('synthetic-first-秘密\\n'))
jar.set_cookie(cookie('synthetic-renewed'))
assert [c.value for c in jar]==['synthetic-renewed']
raise RuntimeError('fixed synthetic API failure after cookie overwrite')
'''
            with self.assertRaises(RuntimeError):
                exec(run.recording_api_program(program, path), {'__name__':'local_cookie_test'})
            values = json.loads(path.read_text())
            self.assertEqual(set(values), {'synthetic-first-秘密\n', 'synthetic-renewed'})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            base, roots = self.files(folder)
            (Path(folder)/'archives/one.json').write_text(json.dumps({'old':values[0]}))
            self.assertGreater(scan.scan(values, roots, base=base)['hits'], 0)

    def test_pre_api_upload_failure_has_no_cookies_but_attempted_missing_journal_refuses(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder)/'issued.json'; source = (run.HERE/'focus_n8n_instance_acceptance_ops.py').read_text()
            def prepare(attempted):
                with patch.object(sys, 'stdin', io.StringIO('["synthetic-registered"]')):
                    exec(run.scan_input_prefix(p, 123, attempted, source), {'__name__':'test'})
                    return json.load(sys.stdin)
            self.assertEqual(prepare(False), {'values':['synthetic-registered'], 'since':123})
            with self.assertRaises(FileNotFoundError): prepare(True)
            p.write_text('["synthetic-cookie"]'); p.chmod(0o600)
            self.assertEqual(prepare(True)['values'], ['synthetic-registered', 'synthetic-cookie'])
            with self.assertRaises(RuntimeError): prepare(False)


if __name__ == '__main__': unittest.main()
