"""Caller boundary tests using only synthetic local data."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('review_driver', Path(__file__).with_name('ha_import_b1_e2e.py'))
b1 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b1)


class Boundaries(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        env = self.root / 'env'; env.write_text('PASSWORD=abcdefghi\n')
        markers = self.root / 'markers'; markers.write_text('{}')
        self.secrets = b1.Secrets([env], markers)
        self.special = 'secret"\\line\nending'
        self.secrets.register('SPECIAL', self.special)

    def test_real_evidence_check_and_save_redact_before_json(self):
        with patch.object(b1, 'LAB', self.root), contextlib.redirect_stdout(io.StringIO()) as printed:
            ev = b1.Evidence(self.secrets, 'synthetic')
            data = {self.special: ['prefix ' + self.special, {'message': self.special}]}
            ev.check('failed ' + self.special, False, data)
            ev.save('case.json', data)
            ev.save('results.json', ev.results)
            raw = (ev.dir / 'case.json').read_text()
            parsed = json.loads(raw)
            parsed_result = json.loads((ev.dir / 'results.json').read_text())
            detail = json.loads(parsed_result[0]['detail'])
            for obj in (parsed, detail, parsed_result):
                self.assertNotIn(self.special, str(obj))
            self.assertIn('<SPECIAL>', str(parsed))
            self.assertNotIn(self.special, printed.getvalue())
            self.assertNotIn(self.special, (ev.dir / 'run.log').read_text())
            self.assertEqual(os.stat(ev.dir / 'case.json').st_mode & 0o777, 0o600)

    def test_redacted_key_collision_stops_before_evidence_write(self):
        with patch.object(b1, 'LAB', self.root), contextlib.redirect_stdout(io.StringIO()) as printed:
            ev = b1.Evidence(self.secrets, 'collision')
            with self.assertRaisesRegex(b1.Failed, 'key collision'):
                ev.save('case.json', {self.special: 'first', '<SPECIAL>': 'second'})
            self.assertFalse((ev.dir / 'case.json').exists())
            self.assertNotIn(self.special, printed.getvalue())

    def test_device_scan_missing_root_and_walk_error_fail(self):
        code = b1.LEAK_SCAN
        start = code.index('roots = ['); end = code.index('\nfor root in roots:', start)
        request = json.dumps({'secrets': {'test': 'synthetic-secret'}, 'podman_secrets': [], 'uid': 1019})
        def run(source):
            return subprocess.run([sys.executable, '-I', '-c', source], input=request, text=True, capture_output=True)
        missing = code[:start] + 'roots = ' + repr([str(self.root / 'absent')]) + code[end:]
        self.assertNotEqual(run(missing).returncode, 0)
        jobs = self.root / 'jobs'; jobs.mkdir()
        broken = code[:start] + ('def broken_walk(path, onerror, followlinks):\n'
                                '    onerror(PermissionError("synthetic private path"))\n'
                                '    yield from ()\n'
                                'os.walk = broken_walk\nroots = ' + repr([str(jobs)])) + code[end:]
        failed = run(broken)
        self.assertNotEqual(failed.returncode, 0)
        self.assertNotIn('synthetic-secret', failed.stderr)

    def test_host_scan_and_device_scan_failure_prevent_success(self):
        evidence = self.root / 'evidence'; evidence.mkdir()
        (evidence / 'run.log').write_text('synthetic-secret')
        self.secrets.register('TOKEN', 'synthetic-secret')
        self.assertEqual(b1.scan_host_evidence(evidence, self.secrets), {'files': 1, 'hits': 1})
        with self.assertRaises(b1.Failed):
            b1.scan_host_evidence(evidence / 'missing', self.secrets)
        def failed_walk(path, onerror, **kwargs):
            onerror(PermissionError('private path'))
            yield from ()
        with patch.object(b1.os, 'walk', failed_walk):
            with self.assertRaises(b1.Failed):
                b1.scan_host_evidence(evidence, self.secrets)
        class Args: pass
        class Evidence: pass
        args = Args(); args.secrets = self.secrets
        ev = Evidence(); ev.dir = evidence
        ev.save = lambda *args: self.fail('must not report success')
        with patch.object(b1, 'device_python', side_effect=b1.Failed('scan failed')):
            with self.assertRaisesRegex(b1.Failed, 'scan failed'):
                b1.scenario_leaks(ev, args)

    def test_failed_login_http_status_does_not_retry(self):
        # Run the real common probe call() with a fake HTTP error and observe attempts.
        code = b1.PROBE_COMMON + r'''
import io
calls = []
def fake(req, timeout):
    calls.append(1)
    raise urllib.error.HTTPError(req.full_url, 400, "bad", {}, io.BytesIO(b"not_initialized"))
urllib.request.urlopen = fake
code, _ = call("http://127.0.0.1", "POST", "/auth/login", {"password":"synthetic"}, wait=5)
first = len(calls)
def unauthorized(req, timeout):
    calls.append(1)
    raise urllib.error.HTTPError(req.full_url, 401, "bad", {}, io.BytesIO(b"not_initialized"))
urllib.request.urlopen = unauthorized
code2, _ = call("http://127.0.0.1", "POST", "/api/v5/login", {}, wait=5)
print(json.dumps({"code": code, "calls": first, "code2": code2, "calls2": len(calls) - first}))
'''
        proc = subprocess.run([sys.executable, '-I', '-c', code], input='{}', text=True,
                              capture_output=True, check=True, timeout=3)
        self.assertEqual(json.loads(proc.stdout), {'code': 400, 'calls': 1, 'code2': 401, 'calls2': 1})

    def test_baseline_stops_before_restore(self):
        with patch.object(b1, 'restore', side_effect=AssertionError('restore called')):
            with self.assertRaisesRegex(b1.Failed, 'baseline preflight'):
                b1.scenario_baseline(None, None)

    def test_probe_routes_and_negative_login_blocked_before_device(self):
        self.assertIn('tokens["negative"], negative = login(', b1.OMNI_PROBE)
        for script in (b1.OMNI_PROBE, b1.EMQX_PROBE, b1.CREDENTIAL_HTTP):
            with patch.object(b1, 'run', side_effect=AssertionError('device action')):
                with self.assertRaisesRegex(b1.Failed, 'producer disabled'):
                    b1.device_python(script, {})


if __name__ == '__main__':
    unittest.main()
