"""Offline regression checks; never contact a device or production."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('b1', Path(__file__).with_name('ha_import_b1_e2e.py'))
b1 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b1)


class SecretTests(unittest.TestCase):
    def test_dynamic_secrets_are_redacted_and_in_scan_set(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = Path(tmp) / 'env'
            env.write_text('TEST_USER=alice\nTEST_PASSWORD=abcdefgh\n')
            markers = Path(tmp) / 'markers'
            markers.write_text('{}')
            secrets = b1.Secrets([env], markers)
            secrets.register('SESSION_TOKEN', 'generated-token-123')
            secrets.register('SHORT_TOKEN', 'sixsix')
            text = secrets.redact('alice abcdefgh generated-token-123 sixsix')
            self.assertEqual(text, 'alice <TEST_PASSWORD> <SESSION_TOKEN> <SHORT_TOKEN>')
            self.assertIn('generated-token-123', secrets.secret_values())
            self.assertIn('sixsix', secrets.secret_values())
            with self.assertRaises(ValueError):
                secrets.register('bad', 'tiny')
            with self.assertRaises(ValueError):
                secrets.register('SESSION_TOKEN', 'replacement-token-456')
            self.assertIn('generated-token-123', secrets.secret_values())

    def test_omnigent_probe_uses_event_transport(self):
        from unittest.mock import patch
        with patch.object(b1, 'event_device_python', return_value={'status': 'ok'}) as transport:
            self.assertEqual(b1.omnigent_probe('registry', {}), {'status': 'ok'})
            transport.assert_called_once_with(b1.OMNI_PROBE, {}, 'registry', [('/auth/login', ('token',), False)] * 5)

    def test_runner_consumer_rejects_missing_credentials_before_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = Path(tmp) / 'env'; env.write_text('PASSWORD=abcdefgh\n')
            markers = Path(tmp) / 'markers'; markers.write_text('{}')
            secrets = b1.Secrets([env], markers)
            original = b1.device_python
            try:
                for script, count in ((b1.RUNNER_TOKEN, 2), (b1.RUNNER_HOST, 3)):
                    valid = ['secret-value-%d' % i for i in range(count)]
                    cases = [None, valid[:-1]]
                    for index in range(count):
                        for bad in (None, '', 'tiny'):
                            vals = valid.copy(); vals[index] = bad; cases.append(vals)
                    for issued in cases:
                        response = {'detail': 'secret-value-0'}
                        if issued is not None: response['_issued_credentials'] = issued
                        b1.device_python = lambda *a, **k: dict(response)
                        with self.assertRaises(b1.Failed):
                            b1.runner_probe(secrets, script, {}, count)
                    b1.device_python = lambda *a, **k: {'_issued_credentials': valid, 'detail': valid[0]}
                    result = b1.runner_probe(secrets, script, {}, count)
                    self.assertNotIn('_issued_credentials', result)
                    self.assertNotIn(valid[0], secrets.redact(result))
                    self.assertTrue(all(v in secrets.secret_values() for v in valid))
            finally:
                b1.device_python = original

    def test_scenario_passes_dynamic_secrets_to_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = Path(tmp) / 'env'
            env.write_text('TEST_PASSWORD=abcdefgh\n')
            markers = Path(tmp) / 'markers'
            markers.write_text('{}')
            secrets = b1.Secrets([env], markers)
            secrets.register('SESSION_TOKEN', 'generated-token-123')
            captured = {}
            class Evidence:
                dir = Path(tmp)
                def save(self, *args): pass
                def check(self, *args): pass
            class Args:
                pass
            args = Args()
            args.secrets = secrets
            original = b1.device_python
            def fake_scan(code, request, **kwargs):
                captured.update(request)
                return {'hits': 0, 'scanned': 0, 'names': len(request['secrets']), 'journal_bytes': 0}
            try:
                b1.device_python = fake_scan
                with self.assertRaisesRegex(b1.Failed, "coverage incomplete"):
                    b1.scenario_leaks(Evidence(), args)
            finally:
                b1.device_python = original
            self.assertEqual(captured['secrets']['SESSION_TOKEN'], 'generated-token-123')

    def test_scan_entire_large_file_and_fail_on_journal_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            jobs = root / 'jobs'
            jobs.mkdir()
            with (jobs / 'large').open('wb') as handle:
                handle.seek(64 * 1024 * 1024 + 5)
                handle.write(b'dynamic-secret-value')
            journal = root / 'journalctl'
            journal.write_text('#!/bin/sh\nexit 0\n')
            journal.chmod(0o755)
            code = b1.LEAK_SCAN
            start = code.index('roots = [')
            end = code.index('\nfor root in roots:', start)
            code = code[:start] + 'roots = ' + repr([str(jobs)]) + code[end:]
            request = json.dumps({'secrets': {'dynamic': 'dynamic-secret-value'}, 'podman_secrets': [], 'uid': 1019})
            env = {**os.environ, 'PATH': str(root) + ':' + os.environ['PATH']}
            run = lambda: subprocess.run([sys.executable, '-I', '-c', code], input=request, text=True, capture_output=True, env=env)
            result = run()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)['hits'], 1)
            journal.write_text('#!/bin/sh\nexit 1\n')
            self.assertNotEqual(run().returncode, 0)


if __name__ == '__main__':
    unittest.main()
