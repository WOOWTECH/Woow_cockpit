"""Synthetic HTTP integration only: never contacts a lab device."""
import importlib.util
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('b1_driver', Path(__file__).with_name('ha_import_b1_e2e.py'))
b1 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b1)


class Handler(BaseHTTPRequestHandler):
    calls = []
    refresh_reply = {'access_token': 'synthetic-access-new', 'refresh_token': 'synthetic-refresh-new'}

    def do_POST(self):
        payload = self.rfile.read(int(self.headers['Content-Length']))
        type(self).calls.append((self.path, payload))
        body = ({'token': 'synthetic-access-first', 'refresh_token': 'synthetic-refresh-first'}
                if self.path == '/auth/login' else type(self).refresh_reply)
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        env = Path(self.temp.name) / 'env'
        env.write_text('B1_CREDENTIAL_LAB_USER=lab-user\nB1_CREDENTIAL_LAB_PASSWORD=synthetic-password\n')
        markers = Path(self.temp.name) / 'markers'
        markers.write_text('{}')
        self.secrets = b1.Secrets([env], markers)
        self.server = HTTPServer(('127.0.0.1', 0), Handler)
        Handler.calls = []
        Handler.refresh_reply = {'access_token': 'synthetic-access-new', 'refresh_token': 'synthetic-refresh-new'}
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.thread.join()
        self.server.server_close()
        self.temp.cleanup()

    def device(self, code, request, **kwargs):
        if code == b1.CREDENTIAL_HTTP:
            code = code.replace('http://127.0.0.1:8000', 'http://127.0.0.1:%d' % self.server.server_port)
            proc = subprocess.run([sys.executable, '-I', '-c', code], input=json.dumps(request),
                                  text=True, capture_output=True, check=True)
            return json.loads(proc.stdout)
        self.scan_request = request
        return {'hits': {}, 'scanned': 0, 'names': len(request['secrets']), 'journal_bytes': 0}

    def test_caller_http_producer_registry_and_scan_boundary(self):
        class Evidence:
            def __init__(self): self.records = []
            def check(self, *a): self.records.append(a)
            def save(self, *a): self.records.append(a)
        class Args: pass
        args = Args(); args.secrets = self.secrets
        evidence = Evidence()
        with patch.object(b1, 'device_python', side_effect=self.device):
            b1.scenario_credentials(evidence, args)
            with self.assertRaisesRegex(b1.Failed, 'coverage incomplete'):
                b1.scenario_leaks(evidence, args)
        self.assertEqual([p for p, _ in Handler.calls], ['/auth/login', '/oauth/token'])
        self.assertTrue(json.loads(Handler.calls[0][1])['issue_refresh'])
        expected = {'synthetic-access-first', 'synthetic-refresh-first',
                    'synthetic-access-new', 'synthetic-refresh-new'}
        self.assertTrue(expected <= set(self.scan_request['secrets'].values()))
        for value in expected:
            self.assertNotIn(value, self.secrets.redact(value))
            self.assertNotIn(value, str(evidence.records))
        self.assertFalse(evidence.records[0][2]['runner_coverage'])

    def test_missing_refresh_event_fails_and_preserves_first_generation(self):
        Handler.refresh_reply = {'refresh_token': 'synthetic-refresh-new'}
        with patch.object(b1, 'device_python', side_effect=self.device):
            with self.assertRaisesRegex(b1.Failed, 'refresh event missing'):
                b1.direct_credential_probe(self.secrets, 'lab-user', 'synthetic-password')
        self.assertIn('synthetic-access-first', self.secrets.secret_values())
        self.assertIn('synthetic-refresh-new', self.secrets.secret_values())
        self.assertEqual(len(Handler.calls), 2)

    def test_missing_login_grant_prevents_refresh(self):
        with patch.object(b1, 'device_python', return_value={'token': 'synthetic-access-first'} ) as device:
            with self.assertRaisesRegex(b1.Failed, 'login event missing'):
                b1.direct_credential_probe(self.secrets, 'lab-user', 'synthetic-password')
        self.assertEqual(device.call_count, 1)
        self.assertIn('synthetic-access-first', self.secrets.secret_values())

    def test_runner_fails_before_any_action(self):
        with patch.object(b1, 'owner', side_effect=AssertionError('unexpected action')):
            with self.assertRaisesRegex(b1.Failed, 'event source unavailable'):
                b1.scenario_runner(None, None)


if __name__ == '__main__':
    unittest.main()
