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
    login_reply = {'token': 'synthetic-access-first', 'refresh_token': 'synthetic-refresh-first'}
    refresh_reply = {'access_token': 'synthetic-access-new', 'refresh_token': 'synthetic-refresh-new'}

    def do_POST(self):
        payload = self.rfile.read(int(self.headers['Content-Length']))
        type(self).calls.append((self.path, payload))
        body = (type(self).login_reply if self.path == '/auth/login' else type(self).refresh_reply)
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
        Handler.login_reply = {'token': 'synthetic-access-first', 'refresh_token': 'synthetic-refresh-first'}
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

    def test_credential_scenario_uses_real_event_transport(self):
        class Args: pass
        class Evidence:
            def __init__(self): self.results = []
            def check(self, *args): self.results.append(args)
        args = Args(); args.secrets = self.secrets
        ev = Evidence()
        def execute(script, request, secrets, expected, **kwargs):
            script = script.replace('http://127.0.0.1:8000', 'http://127.0.0.1:%d' % self.server.server_port)
            request = dict(request, __events=True)
            return b1._transport.run_events([sys.executable, '-I', '-c', script], request,
                                           secrets.register_observed, expected, 8)
        with patch.object(b1, 'event_device_python', side_effect=execute):
            b1.scenario_credentials(ev, args)
        self.assertEqual([p for p, _ in Handler.calls], ['/auth/login', '/oauth/token'])
        scanned = b1.leak_scan_request(args)['secrets'].values()
        for value in ('synthetic-access-first', 'synthetic-refresh-first',
                      'synthetic-access-new', 'synthetic-refresh-new'):
            self.assertIn(value, scanned)
            self.assertNotIn(value, str(ev.results))
        self.assertFalse(ev.results[0][2]['runner_coverage'])

    def test_real_child_rejects_missing_empty_and_short_grants(self):
        schema = [('/auth/login', ('token', 'refresh_token'), True),
                  ('/oauth/token', ('access_token', 'refresh_token'), True)]
        def invoke():
            code = b1.CREDENTIAL_HTTP.replace('http://127.0.0.1:8000',
                                               'http://127.0.0.1:%d' % self.server.server_port)
            return b1._transport.run_events([sys.executable, '-I', '-c', code],
                {'__events': True, 'username': 'synthetic-user', 'password': 'synthetic-password'},
                self.secrets.register_observed, schema, 8)
        for stage in ('login', 'refresh'):
            for bad in ('missing', '', 'tiny'):
                with self.subTest(stage=stage, bad=bad):
                    Handler.calls = []
                    Handler.login_reply = {'token': 'synthetic-login-token', 'refresh_token': 'synthetic-login-grant'}
                    Handler.refresh_reply = {'access_token': 'synthetic-new-token', 'refresh_token': 'synthetic-new-grant'}
                    target = Handler.login_reply if stage == 'login' else Handler.refresh_reply
                    if bad == 'missing': target.pop('refresh_token')
                    else: target['refresh_token'] = bad
                    with self.assertRaises(b1._transport.Incomplete) as caught:
                        invoke()
                    self.assertNotIn('synthetic-', str(caught.exception))
                    self.assertIn('synthetic-login-token', self.secrets.secret_values())
                    if stage == 'refresh':
                        self.assertIn('synthetic-new-token', self.secrets.secret_values())
                        self.assertEqual(len(Handler.calls), 2)
                    else:
                        self.assertEqual(len(Handler.calls), 1)
                    if bad == 'tiny':
                        self.assertIn('tiny', self.secrets.secret_values())
                        self.assertNotIn('tiny', self.secrets.redact('tiny'))

    def test_arm_and_other_imports_are_preflight_blocked(self):
        with patch.object(b1, 'import_once', side_effect=AssertionError('import started')):
            with self.assertRaisesRegex(b1.Failed, 'arm preflight'):
                b1.scenario_arm(None, None)
        with patch.object(b1, 'ok', side_effect=AssertionError('device touched')):
            with self.assertRaisesRegex(b1.Failed, 'import preflight'):
                b1.import_once(None, None, 'arm-enc', ['omnigent'])

    def test_runner_fails_before_any_action(self):
        with patch.object(b1, 'owner', side_effect=AssertionError('unexpected action')):
            with self.assertRaisesRegex(b1.Failed, 'event source unavailable'):
                b1.scenario_runner(None, None)


if __name__ == '__main__':
    unittest.main()
