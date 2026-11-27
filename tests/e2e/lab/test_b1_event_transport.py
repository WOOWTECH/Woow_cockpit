"""Real synthetic HTTP -> child pipe -> parent registration; no lab access."""
import contextlib
import importlib.util
import io
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('transport_driver', Path(__file__).with_name('ha_import_b1_e2e.py'))
b1 = importlib.util.module_from_spec(spec); spec.loader.exec_module(b1)


class Http(BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers['Content-Length']))
        data = json.dumps({'token': 'synthetic-issued-"\\\n-token'}).encode()
        self.send_response(200); self.send_header('Content-Length', str(len(data))); self.end_headers(); self.wfile.write(data)
    def log_message(self, *args): pass


class EventTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        env = self.root / 'env'; env.write_text('PASSWORD=synthetic-password\n')
        markers = self.root / 'markers'; markers.write_text('{}')
        self.secrets = b1.Secrets([env], markers)
        self.server = HTTPServer(('127.0.0.1', 0), Http)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True); self.thread.start()
        self.addCleanup(self.server.server_close); self.addCleanup(self.thread.join); self.addCleanup(self.server.shutdown)
        self.url = 'http://127.0.0.1:%d' % self.server.server_port
        b1.CREDENTIAL_COVERAGE_BROKEN = False

    def run_child(self, suffix, timeout=3, expected=None):
        expected = expected or [("/auth/login", ("token",), True)]
        script = b1.PROBE_COMMON + suffix
        return b1._transport.run_events([sys.executable, '-I', '-c', script],
                   {'__events': True, 'url': self.url}, self.secrets.register_observed, expected, timeout)

    def test_http_event_before_summary_and_masked_evidence_scan(self):
        result = self.run_child('''\ncode, body = call(REQ["url"], "POST", "/auth/login", {"user":"synthetic"})\nfinish({"code": code, "detail": body["token"]})\n''')
        token = 'synthetic-issued-"\\\n-token'
        self.assertIn(token, self.secrets.secret_values())
        with patch.object(b1, 'LAB', self.root), contextlib.redirect_stdout(io.StringIO()):
            ev = b1.Evidence(self.secrets, 'case'); ev.save('summary.json', result)
        saved = json.loads((ev.dir / 'summary.json').read_text())
        self.assertNotEqual(saved['detail'], token)
        self.assertEqual(saved['detail'], self.secrets.redact(token))
        self.assertNotIn(token, saved['detail'])
        self.assertEqual(b1.scan_host_evidence(ev.dir, self.secrets)['hits'], 0)
        class Args: pass
        args = Args(); args.secrets = self.secrets
        self.assertIn(token, b1.leak_scan_request(args)['secrets'].values())

    def test_http_login_then_child_failure_retains_token(self):
        with self.assertRaises(b1._transport.Incomplete):
            self.run_child('''\ncall(REQ["url"], "POST", "/auth/login", {})\nraise RuntimeError("do not expose diagnostic")\n''')
        self.assertIn('synthetic-issued-"\\\n-token', self.secrets.secret_values())

    def test_http_login_then_timeout_retains_token(self):
        with self.assertRaises(b1._transport.Incomplete):
            self.run_child('''\ncall(REQ["url"], "POST", "/auth/login", {})\ntime.sleep(10)\n''', timeout=3)
        self.assertIn('synthetic-issued-"\\\n-token', self.secrets.secret_values())

    def test_missing_truncated_and_out_of_order_events_fail(self):
        for script in ("print('{\\\"type\\\":', flush=True)",
                       'import json; print(json.dumps({"type":"auth","sequence":1,"status":200,"source":"/auth/login","credentials":{"token":"synthetic-bad-seq"}}),flush=True)',
                       'import json; print(json.dumps({"type":"summary","sequence":0,"data":{}}),flush=True)'):
            with self.subTest(script=script), self.assertRaises(b1._transport.Incomplete):
                b1._transport.run_events([sys.executable, '-I', '-c', script], {},
                    self.secrets.register_observed, [('/auth/login', ('token',), True)], 2)
        self.assertIn('synthetic-bad-seq', self.secrets.secret_values())

    def test_duplicate_event_fields_cannot_hide_issued_credentials(self):
        script = """import json, sys
frame = '{"type":"auth","sequence":0,"source":"/auth/login","status":200,"credentials":{"token":"synthetic-hidden-secret","token":"synthetic-last-secret"}}'
print(frame, flush=True)
sys.stdin.readline()
sys.stdin.readline()
print(json.dumps({"type":"summary","sequence":1,"data":{"ok":True}}), flush=True)
sys.stdin.readline()
print(json.dumps({"type":"end","sequence":2}), flush=True)
sys.stdin.readline()
"""
        with self.assertRaises(b1._transport.Incomplete):
            b1._transport.run_events([sys.executable, '-I', '-c', script], {},
                self.secrets.register_observed, [('/auth/login', ('token',), True)], 3)
        # Isolated mutation: old permissive decoding accepts this exact stream.
        original_loads = json.loads
        with patch.object(b1._transport.json, 'loads', side_effect=lambda value, **_kw: original_loads(value)):
            accepted = b1._transport.run_events([sys.executable, '-I', '-c', script], {},
                self.secrets.register_observed, [('/auth/login', ('token',), True)], 3)
        self.assertEqual(accepted, {'ok': True})

    def test_wrong_source_is_rejected_after_registration(self):
        script = ('import json; print(json.dumps({"type":"auth","sequence":0,"source":"/wrong",'
                  '"status":200,"credentials":{"token":"synthetic-wrong-source"}}),flush=True)')
        with self.assertRaises(b1._transport.Incomplete):
            b1._transport.run_events([sys.executable, '-I', '-c', script], {}, self.secrets.register_observed,
                                     [('/auth/login', ('token',), True)], 3)
        self.assertIn('synthetic-wrong-source', self.secrets.secret_values())

    def test_request_size_and_blocked_stdin_fail_with_deadline(self):
        import time
        script = 'import time; time.sleep(10)'
        argv = [sys.executable, '-I', '-c', script]
        with self.assertRaisesRegex(b1._transport.Incomplete, 'too large'):
            b1._transport.run_events(argv, {'input': 'x' * (b1._transport.MAX_REQUEST + 1)},
                                     self.secrets.register_observed, [], 1)
        start = time.monotonic()
        with self.assertRaises(b1._transport.Incomplete):
            b1._transport.run_events(argv, {'input': 'x' * 60000}, self.secrets.register_observed, [], 1)
        self.assertLess(time.monotonic() - start, 4)

    def test_failure_latches_and_blocks_restore_before_device(self):
        with patch.object(b1._transport, 'run_events', side_effect=b1._transport.Incomplete('private')):
            with self.assertRaises(b1.Failed):
                b1.event_device_python('probe', {}, self.secrets, 1)
        with patch.object(b1, 'ok', side_effect=AssertionError('restore touched device')):
            with self.assertRaisesRegex(b1.Failed, 'coverage incomplete'):
                b1.restore('x', ['omnigent'], ev=None, tag='x')
        b1.CREDENTIAL_COVERAGE_BROKEN = False


if __name__ == '__main__': unittest.main()
