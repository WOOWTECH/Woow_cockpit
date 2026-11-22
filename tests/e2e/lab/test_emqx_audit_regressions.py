"""Defensive regressions for three independently reproduced EMQX defects."""
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from urllib.parse import urlsplit, unquote_to_bytes

from tests.backup import hafixtures as hx
from test_emqx_source_consumer import payload, documents, binding
from emqx_source_consumer import Capture, addon_values, PrivateFailure
from emqx_private_evidence import publish
from emqx_native_hocon import native_hocon
from emqx_semantic_readers import read_hocon, SemanticRefused


class AuditRegressionTests(unittest.TestCase):
    def test_url_query_and_fragment_cannot_hide_actual_decoded_password(self):
        for suffix in ('?note=@suffix', '#note@extension', '/path?note=@suffix'):
            url = 'https://audit-user:p%61ssed@fixture.invalid' + suffix
            self.assertEqual(unquote_to_bytes(urlsplit(url).password), b'passed')
            addon = json.dumps({'system': {'slug': 'woow-emqx', 'url': url}, 'version': '5.9.0'}).encode()
            self.assertIn(b'passed', addon_values(addon))
            capture = Capture('audit-key', documents(), product_selection=True)
            capture(binding(hx.tar_bytes([
                {'name': 'addon.json', 'data': addon},
                {'name': 'data/emqx/node.name', 'data': b'emqx@fixture'}])))
            with self.assertRaises(PrivateFailure):
                capture.registry.scan(b'passed')
            with tempfile.TemporaryDirectory() as directory:
                with self.assertRaises(PrivateFailure):
                    publish(directory, 'audit.json', registry=capture.registry,
                            phase='preflight', result='passed', coverage=capture.registry.summary(),
                            coverage_mode='names')
                self.assertEqual(list(Path(directory).iterdir()), [])

    def test_memory_and_spool_replays_are_readonly_including_kernel_fd(self):
        raw = payload()
        with tempfile.TemporaryDirectory() as directory:
            for spool in (None, directory):
                with self.subTest(spool=spool is not None):
                    with Capture('audit-key', documents(), spool_directory=spool) as captured:
                        bound = captured(binding(raw))
                        with bound['open']('repo_woow-emqx') as replay:
                            writable = replay.writable()
                            if not writable:
                                for operation in (lambda: replay.write(b'x'), lambda: replay.truncate(0)):
                                    with self.assertRaises(io.UnsupportedOperation):
                                        operation()
                                try:
                                    fd = replay.fileno()
                                except io.UnsupportedOperation:
                                    fd = None
                                if fd is not None:
                                    with self.assertRaises(OSError):
                                        os.write(fd, b'x')
                        with bound['open']('repo_woow-emqx') as replay:
                            self.assertEqual(replay.read(), raw)
                        self.assertTrue(captured.registry._sealed)
                    self.assertFalse(writable)
                    self.assertEqual(list(Path(directory).iterdir()), [])

    def test_actual_native_file_authorizer_dependency_cannot_seal(self):
        raw = b'authorization { sources=[{type=file,path="/data/emqx/data/not-staged/audit.acl"}] }'
        parsed = native_hocon(raw)
        # Scanner reference list concerns HOCON syntax; semantic file dependencies
        # must still refuse independently of include/substitution detection.
        self.assertEqual(json.loads(parsed)['references'], [])
        with self.assertRaises(SemanticRefused):
            read_hocon(raw, lambda _: parsed)
        capture = Capture('audit-key', documents(), product_selection=True,
                          hocon_parser=lambda _: parsed)
        with self.assertRaises(PrivateFailure):
            capture(binding(payload([
                {'name': 'data/emqx/data/configs/cluster.hocon', 'data': raw},
                {'name': 'data/emqx/data/not-staged/audit.acl', 'data': b'not-captured'}])))
        self.assertFalse(capture.registry._sealed)
