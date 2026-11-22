"""Generated native JSON contracts only: consumer wiring, not real cold acceptance."""
import base64
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from emqx_cold_history import CONTAINERS
from emqx_source_consumer import Capture, PrivateFailure
from emqx_semantic_readers import SemanticRefused
from test_emqx_source_consumer import payload, binding, documents

PREFIX = 'data/emqx/data/mnesia/emqx@fixture/'
SECRET = b'generated-persisted-jwt-private'


def decoder(raw, kind):
    container, traversal = CONTAINERS[kind]
    return json.dumps(dict(contract='emqx-cold-history-json-v1', version='5.8.9',
        otp_release='26', erts_version='14.2.5.11', input_sha256=hashlib.sha256(raw).hexdigest(),
        input_bytes=len(raw), complete=True, kind=kind, container=container,
        traversal=traversal, semantics='historical-value-superset', final_state=False,
        term_count=1, terms=[dict(type='binary', value=base64.b64encode(SECRET).decode())])).encode()


def source(extra=()):
    return payload([{'name': PREFIX + 'schema.DAT', 'data': b'generated-schema'},
                    {'name': PREFIX + 'emqx_admin_jwt.DCD', 'data': b'generated-jwt-data'}, *extra])


class ColdCaptureTests(unittest.TestCase):
    def test_selected_inventory_to_decoder_to_actual_registry_and_private_replay(self):
        calls = Mock(side_effect=decoder)
        capture = Capture('fixture-key', documents(), product_selection=True, cold_decoder=calls)
        raw = source()
        bound = capture(binding(raw))
        self.assertEqual(calls.call_count, 2)
        self.assertEqual(capture.cold_receipt['files'], 2)
        self.assertFalse(capture.cold_receipt['final_state'])
        with self.assertRaises(PrivateFailure):
            capture.registry.scan(SECRET)
        with bound['open']('repo_woow-emqx') as stream:
            self.assertEqual(stream.read(), raw)

    def test_late_native_failure_cannot_seal_or_publish_receipt(self):
        def late(raw, kind):
            if kind == 'dcd':
                raise SemanticRefused()
            return decoder(raw, kind)
        capture = Capture('fixture-key', documents(), product_selection=True, cold_decoder=late)
        with self.assertRaises(SemanticRefused):
            capture(binding(source()))
        self.assertFalse(capture.registry._sealed)
        self.assertIsNone(capture.cold_receipt)

    def test_unknown_selected_file_missing_schema_and_inventory_count_refuse(self):
        cases = [source([{'name': PREFIX + 'unknown.bin', 'data': b'private'}]),
                 payload([{'name': PREFIX + 'emqx_admin_jwt.DCD', 'data': b'private-rows'}]),
                 source([{'name': PREFIX + 'extra_%d.DCD' % n, 'data': b'row'} for n in range(64)])]
        for raw in cases:
            calls = Mock(side_effect=decoder)
            capture = Capture('fixture-key', documents(), product_selection=True, cold_decoder=calls)
            with self.subTest(bytes=len(raw)), self.assertRaises(PrivateFailure):
                capture(binding(raw))
            calls.assert_not_called()
            self.assertFalse(capture.registry._sealed)

    def test_authenticated_finish_precedes_all_native_calls_and_spool_cleanup(self):
        class Broken(io.BytesIO):
            def finish(self):
                raise RuntimeError('generated-private-late-error')
        @contextlib.contextmanager
        def opened(_):
            yield Broken(source())
        calls = Mock(side_effect=decoder)
        with tempfile.TemporaryDirectory() as root:
            with Capture('fixture-key', documents(), product_selection=True,
                         cold_decoder=calls, spool_directory=root) as captured:
                with self.assertRaises(PrivateFailure):
                    captured(dict(binding(b''), open=opened))
                calls.assert_not_called()
                self.assertFalse(captured.registry._sealed)
            self.assertEqual(list(Path(root).iterdir()), [])
