"""Generated plaintext/real SecureTar v3; no runtime or credential access."""
import contextlib
import io
import unittest
from unittest.mock import patch

import emqx_source_consumer as consumer
import emqx_real_candidate as caller
from ha_real_fixture import source_binding
from tests.backup import hafixtures as hx
import test_emqx_real_candidate as fixtures


def documents():
    return {name: b'[]' for name in consumer.SOURCES -
            {'backup-key', 'source-options', 'source-cookie'}}


def payload(extra=()):
    return hx.tar_bytes([
        {'name': 'addon.json', 'data': b'{"system":{"slug":"woow-emqx"},"user":{"options":{"password":"fixture-options"}},"version":"5.9.0"}'},
        {'name': 'data/emqx/node.cookie', 'data': b'fixture-cookie\n'},
        {'name': 'data/emqx/node.name', 'data': b'emqx@fixture'}, *extra])


def binding(raw):
    @contextlib.contextmanager
    def opened(slug):
        yield io.BytesIO(raw)
    return {'addon_member': lambda slug: 'repo_woow-emqx', 'open': opened}


class ConsumerTests(unittest.TestCase):
    def test_complete_stream_registered_and_replayed_identically(self):
        capture = consumer.Capture('fixture-key', documents())
        raw = payload()
        bound = capture(binding(raw))
        with bound['open']('repo_woow-emqx') as stream:
            self.assertEqual(stream.read(), raw)
        for secret in (b'fixture-key', b'fixture-options', b'fixture-cookie'):
            with self.assertRaises(consumer.PrivateFailure):
                capture.registry.scan(secret)
        with self.assertRaises(consumer.PrivateFailure):
            capture(binding(raw))

    def test_opt_in_selection_matches_product_and_observes_unused_cookie_absence(self):
        raw = hx.tar_bytes([
            {'name': 'addon.json', 'data': b'{"system":{"slug":"woow-emqx"},"version":"5.9.0"}'},
            {'name': 'data/emqx/node.name', 'data': b'emqx@fixture'},
            {'name': 'data/emqx/data/configs/generated.conf', 'data': b'x' * 131072}])
        capture = consumer.Capture('fixture-key', documents(), product_selection=True)
        bound = capture(binding(raw))
        self.assertEqual(capture.registry.summary()['source-cookie'], 0)
        self.assertEqual(capture.discarded, {'files': 1, 'bytes': 131072})
        with bound['open']('repo_woow-emqx') as replay:
            self.assertEqual(replay.read(), raw)
        with self.assertRaises(consumer.PrivateFailure):
            consumer.Capture('fixture-key', documents())(binding(raw))

    def test_selection_never_discards_unknown_staged_secrets_or_unsafe_tar(self):
        for name in ('data/emqx/data/mnesia/schema.DAT',
                     'data/emqx/data/certs/key.pem', 'data/emqx/data/authz/acl.conf'):
            with self.subTest(name=name), self.assertRaises(consumer.PrivateFailure):
                consumer.Capture('fixture-key', documents(), product_selection=True)(
                    binding(payload([{'name': name, 'data': b'unsupported-private'}])))
        with self.assertRaises(Exception):
            consumer.Capture('fixture-key', documents(), product_selection=True)(
                binding(payload() + b'unsafe-trailer'))
        with self.assertRaises(consumer.PrivateFailure):
            consumer.Capture('fixture-key', documents(), product_selection='true')

    def test_missing_unknown_binary_and_trailing_sources_refuse(self):
        for raw in (payload()[:3072], payload() + b'nonzero-trailer',
                    payload([{'name': 'data/emqx/data/mnesia/schema.DAT', 'data': b'binary'}]),
                    payload([{'name': 'data/emqx/data/configs/cluster.hocon', 'data': b'a=1'}])):
            with self.subTest(length=len(raw)), self.assertRaises(Exception):
                consumer.Capture('fixture-key', documents())(binding(raw))
        with self.assertRaises(consumer.PrivateFailure):
            consumer.Capture('fixture-key', {})
        with self.assertRaises(consumer.PrivateFailure):
            consumer.Capture('fixture-key', documents())(binding(hx.tar_bytes([])))

    def test_reader_limits_duplicate_fields_and_references(self):
        for raw in (b'{"a":1,"a":2}', b'{"password":"${SECRET}"}',
                    b'{"key":"file:/private"}', b'NaN', b'[' * 20 + b'0' + b']' * 20):
            with self.assertRaises(Exception):
                consumer.json_values(raw)
        docs = documents()
        docs['tls'] = b'x' * (consumer.MAX_VALUE + 1)
        with self.assertRaises(consumer.PrivateFailure):
            consumer.Capture('fixture-key', docs)
        with patch.object(consumer, 'MAX_STREAM', 1024):
            with self.assertRaises(consumer.PrivateFailure):
                consumer.Capture('fixture-key', documents())(binding(payload()))

    def test_late_stream_failure_prevents_replay_and_sealing(self):
        class Broken(io.BytesIO):
            def finish(self):
                raise RuntimeError('fixture-private-error')
        @contextlib.contextmanager
        def opened(slug):
            yield Broken(payload())
        capture = consumer.Capture('fixture-key', documents())
        with self.assertRaises(RuntimeError):
            capture(dict(binding(b''), open=opened))
        self.assertFalse(capture.registry._sealed)

    def test_real_v3_unsupported_source_refuses_before_temporary_runtime(self):
        case = fixtures.RealCallerTests()
        case.setUp()
        self.addCleanup(case.doCleanups)
        case.fixture()
        capture = consumer.Capture(hx.PASSWORD, documents())
        with source_binding(case.path, 'emqx', caller.hacommon.semver('5.8.9'), case.digest,
                            keys=capture.keys, required_encryption='v3') as source:
            with self.assertRaisesRegex(consumer.PrivateFailure,
                                        '^private-source-format-unsupported$'):
                capture(source)
        self.assertFalse(capture.registry._sealed)
        with patch.object(caller, 'build_verified_candidate',
                          side_effect=lambda *a, **k: consumer.build_consumed_candidate(
                              *a, password=hx.PASSWORD, target_documents=documents(),
                              **{key: value for key, value in k.items() if key != 'keys'})):
            with self.assertRaisesRegex(consumer.PrivateFailure, '^candidate-refused$'):
                case.invoke()
        case.temp_factory.assert_not_called()
        self.assertEqual(set(case.root.iterdir()), {case.path})
        self.assertFalse(any(event[0] == 'volume' for event in case.runtime.events))
