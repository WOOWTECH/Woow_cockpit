"""Actual native parser regressions; synthetic data, no broker or lab access."""
import unittest
import contextlib
import io
import pathlib
import tempfile
from unittest.mock import patch
from emqx_native_hocon import native_hocon
from emqx_semantic_readers import read_hocon, SemanticRefused
import emqx_source_consumer as consumer
from test_emqx_source_consumer import documents, payload, binding


class NativeTests(unittest.TestCase):
    def test_native_syntax_overrides_concat_and_unicode(self):
        values = read_hocon('''# native syntax
        auth { password = "first-private"\n password = "second-private" }
        quoted = "abc" "def"
        unicode = "測試"
        array = [true, 12, "array-private",]
        '''.encode(), native_hocon).values
        for secret in (b'first-private', b'second-private', b'abc', b'def',
                       b'abcdef', '測試'.encode(), b'array-private'):
            self.assertIn(secret, values)

    def test_native_nested_authentication_keeps_overwritten_and_concat_secrets(self):
        # Six semantic container levels; hocon's boxed/list/field wrappers must
        # not exhaust the native depth limit before Python's semantic checks.
        raw = '''authentication = [{
            mechanism = password_based
            backend = http
            body { credentials { primary {
                password = "nested-old-private"
                password = "nested-new-private"
                token = "nested-left-" "right-private"
                labels = ["nested-array-private", "unicode-測試"]
            } } }
        }]
        '''.encode()
        values = read_hocon(raw, native_hocon).values
        for secret in (b'nested-old-private', b'nested-new-private',
                       b'nested-left-', b'right-private',
                       b'nested-left-right-private', b'nested-array-private',
                       'unicode-測試'.encode()):
            self.assertIn(secret, values)

    def test_native_semantic_depth_and_nested_dependencies_remain_gated(self):
        from emqx_native_hocon import native_hocon_diagnostic
        deep = b'level {' * 40 + b'password="generated-depth-private"' + b'}' * 40
        self.assertEqual(native_hocon_diagnostic(deep), 'syntax')
        with self.assertRaises(SemanticRefused):
            read_hocon(deep, native_hocon)
        for leaf in (b'keyfile="/private/generated"\nkeyfile=""',
                     b'password=${?GENERATED_ONLY}',
                     b'include "generated-missing.conf"'):
            raw = b'authentication=[{body {credentials {primary {' + leaf + b'}}}}]'
            with self.subTest(leaf=leaf), self.assertRaises(SemanticRefused):
                read_hocon(raw, native_hocon)

    def test_native_references_syntax_and_external_files_refuse(self):
        for raw in (b'include "missing-private-file"',
                    b'include required("missing-private-file")',
                    b'a=${HOME}', b'a=${?HOME}',
                    b'a { b = [ }', b'a=1\x00', b'a="\xff"',
                    b'tls.keyfile="/private/key"',
                    b'keyfile="/private/key"\nkeyfile=""'):
            with self.subTest(raw=raw), self.assertRaises(SemanticRefused):
                read_hocon(raw, native_hocon)

    def test_consumer_opt_in_native_and_late_mnesia_gate(self):
        extra = [{'name': 'data/emqx/data/configs/cluster.hocon',
                  'data': b'auth.password="native-consumer-private"'}]
        capture = consumer.Capture('fixture-key', documents(), hocon_parser=native_hocon)
        capture(binding(payload(extra)))
        with self.assertRaises(consumer.PrivateFailure):
            capture.registry.scan(b'native-consumer-private')
        extra.append({'name': 'data/emqx/data/mnesia/schema.DAT', 'data': b'not-etf'})
        capture = consumer.Capture('fixture-key', documents(), hocon_parser=native_hocon)
        with self.assertRaisesRegex(consumer.PrivateFailure, 'native-mnesia-unsupported'):
            capture(binding(payload(extra)))
        self.assertFalse(capture.registry._sealed)

    def test_spool_native_replay_lifetime_and_late_finish(self):
        extra = [{'name': 'data/emqx/data/configs/cluster.hocon',
                  'data': b'password="spool-native-private"'}]
        raw = payload(extra)
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            # A source larger than the legacy aggregate limit takes the spool path.
            with patch.object(consumer, 'MAX_STREAM', 1024):
                with consumer.Capture('fixture-key', documents(),
                                      hocon_parser=native_hocon,
                                      spool_directory=directory) as capture:
                    bound = capture(binding(raw))
                    with bound['open']('repo_woow-emqx') as replay:
                        self.assertEqual(replay.read(512), raw[:512])
                    self.assertEqual(len(list(root.iterdir())), 1)
                    with self.assertRaises(consumer.PrivateFailure):
                        capture.registry.scan(b'spool-native-private')
                self.assertEqual(list(root.iterdir()), [])
                with self.assertRaisesRegex(consumer.PrivateFailure, '^private-source-refused$'):
                    with bound['open']('repo_woow-emqx'):
                        pass
            class Broken(io.BytesIO):
                def finish(self):
                    raise RuntimeError('late-private-failure')
            @contextlib.contextmanager
            def opened(_):
                yield Broken(raw)
            parser = unittest.mock.Mock(side_effect=native_hocon)
            with consumer.Capture('fixture-key', documents(), hocon_parser=parser,
                                  spool_directory=directory) as capture:
                with self.assertRaises(consumer.PrivateFailure):
                    capture(dict(binding(raw), open=opened))
                self.assertFalse(capture.registry._sealed)
                parser.assert_not_called()
            self.assertEqual(list(root.iterdir()), [])
