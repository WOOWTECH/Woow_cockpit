"""Generated integration inputs only; no lab, native process or real secrets."""
import unittest

from emqx_source_consumer import Capture, PrivateFailure
from test_emqx_source_consumer import binding
from test_emqx_source_cold_capture import source, decoder, SECRET


class SourceOnlyTests(unittest.TestCase):
    def test_complete_source_without_target_cannot_seal_scan_or_replay(self):
        with Capture.source_only('fixture-key', product_selection=True,
                                 cold_decoder=decoder) as captured:
            bound = captured(binding(source()))
            self.assertEqual(captured.cold_receipt['files'], 2)
            self.assertFalse(captured.cold_receipt['final_state'])
            with self.assertRaises(PrivateFailure):
                captured.registry.seal()
            with self.assertRaises(PrivateFailure):
                captured.registry.summary()
            with self.assertRaises(PrivateFailure):
                captured.registry.scan(SECRET)
            with self.assertRaises(PrivateFailure):
                with bound['open']('repo_woow-emqx'):
                    self.fail('unsealed source replay escaped')

    def test_real_owner_documents_can_complete_same_source_registration(self):
        docs = {name: ('["generated-target-' + name + '"]').encode()
                for name in ('mqtt-auth', 'api-keys', 'tls', 'target-bootstrap', 'connectors')}
        raw = source()
        with Capture.source_only('fixture-key', product_selection=True,
                                 cold_decoder=decoder) as captured:
            bound = captured(binding(raw))
            captured.supply_target_documents(docs)
            summary = captured.registry.summary()
            self.assertEqual(summary['source-cookie'], 0)
            for name in docs:
                self.assertEqual(summary[name], 1)
                with self.assertRaisesRegex(PrivateFailure, 'private-diagnostic-leak'):
                    captured.registry.scan(('generated-target-' + name).encode())
            with self.assertRaisesRegex(PrivateFailure, 'private-diagnostic-leak'):
                captured.registry.scan(SECRET)
            with bound['open']('repo_woow-emqx') as reader:
                self.assertEqual(reader.read(), raw)
            with self.assertRaises(PrivateFailure):
                captured.supply_target_documents(docs)
        with self.assertRaises(PrivateFailure):
            with bound['open']('repo_woow-emqx'):
                self.fail('closed source escaped')


class OwnerHarnessTests(unittest.TestCase):
    def fixture(self):
        import gzip
        import hashlib
        import json
        from pathlib import Path
        import tempfile
        from tests.backup import hafixtures as hx
        from woowbackup import ha_emqx
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.spool = self.root / 'spool'
        self.spool.mkdir(mode=0o700)
        slug = 'fedcba98_woow-emqx'
        addon = {'system': {'slug': 'woow-emqx'},
                 'user': {'image': 'test/aarch64-addon-woow-emqx',
                          'options': {'password': 'generated-options'}},
                 'version': '5.9.0', 'state': 'stopped'}
        self.raw = hx.tar_bytes([
            {'name': 'addon.json', 'data': json.dumps(addon).encode()},
            {'name': ha_emqx.NODE_FILE, 'data': b'emqx@fixture'},
            {'name': 'data/emqx/node.cookie', 'data': b'never-used-cookie'},
            {'name': ha_emqx.DATA + '/configs/cluster.hocon', 'data': b'password="generated-hocon"'},
            {'name': ha_emqx.DATA + '/mnesia/emqx@fixture/schema.DAT', 'data': b'generated-schema'},
            {'name': ha_emqx.DATA + '/mnesia/emqx@fixture/emqx_admin_jwt.DCD', 'data': b'generated-jwt'},
        ])
        doc = hx.ha_doc((slug,), protected=True)
        doc['addons'][0]['version'] = '5.9.0'
        self.path = self.root / 'generated-encrypted.tar'
        self.path.write_bytes(hx.outer_bytes([(slug + '.tar.gz', hx.v3_encrypt(gzip.compress(self.raw)))], doc))
        self.digest = hashlib.sha256(self.path.read_bytes()).hexdigest()
        self.password = hx.PASSWORD

    @staticmethod
    def hocon(raw):
        import hashlib
        import json
        return json.dumps(dict(contract='emqx-hocon-json-v1', version='5.8.9',
            input_sha256=hashlib.sha256(raw).hexdigest(), input_bytes=len(raw),
            complete=True, resolution='disabled', references=[],
            document={'password': 'generated-hocon'})).encode()

    def test_owner_binding_decryption_spool_native_contracts_and_unsealed_cleanup(self):
        from unittest.mock import patch
        import emqx_owner_source_capture as owner
        self.fixture()
        calls = []
        def cold(raw, kind):
            calls.append(kind)
            return decoder(raw, kind)
        with patch.object(owner, 'native_hocon', self.hocon), \
             patch.object(owner, 'native_cold_history', cold):
            with owner.capture_owner_source(self.path, password=self.password,
                    expected_sha256=self.digest, spool_directory=self.spool,
                    required_encryption='v3') as (captured, bound):
                self.assertEqual(calls, ['schema-dat', 'dcd'])
                self.assertEqual(captured.cold_receipt['files'], 2)
                self.assertEqual(captured.discarded['files'], 1)
                self.assertEqual(len(list(self.spool.iterdir())), 1)
                with self.assertRaises(PrivateFailure):
                    captured.registry.summary()
                with self.assertRaises(PrivateFailure):
                    with bound['open']('fedcba98_woow-emqx'):
                        self.fail('owner source-only replay escaped')
        self.assertEqual(list(self.spool.iterdir()), [])
        self.assertEqual(set(self.root.iterdir()), {self.path, self.spool})

    def test_late_binding_change_refuses_before_yield_and_cleans_spool(self):
        from unittest.mock import patch
        import emqx_owner_source_capture as owner
        self.fixture()
        def mutate_archive(raw, kind):
            with self.path.open('ab') as output:
                output.write(b'\0')
            return decoder(raw, kind)
        with patch.object(owner, 'native_hocon', self.hocon), \
             patch.object(owner, 'native_cold_history', mutate_archive):
            with self.assertRaisesRegex(PrivateFailure, '^private-owner-source-refused$'):
                with owner.capture_owner_source(self.path, password=self.password,
                        expected_sha256=self.digest, spool_directory=self.spool):
                    self.fail('source_binding final consistency was not checked')
        self.assertEqual(list(self.spool.iterdir()), [])

    def test_native_late_failure_cleans_spool_and_does_not_yield(self):
        from unittest.mock import patch
        from emqx_semantic_readers import SemanticRefused
        import emqx_owner_source_capture as owner
        self.fixture()
        calls = []
        def late(raw, kind):
            calls.append(kind)
            if kind == 'dcd':
                raise SemanticRefused()
            return decoder(raw, kind)
        with patch.object(owner, 'native_hocon', self.hocon), \
             patch.object(owner, 'native_cold_history', late):
            with self.assertRaisesRegex(PrivateFailure, '^private-owner-source-refused$'):
                with owner.capture_owner_source(self.path, password=self.password,
                        expected_sha256=self.digest, spool_directory=self.spool):
                    self.fail('partial inventory escaped')
        self.assertEqual(calls, ['schema-dat', 'dcd'])
        self.assertEqual(list(self.spool.iterdir()), [])

    def test_wrong_archive_hash_refuses_before_native_or_spool(self):
        from unittest.mock import patch
        import emqx_owner_source_capture as owner
        self.fixture()
        with patch.object(owner, 'native_hocon') as hocon, \
             patch.object(owner, 'native_cold_history') as cold:
            with self.assertRaisesRegex(PrivateFailure, '^private-owner-source-refused$'):
                with owner.capture_owner_source(self.path, password=self.password,
                        expected_sha256='0' * 64, spool_directory=self.spool):
                    self.fail('unbound archive escaped')
        hocon.assert_not_called()
        cold.assert_not_called()
        self.assertEqual(list(self.spool.iterdir()), [])


class TargetCompletionGateTests(unittest.TestCase):
    def test_missing_or_invalid_owner_docs_never_ack_empty_targets_or_allow_retry(self):
        for docs in ({}, {'mqtt-auth': b'[]'},
                     {name: b'{"key":"file:/private"}' for name in
                      ('mqtt-auth', 'api-keys', 'tls', 'target-bootstrap', 'connectors')}):
            with self.subTest(categories=tuple(docs)):
                with Capture.source_only('fixture-key', product_selection=True,
                                         cold_decoder=decoder) as captured:
                    captured(binding(source()))
                    with self.assertRaises(PrivateFailure):
                        captured.supply_target_documents(docs)
                    with self.assertRaises(PrivateFailure):
                        captured.registry.seal()
                    with self.assertRaises(PrivateFailure):
                        captured.registry.summary()
                    with self.assertRaises(PrivateFailure):
                        captured.supply_target_documents({name: b'[]' for name in
                            ('mqtt-auth', 'api-keys', 'tls', 'target-bootstrap', 'connectors')})

    def test_target_completion_requires_successful_source_in_live_context(self):
        docs = {name: b'["generated-target"]' for name in
                ('mqtt-auth', 'api-keys', 'tls', 'target-bootstrap', 'connectors')}
        captured = Capture.source_only('fixture-key', product_selection=True, cold_decoder=decoder)
        with self.assertRaises(PrivateFailure):
            captured.supply_target_documents(docs)
        with captured:
            with self.assertRaises(PrivateFailure):
                captured.supply_target_documents(docs)
            captured(binding(source()))
        with self.assertRaises(PrivateFailure):
            captured.supply_target_documents(docs)
        with self.assertRaises(PrivateFailure):
            captured.registry.summary()

    def test_unknown_selected_file_cannot_complete_source_or_target(self):
        from test_emqx_source_cold_capture import PREFIX
        from unittest.mock import Mock
        calls = Mock(side_effect=decoder)
        with Capture.source_only('fixture-key', product_selection=True, cold_decoder=calls) as captured:
            with self.assertRaises(PrivateFailure):
                captured(binding(source([{'name': PREFIX + 'unknown.bin', 'data': b'generated-only'}])))
            calls.assert_not_called()
            with self.assertRaises(PrivateFailure):
                captured.supply_target_documents({})
            with self.assertRaises(PrivateFailure):
                captured.registry.seal()
