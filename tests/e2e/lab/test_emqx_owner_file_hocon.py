"""Generated contracts/filesystem only: no native process, image, lab or secrets."""
import base64
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import emqx_owner_file_hocon as owner
from emqx_semantic_readers import read_hocon, SemanticRefused
from test_emqx_semantic_readers import RAW, hocon, adapter

ACL = b'{allow, {user, "generated-acl-user"}, all, ["generated/topic"]}.\n'


def observed():
    return json.dumps({'contract': 'emqx-vendor-acl-v1',
        'content_b64': base64.b64encode(ACL).decode(), 'terms': [
            {'type': 'tuple', 'value': [
                {'type': 'atom', 'value': 'allow'},
                {'type': 'binary', 'value': base64.b64encode(b'generated-acl-user').decode()}]}]}).encode()


def document():
    return hocon({'parsed': {
        'authorization': {'no_match': 'deny', 'sources': [
            {'type': 'file', 'enable': True, 'path': owner.LITERAL}]},
        'authentication': [{'password': 'generated-current-private'}]},
        'syntax_strings': ['generated-overwritten-private', 'generated-current-private', owner.LITERAL]})


class ProfileTests(unittest.TestCase):
    def run_observer(self, directory, script, *, output):
        self.assertEqual(script, 'emqx_vendor_acl.escript')
        root = Path(directory)
        self.assertEqual(root.stat().st_mode & 0o777, 0o700)
        self.assertEqual(set(p.name for p in root.iterdir()), {script})
        self.assertEqual((root / script).stat().st_mode & 0o777, 0o600)
        self.observer_directory = root
        output.write(observed())
        return 0

    def read(self, doc=None, **kwargs):
        return read_hocon(RAW, adapter(document() if doc is None else doc),
                          file_profile=owner.PROFILE, product_image=owner.IMAGE, **kwargs)

    def test_explicit_full_values_full_acl_receipt_and_default_strict(self):
        with patch.object(owner, 'run_native', side_effect=self.run_observer) as run:
            values = self.read()
            run.assert_called_once()
        self.assertFalse(self.observer_directory.exists())
        for value in (ACL, b'generated-acl-user', b'generated-overwritten-private',
                      b'generated-current-private', b'authorization', b'no_match',
                      b'deny', b'type', b'file', owner.LITERAL.encode()):
            self.assertIn(value, values.values)
        self.assertEqual(values.file_receipts, ({'image': owner.IMAGE,
            'path': owner.VENDOR_PATH, 'bytes': len(ACL),
            'sha256': hashlib.sha256(ACL).hexdigest(), 'complete': True, 'regular': True},))
        self.assertNotIn('generated', repr(values))
        with patch.object(owner, 'run_native') as run:
            with self.assertRaises(SemanticRefused):
                read_hocon(RAW, adapter(document()))
            run.assert_not_called()

    def test_unknown_missing_implicit_paths_locations_and_other_files_no_io(self):
        variants = []
        for path in (None, '', '/opt/emqx/etc/acl.conf', '/data/emqx/data/authz/acl.conf',
                     '${HOME}/acl.conf', '${EMQX_ETC_DIR}/../acl.conf', 'file:/private'):
            doc = document()
            src = doc['document']['parsed']['authorization']['sources'][0]
            if path is None:
                del src['path']
            else:
                src['path'] = path
            variants.append(doc)
        doc = document(); doc['document']['parsed']['other'] = {'type': 'file', 'path': owner.LITERAL}
        variants.append(doc)
        doc = document(); doc['document']['parsed']['tls'] = {'keyfile': '/private/generated'}
        variants.append(doc)
        doc = document(); doc['document']['parsed']['password'] = owner.LITERAL
        variants.append(doc)
        doc = document(); doc['document']['parsed']['authorization']['sources'] = []
        variants.append(doc)
        with patch.object(owner, 'run_native') as run:
            for doc in variants:
                with self.subTest(doc=doc), self.assertRaises(SemanticRefused):
                    self.read(doc)
            run.assert_not_called()

    def test_incomplete_references_wrong_binding_and_unknown_profile_refuse(self):
        with patch.object(owner, 'run_native') as run:
            for key, value in (('references', ['${EMQX_ETC_DIR}']), ('complete', False),
                               ('input_sha256', '0'*64), ('resolution', 'enabled')):
                doc = document(); doc[key] = value
                with self.assertRaises(SemanticRefused):
                    self.read(doc)
            for profile, image in (('unknown', owner.IMAGE), (owner.PROFILE, 'tag:latest'),
                                   (owner.PROFILE, None)):
                with self.assertRaises(SemanticRefused):
                    read_hocon(RAW, adapter(document()), file_profile=profile, product_image=image)
            doc = document(); doc['document']['syntax_strings'].append('${UNOBSERVED}')
            with self.assertRaises(SemanticRefused):
                self.read(doc)
            run.assert_not_called()

    def test_observer_missing_late_failure_invalid_terms_and_oversize_cleanup(self):
        bad = json.loads(observed()); bad['terms'] = [{'type': 'reference', 'value': 'unknown'}]
        for status, encoded in ((2, observed()), (0, b''), (0, b'x'*(owner.MAX_OUTPUT+1)),
                                (0, json.dumps(bad).encode()), (0, observed()+b'{}')):
            def failed(directory, script, *, output):
                self.observer_directory = Path(directory)
                output.write(encoded)
                return status
            with patch.object(owner, 'run_native', side_effect=failed):
                with self.assertRaises(SemanticRefused):
                    self.read()
            self.assertFalse(self.observer_directory.exists())

    def test_missing_empty_oversize_and_incomplete_native_file_contract_refuses(self):
        docs = []
        for changes in ({'terms': []}, {'content_b64': ''},
                        {'content_b64': base64.b64encode(b'x' * (owner.MAX_VALUE+1)).decode()},
                        {'content_b64': 'invalid!'}, {'unexpected': 'private'}):
            doc = json.loads(observed()); doc.update(changes); docs.append(doc)
        for doc in docs:
            def emit(directory, script, *, output):
                output.write(json.dumps(doc).encode())
                return 0
            with patch.object(owner, 'run_native', side_effect=emit):
                with self.assertRaises(SemanticRefused):
                    self.read()

    def test_prior_audit_unknown_file_path_still_refuses_in_both_modes(self):
        doc = document()
        doc['document']['parsed']['authorization']['sources'][0]['path'] = '/data/emqx/data/not-staged/audit.acl'
        for kwargs in ({}, {'file_profile': owner.PROFILE, 'product_image': owner.IMAGE}):
            with self.assertRaises(SemanticRefused):
                read_hocon(RAW, adapter(doc), **kwargs)


class OwnerWiringTests(unittest.TestCase):
    def test_generated_real_digest_binding_then_profile_capture_stays_unsealed(self):
        # Reuse only the fixture builder; do not inherit native/lab test cases.
        from test_emqx_owner_source_capture import OwnerHarnessTests
        OwnerHarnessTests.fixture(self)
        import emqx_owner_source_capture as capture
        from test_emqx_source_cold_capture import decoder
        from emqx_private_boundary import PrivateFailure
        def native_contract(raw):
            doc = document()
            doc.update(input_sha256=hashlib.sha256(raw).hexdigest(), input_bytes=len(raw))
            return json.dumps(doc).encode()
        def observe(directory, script, *, output):
            output.write(observed())
            return 0
        with patch.object(capture, 'native_hocon', native_contract), \
             patch.object(capture, 'native_cold_history', decoder), \
             patch.object(owner, 'run_native', side_effect=observe) as run:
            with self.assertRaises(PrivateFailure):
                with capture.capture_owner_source(self.path, password=self.password,
                        expected_sha256='0'*64, spool_directory=self.spool,
                        file_dependency_profile=owner.PROFILE, product_image=owner.IMAGE):
                    self.fail('digest mismatch yielded')
            run.assert_not_called()
            with capture.capture_owner_source(self.path, password=self.password,
                    expected_sha256=self.digest, spool_directory=self.spool,
                    file_dependency_profile=owner.PROFILE, product_image=owner.IMAGE) as (captured, bound):
                run.assert_called_once()
                self.assertEqual(len(captured.hocon_file_receipts), 1)
                with self.assertRaises(PrivateFailure):
                    captured.registry.summary()
                with self.assertRaises(PrivateFailure):
                    with bound['open']('fedcba98_woow-emqx'):
                        self.fail('unsealed replay')
                docs = {name: b'[]' for name in
                        ('mqtt-auth','api-keys','tls','target-bootstrap','connectors')}
                captured.supply_target_documents(docs)
                with self.assertRaisesRegex(PrivateFailure, 'private-diagnostic-leak'):
                    captured.registry.scan(b'generated-acl-user')
        self.assertEqual(list(self.spool.iterdir()), [])

        with patch.object(capture, 'native_hocon', native_contract), \
             patch.object(capture, 'native_cold_history', decoder), \
             patch.object(owner, 'run_native', return_value=2):
            with self.assertRaises(PrivateFailure):
                with capture.capture_owner_source(self.path, password=self.password,
                        expected_sha256=self.digest, spool_directory=self.spool,
                        file_dependency_profile=owner.PROFILE, product_image=owner.IMAGE):
                    self.fail('missing vendor file yielded')
        self.assertEqual(list(self.spool.iterdir()), [])
