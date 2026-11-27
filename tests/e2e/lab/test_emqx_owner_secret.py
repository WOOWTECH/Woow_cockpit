"""Synthetic native public constructor -> strict v2 consumer private scan."""
import base64
from contextlib import contextmanager
import copy
import json
from pathlib import Path
import re
import tempfile
import unittest

from emqx_owner_target import owner_target_readers
from emqx_private_boundary import PrivateFailure
from emqx_target_capture import TargetCaptureUnsupported
from test_emqx_owner_target import Atom, reply_document, typed

ROOT = Path(__file__).parent
SECRET = b'fixture-native-wrapped-secret-private'


class OwnerSecretTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from emqx_native_runtime import run_native
        with tempfile.TemporaryDirectory(prefix='emqx-public-secret-fixture-') as directory:
            root = Path(directory)
            for name in ('emqx_owner_secret_fixture.escript','emqx_owner_target.expr'):
                (root/name).write_bytes((ROOT/name).read_bytes())
                (root/name).chmod(0o600)
            with tempfile.TemporaryFile() as output:
                code = run_native(root,'emqx_owner_secret_fixture.escript',
                    args=('/input/emqx_owner_target.expr',),output=output)
                output.seek(0)
                raw = output.read(1048577)
                if code or len(raw) > 1048576:
                    raise AssertionError('public native secret fixture failed')
                cls.native = json.loads(raw)

    def transport(self, edit=None):
        def evaluate(expression):
            nonce = re.search(r'generation => <<"([0-9a-f]{32})">>', expression)[1]
            doc = reply_document(nonce)
            doc['contract'] = 'emqx-owner-live-target-v2'
            config = doc['config']['value']
            native_password = self.native['config']['value'][0][1]['value'][0][1]
            for key,value in config:
                if key['value'] == 'dashboard':
                    for pair in value['value']:
                        if pair[0]['value'] == 'default_password':
                            pair[1] = copy.deepcopy(native_password)
            doc['config_secret_wrappers'] = copy.deepcopy(self.native['config_secret_wrappers'])
            if edit:
                edit(doc)
            return b'WOOWTARGET:' + base64.b64encode(json.dumps(doc).encode()) + b':ENDok'
        return evaluate

    @contextmanager
    def quiesce(self):
        yield

    def test_actual_native_constructor_output_enters_exact_reader_and_private_scan(self):
        with owner_target_readers(private_eval=self.transport(), quiesce=self.quiesce) as readers:
            self.assertEqual(len(readers),5)
            with readers['target-bootstrap']() as stream:
                self.assertIn(SECRET.decode(), stream.read().decode())
            for payload in (SECRET,b'emqx_secret',b'-wrap/1-fun-0-',
                            b'A27D8A4F73E7689F1F8B78E0DCB7C91B'):
                with self.assertRaises(PrivateFailure):
                    readers.persisted_values.scan(payload)

    def test_provenance_path_identity_environment_and_contract_refuse(self):
        def metadata(doc):
            return doc['config_secret_wrappers']['value'][0]['value']
        def replace_field(doc,name,value):
            for pair in metadata(doc):
                if pair[0]['value'] == name:
                    pair[1] = typed(value)
        edits = [lambda d: d.pop('config_secret_wrappers'),
            lambda d: d.update(contract='emqx-owner-live-target-v1'),
            lambda d: replace_field(d,'module',Atom('custom')),
            lambda d: replace_field(d,'name',Atom('-wrap_load/1-fun-0-')),
            lambda d: replace_field(d,'new_uniq',b'unknown-code'),
            lambda d: replace_field(d,'arity',1),
            lambda d: replace_field(d,'env',[{'nested': SECRET}]),
            lambda d: replace_field(d,'env',[b'wrong-secret']),
            lambda d: replace_field(d,'env',[SECRET,SECRET]),
            lambda d: replace_field(d,'path',[(Atom('map'),Atom('missing'))]),
            lambda d: d['config_secret_wrappers']['value'].append(copy.deepcopy(
                d['config_secret_wrappers']['value'][0]))]
        for edit in edits:
            with self.subTest(edit=edit), self.assertRaises(TargetCaptureUnsupported):
                with owner_target_readers(private_eval=self.transport(edit), quiesce=self.quiesce):
                    pass

    def test_only_config_serializer_has_wrapper_capability(self):
        source = (ROOT/'emqx_owner_target.expr').read_text()
        self.assertIn('Row = Typed(R,0)',source)
        self.assertIn('ProvidersTyped = Typed(Providers,0)',source)
        self.assertIn('{Typed(Defs,0),Data,SchemaBefore,SchemaAfter}',source)
        self.assertEqual(source.count('= ConfigSecrets('),2)
        self.assertIn('case Before =:= After',source)
        self.assertIn('Fingerprint({ConfigPlainAfter,ConfigSecretMetadataAfter})',source)
        self.assertNotIn('emqx_secret:unwrap(',source)
        self.assertNotIn('SecretFun()',source)
