"""Public native code metadata only; no broker or arbitrary function execution."""
import base64
import copy
import json
from pathlib import Path
import tempfile
import unittest
import emqx_broker_owner_target as adapter

ROOT=Path(__file__).parent


class FunctionDiagnosticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from emqx_native_runtime import run_native
        with tempfile.TemporaryDirectory(prefix='emqx-public-fundiag-') as directory:
            root=Path(directory)
            for name in ('emqx_owner_function_diagnostic_fixture.escript','emqx_owner_target.expr'):
                (root/name).write_bytes((ROOT/name).read_bytes())
                (root/name).chmod(0o600)
            with tempfile.TemporaryFile() as output:
                code=run_native(root,'emqx_owner_function_diagnostic_fixture.escript',
                    args=('/input/emqx_owner_target.expr',),output=output)
                output.seek(0);raw=output.read(8192)
                if code:
                    raise AssertionError('public function diagnostic fixture failed')
                cls.data=json.loads(raw)
                if b'fixture-env-value' in raw:
                    raise AssertionError('environment or dynamic path was published')

    def frame(self,item,stage='serialize_config'):
        return b'WOOWFUN:'+base64.b64encode(json.dumps(item).encode())+b':END\nWOOWTARGETFAIL:'+stage.encode()+b':unsupported_function:ENDok'

    def test_native_public_identity_and_env_kind_only(self):
        for item in self.data:
            result=adapter.fixed_native_diagnostic(self.frame(item))
            self.assertEqual(result['native_config_function'],item)
        self.assertEqual(self.data[0]['env_kind'],'map')
        self.assertEqual(self.data[1]['profile'],'secret_loader_refused')
        self.assertEqual(self.data[2]['name'],'namespace')
        self.assertEqual(self.data[3]['module'],'unknown')

    def test_private_identity_unknown_hash_and_extra_payload_refuse(self):
        for field,value in (('module','private-secret-module'),('name','private-secret-name'),
                            ('md5','private-secret-hash'),('env_kind','private-secret-value'),
                            ('path','private-secret-path'),('arity',False)):
            item=copy.deepcopy(self.data[0]);item[field]=value
            self.assertIsNone(adapter.fixed_native_diagnostic(self.frame(item)))
        item=copy.deepcopy(self.data[0]);item['env']=['private-secret-value']
        self.assertIsNone(adapter.fixed_native_diagnostic(self.frame(item)))
        self.assertIsNone(adapter.fixed_native_diagnostic(self.frame(self.data[0],stage='schema_terms')))
        self.assertIsNone(adapter.fixed_native_diagnostic(self.frame(self.data[0])+b'private-tail'))
