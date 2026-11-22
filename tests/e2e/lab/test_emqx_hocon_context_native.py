"""Generated public native syntax and authenticated Capture integration only."""
from collections import Counter
import copy
import gzip
import hashlib
import json
import unittest
from unittest.mock import patch

from emqx_native_hocon import native_hocon_context, native_hocon
from emqx_hocon_context import PROFILE
from emqx_native_runtime import IMAGE
from emqx_semantic_readers import read_hocon, SemanticRefused
import emqx_owner_file_hocon as vendor

ACL = b'generated-complete-vendor-file'
BASE = b'authorization.sources=[{type=file,path="${EMQX_ETC_DIR}/acl.conf"}]\n'
ACTION = b'rule_engine.rules.r.actions=[{function=republish,args {payload="prefix-${payload.body}"\ntopic="${clientid}"\nqos="${qos}"\nretain="${flags.retain}"}}]\n'


def observe():
    return ACL, dict(image=IMAGE,path=vendor.VENDOR_PATH,bytes=len(ACL),
                     sha256=hashlib.sha256(ACL).hexdigest(),complete=True,regular=True), (b'generated-acl-value',)


class NativeContextTests(unittest.TestCase):
    def read(self, raw, encoded=None):
        return read_hocon(raw, (lambda _: encoded) if encoded else native_hocon_context,
                          file_profile=PROFILE, product_image=IMAGE)

    def test_dotted_arrays_overrides_concat_complete_original_ledger(self):
        raw = BASE + ACTION + b'password="old-value"\npassword="new-value"\njoined="left" "right"\nhistorical="hidden-left" "hidden-right"\nhistorical="replaced"\n'
        encoded = native_hocon_context(raw)
        doc = json.loads(encoded)['document']
        self.assertEqual(Counter(doc['syntax_strings']), Counter(b['value'] for b in doc['string_bindings']))
        self.assertIn('old-value', doc['syntax_strings'])
        self.assertIn('left', doc['syntax_strings'])
        self.assertIn('right', doc['syntax_strings'])
        self.assertTrue(any('hidden-left' in s and 'hidden-right' in s for s in doc['concat_strings']))
        self.assertEqual(doc['parsed']['password'], 'new-value')
        self.assertEqual([b['path'] for b in doc['string_bindings'] if b['role']=='republish-value'][0],
                         ['rule_engine','rules','r','actions',0,'args','payload'])
        with patch.object(vendor,'observe_vendor_acl',observe):
            values=self.read(raw,encoded)
        for value in (s.encode() for s in doc['concat_strings']):
            self.assertIn(value,values.values)
        for value in (b'old-value',b'new-value',b'left',b'right',doc['parsed']['joined'].encode(),
                      b'prefix-${payload.body}',b'prefix-',b'${payload.body}',ACL):
            self.assertIn(value,values.values)
        for profile in (None, vendor.PROFILE):
            with self.assertRaises(SemanticRefused):
                read_hocon(raw,native_hocon,file_profile=profile,product_image=IMAGE if profile else None)

    def test_context_spoof_and_historical_overrides_cannot_borrow_permission(self):
        cases = [
            ACTION+b'"${payload.body}"="plain"\n',
            ACTION+b'outside="${payload.body}"\noutside="plain"\n',
            b'rule_engine.rules.r.actions=[{function=unknown,args.payload="${payload.body}"}]\n'+ACTION,
            b'rule_engine.rules.r.actions=[{function=republish,function=unknown,args.payload="${payload.body}"}]\n'+ACTION,
            b'rule_engine.rules.r.actions=[{args.payload="${payload.body}"}]\n'+ACTION,
            ACTION+b'outside="${EMQX_ETC_DIR}/acl.conf"\noutside="plain"\n',
            ACTION.replace(b'${payload.body}',b'${HOME}'),
            ACTION.replace(b'${payload.body}',b'${env:HOME}'),
            ACTION.replace(b'${payload.body}',b'${vault:token}'),
            ACTION.replace(b'${payload.body}',b'${file:/private}'),
            ACTION.replace(b'function=republish',b'function=custom'),
            ACTION.replace(b'payload="prefix-${payload.body}"',b'unknown="${payload.body}"'),
        ]
        with patch.object(vendor,'observe_vendor_acl') as io:
            for index, case in enumerate(cases):
                with self.subTest(case=index), self.assertRaises(SemanticRefused):
                    self.read(BASE+case)
            io.assert_not_called()

    def test_split_concat_and_actual_references_refused_native(self):
        for tail in (
            b'rule_engine.rules.r.actions=[{function=republish,args.payload="$" "{payload}"}]',
            b'rule_engine.rules.r.actions=[{function=republish,args.payload="${payload}" "suffix"}]',
            b'outside=${HOME}', b'include "missing.conf"',
        ):
            with self.subTest(case=tail),self.assertRaises(SemanticRefused):
                native_hocon_context(BASE+tail)

    def test_historical_valid_action_instances_and_literal_dotted_key(self):
        first=ACTION.replace(b'prefix-${payload.body}',b'old-${payload.old}')
        second=ACTION.replace(b'prefix-${payload.body}',b'new-${payload.new}')
        raw=BASE+first+second
        with patch.object(vendor,'observe_vendor_acl',observe):
            values=self.read(raw)
        self.assertIn(b'old-${payload.old}',values.values)
        self.assertIn(b'new-${payload.new}',values.values)
        # Quoting makes this ONE key, never the declared nested rule path.
        spoof=BASE+b'"rule_engine.rules.r.actions"=[{function=republish,args.payload="${payload}"}]'
        with patch.object(vendor,'observe_vendor_acl') as io:
            with self.assertRaises(SemanticRefused):self.read(spoof)
            io.assert_not_called()

    def test_ledger_missing_duplicate_or_wrong_role_refused_before_io(self):
        raw=BASE+ACTION
        original=json.loads(native_hocon_context(raw))
        docs=[]
        for kind in ('missing','extra','key','path','unbound'):
            doc=copy.deepcopy(original); bindings=doc['document']['string_bindings']
            index=next(i for i,b in enumerate(bindings) if b['role']=='republish-value')
            if kind=='missing':bindings.pop(index)
            elif kind=='extra':bindings.append(copy.deepcopy(bindings[index]))
            elif kind=='key':bindings[index]['role']='key'
            elif kind=='path':bindings[index]['path']=['outside']
            else:doc['document']['syntax_strings'].append('${payload.body}')
            docs.append(doc)
        with patch.object(vendor,'observe_vendor_acl') as io:
            for doc in docs:
                with self.assertRaises(SemanticRefused):self.read(raw,json.dumps(doc).encode())
            io.assert_not_called()

    def test_authenticated_owner_uses_real_context_adapter_after_digest_and_unsealed(self):
        from test_emqx_owner_source_capture import OwnerHarnessTests
        from test_emqx_source_cold_capture import decoder
        from tests.backup import hafixtures as hx
        from woowbackup import ha_emqx
        import emqx_owner_source_capture as owner
        from emqx_private_boundary import PrivateFailure
        OwnerHarnessTests.fixture(self)
        # Replace generated fixture HOCON only; actual binding/decryption/EOF/Capture.
        import io,tarfile
        with tarfile.open(fileobj=io.BytesIO(self.raw)) as tar:
            entries=[dict(name=m.name,data=(BASE+ACTION if m.name.endswith('/configs/cluster.hocon')
                     else tar.extractfile(m).read())) for m in tar if m.isfile()]
        self.raw=hx.tar_bytes(entries)
        slug='fedcba98_woow-emqx'
        doc=hx.ha_doc((slug,),protected=True);doc['addons'][0]['version']='5.9.0'
        self.path.write_bytes(hx.outer_bytes([(slug+'.tar.gz',hx.v3_encrypt(gzip.compress(self.raw)))],doc))
        self.digest=hashlib.sha256(self.path.read_bytes()).hexdigest()
        with patch.object(owner,'native_cold_history',decoder),patch.object(vendor,'observe_vendor_acl',observe), \
             patch('emqx_native_hocon.native_hocon_context',wraps=native_hocon_context) as parser:
            with self.assertRaises(PrivateFailure):
                with owner.capture_owner_source(self.path,password=self.password,expected_sha256='0'*64,
                     spool_directory=self.spool,file_dependency_profile=PROFILE,product_image=IMAGE):pass
            parser.assert_not_called()
            with owner.capture_owner_source(self.path,password=self.password,expected_sha256=self.digest,
                     spool_directory=self.spool,file_dependency_profile=PROFILE,product_image=IMAGE) as (captured,bound):
                parser.assert_called_once_with(BASE+ACTION)
                for value in (b'prefix-${payload.body}',b'prefix-',b'${payload.body}',ACL):
                    self.assertIn(value,captured.registry._values)
                self.assertNotIn('mqtt-auth',captured.registry._sources)
                for operation in (captured.registry.seal,captured.registry.summary,
                                  lambda:captured.registry.scan(b'generated')):
                    with self.assertRaises(PrivateFailure):operation()
                self.assertEqual(len(captured.hocon_file_receipts),1)
        self.assertEqual(list(self.spool.iterdir()),[])

    def test_mixed_republish_http_literal_ref_bound_and_other_roots_retained(self):
        configuration=b'''connectors.http.generated_conn {url="http://generated.invalid"}
actions.http.generated_action {connector=generated_conn,parameters.body="generated-http-body"}
rule_engine.rules.http_rule.actions=["http:generated_action"]
'''
        raw=BASE+ACTION+configuration
        with patch.object(vendor,'observe_vendor_acl',observe):
            values=self.read(raw)
        for value in (b'http:generated_action',b'generated-http-body',b'generated_conn',
                      b'http://generated.invalid',b'http_rule'):
            self.assertIn(value,values.values)
        bad=(configuration.replace(b'http:generated_action',b'http:missing_action'),
             configuration.replace(b'connector=generated_conn',b'connector=missing_conn'),
             configuration.replace(b'generated-http-body',b'${payload}'),
             configuration.replace(b'http:generated_action',b'env:HOME'))
        with patch.object(vendor,'observe_vendor_acl') as io:
            for tail in bad:
                with self.assertRaises(SemanticRefused):self.read(BASE+ACTION+tail)
            io.assert_not_called()
