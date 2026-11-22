"""Bounded root/key/context diagnostics, preserving every existing ref refusal."""
from contextlib import contextmanager
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import emqx_broker_owner_target as harness
from emqx_owner_target import OwnerCaptureRefused,owner_target_readers,_no_refs
import test_emqx_owner_target as fixtures
from test_emqx_owner_target import cooked_config


class ReferenceDiagnosticTests(unittest.TestCase):
    @contextmanager
    def quiesce(self): yield

    def capture(self,config):
        transport=fixtures.OwnerProducerTests().transport([],config=config)
        with owner_target_readers(private_eval=transport,quiesce=self.quiesce): pass

    def test_disabled_and_active_tls_refs_both_refuse_with_fixed_context(self):
        for kind in ('ssl','wss'):
            for enabled in (False,True):
                config=cooked_config()
                config['listeners'][kind]['default'].update(enable=enabled,
                    ssl_options={'keyfile':'/private-value-must-never-appear/key.pem'})
                with self.subTest(kind=kind,enabled=enabled),self.assertRaises(OwnerCaptureRefused) as caught:
                    self.capture(config)
                failure=caught.exception
                self.assertEqual((failure.phase,failure.reason),('references','reference_file_setting'))
                self.assertEqual(failure.reference,{'root':'listeners','key':'keyfile',
                    'context':kind+('_enabled' if enabled else '_disabled')})
                self.assertNotIn('private-value',json.dumps(failure.reference))

    def test_fixed_markers_authorizer_and_unknown_keys_no_dynamic_text(self):
        cases=[({'node':{'cookie':'env:private-value'}},'reference_env','node','cookie'),
            ({'node':{'cookie':'vault:private-value'}},'reference_vault','node','cookie'),
            ({'node':{'config_files':['${PRIVATE}/secret']}},'reference_template','node','config_files'),
            ({'private-root':{'private-setting_file':'/private-value'}},'reference_file_setting','other_root','other_file_key'),
            ({'private-root':{'private-setting':'https://private-value'}},'reference_url','other_root','other_key'),
            ({'authorization':{'sources':[{'type':'file'}]}},'reference_file_authorizer','authorization','other_key'),
            ({'node':{'cookie':'file:/private-value'}},'reference_file_uri','node','cookie')]
        for config,reason,root,key in cases:
            with self.subTest(reason=reason),self.assertRaises(OwnerCaptureRefused) as caught:
                _no_refs(config)
            self.assertEqual(caught.exception.reason,reason)
            self.assertEqual(caught.exception.reference,{'root':root,'key':key,'context':'not_assessed'})
            self.assertNotIn('private-',json.dumps(caught.exception.reference))

    def test_dashboard_context_and_bounded_report(self):
        config=cooked_config()
        config['dashboard']['listeners']['https']['keyfile']='/private-value'
        with self.assertRaises(OwnerCaptureRefused) as caught:self.capture(config)
        self.assertEqual(caught.exception.reference['context'],'dashboard_https_disabled')
        failure=caught.exception
        @contextmanager
        def refused(**kwargs):
            raise failure
            yield
        report={'checks':{}}
        with patch.object(harness,'broker_target_readers',refused):
            with self.assertRaises(OwnerCaptureRefused):
                harness.run_owner_target(Path('/not-opened'),'fixture',[],report,owned_container_id='a'*64)
        self.assertEqual(report['consumer_fixed_reference'],failure.reference)
        self.assertNotIn('private-value',json.dumps(report))
        forged=OwnerCaptureRefused('references','reference_url',{'root':'private-root','key':'cookie','context':'not_assessed'})
        self.assertIsNone(forged.reference)


class ListenerKnownURLDiagnosticTests(unittest.TestCase):
    def test_known_keys_in_disabled_ws_and_tcp_are_still_refused(self):
        from emqx_owner_target import _no_refs, OwnerCaptureRefused
        for kind in ('ws','tcp'):
            for key in ('check_origins','origins','responder_url'):
                config={'listeners':{kind:{'default':{'enable':'false',
                    'websocket':{key:[b'http://localhost:18083']}}}}}
                with self.subTest(kind=kind,key=key), self.assertRaises(OwnerCaptureRefused) as caught:
                    _no_refs(config)
                self.assertEqual(caught.exception.reference,
                    {'root':'listeners','key':key,'context':kind+'_disabled'})
                self.assertEqual(caught.exception.reason,'reference_url')


class BatchedReferenceDiagnosticTests(unittest.TestCase):
    def test_one_capture_reports_all_fixed_categories_without_values(self):
        config=cooked_config()
        config['durable_storage']={'messages':{'backend':fixtures.Atom('builtin_local'),
            'data_dir':'${PRIVATE}/private-directory'}}
        config['plugins']={'enable':False,'root_dir':'${PRIVATE}/plugins'}
        config['node']['config_files']=['${PRIVATE}/a','${PRIVATE}/b']
        config['unknown-private-root']={'private-setting':'vault:private-value'}
        config['authorization']={'sources':[{'type':fixtures.Atom('file'),'enable':True,
            'path':'${PRIVATE}/acl.conf'}]}
        with self.assertRaises(OwnerCaptureRefused) as caught:
            ReferenceDiagnosticTests().capture(config)
        failure=caught.exception
        self.assertEqual(failure.phase,'references')
        self.assertEqual(len(failure.reference_batch),6)
        roots={item['root'] for item in failure.reference_batch}
        self.assertEqual(roots,{'durable_storage','plugins','node','other_root','authorization'})
        storage=next(item for item in failure.reference_batch if item['root']=='durable_storage')
        self.assertEqual(storage['key'],'data_dir')
        self.assertEqual(storage['context'],'durable_storage_builtin_local')
        self.assertFalse(failure.reference_batch_truncated)
        encoded=json.dumps(failure.reference_batch)
        for private in ('PRIVATE','private-value','private-setting','private-directory','unknown-private-root'):
            self.assertNotIn(private,encoded)
        @contextmanager
        def refused(**kwargs):
            raise failure
            yield
        report={'checks':{}}
        with patch.object(harness,'broker_target_readers',refused),self.assertRaises(OwnerCaptureRefused):
            harness.run_owner_target(Path('/not-opened'),'fixture',[],report,owned_container_id='a'*64)
        self.assertEqual(report['consumer_fixed_references'],failure.reference_batch)
        self.assertFalse(report['consumer_fixed_references_truncated'])

    def test_approved_profiles_excluded_unknown_neighbor_still_refuses(self):
        import test_emqx_target_vendor_policy as policy_fixtures
        from emqx_target_vendor_policy import DisabledVendorTLS, DEFAULT_ORIGINS
        from emqx_owner_target import _reference_failure_batch
        config=policy_fixtures.VendorACLPolicyTests().config()
        config['listeners']={'ws':{'default':{'enable':'false','websocket':{
            'check_origin_enable':'false','check_origins':list(DEFAULT_ORIGINS)}}}}
        config['node']={'data_dir':b'${PRIVATE}/unknown'}
        policy=DisabledVendorTLS(policy_fixtures.VendorACLPolicyTests().observed())
        batch,truncated=_reference_failure_batch(config,policy)
        self.assertEqual(batch,[{'reason':'reference_template','root':'node','key':'data_dir','context':'not_assessed'}])
        self.assertFalse(truncated)
        with self.assertRaises(OwnerCaptureRefused): _no_refs(config,vendor_policy=policy)

    def test_bounded_set_truncation_and_forged_fields(self):
        from emqx_owner_target import _reference_failure_batch
        config={'node':{'data_dir':'${PRIVATE}/a','config_files':['vault:private']}}
        with patch('emqx_owner_target.MAX_REFERENCE_DIAGNOSTICS',1):
            batch,truncated=_reference_failure_batch(config)
        self.assertEqual(len(batch),1)
        self.assertTrue(truncated)
        forged=OwnerCaptureRefused('references',reference_batch=[{
            'reason':'reference_template','root':'private-root','key':'data_dir','context':'not_assessed'}])
        self.assertEqual(forged.reference_batch,[])

    def test_pinned_public_root_catalog(self):
        import tempfile
        from emqx_native_runtime import run_native
        from emqx_owner_target import PINNED_REFERENCE_ROOTS
        with tempfile.TemporaryDirectory(prefix='emqx-public-roots-fixture-') as directory:
            root=Path(directory)
            script=root/'roots.escript'
            script.write_text('#!/usr/bin/env escript\n%%! +S 1:1 +A 1 -noshell\n'
                'main([]) -> try code:add_paths(filelib:wildcard("/opt/emqx/lib/*/ebin")), '
                'Roots=lists:sort([N || {N,_} <- hocon_schema:roots(emqx_conf_schema)]), '
                'io:put_chars(jsone:encode(Roots)) catch _:_ -> halt(2) end.\n')
            with tempfile.TemporaryFile() as output:
                self.assertEqual(run_native(root,script.name,output=output),0)
                output.seek(0)
                actual=json.loads(output.read(16384))
        self.assertEqual(len(actual),44)
        self.assertEqual(set(actual),set(PINNED_REFERENCE_ROOTS))
