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
