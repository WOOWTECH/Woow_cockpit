"""Generated IO boundaries, actual capability issuance/registration/scanning.
No real broker/lab or commercial acceptance claims.
"""
from contextlib import contextmanager
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import emqx_issued_target_probe as m
import emqx_adapter_owner as owner
from emqx_adapter_fixture import Fixture
from emqx_owner_fixture_files import _record, revoke
from test_emqx_owner_fixture_files import GeneratedRunner
from test_emqx_owner_target import reply_document, cooked_config
from emqx_owner_target import _build
import base64,json

class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name); generated=GeneratedRunner(self.root)
        runner=owner.LabOwnerRunner.__new__(owner.LabOwnerRunner)
        runner.owner='appowner';runner.home=str(self.root);runner.uid=os.geteuid();runner.gid=os.getegid()
        for method in ('run','write_file','stat_files','systemctl','podman'):
            setattr(runner,method,getattr(generated,method))
        self.provision=owner.OwnerProvision.__new__(owner.OwnerProvision)
        self.provision.runner=runner;self.provision.fixture=Fixture('woowbk-emqxlab-12345678','appowner',m.IMAGE.removeprefix('sha256:'))
        self.provision.created=[];self.provision.file_capability=None
        self.events=[]; self.leak=False; self.file_failure=False
    def observer(self,provision):
        self.assertIs(provision,self.provision)
        self.assertIs(_record(provision.file_capability)[1],provision)
        @contextmanager
        def observed(**kwargs):
            from emqx_owner_fixture_files import FixtureFilesFailure
            self.events.append('observed-enter')
            if self.file_failure:raise FixtureFilesFailure('secret_mapping','shape')
            try:yield object()
            finally:self.events.append('observed-exit')
        return observed
    @contextmanager
    def readers(self,**kwargs):
        self.events.append('enter')
        generation='a'*32; doc=reply_document(generation,cooked_config())
        readers=_build(b'WOOWTARGET:'+base64.b64encode(json.dumps(doc).encode())+b':ENDok',generation)
        if self.leak:readers.persisted_values._values+=('通過'.encode(),)
        try:
            from emqx_semantic_readers import Values
            with kwargs['vendor_observer'](generation=generation,private_values=Values()):
                yield readers
        finally:self.events.append('exit')
    def cleanup(self):
        self.events.append('cleanup');revoke(self.provision.file_capability)
    def invoke(self):
        with patch.object(m,'OwnerProvision',return_value=self.provision), \
             patch.object(m,'_full_restore_budget'),patch.object(m,'_opt_in_private_unit'), \
             patch.object(m,'_ready'),patch.object(m,'issued_fixture_observer',side_effect=self.observer), \
             patch.object(m,'owner_target_readers',side_effect=self.readers), \
             patch.object(self.provision,'cleanup',side_effect=self.cleanup):
            return m.run_issued_target_probe()
    def test_actual_issuance_registration_and_exact_scan_return_after_lease_and_cleanup(self):
        self.assertEqual(self.invoke(),m.TARGET_RECEIPT)
        self.assertEqual(self.events,['enter','observed-enter','observed-exit','exit','cleanup'])
    def test_actual_persisted_collision_refuses_and_still_exits_and_cleans(self):
        self.leak=True
        with self.assertRaises(m.IssuedProbeRefused) as failure:self.invoke()
        self.assertEqual(failure.exception.phase,'scan')
        self.assertEqual(self.events,['enter','observed-enter','observed-exit','exit','cleanup'])
    def test_actual_issued_file_fixed_failure_survives_masking_without_private_details(self):
        self.file_failure=True
        with self.assertRaises(m.IssuedProbeRefused) as failure:self.invoke()
        self.assertEqual(failure.exception.phase,'files_secret_mapping_shape')
        self.assertEqual(self.events,['enter','observed-enter','exit','cleanup'])

    def test_cleanup_failure_never_returns_scanned_evidence(self):
        def cleanup():
            revoke(self.provision.file_capability)
            raise ValueError('generated-private-detail')
        self.cleanup=cleanup
        with self.assertRaises(m.IssuedProbeRefused) as failure:self.invoke()
        self.assertEqual(failure.exception.phase,'cleanup')
        self.assertNotIn('generated-private-detail',str(failure.exception))
