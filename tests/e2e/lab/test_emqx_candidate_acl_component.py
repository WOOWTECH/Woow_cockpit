"""Host-only tests for the optional already-owned native receipt component."""
import copy
import unittest
from emqx_candidate_acl_component import check_owned_candidate_acl_receipt
import emqx_candidate_stage as stages
from woowbackup import ha_emqx
from woowbackup.errors import BackupError
from tests.backup.test_ha_emqx_acl_preservation import NativeRemovalTransport

class CandidateAclComponentTests(unittest.TestCase):
    def test_readonly_component_uses_existing_candidate_no_load_or_create(self):
        t=NativeRemovalTransport()
        self.assertIsNone(check_owned_candidate_acl_receipt(t))
        self.assertEqual(t.receipts,2)
        self.assertEqual(t.loads,[])
        self.assertNotIn('start',t.events)
        self.assertNotIn('export',t.events)

    def test_same_count_or_schema_change_refuses(self):
        for kind in ('receipt-mutation','schema-mutation'):
            t=NativeRemovalTransport();t.break_at=(kind,2)
            with self.subTest(kind=kind),self.assertRaises(BackupError):check_owned_candidate_acl_receipt(t)
            self.assertEqual(t.loads,[])

    def test_fixed_stages_reach_real_restore_path(self):
        t=NativeRemovalTransport()
        t.running_config['authorization']['sources']=[copy.deepcopy(t.builtin)]
        observed=[]
        def observe(name):
            observed.append(name);stages.mark('product_'+name)
        def read(command):return t.exec('emqx-new',command,timeout=120,max_output=ha_emqx.MAX_HOCON,check=False)
        ha_emqx.restore_target_settings(t,t.config,read,observe=observe)
        self.assertEqual(observed,['acl_baseline','acl_disable','acl_afterdisable','acl_restore','acl_final'])
        self.assertEqual(stages.current(),'product_acl_final')

    def test_failure_stage_is_bounded_and_precise(self):
        for fault,expected in [('receipt-refused','acl_baseline'),('disable-load','acl_disable'),
                ('intermediate-config','acl_afterdisable'),('final-config','acl_final')]:
            t=NativeRemovalTransport();t.break_at=fault
            t.running_config['authorization']['sources']=[copy.deepcopy(t.builtin)]
            observed=[]
            def read(command):return t.exec('emqx-new',command,timeout=120,max_output=ha_emqx.MAX_HOCON,check=False)
            with self.subTest(fault=fault),self.assertRaises(BackupError):
                ha_emqx.restore_target_settings(t,t.config,read,observe=observed.append)
            self.assertEqual(observed[-1],expected)
