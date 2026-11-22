"""Fixed raw shape diagnostics on the SAME product capture; no admission change."""
import copy
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from woowbackup import ha_emqx
from woowbackup.ha_emqx_authorizers import builtin_database_shape,builtin_database_references
from woowbackup.errors import BackupError
from .test_ha_emqx_candidate_flow import Transport

class BuiltinShapeDiagnosticsTests(unittest.TestCase):
    def test_only_fixed_shapes_no_values_or_coercion(self):
        for enabled in (True,False):
            two={'type':'built_in_database','enable':enabled}
            self.assertEqual(builtin_database_shape(two),'exact_type_enable')
            three=dict(two,max_rules=100)
            self.assertEqual(builtin_database_shape(three),'exact_type_enable_maxrules100')
            with self.assertRaises(BackupError):builtin_database_references(three)
            for value in ('100',100.0,True,101,0,None):
                self.assertEqual(builtin_database_shape(dict(two,max_rules=value)),'unknown')
            self.assertEqual(builtin_database_shape(dict(three,private_unknown='not-output')),'unknown')
        for source in (None,[],{}, {'type':'built_in_database','enable':'true'},
                       {'type':'file','enable':True}):
            self.assertEqual(builtin_database_shape(source),'unknown')

    def test_real_capture_retains_exact_three_key_failure_stage_before_snapshot(self):
        for rule,stage in [(100,'exact_type_enable_maxrules100'),('100','unknown')]:
            t=Transport()
            t.config['authorization']['sources'].append({'type':'built_in_database','enable':True,'max_rules':rule})
            t.running_config=copy.deepcopy(t.config)
            observed=[]
            work=SimpleNamespace(runner=lambda app:t,_emqx_build_stage=observed.append)
            target=SimpleNamespace(env={},container='lab-target',secrets=[],files=[('/fixture/acl.conf','/opt/emqx/etc/acl.conf','ro')])
            with patch.object(ha_emqx,'snapshot_target_volume') as snapshot:
                with self.assertRaises(BackupError):ha_emqx.capture_target_seed(work,'app',target,None)
            self.assertEqual(observed[-1],'target_references_builtin_'+stage)
            self.assertNotIn('export',t.events)
            snapshot.assert_not_called()

    def test_two_key_success_does_not_mask_later_file_failure(self):
        observed=[]
        sources=[{'type':'built_in_database','enable':True},{'type':'file','path':'/unmounted/acl'}]
        with self.assertRaises(BackupError):
            ha_emqx.authorization_file_references({'sources':sources},[],observe=observed.append)
        self.assertEqual(observed,['target_references_builtin_exact_type_enable','target_references'])
