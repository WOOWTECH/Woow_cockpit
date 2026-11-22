"""No file reads or runtime: exact imported literal preservation and negatives."""
import copy
import unittest
from woowbackup import ha_emqx
from woowbackup.errors import BackupError
from woowbackup.ha_emqx_acl_preservation import disabled_intermediate,acl_path_class
from .test_ha_emqx_acl_preservation import NativeRemovalTransport
from . import test_ha_emqx_candidate_flow as flow

class ImportedDefaultAclPathTests(unittest.TestCase):
    def test_entry_preserves_default_path_only_flips_builtin_then_restores_target(self):
        for path in ('etc/acl.conf','${EMQX_ETC_DIR}/acl.conf'):
            class WithDefault(NativeRemovalTransport):
                def exec(self,role,command,**kwargs):
                    if command[:4]==['emqx','ctl','conf','load']:
                        self.auth_loads=getattr(self,'auth_loads',[])+[copy.deepcopy(self.restore['authorization'])]
                    result=super().exec(role,command,**kwargs)
                    if command[:4]==['emqx','ctl','data','import']:
                        self.running_config['authorization']['sources'].insert(0,
                            {'type':'file','enable':True,'path':path})
                        self.imported=copy.deepcopy(self.running_config)
                    return result
            t=WithDefault();rows=copy.deepcopy(t.acl_rows)
            with self.subTest(path_class=acl_path_class(path)):
                flow.CandidateFlowTests.invoke(self,t)
                self.assertEqual(t.loads[0],[{'type':'file','enable':True,'path':path},
                    {'type':'built_in_database','enable':False}])
                intermediate=copy.deepcopy(t.imported['authorization'])
                intermediate['sources'][-1]['enable']=False
                self.assertEqual(t.auth_loads[0],intermediate)
                self.assertEqual(t.auth_loads[1],t.config['authorization'])
                self.assertEqual(t.running_config,t.config)
                self.assertEqual(t.acl_rows,rows)
                self.assertEqual(t.receipts,3)

    def configs(self,path):
        original=NativeRemovalTransport().config
        imported=copy.deepcopy(original)
        imported['authorization']['sources']=[{'type':'file','enable':True,'path':path},
            {'type':'built_in_database','enable':True}]
        return original,imported

    def test_unknown_path_classes_refuse_without_read_or_rewrite(self):
        for path,kind in [(None,'nontext'),([], 'nontext'),('../etc/acl.conf','traversal'),
                ('etc/../etc/acl.conf','traversal'),('/opt/emqx/etc/../acl.conf','traversal'),
                ('etc/custom.conf','relative_other'),('./etc/acl.conf','relative_other'),
                ('${UNKNOWN_DIR}/acl.conf','unknown_variable'),('${EMQX_ETC_DIR}/custom.conf','unknown_variable'),
                ('${EMQX_ETC_DIR}/acl.conf/suffix','unknown_variable'),('file:/etc/acl.conf','uri'),
                ('/opt/emqx/etc/acl.conf\n','control'),('/opt//emqx/etc/acl.conf','absolute_noncanonical')]:
            original,imported=self.configs(path);before=copy.deepcopy(imported);observed=[]
            with self.subTest(kind=kind),self.assertRaises(BackupError):
                disabled_intermediate(original,imported,observe=observed.append)
            self.assertEqual(observed,['acl_profile_file_path_'+kind])
            self.assertEqual(imported,before)

    def test_original_target_does_not_get_relative_or_template_waiver(self):
        for path in ('etc/acl.conf','${EMQX_ETC_DIR}/acl.conf'):
            original,imported=self.configs(path)
            original['authorization']['sources'][0]['path']=path
            with self.assertRaises(BackupError):disabled_intermediate(original,imported)
            with self.assertRaises(BackupError):ha_emqx.authorization_file_references(original['authorization'],[])
