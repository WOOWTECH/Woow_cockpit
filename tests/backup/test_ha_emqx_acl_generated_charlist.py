"""Host-only modeled native map update; no file, credential, or lab access."""
import copy
import unittest
from woowbackup.errors import BackupError
from woowbackup.podman import Result
from woowbackup.ha_emqx_acl_preservation import (GENERATED_ACL_PATH,ACL_DISABLE_GENERATED_EXPR,
    generated_acl_charlist,disabled_intermediate,file_path_type_reason,disable_generated_acl_builtin)
from .test_ha_emqx_acl_preservation import NativeRemovalTransport
from . import test_ha_emqx_candidate_flow as flow

class GeneratedPathTransport(NativeRemovalTransport):
    def __init__(self):
        super().__init__()
        self.config['node']={'data_dir':'/opt/emqx/data'}
        self.running_config=copy.deepcopy(self.config)
        self.native_calls=0
        self.native_fault=None

    def exec(self,role,command,**kwargs):
        if command==['emqx','eval',ACL_DISABLE_GENERATED_EXPR]:
            assert role=='emqx-new' and kwargs=={'timeout':10,'max_output':256,'check':False}
            self.native_calls+=1
            if self.native_fault=='refused':return Result(0,b'WOOWACLDISABLED:REFUSED',b'')
            self.native_before=copy.deepcopy(self.running_config)
            for source in self.running_config['authorization']['sources']:
                if source['type']=='built_in_database':source['enable']=False
            if self.native_fault=='normalize':
                self.running_config['authorization']['sources'][0]['path']=GENERATED_ACL_PATH
            if self.native_fault=='row-change':self.acl_rows[0]=b'generated-same-count-mutation'
            self.native_after=copy.deepcopy(self.running_config)
            return Result(0,b'WOOWACLDISABLED:OKok\n',b'')
        result=super().exec(role,command,**kwargs)
        if command[:4]==['emqx','ctl','data','import']:
            self.running_config['authorization']['sources'].insert(0,{'type':'file','enable':True,
                'path':list(GENERATED_ACL_PATH.encode('ascii'))})
        return result

class GeneratedCharlistTests(unittest.TestCase):
    def test_entry_native_disable_preserves_full_array_then_restores_absolute_target(self):
        t=GeneratedPathTransport();rows=copy.deepcopy(t.acl_rows)
        flow.CandidateFlowTests.invoke(self,t)
        self.assertEqual(t.native_calls,1)
        self.assertEqual(len(t.loads),1) # only final target JSON load
        expected=copy.deepcopy(t.native_before)
        expected['authorization']['sources'][-1]['enable']=False
        self.assertEqual(t.native_after,expected)
        self.assertEqual(t.native_after['authorization']['sources'][0]['path'],list(GENERATED_ACL_PATH.encode('ascii')))
        self.assertEqual(t.running_config,t.config)
        self.assertEqual(t.acl_rows,rows)
        self.assertEqual(t.receipts,3)

    def test_array_normalization_same_count_mutation_or_native_failure_refuses(self):
        for fault in ('normalize','row-change','refused'):
            t=GeneratedPathTransport();t.native_fault=fault
            with self.subTest(fault=fault),self.assertRaises(BackupError):flow.CandidateFlowTests.invoke(self,t)
            self.assertEqual(len(t.loads),0)

    def configs(self,path):
        t=GeneratedPathTransport()
        imported=copy.deepcopy(t.config)
        imported['authorization']['sources']=[{'type':'file','enable':True,'path':path},
            {'type':'built_in_database','enable':True}]
        return t.config,imported

    def test_only_exact_owned_ascii_array_is_accepted_without_mutation(self):
        path=list(GENERATED_ACL_PATH.encode('ascii'))
        original,imported=self.configs(path);before=copy.deepcopy(imported)
        result=disabled_intermediate(original,imported)
        self.assertEqual(result['authorization']['sources'][0]['path'],path)
        result['authorization']['sources'][1]['enable']=True
        self.assertEqual(result,before);self.assertEqual(imported,before)
        invalid=[None,{},[],[True]+path[1:],[47.0]+path[1:],path+[0],[[47]]+path[1:],
            list(b'/opt/emqx/data/authz/../acl.conf'),list(b'/opt/emqx/data/authz/custom.conf'),
            list(b'/outside/acl.conf')]
        for bad in invalid:
            original,imported=self.configs(bad);observed=[]
            with self.subTest(kind=type(bad).__name__),self.assertRaises(BackupError):
                disabled_intermediate(original,imported,observe=observed.append)
            self.assertEqual(observed,['acl_profile_'+file_path_type_reason({'path':bad,'enable':True},True)])
        for side in ('original','imported'):
            original,imported=self.configs(path)
            (original if side=='original' else imported)['node']['data_dir']='/outside'
            observed=[]
            with self.assertRaises(BackupError):disabled_intermediate(original,imported,observe=observed.append)
            self.assertEqual(observed,['acl_profile_file_path_generated_context'])
        original,imported=self.configs(path)
        original['authorization']['sources'][0]['path']=path
        with self.assertRaises(BackupError):disabled_intermediate(original,imported)

    def test_fixed_native_command_has_no_json_hocon_or_dynamic_terms(self):
        self.assertIn('Auth = emqx:get_raw_config([authorization])',ACL_DISABLE_GENERATED_EXPR)
        self.assertIn('emqx_conf:update([authorization],Auth#{<<"sources">>=>Disabled},#{override_to=>cluster})',ACL_DISABLE_GENERATED_EXPR)
        self.assertIn('"/opt/emqx/data/authz/acl.conf" = maps:get(<<"path">>,File)',ACL_DISABLE_GENERATED_EXPR)
        self.assertNotIn('erl_eval',ACL_DISABLE_GENERATED_EXPR)
        self.assertNotIn('file:read',ACL_DISABLE_GENERATED_EXPR)
        self.assertNotIn('hocon',ACL_DISABLE_GENERATED_EXPR)
        self.assertNotIn('json',ACL_DISABLE_GENERATED_EXPR)

    def test_type_side_and_enable_enums_never_contain_values(self):
        for side in (False,True):
            for path,kind in ((None,'null'),({},'dict'),([47,111],'list_ascii'),([True],'list_other')):
                for value,state in ((True,'true'),(False,'false'),(None,'invalid')):
                    self.assertEqual(file_path_type_reason({'path':path,'enable':value},side),
                        'file_path_'+('imported' if side else 'original')+'_'+kind+'_'+state)
                self.assertTrue(file_path_type_reason({'path':path},side).endswith('_missing'))
