"""Optional raw omission, exact preservation and bounded refusal enums; no lab."""
import copy
import unittest
from woowbackup import ha_emqx
from woowbackup.errors import BackupError
from woowbackup.ha_emqx_acl_preservation import disabled_intermediate,ACL_REMOVAL_STAGES
from .test_ha_emqx_acl_preservation import NativeRemovalTransport
from . import test_ha_emqx_candidate_flow as flow

class RawAclProfileTests(unittest.TestCase):
    def test_entry_preserves_each_raw_omission_until_final_explicit_policy(self):
        for missing in (('no_match',),('deny_action',),('no_match','deny_action')):
            class Omitted(NativeRemovalTransport):
                def exec(self,role,command,**kwargs):
                    if command[:4]==['emqx','ctl','conf','load']:
                        self.loaded_authorizations=getattr(self,'loaded_authorizations',[])+[copy.deepcopy(self.restore['authorization'])]
                    result=super().exec(role,command,**kwargs)
                    if command[:4]==['emqx','ctl','data','import']:
                        for key in missing:self.running_config['authorization'].pop(key,None)
                        self.running_config['authorization']['cache']={'enable':True,'max_size':32,'ttl':'1m',
                            'excludes':['b1/status/#']}
                    return result
            t=Omitted();rows=copy.deepcopy(t.acl_rows)
            with self.subTest(missing=missing):
                flow.CandidateFlowTests.invoke(self,t)
                self.assertEqual(t.acl_rows,rows)
                self.assertEqual(t.loads[0],[{'type':'built_in_database','enable':False}])
                self.assertEqual(t.running_config,t.config)
                self.assertEqual(t.receipts,3)
                for key in missing:self.assertNotIn(key,t.loaded_authorizations[0])
                self.assertEqual(t.loaded_authorizations[0]['cache']['excludes'],['b1/status/#'])
                self.assertEqual(t.loaded_authorizations[1],t.config['authorization'])

    def test_exact_intermediate_preserves_omissions_and_passive_topic_filters(self):
        t=NativeRemovalTransport();original=t.config
        imported=copy.deepcopy(original)
        imported['authorization']={'sources':[{'type':'built_in_database','enable':True}],
            'cache':{'enable':True,'max_size':1048576,'ttl':'60s','excludes':['b1/status/#','lab/#']}}
        before=copy.deepcopy(imported)
        intermediate=disabled_intermediate(original,imported)
        self.assertNotIn('no_match',intermediate['authorization'])
        self.assertNotIn('deny_action',intermediate['authorization'])
        intermediate['authorization']['sources'][0]['enable']=True
        self.assertEqual(intermediate,before)
        self.assertEqual(imported,before)

    def test_default_reader_remains_strict_and_optional_reader_still_validates_present_enums(self):
        config={'authorization':{'sources':[{'type':'built_in_database','enable':True}]}}
        def read(command):return flow.response(config)
        with self.assertRaises(BackupError):ha_emqx.read_effective_config(read)
        self.assertEqual(ha_emqx.read_effective_config(read,allow_authz_omission=True),config)
        for key in ('no_match','deny_action'):
            for invalid in (None,True,'invalid'):
                config['authorization'][key]=invalid
                with self.assertRaises(BackupError):ha_emqx.read_effective_config(read,allow_authz_omission=True)
            config['authorization'].pop(key)

    def test_every_supported_refusal_class_has_fixed_stage(self):
        original=NativeRemovalTransport().config
        base={'authorization':{'sources':[{'type':'built_in_database','enable':True}]}}
        def put_auth(key,value):
            value_config=copy.deepcopy(base);value_config['authorization'][key]=value;return value_config
        cases=[(None,'auth_shape'),({'authorization':{'sources':None}},'sources_shape'),
            (put_auth('node_cache',{}),'auth_unknownfields'),(put_auth('no_match','invalid'),'auth_no_match'),
            (put_auth('deny_action',None),'auth_deny_action'),(put_auth('cache',[]),'cache_shape')]
        for cache,reason in [({'unknown':True},'cache_unknownfields'),({'enable':1},'cache_enable'),
                ({'max_size':1048577},'cache_max_size'),({'ttl':'file:/private'},'cache_ttl'),
                ({'excludes':[{}]},'cache_excludes')]:
            cases.append((put_auth('cache',cache),reason))
        builtin=base['authorization']['sources'][0]
        for sources,reason in [([builtin,builtin],'builtin_duplicate'),
                ([dict(builtin,max_rules=99)],'builtin_shape'),([builtin,None],'source_shape'),
                ([builtin,{'type':'file','path':'/a'},{'type':'file','path':'/b'}],'source_duplicate'),
                ([builtin,{'type':'http'}],'source_type'),
                ([builtin,{'type':'file','path':'/a','unknown':True}],'file_fields'),
                ([builtin,{'type':'file','path':'/a','enable':1}],'file_enable'),
                ([builtin,{'type':'file','path':'${UNKNOWN_DIR}/acl.conf'}],'file_path_unknown_variable')]:
            cases.append((put_auth('sources',sources),reason))
        for imported,reason in cases:
            observed=[]
            with self.subTest(reason=reason),self.assertRaises(BackupError):
                disabled_intermediate(original,imported,observe=observed.append)
            self.assertEqual(observed,['acl_profile_'+reason])
            self.assertIn(observed[-1],ACL_REMOVAL_STAGES)
