"""Metadata/digest native transport models only; no broker or file access."""
import base64
import copy
import hashlib
import json
import unittest
from woowbackup import ha_emqx
from woowbackup.errors import BackupError
from woowbackup.podman import Result
from woowbackup.ha_emqx_acl_path_proof import (PATH_PROOF_EXPR,DISABLE_PROVIDER_EXPR,MAX_WIRE,
    NATIVE_PATH_STAGES,observe_generated_path,verify_generated_path,disable_generated_path)
from woowbackup.ha_emqx_acl_preservation import disabled_intermediate
from .test_ha_emqx_acl_preservation import NativeRemovalTransport
from . import test_ha_emqx_candidate_flow as flow

OWNED='/opt/emqx/data/authz/acl.conf'
def digest(config):return hashlib.sha256(json.dumps(config).encode()).hexdigest().upper()

class ProviderTransport(NativeRemovalTransport):
    def __init__(self,relative=True):
        super().__init__()
        self.data='data' if relative else '/opt/emqx/data'
        self.provider=self.data+'/authz/acl.conf'
        self.config['node']={'data_dir':self.data}
        self.running_config=copy.deepcopy(self.config)
        self.path_queries=0;self.native_calls=0;self.fault=None

    def doc(self):
        identity=[20,33152,1,10,0,1000,1000,1000,50,50]
        return {'contract':'candidate-acl-provider-path-v1','config_sha256':digest(self.running_config),
            'before_sha256':digest(self.running_config),'provider_path':list(self.provider.encode()),
            'raw_data_dir':self.running_config['node']['data_dir'],'app_data_dir':list(self.data.encode()),
            'cwd':'/opt/emqx','data_root':'/opt/emqx/data','acl_path':OWNED,
            'directories':[identity.copy() for _ in range(4)],'file':identity.copy(),'sha256':'A'*64,
            'runtime':['emqx@127.0.0.1',123456]}

    def exec(self,role,command,**kwargs):
        if command in (['emqx','eval',PATH_PROOF_EXPR],['emqx','eval',DISABLE_PROVIDER_EXPR]):
            # Wall-clock bound 120 s (vendor CLI eval is unbounded, bin/nodetool:172-176); the wire bound is unchanged.
            assert role=='emqx-new' and kwargs=={'timeout':120,'max_output':MAX_WIRE,'check':False}
            self.path_queries+=1
            if type(self.fault) is str and self.fault.startswith('native:'):
                return Result(0,b'WOOWACLPATH:REFUSED:'+self.fault[7:].encode()+b'ok\n',b'')
            old=digest(self.running_config)
            if command[-1]==DISABLE_PROVIDER_EXPR:
                self.native_calls+=1;self.native_before=copy.deepcopy(self.running_config)
                for source in self.running_config['authorization']['sources']:
                    if source['type']=='built_in_database':source['enable']=False
                if self.fault=='normalize':self.running_config['authorization']['sources'][0]['path']=self.provider
                if self.fault=='row-change':self.acl_rows[0]=b'generated-row-change'
                self.native_after=copy.deepcopy(self.running_config)
            doc=self.doc();doc['before_sha256']=old
            if self.fault=='digest':doc['config_sha256']='B'*64
            if self.fault=='provider':doc['provider_path']=list(b'data/authz/custom.conf')
            if self.fault=='outside':doc['app_data_dir']=list(b'/outside')
            if self.fault=='cwd':doc['cwd']='/outside'
            if self.path_queries>=2:
                if self.fault=='inode':doc['file'][5]+=1
                if self.fault=='content':doc['sha256']='C'*64
                if self.fault=='restart':doc['runtime'][1]+=1
                if self.fault=='parent':doc['directories'][0][5]+=1
            return Result(0,b'WOOWACLPATH:'+base64.b64encode(json.dumps(doc).encode())+b':ENDok\n',b'')
        result=super().exec(role,command,**kwargs)
        if command[:4]==['emqx','ctl','data','import']:
            self.running_config['authorization']['sources'].insert(0,
                {'type':'file','enable':True,'path':list(self.provider.encode())})
        return result

    def imported(self):
        self.running_config['authorization']['sources']=[{'type':'file','enable':True,
            'path':list(self.provider.encode())},{'type':'built_in_database','enable':True}]
        return self.running_config

class ProviderPathTests(unittest.TestCase):
    def test_entry_derives_relative_and_absolute_provider_without_rewriting_raw_values(self):
        for relative in (True,False):
            t=ProviderTransport(relative);rows=copy.deepcopy(t.acl_rows)
            with self.subTest(relative=relative):flow.CandidateFlowTests.invoke(self,t)
            self.assertEqual(t.native_calls,1);self.assertEqual(len(t.loads),1)
            expected=copy.deepcopy(t.native_before);expected['authorization']['sources'][-1]['enable']=False
            self.assertEqual(t.native_after,expected)
            self.assertEqual(t.running_config,t.config)
            self.assertEqual(t.running_config['node']['data_dir'],t.data)
            self.assertEqual(t.acl_rows,rows);self.assertEqual(t.receipts,3)
            self.assertEqual(t.path_queries,4) # initial, disable, after-disable, final

    def test_data_file_config_runtime_and_digest_change_refuse(self):
        for fault in ('digest','provider','outside','cwd','inode','content','restart','parent','normalize','row-change'):
            t=ProviderTransport();t.fault=fault
            with self.subTest(fault=fault),self.assertRaises(BackupError):flow.CandidateFlowTests.invoke(self,t)
            self.assertEqual(len(t.loads),0)

    def test_proof_bound_to_same_owner_capture_and_not_caller_json(self):
        t=ProviderTransport();config=t.imported();before=copy.deepcopy(config)
        proof=observe_generated_path(t,config,digest(config))
        intermediate=disabled_intermediate(t.config,config,path_proof=proof)
        self.assertEqual(intermediate['authorization']['sources'][0]['path'],list(t.provider.encode()))
        self.assertEqual(config,before)
        with self.assertRaises(BackupError):disabled_intermediate(t.config,config,path_proof=t.doc())
        stale=copy.deepcopy(config);stale['mqtt']={'injected':True}
        with self.assertRaises(BackupError):disabled_intermediate(t.config,stale,path_proof=proof)
        with self.assertRaises(BackupError):verify_generated_path(ProviderTransport(),proof)
        with self.assertRaises(BackupError):disable_generated_path(ProviderTransport(),proof)

    def test_unproven_arrays_still_refuse_before_profile_mutation(self):
        for path in (list(b'data/authz/custom.conf'),list(b'/outside/acl.conf'),[True],[],{},None):
            t=ProviderTransport();config=t.imported();config['authorization']['sources'][0]['path']=path
            with self.subTest(kind=type(path).__name__),self.assertRaises(BackupError):
                disabled_intermediate(t.config,config)
        t=ProviderTransport();config=t.imported();proof=observe_generated_path(t,config,digest(config))
        original=copy.deepcopy(t.config);original['authorization']['sources'][0]['path']=list(t.provider.encode())
        with self.assertRaises(BackupError):disabled_intermediate(original,config,path_proof=proof)

    def test_fixed_native_and_host_diagnostics_never_emit_dynamic_terms(self):
        for stage in NATIVE_PATH_STAGES:
            t=ProviderTransport();config=t.imported();t.fault='native:'+stage;seen=[]
            with self.subTest(stage=stage),self.assertRaises(BackupError):
                observe_generated_path(t,config,digest(config),observe=seen.append)
            self.assertEqual(seen,['acl_path_native_'+stage])
            import emqx_candidate_stage
            emqx_candidate_stage.mark('product_'+seen[-1])
        t=ProviderTransport();config=t.imported();seen=[];t.fault='native:unexpected_private'
        with self.assertRaises(BackupError):observe_generated_path(t,config,digest(config),observe=seen.append)
        self.assertEqual(seen,['acl_path_native_native'])
        t=ProviderTransport();config=t.imported();seen=[];t.fault='digest'
        with self.assertRaises(BackupError):observe_generated_path(t,config,digest(config),observe=seen.append)
        self.assertEqual(seen,['acl_path_host_digest'])

    def test_existing_raw_read_digest_uses_original_native_bytes_not_reencoding(self):
        config=ProviderTransport().config;result=flow.response(config);sink=[]
        self.assertEqual(ha_emqx.read_effective_config(lambda command:result,_native_digest=sink),config)
        self.assertEqual(sink,[digest(config)])

    def test_expression_only_emits_metadata_and_hashes(self):
        self.assertIn('Provider=emqx_authz_file:acl_conf_file()',PATH_PROOF_EXPR)
        self.assertIn('filename:absname(Clean',PATH_PROOF_EXPR.replace('RawClean','Clean').replace('AppClean','Clean'))
        self.assertIn('config_sha256=>Hash',PATH_PROOF_EXPR)
        self.assertNotIn('config=>Config',PATH_PROOF_EXPR)
        self.assertNotIn('content_b64',PATH_PROOF_EXPR)
        self.assertIn('eof=file:read(F,1)',PATH_PROOF_EXPR)
        self.assertIn('maps:without([config_sha256,before_sha256]',DISABLE_PROVIDER_EXPR)
        self.assertIn('Auth#{<<"sources">>=>Disabled}',DISABLE_PROVIDER_EXPR)
        self.assertNotIn('erl_eval',DISABLE_PROVIDER_EXPR)

    def test_float_character_cannot_borrow_integer_list_proof(self):
        t=ProviderTransport();config=t.imported();proof=observe_generated_path(t,config,digest(config))
        changed=copy.deepcopy(config)
        changed['authorization']['sources'][0]['path'][0]=float(changed['authorization']['sources'][0]['path'][0])
        with self.assertRaises(BackupError):disabled_intermediate(t.config,changed,path_proof=proof)
        t.running_config=changed
        with self.assertRaises(BackupError):observe_generated_path(t,changed,digest(changed))
