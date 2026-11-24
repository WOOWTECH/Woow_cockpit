"""Candidate entry with modeled native destructive removal; never a broker/lab."""
import copy
import hashlib
import unittest
from woowbackup import ha_emqx as emqx
from woowbackup.ha_emqx_acl_preservation import ACL_RECEIPT_EXPR,acl_receipt,disabled_intermediate
from woowbackup.errors import BackupError
from woowbackup.podman import Result
from . import test_ha_emqx_candidate_flow as flow


class NativeRemovalTransport(flow.Transport):
    """Models the pinned removed-enabled destroy path, not native acceptance."""
    def __init__(self):
        super().__init__()
        self.config['authorization']['sources']=self.config['authorization']['sources'][:1]
        self.running_config=copy.deepcopy(self.config)
        self.acl_rows=[b'generated-acl-one',b'generated-acl-two']
        self.loads=[]
        self.receipts=0
        self.break_at=None
        self.builtin={'type':'built_in_database','enable':True}

    def exec(self,role,command,**kwargs):
        if command==['emqx','eval',ACL_RECEIPT_EXPR]:
            assert role=='emqx-new'
            # Wall-clock bound: 120 s (the vendor CLI waits without a limit, bin/nodetool:172-176; 10 s failed under load).
            assert kwargs['timeout']==120 and kwargs['max_output']==256 and kwargs['check'] is False
            self.events.append('acl-receipt');self.receipts+=1
            if self.break_at=='receipt-refused':return Result(0,b'WOOWACL:REFUSED',b'')
            if self.break_at==('receipt-mutation',self.receipts):self.acl_rows[0]=b'changed-same-count'
            body=b''.join(sorted(self.acl_rows))
            digest=hashlib.sha256(body).hexdigest().upper().encode()
            schema=b'C'*64 if self.break_at==('schema-mutation',self.receipts) else b'A'*64
            return Result(0,b'WOOWACL:'+str(len(self.acl_rows)).encode()+b':'+str(len(body)).encode()+b':'+schema+b':'+digest+b':ENDok\n',b'')
        if command[:4]==['emqx','ctl','data','import']:
            result=super().exec(role,command,**kwargs)
            self.running_config['authorization']['sources']=[copy.deepcopy(self.builtin)]
            return result
        if command[:4]==['emqx','ctl','conf','load']:
            old_sources=copy.deepcopy(self.running_config['authorization']['sources'])
            new_sources=self.restore.get('authorization',{}).get('sources',old_sources)
            self.loads.append(copy.deepcopy(new_sources))
            old_builtin=next((s for s in old_sources if s.get('type')=='built_in_database'),None)
            new_builtin=next((s for s in new_sources if s.get('type')=='built_in_database'),None)
            # Native contract: removed enabled source destroys all ACL rows.
            if old_builtin and old_builtin.get('enable') is True and new_builtin is None:
                self.acl_rows=[]
            if self.break_at=='disable-load' and new_builtin and new_builtin['enable'] is False:
                return Result(1,b'generated-private-diagnostic',b'')
            result=super().exec(role,command,**kwargs)
            if len(self.loads)==1 and self.break_at=='intermediate-config':
                self.running_config['authorization']['deny_action']='disconnect'
            if len(self.loads)==2 and self.break_at=='final-config':
                self.running_config['mqtt']={'max_inflight':999}
            if self.break_at==('delete-row',len(self.loads)):
                self.acl_rows.pop()
            return result
        return super().exec(role,command,**kwargs)


class CandidateAclRemovalTests(unittest.TestCase):
    def invoke(self,transport):return flow.CandidateFlowTests.invoke(self,transport)

    def test_entry_disables_then_removes_and_preserves_all_rows(self):
        t=NativeRemovalTransport();rows=copy.deepcopy(t.acl_rows)
        self.invoke(t)
        self.assertEqual(t.loads[0],[{'type':'built_in_database','enable':False}])
        self.assertEqual(t.loads[1],t.config['authorization']['sources'])
        self.assertEqual(t.running_config,t.config)
        self.assertEqual(t.acl_rows,rows)
        self.assertEqual(t.receipts,3)
        self.assertEqual(t.events.count('restore'),2)
        self.assertLess(t.events.index('import'),t.events.index('acl-receipt'))

    def test_same_count_changes_row_loss_config_changes_and_failures_refuse(self):
        for fault in (('schema-mutation',2),('schema-mutation',3),('receipt-mutation',2),('receipt-mutation',3),('delete-row',1),('delete-row',2),
                      'intermediate-config','final-config','disable-load','receipt-refused'):
            t=NativeRemovalTransport();t.break_at=fault
            with self.subTest(fault=fault),self.assertRaises(BackupError):self.invoke(t)
            if fault in ('receipt-refused','disable-load','intermediate-config',('receipt-mutation',2),('delete-row',1)):
                self.assertLessEqual(len(t.loads),1)

    def test_unknown_or_expanded_builtin_refused_before_any_load(self):
        for builtin in ({'type':'built_in_database','enable':True,'max_rules':101},
                        {'type':'built_in_database','enable':'true'}, {'type':'built_in_database'}):
            t=NativeRemovalTransport();t.builtin=builtin
            with self.subTest(keys=sorted(builtin)),self.assertRaises(BackupError):self.invoke(t)
            self.assertEqual(t.loads,[])
            self.assertEqual(t.receipts,0)

    def test_direct_removal_model_demonstrates_destructive_control(self):
        t=NativeRemovalTransport()
        t.running_config['authorization']['sources']=[copy.deepcopy(t.builtin)]
        t.restore={'authorization':copy.deepcopy(t.config['authorization'])}
        t.exec('emqx-new',['emqx','ctl','conf','load','--replace','fixed'])
        self.assertEqual(t.acl_rows,[])

    def test_original_builtin_target_and_existing_disabled_removal_do_not_enter_path(self):
        original={'authorization':{'sources':[{'type':'built_in_database','enable':True}]}}
        self.assertIsNone(disabled_intermediate(original,original))
        t=NativeRemovalTransport();t.builtin['enable']=False
        self.invoke(t)
        self.assertEqual(len(t.loads),1)
        self.assertEqual(t.receipts,0)
        self.assertEqual(len(t.acl_rows),2)

    def test_intermediate_changes_only_one_boolean_and_no_inputs(self):
        original={'authorization':{'no_match':'deny','deny_action':'ignore','sources':[
            {'type':'file','enable':True,'path':'/opt/emqx/etc/lab-acl.conf'}]}}
        imported=copy.deepcopy(original)
        imported['authorization']['sources'].append({'type':'built_in_database','enable':True})
        imported['opaque-data']={'private':'generated-data'}
        before=copy.deepcopy(imported)
        result=disabled_intermediate(original,imported)
        result['authorization']['sources'][-1]['enable']=True
        self.assertEqual(result,before)
        self.assertEqual(imported,before)
        for field in ('unknown','path'):
            bad=copy.deepcopy(imported);bad['authorization'][field]='generated-private'
            with self.assertRaises(BackupError):disabled_intermediate(original,bad)
        bad=copy.deepcopy(imported);bad['authorization']['sources'].append(copy.deepcopy(bad['authorization']['sources'][-1]))
        with self.assertRaises(BackupError):disabled_intermediate(original,bad)

    def test_malformed_or_oversized_receipt_refuses_without_body(self):
        valid=b'WOOWACL:0:0:'+b'A'*64+b':'+b'B'*64+b':END'
        for body in (b'private-invalid',valid+b'junk',valid.replace(b':0:0:',b':65537:0:'),
                     valid.replace(b':0:0:',b':0:8388609:'),b'x'*257):
            with self.subTest(size=len(body)),self.assertRaises(BackupError) as caught:
                acl_receipt(lambda command:Result(0,body,b'private-stderr'))
            self.assertNotIn('private',str(caught.exception))

    def test_fixed_native_schema_contract_uses_full_ets_record_under_read_lock(self):
        self.assertIn('ok = mnesia:read_lock_table(schema)',ACL_RECEIPT_EXPR)
        self.assertIn('[{schema,emqx_acl,Create}] = ets:lookup(schema,emqx_acl)',ACL_RECEIPT_EXPR)
        self.assertLess(ACL_RECEIPT_EXPR.index('read_lock_table(schema)'),ACL_RECEIPT_EXPR.index('ets:lookup(schema,emqx_acl)'))
        self.assertNotIn('mnesia:read(schema',ACL_RECEIPT_EXPR)
        self.assertIn('Schema = term_to_binary(Create)',ACL_RECEIPT_EXPR)
        self.assertIn('emqx_acl = mnesia:table_info(emqx_acl,record_name)',ACL_RECEIPT_EXPR)
        self.assertIn('[who,rules] = mnesia:table_info(emqx_acl,attributes)',ACL_RECEIPT_EXPR)
        self.assertIn('Count = mnesia:table_info(emqx_acl,size)',ACL_RECEIPT_EXPR)

    def test_three_key_imported_source_is_preserved_while_disabling(self):
        t=NativeRemovalTransport();t.builtin['max_rules']=100
        before=copy.deepcopy(t.builtin);rows=copy.deepcopy(t.acl_rows)
        self.invoke(t)
        self.assertEqual(t.loads[0],[{'type':'built_in_database','enable':False,'max_rules':100}])
        self.assertEqual(t.builtin,before)
        self.assertEqual(t.loads[1],t.config['authorization']['sources'])
        self.assertEqual(t.acl_rows,rows)
        self.assertEqual(t.receipts,3)

    def test_dropping_third_key_in_disable_phase_refuses_before_removal(self):
        class DropIntermediate(NativeRemovalTransport):
            def exec(self,role,command,**kwargs):
                result=super().exec(role,command,**kwargs)
                if command[:4]==['emqx','ctl','conf','load'] and len(self.loads)==1:
                    self.running_config['authorization']['sources'][0].pop('max_rules',None)
                return result
        t=DropIntermediate();t.builtin['max_rules']=100
        with self.assertRaises(BackupError):self.invoke(t)
        self.assertEqual(len(t.loads),1)
        self.assertEqual(t.receipts,1)
