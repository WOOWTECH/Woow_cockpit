"""Actual internal product entry, generated transport only; no broker/lab."""
import copy
import unittest
from woowbackup import ha_emqx as emqx
from woowbackup.errors import BackupError
from . import test_ha_emqx_candidate_flow as flow

class BuiltinProductFlowTests(unittest.TestCase):
    def invoke(self,transport):
        return flow.CandidateFlowTests.invoke(self,transport)

    def fixture(self,source):
        transport=flow.Transport()
        transport.config['authorization']['sources'].append(source)
        transport.running_config=copy.deepcopy(transport.config)
        return transport

    def test_raw_observation_preserves_order_and_exact_sources_through_import(self):
        for enabled in (True,False):
            t=self.fixture({'type':'built_in_database','enable':enabled})
            original=copy.deepcopy(t.config['authorization'])
            with self.subTest(enabled=enabled):
                self.assertEqual(len(self.invoke(t)),4)
                self.assertEqual(t.restore['authorization'],original)
                self.assertEqual(t.running_config['authorization'],original)
                self.assertEqual(t.seed['authz/custom.acl'],b'{deny, all}.')
                self.assertEqual(set(t.seed),{'configs/cluster.hocon','authz/custom.acl','certs/lab.pem'})
                self.assertLess(t.events.index('import'),t.events.index('restore'))

    def test_raw_reader_never_expands_or_drops_fields(self):
        self.assertIn('emqx:get_raw_config([])',emqx.CONFIG_EXPR)
        self.assertNotIn('emqx:get_config(',emqx.CONFIG_EXPR)
        for source in ({'type':'built_in_database','enable':True},
                       {'type':'built_in_database','enable':True,'max_rules':100}):
            config=self.fixture(source).config
            commands=[]
            def execute(command):
                commands.append(command)
                return flow.response(config)
            self.assertEqual(emqx.read_effective_config(execute),config)
            self.assertEqual(commands,[['emqx','eval',emqx.CONFIG_EXPR]])

    def test_expanded_unknown_and_untyped_source_refuse_before_export(self):
        for source in ({'type':'built_in_database','enable':True,'max_rules':100},
                {'type':'built_in_database','enable':False,'path':'/fixture/loader'},
                {'type':'built_in_database','enable':True,'loader':{}},
                {'type':'built_in_database'}, {'type':'built_in_database','enable':1},
                {'type':'redis','enable':True}):
            t=self.fixture(source)
            with self.subTest(keys=sorted(source)),self.assertRaises(BackupError):self.invoke(t)
            self.assertNotIn('export',t.events)
            self.assertNotIn('start',t.events)

    def test_builtin_does_not_hide_unsafe_file_in_either_order(self):
        for reverse in (False,True):
            t=self.fixture({'type':'built_in_database','enable':True})
            t.config['authorization']['sources'][0]['path']='/outside/unmounted.acl'
            if reverse:t.config['authorization']['sources'].reverse()
            with self.subTest(reverse=reverse),self.assertRaises(BackupError):self.invoke(t)
            self.assertNotIn('export',t.events)

    def test_restored_builtin_mutation_refuses_on_readback(self):
        class ChangedRestore(flow.Transport):
            def exec(self,role,command,**kwargs):
                result=super().exec(role,command,**kwargs)
                if command[:4]==['emqx','ctl','conf','load']:
                    self.running_config['authorization']['sources'][-1]['enable']=False
                return result
        t=ChangedRestore()
        t.config['authorization']['sources'].append({'type':'built_in_database','enable':True})
        t.running_config=copy.deepcopy(t.config)
        with self.assertRaises(BackupError):self.invoke(t)
        self.assertIn('restore',t.events)
