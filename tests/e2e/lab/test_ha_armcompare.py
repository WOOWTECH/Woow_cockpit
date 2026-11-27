"""AST-extracted candidate only: no driver import, lab access, or real credentials."""
import ast
from pathlib import Path
import re
import tempfile
import types
import unittest

ROOT = Path(__file__).resolve().parent
class Failed(Exception): pass
class Evidence:
    def __init__(self): self.checks=[]; self.saved={}
    def check(self, name, ok, detail): self.checks.append((name, bool(ok)))
    def save(self, name, value): self.saved[name]=value
    def log(self, message): pass

class CompareTests(unittest.TestCase):
    def setUp(self):
        tree=ast.parse((ROOT/'ha_import_e2e.py').read_text())
        nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in ('parse_arm_fingerprint','scenario_armcompare')]
        self.ns={'Path':Path,'re':re,'Failed':Failed,'FINGERPRINT_SQL':'synthetic SQL'}
        exec(compile(ast.Module(body=nodes,type_ignores=[]),'<candidate>','exec'),self.ns)
        names=['res_partner','woow_import_probe','res_partner_category','res_country','ir_config_parameter','ir_cron','ir_cron_progress','bus_bus']+[f'table_{i}' for i in range(197)]
        self.rows={f'public.{n}':('15','a'*32) for n in names}
    def text(self, rows): return '\n'.join(f'{t} {n} {d}' for t,(n,d) in rows.items())
    def run_compare(self, source=None, target=None):
        ev=Evidence()
        source='#DB woowtest\n'+self.text(self.rows) if source is None else source
        target=self.text(self.rows) if target is None else target
        calls=[]
        def psql(*args): calls.append(args); return target
        self.ns['psql']=psql
        with tempfile.TemporaryDirectory(dir=ROOT) as d:
            p=Path(d)/'synthetic.txt';p.write_text(source)
            self.ns['scenario_armcompare'](ev,types.SimpleNamespace(fingerprint=p))
        self.assertTrue(ev.checks)
        return all(ok for _,ok in ev.checks),ev,calls
    def test_identical_205(self):
        passed,ev,_=self.run_compare()
        self.assertTrue(passed)
        self.assertEqual(ev.saved['arm-compare.json']['status'],'equal_fingerprints')
    def test_non_core_content_corruption(self):
        r=dict(self.rows);r['public.table_0']=('15','b'*32)
        self.assertFalse(self.run_compare(target=self.text(r))[0])
    def test_non_core_row_loss(self):
        r=dict(self.rows);r['public.table_0']=('14','a'*32)
        self.assertFalse(self.run_compare(target=self.text(r))[0])
    def test_missing_table(self):
        r=dict(self.rows);r.pop('public.table_0')
        self.assertFalse(self.run_compare(target=self.text(r))[0])
    def test_added_table(self):
        r=dict(self.rows);r['public.extra']=('0','a'*32)
        self.assertFalse(self.run_compare(target=self.text(r))[0])
    def test_missing_both_cannot_pass(self):
        r=dict(self.rows);r.pop('public.res_country');r['public.replacement']=('15','a'*32)
        passed,_,calls=self.run_compare(source='#DB woowtest\n'+self.text(r),target=self.text(r))
        self.assertFalse(passed);self.assertFalse(calls)
    def test_settings_and_scheduler_never_blanket_exempt(self):
        for name in ('ir_config_parameter','ir_cron','ir_cron_progress','bus_bus'):
            with self.subTest(name=name):
                r=dict(self.rows);r['public.'+name]=('15','b'*32)
                passed,ev,_=self.run_compare(target=self.text(r))
                self.assertFalse(passed)
                self.assertIn('public.'+name,ev.saved['arm-compare.json']['requires_row_evidence'])
    def test_historical_cron_shape_stays_unresolved(self):
        r=dict(self.rows)
        r['public.ir_cron_progress']=('20','b'*32)
        for name in ('ir_cron','ir_config_parameter'):r['public.'+name]=('15','b'*32)
        self.assertFalse(self.run_compare(target=self.text(r))[0])
    def test_latest_four_table_delta_stays_unresolved(self):
        r=dict(self.rows)
        for name in ('bus_bus','ir_cron_progress'):
            r['public.'+name]=('20','b'*32)
        for name in ('ir_config_parameter','ir_cron'):
            r['public.'+name]=('15','b'*32)
        passed,ev,_=self.run_compare(target=self.text(r))
        self.assertFalse(passed)
        report=ev.saved['arm-compare.json']
        self.assertEqual(report['identical'],201)
        self.assertEqual(report['status'],'unverified_differences')
        self.assertEqual(len(report['unverified_tables']),4)
        self.assertEqual(report['requires_row_evidence'],
            ['public.bus_bus','public.ir_config_parameter','public.ir_cron','public.ir_cron_progress'])
        self.assertEqual(report['missing'],[])
        self.assertEqual(report['added'],[])
    def test_invalid_source(self):
        base='#DB woowtest\n'+self.text(self.rows)
        for value in ('', '#DB other\n'+self.text(self.rows),base+'\n#DB woowtest',base+'\npublic.bad 1 nope',base+'\npublic.res_partner 15 '+'a'*32,'#DB woowtest\n'+self.text(dict(list(self.rows.items())[:-1]))):
            with self.subTest(value=value[:24]):
                passed,_,calls=self.run_compare(source=value)
                self.assertFalse(passed);self.assertFalse(calls)
    def test_invalid_target(self):
        base=self.text(self.rows)
        for value in ('',base+'\nbroken row',base+'\npublic.res_partner 15 '+'a'*32,base.replace(' 15 ',' -1 ',1)):
            with self.subTest(value=value[:24]):self.assertFalse(self.run_compare(target=value)[0])
    def test_unknown_table_delta_has_unverified_status(self):
        r=dict(self.rows);r['public.table_1']=('15','c'*32)
        passed,ev,_=self.run_compare(target=self.text(r))
        self.assertFalse(passed)
        self.assertEqual(ev.saved['arm-compare.json']['unverified_tables'],['public.table_1'])
        self.assertEqual(ev.saved['arm-compare.json']['requires_row_evidence'],['public.table_1'])
    def test_invalid_input_replaces_comparison_report(self):
        passed,ev,_=self.run_compare(target='SECRET_BAD_RESPONSE')
        self.assertFalse(passed)
        self.assertEqual(ev.saved['arm-compare.json'],
                         {'schema_version':1,'status':'invalid_input','error_type':'Failed'})
    def test_target_comments_rejected(self):
        self.assertFalse(self.run_compare(target=self.text(self.rows)+'\n# unexpected')[0])
    def test_source_read_failure_does_not_call_database(self):
        ev=Evidence()
        self.ns['psql']=lambda *args: self.fail('database must not be queried')
        self.ns['scenario_armcompare'](ev,types.SimpleNamespace(fingerprint=ROOT/'nonexistent-source'))
        self.assertEqual(ev.saved['arm-compare.json']['status'],'invalid_input')
        self.assertFalse(all(ok for _,ok in ev.checks))
    def test_database_failure_is_not_green(self):
        ev=Evidence()
        def fail(*args): raise Failed('SECRET_DATABASE_ERROR')
        self.ns['psql']=fail
        with tempfile.TemporaryDirectory(dir=ROOT) as d:
            p=Path(d)/'source';p.write_text('#DB woowtest\n'+self.text(self.rows))
            self.ns['scenario_armcompare'](ev,types.SimpleNamespace(fingerprint=p))
        self.assertEqual(ev.saved['arm-compare.json']['status'],'invalid_input')
        self.assertNotIn('SECRET',str(ev.saved))
        self.assertFalse(all(ok for _,ok in ev.checks))
    def test_other_database_not_merged(self):
        source='#DB other\npublic.other 1 '+'a'*32+'\n#DB woowtest\n'+self.text(self.rows)
        self.assertTrue(self.run_compare(source=source)[0])

if __name__=='__main__':unittest.main(verbosity=2)
