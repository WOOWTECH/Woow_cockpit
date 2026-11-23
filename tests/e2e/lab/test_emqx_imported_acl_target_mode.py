"""Generated transport only; no actual broker, archive, or lab access."""
import json
import unittest
from unittest.mock import patch
from emqx_imported_acl_target_mode import target_policy_for_mode,FILE_BASELINE,IMPORTED_MNESIA
from emqx_mnesia_acl_target_variant import _FILE_ONLY,_FALLBACK
from emqx_owner_target import owner_target_readers
from emqx_private_boundary import PrivateFailure
import test_emqx_owner_target as fixture

class ImportedAclModeTests(unittest.TestCase):
    def test_explicit_modes_preserve_baseline(self):
        from emqx_real_owner_workflow import _target_acl
        with patch('emqx_real_owner_workflow._target_base',return_value=b'prefix\n'+_FILE_ONLY):
            baseline=target_policy_for_mode(FILE_BASELINE)
            imported=target_policy_for_mode(IMPORTED_MNESIA)
        self.assertEqual(baseline.base,b'prefix\n'+_FILE_ONLY)
        self.assertEqual(baseline.acl,_target_acl())
        self.assertEqual(imported.base,b'prefix\n'+_FALLBACK)
        self.assertEqual(imported.acl,b'{allow, {username, "lab"}, all, ["lab/#"]}.\n')
        for value in (b'b1-sensor',b'b1-gateway',b'{deny, all}'):
            self.assertNotIn(value,imported.acl)
        self.assertTrue(imported.unchanged(base=imported.base,acl=imported.acl))
        self.assertFalse(imported.unchanged(base=imported.base,acl=baseline.acl))

    def test_no_source_mode_alias_or_implicit_default(self):
        for mode in (None,True,0,'','--source-vendor-acl-sql-aliases','mnesia',b'imported-mnesia-acl'):
            with self.subTest(kind=type(mode).__name__),self.assertRaises(ValueError):
                target_policy_for_mode(mode)

    def test_empty_native_categories_and_builtin_cooked_config_are_compatible(self):
        config=fixture.cooked_config()
        # COOKED native max_rules is fully retained/scanned, distinct from RAW
        # product two-key contract. Generated transport is not native evidence.
        config['authorization']={'no_match':fixture.Atom('deny'),'deny_action':fixture.Atom('ignore'),
            'sources':[{'type':fixture.Atom('built_in_database'),'enable':True,'max_rules':100}]}
        producer=fixture.OwnerProducerTests()
        def empty(doc):
            for table in doc['tables']:
                if table['table'] in ('emqx_acl','emqx_authn_mnesia','emqx_admin_jwt'):
                    table['rows']=[];table['row_count']=0
        events=[]
        with owner_target_readers(private_eval=producer.transport(events,edit=empty,config=config),
                quiesce=lambda:producer.lock(events)) as readers:
            self.assertEqual(len(readers),5)
            for name in ('mqtt-auth','api-keys','connectors','tls'):
                with readers[name]() as stream:self.assertEqual(json.load(stream)['records'],[])
            self.assertIn('emqx_acl',readers.persisted_values.tables)
            for value in (b'built_in_database',b'100'):
                with self.assertRaises(PrivateFailure):readers.persisted_values.scan(value)
        self.assertEqual(events,['locked','eval','unlocked'])

    def test_empty_native_claim_requires_matching_row_count(self):
        producer=fixture.OwnerProducerTests()
        def inconsistent(doc):
            table=next(t for t in doc['tables'] if t['table']=='emqx_acl')
            table['rows']=[];table['row_count']=1
        events=[]
        with self.assertRaises(PrivateFailure):
            with owner_target_readers(private_eval=producer.transport(events,edit=inconsistent),
                    quiesce=lambda:producer.lock(events)):pass
        self.assertEqual(events,['locked','eval','unlocked'])
