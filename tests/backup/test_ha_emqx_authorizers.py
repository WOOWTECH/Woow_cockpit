"""No files, broker, credentials or lab access."""
import copy
import unittest
from woowbackup.ha_emqx_authorizers import builtin_database_references
from woowbackup.errors import BackupError

class BuiltinAuthorizerTests(unittest.TestCase):
    def test_explicit_boolean_only_and_no_mutation(self):
        for enabled in (True, False):
            source={'type':'built_in_database','enable':enabled}
            before=copy.deepcopy(source)
            self.assertEqual(builtin_database_references(source),frozenset())
            self.assertEqual(source,before)

    def test_missing_unknown_and_external_fields_refuse_even_disabled(self):
        for enabled in (True,False):
            for key,value in [('path','/fixture/acl'),('url','https://example.invalid'),
                    ('loader','custom'),('max_rules',100),('headers',{}),('file','/fixture/acl')]:
                source={'type':'built_in_database','enable':enabled,key:value}
                with self.subTest(enabled=enabled,key=key),self.assertRaises(BackupError):
                    builtin_database_references(source)
        for source in ({}, {'type':'built_in_database'}, {'enable':True}, None, [],
                {'type':'file','enable':True},{'type':'redis','enable':True},
                {'type':b'built_in_database','enable':True}):
            with self.subTest(shape=type(source).__name__),self.assertRaises(BackupError):
                builtin_database_references(source)

    def test_boolean_coercion_forbidden(self):
        for value in (0,1,'true','false',None,[],{}):
            with self.subTest(kind=type(value).__name__),self.assertRaises(BackupError):
                builtin_database_references({'type':'built_in_database','enable':value})

    def test_dict_subclass_cannot_supply_callbacks(self):
        class CallbackDict(dict):
            def __getitem__(self,key):raise AssertionError('untrusted callback executed')
        with self.assertRaises(BackupError):
            builtin_database_references(CallbackDict(type='built_in_database',enable=True))

    def test_main_guard_uses_same_exact_profile(self):
        from woowbackup.ha_emqx import authorization_file_references
        self.assertEqual(authorization_file_references(
            {'sources':[{'type':'built_in_database','enable':True}]},[]),{'configs/cluster.hocon'})
        with self.assertRaises(BackupError):
            authorization_file_references({'sources':[{'type':'built_in_database','enable':True,'max_rules':100}]},[])
