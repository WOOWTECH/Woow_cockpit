"""Structured instance access: app data objects only, bounded facts and quoted identifiers."""
import copy
import unittest

from woowbackup import ha_instance_access as access
from .test_adapter_ha_instance import access_plan


class AccessPlanTests(unittest.TestCase):
    def test_valid_app_access_and_installed_extension_facts(self):
        for app_id in ('n8n', 'litellm'):
            plan = access_plan('db_owner', table_owner='table_owner', app_role='app_login', extension=True)
            self.assertIs(access.validate(plan, app_id), plan)

    def test_malformed_program_or_omitted_schema_facts_are_rejected(self):
        plan = access_plan('db_owner', table_owner='table_owner')
        mutations = [lambda p: p.update(programs=['arbitrary SQL']),
                     lambda p: p['schemas'].append(['omitted', 'db_owner', []]),
                     lambda p: p['relations'][0].__setitem__(2, 'f'),
                     lambda p: p['relations'][0].__setitem__(0, 'omitted'),
                     lambda p: p['relations'][0][-1].append(['app', 'SUPERUSER', False]),
                     lambda p: p['relations'][0][-1].append(['app', 'SELECT', 1]),
                     lambda p: p['extensions'].append(['vector', 'missing; SQL', 'public']),
                     lambda p: p['extensions'].append(['vector', '1.0', 'omitted'])]
        for mutate in mutations:
            bad = copy.deepcopy(plan)
            mutate(bad)
            with self.subTest(mutate=mutate), self.assertRaises((ValueError, TypeError)):
                access.validate(bad, 'litellm')
        with self.assertRaises(ValueError):
            access.validate(plan, 'hermes')

    def test_replay_intersects_moved_objects_and_never_recreates_programs_or_omitted_data(self):
        plan = access_plan('db_owner', table_owner='table_owner', app_role='app_login')
        plan['relations'].append(['public', 'old_table_omitted', 'r', 'table_owner', []])
        present = copy.deepcopy(plan)
        present['relations'].pop()
        script = access.restore_sql(plan, present, 'litellm')
        self.assertIn('ALTER TABLE "public"."marker" OWNER TO "table_owner";', script)
        self.assertIn('GRANT INSERT ON TABLE "public"."marker" TO "app_login";', script)
        self.assertIn('GRANT CREATE ON SCHEMA "public" TO "app_login";', script)
        self.assertNotIn('old_table_omitted', script)
        self.assertNotIn('CREATE SCHEMA', script)
        self.assertNotIn('FUNCTION', script)
        self.assertNotIn('omitted', access.capture_sql('litellm'))

    def test_catalog_identifiers_are_quoted_as_data(self):
        self.assertEqual(access.ident('a";b'), '"a"";b"')
        self.assertEqual(access.literal("v'1"), "'v''1'")

    def test_column_privileges_remain_narrow_and_keep_grant_options(self):
        plan = access_plan('db_owner', table_owner='table_owner')
        plan['columns'] = [['public', 'marker', 'value', [['app_login', 'SELECT', True]]]]
        access.validate(plan, 'n8n')
        script = access.restore_sql(plan, plan, 'n8n')
        self.assertIn('GRANT SELECT ("value") ON TABLE "public"."marker" TO "app_login" WITH GRANT OPTION;', script)
        self.assertNotIn('GRANT SELECT ON TABLE "public"."marker" TO "app_login";', script)
