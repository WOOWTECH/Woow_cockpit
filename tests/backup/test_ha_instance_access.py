"""Structured instance access: app data objects only, bounded facts and quoted identifiers."""
import copy
import unittest
from types import SimpleNamespace
from unittest import mock

from woowbackup import ha_instance_access as access
from woowbackup import ha_n8n
from woowbackup.adapters.quadlet_postgres import QuadletPostgresAdapter
from woowbackup.errors import BackupError
from .test_adapter_ha_instance import access_plan


class AccessPlanTests(unittest.TestCase):
    def test_endpoint_lifecycle_finishes_before_restore_and_on_error_or_cancel(self):
        from .test_adapter import QUADLETS
        sources = dict(QUADLETS)
        sources['woowbk-demo-app.container'] += b'Network=woowbk-demo.network\n'
        runner = SimpleNamespace(owner='appowner', uid=1000, home='/home/appowner')
        app = SimpleNamespace(id='n8n')
        adapter = QuadletPostgresAdapter(app, runner, lambda _line: None)
        pg = {'container': 'woowbk-demo-db'}
        for failure in (None, 'job-failed', 'cancelled'):
            state, temps = {'running': False}, []
            def prepare(work, current, *, quadlets):
                self.assertIs(current, app)
                self.assertIs(quadlets, sources)
                temp = work.temp(app)
                temps.append(temp)
                temp.put_back_later('main', lambda: state.update(running=False))
                state['running'] = True
                if failure:
                    raise BackupError(failure, 'bounded failure')
                return {'database': 'notes', 'user': 'app', 'host': 'woowbk-demo-db', 'port': 5432}
            with mock.patch.object(ha_n8n, 'prepare_app_endpoint', prepare, create=True), \
                    mock.patch.object(ha_n8n, 'main_container', return_value='woowbk-demo-app', create=True):
                if failure:
                    with self.assertRaises(BackupError) as caught:
                        adapter._read_ha_app_connection(pg, sources)
                    self.assertEqual(caught.exception.code, failure)
                else:
                    self.assertEqual(adapter._read_ha_app_connection(pg, sources)['database'], 'notes')
            self.assertFalse(state['running'], 'scoped cleanup already completed')
            state['running'] = True  # ordinary restore has now started the restored application
            self.assertEqual(temps[0].cleanup(), [])
            self.assertTrue(state['running'], 'no deferred callback may stop the restored application')

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

    def test_password_rotation_only_masks_known_password_components(self):
        pairs = [(b'DB_POSTGRESDB_PASSWORD=old\nDB_POSTGRESDB_DATABASE=notes\n',
                  b'DB_POSTGRESDB_PASSWORD=new\nDB_POSTGRESDB_DATABASE=notes\n'),
                 (b'DATABASE_URL=postgresql://app:old@pg:5432/litellm\n',
                  b'DATABASE_URL=postgresql://app:new@pg:5432/litellm\n')]
        for before, after in pairs:
            self.assertTrue(access.password_only_change(before, after))
            self.assertFalse(access.password_only_change(before, after.replace(b'notes', b'other').replace(b'/litellm', b'/other')))
        self.assertFalse(access.password_only_change(b'UNKNOWN_PASSWORD=old\n', b'UNKNOWN_PASSWORD=new\n'))
        self.assertFalse(access.password_only_change(b'DATABASE_URL=postgresql://app:pw@pg/litellm\n',
                                                    b'DATABASE_URL=postgresql://app:pw@other/litellm\n'))

    def test_backend_binding_refuses_an_equally_named_foreign_database(self):
        from .test_adapter import QUADLETS
        quadlets = dict(QUADLETS)
        quadlets['woowbk-demo-app.container'] += b'Network=woowbk-demo.network\n'
        postgres = {'container': 'woowbk-demo-db'}
        self.assertTrue(access.local_backend({'host': 'woowbk-demo-db', 'port': 5432}, quadlets,
                                            'woowbk-demo-app.container', postgres))
        self.assertFalse(access.local_backend({'host': 'foreign-db', 'port': 5432}, quadlets,
                                             'woowbk-demo-app.container', postgres))
