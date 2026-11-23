"""The lab compatibility entries of the internal candidate (2026-11-20..23) now run exactly the product conversion,
whose protections hold whoever calls it (B1-01: the public guard was removed by the owner's decision of 2026-11-23
together with this change); request fields can neither select another converter nor skip a check."""
from unittest import mock

from woowbackup import cli, haimport
from woowbackup import ha_omnigent as omni
from woowbackup.errors import BackupError
from .test_ha_omnigent import OmnigentCase, World, HASH, BUNDLE

COLUMNS = [['users', 'id', 'text', True, '', ''], ['scheduled_tasks', 'state', 'integer', True, '', '']]


class CandidateWorld(World):
    mismatch = False

    def __init__(self):
        super().__init__()
        self.ha_columns, self.live_columns = list(COLUMNS), list(COLUMNS)

    def answer(self, role, sql, database):
        if sql == omni.SCHEMA_COLUMNS_SQL and role == 'omni-db' and self.mismatch:
            return COLUMNS + [['users', 'extra', 'integer', False, '', '']]
        return super().answer(role, sql, database)


class CandidateFlowTests(OmnigentCase):
    world_class = CandidateWorld

    def synthetic_snapshot(self, work, app, target, path, expected_alembic):
        self.assertEqual(expected_alembic, self.world.live_alembic)
        path.write_bytes(b'synthetic-trusted-schema-archive')
        return COLUMNS

    def run_candidate(self, **kwargs):
        params = {'source': 'ha', 'ha_backup_id': self.upload_omnigent(), 'apps': ['omnigent'],
                  'encrypt': True, 'test_mode': False, **kwargs}
        with mock.patch.object(omni, 'capture_consistent_target_schema', self.synthetic_snapshot):
            return haimport._run_omnigent_candidate(self.ctx(), params, schema_ddl_quiesced=True)

    def test_full_synthetic_backup_candidate(self):
        result = self.run_candidate(test_mode=True)
        self.assertEqual(result['ha_import']['apps'], ['omnigent'])
        self.assertEqual(sorted(self.world.volume_data),
                         ['omnigent-pi-data', 'omnigent-postgres-data', 'omnigent-server-data'])
        self.assertIn('PG_VERSION', self.volume('omnigent-postgres-data'))
        self.assertIn('artifacts/' + BUNDLE, self.volume('omnigent-server-data'))
        self.assertEqual(self.volume('omnigent-pi-data')['auth.json'][1], b'pi-login')
        commands = [cmd for role, cmd, _data in self.world.execs if role == 'omni-db']
        restore = [cmd for cmd in commands if cmd[0] == 'pg_restore' and '-U' in cmd]
        self.assertEqual(len(restore), 3)
        self.assertIn('--section=pre-data', restore[0])
        self.assertEqual(restore[1][restore[1].index('-U') + 1], omni.RESTORE_ROLE)
        self.assertIn('--section=post-data', restore[2])
        self.assertEqual([row['id'] for row in self.world.carried()], ['admin', 'operator'])
        self.assertNotIn(HASH, '\n'.join(self.reporter.logs))

    def test_the_compatibility_entry_is_the_product_conversion(self):
        with mock.patch.object(omni, 'convert', side_effect=BackupError('incompatible', 'product path')) as product:
            with self.assertRaises(BackupError) as caught:
                self.run_candidate()
        self.assertEqual(caught.exception.message, 'product path')
        product.assert_called_once()

    def test_same_alembic_but_different_columns_is_rejected_before_data(self):
        self.world.mismatch = True
        with self.assertRaises(BackupError) as caught:
            self.run_candidate()
        self.assertIn('欄位結構不同', caught.exception.message)
        self.assertFalse(any(role == 'omni-db' and cmd[0] == 'pg_restore' and
                             '-U' in cmd and omni.RESTORE_ROLE in cmd
                             for role, cmd, _data in self.world.execs))
        self.assertEqual(self.storage.list_backups(), [])

    def test_invalid_revision_rejected_before_capture(self):
        with self.assertRaises(BackupError):
            omni.capture_consistent_target_schema(mock.Mock(), self.catalog['omnigent'], None, None, ['bad;sql'])

    def test_candidate_requires_ddl_quiescence(self):
        with self.assertRaises(BackupError) as caught:
            omni._convert_candidate(mock.Mock(), self.catalog['omnigent'], False, None, schema_ddl_quiesced=False)
        self.assertIn('結構變更', caught.exception.message)

    def test_private_entry_rejects_truthy_quiescence_and_mixed_apps(self):
        for apps, guarantee in [(['omnigent'], False), (['omnigent'], 1),
                                (['omnigent'], 'yes'), (['omnigent', 'emqx'], True)]:
            with self.subTest(apps=apps, guarantee=guarantee), self.assertRaises(BackupError):
                haimport._run_omnigent_candidate(self.ctx(), {'apps': apps},
                                                 schema_ddl_quiesced=guarantee)
        self.assertEqual(self.world.runs, [])
        self.assertEqual(self.storage.list_backups(), [])

    def test_unregistered_quadlet_secret_refuses_before_conversion(self):
        for declarations in [[], [{'name': 'omnigent-postgres-password'}],
                             [{'name': 'omnigent-postgres-password'}] * 2]:
            self.catalog['omnigent'].secrets = declarations
            with self.subTest(declarations=declarations), self.assertRaises(BackupError) as caught:
                haimport._run_omnigent_candidate(self.ctx(), {
                    'apps': ['omnigent'], 'ha_backup_id': self.upload_omnigent()},
                    schema_ddl_quiesced=True)
            self.assertIn('機密未完整登記', caught.exception.message)
        self.assertEqual(self.world.runs, [])
        self.assertEqual(self.storage.list_backups(), [])

    def test_request_fields_cannot_select_a_converter_or_skip_a_check(self):
        # The helper refuses such fields before any job exists ...
        base = {'ha_backup_id': 'ha-' + 'a' * 20, 'apps': ['omnigent'], 'test_mode': False,
                'request_id': 'req-00000001', 'confirm': True}
        for field, value in (('schema_ddl_quiesced', True), ('omnigent_candidate', 'omnigent'),
                             ('trusted_schema', False)):
            with self.subTest(field=field), self.assertRaises(BackupError) as caught:
                cli.validate('ha-convert-start', dict(base, **{field: value}))
            self.assertEqual(caught.exception.code, 'invalid-request')
        # ... and a job's params carrying them still run the one product path with every check.
        backup_id = self.upload_omnigent()
        self.world.ha_columns = self.world.ha_columns + [['users', 'extra', 'integer', False, '', '']]
        for test_mode in (False, True):
            for selector in (True, 'omnigent', {'enabled': True}):
                with self.subTest(test_mode=test_mode, selector=selector):
                    with self.assertRaises(BackupError) as caught:
                        self.convert(backup_id, ['omnigent'], test_mode=test_mode,
                                     schema_ddl_quiesced=True, omnigent_candidate=selector)
                    self.assertEqual(caught.exception.code, 'incompatible')
                    self.assertIn('資料庫結構不同', caught.exception.message)
        self.assertFalse([cmd for role, cmd, _d in self.world.execs if role == 'omni-db' and cmd[0] == 'pg_restore'
                          and omni.RESTORE_ROLE in cmd])
        self.assertEqual(self.storage.list_backups(), [])
