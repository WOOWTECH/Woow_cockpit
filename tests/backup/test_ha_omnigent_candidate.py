"""Synthetic full conversion exercises the internal candidate; public guard stays intact."""
from unittest import mock

from woowbackup import ha_omnigent as omni
from woowbackup.errors import BackupError
from .test_ha_omnigent import OmnigentCase, World, HASH, BUNDLE

COLUMNS = [['users', 'id', 'text', True, '', ''], ['scheduled_tasks', 'state', 'integer', True, '', '']]


class CandidateWorld(World):
    mismatch = False

    def answer(self, role, sql, database):
        if sql == omni.SCHEMA_COLUMNS_SQL:
            if role == 'omni-db' and self.mismatch:
                return COLUMNS + [['users', 'extra', 'integer', False, '', '']]
            return COLUMNS
        return super().answer(role, sql, database)

    def carried(self):
        if any('json_populate_recordset' in sql for sql in self.executed('omni-db')):
            return [row for row in self.live_rows if row['id'] not in self.ha_users]
        return []


class CandidateFlowTests(OmnigentCase):
    world_class = CandidateWorld

    def synthetic_snapshot(self, work, app, target, path, expected_alembic):
        self.assertEqual(expected_alembic, self.world.live_alembic)
        path.write_bytes(b'synthetic-trusted-schema-archive')
        return COLUMNS

    def run_candidate(self, **kwargs):
        # Test-only routing to the private candidate; no application guard is changed.
        with mock.patch.object(omni, 'convert', lambda *args: omni._convert_candidate(*args, schema_ddl_quiesced=True)), \
             mock.patch.object(omni, 'capture_consistent_target_schema', self.synthetic_snapshot):
            return self.convert(self.upload_omnigent(), ['omnigent'], **kwargs)

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
