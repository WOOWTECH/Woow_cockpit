"""Helper commands for uploaded Home Assistant backups (CONTRACT section 7): `upload-finish` -> `{ha_backup}`, `list`
-> `ha_backups`, `ha-delete`. Teams E1/E2."""
import contextlib
import io
import os
import types
import unittest
from pathlib import Path

from woowbackup import cli, flows, hastore, jobs
from woowbackup.storage import Storage

from . import hafixtures as hx
from .test_archive import fake_archive_bytes
from .test_cli import CliCase

HA_META_KEYS = set(hastore.SIDECAR_KEYS) | {'importable_apps', 'other_addons'}
GIB = 1024 ** 3


class HaCliCase(CliCase):
    """CliCase with the real Storage (uploads and the HA store on the temp layout)."""

    def setUp(self):
        super().setUp()
        self.storage = Storage(self.paths, free_space=lambda path: 100 * GIB)
        self.storage.ensure_layout()
        self.audit = []
        self.deps = flows.Deps(storage=self.storage, keys=self.keys, archive=self.archive,
                               load_catalog=lambda: self.catalog, adapter_factory=self.world.factory,
                               host_info=self.deps.host_info, audit=self.audit.append)

    def upload(self, data, filename='WOOW匯入測試.tar'):
        begin = self.call(['upload-begin'], {'filename': filename, 'size': len(data)})
        Path(begin['path']).write_bytes(data)
        return begin, self.call(['upload-finish'], {'upload_id': begin['upload_id']})


class UploadFinishTests(HaCliCase):
    def test_an_ha_file_answers_ha_backup(self):
        data = hx.fixture('v3_gzip.tar').read_bytes()
        begin, reply = self.upload(data)
        self.assertEqual(set(reply), {'ok', 'ha_backup'})
        view = reply['ha_backup']
        self.assertEqual(set(view), HA_META_KEYS)
        self.assertTrue(view['id'].startswith('ha-'))
        self.assertEqual(view['importable_apps'], [
            {'slug': hx.ODOO, 'app_id': 'odoo', 'app_name': 'Odoo 18', 'installed': False},
            {'slug': hx.N8N, 'app_id': 'n8n', 'app_name': 'n8n 工作流程', 'installed': False}])
        self.assertEqual(view['other_addons'], [])
        again = self.call(['upload-finish'], {'upload_id': begin['upload_id']})
        self.assertEqual(again, reply, 'a retry after a page timeout returns the same record')
        self.assertEqual(self.call(['list'])['backups'], [])

    def test_a_cockpit_file_still_answers_backup(self):
        _begin, reply = self.upload(fake_archive_bytes(backup_id='20261101T080000Z-0123abcd'), 'x.woowbackup')
        self.assertEqual(set(reply), {'ok', 'backup'})
        self.assertEqual(reply['backup']['id'], '20261101T080000Z-0123abcd')

    def test_a_broken_ha_file(self):
        begin, reply = self.upload(hx.simple_backup(protected='yes'))
        self.assertEqual(reply['error']['code'], 'corrupt-archive')
        self.assertEqual(reply['error']['message'], 'HA 備份檔已損毀或遭到修改，無法使用。')
        self.assertEqual(self.call(['upload-abort'], {'upload_id': begin['upload_id']}), {'ok': True})


class ListTests(HaCliCase):
    def test_list_carries_ha_backups(self):
        self.assertEqual(self.call(['list'])['ha_backups'], [])
        _begin, first = self.upload(hx.simple_backup(date='2026-11-01T00:00:00+00:00', slug='0ld00001'))
        _begin, second = self.upload(hx.fixture('plain_gzip.tar').read_bytes())
        listed = self.call(['list'])['ha_backups']
        self.assertEqual([item['id'] for item in listed], [second['ha_backup']['id'], first['ha_backup']['id']])
        self.assertTrue(all(set(item) == HA_META_KEYS for item in listed))
        self.catalog['odoo'] = types.SimpleNamespace(id='odoo', name='Odoo 18（這台）')
        apps = self.call(['list'])['ha_backups'][0]['importable_apps']
        self.assertEqual([(a['app_id'], a['app_name'], a['installed']) for a in apps],
                         [('odoo', 'Odoo 18（這台）', True), ('n8n', 'n8n 工作流程', False)])

    def test_a_broken_ha_store_never_breaks_the_list(self):
        root = Path(self.paths.data) / 'ha-backups'
        root.symlink_to(Path(self.tmp.name))
        with contextlib.redirect_stderr(io.StringIO()):
            reply = self.call(['list'])
        self.assertEqual((reply['ok'], reply['ha_backups'], reply['backups']), (True, [], []))


class HaDeleteTests(HaCliCase):
    def test_validation(self):
        valid = 'ha-' + '0' * 20
        for request in ({}, {'ha_backup_id': valid}, {'ha_backup_id': valid, 'confirm': False},
                        {'ha_backup_id': 'ha-xyz', 'confirm': True}, {'ha_backup_id': '../x', 'confirm': True},
                        {'ha_backup_id': valid, 'confirm': True, 'force': True}):
            with self.subTest(request=request):
                self.assertEqual(self.error_code(['ha-delete'], request), 'invalid-request')
        self.assertEqual(self.error_code(['ha-delete'], {'ha_backup_id': valid, 'confirm': True}), 'not-found')

    def test_delete_refuses_while_a_job_reads_it_and_is_journaled(self):
        _begin, reply = self.upload(hx.simple_backup())
        ha_id = reply['ha_backup']['id']
        store = jobs.JobStore(self.paths)
        record = store.create('verify', {'source': 'ha', 'ha_backup_id': ha_id, 'apps': ['odoo'],
                                         'key_provided': True}, request_id='req-ha-000001')
        record['state'] = 'running'
        store.save(record)
        self.active_units.add(record['unit'])
        response = self.call(['ha-delete'], {'ha_backup_id': ha_id, 'confirm': True})
        self.assertEqual((response['error']['code'], response['error']['details']['job_id']), ('busy', record['id']))
        self.assertEqual(len(self.call(['list'])['ha_backups']), 1)
        record['state'] = 'failed'
        store.save(record)
        self.assertEqual(self.call(['ha-delete'], {'ha_backup_id': ha_id, 'confirm': True}), {'ok': True})
        self.assertEqual(self.call(['list'])['ha_backups'], [])
        self.assertEqual(os.listdir(Path(self.paths.data) / 'ha-backups'), [])
        self.assertTrue(any(line.startswith(f'ha-backup-delete ha_backup={ha_id} ') for line in self.audit), self.audit)
        self.assertEqual(self.error_code(['ha-delete'], {'ha_backup_id': ha_id, 'confirm': True}), 'not-found')

    def test_the_command_is_in_the_specs(self):
        self.assertIn('ha-delete', cli.COMMANDS)
        self.assertEqual(set(cli.SPECS['ha-delete']), {'ha_backup_id', 'confirm'})


if __name__ == '__main__':
    unittest.main()
