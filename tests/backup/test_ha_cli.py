"""Helper commands for uploaded Home Assistant backups (CONTRACT section 7): `upload-finish` -> `{ha_backup}`, `list`
-> `ha_backups`, `ha-delete`. Teams E1/E2."""
import contextlib
import io
import json
import os
import types
import unittest
from pathlib import Path

from woowbackup import cli, flows, haimport, hastore, jobs
from woowbackup.storage import Storage

from . import hafixtures as hx
from .test_archive import fake_archive_bytes
from .test_cli import CliCase
from .test_flows import FakeKeys

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



class HaJobStartTests(HaCliCase):
    """ha-check-start / ha-convert-start (part B): validation, keys before a job starts, job params."""

    def setUp(self):
        super().setUp()
        self.catalog['odoo'] = types.SimpleNamespace(id='odoo', name='Odoo 18')
        self.catalog['n8n'] = types.SimpleNamespace(id='n8n', name='n8n 工作流程')

    def two_addons(self):
        n8n = hx.addon_member('woow-n8n', image='ghcr.io/woowtech/woow-ha-n8n-amd64')
        _begin, reply = self.upload(hx.outer_bytes([(f'{hx.ODOO}.tar.gz', hx.addon_member()),
                                                    (f'{hx.N8N}.tar.gz', n8n)], hx.ha_doc(addons=(hx.ODOO, hx.N8N))))
        return reply['ha_backup']['id']

    def record(self, job_id):
        return jobs.JobStore(self.paths).get(job_id)

    def test_specs_and_validation(self):
        self.assertEqual(set(cli.SPECS['ha-check-start']), {'ha_backup_id', 'apps', 'request_id', 'key'})
        self.assertEqual(set(cli.SPECS['ha-convert-start']), {'ha_backup_id', 'apps', 'test_mode', 'request_id',
                                                              'confirm', 'odoo_database', 'key'})
        valid = 'ha-' + '0' * 20
        base = {'ha_backup_id': valid, 'apps': ['odoo'], 'request_id': 'req-ha-check-1'}
        for request in ({**base, 'apps': ['wordpress']}, {**base, 'apps': ['odoo', 'odoo']}, {**base, 'apps': []},
                        {**base, 'extra': 1}, {'ha_backup_id': valid, 'apps': ['odoo']}, {**base, 'key': ''}):
            with self.subTest(request=request):
                self.assertEqual(self.error_code(['ha-check-start'], request), 'invalid-request')
        self.assertEqual(self.error_code(['ha-check-start'], base), 'not-found')
        convert = {**base, 'test_mode': False, 'confirm': True}
        for request in ({**convert, 'confirm': False}, {k: v for k, v in convert.items() if k != 'test_mode'},
                        {**convert, 'odoo_database': '../x'}, {**convert, 'test_mode': 'no'}):
            with self.subTest(request=request):
                self.assertEqual(self.error_code(['ha-convert-start'], request), 'invalid-request')

    def test_check_start_params_and_the_selected_addons(self):
        _begin, reply = self.upload(hx.simple_backup())
        ha_id = reply['ha_backup']['id']
        response = self.call(['ha-check-start'], {'ha_backup_id': ha_id, 'apps': ['odoo'],
                                                  'request_id': 'req-ha-check-2', 'key': 'NOT-NEEDED'})
        record = self.record(response['job_id'])
        self.assertEqual((record['type'], record['params']), ('verify', {
            'source': 'ha', 'ha_backup_id': ha_id, 'apps': ['odoo'], 'key_provided': False}))
        self.assertEqual([p['label'] for p in record['phases']], ['準備', '解開 HA 備份', '檢查內容與版本'])
        self.assertFalse(jobs.JobStore(self.paths).key_path(response['job_id']).exists(), 'nothing to decrypt')
        self.assertEqual(self.launched, [response['job_id']])
        reply = self.call(['ha-check-start'], {'ha_backup_id': ha_id, 'apps': ['n8n'], 'request_id': 'req-ha-check-3'})
        self.assertEqual(reply['error']['code'], 'invalid-request')

    @hx.needs_crypto
    def test_keys_are_checked_before_a_job_starts(self):
        _begin, reply = self.upload(hx.fixture('v3_gzip.tar').read_bytes())
        ha_id = reply['ha_backup']['id']
        request = {'ha_backup_id': ha_id, 'apps': ['odoo', 'n8n'], 'request_id': 'req-ha-check-4'}
        self.assertEqual(self.error_code(['ha-check-start'], request), 'key-required')
        wrong = self.call(['ha-check-start'], {**request, 'key': hx.WRONG_PASSWORD})
        self.assertEqual((wrong['error']['code'], wrong['error']['message']),
                         ('wrong-key', 'HA 備份金鑰不正確，請確認後再試一次。'))
        self.assertEqual(self.launched, [])
        response = self.call(['ha-check-start'], {**request, 'key': hx.PASSWORD})
        path = jobs.JobStore(self.paths).key_path(response['job_id'])
        self.assertEqual(path.read_bytes(), hx.PASSWORD.encode('utf-8'))
        self.assertTrue(self.record(response['job_id'])['params']['key_provided'])
        self.assertNotIn(hx.PASSWORD, json.dumps(self.record(response['job_id'])))

    def test_convert_start(self):
        ha_id = self.two_addons()
        base = {'ha_backup_id': ha_id, 'request_id': 'req-ha-conv-1', 'test_mode': True, 'confirm': True}
        reply = self.call(['ha-convert-start'], {**base, 'apps': ['odoo']})
        self.assertEqual((reply['error']['code'], reply['error']['details']['field']),
                         ('invalid-request', 'odoo_database'))
        response = self.call(['ha-convert-start'], {**base, 'apps': ['odoo', 'n8n'], 'odoo_database': 'woowtest'})
        record = self.record(response['job_id'])
        self.assertEqual((record['type'], record['params']), ('backup', {
            'source': 'ha', 'ha_backup_id': ha_id, 'apps': ['odoo', 'n8n'], 'odoo_database': 'woowtest',
            'test_mode': True, 'encrypt': True, 'key_provided': False}))
        self.assertEqual([p['id'] for p in record['phases']], ['prepare', 'decrypt', 'convert', 'package', 'verify'])
        again = self.call(['ha-convert-start'], {**base, 'apps': ['odoo', 'n8n'], 'odoo_database': 'woowtest'})
        self.assertEqual((again['job_id'], again['deduplicated']), (response['job_id'], True))

    def test_convert_start_refusals(self):
        ha_id = self.two_addons()
        request = {'ha_backup_id': ha_id, 'apps': ['n8n'], 'request_id': 'req-ha-conv-2', 'test_mode': False,
                   'confirm': True, 'odoo_database': 'ignored'}
        del self.catalog['n8n']
        reply = self.call(['ha-convert-start'], request)
        self.assertEqual((reply['error']['code'], reply['error']['message']),
                         ('app-not-in-catalog', '請先到「應用軟體」安裝同版本的 n8n 工作流程，再匯入。'))
        self.catalog['n8n'] = types.SimpleNamespace(id='n8n', name='n8n 工作流程')
        self.keys.device = None
        self.assertEqual(self.error_code(['ha-convert-start'], request), 'no-device-key')
        self.keys.device = FakeKeys(self.root).device
        response = self.call(['ha-convert-start'], request)
        self.assertIsNone(self.record(response['job_id'])['params']['odoo_database'])


class FromHaTests(HaCliCase):
    def test_list_from_ha_survives_the_ha_file_and_goes_with_the_backup(self):
        backup_id = self.make_backup()
        meta = self.storage.get(backup_id)
        self.assertNotIn('from_ha', self.call(['list'])['backups'][0])
        _begin, reply = self.upload(hx.simple_backup())
        ha_id = reply['ha_backup']['id']
        row = {'ha_backup_id': ha_id, 'name': 'WOOW', 'date': '2026-11-18T09:01:20Z', 'apps': ['odoo'],
               'odoo_database': 'woowtest', 'test_mode': False, 'workflows_to_fix': [], 'reminders': ['x'],
               'addons': [{'app_id': 'odoo', 'slug': hx.ODOO, 'name': 'Woow Odoo 18'}],
               'job_id': 'j20261118T120000Z-0123abcd', 'created': '2026-11-18T12:00:00Z'}
        haimport.register(self.paths, backup_id, row)
        listed = self.call(['list'])['backups'][0]
        self.assertEqual(listed['from_ha'], haimport.view_row(row))
        self.assertEqual(meta['type'], 'manual')
        self.assertEqual(self.call(['ha-delete'], {'ha_backup_id': ha_id, 'confirm': True}), {'ok': True})
        self.assertEqual(self.call(['list'])['backups'][0]['from_ha']['name'], 'WOOW', 'kept without the HA file')
        self.assertEqual(self.call(['delete'], {'backup_id': backup_id}), {'ok': True})
        self.assertEqual(haimport.load_registry(self.paths), {})

    def register(self, backup_id):
        _begin, reply = self.upload(hx.simple_backup())
        row = {'ha_backup_id': reply['ha_backup']['id'], 'name': 'WOOW', 'date': '2026-11-18T09:01:20Z',
               'apps': ['odoo'], 'odoo_database': 'woowtest', 'test_mode': False, 'workflows_to_fix': [],
               'reminders': [], 'addons': [], 'job_id': 'j20261118T120000Z-0123abcd',
               'created': '2026-11-18T12:00:00Z'}
        haimport.register(self.paths, backup_id, row)
        return haimport.view_row(haimport.clean_row(haimport._upgrade(row)))

    def test_inspect_carries_from_ha_like_list(self):
        backup_id = self.make_backup()
        view = self.register(backup_id)
        reply = self.call(['inspect'], {'backup_id': backup_id})
        self.assertEqual(reply['backup']['from_ha'], view, 'review P-01')
        self.assertEqual(reply['backup']['from_ha'], self.call(['list'])['backups'][0]['from_ha'])

    def test_a_converted_backup_is_no_apps_latest_backup_and_its_own_pool(self):
        """Review C-04: it holds HA's data, not this device's."""
        from woowbackup import retention
        converted = self.make_backup()
        before = {app['id']: app['last_backup'] for app in self.call(['status'])['apps']}
        self.register(converted)
        status = self.call(['status'])
        after = {app['id']: app['last_backup'] for app in status['apps']}
        self.assertTrue(any(value and value['id'] == converted for value in before.values()))
        self.assertFalse(any(value and value['id'] == converted for value in after.values()))
        usage = {row['id']: row['types'] for row in status['storage']['apps']}
        self.assertTrue(any(types['converted'] == 1 and types['manual'] == 0 for types in usage.values()))
        newer = self.make_backup()
        backups = self.storage.list_backups()
        ids, readable = retention.converted_ids(self.paths)
        self.assertEqual((ids, readable), (frozenset({converted}), True))
        policy = {'default_keep_last': 1, 'apps': {}}
        self.assertEqual(len(retention.plan(backups, policy, {}, scheduled=frozenset())['candidates']), 1,
                         'counted as manual, one of the two would be deleted')
        self.assertEqual(retention.plan(backups, policy, {}, scheduled=frozenset(), converted=ids)['candidates'], [])
        self.assertTrue(newer)
        haimport.registry_path(self.paths).write_text('not json')
        listed = [{'id': '20261118T120001Z-0123abcd', 'type': 'manual', 'note': haimport.NOTE_PREFIX + 'WOOW'},
                  {'id': '20261118T120002Z-0123abcd', 'type': 'manual', 'note': ''}]
        self.assertEqual(sorted(retention.protected_backups(self.paths, listed)), ['20261118T120001Z-0123abcd'])

    def test_status_counts_ha_backups(self):
        data = hx.simple_backup()
        self.upload(data)
        storage = self.call(['status'])['storage']
        self.assertEqual((storage['ha_backup_count'], storage['ha_backups_bytes']), (1, len(data)))


if __name__ == '__main__':
    unittest.main()
