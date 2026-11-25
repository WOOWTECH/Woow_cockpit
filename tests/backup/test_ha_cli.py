"""Helper commands for uploaded Home Assistant backups (CONTRACT section 7): `upload-finish` -> `{ha_backup}`, `list`
-> `ha_backups`, `ha-delete`. Teams E1/E2."""
import contextlib
import io
import json
import os
import types
import unittest
from pathlib import Path
from unittest import mock

from woowbackup import cli, flows, ha_odoo, haapps, haimport, haissues, hastore, jobs
from woowbackup.errors import BackupError
from woowbackup.haissues import Issue
from woowbackup.storage import Storage

from . import hafixtures as hx
from .test_archive import fake_archive_bytes
from .test_cli import CliCase
from .test_flows import FakeAdapter, FakeKeys, FakeReporter

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

    def test_a_file_name_is_only_shown(self):
        """X-UP-01: blank, long or with control characters, the upload begins and the record's name is clean."""
        data = hx.simple_backup()
        for filename, shown in (('', None), ('\n', None), ('a\nb\u202e.tar', 'a b .tar'), ('x' * 300, None)):
            with self.subTest(filename=filename[:10]):
                _begin, reply = self.upload(data + bytes(len(filename)), filename)
                name = reply['ha_backup']['filename']
                self.assertEqual(name, shown or name)
                self.assertTrue(name.isprintable() and 1 <= len(name) <= 255)
        for bad in (5, None, ['x'], 'a/b.tar', 'a\\b.tar'):
            self.assertEqual(self.call(['upload-begin'], {'filename': bad, 'size': 1000})['error']['code'], 'invalid-request')

    def test_a_cockpit_file_still_answers_backup(self):
        _begin, reply = self.upload(fake_archive_bytes(backup_id='20261101T080000Z-0123abcd'), 'x.woowbackup')
        self.assertEqual(set(reply), {'ok', 'backup'})
        self.assertEqual(reply['backup']['id'], '20261101T080000Z-0123abcd')

    def test_a_broken_ha_file(self):
        begin, reply = self.upload(hx.simple_backup(version=99))
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
        self.assertEqual(set(cli.SPECS['ha-check-start']), {'ha_backup_id', 'apps', 'request_id', 'key', 'choices'})
        self.assertEqual(set(cli.SPECS['ha-convert-start']), {'ha_backup_id', 'apps', 'test_mode', 'request_id',
                                                              'confirm', 'odoo_database', 'key', 'acknowledged',
                                                              'choices'})
        valid = 'ha-' + '0' * 20
        base = {'ha_backup_id': valid, 'apps': ['odoo'], 'request_id': 'req-ha-check-1'}
        for request in ({**base, 'apps': ['wordpress']}, {**base, 'apps': ['odoo', 'odoo']}, {**base, 'apps': []},
                        {**base, 'extra': 1}, {'ha_backup_id': valid, 'apps': ['odoo']}, {**base, 'key': ''}):
            with self.subTest(request=request):
                self.assertEqual(self.error_code(['ha-check-start'], request), 'invalid-request')
        self.assertEqual(self.error_code(['ha-check-start'], base), 'not-found')
        convert = {**base, 'test_mode': False, 'confirm': True}
        for request in ({**convert, 'confirm': False}, {k: v for k, v in convert.items() if k != 'test_mode'},
                        {**convert, 'odoo_database': 'a\nb'}, {**convert, 'odoo_database': 'x' * 64},
                        {**convert, 'test_mode': 'no'}, {**convert, 'acknowledged': []}, {**convert, 'choices': []}):
            with self.subTest(request=request):
                self.assertEqual(self.error_code(['ha-convert-start'], request), 'invalid-request')

    def test_choices_and_acknowledged_are_checked_strictly(self):
        self.catalog['emqx'] = types.SimpleNamespace(id='emqx', name='EMQX')
        base = {'ha_backup_id': 'ha-' + '0' * 20, 'apps': ['odoo', 'emqx', 'n8n'], 'request_id': 'req-ha-choice-1',
                'test_mode': False, 'confirm': True}
        key = 'emqx.no-authentication:1f0c52ab9d3e4f60'
        good = ({'odoo': {'database': '客戶 a$b'}}, {'emqx': {'node': 'emqx@ha.local'}}, {'n8n': {'addon': 'a1_woow-n8n'}},
                {'odoo': {'database': 'x', 'addon': 'local_odoo18ce'}}, {'odoo': {}}, {})
        for choices in good:
            with self.subTest(choices=choices):
                self.assertEqual(self.error_code(['ha-convert-start'], {**base, 'choices': choices}), 'not-found')
                self.assertEqual(self.error_code(['ha-check-start'], {'ha_backup_id': base['ha_backup_id'], 'apps': [
                    'odoo'], 'request_id': 'req-ha-choice-2', 'choices': choices}), 'not-found')
        for choices in ({'wordpress': {}}, {'odoo': 'x'}, {'odoo': {'node': 'a@b'}}, {'n8n': {'database': 'x'}},
                        {'emqx': {'node': 'emqx'}}, {'emqx': {'node': 'emqx@ha local'}}, {'emqx': {'node': '-x@y\n'}},
                        {'odoo': {'database': ''}}, {'odoo': {'database': 5}}, {'n8n': {'addon': '../x'}},
                        {'n8n': {'addon': None}}, {'odoo': {'volume': 'x'}}, 'x'):
            with self.subTest(choices=choices):
                self.assertEqual(self.error_code(['ha-convert-start'], {**base, 'choices': choices}), 'invalid-request')
        for acknowledged in ({'emqx': [key]}, {'_shared': [key], 'odoo': []}, {}):
            with self.subTest(acknowledged=acknowledged):
                self.assertEqual(self.error_code(['ha-convert-start'], {**base, 'acknowledged': acknowledged}),
                                 'not-found')
        many = [f'emqx.no-authentication:{i:016x}' for i in range(haissues.MAX_ACKNOWLEDGED + 1)]
        self.assertEqual(self.error_code(['ha-convert-start'], {**base, 'acknowledged': {'emqx': many[:-1]}}),
                         'not-found')
        for acknowledged in ({'emqx': many}, {'emqx': [key, key]}, {'emqx': key}, {'emqx': ['x']}, {'EMQX': [key]},
                             {'emqx': [key + '0']}, {'emqx': [5]}, 'x', None):
            with self.subTest(acknowledged=str(acknowledged)[:60]):
                self.assertEqual(self.error_code(['ha-convert-start'], {**base, 'acknowledged': acknowledged}),
                                 'invalid-request')

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
        self.assertEqual(reply['error']['code'], 'invalid-request', 'the backup holds nothing of the selection')

    def test_an_app_the_backup_does_not_hold_is_only_left_out(self):
        """X-CLI-03, HA-03: it stays in the check (its result says so) while another selected app is there."""
        _begin, reply = self.upload(hx.simple_backup())
        ha_id = reply['ha_backup']['id']
        response = self.call(['ha-check-start'], {'ha_backup_id': ha_id, 'apps': ['n8n', 'odoo', 'hermes'],
                                                  'request_id': 'req-ha-check-5',
                                                  'choices': {'odoo': {'addon': hx.ODOO}}})
        params = self.record(response['job_id'])['params']
        self.assertEqual((params['apps'], params['choices']), (['n8n', 'odoo', 'hermes'], {'odoo': {'addon': hx.ODOO}}))
        for apps in (['n8n'], ['n8n', 'hermes']):
            reply = self.call(['ha-check-start'], {'ha_backup_id': ha_id, 'apps': apps, 'request_id': 'req-ha-check-6'})
            self.assertEqual((reply['error']['code'], reply['error']['details']['app']), ('invalid-request', 'n8n'))
        base = {'ha_backup_id': ha_id, 'test_mode': False, 'confirm': True, 'request_id': 'req-ha-conv-3',
                'odoo_database': 'woowtest'}
        self.catalog['hermes'] = types.SimpleNamespace(id='hermes', name='Hermes')
        self.assertEqual(self.error_code(['ha-convert-start'], {**base, 'apps': ['odoo', 'hermes']}), 'invalid-request',
                         'one job of several apps (the labs) stays as strict as it was')

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
        response = self.call(['ha-convert-start'], {**base, 'apps': ['odoo', 'n8n'], 'odoo_database': 'woowtest'})
        self.assertEqual(set(response), {'ok', 'job_id', 'deduplicated', 'key_created'})
        self.assertFalse(response['key_created'])
        record = self.record(response['job_id'])
        self.assertEqual((record['type'], record['params']), ('backup', {
            'source': 'ha', 'ha_backup_id': ha_id, 'apps': ['odoo', 'n8n'], 'odoo_database': 'woowtest',
            'test_mode': True, 'encrypt': True, 'key_provided': False}))
        self.assertEqual([p['id'] for p in record['phases']], ['prepare', 'decrypt', 'convert', 'package', 'verify'])
        again = self.call(['ha-convert-start'], {**base, 'apps': ['odoo', 'n8n'], 'odoo_database': 'woowtest'})
        self.assertEqual((again['job_id'], again['deduplicated']), (response['job_id'], True))

    def test_convert_start_without_a_database_lets_the_job_choose(self):
        """HA-14: the only one that can move; the job says so when there are several."""
        ha_id = self.two_addons()
        base = {'ha_backup_id': ha_id, 'test_mode': True, 'confirm': True, 'apps': ['odoo']}
        response = self.call(['ha-convert-start'], {**base, 'request_id': 'req-ha-conv-4'})
        self.assertIsNone(self.record(response['job_id'])['params']['odoo_database'])
        self.finish(response['job_id'])
        key = 'n8n.credentials:1f0c52ab9d3e4f60'
        response = self.call(['ha-convert-start'], {
            **base, 'apps': ['odoo', 'n8n'], 'request_id': 'req-ha-conv-5',
            'choices': {'odoo': {'database': '客戶 a'}, 'emqx': {'node': 'a@b'}},
            'acknowledged': {'n8n': [key], 'odoo': [], 'hermes': [key], '_shared': [key]}})
        params = self.record(response['job_id'])['params']
        self.assertEqual((params['odoo_database'], params['choices'], params['acknowledged']),
                         ('客戶 a', {'odoo': {'database': '客戶 a'}}, {'n8n': [key], '_shared': [key]}))

    def finish(self, job_id):
        store = jobs.JobStore(self.paths)
        record = store.get(job_id)
        record['state'] = 'failed'
        store.save(record)

    def test_convert_start_refusals(self):
        ha_id = self.two_addons()
        request = {'ha_backup_id': ha_id, 'apps': ['n8n'], 'request_id': 'req-ha-conv-2', 'test_mode': False,
                   'confirm': True, 'odoo_database': 'ignored'}
        del self.catalog['n8n']
        reply = self.call(['ha-convert-start'], request)
        self.assertEqual((reply['error']['code'], reply['error']['message']),
                         ('app-not-in-catalog', haimport.INSTALL_HINT.format(name='n8n 工作流程')))
        self.assertNotIn('應用軟體', reply['error']['message'], 'that page installs nothing (DESIGN H-b 16)')
        self.catalog['n8n'] = types.SimpleNamespace(id='n8n', name='n8n 工作流程')
        response = self.call(['ha-convert-start'], request)
        self.assertIsNone(self.record(response['job_id'])['params']['odoo_database'])

    def test_convert_start_creates_the_device_key(self):
        """HA-13 (D11)."""
        ha_id = self.two_addons()
        request = {'ha_backup_id': ha_id, 'apps': ['n8n'], 'request_id': 'req-ha-conv-6', 'test_mode': False,
                   'confirm': True}
        self.keys.device = None
        with mock.patch.object(FakeKeys, 'ensure_device_key', side_effect=BackupError('internal-error', 'x')):
            reply = self.call(['ha-convert-start'], request)
        self.assertEqual(reply['error']['code'], 'no-device-key', 'only when it really cannot be created')
        self.assertEqual(self.launched, [])
        response = self.call(['ha-convert-start'], request)
        self.assertTrue(response['key_created'])
        self.assertEqual([line for line in self.audit if line.startswith('device-key-created ')],
                         [f'device-key-created key_id={self.keys.device.key_id} reason=ha-convert '
                          f'loginuid={cli._login_uid()}'])
        self.assertFalse(cli.key_view(self.keys.device_key())['kit_confirmed'], 'the page keeps asking to download it')


class ShareKeyTests(HaCliCase):
    """KEY-16: one key for the whole backup; an add-on that is not encrypted does not lose the key its share needs."""

    def setUp(self):
        super().setUp()
        for app_id in ('odoo', 'n8n', 'nextcloud', 'woow-code-server'):
            self.catalog[app_id] = types.SimpleNamespace(id=app_id, name=app_id)

    def share_backup(self, share=True, encrypted=True):
        n8n = hx.addon_member('woow-n8n', image='ghcr.io/woowtech/woow-ha-n8n-amd64')
        members = [(f'{hx.ODOO}.tar.gz', hx.addon_member()), (f'{hx.N8N}.tar.gz', n8n)]
        if share:
            data = hx.tar_bytes([{'name': '.', 'type': 'dir'}, {'name': 'odoo_addons', 'type': 'dir'}], compress=True)
            members.append(('share.tar.gz', hx.v3_encrypt(data) if encrypted else data))
        _begin, reply = self.upload(hx.outer_bytes(members, hx.ha_doc(addons=(hx.ODOO, hx.N8N),
                                                                     folders=('share',) if share else ())))
        return reply['ha_backup']['id']

    def start(self, ha_id, apps, request_id, **fields):
        return self.call(['ha-check-start'], {'ha_backup_id': ha_id, 'apps': apps, 'request_id': request_id, **fields})

    def finish(self, job_id):
        store = jobs.JobStore(self.paths)
        record = store.get(job_id)
        record['state'] = 'failed'
        store.save(record)
        return record

    @hx.needs_crypto
    def test_an_encrypted_share_folder_asks_for_the_key_once(self):
        ha_id = self.share_backup()
        reply = self.start(ha_id, ['odoo', 'n8n'], 'req-share-0001')
        self.assertEqual(reply['error']['code'], 'key-required')
        reply = self.start(ha_id, ['odoo'], 'req-share-0002', key=hx.WRONG_PASSWORD)
        self.assertEqual(reply['error']['code'], 'wrong-key')
        self.assertEqual(self.launched, [])
        reply = self.start(ha_id, ['odoo'], 'req-share-0003', key=hx.PASSWORD)
        store = jobs.JobStore(self.paths)
        self.assertEqual(store.key_path(reply['job_id']).read_bytes(), hx.PASSWORD.encode(), 'the key is kept')
        self.assertTrue(self.finish(reply['job_id'])['params']['key_provided'])

    @hx.needs_crypto
    def test_apps_that_do_not_read_it_need_no_key(self):
        reply = self.start(self.share_backup(), ['n8n'], 'req-share-0004', key='NOT-NEEDED')
        self.assertFalse(jobs.JobStore(self.paths).key_path(reply['job_id']).exists())
        self.assertFalse(self.finish(reply['job_id'])['params']['key_provided'])

    def test_a_share_folder_that_is_not_encrypted_needs_none(self):
        for share, encrypted in ((True, False), (False, False)):
            reply = self.start(self.share_backup(share, encrypted), ['odoo'], f'req-share-1{share}', key='NOT-NEEDED')
            self.assertFalse(jobs.JobStore(self.paths).key_path(reply['job_id']).exists())
            self.assertFalse(self.finish(reply['job_id'])['params']['key_provided'])

    @hx.needs_crypto
    def test_the_job_opens_the_share_folder_with_the_key(self):
        """The whole way (stubbed app step): the check reads the encrypted share folder with the key that was kept."""
        ha_id = self.share_backup()
        seen = []

        def check(work, app):
            with work.open(work.share_member()) as stream:
                seen.append(len(stream.read(512)))
            return {'target_version': '18', 'odoo': {'databases': [{'name': 'prod', 'ok': True}]}}

        ctx = flows.FlowContext(self.paths, 'j20261118T120000Z-0123abcd', self.deps, FakeReporter())
        ctx.ha_key = hx.PASSWORD
        self.deps.adapter_factory = lambda app, **_kw: types.SimpleNamespace(
            probe=lambda: {'deployed': True, 'problems': []}, runner=types.SimpleNamespace(home='/nonexistent'), job_id=None)
        with mock.patch.object(ha_odoo, 'check', check), mock.patch.object(ha_odoo, 'check_blockers', lambda f: []), \
                mock.patch.object(flows, 'running_reserve', lambda ctx: 0), \
                mock.patch.object(haimport.SpaceGuard, 'free', lambda guard: 1024 ** 4):
            check_result = flows.run_verify(ctx, {'source': 'ha', 'ha_backup_id': ha_id, 'apps': ['odoo'],
                                                  'key_provided': True})['ha_check']
        self.assertEqual((seen, check_result['apps'][0]['importable']), ([512], True))


class ImportStartTests(HaCliCase):
    """ha-import-start (B4): the request, what is refused before anything starts, the plan and the first job. (The chain
    of the other apps is hachain's.)"""

    KEY = 'n8n.credentials:1f0c52ab9d3e4f60'

    def setUp(self):
        super().setUp()
        for importer in haapps.IMPORTERS:
            self.catalog[importer.app_id] = types.SimpleNamespace(id=importer.app_id, name=importer.name)
        n8n = hx.addon_member('woow-n8n', image='ghcr.io/woowtech/woow-ha-n8n-amd64')
        _begin, reply = self.upload(hx.outer_bytes([(f'{hx.ODOO}.tar.gz', hx.addon_member()),
                                                    (f'{hx.N8N}.tar.gz', n8n)], hx.ha_doc(addons=(hx.ODOO, hx.N8N))))
        self.ha_id = reply['ha_backup']['id']
        self.base = {'ha_backup_id': self.ha_id, 'apps': ['odoo', 'n8n'], 'request_id': 'req-import-0001',
                     'confirm': True, 'test_mode': False, 'then_restore': True, 'overwrite': True}

    def params(self, response):
        return jobs.JobStore(self.paths).get(response['job_id'])['params']

    def test_the_request_is_strict(self):
        self.assertEqual(set(cli.SPECS['ha-import-start']), {
            'ha_backup_id', 'apps', 'request_id', 'confirm', 'test_mode', 'then_restore', 'overwrite', 'acknowledged',
            'choices', 'check_job_id', 'key'})
        for field in ('ha_backup_id', 'apps', 'request_id', 'confirm', 'test_mode', 'then_restore'):
            request = {key: value for key, value in self.base.items() if key != field}
            with self.subTest(missing=field):
                self.assertEqual(self.error_code(['ha-import-start'], request), 'invalid-request')
        for change in ({'confirm': False}, {'extra': 1}, {'apps': ['wordpress']}, {'apps': []}, {'check_job_id': 'x'},
                       {'acknowledged': {'hermes': [self.KEY]}}, {'choices': {'emqx': {'node': 'a@b'}}},
                       {'acknowledged': {'n8n': ['x']}}, {'then_restore': 'yes'}, {'key': ''}, {'odoo_database': 'x'}):
            with self.subTest(change=change):
                self.assertEqual(self.error_code(['ha-import-start'], {**self.base, **change}), 'invalid-request')
        self.assertEqual(self.error_code(['ha-import-start'], {**self.base, 'ha_backup_id': 'ha-' + '0' * 20}),
                         'not-found')
        self.assertEqual(self.launched, [])

    def test_replacing_the_data_needs_an_explicit_yes(self):
        for overwrite in (None, False):
            request = {**self.base, 'overwrite': overwrite}
            if overwrite is None:
                del request['overwrite']
            reply = self.call(['ha-import-start'], request)
            self.assertEqual((reply['error']['code'], reply['error']['details']['field']), ('invalid-request', 'overwrite'))
        response = self.call(['ha-import-start'], {**self.base, 'then_restore': False, 'overwrite': False})
        self.assertFalse(self.params(response)['chain']['then_restore'], 'only converting replaces nothing')

    def test_the_first_job_and_the_plan(self):
        response = self.call(['ha-import-start'], {
            **self.base, 'test_mode': True, 'acknowledged': {'n8n': [self.KEY], '_shared': [], 'odoo': []},
            'choices': {'odoo': {'database': '客戶 a'}}})
        self.assertEqual(set(response), {'ok', 'job_id', 'deduplicated', 'group', 'key_created'})
        self.assertEqual((response['deduplicated'], response['key_created']), (False, False))
        self.assertRegex(response['group'], r'\Ag[0-9a-f]{16}\Z')
        params = self.params(response)
        self.assertEqual({key: params[key] for key in ('source', 'ha_backup_id', 'apps', 'odoo_database', 'test_mode',
                                                       'encrypt', 'key_provided')},
                         {'source': 'ha', 'ha_backup_id': self.ha_id, 'apps': ['odoo'], 'odoo_database': '客戶 a',
                          'test_mode': True, 'encrypt': True, 'key_provided': False})
        self.assertEqual(params['choices'], {'odoo': {'database': '客戶 a'}})
        self.assertNotIn('acknowledged', params, 'nothing was confirmed for the first app')
        self.assertEqual(params['group'], {'id': response['group'], 'index': 0, 'count': 2, 'kind': 'ha-import',
                                           'step': 'convert', 'app_id': 'odoo'})
        self.assertEqual(params['chain'], {
            'apps': ['odoo', 'n8n'], 'test_mode': True, 'then_restore': True, 'encrypt': True, 'key_provided': False,
            'ha_backup_id': self.ha_id, 'acknowledged': {'n8n': [self.KEY]}, 'choices': {'odoo': {'database': '客戶 a'}},
            'results': []})
        record = jobs.JobStore(self.paths).get(response['job_id'])
        self.assertEqual((record['type'], [p['id'] for p in record['phases']]),
                         ('backup', ['prepare', 'decrypt', 'convert', 'package', 'verify']))
        self.assertEqual(self.launched, [response['job_id']])

    def test_the_confirmed_keys_of_the_first_app_are_handed_over(self):
        response = self.call(['ha-import-start'], {**self.base, 'apps': ['n8n', 'odoo'],
                                                   'acknowledged': {'n8n': [self.KEY], '_shared': [self.KEY]}})
        params = self.params(response)
        self.assertEqual((params['apps'], params['acknowledged'], params['odoo_database']),
                         (['n8n'], {'n8n': [self.KEY], '_shared': [self.KEY]}, None))

    def test_a_retry_returns_the_same_import(self):
        first = self.call(['ha-import-start'], self.base)
        again = self.call(['ha-import-start'], self.base)
        self.assertEqual((again['job_id'], again['group'], again['deduplicated']), (first['job_id'], first['group'], True))
        self.assertEqual(sum(1 for line in self.audit if line.startswith('ha-import-confirm')), 0)
        self.assertEqual(self.error_code(['ha-import-start'], {**self.base, 'request_id': 'req-import-0002'}), 'busy')
        store = jobs.JobStore(self.paths)
        record = store.get(first['job_id'])
        record['state'] = 'failed'
        store.save(record)
        other = self.call(['ha-convert-start'], {'ha_backup_id': self.ha_id, 'apps': ['n8n'], 'test_mode': False,
                                                 'confirm': True, 'request_id': 'req-import-0003'})
        self.assertFalse(other['deduplicated'])
        self.assertEqual(self.error_code(['ha-import-start'], {**self.base, 'request_id': 'req-import-0003'}),
                         'invalid-request', 'the id of another kind of job')

    def test_apps_that_cannot_start_are_left_out_with_their_reason(self):
        del self.catalog['odoo']
        response = self.call(['ha-import-start'], {**self.base, 'apps': ['hermes', 'odoo', 'n8n']})
        params = self.params(response)
        self.assertEqual((params['apps'], params['group']['count'], params['chain']['apps']), (['n8n'], 1, ['n8n']))
        rows = {row['app_id']: row for row in params['chain']['results']}
        self.assertEqual(set(rows), {'hermes', 'odoo'})
        for row in rows.values():
            self.assertEqual(set(row), set(haimport.RESULT_KEYS))
            self.assertEqual(row['status'], 'skipped')
        self.assertEqual((rows['hermes']['code'], rows['odoo']['code']), ('not-found', 'app-not-in-catalog'))
        self.assertIn('請在 HA 建立備份時勾選', rows['hermes']['message'])
        self.assertIn('應用設定', rows['odoo']['message'])
        self.assertEqual(haimport._clean_results(params['chain']['results']), params['chain']['results'])

    def test_nothing_left_to_import_is_refused(self):
        self.assertEqual(self.error_code(['ha-import-start'], {**self.base, 'apps': ['hermes', 'emqx']}),
                         'invalid-request')
        del self.catalog['n8n']
        self.assertEqual(self.error_code(['ha-import-start'], {**self.base, 'apps': ['n8n']}), 'app-not-in-catalog')
        self.assertEqual(self.error_code(['ha-import-start'], {**self.base, 'apps': ['hermes', 'n8n']}),
                         'app-not-in-catalog')
        self.assertEqual(self.launched, [])

    @hx.needs_crypto
    def test_keys_are_checked_before_the_import_starts(self):
        _begin, reply = self.upload(hx.fixture('v3_gzip.tar').read_bytes())
        request = {**self.base, 'ha_backup_id': reply['ha_backup']['id']}
        self.keys.device = None
        self.assertEqual(self.error_code(['ha-import-start'], request), 'key-required')
        self.assertEqual(self.error_code(['ha-import-start'], {**request, 'key': hx.WRONG_PASSWORD}), 'wrong-key')
        self.assertIsNone(self.keys.device, 'nothing was created for a refused import')
        response = self.call(['ha-import-start'], {**request, 'key': hx.PASSWORD})
        self.assertTrue(response['key_created'])
        self.assertTrue(self.params(response)['key_provided'])
        record = json.dumps(jobs.JobStore(self.paths).get(response['job_id']))
        self.assertNotIn(hx.PASSWORD, record)

    def test_the_device_key_is_created_only_when_something_is_encrypted(self):
        self.keys.device = None
        self.deps.encrypt_by_default = lambda: False
        response = self.call(['ha-import-start'], self.base)
        self.assertEqual((response['key_created'], self.keys.device, self.params(response)['encrypt']),
                         (False, None, False))

    def test_what_was_confirmed_is_journaled_without_names(self):
        store = jobs.JobStore(self.paths)
        check = store.create('verify', {'source': 'ha', 'ha_backup_id': self.ha_id, 'apps': ['n8n']})
        issue = Issue('n8n.credentials', 'confirm', '憑證要重新輸入', [f'cred{i}' for i in range(25)])
        shared = Issue('shared.pauses', 'confirm', '會暫停', ['filebrowser'])
        check.update(state='succeeded', result={'ha_check': {'schema': 2, 'ha_backup_id': self.ha_id, 'shared': [
            shared.view('_shared')], 'apps': [{'app_id': 'n8n', 'issues': [issue.view('n8n')]}]}})
        store.save(check)
        keys = {'n8n': [issue.key('n8n'), self.KEY], '_shared': [shared.key('_shared')]}
        response = self.call(['ha-import-start'], {**self.base, 'acknowledged': keys, 'check_job_id': check['id']})
        lines = [line for line in self.audit if line.startswith('ha-import-confirm ')]
        head = f'ha-import-confirm ha_backup={self.ha_id} group={response["group"]} '
        uid = cli._login_uid()
        self.assertEqual(lines, [f'{head}app=n8n issue=n8n.credentials items=25 loginuid={uid}',
                                 f'{head}app=n8n issue=n8n.credentials items=- loginuid={uid}',
                                 f'{head}app=_shared issue=shared.pauses items=1 loginuid={uid}'])
        self.assertFalse(any('cred1' in line or 'filebrowser' in line for line in self.audit))
        self.assertNotIn('check_job_id', self.params(response), 'the audit only')

    def run_first_job(self, response, convert):
        """The first job alone in this process (`chain=False`: what follows it is hachain's, tested in test_ha_chain), as its
        unit runs it (stubbed app step and adapter)."""
        from .test_ha_import import HaWorld, app
        world = HaWorld()
        self.deps.adapter_factory = world.factory
        for importer in haapps.IMPORTERS:
            self.catalog[importer.app_id] = app(importer.app_id, importer.name)
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(ha_odoo, 'convert', convert))
            stack.enter_context(mock.patch.object(flows, 'running_reserve', lambda ctx: 0))
            stack.enter_context(mock.patch.object(haimport.SpaceGuard, 'free', lambda guard: 1024 ** 4))
            stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
            return jobs.run_job(self.paths, response['job_id'], deps=self.deps, chain=False)

    def test_the_first_job_runs_and_reports_itself(self):
        key = Issue('odoo.modules', 'confirm', 'x', ['m'], database='客戶 a').key('odoo')
        request = {**self.base, 'choices': {'odoo': {'database': '客戶 a'}}, 'acknowledged': {'odoo': [key]}}
        response = self.call(['ha-import-start'], request)

        def convert(work, app, database, test_mode, out_dir):
            sink = work.sink(app)
            sink.confirm('odoo.modules', '缺少的模組', ['m'], database=database)
            sink.confirm('odoo.modules', '缺少的模組', ['other'], database='test')
            (out_dir / 'volumes').mkdir(parents=True)
            path = out_dir / 'volumes' / 'odoo18-web-data.tar'
            path.write_bytes(b'volume')
            return {'volumes': {'odoo18-web-data': path}, 'database': database, 'custom_modules': [],
                    'left_databases': ['test']}

        record = self.run_first_job(response, convert)
        self.assertEqual((record['state'], record['error']), ('succeeded', None))
        result = record['result']
        self.assertEqual([(row['app_id'], row['status'], [i['id'] for i in row['issues']]) for row in result['results']],
                         [('odoo', 'converted', ['odoo.modules'])])
        self.assertEqual((result['ha_import']['group'], result['ha_import']['odoo_database'],
                          result['ha_import']['left_databases']), (response['group'], '客戶 a', ['test']))
        row = haimport.load_registry(self.paths)[result['backup_id']]
        self.assertEqual(row['confirmed'], [{'app_id': 'odoo', 'id': 'odoo.modules', 'items': ['m']}])
        self.assertEqual(record['params']['chain']['apps'], ['odoo', 'n8n'], 'what the rest of the import needs stays')

    def test_the_first_job_that_fails_reports_itself_in_the_record(self):
        for error, status, code in ((BackupError('corrupt-archive', '讀不出來。'), 'failed', 'corrupt-archive'),
                                    (RuntimeError('x'), 'failed', 'internal-error'),
                                    (BackupError('confirmation-required', 'x'), 'skipped', 'confirmation-required')):
            response = self.call(['ha-import-start'], {**self.base, 'request_id': f'req-import-{code}',
                                                       'choices': {'odoo': {'database': 'prod'}}})
            record = self.run_first_job(response, mock.Mock(side_effect=error))
            self.assertEqual((record['state'], record['error']['code']), ('failed', code))
            row = record['result']['results'][0]
            self.assertEqual((row['app_id'], row['status'], row['code']), ('odoo', status, code))
            self.assertEqual((self.storage.list_backups(), haimport.load_registry(self.paths)), ([], {}))
            self.assertEqual(os.listdir(self.paths.staging), [])

    def test_the_command_is_listed(self):
        self.assertIn('ha-import-start', cli.COMMANDS)


class RestoreKeyTests(HaCliCase):
    """FL-07, X-PF-03 (D11): an in-place restore without a device key creates it instead of refusing."""

    def setUp(self):
        super().setUp()
        self.backup_id = self.make_backup()
        self.request = {'backup_id': self.backup_id, 'apps': ['woowbk-demo'], 'request_id': 'req-restore-0001',
                        'confirm': True}

    def test_the_restore_check_no_longer_refuses(self):
        data = (self.keys.device, self.keys.imported)
        self.keys.imported, self.keys.device = [self.keys.device], None  # the backup's key is here, not as device key
        app = self.call(['inspect'], {'backup_id': self.backup_id})['preflight']['apps'][0]
        check = next(c for c in app['checks'] if c['id'] == 'woowbk-demo/device-key')
        self.assertEqual((app['restorable'], check['status']), (True, 'warn'))
        self.assertIn('自動建立', check['message'])
        self.assertEqual([(i['id'], i['level']) for i in app['issues']], [('restore.device-key', 'auto')])
        self.assertIsNone(self.keys.device, 'the check itself creates nothing')
        self.keys.device, self.keys.imported = data
        app = self.call(['inspect'], {'backup_id': self.backup_id})['preflight']['apps'][0]
        self.assertNotIn('issues', app)
        self.assertFalse(any(c['id'].endswith('/device-key') for c in app['checks']))

    def test_the_restore_creates_the_key(self):
        self.keys.imported, self.keys.device = [self.keys.device], None
        response = self.call(['restore-start'], self.request)
        self.assertTrue(response['key_created'])
        self.assertIsNotNone(self.keys.device)
        self.assertEqual(self.audit[-1], f'device-key-created key_id={self.keys.device.key_id} reason=restore '
                                         f'loginuid={cli._login_uid()}')

    def test_no_key_where_none_is_needed(self):
        self.keys.imported, self.keys.device = [self.keys.device], None
        self.world.mode['woowbk-demo'] = 'fresh'
        self.assertFalse(self.call(['restore-start'], self.request)['key_created'], 'a new deployment has no copy')
        self.assertIsNone(self.keys.device)
        self.assertEqual(self.error_code(['restore-start'], {**self.request, 'request_id': 'req-restore-0002'}), 'busy')

    def test_unencrypted_safety_backups_need_none(self):
        self.keys.imported, self.keys.device = [self.keys.device], None
        self.deps.encrypt_by_default = lambda: False
        self.assertFalse(self.call(['restore-start'], self.request)['key_created'])
        self.assertIsNone(self.keys.device)

    def test_an_app_that_cannot_be_asked_counts_as_there(self):
        self.keys.imported, self.keys.device = [self.keys.device], None
        with mock.patch.object(FakeAdapter, 'detect_mode', side_effect=RuntimeError('x')), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertTrue(self.call(['restore-start'], self.request)['key_created'])

    def test_a_key_that_cannot_be_created_refuses_before_anything_starts(self):
        self.keys.imported, self.keys.device = [self.keys.device], None
        with mock.patch.object(FakeKeys, 'ensure_device_key', side_effect=OSError('x')):
            self.assertEqual(self.error_code(['restore-start'], self.request), 'no-device-key')
        self.assertEqual(self.launched, [])


class RestoreConfirmTests(HaCliCase):
    """B6: lines a restore check wants confirmed (an adapter's `restore_issues`); the request's `acknowledged`."""

    class Adapter(FakeAdapter):
        restore_issues = ()
        found = ()

        def preflight(self, *args, **kwargs):
            checks = super().preflight(*args, **kwargs)
            self.restore_issues = list(self.found)
            return checks

    def setUp(self):
        super().setUp()
        self.backup_id = self.make_backup(('woowbk-demo', 'woowbk-two'))
        self.issue = Issue('restore.device-key', 'confirm', '還原時會先停止。', ['filebrowser'])
        self.Adapter.found = [self.issue, Issue('restore.device-key', 'auto', '自動')]
        self.deps.adapter_factory = lambda app, *, log, phase=None, checkpoint=None, writers_hook=None, \
            imported_hook=None: self.Adapter(app, self.world, log, phase, checkpoint, writers_hook, imported_hook)
        self.request = {'backup_id': self.backup_id, 'apps': ['woowbk-demo'], 'request_id': 'req-restore-0011',
                        'confirm': True}

    def test_inspect_lists_them(self):
        for app in self.call(['inspect'], {'backup_id': self.backup_id})['preflight']['apps']:
            self.assertEqual([i['level'] for i in app['issues']], ['confirm', 'auto'])
            self.assertTrue(app['restorable'], 'a line to confirm does not stop the restore')

    def test_an_unconfirmed_line_refuses_before_anything_starts(self):
        for acknowledged in (None, {}, {'woowbk-two': [self.issue.key('woowbk-demo')]},
                             {'woowbk-demo': [self.issue.key('woowbk-two')]}):
            request = dict(self.request, **({} if acknowledged is None else {'acknowledged': acknowledged}))
            reply = self.call(['restore-start'], request)
            self.assertEqual(reply['error']['code'], 'confirmation-required')
            self.assertEqual(reply['error']['details'], {'apps': {'woowbk-demo': [self.issue.view('woowbk-demo')]}})
        self.assertEqual(self.launched, [])

    def test_a_confirmed_line_starts_and_is_recorded(self):
        keys = {'woowbk-demo': [self.issue.key('woowbk-demo')], 'woowbk-two': []}
        response = self.call(['restore-start'], {**self.request, 'acknowledged': keys})
        params = jobs.JobStore(self.paths).get(response['job_id'])['params']
        self.assertEqual(params['acknowledged'], {'woowbk-demo': keys['woowbk-demo']})

    def test_only_the_lines_of_the_restored_apps_stay_in_the_job_record(self):
        keys = {'woowbk-demo': [self.issue.key('woowbk-demo')], 'woowbk-two': [self.issue.key('woowbk-two')]}
        response = self.call(['restore-start'], {**self.request, 'acknowledged': keys})
        params = jobs.JobStore(self.paths).get(response['job_id'])['params']
        self.assertEqual(params['acknowledged'], {'woowbk-demo': keys['woowbk-demo']},
                         'the keys of an app that is not restored are not kept')

    def test_one_more_name_must_be_confirmed_again(self):
        keys = {'woowbk-demo': [self.issue.key('woowbk-demo')]}
        self.Adapter.found = [Issue('restore.device-key', 'confirm', '還原時會先停止。', ['filebrowser', 'code-server'])]
        self.assertEqual(self.error_code(['restore-start'], {**self.request, 'acknowledged': keys}),
                         'confirmation-required')

    def test_adapters_without_such_lines_are_not_asked(self):
        self.deps.adapter_factory = self.world.factory
        with mock.patch.object(self.archive, 'read_manifest', side_effect=AssertionError('not read')):
            self.assertTrue(self.call(['restore-start'], self.request)['ok'])

    def test_an_adapter_that_cannot_be_made_is_the_jobs_to_report(self):
        def factory(app, **_kwargs):
            raise BackupError('owner-missing', '找不到應用擁有者帳號。')

        self.deps.adapter_factory = factory
        self.assertTrue(self.call(['restore-start'], self.request)['ok'])

    def test_the_lines_are_validated(self):
        for acknowledged in ({'woowbk-demo': ['x']}, {'woowbk-demo': 'x'}, [], {'Bad App': []}):
            self.assertEqual(self.error_code(['restore-start'], {**self.request, 'acknowledged': acknowledged}),
                             'invalid-request')


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
