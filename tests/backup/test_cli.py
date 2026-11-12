"""CLI contract (CONTRACT section 7): one JSON object on stdout, exit codes, strict stdin, shapes."""
import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

from woowbackup import cli, flows, jobs
from woowbackup.errors import BackupError
from woowbackup.paths import Paths

from .test_flows import (TEST_SECRET, TEST_SECRET_ID, FakeArchive, FakeKeys, FakeReporter, FakeStorage, HOST, World,
                         make_catalog)

APP_KEYS = ['id', 'name', 'description', 'owner', 'adapter', 'deployed', 'state', 'units', 'last_backup', 'problems']
META_KEYS = {'id', 'type', 'created', 'note', 'apps', 'size', 'sha256', 'key_id', 'include_images', 'filename',
             'source', 'verified', 'inspected', 'key_available'}


class ExplodingStdin:
    def read(self, *_args):
        raise AssertionError('stdin must not be read for this command')

    @property
    def buffer(self):
        return self


class CliCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.paths = Paths(base=self.root / 'sys')
        self.storage = FakeStorage(self.root / 'data')
        self.keys = FakeKeys(self.root)
        self.archive = FakeArchive()
        self.world = World()
        self.catalog = make_catalog(self.paths)
        self.deps = flows.Deps(storage=self.storage, keys=self.keys, archive=self.archive,
                               load_catalog=lambda: self.catalog, adapter_factory=self.world.factory,
                               host_info=lambda: dict(HOST))
        self.launched = []
        self.active_units = set()

    def tearDown(self):
        self.tmp.cleanup()

    def services(self):
        return cli.Services(self.paths, deps=self.deps, launcher=self.launched.append,
                            unit_active=lambda unit: unit in self.active_units)

    def call(self, argv, request=None, raw=None, require_root=False):
        out = io.StringIO()
        if raw is not None:
            stdin = io.StringIO(raw)
        elif request is not None:
            stdin = io.StringIO(json.dumps(request))
        else:
            stdin = ExplodingStdin()
        code = cli.main(argv, stdin=stdin, stdout=out, services=self.services(), require_root=require_root)
        text = out.getvalue()
        self.assertTrue(text.endswith('\n'))
        self.assertEqual(text.count('\n'), 1, text)
        response = json.loads(text)
        self.assertIsInstance(response, dict)
        self.assertEqual(code, 0 if response['ok'] else 1)
        if not response['ok']:
            self.assertEqual(set(response['error']), {'code', 'message', 'details'})
            self.assertTrue(response['error']['message'])
        return response

    def error_code(self, argv, request=None, raw=None):
        response = self.call(argv, request, raw)
        self.assertFalse(response['ok'], response)
        return response['error']['code']

    def make_backup(self, apps=('woowbk-demo',)):
        ctx = flows.FlowContext(self.paths, 'j20261113T010000Z-00000001', self.deps, FakeReporter())
        return flows.run_backup(ctx, {'apps': list(apps), 'include_images': False, 'note': ''})['backup_id']


class EnvelopeTests(CliCase):
    def test_requires_root(self):
        if os.geteuid() == 0:
            self.skipTest('running as root')
        response = self.call(['status'], require_root=True)
        self.assertEqual(response['error']['code'], 'permission-denied')

    def test_unknown_command_and_arguments(self):
        self.assertEqual(self.error_code(['nope']), 'invalid-request')
        self.assertEqual(self.error_code([]), 'invalid-request')
        self.assertEqual(self.error_code(['status', 'extra']), 'invalid-request')
        self.assertEqual(self.error_code(['run-job']), 'invalid-request')
        self.assertEqual(self.error_code(['run-job', '../../etc']), 'invalid-request')

    def test_strict_stdin(self):
        big = json.dumps({'backup_id': '20261113T020000Z-a1b2c3d4', 'pad': 'x' * (1024 * 1024)})
        cases = [
            ('download-info', None, big),
            ('download-info', None, '{"backup_id": '),
            ('download-info', None, '["20261113T020000Z-a1b2c3d4"]'),
            ('download-info', None, ''),
            ('download-info', None, '{"backup_id": "20261113T020000Z-a1b2c3d4", "backup_id": "x"}'),
            ('upload-begin', None, '{"filename": "a.woowbackup", "size": NaN}'),
            ('download-info', {'backup_id': '20261113T020000Z-a1b2c3d4', 'path': '/etc/shadow'}, None),
            ('download-info', {}, None),
            ('download-info', {'backup_id': '../../etc/passwd'}, None),
            ('upload-begin', {'filename': 'a.woowbackup', 'size': True}, None),
            ('upload-begin', {'filename': 'a/b.woowbackup', 'size': 10}, None),
            ('backup-start', {'apps': 'woowbk-demo', 'request_id': 'req-00000001'}, None),
            ('backup-start', {'apps': ['woowbk-demo'], 'request_id': 'req-00000001', 'include_images': 'yes'}, None),
            ('backup-start', {'apps': ['woowbk-demo', 'woowbk-demo'], 'request_id': 'req-00000001'}, None),
            ('backup-start', {'apps': ['woowbk-demo'], 'request_id': 'req-00000001', 'note': 'a\nb'}, None),
            ('restore-start', {'backup_id': '20261113T020000Z-a1b2c3d4', 'apps': ['woowbk-demo'],
                               'request_id': 'req-00000001', 'confirm': False}, None),
            ('restore-start', {'backup_id': '20261113T020000Z-a1b2c3d4', 'apps': ['woowbk-demo'],
                               'request_id': 'req-00000001', 'confirm': True, 'save_key': True}, None),
            ('key-confirm', {'key_id': 'abcd-ef01-2345-6789'}, None),
            ('job-status', {'job_id': 'j1'}, None),
        ]
        for command, request, raw in cases:
            with self.subTest(command=command, request=request, raw=(raw or '')[:40]):
                self.assertEqual(self.error_code([command], request, raw), 'invalid-request')

    def test_no_input_commands_do_not_read_stdin(self):
        for command in ('status', 'list', 'jobs', 'key-init'):
            self.assertTrue(self.call([command])['ok'], command)

    def test_internal_error_is_generic_and_traceback_stays_on_stderr(self):
        def broken():
            raise RuntimeError(f'boom detail {TEST_SECRET}')
        self.storage.list_backups = broken
        err = io.StringIO()
        out = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = cli.main(['list'], stdin=ExplodingStdin(), stdout=out, services=self.services(), require_root=False)
        self.assertEqual(code, 1)
        response = json.loads(out.getvalue())
        self.assertEqual(response, {'ok': False, 'error': {'code': 'internal-error', 'message': cli.GENERIC_ERROR,
                                                           'details': {}}})
        self.assertNotIn('Traceback', out.getvalue())
        self.assertNotIn('boom', out.getvalue())
        self.assertIn('Traceback', err.getvalue())

    def test_key_material_never_echoed(self):
        wrong = 'AGE-SECRET-KEY-1' + 'Z' * 58
        backup_id = self.make_backup()
        for command, request in (('key-import', {'key': wrong}),
                                 ('inspect', {'backup_id': backup_id, 'key': wrong})):
            response = self.call([command], request)
            self.assertFalse(response['ok'])
            self.assertNotIn(wrong, json.dumps(response))


class StatusTests(CliCase):
    def test_status_shape(self):
        self.catalog.problems.append({'file': 'bad.json', 'id': None, 'code': 'invalid-request',
                                      'message': 'bad.json：格式不正確。'})
        backup_id = self.make_backup()
        response = self.call(['status'])
        self.assertEqual(set(response), {'ok', 'version', 'host', 'storage', 'key', 'imported_keys', 'apps',
                                         'active_job', 'warnings'})
        self.assertEqual(response['host'], {k: HOST[k] for k in ('hostname', 'arch', 'os', 'podman')})
        self.assertEqual(set(response['storage']), {'path', 'free_bytes', 'total_bytes', 'backups_bytes', 'backup_count'})
        self.assertEqual(response['key'], {'key_id': 'AAAA-BBBB-CCCC-DDDD', 'created': '2026-11-01T00:00:00Z',
                                           'kit_confirmed': False})
        self.assertEqual(response['imported_keys'], [])
        self.assertEqual([list(app) for app in response['apps']], [APP_KEYS, APP_KEYS])
        demo = response['apps'][0]
        self.assertEqual((demo['state'], demo['deployed']), ('running', True))
        self.assertEqual(demo['units'][0], {'name': 'woowbk-demo-db.service', 'active': True})
        self.assertEqual(demo['last_backup']['id'], backup_id)
        self.assertIsNone(response['apps'][1]['last_backup'])
        self.assertIsNone(response['active_job'])
        self.assertEqual(response['warnings'], ['bad.json：格式不正確。'])

    def test_status_reports_app_errors_and_no_key(self):
        self.keys.device = None
        self.world.factory = None

        def factory(app, **kwargs):
            raise BackupError('owner-missing', '找不到應用擁有者帳號 appowner。')

        self.deps.adapter_factory = factory
        response = self.call(['status'])
        self.assertIsNone(response['key'])
        self.assertEqual(response['apps'][0]['state'], 'error')
        self.assertEqual(response['apps'][0]['problems'], ['找不到應用擁有者帳號 appowner。'])

    def test_list_shape(self):
        self.make_backup()
        response = self.call(['list'])
        self.assertEqual(len(response['backups']), 1)
        self.assertEqual(set(response['backups'][0]), META_KEYS)
        self.assertTrue(response['backups'][0]['key_available'])
        self.keys.device = None
        self.assertFalse(self.call(['list'])['backups'][0]['key_available'])


class KeyTests(CliCase):
    def test_key_lifecycle(self):
        self.keys.device = None
        self.assertEqual(self.error_code(['key-kit']), 'no-device-key')
        response = self.call(['key-init'])
        self.assertEqual(response['created'], True)
        self.assertEqual(set(response['key']), {'key_id', 'created', 'kit_confirmed'})
        self.assertEqual(self.call(['key-init'])['created'], False)
        kit = self.call(['key-kit'])
        self.assertEqual(kit['key_id'], 'AAAA-BBBB-CCCC-DDDD')
        self.assertIn(TEST_SECRET, kit['content'])
        self.assertTrue(kit['filename'].endswith('.txt'))
        self.assertEqual(self.call(['key-confirm'], {'key_id': 'AAAA-BBBB-CCCC-DDDD'}), {'ok': True})
        self.assertEqual(self.error_code(['key-confirm'], {'key_id': 'AAAA-BBBB-CCCC-0000'}), 'invalid-request')
        imported = self.call(['key-import'], {'key': TEST_SECRET})
        self.assertEqual(imported['key'], {'key_id': TEST_SECRET_ID, 'created': '2026-11-13T00:00:00Z'})
        self.assertEqual(self.call(['status'])['imported_keys'], [{'key_id': TEST_SECRET_ID,
                                                                   'created': '2026-11-13T00:00:00Z'}])


class InspectTests(CliCase):
    def setUp(self):
        super().setUp()
        self.backup_id = self.make_backup(apps=('woowbk-demo', 'woowbk-two'))
        self.catalog.pop('woowbk-two')

    def reencrypt_for_imported_key(self):
        path = self.storage.archive_path(self.backup_id)
        data = json.loads(path.read_text())
        data['header']['key_id'] = TEST_SECRET_ID
        path.write_text(json.dumps(data))
        self.storage.index[self.backup_id]['key_id'] = TEST_SECRET_ID

    def test_inspect_shapes_and_index_update(self):
        response = self.call(['inspect'], {'backup_id': self.backup_id})
        self.assertEqual(set(response), {'ok', 'backup', 'manifest', 'preflight'})
        self.assertEqual(set(response['backup']), META_KEYS)
        manifest = response['manifest']
        self.assertEqual(set(manifest), {'backup_id', 'created', 'type', 'note', 'tool', 'source', 'consistency',
                                         'total_size', 'apps'})
        self.assertEqual(set(manifest['apps'][0]), {'id', 'name', 'adapter', 'owner', 'images', 'postgres', 'volumes',
                                                    'secrets_count', 'config_files_count', 'verify_snapshot'})
        self.assertEqual(manifest['apps'][0]['images'], [{'ref': 'localhost/x:1', 'included': False}])
        preflight = response['preflight']
        self.assertEqual(set(preflight), {'ok', 'checks', 'apps'})
        self.assertTrue(preflight['ok'])
        demo, two = preflight['apps']
        self.assertEqual(set(demo), {'id', 'name', 'restorable', 'mode', 'checks'})
        self.assertEqual((demo['restorable'], demo['mode']), (True, 'inplace'))
        self.assertEqual((two['restorable'], two['checks'][0]['status']), (False, 'fail'))
        for check in preflight['checks'] + demo['checks']:
            self.assertEqual(set(check), {'id', 'status', 'message'})
            self.assertIn(check['status'], ('ok', 'warn', 'fail'))
        self.assertTrue(self.storage.index[self.backup_id]['inspected'])

    def test_key_required_then_temporary_key_then_saved_key(self):
        self.reencrypt_for_imported_key()
        response = self.call(['inspect'], {'backup_id': self.backup_id})
        self.assertEqual((response['error']['code'], response['error']['details']['key_id']),
                         ('key-required', TEST_SECRET_ID))
        response = self.call(['inspect'], {'backup_id': self.backup_id, 'key': TEST_SECRET})
        self.assertTrue(response['ok'])
        self.assertFalse(response['backup']['key_available'])
        self.assertTrue(self.keys.temp_paths)
        self.assertFalse(any(p.exists() for p in self.keys.temp_paths))
        self.assertEqual(self.keys.imported, [])
        response = self.call(['inspect'], {'backup_id': self.backup_id, 'key': TEST_SECRET, 'save_key': True})
        self.assertTrue(response['backup']['key_available'])
        self.assertEqual([k.key_id for k in self.keys.imported], [TEST_SECRET_ID])

    def test_space_and_missing_device_key_for_inplace(self):
        self.storage.free = 10
        self.keys.import_key(TEST_SECRET)
        self.reencrypt_for_imported_key()
        self.keys.device = None
        preflight = self.call(['inspect'], {'backup_id': self.backup_id})['preflight']
        self.assertFalse(preflight['ok'])
        self.assertEqual(preflight['checks'][1]['status'], 'fail')
        self.assertIn('woowbk-demo/device-key', [c['id'] for c in preflight['apps'][0]['checks']])

    def test_not_found(self):
        self.assertEqual(self.error_code(['inspect'], {'backup_id': '20200101T000000Z-00000000'}), 'not-found')


class JobCommandTests(CliCase):
    def setUp(self):
        super().setUp()
        self.backup_id = self.make_backup()

    def test_backup_start_dedup_and_busy(self):
        request = {'apps': ['woowbk-demo'], 'include_images': True, 'note': '週末前', 'request_id': 'req-00000001'}
        first = self.call(['backup-start'], request)
        self.assertEqual(set(first), {'ok', 'job_id', 'deduplicated'})
        self.assertFalse(first['deduplicated'])
        self.assertEqual(self.launched, [first['job_id']])
        self.assertEqual(self.call(['backup-start'], request)['job_id'], first['job_id'])
        self.assertTrue(self.call(['backup-start'], request)['deduplicated'])
        self.active_units.add(f'woowtech-backup-{first["job_id"]}.service')
        self.assertEqual(self.error_code(['backup-start'], dict(request, request_id='req-00000002')), 'busy')
        record = jobs.JobStore(self.paths).get(first['job_id'])
        self.assertEqual(record['params'], {'apps': ['woowbk-demo'], 'include_images': True, 'note': '週末前'})

    def test_backup_start_validation(self):
        self.assertEqual(self.error_code(['backup-start'], {'apps': ['nope-app'], 'request_id': 'req-00000001'}),
                         'app-not-in-catalog')
        self.keys.device = None
        self.assertEqual(self.error_code(['backup-start'], {'apps': ['woowbk-demo'], 'request_id': 'req-00000001'}),
                         'no-device-key')
        self.assertEqual(self.launched, [])

    def test_restore_start_with_temporary_and_saved_key(self):
        base = {'backup_id': self.backup_id, 'apps': ['woowbk-demo'], 'confirm': True}
        first = self.call(['restore-start'], dict(base, request_id='req-00000001', key=TEST_SECRET))
        key_file = jobs.JobStore(self.paths).key_path(first['job_id'])
        self.assertEqual(key_file.read_text(), TEST_SECRET + '\n')
        record = jobs.JobStore(self.paths).get(first['job_id'])
        self.assertEqual(record['params'], {'backup_id': self.backup_id, 'apps': ['woowbk-demo'], 'key_provided': True})
        self.assertNotIn(TEST_SECRET, json.dumps(record))
        self.call(['job-cancel'], {'job_id': first['job_id']})
        jobs.run_job(self.paths, first['job_id'], deps=self.deps)
        self.assertFalse(key_file.exists())
        second = self.call(['restore-start'], dict(base, request_id='req-00000002', key=TEST_SECRET, save_key=True))
        self.assertFalse(jobs.JobStore(self.paths).key_path(second['job_id']).exists())
        self.assertEqual([k.key_id for k in self.keys.imported], [TEST_SECRET_ID])

    def test_restore_start_validation(self):
        base = {'backup_id': self.backup_id, 'apps': ['woowbk-demo'], 'confirm': True, 'request_id': 'req-00000001'}
        self.assertEqual(self.error_code(['restore-start'], dict(base, apps=['nope-app'])), 'app-not-in-catalog')
        self.assertEqual(self.error_code(['restore-start'], dict(base, backup_id='20200101T000000Z-00000000')),
                         'not-found')
        self.assertEqual(self.error_code(['restore-start'], {k: v for k, v in base.items() if k != 'confirm'}),
                         'invalid-request')

    def test_start_then_run_job_end_to_end(self):
        started = self.call(['backup-start'], {'apps': ['woowbk-demo'], 'request_id': 'req-00000009'})
        ran = self.call(['run-job', started['job_id']])
        self.assertEqual(ran, {'ok': True, 'state': 'succeeded'})
        status = self.call(['job-status'], {'job_id': started['job_id']})
        self.assertEqual(set(status), {'ok', 'job', 'log'})
        job = status['job']
        self.assertEqual(list(job), list(jobs.PUBLIC_KEYS))
        self.assertEqual(job['state'], 'succeeded')
        self.assertEqual(set(job['result']), {'backup_id', 'size', 'apps', 'downtime_seconds'})
        self.assertTrue(status['log'])
        self.assertTrue(all(isinstance(line, str) for line in status['log']))
        listed = self.call(['jobs'])['jobs']
        self.assertEqual(listed[0]['id'], started['job_id'])
        self.assertNotIn('log', listed[0])
        self.assertEqual(self.call(['job-cancel'], {'job_id': started['job_id']}), {'ok': True, 'state': 'succeeded'})
        verify = self.call(['verify-start'], {'backup_id': job['result']['backup_id'], 'request_id': 'req-00000010'})
        self.assertEqual(self.call(['run-job', verify['job_id']])['state'], 'succeeded')
        verified = self.call(['job-status'], {'job_id': verify['job_id']})['job']
        self.assertEqual(verified['result'], {'ok': True, 'entries': 1, 'bytes': len(b'notes-v1')})

    def test_status_shows_active_job_and_interrupted_recovery(self):
        started = self.call(['backup-start'], {'apps': ['woowbk-demo'], 'request_id': 'req-00000001'})
        self.active_units.add(f'woowtech-backup-{started["job_id"]}.service')
        self.assertEqual(self.call(['status'])['active_job']['id'], started['job_id'])
        record = jobs.JobStore(self.paths).get(started['job_id'])
        record['created'], record['state'] = '2026-01-01T00:00:00Z', 'running'
        jobs.JobStore(self.paths).save(record)
        self.active_units.clear()
        job = self.call(['job-status'], {'job_id': started['job_id']})['job']
        self.assertEqual(job['state'], 'interrupted')
        self.assertIsNone(self.call(['status'])['active_job'])

    def test_status_restarts_writers_left_stopped_by_a_killed_backup(self):
        started = self.call(['backup-start'], {'apps': ['woowbk-demo'], 'request_id': 'req-00000001'})
        store = jobs.JobStore(self.paths)
        record = store.get(started['job_id'])
        record.update(state='running', created='2026-01-01T00:00:00Z',
                      stopped_writers={'woowbk-demo': ['woowbk-demo-app.service']})
        store.save(record)
        self.assertIsNone(self.call(['status'])['active_job'])
        self.assertIn(('start_units', 'woowbk-demo', ('woowbk-demo-app.service',)), self.world.events)
        job = self.call(['job-status'], {'job_id': started['job_id']})['job']
        self.assertEqual(job['state'], 'interrupted')
        self.assertIn('已自動重新啟動', job['error']['message'])
        self.assertNotIn('stopped_writers', job)

    def test_job_errors(self):
        self.assertEqual(self.error_code(['job-status'], {'job_id': 'j20261113T020000Z-00000000'}), 'not-found')
        started = self.call(['backup-start'], {'apps': ['woowbk-demo'], 'request_id': 'req-00000001'})
        record = jobs.JobStore(self.paths).get(started['job_id'])
        record['cancellable'] = False
        jobs.JobStore(self.paths).save(record)
        self.active_units.add(f'woowtech-backup-{started["job_id"]}.service')
        self.assertEqual(self.error_code(['job-cancel'], {'job_id': started['job_id']}), 'not-cancellable')


class FileCommandTests(CliCase):
    def test_delete_refuses_backup_in_use(self):
        backup_id = self.make_backup()
        started = self.call(['restore-start'], {'backup_id': backup_id, 'apps': ['woowbk-demo'], 'confirm': True,
                                                'request_id': 'req-00000001'})
        self.active_units.add(f'woowtech-backup-{started["job_id"]}.service')
        self.assertEqual(self.error_code(['delete'], {'backup_id': backup_id}), 'busy')
        self.active_units.clear()
        record = jobs.JobStore(self.paths).get(started['job_id'])
        record['state'] = 'failed'
        jobs.JobStore(self.paths).save(record)
        self.assertEqual(self.call(['delete'], {'backup_id': backup_id}), {'ok': True})
        self.assertEqual(self.error_code(['delete'], {'backup_id': backup_id}), 'not-found')

    def test_upload_and_download_shapes(self):
        begin = self.call(['upload-begin'], {'filename': 'woowtech-backup-dev-a-20261113-0200.woowbackup', 'size': 4096})
        self.assertEqual(set(begin), {'ok', 'upload_id', 'path', 'max_size'})
        finished = self.call(['upload-finish'], {'upload_id': begin['upload_id']})
        self.assertEqual(set(finished['backup']) - {'uploaded_at'}, META_KEYS)
        self.assertTrue(finished['backup']['key_available'] is False)
        self.assertEqual(self.call(['upload-abort'], {'upload_id': begin['upload_id']}), {'ok': True})
        backup_id = self.make_backup()
        info = self.call(['download-info'], {'backup_id': backup_id})
        self.assertEqual(set(info), {'ok', 'path', 'filename', 'size'})
        self.assertTrue(info['path'].endswith(f'{backup_id}.woowbackup'))


if __name__ == '__main__':
    unittest.main()
