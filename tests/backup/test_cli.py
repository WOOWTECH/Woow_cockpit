"""CLI contract (CONTRACT section 7): one JSON object on stdout, exit codes, strict stdin, shapes."""
import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from woowbackup import cli, flows, jobs
from woowbackup.errors import BackupError
from woowbackup.paths import Paths

from .test_flows import (TEST_SECRET, TEST_SECRET_ID, FakeArchive, FakeKeys, FakeReporter, FakeStorage, HOST, World,
                         make_catalog)

APP_KEYS = ['id', 'name', 'description', 'owner', 'adapter', 'deployed', 'state', 'units', 'last_backup', 'problems']
META_KEYS = {'id', 'type', 'created', 'note', 'apps', 'size', 'sha256', 'key_id', 'include_images', 'filename',
             'source', 'verified', 'inspected', 'key_available', 'format', 'encrypted', 'unauthenticated'}


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
        # Pre-restore copies live where the recovery (jobs.py) looks for them, as on a device (CONTRACT section 3).
        self.storage.pending = Path(self.paths.pending)
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
                                         'active_job', 'warnings', 'settings'})
        self.assertEqual(set(response['settings']), {'encrypt_by_default', 'problem', 'plaintext_warning'})
        self.assertIs(response['settings']['encrypt_by_default'], True)
        self.assertEqual(response['host'], {k: HOST[k] for k in ('hostname', 'arch', 'os', 'podman')})
        self.assertEqual(set(response['storage']), {'path', 'free_bytes', 'total_bytes', 'backups_bytes', 'backup_count',
                                                    'apps'})
        usage = {row['id']: row for row in response['storage']['apps']}
        self.assertEqual(set(usage), {'woowbk-demo', 'woowbk-two'})
        self.assertEqual((usage['woowbk-demo']['backups'], usage['woowbk-demo']['types']['manual']), (1, 1))
        self.assertTrue(usage['woowbk-demo']['in_catalog'])
        self.assertIsNone(usage['woowbk-demo']['keep_last'])
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

    def test_running_but_unhealthy_app_is_not_shown_as_running(self):
        # Lab H5 open issue: units were active while /healthz answered 503; the page said 執行中.
        self.world.health_hints['woowbk-demo'] = '服務已啟動，但健康檢查未通過（http://127.0.0.1:18090/healthz，HTTP 503）。'
        demo = self.call(['status'])['apps'][0]
        self.assertEqual(demo['state'], 'error')
        self.assertIn('HTTP 503', demo['problems'][-1])
        self.assertEqual(self.call(['status'])['apps'][1]['state'], 'running')

    def test_hd07_apps_are_probed_side_by_side(self):
        # Each status call probes every app and sends one bounded health request per running app; with many
        # apps they run concurrently, so one slow app no longer adds up with the others (review finding HD-07).
        import threading
        import time
        from .test_flows import FakeAdapter
        threads = set()

        def slow_hint(adapter):
            threads.add(threading.current_thread().name)
            time.sleep(1.0)
            return None
        original = FakeAdapter.health_hint
        FakeAdapter.health_hint = slow_hint
        try:
            start = time.monotonic()
            response = self.call(['status'])
            elapsed = time.monotonic() - start
        finally:
            FakeAdapter.health_hint = original
        self.assertTrue(response['ok'])
        self.assertEqual([app['id'] for app in response['apps']], ['woowbk-demo', 'woowbk-two'], 'catalog order kept')
        self.assertEqual(len(threads), 2)
        self.assertLess(elapsed, 1.8, f'{elapsed:.2f} s for two apps of 1 s each')

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
                                         'total_size', 'apps', 'format', 'encryption'})
        self.assertEqual((manifest['format'], manifest['encryption']), (2, 'age-x25519'))
        self.assertEqual(set(manifest['apps'][0]), {'id', 'name', 'adapter', 'owner', 'images', 'postgres', 'volumes',
                                                    'data_dirs', 'secrets_count', 'config_files_count',
                                                    'verify_snapshot', 'verify_digests'})
        self.assertEqual(manifest['apps'][0]['data_dirs'], [], 'an archive without host directories lists none')
        self.assertEqual(manifest['apps'][0]['verify_digests'], [], 'an archive without digests lists none')
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

    def test_a_wrong_key_is_never_saved(self):
        # Review F4: with save_key, the key was imported before decryption and kept although it was wrong.
        response = self.call(['inspect'], {'backup_id': self.backup_id, 'key': TEST_SECRET, 'save_key': True})
        self.assertEqual(response['error']['code'], 'wrong-key')
        self.assertEqual(self.keys.imported, [])
        self.assertFalse(any(p.exists() for p in self.keys.temp_paths))

    def test_sigterm_during_inspect_removes_the_pasted_key(self):
        # Review SEC-4: cockpit-bridge sends SIGTERM when the channel closes; the temp key must still go.
        import signal
        self.reencrypt_for_imported_key()
        read_manifest = self.archive.read_manifest

        def interrupted(path, identities, **kwargs):
            os.kill(os.getpid(), signal.SIGTERM)
            import time
            time.sleep(5)
            return read_manifest(path, identities, **kwargs)
        self.archive.read_manifest = interrupted
        previous = signal.getsignal(signal.SIGTERM)
        with contextlib.redirect_stderr(io.StringIO()):
            response = self.call(['inspect'], {'backup_id': self.backup_id, 'key': TEST_SECRET})
        self.assertEqual(signal.getsignal(signal.SIGTERM), previous)
        self.assertFalse(response['ok'])
        self.assertTrue(self.keys.temp_paths)
        self.assertFalse(any(p.exists() for p in self.keys.temp_paths))

    def test_lone_surrogates_never_break_the_one_json_object_contract(self):
        # Review SEC-5: a hostile note came back from inspect; stdout must still be exactly one JSON object.
        out = io.StringIO()
        cli._emit(out, {'ok': True, 'note': 'x\ud800y'})
        self.assertEqual(json.loads(out.getvalue())['note'], 'x\ud800y')
        out.getvalue().encode('ascii')
        self.assertEqual(self.error_code(['download-info'], raw='{"backup_id": "\\ud800"}'), 'invalid-request')

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
        self.assertEqual(record['params'], {'apps': ['woowbk-demo'], 'include_images': True, 'note': '週末前',
                                            'encrypt': True})

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
        # Review F4: a key is saved only after it opened this backup; this one did not (wrong key).
        refused = self.call(['restore-start'], dict(base, request_id='req-00000002', key=TEST_SECRET, save_key=True))
        self.assertEqual(refused['error']['code'], 'wrong-key')
        self.assertEqual(self.keys.imported, [])
        path = self.storage.archive_path(self.backup_id)
        data = json.loads(path.read_text())
        data['header']['key_id'] = TEST_SECRET_ID
        path.write_text(json.dumps(data))
        second = self.call(['restore-start'], dict(base, request_id='req-00000003', key=TEST_SECRET, save_key=True))
        self.assertFalse(jobs.JobStore(self.paths).key_path(second['job_id']).exists())
        self.assertEqual([k.key_id for k in self.keys.imported], [TEST_SECRET_ID])
        self.assertFalse(any(p.exists() for p in self.keys.temp_paths))

    def test_restore_start_without_safety_backup_is_explicit(self):
        # Review CR-16: only an explicit, separately confirmed option skips the safety backup.
        base = {'backup_id': self.backup_id, 'apps': ['woowbk-demo'], 'confirm': True}
        started = self.call(['restore-start'], dict(base, request_id='req-00000004', allow_no_safety=True))
        self.assertEqual(jobs.JobStore(self.paths).get(started['job_id'])['params']['allow_no_safety'], True)
        self.assertEqual(self.error_code(['restore-start'], dict(base, request_id='req-00000005',
                                                                 allow_no_safety='yes')), 'invalid-request')

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
        self.assertEqual(set(job['result']), {'backup_id', 'size', 'apps', 'downtime_seconds', 'unavailable_seconds',
                                              'timing', 'encrypted', 'retention_deleted'})
        self.assertEqual(job['result']['retention_deleted'], [])
        self.assertTrue(status['log'])
        self.assertTrue(all(isinstance(line, str) for line in status['log']))
        listed = self.call(['jobs'])['jobs']
        self.assertEqual(listed[0]['id'], started['job_id'])
        self.assertNotIn('log', listed[0])
        self.assertEqual(self.call(['job-cancel'], {'job_id': started['job_id']}), {'ok': True, 'state': 'succeeded'})
        verify = self.call(['verify-start'], {'backup_id': job['result']['backup_id'], 'request_id': 'req-00000010'})
        self.assertEqual(self.call(['run-job', verify['job_id']])['state'], 'succeeded')
        verified = self.call(['job-status'], {'job_id': verify['job_id']})['job']
        self.assertEqual(verified['result'], {'ok': True, 'entries': 1, 'bytes': len(b'notes-v1'), 'deep': True,
                                              'format': 2, 'encrypted': True, 'notes': [],
                                              'apps': [{'id': 'woowbk-demo', 'name': '示範筆記應用',
                                                        'checked': {'volumes': 0, 'dirs': 0, 'images': 0,
                                                                    'digests': 0, 'globals': 0, 'dumps': 0,
                                                                    'secrets': 0}, 'header_only': []}]})

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
    def test_delete_refuses_the_running_restores_safety_backup(self):
        # Review CR-08: deleting it would take away the rollback source of the running restore.
        backup_id = self.make_backup()
        safety_id = self.make_backup()
        self.storage.index[safety_id]['type'] = 'safety'
        other_safety = self.make_backup()
        self.storage.index[other_safety]['type'] = 'safety'
        started = self.call(['restore-start'], {'backup_id': backup_id, 'apps': ['woowbk-demo'], 'confirm': True,
                                                'request_id': 'req-00000009'})
        self.active_units.add(f'woowtech-backup-{started["job_id"]}.service')
        store = jobs.JobStore(self.paths)
        record = store.get(started['job_id'])
        record.update(state='running', safety_backup_id=safety_id)
        store.save(record)
        response = self.call(['delete'], {'backup_id': safety_id})
        self.assertEqual((response['error']['code'], response['error']['details']['job_id']), ('busy', started['job_id']))
        self.assertEqual(self.error_code(['delete'], {'backup_id': other_safety}), 'busy')
        self.assertIn(safety_id, self.storage.index)
        manual = self.make_backup()
        self.assertEqual(self.call(['delete'], {'backup_id': manual}), {'ok': True})

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
        begin = self.call(['upload-begin'], {'filename': 'woowtech-backup-dev-a-20261113-020000.woowbackup', 'size': 4096})
        self.assertEqual(set(begin), {'ok', 'upload_id', 'path', 'max_size'})
        finished = self.call(['upload-finish'], {'upload_id': begin['upload_id']})
        self.assertEqual(set(finished['backup']) - {'uploaded_at'}, META_KEYS)
        self.assertTrue(finished['backup']['key_available'] is False)
        self.assertEqual(self.call(['upload-abort'], {'upload_id': begin['upload_id']}), {'ok': True})
        backup_id = self.make_backup()
        info = self.call(['download-info'], {'backup_id': backup_id})
        self.assertEqual(set(info), {'ok', 'path', 'filename', 'size'})
        self.assertTrue(info['path'].endswith(f'{backup_id}.tar'))


if __name__ == '__main__':
    unittest.main()


class HostDirCliTests(CliCase):
    def test_manifest_summary_lists_directories_with_size_and_local_label(self):
        from woowbackup import catalog as catalog_module
        from .test_catalog import demo_entry, lookup
        entry = demo_entry(self.paths)
        entry['data_dirs'] = [{'path': 'homeassistant/config', 'label': '設定資料夾'}]
        local = {'woowbk-demo': catalog_module.validate_entry(entry, paths=self.paths, user_lookup=lookup)}
        manifest = {'backup_id': '20261113T020000Z-a1b2c3d4', 'created': '2026-11-13T02:00:00Z', 'type': 'manual',
                    'note': '', 'tool': {}, 'source': {}, 'consistency': {},
                    'entries': [{'path': 'apps/woowbk-demo/dirs/0.tar', 'size': 4096, 'sha256': '0' * 64},
                                {'path': 'apps/woowbk-demo/dirs/1.tar', 'size': 10, 'sha256': '0' * 64}],
                    'apps': [{'id': 'woowbk-demo', 'name': '示範', 'adapter': 'quadlet-postgres',
                              'owner': {'name': 'appowner', 'uid': 1001}, 'images': [], 'postgres': [], 'volumes': [],
                              'secrets': [], 'config_files': [], 'verify_snapshot': {},
                              'data_dirs': [{'path': 'homeassistant/config', 'entry': 'apps/woowbk-demo/dirs/0.tar'},
                                            {'path': 'not/declared', 'entry': 'apps/woowbk-demo/dirs/1.tar'}]}]}
        summary = cli.manifest_summary(manifest, local)
        self.assertEqual(summary['apps'][0]['data_dirs'], [
            {'path': 'homeassistant/config', 'size': 4096, 'label': '設定資料夾'},
            {'path': 'not/declared', 'size': 10, 'label': ''}])
        self.assertEqual(cli.manifest_summary(manifest)['apps'][0]['data_dirs'][0]['label'], '')

    def test_recovery_from_status_settles_the_directories_of_a_dead_restore(self):
        store = jobs.JobStore(self.paths)
        store.ensure()
        record = store.create('restore', {'backup_id': '20261113T020000Z-a1b2c3d4', 'apps': ['woowbk-demo']},
                              now=jobs.time.time() - 60)
        record.update(state='running', dir_apps=['woowbk-demo'])
        store.save(record)
        self.world.recover_notes['woowbk-demo'] = ['已移除沒寫完或未換上的 ~/data.woowbk-new-x']
        response = self.call(['status'])
        self.assertTrue(response['ok'])
        self.assertIn(('recover_dirs', 'woowbk-demo', record['id']), self.world.events)
        saved = store.get(record['id'])
        self.assertEqual((saved['state'], saved['dir_apps']), ('interrupted', []))
        self.assertIn('已移除沒寫完或未換上的 ~/data.woowbk-new-x', saved['error']['message'])

    def test_start_commands_give_the_recovery_its_directory_hook(self):
        seen = []
        original = jobs.start_job

        def spy(paths, job_type, params, request_id, **kwargs):
            seen.append((job_type, kwargs.get('settle_dirs')))
            return {'job_id': 'j20261113T020000Z-00000001', 'deduplicated': False}
        jobs.start_job = spy
        try:
            self.call(['backup-start'], {'apps': ['woowbk-demo'], 'request_id': 'req-dirs-0001'})
            backup_id = self.make_backup()
            self.call(['restore-start'], {'backup_id': backup_id, 'apps': ['woowbk-demo'], 'request_id': 'req-dirs-0002',
                                          'confirm': True})
            self.call(['verify-start'], {'backup_id': backup_id, 'request_id': 'req-dirs-0003'})
        finally:
            jobs.start_job = original
        self.assertEqual([kind for kind, _ in seen], ['backup', 'restore', 'verify'])
        self.assertTrue(all(callable(hook) for _, hook in seen))


class CatalogRetentionCliTests(CliCase):
    """應用設定 and 清理備份 through the helper (CONTRACT sections 4, 7, 8): strict requests, dispatch to suggest,
    catalog_admin and retention, `status.storage.apps` and the backup job's `retention_deleted`."""

    POLICY = {'schema': 1, 'default_keep_last': 1, 'apps': {}}

    def setUp(self):
        super().setUp()
        self.audit = []
        self.deps.audit = self.audit.append
        # The trusted configuration directory as the loader wants it: owned by the uid the services trust, 0755.
        self.paths.config.mkdir(parents=True, exist_ok=True)
        os.chmod(self.paths.config, 0o755)

    def services(self):
        return cli.Services(self.paths, deps=self.deps, launcher=self.launched.append,
                            unit_active=lambda unit: unit in self.active_units, trusted_uid=os.geteuid())

    def enforce(self, app_ids, *, exclude, log):
        from woowbackup import retention
        return retention.enforce_after_backup(self.paths, self.storage, app_ids, exclude=exclude, log=log,
                                              audit=self.audit.append, trusted_uid=os.geteuid())

    def test_requests_are_strict(self):
        backup_id = '20261113T020000Z-a1b2c3d4'
        cases = [
            ('catalog-suggest', {'owner': 'root'}), ('catalog-suggest', {'owner': 'Bad Name'}),
            ('catalog-suggest', {'owner': 'appowner', 'extra': 1}), ('catalog-suggest', {'owner': 7}),
            ('catalog-install', {}), ('catalog-install', {'entry': []}), ('catalog-install', {'entry': 'x'}),
            ('catalog-install', {'entry': {}, 'confirm': 'yes'}),
            ('catalog-install', {'entry': {}, 'confirm': True}),
            ('catalog-install', {'entry': {}, 'confirm': True, 'expected_sha256': 'A' * 64}),
            ('catalog-install', {'entry': {}, 'expected_sha256': 'abc'}),
            ('catalog-remove', {}), ('catalog-remove', {'id': '../etc'}), ('catalog-remove', {'id': 'x'}),
            ('catalog-remove', {'id': 'woowbk-demo', 'confirm': True}),
            ('retention-plan', {'policy': []}), ('retention-plan', {'policy': self.POLICY, 'x': 1}),
            ('retention-apply', {'backup_ids': []}), ('retention-apply', {'confirm': False, 'backup_ids': []}),
            ('retention-apply', {'confirm': True}), ('retention-apply', {'confirm': True, 'backup_ids': ['nope']}),
            ('retention-apply', {'confirm': True, 'backup_ids': [backup_id, backup_id]}),
            ('retention-apply', {'confirm': True, 'backup_ids': [f'20261113T020000Z-{n:08x}' for n in range(501)]}),
            ('retention-apply', {'confirm': True, 'backup_ids': [], 'policy': 'keep'}),
        ]
        for command, request in cases:
            with self.subTest(command=command, request=str(request)[:80]):
                self.assertEqual(self.error_code([command], request), 'invalid-request')
        response = self.call(['catalog-install'], {'entry': {}, 'confirm': True})
        self.assertEqual(response['error']['details']['field'], 'expected_sha256')
        # Without input the command is refused (catalog-suggest takes `{}`), and the read is bounded as usual.
        self.assertEqual(self.error_code(['catalog-suggest'], raw=''), 'invalid-request')

    def test_catalog_suggest_dispatch(self):
        from woowbackup import suggest
        seen = []
        original = suggest.suggest

        def spy(owner, *, paths, catalog=None, **_kwargs):
            seen.append((owner, paths, catalog))
            return {'owners': [{'name': 'appowner', 'uid': 1001, 'linger': True, 'catalog_apps': ['woowbk-demo']}]}
        suggest.suggest = spy
        try:
            self.assertEqual(self.call(['catalog-suggest'], {})['owners'][0]['name'], 'appowner')
            self.call(['catalog-suggest'], {'owner': 'appowner'})
        finally:
            suggest.suggest = original
        self.assertEqual([owner for owner, _paths, _catalog in seen], [None, 'appowner'])
        self.assertTrue(all(paths == self.paths and catalog is self.catalog for _owner, paths, catalog in seen))

    def test_catalog_install_preview_is_the_loaders_validation_and_confirm_passes_the_previewed_digest(self):
        from woowbackup import catalog_admin
        from .test_catalog import demo_entry
        entry = demo_entry(self.paths)
        entry['owner'] = 'woowbk-no-such-owner'
        preview = self.call(['catalog-install'], {'entry': entry})
        self.assertTrue(preview['ok'])
        self.assertEqual((preview['preview'], preview['valid'], preview['id']), (True, False, 'woowbk-demo'))
        self.assertEqual(preview['error']['code'], 'owner-missing')
        self.assertIsNone(preview['expected_sha256'])
        self.assertFalse((self.paths.catalog / 'woowbk-demo.json').exists())
        seen = []
        original = catalog_admin.install

        def spy(paths, entry_, expected, **kwargs):
            kwargs['audit']('catalog-install probe')  # the journal writer of the services (deps.audit here)
            seen.append((entry_['id'], expected, kwargs['trusted_uid'], len(kwargs['backups'])))
            return {'installed': True, 'id': entry_['id']}
        catalog_admin.install = spy
        try:
            self.make_backup()
            done = self.call(['catalog-install'], {'entry': entry, 'confirm': True, 'expected_sha256': None})
        finally:
            catalog_admin.install = original
        self.assertEqual(done, {'ok': True, 'installed': True, 'id': 'woowbk-demo'})
        self.assertEqual(seen, [('woowbk-demo', None, os.geteuid(), 1)])
        self.assertEqual(self.audit, ['catalog-install probe'])

    def test_catalog_remove_of_an_entry_that_is_not_installed(self):
        self.assertEqual(self.error_code(['catalog-remove'], {'id': 'woowbk-demo'}), 'not-found')
        self.assertEqual(self.error_code(['catalog-remove'], {'id': 'woowbk-demo', 'confirm': True,
                                                               'expected_sha256': None}), 'not-found')

    def test_retention_plan_apply_status_and_the_backup_jobs_policy(self):
        self.deps.enforce_retention = self.enforce
        first, second = self.make_backup(), self.make_backup()
        plan = self.call(['retention-plan'], {})
        self.assertEqual(set(plan), {'ok', 'policy', 'saved_policy', 'proposed', 'policy_problem', 'usage', 'candidates',
                                     'blocked', 'protected', 'freed_bytes'})
        self.assertEqual((plan['proposed'], plan['candidates'], plan['policy_problem']), (False, [], None))
        self.assertEqual({row['id'] for row in plan['usage']['apps']}, {'woowbk-demo', 'woowbk-two'})
        proposed = self.call(['retention-plan'], {'policy': self.POLICY})
        self.assertTrue(proposed['proposed'])
        self.assertEqual([item['id'] for item in proposed['candidates']], [first])
        self.assertFalse((self.paths.config / 'retention.json').exists(), 'a preview saves nothing')
        applied = self.call(['retention-apply'], {'confirm': True, 'backup_ids': [first], 'policy': self.POLICY})
        self.assertEqual([item['id'] for item in applied['deleted']], [first])
        self.assertEqual((applied['skipped'], applied['policy']['default_keep_last']), ([], 1))
        self.assertEqual(oct((self.paths.config / 'retention.json').stat().st_mode & 0o777), '0o644')
        self.assertTrue(any(line.startswith('retention-policy default=1 ') for line in self.audit), self.audit)
        self.assertTrue(any(line.startswith(f'retention-delete backup={first} type=manual ') for line in self.audit))
        usage = {row['id']: row for row in self.call(['status'])['storage']['apps']}
        self.assertEqual((usage['woowbk-demo']['keep_last'], usage['woowbk-demo']['backups']), (1, 1))
        again = self.call(['retention-apply'], {'confirm': True, 'backup_ids': [first]})
        self.assertEqual(again['deleted'], [])
        self.assertEqual(again['skipped'][0]['id'], first)
        # A manual backup job applies the saved policy (keep the newest 1): the older one goes, the new one stays.
        started = self.call(['backup-start'], {'apps': ['woowbk-demo'], 'request_id': 'req-retain-0001'})
        self.assertEqual(self.call(['run-job', started['job_id']])['state'], 'succeeded')
        status = self.call(['job-status'], {'job_id': started['job_id']})
        result = status['job']['result']
        self.assertEqual(result['retention_deleted'], [second])
        self.assertTrue(any('已依保留原則刪除較舊的手動備份' in line for line in status['log']), status['log'])
        self.assertEqual([b['id'] for b in self.storage.list_backups()], [result['backup_id']])

    def test_a_retention_problem_never_fails_the_backup(self):
        def broken(_app_ids, *, exclude, log):
            raise OSError('disk on fire')
        self.deps.enforce_retention = broken
        started = self.call(['backup-start'], {'apps': ['woowbk-demo'], 'request_id': 'req-retain-0002'})
        self.assertEqual(self.call(['run-job', started['job_id']])['state'], 'succeeded')
        status = self.call(['job-status'], {'job_id': started['job_id']})
        self.assertEqual(status['job']['result']['retention_deleted'], [])
        self.assertTrue(any('無法套用備份保留原則' in line for line in status['log']), status['log'])

    def test_status_storage_apps_never_breaks_the_status(self):
        from woowbackup import retention
        original = retention.app_usage

        def broken(*_args, **_kwargs):
            raise RuntimeError('usage failed')
        retention.app_usage = broken
        err = io.StringIO()
        try:
            with contextlib.redirect_stderr(err):
                response = self.call(['status'])
        finally:
            retention.app_usage = original
        self.assertTrue(response['ok'])
        self.assertEqual(response['storage']['apps'], [])


class PendingCopyCliTests(CliCase):
    """2026.11.14.2: the helper's recovery packages the pre-restore copy a restore kept (CONTRACT section 8)."""

    def test_job_status_packages_the_copy_a_restore_cut_by_a_shutdown_kept(self):
        backup_id = self.make_backup()
        self.world.data['woowbk-demo'] = b'notes-v2-changed'
        started = self.call(['restore-start'], {'backup_id': backup_id, 'apps': ['woowbk-demo'], 'confirm': True,
                                                'request_id': 'req-pending-0001'})
        job_id = started['job_id']
        self.deps.system_stopping = lambda: True
        self.world.raise_after_destructive = jobs.Terminated(15)
        self.assertEqual(self.call(['run-job', job_id])['state'], 'interrupted')
        pending = self.storage.pending / job_id
        record = jobs.JobStore(self.paths).get(job_id)
        self.assertTrue((pending / 'pending.json').is_file())
        self.assertIs(record['safety_pending'], True)
        self.assertIn(jobs.PENDING_MESSAGE, record['error']['message'])
        self.assertEqual([b for b in self.storage.list_backups() if b['type'] == 'safety'], [])
        status = self.call(['job-status'], {'job_id': job_id})
        job = status['job']
        safety = job['result']['safety_backup_id']
        self.assertEqual(self.storage.index[safety]['type'], 'safety')
        self.assertEqual(self.storage.index[safety]['note'], f'還原前自動備份（還原來源 {backup_id}）')
        self.assertIs(job['result']['safety_pending'], False)
        self.assertTrue(job['error']['message'].endswith(f'已將保留的還原前資料封裝成還原前備份 {safety}，可用它再次還原。'))
        self.assertTrue(any(f'備份 {safety} 已建立並通過完整驗證' in line for line in status['log']), status['log'])
        self.assertFalse(pending.exists())
        self.assertNotIn('safety_pending', job, 'record fields beyond the public ones stay private')
        self.call(['status'])
        self.assertEqual(len([b for b in self.storage.list_backups() if b['type'] == 'safety']), 1, 'packaged once')

    def test_every_recovery_entry_point_gets_the_package_hook(self):
        seen = []

        def start(paths, job_type, params, request_id, **kwargs):
            seen.append(('start', kwargs.get('package_safety')))
            return {'job_id': 'j20261113T020000Z-00000001', 'deduplicated': False}

        def recover(paths, **kwargs):
            seen.append(('recover', kwargs.get('package_safety')))
            return []
        with mock.patch.object(jobs, 'start_job', start), mock.patch.object(jobs, 'recover_interrupted', recover):
            self.call(['status'])
            self.call(['backup-start'], {'apps': ['woowbk-demo'], 'request_id': 'req-pack-0001'})
        self.assertEqual([kind for kind, _hook in seen], ['recover', 'start'])
        self.assertTrue(all(callable(hook) for _kind, hook in seen))
        self.assertEqual(seen[0][1]('j20261113T020000Z-00000002'), (None, '找不到還原前資料的紀錄（pending.json）', False))
