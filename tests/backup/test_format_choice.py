"""Encryption choice, uploads of every format and unencrypted download copies (CONTRACT sections 5, 7, 8; team E1, format).

* settings: 預設加密備份 (default on, root-owned file, turning it off needs the plaintext acknowledgement, audited),
* backups: the per-backup choice (no device key needed without encryption), safety backups follow the setting,
* uploads: v1, v2 encrypted and v2 unencrypted accepted (strict outer scan, sizes and checksums against backup.json), an
  unencrypted upload is unauthenticated and its restore needs an extra acknowledgement,
* exports: the unencrypted copy (root 0600, gzip inner archives, verified), its expiry by TTL, the next status/list
  command and the scheduled timer, and the audit lines.
"""
import hashlib
import json
import os
import shutil
import stat
import tarfile
import unittest
from pathlib import Path

from woowbackup import archive, cli, flows, jobs, settings
from woowbackup.errors import BackupError
from woowbackup.storage import EXPORT_TTL, Storage

from .test_archive import BACKUP_ID, demo_app, demo_manifest, demo_payloads, needs_age, stage, tool_children
from .test_archive_v2 import SECOND, V2Workspace, outer_members, second_app, second_payloads
from .test_flows import HOST, FakeReporter, FlowCase

GIB = 1024 ** 3
JOB_ID = 'j20261113T030000Z-00c0ffee'


# ---------------------------------------------------------------------------- the setting

class SettingsTests(unittest.TestCase):
    def setUp(self):
        self.ws = V2Workspace(self, with_key=False)
        os.makedirs(self.ws.paths.config, mode=0o755, exist_ok=True)
        self.uid = os.geteuid()
        self.audit = []

    def test_default_on_and_turning_it_off_needs_the_acknowledgement(self):
        self.assertEqual(settings.load(self.ws.paths, trusted_uid=self.uid), ({'encrypt_by_default': True}, None))
        with self.assertRaises(BackupError) as caught:
            settings.save(self.ws.paths, encrypt_by_default=False, trusted_uid=self.uid, audit=self.audit.append)
        self.assertEqual((caught.exception.code, caught.exception.details['field']),
                         ('invalid-request', 'acknowledge_plaintext'))
        self.assertIn('明文', caught.exception.message)
        self.assertFalse((self.ws.paths.config / 'settings.json').exists())
        view = settings.save(self.ws.paths, encrypt_by_default=False, acknowledge_plaintext=True, trusted_uid=self.uid,
                             audit=self.audit.append)
        self.assertEqual((view['encrypt_by_default'], view['problem']), (False, None))
        self.assertEqual(view['plaintext_warning'], settings.PLAINTEXT_WARNING)
        path = self.ws.paths.config / 'settings.json'
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)
        self.assertEqual(set(json.loads(path.read_text())), {'schema', 'encrypt_by_default', 'updated'})
        self.assertRegex(self.audit[-1], r'^settings encrypt_by_default=false previous=true loginuid=')
        self.assertFalse(settings.load(self.ws.paths, trusted_uid=self.uid)[0]['encrypt_by_default'])
        settings.save(self.ws.paths, encrypt_by_default=True, trusted_uid=self.uid, audit=self.audit.append)
        self.assertTrue(settings.load(self.ws.paths, trusted_uid=self.uid)[0]['encrypt_by_default'])

    def test_an_unsafe_or_damaged_file_never_turns_encryption_off(self):
        path = self.ws.paths.config / 'settings.json'
        good = json.dumps({'schema': 1, 'encrypt_by_default': False, 'updated': '2026-11-13T00:00:00Z'})
        cases = {
            'group writable': lambda: (path.write_text(good), os.chmod(path, 0o664)),
            'not root-owned': None,
            'not json': lambda: (path.write_text('{nope'), os.chmod(path, 0o644)),
            'unknown key': lambda: (path.write_text(json.dumps(dict(json.loads(good), extra=1))), os.chmod(path, 0o644)),
            'symlink': lambda: (path.unlink(missing_ok=True), (self.ws.base / 'x.json').write_text(good),
                                path.symlink_to(self.ws.base / 'x.json')),
        }
        for name, make in cases.items():
            with self.subTest(name):
                path.unlink(missing_ok=True)
                if make is None:
                    path.write_text(good)
                    os.chmod(path, 0o644)
                    loaded = settings.load(self.ws.paths, trusted_uid=self.uid + 1)
                else:
                    make()
                    loaded = settings.load(self.ws.paths, trusted_uid=self.uid)
                self.assertEqual(loaded[0], {'encrypt_by_default': True})
                self.assertIn('已改用預設值（加密備份）', loaded[1])


# ---------------------------------------------------------------------------- flows with the fakes

class EncryptionChoiceFlowTests(FlowCase):
    def test_an_unencrypted_backup_needs_no_device_key(self):
        self.keys.device = None
        result = self.backup(encrypt=False)
        self.assertFalse(result['encrypted'])
        write = self.archive.writes[-1]
        self.assertIsNone(write['recipient'])
        self.assertEqual((write['manifest']['format'], write['manifest']['encryption'], write['manifest']['key_id']),
                         (2, 'none', None))
        meta = self.storage.index[result['backup_id']]
        self.assertEqual((meta['format'], meta['encrypted'], meta['key_id']), (2, False, None))
        self.assertTrue(any('明文' in line for line in self.reporter.logs))

    def test_an_encrypted_backup_still_needs_the_device_key(self):
        self.keys.device = None
        with self.assertRaises(BackupError) as caught:
            self.backup()
        self.assertEqual(caught.exception.code, 'no-device-key')
        self.keys.ensure_device_key()
        self.assertTrue(self.backup(encrypt=True)['encrypted'])

    def test_safety_backups_follow_the_setting(self):
        backup_id = self.backup(encrypt=False)['backup_id']
        self.keys.device = None
        self.deps.encrypt_by_default = lambda: False
        result = flows.run_restore(self.ctx(), {'backup_id': backup_id, 'apps': ['woowbk-demo']})
        safety = self.storage.index[result['safety_backup_id']]
        self.assertEqual((safety['type'], safety['encrypted'], safety['key_id']), ('safety', False, None))
        self.assertEqual(self.archive.extracts[0][2], ['woowbk-demo'], 'only the restored app is extracted')
        self.deps.encrypt_by_default = lambda: True
        with self.assertRaises(BackupError) as caught:
            flows.run_restore(self.ctx(), {'backup_id': backup_id, 'apps': ['woowbk-demo']})
        self.assertEqual(caught.exception.code, 'no-device-key')

    def test_an_unencrypted_upload_needs_an_explicit_acceptance(self):
        backup_id = self.backup(encrypt=False)['backup_id']
        self.storage.index[backup_id]['type'] = 'uploaded'
        with self.assertRaises(BackupError) as caught:
            flows.run_restore(self.ctx(), {'backup_id': backup_id, 'apps': ['woowbk-demo']})
        self.assertEqual((caught.exception.code, caught.exception.details['field']),
                         ('invalid-request', 'accept_unauthenticated'))
        self.assertEqual(self.archive.extracts, [], 'refused before anything was read')
        result = flows.run_restore(self.ctx(), {'backup_id': backup_id, 'apps': ['woowbk-demo'],
                                                'accept_unauthenticated': True})
        self.assertFalse(result['rolled_back'])


class EncryptionChoiceCliTests(FlowCase):
    def call(self, argv, request=None):
        import io
        out = io.StringIO()
        stdin = io.StringIO(json.dumps(request)) if request is not None else None
        services = cli.Services(self.paths, deps=self.deps, launcher=self.launched.append,
                                unit_active=lambda unit: False, trusted_uid=os.geteuid())
        cli.main(argv, stdin=stdin, stdout=out, services=services, require_root=False)
        return json.loads(out.getvalue())

    def setUp(self):
        super().setUp()
        self.launched = []
        os.makedirs(self.paths.config, mode=0o755, exist_ok=True)

    def params(self, job_id):
        return jobs.JobStore(self.paths).get(job_id)['params']

    def test_backup_start_choice_defaults_to_the_setting(self):
        base = {'apps': ['woowbk-demo']}
        started = self.call(['backup-start'], dict(base, request_id='req-00000001'))
        self.assertTrue(self.params(started['job_id'])['encrypt'])
        refused = self.call(['backup-start'], dict(base, request_id='req-00000002', encrypt=False))
        self.assertEqual((refused['error']['code'], refused['error']['details']['field']),
                         ('invalid-request', 'acknowledge_plaintext'))
        record = jobs.JobStore(self.paths).get(started['job_id'])
        record['state'] = 'succeeded'
        jobs.JobStore(self.paths).save(record)
        self.keys.device = None  # the key banner must not block an unencrypted backup
        plain = self.call(['backup-start'], dict(base, request_id='req-00000003', encrypt=False,
                                                  acknowledge_plaintext=True))
        self.assertFalse(self.params(plain['job_id'])['encrypt'])
        self.assertEqual(self.call(['backup-start'], dict(base, request_id='req-00000004'))['error']['code'],
                         'no-device-key')

    def test_settings_commands_and_the_default_off(self):
        got = self.call(['settings-get'])
        self.assertEqual(set(got['settings']), {'encrypt_by_default', 'problem', 'plaintext_warning'})
        refused = self.call(['settings-set'], {'encrypt_by_default': False})
        self.assertEqual(refused['error']['details']['field'], 'acknowledge_plaintext')
        self.assertEqual(self.call(['settings-set'], {'encrypt_by_default': 'no'})['error']['code'], 'invalid-request')
        changed = self.call(['settings-set'], {'encrypt_by_default': False, 'acknowledge_plaintext': True})
        self.assertFalse(changed['settings']['encrypt_by_default'])
        self.assertFalse(self.call(['status'])['settings']['encrypt_by_default'])
        started = self.call(['backup-start'], {'apps': ['woowbk-demo'], 'request_id': 'req-00000005'})
        self.assertFalse(self.params(started['job_id'])['encrypt'], 'the setting is the default choice')

    def test_restore_and_inspect_of_an_unencrypted_upload(self):
        backup_id = self.backup(encrypt=False)['backup_id']
        self.storage.index[backup_id]['type'] = 'uploaded'
        listed = self.call(['list'])['backups'][0]
        self.assertEqual((listed['encrypted'], listed['key_available'], listed['unauthenticated'], listed['format']),
                         (False, True, True, 2))
        inspected = self.call(['inspect'], {'backup_id': backup_id})
        self.assertEqual(inspected['manifest']['encryption'], 'none')
        warn = [c for c in inspected['preflight']['checks'] if c['id'] == 'unauthenticated']
        self.assertEqual(warn[0]['status'], 'warn')
        self.assertEqual(self.call(['inspect'], {'backup_id': backup_id, 'key': 'AGE-SECRET-KEY-1' + 'Q' * 58})
                         ['error']['code'], 'invalid-request')
        base = {'backup_id': backup_id, 'apps': ['woowbk-demo'], 'confirm': True}
        refused = self.call(['restore-start'], dict(base, request_id='req-00000006'))
        self.assertEqual(refused['error']['details']['field'], 'accept_unauthenticated')
        started = self.call(['restore-start'], dict(base, request_id='req-00000007', accept_unauthenticated=True))
        self.assertTrue(self.params(started['job_id'])['accept_unauthenticated'])

    def test_inplace_preflight_needs_the_device_key_only_while_safety_backups_are_encrypted(self):
        backup_id = self.backup()['backup_id']
        self.keys.import_key('AGE-SECRET-KEY-1' + 'Q' * 58)
        device = self.keys.device
        self.keys.device = None
        self.keys.imported.append(device)
        checks = self.call(['inspect'], {'backup_id': backup_id})['preflight']['apps'][0]['checks']
        self.assertIn('woowbk-demo/device-key', [c['id'] for c in checks])
        self.deps.encrypt_by_default = lambda: False
        checks = self.call(['inspect'], {'backup_id': backup_id})['preflight']['apps'][0]['checks']
        self.assertNotIn('woowbk-demo/device-key', [c['id'] for c in checks])


# ---------------------------------------------------------------------------- uploads of every format

@needs_age
class UploadFormatTests(unittest.TestCase):
    def setUp(self):
        self.ws = V2Workspace(self)
        self.storage = Storage(self.ws.paths, free_space=lambda path: 100 * GIB)
        self.storage.ensure_layout()

    def upload(self, data, filename):
        begun = self.storage.begin_upload(filename, len(data))
        Path(begun['path']).write_bytes(data)
        return self.storage.finish_upload(begun['upload_id'])

    def test_v2_encrypted_and_unencrypted_uploads(self):
        for encrypted in (True, False):
            with self.subTest(encrypted=encrypted):
                dest, _result, _payloads = self.ws.write_v2(encrypted=encrypted, name=f'u{int(encrypted)}.tar')
                data = dest.read_bytes()
                name = 'woowtech-backup-dev-a-20261113-020000.tar' if encrypted else 'My Copy.tar'
                meta = self.upload(data, name)
                self.assertEqual((meta['format'], meta['encrypted'], meta['type']), (2, encrypted, 'uploaded'))
                self.assertEqual(meta['key_id'], self.ws.key.key_id if encrypted else None)
                self.assertEqual(meta['sha256'], hashlib.sha256(data).hexdigest())
                self.assertEqual(meta['apps'], [], 'apps come from the authenticated manifests at inspect')
                self.assertEqual(meta['filename'], name if encrypted else
                                 'woowtech-backup-uploaded-20261113-020000.tar')
                stored = self.storage.archive_path(BACKUP_ID)
                self.assertEqual(stored.name, f'{BACKUP_ID}.tar')
                self.assertEqual(stored.read_bytes(), data)
                view = cli.backup_view(meta, set())
                self.assertEqual((view['key_available'], view['unauthenticated']), (not encrypted, not encrypted))
                self.assertEqual(self.storage.download_info(BACKUP_ID)['path'], os.path.realpath(stored))
                again = self.upload(data, 'again.tar')
                self.assertEqual(again['id'], BACKUP_ID, 'idempotent re-upload')
                self.storage.delete(BACKUP_ID)

    def test_a_damaged_v2_upload_is_refused_and_nothing_is_listed(self):
        dest, _result, _payloads = self.ws.write_v2()
        data = bytearray(dest.read_bytes())
        with tarfile.open(dest) as tar:
            member = tar.getmember(f'apps/{SECOND}.tar.zst.age')
        data[member.offset_data + member.size // 2] ^= 1
        with self.assertRaises(BackupError) as caught:
            self.upload(bytes(data), 'damaged.tar')
        self.assertEqual(caught.exception.code, 'corrupt-archive')
        self.assertEqual(os.listdir(self.ws.paths.archives), [])

    def test_a_v2_file_with_the_v1_extension_gets_a_matching_name(self):
        dest, _result, _payloads = self.ws.write_v2()
        meta = self.upload(dest.read_bytes(), 'woowtech-backup-dev-a-20261113-020000.woowbackup')
        self.assertEqual(meta['filename'], 'woowtech-backup-uploaded-20261113-020000.tar')

    def test_a_v1_upload_keeps_its_format(self):
        dest, _result, _entries = self.ws.write(demo_payloads(big=4096), name='old.woowbackup')
        meta = self.upload(dest.read_bytes(), 'woowtech-backup-dev-a-20261113-020000.woowbackup')
        self.assertEqual((meta['format'], meta['encrypted'], meta['filename']),
                         (1, True, 'woowtech-backup-dev-a-20261113-020000.woowbackup'))
        self.assertEqual(self.storage.archive_path(BACKUP_ID).name, f'{BACKUP_ID}.woowbackup')


# ---------------------------------------------------------------------------- unencrypted download copies

@needs_age
class ExportTests(unittest.TestCase):
    def setUp(self):
        self.ws = V2Workspace(self)
        self.paths = self.ws.paths
        self.storage = Storage(self.paths, free_space=lambda path: 100 * GIB)
        self.storage.ensure_layout()
        self.audit, self.scheduled, self.launched = [], [], []
        self.deps = flows.Deps(storage=self.storage, keys=self.ws.keys, archive=archive, load_catalog=lambda: {},
                               adapter_factory=None, host_info=lambda: dict(HOST), audit=self.audit.append,
                               schedule_cleanup=lambda seconds, export_id: self.scheduled.append((seconds, export_id)))
        self.payloads = dict(demo_payloads(big=1024 * 1024))
        self.payloads.update(second_payloads())
        self.backup_id = self.register(BACKUP_ID, fmt=2)

    def register(self, backup_id, *, fmt=2, encrypted=True, payloads=None):
        payloads = payloads or self.payloads
        entries = stage(self.ws.staging, payloads)
        apps = [demo_app(), second_app()] if any(p.startswith(f'apps/{SECOND}/') for p in payloads) else [demo_app()]
        manifest = demo_manifest(self.ws.key.key_id if encrypted else None, backup_id=backup_id, apps=apps)
        if fmt == 2:
            manifest.update(format=2, encryption='age-x25519' if encrypted else 'none')
        dest = self.storage.archive_path(backup_id, fmt)
        archive.write_archive(dest, None, manifest, entries, self.ws.key.recipient if encrypted else None,
                              tmp_dir=self.paths.archives)
        shutil.rmtree(self.ws.staging)
        self.ws.staging.mkdir(mode=0o700)
        self.storage.register(backup_id, {'type': 'manual', 'created': manifest['created'], 'note': '',
                                          'apps': [{'id': a['id'], 'name': a['name']} for a in apps],
                                          'key_id': manifest['key_id'], 'include_images': True,
                                          'source': {'hostname': 'dev-a'}, 'verified': None, 'inspected': True,
                                          'format': fmt, 'encrypted': encrypted})
        return backup_id

    def export(self, backup_id=None, reporter=None):
        ctx = flows.FlowContext(self.paths, JOB_ID, self.deps, reporter or FakeReporter())
        return flows.run_export(ctx, {'backup_id': backup_id or self.backup_id})

    def check_copy(self, result, payloads):
        path = self.storage.exports / f'{result["export_id"]}.tar'
        self.assertEqual(stat.S_IMODE(self.storage.exports.stat().st_mode), 0o700)
        st = path.stat()
        self.assertEqual((stat.S_IMODE(st.st_mode), st.st_uid), (0o600, os.geteuid()))
        self.assertEqual(result['size'], st.st_size)
        self.assertRegex(result['filename'], r'^woowtech-backup-dev-a-[0-9]{8}-[0-9]{6}-unencrypted\.tar$')
        self.assertEqual(archive.read_header(path)['encryption'], 'none')
        names = [name for name, _data in outer_members(path)]
        self.assertTrue(all(name.endswith('.tar.gz') for name in names[2:]), names)
        target = self.ws.dest(f'copy{len(list(self.ws.base.iterdir()))}')
        manifest = archive.extract_archive(path, [], target)
        self.assertEqual((manifest['encryption'], manifest['key_id'], manifest['backup_id']),
                         ('none', None, self.backup_id))
        for rel, data in payloads.items():
            self.assertEqual((target / rel).read_bytes(), data, rel)
        return path

    def test_copy_permissions_content_audit_and_timer(self):
        reporter = FakeReporter()
        result = self.export(reporter=reporter)
        self.assertEqual(set(result), {'export_id', 'backup_id', 'filename', 'size', 'expires'})
        self.check_copy(result, self.payloads)
        self.assertEqual([e[1] for e in reporter.events if e[0] == 'phase'], list(flows.EXPORT_PHASES))
        self.assertRegex(self.audit[-1], rf'^export-unencrypted-created backup={self.backup_id} '
                                         rf'export={result["export_id"]} size={result["size"]} sha256=[0-9a-f]{{64}} '
                                         rf'job={JOB_ID}$')
        self.assertEqual(self.scheduled, [(EXPORT_TTL + 5, result['export_id'])])
        self.assertFalse((self.paths.staging / JOB_ID).exists(), 'plaintext staging removed')
        self.assertEqual(tool_children(), [])

    def test_copy_expires(self):
        result = self.export()
        info = self.storage.export_info(result['export_id'], now=result['expires'] - 1)
        self.assertEqual(Path(info['path']).parent, self.storage.exports)
        self.assertEqual(self.storage.cleanup_exports(now=result['expires'] - 1), [])
        self.assertEqual(self.storage.cleanup_exports(now=result['expires'] + 1), [result['export_id']])
        self.assertEqual(os.listdir(self.storage.exports), [])
        with self.assertRaises(BackupError) as caught:
            self.storage.export_info(result['export_id'])
        self.assertEqual(caught.exception.code, 'not-found')

    def test_v1_source_and_refusals(self):
        old_payloads = demo_payloads(big=4096)  # random bytes: generated once
        old_id = self.register('20261113T010000Z-0000000a', fmt=1, payloads=old_payloads)
        result = self.export(old_id)
        self.backup_id = old_id
        self.check_copy(result, old_payloads)
        plain_id = self.register('20261113T010000Z-0000000b', encrypted=False, payloads=demo_payloads(big=4096))
        with self.assertRaises(BackupError) as caught:
            self.export(plain_id)
        self.assertEqual(caught.exception.code, 'invalid-request')
        for item in list(self.ws.keys.dir.iterdir()):
            if item.name.startswith('device-'):
                item.unlink()
        with self.assertRaises(BackupError) as caught:
            self.export(BACKUP_ID)
        self.assertEqual(caught.exception.code, 'key-required')

    def test_cancel_leaves_no_copy(self):
        reporter = FakeReporter()
        reporter.cancel = True
        with self.assertRaises(flows.Cancelled):
            self.export(reporter=reporter)
        self.assertEqual(os.listdir(self.storage.exports), [])
        self.assertFalse((self.paths.staging / JOB_ID).exists())
        self.assertEqual(tool_children(), [])

    def test_cli_commands_and_cleanup_on_status(self):
        import io

        def call(argv, request=None):
            out = io.StringIO()
            stdin = io.StringIO(json.dumps(request)) if request is not None else None
            services = cli.Services(self.paths, deps=self.deps, launcher=self.launched.append,
                                    unit_active=lambda unit: False, trusted_uid=os.geteuid())
            cli.main(argv, stdin=stdin, stdout=out, services=services, require_root=False)
            return json.loads(out.getvalue())

        self.assertEqual(call(['export-start'], {'backup_id': self.backup_id, 'request_id': 'req-00000001'})
                         ['error']['code'], 'invalid-request', 'explicit confirmation required')
        started = call(['export-start'], {'backup_id': self.backup_id, 'request_id': 'req-00000001', 'confirm': True})
        self.assertRegex(self.audit[-1], rf'^export-unencrypted-request backup={self.backup_id} '
                                         rf'job={started["job_id"]} loginuid=')
        self.assertEqual(call(['run-job', started['job_id']])['state'], 'succeeded')
        job = call(['job-status'], {'job_id': started['job_id']})['job']
        self.assertEqual([p['id'] for p in job['phases']], ['prepare', 'decrypt', 'package', 'verify'])
        export_id = job['result']['export_id']
        listed = call(['list'])
        self.assertEqual([e['export_id'] for e in listed['exports']], [export_id])
        info = call(['export-info'], {'export_id': export_id})
        self.assertEqual(set(info), {'ok', 'path', 'filename', 'size', 'expires', 'backup_id'})
        self.assertTrue(info['path'].endswith(f'/exports/{export_id}.tar'))
        self.assertTrue(self.audit[-1].startswith(f'export-unencrypted-download export={export_id} '))
        self.assertEqual(call(['export-info'], {'export_id': '../../etc/passwd'})['error']['code'], 'invalid-request')
        side = self.storage.exports / f'{export_id}.json'
        record = json.loads(side.read_text())
        record['expires'] = 1
        side.write_text(json.dumps(record))
        self.assertTrue(call(['status'])['ok'])
        self.assertEqual(os.listdir(self.storage.exports), [], 'the next status deleted the expired copy')
        self.assertEqual(self.audit[-1], f'export-unencrypted-deleted export={export_id} reason=expired')
        self.assertEqual(call(['export-info'], {'export_id': export_id})['error']['code'], 'not-found')
        again = call(['export-start'], {'backup_id': self.backup_id, 'request_id': 'req-00000002', 'confirm': True})
        call(['run-job', again['job_id']])
        second = call(['job-status'], {'job_id': again['job_id']})['job']['result']['export_id']
        self.assertEqual(call(['export-delete'], {'export_id': second}), {'ok': True, 'deleted': True})
        self.assertRegex(self.audit[-1], rf'^export-unencrypted-deleted export={second} reason=request loginuid=')
        self.assertEqual(call(['export-cleanup']), {'ok': True, 'removed': []})

    def test_at_most_two_copies(self):
        ids = [self.export()['export_id'] for _ in range(3)]
        left = sorted(name[:-4] for name in os.listdir(self.storage.exports) if name.endswith('.tar'))
        self.assertEqual(left, sorted(ids[1:]), 'the oldest copy goes first')
        # review F17: the eviction is journaled like every other deletion of a plaintext copy
        self.assertIn(f'export-unencrypted-deleted export={ids[0]} reason=evicted job={JOB_ID}', self.audit)

    def test_the_timer_is_set_before_the_copy_is_published(self):
        # review L1: a job that dies right after publishing still has its copy deleted on time
        seen = []
        self.deps.schedule_cleanup = lambda seconds, export_id: seen.append(
            (export_id, (self.storage.exports / f'{export_id}.tar').exists()))
        result = self.export()
        self.assertEqual(seen, [(result['export_id'], False)])

    def call(self, argv, request=None):
        import io
        out = io.StringIO()
        stdin = io.StringIO(json.dumps(request)) if request is not None else None
        services = cli.Services(self.paths, deps=self.deps, launcher=self.launched.append,
                                unit_active=lambda unit: False, trusted_uid=os.geteuid())
        cli.main(argv, stdin=stdin, stdout=out, services=services, require_root=False)
        return json.loads(out.getvalue())

    def expire(self, export_id):
        side = self.storage.exports / f'{export_id}.json'
        record = json.loads(side.read_text())
        record['expires'] = 1
        side.write_text(json.dumps(record))

    def test_every_path_that_deletes_an_expired_copy_journals_it(self):
        # review L1, F17: export-info deletes expired copies on the way; recovery passes and run-job delete them too
        first, second = self.export()['export_id'], self.export()['export_id']
        self.expire(first)
        self.assertEqual(self.call(['export-info'], {'export_id': second})['ok'], True)
        self.assertIn(f'export-unencrypted-deleted export={first} reason=expired', self.audit)
        self.assertFalse((self.storage.exports / f'{first}.tar').exists())
        self.expire(second)
        self.assertEqual(self.call(['export-info'], {'export_id': second})['error']['code'], 'not-found')
        self.assertIn(f'export-unencrypted-deleted export={second} reason=expired', self.audit)
        third = self.export()['export_id']
        self.expire(third)
        self.call(['jobs'])  # any recovery pass (status, jobs, delete, start ...) deletes it, also after a reboot
        self.assertFalse((self.storage.exports / f'{third}.tar').exists())
        self.assertIn(f'export-unencrypted-deleted export={third} reason=expired', self.audit)
        fourth = self.export()['export_id']
        self.expire(fourth)
        verify = self.call(['verify-start'], {'backup_id': self.backup_id, 'request_id': 'req-00000009'})
        self.call(['run-job', verify['job_id']])
        self.assertFalse((self.storage.exports / f'{fourth}.tar').exists(), 'deleted before any job runs')

    def test_plaintext_downloads_and_every_deletion_are_journaled(self):
        # review L6: an unencrypted backup leaving the device and any deleted backup appear in the journal
        plain = self.register('20261113T010000Z-0000000b', encrypted=False, payloads=demo_payloads(big=4096))
        self.assertEqual(self.call(['download-info'], {'backup_id': self.backup_id})['ok'], True)
        self.assertFalse([line for line in self.audit if line.startswith('download-unencrypted')],
                         'an encrypted download is not a plaintext event')
        self.call(['download-info'], {'backup_id': plain})
        self.assertRegex(self.audit[-1], rf'^download-unencrypted backup={plain} loginuid=')
        self.assertEqual(self.call(['delete'], {'backup_id': plain}), {'ok': True})
        self.assertRegex(self.audit[-1], rf'^backup-delete backup={plain} type=manual encrypted=false loginuid=')
        self.call(['delete'], {'backup_id': self.backup_id})
        self.assertRegex(self.audit[-1], rf'^backup-delete backup={self.backup_id} type=manual encrypted=true ')


if __name__ == '__main__':
    unittest.main()
