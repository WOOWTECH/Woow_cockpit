"""Host directories (catalog `data_dirs`) in QuadletPostgresAdapter.

The owner is the stateful fake of test_adapter (podman, systemctl, file helper), except for the host-directory
helper: DIR_HELPER and GNU tar run for real against a temp HOME, with `podman unshare` taken off. Covered: the exact
argv (pack through the relay, unpack/swap after the volumes), symlink refusal, the export check with the owner's ID
map, the writers warning, fresh-mode parents and conflicts, the namespace capacity check, the swap / finish /
discard / rollback rules, interruption recovery at every step (never deleting the only copy), and archives without
`data_dirs`.
"""
import json
import os
import re
import shutil
import stat
import tarfile
import tempfile
import unittest
from unittest import mock
from pathlib import Path

from woowbackup import catalog, nested, podman
from woowbackup.adapters import quadlet_postgres as qp
from woowbackup.errors import BackupError

from .test_adapter import (APP_ID, ID_MAPS, PG_ID, PG_REF, APP_REF, PODMAN, PYTHON, Q, SCOPE, MAINTENANCE, SYSTEMCTL,
                           AdapterCase, FakeOwner, extract_entries, helper, psql)
from .test_catalog import demo_entry, lookup as user_lookup

DIR_HELPER = podman.DIR_HELPER
UNSHARE = [PODMAN, 'unshare', PYTHON, '-I', '-c', DIR_HELPER]
JOB = 'j20261113T020000Z-a1b2c3d4'
ROLLBACK = JOB + '-rollback'
HTML, DATA = '.local/share/woowbk-demo/html', 'woowbk-demo-data'


def dir_call(op, *args):
    return [*UNSHARE, op, *args]


def pack_call(rel):
    return helper('relay', *UNSHARE, 'pack', rel)


def dirs_entry(paths, *, cold=False):
    entry = demo_entry(paths)
    entry['data_dirs'] = [{'path': HTML, 'label': '網站程式'}, {'path': DATA}]
    if cold:  # PostgreSQL kept as files: no pg_dump entry, the database unit is a writer and stops too
        entry.update(postgres=[], writer_units=list(entry['units']))
    return entry


class DirOwner(FakeOwner):
    """FakeOwner whose DIR_HELPER commands run for real (as the current user, HOME = a temp home)."""

    def __init__(self, home, deployed=True):
        super().__init__(deployed)
        self.home = Path(home)
        self.home.mkdir(exist_ok=True)
        self.dir_ops = []
        self.dir_fail = {}  # op -> exit status injected instead of running it
        self.dir_hook = None  # callable(op, args) run before an op (simulates what happens meanwhile)
        self.dir_answers = {}  # (op, first argument) -> what the helper prints instead (bytes, or data as JSON)

    @staticmethod
    def text(inner):
        return ' '.join('HELPER' if part == podman.FILE_HELPER else 'DIRHELPER' if part == DIR_HELPER else part
                        for part in inner)

    def dispatch(self, inner, data, stdout):
        if inner[:6] == UNSHARE:
            return self.dir_helper(inner[6:], data, stdout)
        if inner[:5] == [PYTHON, '-I', '-c', podman.FILE_HELPER, 'relay'] and inner[5:11] == UNSHARE:
            return self.dir_helper(inner[11:], data, stdout)
        return super().dispatch(inner, data, stdout)

    def dir_helper(self, args, data, stdout):
        self.dir_ops.append(list(args))
        if self.dir_hook:
            self.dir_hook(args[0], args[1:])
        if args[0] in self.dir_fail:
            return podman.Result(self.dir_fail[args[0]], b'', b'injected failure\n')
        answer = self.dir_answers.get((args[0], args[1] if len(args) > 1 else None))
        if answer is not None:  # e.g. a helper the owner replaced inside his namespace (review M1)
            return podman.Result(0, answer if isinstance(answer, bytes) else json.dumps(answer).encode(), b'')
        env = {'HOME': str(self.home), 'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}
        return podman.default_runner([PYTHON, '-I', '-c', DIR_HELPER, *args], input=data, stdout=stdout, env=env,
                                     timeout=120)


def snapshot(root):
    """{path: (kind, mode, content)} of a real directory tree (None when it does not exist)."""
    root = Path(root)
    if not root.exists():
        return None
    rows = {}
    for folder, dirs, files in os.walk(root):
        for name in dirs + files:
            path = Path(folder) / name
            st = os.lstat(path)
            content = path.read_bytes() if stat.S_ISREG(st.st_mode) else (
                os.readlink(path).encode() if stat.S_ISLNK(st.st_mode) else b'')
            rows[str(path.relative_to(root))] = (stat.S_IFMT(st.st_mode), stat.S_IMODE(st.st_mode), content)
    return rows


class DirCase(AdapterCase):
    cold = False

    def setUp(self):
        super().setUp()
        self.app = catalog.validate_entry(dirs_entry(self.paths, cold=self.cold), paths=self.paths,
                                          user_lookup=user_lookup)
        self.home = self.root / 'home'
        self.owner = self.new_owner()
        self.adapter = self.make_adapter()

    def new_owner(self, deployed=True, populate=True):
        owner = DirOwner(self.home, deployed)
        if populate and not (self.home / HTML).exists():
            self.populate()
        return owner

    def populate(self, marker='v1'):
        """Two directories like an app's; as root (the test runner) some files belong to container users."""
        html = self.home / HTML
        html.mkdir(parents=True)
        (html / 'index.php').write_text(f'<?php echo "{marker}";\n')
        (html / 'config').mkdir(mode=0o750)
        (html / 'config' / 'config.php').write_text(f'secret={marker}\n')
        os.chmod(html / 'config' / 'config.php', 0o640)
        os.symlink('index.php', html / 'current')
        os.symlink('../../../shared.yaml', html / 'outside-link')
        data = self.home / DATA
        data.mkdir()
        (data / 'app.sqlite').write_bytes(b'SQLite format 3\x00' + marker.encode() * 100)
        (data / 'app.sqlite-wal').write_bytes(b'wal-' + marker.encode())
        os.chmod(data, 0o700)
        if os.geteuid() == 0:
            os.chown(data / 'app.sqlite', 70, 70)
            os.chown(html / 'config' / 'config.php', 33, 33)

    def make_adapter(self, owner=None, job_id=JOB):
        adapter = super().make_adapter(owner or self.owner)
        adapter.job_id = job_id
        return adapter


GOLDEN_DIR_BACKUP_TAIL = [
    helper('relay', PODMAN, 'volume', 'export', 'woowbk-demo-files'),
    pack_call(HTML), pack_call(DATA),
    [PODMAN, 'secret', 'inspect', '--showsecret', '--format', '{{.SecretData}}', 'woowbk-demo-db-password'],
    [PODMAN, 'secret', 'inspect', '--showsecret', '--format', '{{.SecretData}}', 'woowbk-demo-app-key'],
    helper('read', '.config/woowbk-demo/app.env', '16777216'),
    [SYSTEMCTL, '--user', 'start', '--', 'woowbk-demo-app.service'],
    *ID_MAPS,  # the volume and directory exports are checked like a restore checks them, after the restart
]


class DirBackupTests(DirCase):
    def test_exports_through_the_relay_and_records_the_directories(self):
        manifest, entries = self.run_backup()
        argvs = self.owner.argvs()
        self.assertEqual(argvs[-len(GOLDEN_DIR_BACKUP_TAIL):], GOLDEN_DIR_BACKUP_TAIL)
        stop = argvs.index([SYSTEMCTL, '--user', 'stop', '--', 'woowbk-demo-app.service'])
        self.assertLess(stop, argvs.index(pack_call(HTML)), 'read while the writers are stopped')
        self.assertEqual(manifest['data_dirs'], [{'path': HTML, 'entry': 'apps/woowbk-demo/dirs/0.tar'},
                                                 {'path': DATA, 'entry': 'apps/woowbk-demo/dirs/1.tar'}])
        paths = [e.path for e in entries]
        self.assertEqual(paths[1:4], ['apps/woowbk-demo/volumes/woowbk-demo-files.tar', 'apps/woowbk-demo/dirs/0.tar',
                                      'apps/woowbk-demo/dirs/1.tar'])
        tar = next(e for e in entries if e.path.endswith('dirs/0.tar'))
        with tarfile.open(tar.source, 'r:') as handle:
            names = handle.getnames()
        self.assertEqual(names[0], '.', 'the root entry carries the directory itself')
        self.assertIn('./config/config.php', names)
        self.assertEqual(stat.S_IMODE(tar.source.stat().st_mode), 0o600)
        logged = self.everything_logged()
        self.assertIn(f'匯出主機資料夾 ~/{HTML}', logged)
        self.assertIn(f'主機資料夾 ~/{HTML} 有 1 個符號連結指向資料夾以外', logged)

    def test_apps_without_directories_keep_the_old_manifest_shape(self):
        app = catalog.validate_entry(demo_entry(self.paths), paths=self.paths, user_lookup=user_lookup)
        adapter = qp.QuadletPostgresAdapter(app, podman.OwnerRunner('appowner', runner=FakeOwner(),
                                                                    user_lookup=user_lookup),
                                            self.logs.append, http_get=self.http, clock=self.clock.now,
                                            sleep=self.clock.sleep, runtime_ready=lambda: True)
        manifest, _ = adapter.backup(self.staging / 'plain', include_images=False)
        self.assertNotIn('data_dirs', manifest, 'older engines can still read archives of apps without directories')

    def test_cold_database_pattern_stops_the_database_too(self):
        self.cold = True
        self.app = catalog.validate_entry(dirs_entry(self.paths, cold=True), paths=self.paths, user_lookup=user_lookup)
        adapter = self.make_adapter()
        manifest, _ = adapter.backup(self.staging / 'cold', include_images=False)
        stops = [a[-1] for a in self.owner.argvs() if a[:3] == [SYSTEMCTL, '--user', 'stop']]
        starts = [a[-1] for a in self.owner.argvs() if a[:3] == [SYSTEMCTL, '--user', 'start']]
        self.assertEqual(stops, ['woowbk-demo-app.service', 'woowbk-demo-db.service'])
        self.assertEqual(starts, ['woowbk-demo-db.service', 'woowbk-demo-app.service'])
        self.assertEqual(manifest['postgres'], [])
        self.assertNotIn('pg_dump', ' '.join(self.owner.text(a) for a in self.owner.argvs()))

    def test_a_symlinked_directory_fails_and_the_writers_run_again(self):
        shutil.rmtree(self.home / DATA)
        os.symlink(self.home / HTML, self.home / DATA)
        with self.assertRaises(BackupError) as caught:
            self.run_backup()
        self.assertEqual(caught.exception.code, 'permission-denied')
        self.assertIn(f'~/{DATA} 不是資料夾，或路徑中含有符號連結', caught.exception.message)
        self.assertEqual(self.owner.units['woowbk-demo-app.service'], 'active')

    def test_owners_outside_the_namespace_fail_the_backup_after_the_restart(self):
        self.owner.id_map = '0 1001 1\n'  # only the owner himself: container users (and the test user) are outside
        with self.assertRaises(BackupError) as caught:
            self.run_backup()
        self.assertEqual(caught.exception.code, 'job-failed')
        self.assertIn('含有還原時無法寫入的內容（擁有者 UID', caught.exception.message)
        self.assertEqual(self.owner.units['woowbk-demo-app.service'], 'active')

    def test_estimate_measures_inside_the_namespace(self):
        total = self.adapter.estimate_bytes()
        self.assertIn(dir_call('measure', HTML), self.owner.argvs())
        self.assertIn(dir_call('measure', DATA), self.owner.argvs())
        self.assertGreater(total, 1024 * 1024 + 8000000)
        shutil.rmtree(self.home / DATA)
        with self.assertRaises(BackupError) as caught:  # before any writer is stopped
            self.adapter.estimate_bytes()
        self.assertEqual(caught.exception.code, 'not-found')

    def test_running_containers_writing_into_a_directory_must_be_stopped(self):
        # Review M5: whatever started it (Quadlet Volume=/Mount=, a pod, by hand), a running container that can write
        # into a host directory and is not a writer stopped by the backup fails it before anything stops. A writer's
        # own container and a read-only mount are fine.
        home = '/home/appowner'
        self.owner.bind_mounts = [
            {'id': 'a' * 12, 'name': 'woowbk-demo-app', 'unit': 'woowbk-demo-app.service', 'source': f'{home}/{HTML}',
             'rw': True},
            {'id': 'b' * 12, 'name': 'viewer', 'unit': None, 'source': f'{home}/{DATA}', 'rw': False}]
        self.run_backup()
        for extra, needle in (
                ({'id': 'c' * 12, 'name': 'sidecar', 'unit': 'other.service', 'source': f'{home}/{DATA}/db', 'rw': True},
                 f'服務 other.service 的容器 sidecar 以可寫入方式掛載了 ~/{DATA}/db（與主機資料夾 ~/{DATA} 重疊）'),
                ({'id': 'd' * 12, 'name': 'shell', 'unit': None, 'source': home, 'rw': True},
                 f'容器 shell 以可寫入方式掛載了整個家目錄（包含主機資料夾 ~/{HTML}）')):
            with self.subTest(extra['name']):
                owner = self.new_owner()
                owner.units['other.service'] = 'active'
                owner.bind_mounts = self.owner.bind_mounts + [extra]
                with self.assertRaises(BackupError) as caught:
                    self.make_adapter(owner).backup(self.staging / extra['name'], include_images=False)
                self.assertEqual(caught.exception.code, 'incompatible')
                self.assertIn(needle, caught.exception.message)
                self.assertIn('請先停止它，或把它的服務加入這個應用的 writer_units', caught.exception.message)
                self.assertFalse(any(a[:3] == [SYSTEMCTL, '--user', 'stop'] for a in owner.argvs()), 'nothing stopped')

    def test_mount_points_fail_the_backup_before_anything_stops(self):
        # Review M2: tar stays on one filesystem, so content below a mount point would be missing, and a restore can
        # neither rename a mount point nor delete the replaced copy without entering the other filesystem.
        for answer, needle in (({'mount_root': True, 'mounts': [], 'more_mounts': 0}, '是另一個檔案系統的掛載點'),
                               ({'mount_root': False, 'mounts': ['db/disk'], 'more_mounts': 2},
                                f'中有其他檔案系統的掛載點（~/{DATA}/db/disk等 3 處）')):
            with self.subTest(needle):
                owner = self.new_owner()
                owner.dir_answers = {('measure', DATA): {'bytes': 1, 'members': 1, 'acls': 0, **answer}}
                with self.assertRaises(BackupError) as caught:
                    self.make_adapter(owner).backup(self.staging / str(len(needle)), include_images=False)
                self.assertEqual(caught.exception.code, 'incompatible')
                self.assertIn(needle, caught.exception.message)
                self.assertFalse(any(a[:3] == [SYSTEMCTL, '--user', 'stop'] for a in owner.argvs()), 'nothing stopped')
        owner = self.new_owner()
        owner.dir_answers = {('measure', DATA): {'bytes': 1, 'members': 1, 'acls': 3, 'mount_root': False, 'mounts': [],
                                                 'more_mounts': 0}}
        self.make_adapter(owner).backup(self.staging / 'acls', include_images=False)
        self.assertIn(f'主機資料夾 ~/{DATA} 有 3 個項目設定了 POSIX ACL 權限；備份不包含 ACL', self.everything_logged())

    def test_owner_controlled_answers_are_checked(self):
        # Review M1: the helper runs in a namespace the owner controls; any other shape is a BackupError.
        for bad in (b'[]', b'{"bytes": "1"}', b'[' * 100000 + b']' * 100000, b'\xff', b'{"bytes": true, "members": 1}'):
            with self.subTest(bad[:20]):
                owner = self.new_owner()
                owner.dir_answers = {('measure', DATA): bad}
                with self.assertRaises(BackupError) as caught:
                    self.make_adapter(owner).backup(self.staging / 'bad', include_images=False)
                self.assertEqual(caught.exception.code, 'job-failed')
                self.assertIn('結果格式不正確', caught.exception.message)


class DirRestoreCase(DirCase):
    def setUp(self):
        super().setUp()
        self.manifest, self.entries = self.run_backup()
        self.original = {rel: snapshot(self.home / rel) for rel in (HTML, DATA)}
        self.extract = self.root / 'extract'
        self.extract.mkdir(mode=0o700)
        extract_entries(self.entries, self.extract)
        self.logs.clear()
        self.phases.clear()

    def mutate(self):
        (self.home / HTML / 'index.php').write_text('changed')
        (self.home / HTML / 'added-after-backup.txt').write_text('new file')
        (self.home / DATA / 'app.sqlite').write_bytes(b'changed')

    def siblings(self, rel):
        parent = (self.home / rel).parent
        name = Path(rel).name
        return sorted(p.name[len(name):] for p in parent.iterdir() if p.name.startswith(name + '.woowbk-'))


class DirRestoreTests(DirRestoreCase):
    def test_inplace_exact_argv_order_and_content(self):
        self.mutate()
        owner = self.new_owner()
        adapter = self.make_adapter(owner)
        adapter.restore(self.manifest, self.extract, mode='inplace')
        argvs = owner.argvs()
        unpack_at = argvs.index(dir_call('unpack', HTML, JOB))
        self.assertEqual(argvs[unpack_at + 1], dir_call('unpack', DATA, JOB))
        self.assertLess(argvs.index([SYSTEMCTL, '--user', 'stop', '--', 'woowbk-demo-db.service']), unpack_at,
                        'written only once every unit is stopped')
        # Review M3: both copies are written before anything that exists changes (secrets, volumes, the database).
        self.assertLess(unpack_at, min(i for i, a in enumerate(argvs) if a[:3] in ([PODMAN, 'secret', 'create'],
                                                                                   [PODMAN, 'volume', 'rm'])))
        import_at = argvs.index([PODMAN, 'volume', 'import', 'woowbk-demo-files', '-'])
        self.assertEqual(argvs[import_at + 1:import_at + 6], [
            [PODMAN, 'volume', 'rm', '-f', 'woowbk-demo-pgdata'],
            [PODMAN, 'ps', '--format', '{{.ID}}'],  # no container may still use a directory (review M5)
            dir_call('swap', HTML, JOB, 'inplace'), dir_call('swap', DATA, JOB, 'inplace'),
            [SYSTEMCTL, '--user', 'start', '--', 'woowbk-demo-db.service']])
        unpack = next(c for c in owner.calls if c['argv'] == dir_call('unpack', HTML, JOB))
        self.assertEqual(unpack['kind'], 'stream', 'GNU tar only ever reads the canonical stream')
        for rel in (HTML, DATA):
            self.assertEqual(snapshot(self.home / rel), self.original[rel], rel)
            self.assertEqual(self.siblings(rel), [f'.woowbk-old-{JOB}'], 'the old copy stays until the job succeeded')
        self.assertEqual(snapshot(self.home / (HTML + f'.woowbk-old-{JOB}'))['added-after-backup.txt'][2], b'new file')
        self.assertEqual(adapter.finish_dirs(), [])
        self.assertEqual(owner.argvs()[-2:], [dir_call('drop', HTML, 'old', JOB), dir_call('drop', DATA, 'old', JOB)])
        self.assertEqual((self.siblings(HTML), self.siblings(DATA)), ([], []))
        self.assertIn(f'已刪除 ~/{HTML}.woowbk-old-{JOB}（原內容）', self.everything_logged())

    def test_destructive_flag_and_discard_after_a_failed_extraction(self):
        owner = self.new_owner()
        owner.dir_fail = {'swap': 11}
        adapter = self.make_adapter(owner)
        with self.assertRaises(BackupError):
            adapter.restore(self.manifest, self.extract, mode='inplace')
        self.assertTrue(adapter.destructive_started)
        self.assertEqual(self.siblings(HTML), [f'.woowbk-new-{JOB}'])
        owner.dir_fail = {}
        self.assertEqual(adapter.discard_dirs(), [])
        self.assertEqual(self.siblings(HTML), [])
        self.assertEqual(snapshot(self.home / HTML), self.original[HTML], 'never touched')

    def test_archive_without_data_dirs_is_incompatible_when_the_catalog_declares_them(self):
        manifest = json.loads(json.dumps(self.manifest))
        del manifest['data_dirs']
        owner = self.new_owner()
        with self.assertRaises(BackupError) as caught:
            self.make_adapter(owner).restore(manifest, self.extract, mode='inplace')
        self.assertEqual(caught.exception.code, 'incompatible')
        self.assertIn(f'主機資料夾 ~/{HTML}', caught.exception.message)
        self.assertEqual(owner.dir_ops, [])
        checks = self.make_adapter(self.new_owner()).preflight(manifest, mode='inplace')
        items = next(c for c in checks if c['id'] == 'woowbk-demo/items')
        self.assertEqual(items['status'], 'fail')

    def test_extra_directories_in_the_archive_are_ignored(self):
        manifest = json.loads(json.dumps(self.manifest))
        manifest['data_dirs'].append({'path': '.ssh', 'entry': 'apps/woowbk-demo/dirs/1.tar'})
        owner = self.new_owner()
        self.make_adapter(owner).restore(manifest, self.extract, mode='inplace')
        self.assertFalse((self.home / '.ssh').exists(), 'the local catalog alone decides what is written')
        checks = self.make_adapter(self.new_owner()).preflight(manifest, mode='inplace')
        extra = next(c for c in checks if c['id'] == 'woowbk-demo/extra')
        self.assertIn('主機資料夾 ~/.ssh', extra['message'])

    def test_hostile_directory_tar_is_refused_before_any_change(self):
        victim = self.extract / 'apps/woowbk-demo/dirs/0.tar'
        from .test_nested import gnu_dir_tar
        victim.write_bytes(gnu_dir_tar([{'name': '.', 'type': tarfile.DIRTYPE, 'mode': 0o755},
                                        {'name': './link', 'type': tarfile.SYMTYPE, 'linkname': str(self.home / '.ssh')},
                                        {'name': './link/authorized_keys', 'data': b'ssh-ed25519 AAAA'}]))
        owner = self.new_owner()
        with self.assertRaises(BackupError) as caught:
            self.make_adapter(owner).restore(self.manifest, self.extract, mode='inplace')
        self.assertEqual(caught.exception.code, 'corrupt-archive')
        self.assertFalse(any(a[:3] == [SYSTEMCTL, '--user', 'stop'] for a in owner.argvs()))
        self.assertEqual(owner.dir_ops, [])
        self.assertFalse((self.home / '.ssh').exists())

    def test_namespace_capacity_is_checked_before_any_change(self):
        owner = self.new_owner()
        owner.id_map = '0 1007 1\n1 10500 10\n'  # a target owner whose subordinate range is too small (ids 0-10)
        adapter = self.make_adapter(owner)
        checks = adapter.preflight(self.manifest, mode='inplace', extracted_dir=self.extract,
                                   entry_sizes={e.path: e.size for e in self.entries})
        failing = [c for c in checks if c['status'] == 'fail']
        self.assertTrue(failing and failing[0]['id'] == 'woowbk-demo/dir-archive', checks)
        self.assertIn('超出這台設備應用帳號可用的 ID 範圍', failing[0]['message'])
        with self.assertRaises(BackupError) as caught:
            self.make_adapter(owner).restore(self.manifest, self.extract, mode='inplace')
        self.assertEqual(caught.exception.code, 'incompatible')
        self.assertLessEqual({op[0] for op in owner.dir_ops}, {'state', 'mounts'}, 'only read: nothing was written')

    def test_preflight_reports_target_state_capacity_and_space(self):
        sizes = {e.path: e.size for e in self.entries}
        checks = self.adapter.preflight(self.manifest, mode='inplace', extracted_dir=self.extract, entry_sizes=sizes)
        by_id = {}
        for check in checks:  # ids repeat with a -<n> suffix: woowbk-demo/dir-target, woowbk-demo/dir-target-2
            by_id.setdefault(re.sub(r'-[0-9]+$', '', check['id'].split('/', 1)[1]), []).append(check)
        self.assertEqual([c['status'] for c in by_id['dir-target']], ['ok', 'ok'])
        self.assertIn(f'整個取代主機資料夾 ~/{HTML}', by_id['dir-target'][0]['message'])
        self.assertTrue(all(c['status'] == 'ok' for c in by_id['dir-ids']))
        self.assertIn('最大 UID', by_id['dir-ids'][0]['message'])
        self.assertIn('應用資料所在磁碟空間足夠', by_id['space'][0]['message'])
        self.assertEqual([c['status'] for c in by_id['dir-mounts']] if 'dir-mounts' in by_id else [], [])
        self.assertNotIn('fail', [c['status'] for c in checks], checks)
        inspect = self.adapter.preflight(self.manifest, mode='inplace', entry_sizes=sizes)  # no extracted archive
        ids = [c for c in inspect if c['id'] == 'woowbk-demo/dir-ids']
        self.assertEqual(len(ids), 1)
        self.assertIn('UID 0–0、1–55000', ids[0]['message'])
        shutil.rmtree(self.home / DATA)
        missing = self.adapter.preflight(self.manifest, mode='inplace')
        self.assertEqual([c['status'] for c in missing if c['id'].startswith('woowbk-demo/dir-target')], ['ok', 'warn'])
        os.mkdir(self.home / (HTML + '.woowbk-old-j20261101T000000Z-00000000'))
        leftover = [c for c in self.adapter.preflight(self.manifest, mode='inplace') if 'dir-leftover' in c['id']]
        self.assertEqual(leftover[0]['status'], 'warn')
        self.self_free_space_check(sizes)

    def self_free_space_check(self, sizes):
        need = sum(sizes.values())
        for free, status in ((2 * need + qp.SPACE_RESERVE - 4096, 'fail'), (2 * need + qp.SPACE_RESERVE + 4096, 'ok')):
            self.free = free
            for mode in ('inplace', 'fresh'):
                owner = self.new_owner(deployed=mode == 'inplace')
                space = [c for c in self.make_adapter(owner).preflight(self.manifest, mode=mode, entry_sizes=sizes)
                         if c['id'] == 'woowbk-demo/space']
                # Review M3: a rollback moves the replaced copy back, so no room for a third copy is required.
                self.assertEqual(space[0]['status'], status, (mode, free))

    def test_a_directory_on_another_filesystem_counts_there(self):
        sizes = {e.path: e.size for e in self.entries}
        html = next(path for path in sizes if path.endswith('/dirs/0.tar'))
        adapter = self.make_adapter()
        checks = []
        adapter._dir_space = {HTML: (4242, sizes[html] + qp.SPACE_RESERVE - 1), DATA: (None, None)}
        home = os.stat(self.home)
        with mock.patch.object(qp.os, 'stat', return_value=home):
            adapter._preflight_space(self.manifest, sizes, lambda *check: checks.append(check))
        self.assertEqual(checks[0][1], 'fail', checks)
        self.assertIn(f'~/{HTML} 所在磁碟需要約', checks[0][2])
        self.assertNotIn('家目錄所在磁碟', checks[0][2], 'the home has room for the rest')

    def test_preflight_refuses_mount_points_podman_storage_and_other_users(self):
        home = '/home/appowner'
        row = {'type': 'dir', 'empty': False, 'mount': False, 'dev': 1, 'free': 1 << 40, 'siblings': [], 'more': 0}
        cases = [
            # Review M2: the directory is a mount point (cannot be renamed), or holds one (moved and deleted with it).
            ('state', lambda o: o.dir_answers.update({('state', '-'): [{**row, 'path': HTML, 'mount': True},
                                                                       {**row, 'path': DATA}]}),
             'dir-target', f'~/{HTML} 是另一個檔案系統的掛載點'),
            ('mounts', lambda o: o.dir_answers.update({('mounts', DATA): {'mount_root': False, 'mounts': ['cache'],
                                                                         'more_mounts': 0}}),
             'dir-mounts', f'主機資料夾 ~/{DATA} 中有其他檔案系統的掛載點（~/{DATA}/cache）'),
            # Review L1: a storage.conf moved the Podman storage into a declared directory.
            ('storage', lambda o: setattr(o, 'storage', (f'{home}/{DATA}/storage', f'{home}/{DATA}/storage/volumes')),
             'dir-target', f'主機資料夾 ~/{DATA} 與 Podman 的儲存位置 {home}/{DATA}/storage 重疊'),
            # Review M5: another unit's container (even read-only) keeps the replaced copy after the swap.
            ('in-use', lambda o: o.bind_mounts.extend([
                {'id': 'e' * 12, 'name': 'woowbk-demo-app', 'unit': 'woowbk-demo-app.service', 'source': f'{home}/{HTML}',
                 'rw': True},
                {'id': 'f' * 12, 'name': 'viewer', 'unit': None, 'source': f'{home}/{DATA}', 'rw': False}]),
             'dir-in-use', f'容器 viewer 掛載了主機資料夾 ~/{DATA}；還原替換資料夾後它仍會使用被取代的內容'),
        ]
        for name, setup, check_id, needle in cases:
            with self.subTest(name):
                owner = self.new_owner()
                setup(owner)
                checks = self.make_adapter(owner).preflight(self.manifest, mode='inplace')
                failing = [c for c in checks if c['status'] == 'fail']
                self.assertEqual([re.sub(r'-[0-9]+$', '', c['id']) for c in failing], [f'woowbk-demo/{check_id}'], checks)
                self.assertIn(needle, failing[0]['message'])
        owner = self.new_owner()
        owner.dir_answers = {('state', '-'): [{**row, 'path': HTML, 'mount': True}, {**row, 'path': DATA}]}
        with self.assertRaises(BackupError) as caught:  # also when a caller skipped the preflight
            self.make_adapter(owner).restore(self.manifest, self.extract, mode='inplace')
        self.assertIn('是另一個檔案系統的掛載點', caught.exception.message)
        self.assertEqual({op[0] for op in owner.dir_ops}, {'state'}, 'refused before any change')

    def test_a_container_started_meanwhile_stops_the_restore_before_the_swap(self):
        owner = self.new_owner()

        def started(op, args):
            if op == 'unpack' and args[0] == DATA:
                owner.bind_mounts.append({'id': '1' * 12, 'name': 'late', 'unit': None,
                                          'source': f'/home/appowner/{HTML}', 'rw': True})
        owner.dir_hook = started
        adapter = self.make_adapter(owner)
        with self.assertRaises(BackupError) as caught:
            adapter.restore(self.manifest, self.extract, mode='inplace')
        self.assertIn('容器 late 以可寫入方式掛載了主機資料夾', caught.exception.message)
        self.assertTrue(adapter.destructive_started)
        self.assertNotIn('swap', [op[0] for op in owner.dir_ops], 'nothing swapped')
        self.assertEqual(adapter.discard_dirs(), [])
        for rel in (HTML, DATA):
            self.assertEqual(snapshot(self.home / rel), self.original[rel])
            self.assertEqual(self.siblings(rel), [], 'the new copies are discarded')

    def test_symlinked_target_fails_preflight_and_restore(self):
        shutil.rmtree(self.home / DATA)
        elsewhere = self.root / 'elsewhere'
        elsewhere.mkdir()
        os.symlink(elsewhere, self.home / DATA)
        checks = self.adapter.preflight(self.manifest, mode='inplace')
        failing = [c for c in checks if c['status'] == 'fail']
        self.assertEqual([c['id'] for c in failing], ['woowbk-demo/dir-target-2'])
        owner = self.new_owner()
        with self.assertRaises(BackupError) as caught:
            self.make_adapter(owner).restore(self.manifest, self.extract, mode='inplace')
        self.assertEqual(caught.exception.code, 'incompatible')
        self.assertEqual([op[0] for op in owner.dir_ops], ['state'], 'refused before any change')
        self.assertFalse(any(a[:3] == [SYSTEMCTL, '--user', 'stop'] for a in owner.argvs()))
        self.assertEqual(os.listdir(elsewhere), [], 'nothing written through the link')


class DirFreshTests(DirRestoreCase):
    def setUp(self):
        super().setUp()
        shutil.rmtree(self.home)
        self.home.mkdir()

    def test_fresh_creates_parents_and_the_directories(self):
        owner = self.new_owner(deployed=False, populate=False)
        adapter = self.make_adapter(owner)
        checks = adapter.preflight(self.manifest, mode='fresh')
        targets = [c for c in checks if c['id'].startswith('woowbk-demo/dir-target')]
        self.assertEqual([c['status'] for c in targets], ['ok', 'ok'])
        self.assertIn('上層資料夾不存在時以應用擁有者身分建立', targets[0]['message'])
        adapter.restore(self.manifest, self.extract, mode='fresh')
        self.assertIn(dir_call('swap', HTML, JOB, 'fresh'), owner.argvs())
        for rel in (HTML, DATA):
            self.assertEqual(snapshot(self.home / rel), self.original[rel])
            self.assertEqual(self.siblings(rel), [])
        self.assertEqual(stat.S_IMODE(os.stat(self.home / '.local/share/woowbk-demo').st_mode), 0o700)
        self.assertIn('已以擁有者身分建立資料夾 ~/.local/share/woowbk-demo', self.everything_logged())
        self.assertEqual(adapter.finish_dirs(), [], 'nothing was moved aside')

    def test_existing_empty_directory_is_replaced_and_non_empty_one_conflicts(self):
        (self.home / DATA).mkdir()
        owner = self.new_owner(deployed=False, populate=False)
        statuses = {c['id']: c['status'] for c in self.make_adapter(owner).preflight(self.manifest, mode='fresh')}
        self.assertEqual(statuses['woowbk-demo/dir-target-2'], 'ok')
        (self.home / DATA / 'keep.txt').write_text('user data')
        checks = self.make_adapter(owner).preflight(self.manifest, mode='fresh')
        conflict = [c for c in checks if c['id'] == 'woowbk-demo/dir-conflict']
        self.assertEqual(conflict[0]['status'], 'fail')
        self.assertIn('沒有刪除任何東西', conflict[0]['message'])
        # Even if the preflight was skipped, restore() refuses it before any change (and the swap would too).
        with self.assertRaises(BackupError) as caught:
            self.make_adapter(owner).restore(self.manifest, self.extract, mode='fresh')
        self.assertEqual(caught.exception.code, 'incompatible')
        self.assertEqual([a for a in owner.argvs() if a[:5] == helper('write')], [], 'no template was installed')
        self.assertEqual((self.home / DATA / 'keep.txt').read_text(), 'user data')

    def test_removing_a_failed_fresh_deployment_removes_its_directories_only(self):
        owner = self.new_owner(deployed=False, populate=False)
        adapter = self.make_adapter(owner)
        adapter.restore(self.manifest, self.extract, mode='fresh')
        parent = (self.home / HTML).parent
        for name in ('html.woowbk-new-jx', f'html.woowbk-new-{JOB}', f'html.woowbk-del-{JOB}', 'html.woowbk-old-jy'):
            parent.joinpath(name).mkdir()
        adapter.remove_fresh()
        self.assertFalse((self.home / HTML).exists())
        self.assertFalse((self.home / DATA).exists())
        # Review L3: only this job's copies go; another job's (or a folder of the user named like one) stays, and a
        # moved-aside copy is never removed here.
        self.assertEqual(self.siblings(HTML), ['.woowbk-new-jx', '.woowbk-old-jy'])


class DirRollbackTests(DirRestoreCase):
    """The rollback moves what a directory held before the failed restore back from its `-old-<job>` copy (review M3:
    no third copy, no extraction); the failed restore's data goes to `-old-<job>-rollback` and is deleted once the
    rollback was verified. A directory the failed restore never changed is left alone; one it replaced without such
    a copy is extracted from the safety backup."""

    def failed_restore(self, swapped=True):
        self.mutate()
        self.pre_restore = {rel: snapshot(self.home / rel) for rel in (HTML, DATA)}
        safety_manifest, safety_entries = self.make_adapter(self.new_owner()).backup(self.staging / 'safety',
                                                                                     include_images=False)
        self.safety = self.root / 'safety-extract'
        self.safety.mkdir(mode=0o700)
        extract_entries(safety_entries, self.safety)
        owner = self.new_owner()
        if swapped:  # fails after both directories were swapped in
            owner.fail = [('start -- woowbk-demo-app.service', 1)]
        else:  # fails writing the first directory
            owner.dir_fail = {'unpack': 11}
        adapter = self.make_adapter(owner)
        with self.assertRaises(BackupError):
            adapter.restore(self.manifest, self.extract, mode='inplace')
        owner.fail, owner.dir_fail = [], {}
        return owner, adapter, safety_manifest

    def rollback(self, owner, failed, safety_manifest):
        adapter = self.make_adapter(owner)
        start = len(owner.dir_ops)
        adapter.restore(safety_manifest, self.safety, mode='inplace', rollback=True,
                        replaced_dirs=failed.swapped_dirs())
        return adapter, owner.dir_ops[start:]

    def test_rollback_after_both_directories_were_swapped(self):
        owner, failed, safety_manifest = self.failed_restore()
        self.assertEqual(failed.swapped_dirs(), {HTML, DATA})
        self.assertEqual(failed.discard_dirs(), [])
        rollback, ops = self.rollback(owner, failed, safety_manifest)
        self.assertEqual([op for op in ops if op[0] not in ('state', 'mounts')],
                         [['revert', HTML, JOB, ROLLBACK], ['revert', DATA, JOB, ROLLBACK]], 'nothing extracted')
        for rel in (HTML, DATA):
            self.assertEqual(snapshot(self.home / rel), self.pre_restore[rel], 'what it held before the restore')
            self.assertEqual(self.siblings(rel), [f'.woowbk-old-{ROLLBACK}'], 'the failed data, until verified')
        self.assertEqual(rollback.finish_dirs(), [])
        for rel in (HTML, DATA):
            self.assertEqual(self.siblings(rel), [], 'the failed restore\'s data is deleted after a verified rollback')
        logged = self.everything_logged()
        self.assertIn(f'已把主機資料夾 ~/{HTML} 還原前的內容移回', logged)
        self.assertIn(f'已刪除 ~/{HTML}.woowbk-old-{ROLLBACK}（還原失敗時寫入的內容）', logged)

    def test_rollback_of_directories_the_failed_restore_never_reached(self):
        owner, failed, safety_manifest = self.failed_restore(swapped=False)
        self.assertEqual(failed.swapped_dirs(), set())
        self.assertEqual(failed.discard_dirs(), [])
        self.assertEqual(self.siblings(HTML), [], 'the partial copy is gone')
        rollback, ops = self.rollback(owner, failed, safety_manifest)
        self.assertEqual({op[0] for op in ops}, {'state'}, 'never changed by the failed restore: left alone')
        self.assertEqual(rollback.finish_dirs(), [])
        for rel in (HTML, DATA):
            self.assertEqual(snapshot(self.home / rel), self.pre_restore[rel])
            self.assertEqual(self.siblings(rel), [])
        self.assertIn(f'主機資料夾 ~/{HTML} 沒有被失敗的還原變更，保留原內容', self.everything_logged())

    def test_rollback_extracts_a_replaced_directory_whose_copy_is_gone(self):
        owner, failed, safety_manifest = self.failed_restore()
        shutil.rmtree(self.home / (DATA + f'.woowbk-old-{JOB}'))  # removed by hand meanwhile
        rollback, ops = self.rollback(owner, failed, safety_manifest)
        self.assertIn(['revert', HTML, JOB, ROLLBACK], ops)
        self.assertIn(['unpack', DATA, ROLLBACK], ops)
        self.assertIn(['swap', DATA, ROLLBACK, 'inplace'], ops)
        self.assertEqual(rollback.finish_dirs(), [])
        for rel in (HTML, DATA):
            self.assertEqual(snapshot(self.home / rel), self.pre_restore[rel], 'from the copy, or the safety backup')
            self.assertEqual(self.siblings(rel), [])

    def test_failed_rollback_reports_where_the_copies_are(self):
        owner, failed, safety_manifest = self.failed_restore()
        rollback = self.make_adapter(owner)
        owner.dir_fail = {'revert': 11}
        with self.assertRaises(BackupError):
            rollback.restore(safety_manifest, self.safety, mode='inplace', rollback=True,
                             replaced_dirs=failed.swapped_dirs())
        owner.dir_fail = {}
        self.assertEqual(rollback.discard_dirs(), [])
        notes = failed.dir_leftovers()
        self.assertEqual(len(notes), 2)
        self.assertIn(f'~/{HTML}.woowbk-old-{JOB}（還原前的原內容，處理完成前請勿刪除）', notes[0])
        self.assertTrue((self.home / HTML).is_dir())

    def test_a_revert_cut_between_its_renames_is_put_back_in_process(self):
        owner, failed, safety_manifest = self.failed_restore()
        rollback = self.make_adapter(owner)

        def cut(op, args):  # the helper dies after its first rename: the directory is missing
            if op == 'revert' and args[0] == HTML:
                os.rename(self.home / HTML, self.home / (HTML + f'.woowbk-old-{ROLLBACK}'))
                owner.dir_fail = {'revert': 137}
        owner.dir_hook = cut
        with self.assertRaises(BackupError):
            rollback.restore(safety_manifest, self.safety, mode='inplace', rollback=True,
                             replaced_dirs=failed.swapped_dirs())
        owner.dir_fail, owner.dir_hook = {}, None
        self.assertEqual(rollback.discard_dirs(), [])
        self.assertEqual(snapshot(self.home / HTML), self.pre_restore[HTML], 'the content before the restore first')
        self.assertEqual(self.siblings(HTML), [f'.woowbk-old-{ROLLBACK}'])


class DirRecoveryTests(DirRestoreCase):
    """A job killed at any step (SIGKILL: nothing in-process ran) leaves a state the recovery settles: a missing
    directory gets its moved-aside copy back, new copies go, the only copy of earlier content is never deleted."""

    def kill_at(self, step, rollback=False):
        """Lay out HTML as a job killed at `step` would have left it (real helper, real renames)."""
        owner = self.new_owner()
        adapter = self.make_adapter(owner)
        token = ROLLBACK if rollback else JOB
        path = self.extract / self.manifest['data_dirs'][0]['entry']
        ids = adapter.owner_ids()
        with nested.pipe_from(lambda out: nested.stream_dir(path, out, ids)) as feed:
            adapter.runner.dir_unpack(HTML, token, input=feed)
        base, old = self.home / HTML, self.home / (HTML + f'.woowbk-old-{token}')
        new = self.home / (HTML + f'.woowbk-new-{token}')
        if step == 'during-unpack':
            (new / 'index.php').unlink()  # a partial copy
        elif step == 'between-renames':
            os.rename(base, old)
        elif step == 'after-swap':
            os.rename(base, old)
            os.rename(new, base)
        elif step == 'during-finish':  # drop renames the old copy to `-del-` first, then deletes it (review L4)
            os.rename(base, old)
            os.rename(new, base)
            doomed = self.home / (HTML + f'.woowbk-del-{token}')
            os.rename(old, doomed)
            shutil.rmtree(doomed / 'config')
        return owner

    def recover(self, owner):
        adapter = self.make_adapter(owner)
        notes = adapter.recover_dirs()
        return notes

    def test_every_interruption_point_ends_safe(self):
        restored = self.original[HTML]
        for step, content, kept in (('during-unpack', 'pre', []), ('between-renames', 'pre', []),
                                    ('after-swap', 'restored', [f'.woowbk-old-{JOB}']),
                                    ('during-finish', 'restored', [])):
            with self.subTest(step):
                shutil.rmtree(self.home)
                self.home.mkdir()
                self.populate(marker='pre')
                pre = snapshot(self.home / HTML)
                owner = self.kill_at(step)
                notes = self.recover(owner)
                self.assertEqual(snapshot(self.home / HTML), pre if content == 'pre' else restored)
                self.assertEqual(self.siblings(HTML), kept)
                self.assertEqual(snapshot(self.home / DATA)['app.sqlite'][2][:15], b'SQLite format 3')
                if kept:
                    self.assertIn(f'~/{HTML}.woowbk-old-{JOB}', ' '.join(notes))
                if step == 'between-renames':
                    self.assertIn(f'已把 ~/{HTML} 移回還原前的原內容', ' '.join(notes))
                if step == 'during-finish':
                    self.assertIn(f'已刪除先前沒刪完的 ~/{HTML}.woowbk-del-{JOB}', ' '.join(notes))
                    self.assertNotIn('保留', ' '.join(notes), 'a half-deleted copy is never reported as kept content')
                again = self.recover(self.new_owner(populate=False))
                self.assertEqual(snapshot(self.home / HTML), pre if content == 'pre' else restored, 'idempotent')
                self.assertEqual(self.siblings(HTML), kept)
                self.assertFalse([n for n in again if '已移除' in n or '移回' in n])

    def test_a_dead_rollback_is_undone_step_by_step_and_keeps_every_copy(self):
        shutil.rmtree(self.home)
        self.home.mkdir()
        self.populate(marker='pre')
        pre = snapshot(self.home / HTML)
        owner = self.kill_at('after-swap')  # the restore swapped HTML (the original is the -old-<job> copy)
        failed_content = snapshot(self.home / HTML)
        self.kill_at('between-renames', rollback=True)  # then the rollback was killed between its renames
        notes = ' '.join(self.recover(self.new_owner(populate=False)))
        self.assertEqual(snapshot(self.home / HTML), pre, 'the content before the restore comes back (review L4)')
        self.assertEqual(self.siblings(HTML), [f'.woowbk-old-{ROLLBACK}'])
        self.assertEqual(snapshot(self.home / (HTML + f'.woowbk-old-{ROLLBACK}')), failed_content, 'kept, reported')
        self.assertIn(f'已把 ~/{HTML} 移回還原前的原內容（~/{HTML}.woowbk-old-{JOB}）', notes)
        self.assertIn(f'~/{HTML} 還原失敗時寫入的內容保留在 ~/{HTML}.woowbk-old-{ROLLBACK}', notes)
        self.assertTrue(owner)

    def test_fresh_deployment_killed_during_its_extraction(self):
        shutil.rmtree(self.home)
        self.home.mkdir()
        owner = self.new_owner(deployed=False, populate=False)
        adapter = self.make_adapter(owner)
        path = self.extract / self.manifest['data_dirs'][1]['entry']
        with nested.pipe_from(lambda out: nested.stream_dir(path, out, adapter.owner_ids())) as feed:
            adapter.runner.dir_unpack(DATA, JOB, input=feed)
        notes = self.recover(owner)
        self.assertFalse((self.home / DATA).exists())
        self.assertEqual(self.siblings(DATA), [])
        self.assertIn(f'已移除沒寫完或未換上的 ~/{DATA}.woowbk-new-{JOB}', ' '.join(notes))

    def test_unreadable_state_is_reported_not_guessed(self):
        owner = self.new_owner()
        owner.dir_fail = {'state': 125}
        notes = self.recover(owner)
        self.assertEqual(len(notes), 1)
        self.assertIn('需人工確認', notes[0])
        self.assertEqual([op[0] for op in owner.dir_ops], ['state'])


class DirColdDatabaseTests(DirRestoreCase):
    """The cold pattern: no pg_dump entry; the database unit is a writer and its data directory a host directory."""
    cold = True

    def test_inplace_restore_without_database_steps(self):
        self.mutate()
        owner = self.new_owner()
        adapter = self.make_adapter(owner)
        adapter.restore(self.manifest, self.extract, mode='inplace')
        text = ' '.join(owner.text(a) for a in owner.argvs())
        self.assertNotIn('pg_restore', text)
        self.assertNotIn('pg_isready', text)
        masked = [a for a in owner.argvs() if a[:3] == [SYSTEMCTL, '--user', 'mask']]
        self.assertEqual(masked, [[SYSTEMCTL, '--user', 'mask', '--', 'woowbk-demo-db.service', 'woowbk-demo-app.service']],
                         'without a pg_dump database every unit stays masked until the data is in place')
        starts = [a[-1] for a in owner.argvs() if a[:3] == [SYSTEMCTL, '--user', 'start']]
        self.assertEqual(starts, ['woowbk-demo-db.service', 'woowbk-demo-app.service'])
        self.assertEqual(snapshot(self.home / DATA), self.original[DATA])


if __name__ == '__main__':
    unittest.main()
