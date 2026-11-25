"""What the batch 1 importers share (hacommon.py) and the throwaway containers' host lines (tempctr). Team E2."""
import io
import json
import tarfile
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from woowbackup import habackup, hacommon, haimport, hatarget, haissues, nested, podman, tempctr
from woowbackup.errors import BackupError

from . import hafixtures as hx
from . import test_ha_import as hi


class ScanTests(unittest.TestCase):
    def test_ha_only_hosts(self):
        text = ('base_url: http://homeassistant:8123/api\nllm: http://a0d7b954-litellm:4000/v1\n'
                'x: https://api.example.com/v1  y: http://localhost:8642  z: ws://172.30.32.1:8123/api/websocket\n'
                'w: mqtt://core-mosquitto:1883 v: http://my-ha.local:8123 u: http://supervisor/core')
        self.assertEqual(hacommon.ha_hosts(text), ['172.30.32.1', 'a0d7b954-litellm', 'core-mosquitto',
                                                   'homeassistant', 'my-ha.local', 'supervisor'])

    def test_simple_yaml_scalars(self):
        text = ('server_url: "http://homeassistant.local:28080"\nprefixes:\n  v4: "100.64.0.0/10"\n'
                '  v6: fd7a:115c:a1e0::/48  # comment\n  allocation: sequential\nderp:\n  urls:\n    - https://x\n'
                '  paths: []\ndns:\n  base_domain: ts.local\n  extra_records_path: /etc/headscale/dns_records.json\n'
                '# policy: x\npolicy:\n  mode: file\n  path: ""\n_config_version: 51\n')
        values = hacommon.scalars(text)
        self.assertEqual(values['server_url'], 'http://homeassistant.local:28080')
        self.assertEqual((values['prefixes.v4'], values['prefixes.v6']), ('100.64.0.0/10', 'fd7a:115c:a1e0::/48'))
        self.assertEqual(values['dns.extra_records_path'], '/etc/headscale/dns_records.json')
        self.assertEqual((values['policy.mode'], values['policy.path'], values['_config_version']), ('file', '', '51'))
        self.assertNotIn('derp.paths', values)
        self.assertEqual(hacommon.scalars('x' * (2 * 1024 * 1024)), {})

    def test_versions(self):
        table = hacommon.VersionTable('Headscale', {'0.1.0': '0.29.3', '0.1.3': '0.29.4'})
        self.assertIsNone(table.blocker('0.1.3', '0.29.4'))
        self.assertIsNone(table.blocker('0.1.3', 'v0.29.4'))
        self.assertIn('HA 的 Headscale 是 0.29.3', table.blocker('0.1.0', '0.29.4'))
        self.assertIn('還不認得', table.blocker('0.2.0', '0.29.4'))
        self.assertIn('無法讀取這台', table.blocker('0.1.3', None))
        self.assertEqual([[i.id for i in table.issues(*args)] for args in (('0.1.3', '0.29.4'), ('0.2.0', '0.29.4'),
                                                                           ('0.1.3', None), ('0.1.0', '0.29.4'))],
                         [[], ['version.addon-unknown'], ['version.target-unknown'], ['version.different']])
        self.assertEqual((hacommon.semver('v5.8.9'), hacommon.semver('5.8.9-rc1'), hacommon.semver(None)),
                         ('5.8.9', None, None))

    def test_foreign_programs(self):
        x86 = b'\x7fELF\x02\x01\x01' + bytes(11) + b'\x3e\x00'
        arm = b'\x7fELF\x02\x01\x01' + bytes(11) + b'\xb7\x00'
        self.assertFalse(hacommon.foreign_elf(x86, 0x3E))
        self.assertTrue(hacommon.foreign_elf(arm, 0x3E))
        self.assertFalse(hacommon.foreign_elf(b'#!/bin/sh\n' * 3, 0x3E))
        self.assertFalse(hacommon.foreign_elf(arm, None))


class TreeTarTests(unittest.TestCase):
    def test_links_owner_and_modes(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / 'v.tar'
        source = hx.tar_bytes([{'name': 'a', 'data': b'abc', 'mode': 0o4755}, {'name': 'b', 'data': b'b'}])
        out = hacommon.TreeTar(path, 1000, 1000)
        out.root(0o755, 0, 0)
        for entry in habackup.iter_entries(io.BytesIO(source), None, habackup.Report(), addon=False):
            out.file(entry.name, entry, entry.mode)
        out.dir('d', 0o2775, 0)
        out.symlink('d/python', '/opt/data/uv/python3', 0)
        out.hardlink('d/a', 'a', 0)
        with self.assertRaises(BackupError) as caught:
            out.hardlink('d/c', 'skipped', 0)
        self.assertEqual(caught.exception.code, 'incompatible')
        out.close()
        with tarfile.open(path) as tar:
            members = {m.name: m for m in tar.getmembers()}
        self.assertEqual((members['a'].mode, members['a'].uid), (0o755, 1000), 'no setuid')
        self.assertEqual(members['d'].mode, 0o775, 'no setgid either')
        self.assertEqual((members['d/a'].type, members['d/a'].linkname), (tarfile.LNKTYPE, 'a'))
        self.assertEqual(members['.'].uid, 0)
        ids = (nested.IdMap('0 1013 1\n1 100000 65536\n'), nested.IdMap('0 1013 1\n1 100000 65536\n'))
        self.assertEqual(nested.check_volume(path, ids=ids).members, 6)
        self.assertEqual(out.counts, {'files': 2, 'dirs': 1, 'symlinks': 1, 'hardlinks': 1, 'bytes': 4})

    def test_a_live_export_is_copied_without_what_is_dropped(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        live = Path(tmp.name) / 'live.tar'
        live.write_bytes(hx.tar_bytes([{'name': '.', 'type': 'dir', 'uid': 0}, {'name': 'artifacts', 'type': 'dir'},
                                       {'name': 'artifacts/accounts-cookie-secret', 'data': b'live'},
                                       {'name': 'sharing_mode', 'data': b'off'}]))
        out = hacommon.FileTar(Path(tmp.name) / 'out.tar')
        dirs = hacommon.copy_live(live, out, drop=lambda name: hacommon._under(name, 'artifacts'))
        out.close()
        with tarfile.open(Path(tmp.name) / 'out.tar') as tar:
            self.assertEqual(sorted(m.name for m in tar.getmembers()), ['.', 'sharing_mode'])
        self.assertEqual(sorted(dirs), ['.', 'artifacts'])
        live.write_bytes(b'not a tar' * 100)
        with self.assertRaises(BackupError):
            hacommon.copy_live(live, hacommon.FileTar(Path(tmp.name) / 'out2.tar'))


class NamesTests(unittest.TestCase):
    def test_names_carry_no_control_or_bidirectional_character(self):
        """secreview SR-4 and the verifier's bidi gap: a name from HA's backup (a table, schema or extension name, an
        alembic revision) reaches a message on the page. Line breaks, terminal escapes and every Unicode
        bidirectional control (U+061C, U+200E, U+200F, U+202A-U+202E, U+2066-U+2069: a U+202E reverses how the
        rest of the message reads) are shown as '?'; other text, Chinese included, is kept."""
        controls = '\n\r\x1b\x85\u2028\u2029\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069'
        shown = hacommon.names([f'表{ch}x' for ch in controls], limit=len(controls))
        self.assertEqual(shown, '、'.join(['表?x'] * len(controls)))
        self.assertEqual(hacommon.names(['users', '使用者']), 'users、使用者')


class LabelTests(unittest.TestCase):
    def work(self, stdout, code=0):
        runner = types.SimpleNamespace(podman=lambda *a, **k: types.SimpleNamespace(returncode=code, stdout=stdout))
        return types.SimpleNamespace(runner=lambda _app: runner)

    def test_labels(self):
        app = types.SimpleNamespace(id='emqx', name='EMQX')
        labels = hacommon.image_labels(self.work(b'{"org.opencontainers.image.version": "5.8.9", "n": 1}\n'), app,
                                       'docker.io/emqx/emqx:5.8.9')
        self.assertEqual(labels, {'org.opencontainers.image.version': '5.8.9'})
        self.assertEqual(hacommon.image_labels(self.work(b'null\n'), app, 'x:1'), {})
        with self.assertRaises(BackupError):
            hacommon.image_labels(self.work(b'', code=125), app, 'x:1')
        with self.assertRaises(BackupError):
            hacommon.image_labels(self.work(b''), app, 'bad ref')


class AddHostTests(unittest.TestCase):
    def test_host_lines_are_checked(self):
        tmp = tempctr.TempObjects(types.SimpleNamespace(uid=None), 'j20261118T120000Z-0123abcd', cpus=None)
        argv = tmp.run_argv('emqx-ha', 'docker.io/emqx/emqx:5.8.9', [], add_hosts=[('homeassistant.local',
                                                                                     '127.0.0.1')])
        self.assertIn('--add-host', argv)
        self.assertIn('homeassistant.local:127.0.0.1', argv)
        self.assertEqual(argv[argv.index('--network') + 1], 'none')
        for bad in (('-x', '127.0.0.1'), ('a b', '127.0.0.1'), ('host', '::1'), ('host', '127.0.0.1;x')):
            with self.subTest(bad=bad), self.assertRaises(BackupError):
                tmp.run_argv('emqx-ha', 'docker.io/emqx/emqx:5.8.9', [], add_hosts=[bad])


# ====================================================================== lane F3-helpers (HAOS parity, 2026-11-25)

JOB = 'j20261125T120000Z-0123abcd'
IDS = (nested.IdMap('0 1013 1\n1 100000 65536\n'), nested.IdMap('0 1013 1\n1 100000 65536\n'))
APP = types.SimpleNamespace(id='odoo', name='Odoo 18', owner='appowner', volumes=[{'name': 'odoo-db'}, {'name': 'odoo-web'},
                                                                                   {'name': 'odoo-extra'}],
                            data_dirs=[{'path': '.local/share/odoo/addons'}, {'path': '.local/share/odoo/files'}])
QUADLET = (b'[Container]\nContainerName=odoo-db\nImage=docker.io/library/postgres:16.15-alpine\n'
           b'Environment=POSTGRES_USER=odoo\n')
SECRET_ERR = b'Error: initializing source docker://deploy:S3cr3tTokenValue@registry.example/app:1: connection refused\n'


class Clock:
    """Time that only moves when the code sleeps (no test waits for real)."""

    def __init__(self):
        self.now = 0.0
        self.slept = []

    def clock(self):
        return self.now

    def sleep(self, seconds):
        self.slept.append(seconds)
        self.now += seconds


class World:
    """A device as `podman` sees it: images, containers that run, units that start them, a database that becomes ready
    after a while. Every command goes through `Owner`, the app owner's runner."""

    def __init__(self):
        self.images = {'docker.io/library/postgres:16.15-alpine'}
        self.running = set()
        self.calls = []
        self.pulls = []             # Result per pull attempt (the last one is repeated)
        self.pull_error = None      # raised by the pull instead (BackupError)
        self.start = None           # Result of `systemctl start` (None: it works)
        self.stop = None
        self.not_ready = 0          # pg_isready fails this often before it works
        self.exec_results = []      # Result per psql call (the last one is repeated)
        self.volumes = {}           # name -> tar bytes of `volume export`
        self.dirs = {}
        self.systemctl_kwargs = []

    def podman(self, args, kwargs):
        verb = args[0]
        if verb == 'image' and args[1] == 'inspect':
            return podman.Result(0 if args[-1] in self.images else 125, b'sha256:abc\n',
                                 b'Error: image not known')
        if verb == 'pull':
            if self.pull_error is not None:
                raise self.pull_error
            result = (self.pulls.pop(0) if len(self.pulls) > 1 else self.pulls[0]) if self.pulls else \
                podman.Result(0, b'sha256:abc\n', b'')
            if result.returncode == 0:
                self.images.add(args[-1])
            return result
        if verb == 'container' and args[1] == 'inspect':
            running = args[-1] in self.running
            return podman.Result(0 if running else 125, b'true\n' if running else b'',
                                 b'' if running else b'no such container')
        if verb == 'exec' and args[2] == 'pg_isready':
            if self.not_ready > 0:
                self.not_ready -= 1
                return podman.Result(2, b'', b'no response')
            return podman.Result(0, b'', b'')
        if verb == 'exec' and args[2] == 'psql':
            result = (self.exec_results.pop(0) if len(self.exec_results) > 1 else self.exec_results[0])
            if result.returncode != 0 and kwargs.get('check', True):
                raise podman.CommandError('podman exec 執行失敗', returncode=result.returncode, stderr=result.stderr,
                                          reason=podman.classify(result.stderr, result.returncode)[0])
            return result
        return podman.Result(0, b'', b'')


class Owner:
    uid = None
    owner = 'appowner'
    home = '/home/appowner'

    def __init__(self, world):
        self.world = world
        self.calls = world.calls

    def podman(self, *args, **kwargs):
        self.calls.append(('podman', *args))
        kwargs_seen = dict(kwargs)
        result = self.world.podman(args, kwargs_seen)
        if kwargs.get('check', True) and result.returncode != 0:
            raise podman.CommandError(f'podman {args[0]} 執行失敗（結束碼 {result.returncode}）。', returncode=result.returncode,
                                      stderr=result.stderr, reason=podman.classify(result.stderr, result.returncode)[0])
        return result

    def systemctl(self, *args, **kwargs):
        self.calls.append(('systemctl', *args))
        self.world.systemctl_kwargs.append((args[0], dict(kwargs)))
        result = self.world.stop if args[0] == 'stop' else self.world.start
        if result is not None and result.returncode != 0:
            raise podman.CommandError(f'systemctl {args[0]} 執行失敗（結束碼 {result.returncode}）。', returncode=result.returncode,
                                      stderr=result.stderr, reason=podman.classify(result.stderr, result.returncode)[0])
        if args[0] == 'start':
            self.world.running.add('odoo-db')
        if args[0] == 'stop':
            self.world.running.discard('odoo-db')
        return podman.Result(0, b'', b'')

    def relay(self, args, *, stdout, timeout=None, max_output=None, check=True, abort=None):
        self.calls.append(('relay', *args))
        stdout.write(self.world.volumes[args[-1]])

    def dir_pack(self, rel, *, stdout, timeout=None, max_output=None, abort=None):
        self.calls.append(('dir_pack', rel))
        stdout.write(self.world.dirs[rel])


class Case(unittest.TestCase):
    """A work (the parts of haimport.Work these helpers use) over a World."""

    def setUp(self):
        self.world = World()
        self.owner = Owner(self.world)
        self.notes = []
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.temp = tempctr.TempObjects(self.owner, JOB, log=self.notes.append, cpus=None)
        self.sinks = {}
        self.guard = types.SimpleNamespace(folders=[], checked=[], wrote=lambda _n: None, budget=lambda: None)
        self.guard.check = lambda need=0: self.guard.checked.append(need)
        self.stop = None    # what the watchdog says (an exception) once set
        self.clock = Clock()
        for name, value in (('_sleep', self.clock.sleep), ('_clock', self.clock.clock)):
            patcher = mock.patch.object(hatarget, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.work = types.SimpleNamespace(
            runner=lambda _app: self.owner, log=self.notes.append, sink=self.sink, temp=lambda _app: self.temp,
            quadlets=lambda _app: {'odoo-db.container': QUADLET}, abort=lambda: self.stop, guard=self.guard,
            storage_folders=lambda _app: ['/home/appowner', '/home/appowner/.local/share/containers/storage'],
            staging=Path(self.tmpdir.name))

    def sink(self, app):
        return self.sinks.setdefault(app.id, haissues.Sink(app.id, log=self.notes.append))

    def issues(self):
        return [(issue.id, issue.level) for sink in self.sinks.values() for issue in sink.found]


class EnsureImageTests(Case):
    """CM-05 and X-AD-60: an image this device does not have is downloaded as the app's owner; when that cannot be, only
    this app stops, with the reason and nothing about the command's own words."""
    REF = 'docker.io/emqx/emqx:5.8.9'

    def test_an_image_that_is_there_costs_one_look(self):
        self.assertFalse(hatarget.ensure_image(self.work, APP, 'docker.io/library/postgres:16.15-alpine'))
        self.assertEqual([call[:2] for call in self.world.calls], [('podman', 'image')])
        self.assertEqual(self.issues(), [])

    def test_a_missing_image_is_downloaded_as_the_owner_and_said(self):
        self.assertTrue(hatarget.ensure_image(self.work, APP, self.REF))
        pulls = [call for call in self.world.calls if call[1] == 'pull']
        self.assertEqual(pulls, [('podman', 'pull', '--quiet', self.REF)])
        self.assertEqual(self.issues(), [('target.image-pulled', 'auto')])
        self.assertEqual(self.sinks['odoo'].found[0].names, (self.REF,))
        self.assertTrue(any('已自動下載' in note for note in self.notes))
        self.assertIn('/home/appowner/.local/share/containers/storage', self.guard.folders, 'the download is watched')
        self.assertTrue(self.guard.checked)
        self.assertFalse(hatarget.ensure_image(self.work, APP, self.REF), 'now it is there: nothing again')

    def test_a_download_that_only_failed_for_a_moment_is_tried_once_more(self):
        self.world.pulls = [podman.Result(125, b'', SECRET_ERR), podman.Result(0, b'sha256:abc\n', b'')]
        self.assertTrue(hatarget.ensure_image(self.work, APP, self.REF))
        self.assertEqual(len([c for c in self.world.calls if c[1] == 'pull']), 2)
        self.assertEqual(self.clock.slept, [1.0] * 5, 'a pause between the two, in slices the watchdog can end')
        self.assertTrue(any('再試一次' in note for note in self.notes))

    def test_a_download_that_keeps_failing_stops_only_this_app_without_the_commands_words(self):
        self.world.pulls = [podman.Result(125, b'', SECRET_ERR)]
        with self.assertRaises(BackupError) as caught:
            hatarget.ensure_image(self.work, APP, self.REF)
        error = caught.exception
        self.assertEqual(error.code, 'incompatible', 'what Work.image_version hands on to the app')
        self.assertEqual(len([c for c in self.world.calls if c[1] == 'pull']), hatarget.PULL_ATTEMPTS)
        self.assertEqual([(i.id, i.level) for i in error.issues], [('target.image-missing', 'stop')])
        self.assertIn('連不上網路', error.message)
        self.assertIn('這台的應用沒有任何變更', error.message)
        self.assertNotIn('S3cr3tTokenValue', error.message + repr(error.issues[0].view('odoo')))
        self.assertEqual(error.issues[0].names, (self.REF,))
        self.assertTrue(error.issues[0].action)

    def test_a_refusal_is_not_tried_again(self):
        self.world.pulls = [podman.Result(125, b'', b'Error: pull access denied for x, repository does not exist')]
        with self.assertRaises(BackupError) as caught:
            hatarget.ensure_image(self.work, APP, self.REF)
        self.assertEqual(len([c for c in self.world.calls if c[1] == 'pull']), 1)
        self.assertIn('拒絕下載', caught.exception.message)
        self.assertEqual(self.clock.slept, [])

    def test_a_download_that_leaves_no_image_is_a_failure(self):
        real = self.world.podman

        def pull_does_nothing(args, kwargs):
            if args[0] == 'pull':
                return podman.Result(0, b'', b'')
            return real(args, kwargs)

        self.world.podman = pull_does_nothing
        with self.assertRaises(BackupError) as caught:
            hatarget.ensure_image(self.work, APP, self.REF)
        self.assertEqual(caught.exception.issues[0].id, 'target.image-missing')

    def test_a_timeout_is_a_failed_try_a_watchdog_verdict_ends_the_job(self):
        self.world.pull_error = BackupError('job-failed', 'podman pull 執行逾時（1800 秒）。', reason='timeout')
        with self.assertRaises(BackupError) as caught:
            hatarget.ensure_image(self.work, APP, self.REF)
        self.assertEqual(caught.exception.issues[0].id, 'target.image-missing')
        self.assertIn('等待逾時', caught.exception.message)
        self.assertEqual(len([c for c in self.world.calls if c[1] == 'pull']), 2, 'a timeout may pass: once more')
        for error in (haissues.job_wide(BackupError('insufficient-space', 'disk')), BackupError('busy', 'other job'),
                      BackupError('owner-missing', 'no such account')):
            self.world.calls.clear()
            self.world.pull_error = error
            with self.assertRaises(BackupError) as caught:
                hatarget.ensure_image(self.work, APP, self.REF)
            self.assertIs(caught.exception, error, 'not this app\'s failure: it comes up as it is')
            self.assertEqual(len([c for c in self.world.calls if c[1] == 'pull']), 1)

    def test_a_locally_built_image_is_never_pulled(self):
        with self.assertRaises(BackupError) as caught:
            hatarget.ensure_image(self.work, APP, 'localhost/odoo-custom:1')
        self.assertFalse([c for c in self.world.calls if c[1] == 'pull'])
        self.assertIn('自己建置', caught.exception.message)

    def test_a_full_disk_stops_before_anything_is_downloaded(self):
        self.guard.check = lambda need=0: (_ for _ in ()).throw(BackupError('insufficient-space', 'full'))
        with self.assertRaises(BackupError) as caught:
            hatarget.ensure_image(self.work, APP, self.REF)
        self.assertEqual(caught.exception.code, 'insufficient-space')
        self.assertFalse([c for c in self.world.calls if c[1] == 'pull'])

    def test_a_bad_reference_runs_nothing(self):
        for ref in ('bad image', '', None, 5, 'app.build', 'x.image'):
            with self.subTest(ref=ref), self.assertRaises(BackupError) as caught:
                hatarget.ensure_image(self.work, APP, ref)
            self.assertEqual(caught.exception.code, 'incompatible')
        self.assertEqual(self.world.calls, [])

    def test_the_download_is_asked_for_the_watchdog_and_works_without_a_work_that_has_one(self):
        seen = []
        real = self.owner.podman

        def spy(*args, **kwargs):
            seen.append((args[0], kwargs.get('abort'), kwargs.get('check')))
            return real(*args, **kwargs)

        self.owner.podman = spy
        hatarget.ensure_image(self.work, APP, self.REF)
        pull = next(item for item in seen if item[0] == 'pull')
        self.assertEqual((pull[1], pull[2]), (self.work.abort, False))
        bare = types.SimpleNamespace(runner=lambda _app: self.owner)     # nothing of the job: only a runner
        self.world.images.discard(self.REF)
        self.assertTrue(hatarget.ensure_image(bare, APP, self.REF))

    def test_every_image_of_the_apps_quadlet_files(self):
        images = {'odoo-db.service': 'docker.io/library/postgres:16.15-alpine', 'odoo.service': 'docker.io/odoo:18',
                  'odoo-web.service': 'docker.io/odoo:18'}
        self.work.adapter = lambda _app: types.SimpleNamespace(container_images=lambda sources: dict(images))
        self.assertEqual(hatarget.ensure_app_images(self.work, APP), ['docker.io/odoo:18'])
        self.assertEqual(hatarget.ensure_app_images(self.work, APP), [])
        self.work.adapter = lambda _app: types.SimpleNamespace()      # a double that cannot list its images
        self.assertEqual(hatarget.ensure_app_images(self.work, APP), [])


class ImageLabelTests(Case):
    """hacommon.image_labels downloads the image first (CM-05)."""
    REF = 'docker.io/emqx/emqx:5.8.9'

    def labels(self, pull=True):
        real = self.world.podman

        def answer(args, kwargs):
            if args[:3] == ('image', 'inspect', '--format') and args[3].startswith('{{json'):
                present = args[-1] in self.world.images
                return podman.Result(0 if present else 125, b'{"org.opencontainers.image.version":"5.8.9"}\n', b'')
            return real(args, kwargs)

        self.world.podman = answer
        return hacommon.image_labels(self.work, APP, self.REF, pull=pull)

    def test_a_missing_image_is_downloaded_and_read(self):
        self.assertEqual(self.labels(), {'org.opencontainers.image.version': '5.8.9'})
        self.assertEqual(self.issues(), [('target.image-pulled', 'auto')])

    def test_pull_false_reads_only_what_is_there(self):
        with self.assertRaises(BackupError) as caught:
            self.labels(pull=False)
        self.assertEqual(caught.exception.code, 'incompatible')
        self.assertFalse([c for c in self.world.calls if c[1] == 'pull'])

    def test_an_image_that_cannot_be_had_stops_the_app_with_its_issue(self):
        self.world.pulls = [podman.Result(125, b'', b'Error: manifest unknown')]
        with self.assertRaises(BackupError) as caught:
            self.labels()
        self.assertEqual(caught.exception.issues[0].id, 'target.image-missing')
        self.assertEqual(caught.exception.code, 'incompatible')


class EnsureRunningTests(Case):
    """CM-07: a stopped database or service is started to be read, waited for, and put back."""

    def start(self, **kwargs):
        return hatarget.ensure_running(self.work, APP, 'odoo-db', **kwargs)

    def test_a_running_container_is_left_alone(self):
        self.world.running.add('odoo-db')
        service = self.start(ready='postgres')
        self.assertEqual((service.started, service.unit), (False, None))
        self.assertFalse([c for c in self.world.calls if c[0] == 'systemctl'])
        self.assertEqual((self.issues(), self.temp.services, self.temp._puts_back), ([], {}, []))

    def test_a_stopped_one_is_started_through_its_quadlet_unit_waited_for_and_put_back(self):
        self.world.not_ready = 3
        service = self.start(ready='postgres')
        self.assertEqual((service.started, service.unit), (True, 'odoo-db.service'))
        systemctl = [c for c in self.world.calls if c[0] == 'systemctl']
        self.assertEqual(systemctl, [('systemctl', 'start', '--', 'odoo-db.service')])
        self.assertEqual(len([c for c in self.world.calls if c[:3] == ('podman', 'exec', 'odoo-db')]), 4,
                         'pg_isready until it answers')
        self.assertEqual(self.issues(), [('target.service-started', 'auto')])
        self.assertEqual(self.temp.services, {'odoo-db': 'odoo-db.service'})
        self.assertEqual(self.clock.slept[:3], [hatarget.READY_POLL] * 3)
        self.world.calls.clear()
        self.assertEqual(self.temp.cleanup(), [])
        self.assertIn(('systemctl', 'stop', '--', 'odoo-db.service'), self.world.calls)
        self.assertEqual((self.temp.services, self.world.running), ({}, set()))
        self.world.calls.clear()
        self.temp.cleanup()
        self.assertFalse([c for c in self.world.calls if c[0] == 'systemctl'], 'put back once')

    def test_the_start_is_ended_by_the_watchdog_the_put_back_never_is(self):
        self.start()
        self.temp.cleanup()
        kwargs = dict(self.world.systemctl_kwargs)
        self.assertIs(kwargs['start']['abort'], self.work.abort)
        self.assertNotIn('abort', kwargs['stop'], 'a cancel or a full disk must not stop what puts things back')

    def test_asking_again_changes_nothing(self):
        self.start()
        again = self.start(ready='postgres')
        self.assertEqual((again.started, again.unit), (False, 'odoo-db.service'))
        self.assertEqual(len([c for c in self.world.calls if c[0] == 'systemctl']), 1)
        self.assertEqual(len(self.temp._puts_back), 1)
        self.assertEqual(self.issues(), [('target.service-started', 'auto')])

    def test_what_cannot_be_started_stops_only_this_app_and_names_the_reason_not_the_words(self):
        self.world.start = podman.Result(1, b'', b'Failed to start odoo-db.service: Unit odoo-db.service is masked.')
        with self.assertRaises(BackupError) as caught:
            self.start()
        issue = caught.exception.issues[0]
        self.assertEqual((issue.id, issue.level), ('target.service-failed', 'stop'))
        self.assertIn('暫時停用', caught.exception.message)
        self.assertEqual((caught.exception.code, self.temp.services, self.temp._puts_back), ('job-failed', {}, []))

    def test_a_job_wide_error_comes_up_as_it_is(self):
        error = haissues.job_wide(BackupError('insufficient-space', 'disk'))
        self.owner.systemctl = lambda *a, **k: (_ for _ in ()).throw(error)
        with self.assertRaises(BackupError) as caught:
            self.start()
        self.assertIs(caught.exception, error)

    def test_a_service_that_is_not_ready_in_time_is_put_back_at_once(self):
        self.world.not_ready = 10 ** 6
        with self.assertRaises(BackupError) as caught:
            self.start(ready='postgres', timeout=20)
        self.assertEqual(caught.exception.issues[0].id, 'target.service-failed')
        self.assertIn('20 秒內沒有準備好', caught.exception.message)
        self.assertIn('已恢復原狀', caught.exception.message)
        self.assertEqual(self.world.running, set(), 'stopped again before the error came up')
        self.assertEqual(self.world.calls[-1], ('systemctl', 'stop', '--', 'odoo-db.service'))

    def test_a_running_container_that_never_answers_is_not_stopped(self):
        self.world.running.add('odoo-db')
        self.world.not_ready = 10 ** 6
        with self.assertRaises(BackupError) as caught:
            self.start(ready='postgres', timeout=5)
        self.assertIn('沒有任何變更', caught.exception.message)
        self.assertFalse([c for c in self.world.calls if c[0] == 'systemctl'])

    def test_a_container_no_quadlet_file_defines_cannot_be_started(self):
        with self.assertRaises(BackupError) as caught:
            hatarget.ensure_running(self.work, APP, 'other-db')
        self.assertEqual(caught.exception.issues[0].id, 'target.service-failed')
        self.assertFalse([c for c in self.world.calls if c[0] == 'systemctl'])

    def test_a_cancel_while_waiting_still_puts_the_service_back_with_the_cleanup(self):
        self.world.not_ready = 10 ** 6
        verdict = haissues.job_wide(BackupError('insufficient-space', 'disk'))
        polls = []

        def abort():
            polls.append(1)
            return verdict if len(polls) > 3 else None

        self.work.abort = abort
        with self.assertRaises(BackupError) as caught:
            self.start(ready='postgres')
        self.assertIs(caught.exception, verdict)
        self.assertEqual(self.world.running, {'odoo-db'}, 'the cleanup of the app\'s throwaway objects puts it back')
        self.temp.cleanup()
        self.assertEqual(self.world.running, set())

    def test_the_put_back_that_fails_is_kept_and_reported(self):
        self.start()
        self.world.stop = podman.Result(1, b'', b'Failed to stop: Access denied')
        self.assertEqual(self.temp.cleanup(), ['service:容器 odoo-db'])
        self.assertTrue(any('沒能恢復原狀' in note for note in self.notes))
        self.world.stop = None
        self.assertEqual(self.temp.cleanup(), [])
        self.assertEqual(self.world.running, set())

    def test_a_ready_check_of_ones_own_and_a_bad_one(self):
        self.world.running.add('odoo-db')
        seen = []
        hatarget.ensure_running(self.work, APP, 'odoo-db', ready=lambda runner, container: seen.append(container) or True)
        self.assertEqual(seen, ['odoo-db'])
        for bad in ('postgres; rm', 5):
            with self.subTest(ready=bad), self.assertRaises(BackupError):
                hatarget.ensure_running(self.work, APP, 'odoo-db', ready=bad)
        for name in ('', 'a b', '-x', 'x' * 200, None):
            with self.subTest(container=name), self.assertRaises(BackupError) as caught:
                hatarget.ensure_running(self.work, APP, name)
            self.assertEqual(caught.exception.code, 'internal-error')

    def test_a_longer_wait_for_a_bigger_app(self):
        self.world.not_ready = 10 ** 6
        with self.assertRaises(BackupError) as caught:
            self.start(ready='postgres', size=200 * 1024 ** 3)
        limit = podman.scaled_timeout(hatarget.READY_TIMEOUT, 200 * 1024 ** 3)
        self.assertGreater(limit, hatarget.READY_TIMEOUT)
        self.assertIn(f'{limit} 秒內', caught.exception.message)

    def test_without_a_throwaway_registry_nothing_breaks(self):
        bare = types.SimpleNamespace(runner=lambda _app: self.owner, quadlets=lambda _app: {'odoo-db.container': QUADLET})
        service = hatarget.ensure_running(bare, APP, 'odoo-db')
        self.assertTrue(service.started, 'the caller then has to stop it himself')


class LiveJsonTests(Case):
    """hacommon.live_json: a database that is not running is started once and read again; the rest says what is wrong."""

    def read(self, **kwargs):
        return hacommon.live_json(self.work, APP, 'odoo-db', 'odoo', 'odoo', 'select 1', **kwargs)

    def ok(self, text=b'{"a": 1}\n'):
        return podman.Result(0, text, b'')

    def test_the_read_that_works_asks_nothing_more(self):
        self.world.exec_results = [self.ok()]
        self.assertEqual(self.read(), {'a': 1})
        self.assertEqual([c[:3] for c in self.world.calls], [('podman', 'exec', 'odoo-db')])

    def test_a_database_that_does_not_run_is_started_waited_for_and_read(self):
        stopped = podman.Result(125, b'', b'Error: no container with name or ID "odoo-db" found: no such container')
        self.world.exec_results = [stopped, self.ok()]
        self.assertEqual(self.read(), {'a': 1})
        self.assertIn(('systemctl', 'start', '--', 'odoo-db.service'), self.world.calls)
        self.assertEqual(self.issues(), [('target.service-started', 'auto')])
        self.assertEqual(self.temp.services, {'odoo-db': 'odoo-db.service'}, 'put back with the throwaway objects')
        self.temp.cleanup()
        self.assertEqual(self.world.running, set())

    def test_a_database_that_is_starting_up_is_waited_for(self):
        self.world.running.add('odoo-db')
        self.world.not_ready = 2
        self.world.exec_results = [podman.Result(2, b'', b'psql: error: connection to server on socket failed: FATAL:  '
                                                   b'the database system is starting up'), self.ok()]
        self.assertEqual(self.read(), {'a': 1})
        self.assertFalse([c for c in self.world.calls if c[0] == 'systemctl'], 'it ran: nothing is started')
        self.assertEqual(self.issues(), [])

    def test_a_database_that_needs_its_recovery_gets_the_time_of_a_big_backup(self):
        self.world.not_ready = 10 ** 6
        self.world.exec_results = [podman.Result(125, b'', b'Error: no such container')]
        self.work.ha = types.SimpleNamespace(layout=types.SimpleNamespace(size=200 * 1024 ** 3))
        with self.assertRaises(BackupError) as caught:
            self.read()
        limit = podman.scaled_timeout(hatarget.READY_TIMEOUT, 800 * 1024 ** 3)
        self.assertGreater(limit, hatarget.READY_TIMEOUT)
        self.assertIn(f'{limit} 秒內', caught.exception.message)

    def test_it_is_started_only_once_a_second_failure_is_the_answer(self):
        dead = podman.Result(125, b'', b'Error: no such container')
        self.world.exec_results = [dead]
        with self.assertRaises(BackupError) as caught:
            self.read()
        self.assertIn('請確認它正在執行', caught.exception.message)
        self.assertEqual(len([c for c in self.world.calls if c[0] == 'systemctl']), 1)
        self.assertEqual(len([c for c in self.world.calls if c[:3] == ('podman', 'exec', 'odoo-db') and c[3] == 'psql']), 2)

    def test_a_service_that_cannot_be_started_says_so_instead_of_asking_to_check_it(self):
        self.world.exec_results = [podman.Result(125, b'', b'Error: no such container')]
        self.world.start = podman.Result(1, b'', b'Job for odoo-db.service failed because the control process exited with '
                                                 b'error code.')
        with self.assertRaises(BackupError) as caught:
            self.read()
        self.assertEqual(caught.exception.issues[0].id, 'target.service-failed')
        self.assertIn('啟動失敗', caught.exception.message)

    def test_a_wrong_account_or_name_is_told_and_nothing_is_started(self):
        for stderr, words in ((b'psql: error: ... FATAL:  password authentication failed for user "odoo"', '帳號或密碼'),
                              (b'psql: error: ... FATAL:  database "odoo" does not exist', '資料庫不存在'),
                              (b'psql: error: ... FATAL:  role "odoo" does not exist', '帳號不存在')):
            with self.subTest(words=words):
                self.world.calls.clear()
                self.world.exec_results = [podman.Result(2, b'', stderr)]
                with self.assertRaises(BackupError) as caught:
                    self.read()
                self.assertIn(words, caught.exception.message)
                self.assertNotIn('請確認它正在執行', caught.exception.message)
                self.assertNotIn('odoo"', caught.exception.message)
                self.assertFalse([c for c in self.world.calls if c[0] == 'systemctl'])

    def test_an_unknown_failure_keeps_the_old_sentence_other_errors_come_up_as_they_are(self):
        self.world.exec_results = [podman.Result(1, b'', b'something new')]
        with self.assertRaises(BackupError) as caught:
            self.read()
        self.assertEqual(caught.exception.message, '無法讀取這台「Odoo 18」的資料庫，請確認它正在執行。')
        error = BackupError('limit-exceeded', 'too much')
        self.owner.podman = lambda *a, **k: (_ for _ in ()).throw(error)
        with self.assertRaises(BackupError) as caught:
            self.read()
        self.assertIs(caught.exception, error)

    def test_an_answer_that_is_no_json_is_an_unreadable_database(self):
        self.world.exec_results = [self.ok(b'not json')]
        with self.assertRaises(BackupError) as caught:
            self.read()
        self.assertEqual(caught.exception.message, '無法讀取這台「Odoo 18」的資料庫。')

    def test_the_room_and_the_time_grow_with_the_data_the_old_values_are_the_floor(self):
        seen = {}
        real = self.owner.podman

        def spy(*args, **kwargs):
            seen.update(timeout=kwargs.get('timeout'), max_output=kwargs.get('max_output'))
            return real(*args, **kwargs)

        self.owner.podman = spy
        self.world.exec_results = [self.ok()]
        self.read()
        self.assertEqual(seen, {'timeout': 120, 'max_output': hacommon.LIVE_JSON_OUTPUT})
        self.assertGreater(hacommon.LIVE_JSON_OUTPUT, 4 * 1024 * 1024, 'X-PD-04: more room than before')
        self.read(size=500 * 1024 ** 2)
        self.assertEqual(seen['max_output'], 1000 * 1024 ** 2 if 1000 * 1024 ** 2 < hacommon.LIVE_JSON_CEILING
                         else hacommon.LIVE_JSON_CEILING)
        self.assertGreater(seen['timeout'], 120)
        self.read(size=1 << 50)
        self.assertEqual(seen['max_output'], hacommon.LIVE_JSON_CEILING)

    def test_without_a_size_the_wait_follows_the_open_ha_backup_the_room_does_not(self):
        seen = {}
        real = self.owner.podman

        def spy(*args, **kwargs):
            seen.update(timeout=kwargs.get('timeout'), max_output=kwargs.get('max_output'))
            return real(*args, **kwargs)

        self.owner.podman = spy
        self.world.exec_results = [self.ok()]
        self.work.ha = types.SimpleNamespace(layout=types.SimpleNamespace(size=100 * 1024 ** 3))
        self.read()
        self.assertEqual(seen['timeout'], podman.scaled_timeout(120, 400 * 1024 ** 3))
        self.assertGreater(seen['timeout'], 120)
        self.assertEqual(seen['max_output'], hacommon.LIVE_JSON_OUTPUT, 'an HA file says nothing about this answer')
        self.read(size=5)
        self.assertEqual(seen['timeout'], 120, 'a size the caller names is the one that counts')

    def test_a_big_catalog_that_the_old_limit_refused_is_read(self):
        rows = [{'table': f'public.t{i}', 'columns': ['id', 'name', 'created_at', 'owner_id']} for i in range(60000)]
        big = json.dumps(rows).encode() + b'\n'
        self.assertGreater(len(big), 4 * 1024 * 1024)
        self.world.exec_results = [self.ok(big)]
        self.assertEqual(len(self.read()), 60000)


class UserManagerHelperTests(Case):
    def test_a_runner_without_it_does_nothing(self):
        self.assertFalse(hatarget.ensure_user_manager(self.work, APP))
        self.assertEqual(self.issues(), [])

    def test_enabling_is_said_once_as_an_automatic_line(self):
        self.owner.ensure_user_manager = lambda **kwargs: True
        self.assertTrue(hatarget.ensure_user_manager(self.work, APP))
        self.assertEqual(self.issues(), [('target.linger-enabled', 'auto')])
        self.assertIn('appowner', self.sinks['odoo'].found[0].message)
        self.owner.ensure_user_manager = lambda **kwargs: False
        self.assertFalse(hatarget.ensure_user_manager(self.work, APP))
        self.assertEqual(len(self.issues()), 1)

    def test_a_manager_that_cannot_be_started_stops_this_app_with_what_to_do(self):
        def fail(**kwargs):
            raise BackupError('job-failed', '帳號 appowner 的使用者服務管理器沒有在執行，自動開啟失敗。')

        self.owner.ensure_user_manager = fail
        with self.assertRaises(BackupError) as caught:
            hatarget.ensure_user_manager(self.work, APP)
        issue = caught.exception.issues[0]
        self.assertEqual((issue.id, issue.level), ('target.linger-failed', 'stop'))
        self.assertTrue(issue.action)
        error = haissues.job_wide(BackupError('insufficient-space', 'full'))
        self.owner.ensure_user_manager = lambda **kwargs: (_ for _ in ()).throw(error)
        with self.assertRaises(BackupError) as caught:
            hatarget.ensure_user_manager(self.work, APP)
        self.assertIs(caught.exception, error)

    def test_every_service_start_asks_for_the_manager_first(self):
        asked = []
        self.owner.ensure_user_manager = lambda **kwargs: asked.append(1) or False
        self.world.running.add('odoo-db')
        hatarget.ensure_running(self.work, APP, 'odoo-db')
        self.assertEqual(asked, [1])


class RetryAndWaitTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.log = []

    def retry(self, action, **kwargs):
        return hatarget.retry(action, sleep=self.clock.sleep, log=self.log.append, **kwargs)

    def failing(self, times, error):
        state = {'calls': 0}

        def action():
            state['calls'] += 1
            if state['calls'] <= times:
                raise error
            return 'value'

        return action, state

    def test_a_read_that_fails_for_a_moment_is_tried_again_with_growing_pauses(self):
        action, state = self.failing(2, BackupError('job-failed', 'snapshot unreadable'))
        self.assertEqual(self.retry(action, attempts=3, pause_first=2, what='讀取結構快照'), 'value')
        self.assertEqual(state['calls'], 3)
        self.assertEqual(sum(self.clock.slept), 2 + 4)
        self.assertEqual(len(self.log), 2)
        self.assertIn('讀取結構快照', self.log[0])
        self.assertIn('2 秒後再試一次', self.log[0])
        self.assertIn('4 秒後', self.log[1])

    def test_the_last_failure_is_raised_as_it_came(self):
        errors = [BackupError('job-failed', f'try {i}') for i in range(3)]
        calls = iter(errors)

        def action():
            raise next(calls)

        with self.assertRaises(BackupError) as caught:
            self.retry(action, attempts=3)
        self.assertIs(caught.exception, errors[2])

    def test_the_pause_has_a_ceiling_and_a_count_below_one_is_one_try(self):
        action, _state = self.failing(6, BackupError('job-failed', 'x'))
        with self.assertRaises(BackupError):
            self.retry(action, attempts=6, pause_first=10, factor=10, longest=15)
        self.assertEqual(sorted(set(self.clock.slept)), [1.0])
        self.assertEqual(sum(self.clock.slept), 10 + 15 + 15 + 15 + 15)
        action, state = self.failing(1, BackupError('job-failed', 'x'))
        with self.assertRaises(BackupError):
            self.retry(action, attempts=0)
        self.assertEqual(state['calls'], 1)

    def test_what_will_not_pass_is_not_tried_again(self):
        permanent = podman.CommandError('x', returncode=1, stderr=b'password authentication failed', reason='db-auth')
        for error in (permanent, BackupError('incompatible', 'x'), BackupError('insufficient-space', 'x'),
                      haissues.job_wide(BackupError('job-failed', 'x')), ValueError('x')):
            with self.subTest(error=type(error).__name__ + getattr(error, 'code', '')):
                action, state = self.failing(5, error)
                with self.assertRaises(type(error)):
                    self.retry(action, attempts=3)
                self.assertEqual(state['calls'], 1)

    def test_a_transient_reason_is_retried_and_ones_own_judge_decides(self):
        busy = podman.CommandError('x', returncode=1, stderr=b'resource temporarily unavailable', reason='storage-busy')
        action, state = self.failing(1, busy)
        self.assertEqual(self.retry(action), 'value')
        action, state = self.failing(1, ValueError('x'))
        self.assertEqual(self.retry(action, retry_if=lambda error: isinstance(error, ValueError)), 'value')

    def test_the_watchdog_ends_the_wait_and_the_tries(self):
        verdict = haissues.job_wide(BackupError('insufficient-space', 'disk'))
        action, state = self.failing(5, BackupError('job-failed', 'x'))
        with self.assertRaises(BackupError) as caught:
            self.retry(action, attempts=5, pause_first=30, abort=lambda: verdict if self.clock.now >= 3 else None)
        self.assertIs(caught.exception, verdict)
        self.assertLess(self.clock.now, 5, 'not a whole pause later')
        with self.assertRaises(BackupError):
            self.retry(lambda: 'never', abort=lambda: verdict)

    def test_wait_until(self):
        clock = Clock()
        polls = []

        def ready():
            polls.append(clock.now)
            return len(polls) == 4

        self.assertTrue(hatarget.wait_until(ready, timeout=60, interval=2, sleep=clock.sleep, clock=clock.clock))
        self.assertEqual(polls, [0, 2, 4, 6])
        clock = Clock()
        self.assertFalse(hatarget.wait_until(lambda: False, timeout=5, interval=2, sleep=clock.sleep, clock=clock.clock))
        self.assertEqual(clock.now, 5, 'the last slice is cut at the deadline')
        self.assertTrue(hatarget.wait_until(lambda: True, timeout=0, sleep=clock.sleep, clock=clock.clock))
        verdict = BackupError('job-failed', 'stop')
        with self.assertRaises(BackupError) as caught:
            hatarget.wait_until(lambda: False, timeout=5, abort=lambda: verdict, sleep=clock.sleep, clock=clock.clock)
        self.assertIs(caught.exception, verdict)


class LiveExportTests(Case):
    """hacommon.live_export: the 3 hours it always had are the floor, a big volume gets more (X-PD-05)."""

    def test_the_wait_grows_with_the_volume(self):
        seen = []
        self.owner.relay = lambda args, *, stdout, timeout=None, max_output=None, check=True, abort=None: (
            seen.append(timeout), stdout.write(b'tar'))
        path = Path(self.tmpdir.name)
        hacommon.live_export(self.work, APP, 'odoo-db', path / 'a.tar')
        hacommon.live_export(self.work, APP, 'odoo-db', path / 'b.tar', size=5 * 1024 ** 4)
        self.assertEqual(seen[0], 3 * 3600)
        self.assertEqual(seen[1], podman.scaled_timeout(3 * 3600, 5 * 1024 ** 4))
        self.assertGreater(seen[1], 3 * 3600)
        self.assertEqual(oct((path / 'a.tar').stat().st_mode & 0o777), '0o600')


class CarryTests(Case):
    """OD-12/13, N8-02/27, O-07, HS-04, CS-04: this device's own volumes and folders go into the backup as they are."""

    def tar(self, members):
        return hx.tar_bytes(members)

    def test_what_the_importer_does_not_convert(self):
        self.assertEqual(hatarget.extras(APP, ['odoo-db', 'odoo-web'], ['.local/share/odoo/addons']),
                         (['odoo-extra'], ['.local/share/odoo/files']))
        self.assertEqual(hatarget.extras(APP, ['odoo-db', 'odoo-web', 'odoo-extra'], APP.data_dirs and
                                         [d['path'] for d in APP.data_dirs]), ([], []))
        self.assertEqual(hatarget.extras(types.SimpleNamespace()), ([], []))

    def carried(self, **kwargs):
        out_dir = Path(self.tmpdir.name) / 'out'
        out_dir.mkdir(exist_ok=True)
        return out_dir, hatarget.carry(self.work, APP, out_dir, IDS, **kwargs)

    def test_a_volume_is_copied_as_it_is_checked_and_its_staging_copy_removed(self):
        self.world.volumes['odoo-extra'] = self.tar([
            {'name': '.', 'type': 'dir', 'uid': 1000, 'gid': 1000}, {'name': 'a', 'data': b'abc', 'uid': 1000, 'gid': 1000},
            {'name': 'ln', 'type': 'symlink', 'linkname': 'a', 'uid': 1000, 'gid': 1000}])
        out_dir, carried = self.carried(volumes=['odoo-extra'])
        path = out_dir / 'volumes' / 'odoo-extra.tar'
        self.assertEqual(carried, {'volumes': {'odoo-extra': path}, 'dirs': {}})
        with tarfile.open(path) as tar:
            self.assertEqual(sorted(m.name for m in tar.getmembers()), ['.', 'a', 'ln'])
            self.assertEqual(tar.extractfile('a').read(), b'abc')
        self.assertEqual(nested.check_volume(path, ids=IDS).members, 3)
        self.assertEqual(list(Path(self.tmpdir.name).glob('carry-*')), [], 'no staging copy is left')
        self.assertEqual(oct(path.stat().st_mode & 0o777), '0o600')

    def test_a_customers_link_out_of_the_volume_is_left_out_and_listed_not_a_refusal(self):
        self.world.volumes['odoo-extra'] = self.tar([
            {'name': '.', 'type': 'dir', 'uid': 1000, 'gid': 1000}, {'name': 'keep', 'data': b'k', 'uid': 1000, 'gid': 1000},
            {'name': 'sub', 'type': 'dir', 'uid': 1000, 'gid': 1000},
            {'name': 'sub/up', 'type': 'symlink', 'linkname': '../../etc', 'uid': 1000, 'gid': 1000},
            {'name': 'out', 'type': 'symlink', 'linkname': '../outside', 'uid': 1000, 'gid': 1000}])
        report = habackup.Report(names=haissues.Names)
        out_dir, carried = self.carried(volumes=['odoo-extra'], report=report)
        with tarfile.open(carried['volumes']['odoo-extra']) as tar:
            self.assertEqual(sorted(m.name for m in tar.getmembers()), ['.', 'keep', 'sub'])
        self.assertEqual(report.skips['symlink'].first, ['odoo-extra：sub/up', 'odoo-extra：out'])
        nested.check_volume(carried['volumes']['odoo-extra'], ids=IDS)
        # the same volume without a report is what the restore's own check refuses
        with self.assertRaises(BackupError):
            hatarget.carry(self.work, APP, Path(self.tmpdir.name) / 'out2', IDS, volumes=['odoo-extra'])

    def test_a_folder_is_packed_in_the_owners_namespace_and_checked(self):
        rel = '.local/share/odoo/files'
        self.world.dirs[rel] = self.tar([{'name': '.', 'type': 'dir', 'uid': 1000, 'gid': 1000},
                                         {'name': './f.txt', 'data': b'x', 'uid': 1000, 'gid': 1000}])
        out_dir, carried = self.carried(dirs=[rel])
        self.assertEqual(carried['dirs'], {rel: out_dir / 'dirs' / 'carry-0.tar'})
        self.assertIn(('dir_pack', rel), self.world.calls)

    def test_a_bad_name_or_a_broken_copy_stops_this_app_and_leaves_nothing(self):
        for name in ('../x', 'a b', '', None, 'x/y'):
            with self.subTest(name=name), self.assertRaises(BackupError) as caught:
                self.carried(volumes=[name])
            self.assertEqual(caught.exception.code, 'internal-error')
        self.world.volumes['odoo-extra'] = b'not a tar' * 100
        with self.assertRaises(BackupError):
            self.carried(volumes=['odoo-extra'])
        self.assertEqual(list(Path(self.tmpdir.name).glob('carry-*')), [])


class RealWorkTests(hi.FlowCase):
    """The put-back through the real haimport.Work: a service started for a read is stopped again when the app's throwaway
    objects are cleaned (`Work.reset_app`, `Work.close`), also when that cannot be done at once (CM-07)."""

    def setUp(self):
        super().setUp()
        self.owner_world = World()
        self.owner = Owner(self.owner_world)
        self.app = hi.app('odoo', 'Odoo 18')
        adapter = hi.FakeHaAdapter(self.app, self.world)
        adapter.runner = self.owner
        adapter.read_quadlets = lambda: {'odoo-db.container': QUADLET}
        self.deps.adapter_factory = lambda _app, **_kwargs: adapter
        self.work = haimport.Work(self.ctx(), None, None, self.root)
        self.work.guard.folders = []
        patcher = mock.patch.object(hatarget, '_sleep', lambda _seconds: None)
        patcher.start()
        self.addCleanup(patcher.stop)

    def read_with_a_stopped_database(self):
        stopped = podman.Result(125, b'', b'Error: no container with name or ID "odoo-db" found: no such container')
        self.owner_world.exec_results = [stopped, podman.Result(0, b'{"a": 1}\n', b'')]
        return hacommon.live_json(self.work, self.app, 'odoo-db', 'odoo', 'odoo', 'select 1')

    def stops(self):
        return [call for call in self.owner_world.calls if call[:2] == ('systemctl', 'stop')]

    def test_the_app_is_read_and_the_service_is_stopped_again_when_the_app_is_done(self):
        self.assertEqual(self.read_with_a_stopped_database(), {'a': 1})
        self.assertEqual(self.owner_world.running, {'odoo-db'}, 'running while the app is worked on')
        self.assertEqual(self.stops(), [])
        self.work.reset_app(self.app)
        self.assertEqual(self.stops(), [('systemctl', 'stop', '--', 'odoo-db.service')])
        self.assertEqual(self.owner_world.running, set())
        self.assertEqual(self.work.close(), [])
        self.assertEqual(len(self.stops()), 1, 'put back once')

    def test_a_job_that_ends_without_reset_still_puts_it_back_at_close(self):
        self.read_with_a_stopped_database()
        self.assertEqual(self.work.close(), [])
        self.assertEqual(self.owner_world.running, set())

    def test_a_put_back_that_could_not_be_done_is_tried_again_at_the_end(self):
        self.read_with_a_stopped_database()
        self.owner_world.stop = podman.Result(1, b'', b'Failed to stop odoo-db.service: Access denied')
        self.work.reset_app(self.app)
        self.assertEqual(self.owner_world.running, {'odoo-db'})
        self.assertTrue(any('沒能恢復原狀' in line for line in self.reporter.logs), self.reporter.logs)
        self.owner_world.stop = None
        self.assertEqual(self.work.close(), [], 'the end of the job tries again and succeeds')
        self.assertEqual(self.owner_world.running, set())

    def test_the_apps_result_says_what_was_done(self):
        self.read_with_a_stopped_database()
        found = [(issue.id, issue.level) for issue in self.work.sink(self.app).found]
        self.assertEqual(found, [('target.service-started', 'auto')])
        self.assertTrue(any('自動處理：' in line and '暫時啟動' in line for line in self.reporter.logs), self.reporter.logs)
        self.work.close()


class NotDeployedTests(unittest.TestCase):
    """FL-11 and HA-07: the real reason is told, not "not deployed here"."""

    def test_the_adapters_reason_comes_first(self):
        info = {'deployed': False, 'state': 'error', 'units': [], 'problems': ['帳號 appowner 的使用者服務管理器未啟動，請為此帳號啟用 linger。']}
        error = hatarget.not_deployed_error(APP, info)
        self.assertEqual(error.code, 'job-failed')
        self.assertIn('使用者服務管理器未啟動', error.message)
        self.assertIn('Odoo 18', error.message)
        self.assertEqual(error.details['app'], 'odoo')

    def test_without_a_reason_it_is_what_it_always_said(self):
        for info in ({'deployed': False, 'problems': []}, {}, None):
            error = hatarget.not_deployed_error(APP, info)
            self.assertEqual((error.code, error.message), ('not-deployed', '應用「Odoo 18」尚未部署在此設備，無法備份。'))


class ScaleWaitsTests(unittest.TestCase):
    """X-PD-05: the waits of an app's throwaway containers follow the size of the HA backup it comes from."""

    def test_a_big_backup_stretches_the_waits_of_the_apps_throwaway_objects(self):
        tmp = tempctr.TempObjects(types.SimpleNamespace(uid=None), JOB, cpus=None)
        ha = types.SimpleNamespace(layout=types.SimpleNamespace(size=25 * 1024 ** 3))
        hatarget.scale_waits(tmp, ha)
        self.assertEqual(tmp.size, 100 * 1024 ** 3, 'four times the stored size: what it may be unpacked')
        self.assertGreater(tmp._wait(600), 600)

    def test_the_size_hint(self):
        self.assertEqual(hatarget.size_hint(types.SimpleNamespace(layout=types.SimpleNamespace(size=10))), 40)
        for ha in (None, types.SimpleNamespace(), types.SimpleNamespace(layout=types.SimpleNamespace(size=0)),
                   types.SimpleNamespace(layout=types.SimpleNamespace(size=True))):
            self.assertIsNone(hatarget.size_hint(ha))

    def test_what_does_not_know_a_size_changes_nothing(self):
        tmp = tempctr.TempObjects(types.SimpleNamespace(uid=None), JOB, cpus=None)
        for ha in (None, types.SimpleNamespace(), types.SimpleNamespace(layout=None),
                   types.SimpleNamespace(layout=types.SimpleNamespace(size=0)),
                   types.SimpleNamespace(layout=types.SimpleNamespace(size=True)),
                   types.SimpleNamespace(layout=types.SimpleNamespace(size='9'))):
            hatarget.scale_waits(tmp, ha)
            self.assertIsNone(tmp.size)
        hatarget.scale_waits(types.SimpleNamespace(), types.SimpleNamespace(layout=types.SimpleNamespace(size=5)))  # a double


if __name__ == '__main__':
    unittest.main()
