"""Throwaway containers of a job (tempctr.py, CONTRACT section 8 "Throwaway containers"): exact command lines, the
Quadlet parsing that decides secrets/environment/images, clean-up and the sweep of a dead job's objects. Team E2."""
import io
import json
import threading
import types
import unittest

from woowbackup import podman, tempctr
from woowbackup.errors import BackupError
from woowbackup.podman import CommandError, Result

JOB = 'j20261118T110400Z-c6bd8629'
OTHER = 'j20261117T010101Z-00000001'


class FakeRunner:
    """Records podman calls; `answers` maps a command prefix tuple to a Result (or a callable)."""

    def __init__(self, answers=None):
        self.calls = []
        self.answers = dict(answers or {})
        self.home = '/home/appowner'
        self.uid = 1013
        self.owner = 'appowner'
        self.lock = threading.Lock()

    def podman(self, *args, input=None, stdout=None, timeout=None, max_output=None, check=True):
        with self.lock:
            self.calls.append(args)
        data = None
        if input is not None and hasattr(input, 'read'):
            data = input.read()
        for prefix, answer in sorted(self.answers.items(), key=lambda kv: -len(kv[0])):
            if args[:len(prefix)] == prefix:
                result = answer(args, data) if callable(answer) else answer
                break
        else:
            result = Result(0, b'', b'')
        if check and result.returncode != 0:
            raise CommandError('podman failed', returncode=result.returncode, stderr=result.stderr)
        return result

    def relay(self, args, *, stdout, timeout=None, max_output=None, check=True):
        self.calls.append(('relay', *args))
        stdout.write(b'exported')


class ArgvTests(unittest.TestCase):
    def setUp(self):
        self.runner = FakeRunner()
        self.tmp = tempctr.TempObjects(self.runner, JOB)

    def test_names_and_validation(self):
        self.assertEqual(self.tmp.name('hapg'), f'woowbk-{JOB}-hapg')
        for role in ('', 'Upper', 'a' * 40, '../x', 'a b'):
            with self.subTest(role=role), self.assertRaises(BackupError):
                self.tmp.name(role)
        with self.assertRaises(BackupError):
            tempctr.TempObjects(self.runner, 'not-a-job')

    def test_run_argv_is_locked_down(self):
        argv = self.tmp.run_argv('odoo-db', 'docker.io/library/postgres:16.15-alpine', ['postgres', '-c', 'x=1'],
                                 detach=True, env={'POSTGRES_DB': 'n8n'},
                                 volumes=[(self.tmp.name('odoo-db'), '/var/lib/postgresql/data', None),
                                          ('/home/appowner/.local/share/odoo18/addons', '/mnt/extra-addons', 'ro')],
                                 secrets=['odoo18-postgres-super-password,type=mount,target=postgres_password,uid=999,'
                                          'gid=999,mode=0400'])
        self.assertEqual(argv[:18], ['run', '--name', f'woowbk-{JOB}-odoo-db', '--label',
                                     f'io.woowtech.backup.job={JOB}', '--pull=never', '--log-driver', 'none',
                                     '--network', 'none', '--security-opt', 'no-new-privileges', '--pids-limit',
                                     '1024', '--memory', '2g', '--detach', '--env'])
        self.assertIn('POSTGRES_DB=n8n', argv)
        self.assertIn(f'woowbk-{JOB}-odoo-db:/var/lib/postgresql/data', argv)
        self.assertIn('/home/appowner/.local/share/odoo18/addons:/mnt/extra-addons:ro', argv)
        self.assertEqual(argv[argv.index('--secret') + 1].split(',')[0], 'odoo18-postgres-super-password')
        self.assertEqual(argv[-4:], ['docker.io/library/postgres:16.15-alpine', 'postgres', '-c', 'x=1'])
        self.assertNotIn('--publish', argv)
        self.assertNotIn('-p', argv)

    def test_read_only_root_gets_a_private_secrets_tmpfs(self):
        # runc 1.5.1 under rootless Podman 6.1.1 cannot create a secret file's mount point in a read-only root
        # (exit 126, lane arm54-2 on the ARM test target); a tmpfs at /run/secrets holds it with any runtime.
        image = 'docker.io/library/postgres:16.15-alpine'
        mounted = ['pg-password,type=mount,target=/run/secrets/postgres-password,mode=0400']
        argv = self.tmp.run_argv('omni-db', image, [], detach=True, read_only_root=True, secrets=mounted)
        self.assertIn('--read-only', argv)
        self.assertEqual(argv[argv.index('--tmpfs') + 1], '/run/secrets:rw,noexec,nosuid,nodev,mode=0755')
        self.assertLess(argv.index('--tmpfs'), argv.index('--secret'))
        self.assertEqual(argv[argv.index('--secret') + 1], mounted[0])
        for secrets in (['pg-password'], ['pg-password,type=mount,target=postgres_password,uid=999,gid=999,mode=0400']):
            self.assertIn('--tmpfs', self.tmp.run_argv('x', image, [], read_only_root=True, secrets=secrets))
        for options in ({'read_only_root': False, 'secrets': mounted},
                        {'read_only_root': True, 'secrets': ['pg-password,type=env,target=PGPASSWORD']},
                        {'read_only_root': True, 'secrets': ['odoo-conf,type=mount,target=/etc/odoo/odoo.conf']},
                        {'read_only_root': True, 'secrets': []}):
            self.assertNotIn('--tmpfs', self.tmp.run_argv('x', image, [], **options), options)
        self.assertEqual(tempctr.secret_mount_path('a,type=env,target=A'), '')
        self.assertEqual(tempctr.secret_mount_path('a'), '/run/secrets/a')

    def test_run_argv_refuses_unsafe_values(self):
        image = 'docker.io/library/postgres:16.15-alpine'
        bad = [
            dict(network='host'),                        # only an internal network this job made
            dict(env={'BAD KEY': 'x'}), dict(env={'K': 'line\nbreak'}),
            dict(volumes=[('../etc', '/x', None)]), dict(volumes=[('vol', 'relative', None)]),
            dict(volumes=[('vol', '/x', 'ro,Z;rm')]),
            dict(secrets=['name,type=mount,target=/x;rm']), dict(secrets=['-x']),
            dict(entrypoint='sh -c'), dict(user='root;x'), dict(workdir='x'),
        ]
        for options in bad:
            with self.subTest(options=options), self.assertRaises(BackupError):
                self.tmp.run_argv('x', image, [], **options)
        with self.assertRaises(BackupError):
            self.tmp.run_argv('x', 'bad image', [])
        with self.assertRaises(BackupError):
            self.tmp.run_argv('x', image, ['a\x00b'])

    def test_an_internal_network_of_the_job(self):
        net = self.tmp.network('net')
        self.assertEqual(self.runner.calls[-1], ('network', 'create', '--internal', '--label',
                                                 f'io.woowtech.backup.job={JOB}', net))
        argv = self.tmp.run_argv('x', 'img:1', [], network=net)
        self.assertEqual(argv[argv.index('--network') + 1], net)
        with self.assertRaises(BackupError):
            self.tmp.network('net')  # two apps of one job need two roles

    def test_one_shot_runs_use_rm_and_free_their_role(self):
        self.runner.answers[('run',)] = Result(0, b'70\n70\n', b'')
        self.assertEqual(self.tmp.user_ids('ids', 'img:1', 'postgres'), (70, 70))
        self.assertIn('--rm', self.runner.calls[-1])
        self.assertEqual(self.tmp.user_ids('ids', 'img:1', 'postgres'), (70, 70), 'the role can be used again')
        self.runner.answers[('run',)] = Result(0, b'x\n', b'')
        with self.assertRaises(BackupError):
            self.tmp.user_ids('ids2', 'img:1', 'postgres')

    def test_exec_only_in_this_jobs_containers(self):
        with self.assertRaises(BackupError):
            self.tmp.exec('hapg', ['true'])
        self.tmp.run('hapg', 'img:1', [], detach=True)
        self.tmp.exec('hapg', ['psql', '-c', 'x'], user='postgres', input=b'data')
        self.assertEqual(self.runner.calls[-1], ('exec', '--interactive', '--user', 'postgres', f'woowbk-{JOB}-hapg',
                                                 'psql', '-c', 'x'))


class QuadletTests(unittest.TestCase):
    TEXT = """[Container]
ContainerName=odoo18-db
Image=jcr-prod.woowtech.io/woow-paas-docker-local/paas-postgres:17.11@sha256:7a47
Environment=POSTGRES_USER=postgres
Environment=POSTGRES_DB=postgres "POSTGRES_INITDB_ARGS=--data-checksums --locale=C"
Environment=SECRET_TOKEN=do-not-pass
Secret=odoo18-postgres-super-password,type=mount,target=postgres_password,uid=999,gid=999,mode=0400
# Secret=commented,type=env
"""

    def test_secrets_environment_and_image(self):
        self.assertEqual(tempctr.quadlet_secrets(self.TEXT), [
            'odoo18-postgres-super-password,type=mount,target=postgres_password,uid=999,gid=999,mode=0400'])
        env = tempctr.quadlet_environment(self.TEXT, {'POSTGRES_USER', 'POSTGRES_DB', 'POSTGRES_INITDB_ARGS'})
        self.assertEqual(env, {'POSTGRES_USER': 'postgres', 'POSTGRES_DB': 'postgres',
                               'POSTGRES_INITDB_ARGS': '--data-checksums --locale=C'})
        self.assertEqual(tempctr.quadlet_image(self.TEXT.encode()),
                         'jcr-prod.woowtech.io/woow-paas-docker-local/paas-postgres:17.11@sha256:7a47')

    def test_unsupported_values_are_refused(self):
        for text in ('[Container]\nSecret=x,target=/a b\n', '[Container]\nSecret=x,rm=1\n',
                     '[Container]\nImage=app.build\n', '[Container]\nImage=bad image\n'):
            with self.subTest(text=text), self.assertRaises(BackupError):
                tempctr.quadlet_secrets(text) if 'Secret' in text else tempctr.quadlet_image(text)
        with self.assertRaises(BackupError):
            tempctr.quadlet_environment('[Container]\nEnvironment="UNCLOSED=1\n', {'UNCLOSED'})


class CleanupTests(unittest.TestCase):
    def test_cleanup_tracks_only_failed_kind_for_same_name(self):
        runner = FakeRunner({('volume', 'rm'): Result(125, b'', b'in use'),
                             ('volume', 'exists'): Result(0, b'', b'')})
        tmp = tempctr.TempObjects(runner, JOB)
        tmp.run('same', 'img:1', detach=True)
        tmp.volume('same')
        tmp.network('same')
        self.assertEqual(tmp.cleanup(), [tmp.name('same')])
        self.assertEqual((tmp.containers, tmp.volumes, tmp.networks), ([], [tmp.name('same')], []))

    def test_explicit_remove_failure_is_tracked_and_cleanup_retries(self):
        for kind in ('container', 'volume'):
            with self.subTest(kind=kind):
                remove_cmd = ('rm',) if kind == 'container' else ('volume', 'rm')
                runner = FakeRunner({remove_cmd: Result(125, b'', b'failure'),
                                     (kind, 'exists'): Result(0, b'', b'')})
                tmp = tempctr.TempObjects(runner, JOB)
                if kind == 'container':
                    tmp.run('item', 'img:1', detach=True)
                    tracked, remove = tmp.containers, tmp.remove
                else:
                    tmp.volume('item')
                    tracked, remove = tmp.volumes, tmp.remove_volume
                name = tmp.name('item')
                self.assertFalse(remove('item'), 'X-TC-05: a leftover that cannot be removed stops nothing')
                self.assertIn(name, tracked)
                self.assertEqual(tmp.cleanup(), [name])
                self.assertIn(name, getattr(tmp, kind + 's'))
                runner.answers[remove_cmd] = Result(0, b'', b'')
                self.assertEqual(tmp.cleanup(), [])
                self.assertNotIn(name, getattr(tmp, kind + 's'))

    def test_explicit_remove_accepts_only_confirmed_absence(self):
        for kind in ('container', 'volume'):
            with self.subTest(kind=kind):
                remove_cmd = ('rm',) if kind == 'container' else ('volume', 'rm')
                runner = FakeRunner({remove_cmd: Result(125, b'', b'failure'),
                                     (kind, 'exists'): Result(125, b'', b'unknown')})
                tmp = tempctr.TempObjects(runner, JOB)
                if kind == 'container':
                    tmp.run('item', 'img:1', detach=True)
                    remove = tmp.remove
                else:
                    tmp.volume('item')
                    remove = tmp.remove_volume
                self.assertFalse(remove('item'))
                self.assertIn(tmp.name('item'), getattr(tmp, kind + 's'))
                runner.answers[(kind, 'exists')] = Result(1, b'', b'')
                self.assertTrue(remove('item'))
                self.assertNotIn(tmp.name('item'), getattr(tmp, kind + 's'))

    def test_everything_is_removed_containers_first(self):
        runner = FakeRunner()
        with tempctr.TempObjects(runner, JOB) as tmp:
            tmp.volume('hapg')
            tmp.network('net')
            tmp.run('hapg', 'img:1', [], detach=True)
            runner.calls.clear()
        self.assertEqual(runner.calls, [('rm', '--force', '--time', '10', f'woowbk-{JOB}-hapg'),
                                        ('volume', 'rm', '--force', f'woowbk-{JOB}-hapg'),
                                        ('network', 'rm', '--force', f'woowbk-{JOB}-net')])
        self.assertEqual((tmp.containers, tmp.volumes, tmp.networks), ([], [], []))

    def test_leftovers_are_reported_but_never_raise(self):
        runner = FakeRunner({('volume', 'rm'): Result(125, b'', b'in use'),
                             ('volume', 'exists'): Result(0, b'', b'')})
        notes = []
        tmp = tempctr.TempObjects(runner, JOB, log=notes.append)
        tmp.volume('hapg')
        self.assertEqual(tmp.cleanup(), [f'woowbk-{JOB}-hapg'])
        self.assertTrue(notes and '暫用' in notes[0])
        runner.answers[('volume', 'exists')] = Result(1, b'', b'')
        tmp.volume('gone')
        self.assertEqual(tmp.cleanup(), [], 'an object podman says does not exist is not a leftover')


class VolumeImportTests(unittest.TestCase):
    def test_the_producer_streams_into_podman(self):
        got = {}
        runner = FakeRunner({('volume', 'import'): lambda args, data: got.update(data=data) or Result(0, b'', b'')})
        tmp = tempctr.TempObjects(runner, JOB)
        tmp.volume('src')
        tmp.volume_import('src', lambda out: out.write(b'tar bytes' * 1000))
        self.assertEqual(got['data'], b'tar bytes' * 1000)
        with self.assertRaises(BackupError):
            tmp.volume_import('other', lambda out: None)

    def test_the_producers_error_wins(self):
        runner = FakeRunner({('volume', 'import'): Result(125, b'', b'unexpected EOF')})
        tmp = tempctr.TempObjects(runner, JOB)
        tmp.volume('src')

        def produce(out):
            out.write(b'partial')
            raise BackupError('wrong-key', 'HA 備份金鑰不正確，請確認後再試一次。')

        with self.assertRaises(BackupError) as caught:
            tmp.volume_import('src', produce)
        self.assertEqual(caught.exception.code, 'wrong-key')

    def test_a_broken_pipe_leaves_podmans_error(self):
        runner = FakeRunner({('volume', 'import'): Result(125, b'', b'no space')})
        tmp = tempctr.TempObjects(runner, JOB)
        tmp.volume('src')

        def produce(_out):
            raise BrokenPipeError()

        with self.assertRaises(CommandError):
            tmp.volume_import('src', produce)

    def test_a_cancel_in_the_producer_is_not_a_failure(self):
        class Cancelled(Exception):
            pass

        runner = FakeRunner({('volume', 'import'): Result(125, b'', b'EOF')})
        tmp = tempctr.TempObjects(runner, JOB)
        tmp.volume('src')
        with self.assertRaises(Cancelled):
            tmp.volume_import('src', lambda out: (_ for _ in ()).throw(Cancelled()))


class VolumeRootTests(unittest.TestCase):
    """Podman 6.1.1 ignores a tar's '.' entry on `volume import` (an ARM64 test machine): the entry is applied afterwards."""

    @staticmethod
    def tar_with_root(uid, gid, mode, *, first='.'):
        import io
        import tarfile
        import time
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode='w|', format=tarfile.PAX_FORMAT) as tar:
            info = tarfile.TarInfo(first)
            info.type, info.uid, info.gid, info.mode, info.mtime = tarfile.DIRTYPE, uid, gid, mode, time.time()
            tar.addfile(info)
            child = tarfile.TarInfo('configs')
            child.type, child.uid, child.gid, child.mode = tarfile.DIRTYPE, uid, gid, 0o700
            tar.addfile(child)
        return buf.getvalue()

    def test_tar_root_reads_the_top_entry_behind_a_pax_header(self):
        data = self.tar_with_root(1000, 1000, 0o700)   # a float mtime makes tarfile write a pax header first
        self.assertEqual(tempctr.tar_root(data), (1000, 1000, 0o700))
        self.assertEqual(tempctr.tar_root(data[:2048]), (1000, 1000, 0o700))
        self.assertIsNone(tempctr.tar_root(self.tar_with_root(1000, 1000, 0o700, first='configs')))
        self.assertIsNone(tempctr.tar_root(b'tar bytes' * 1000))
        self.assertIsNone(tempctr.tar_root(b''))

    def test_a_negative_owner_is_never_applied(self):
        # a pax header can carry any integer; `chown -1:...` would mean "leave unchanged" instead of an owner
        for uid, gid in ((-1, 1000), (1000, -1)):
            with self.subTest(uid=uid, gid=gid):
                self.assertIsNone(tempctr.tar_root(self.tar_with_root(uid, gid, 0o700)))

    def test_the_top_entry_is_applied_after_the_import(self):
        runner = FakeRunner({('volume', 'inspect'): Result(0, b'/store/volumes/woowbk-x/_data\n', b'')})
        tmp = tempctr.TempObjects(runner, JOB)
        tmp.volume('emqx-new')
        data = self.tar_with_root(1000, 1000, 0o700)
        tmp.volume_import('emqx-new', lambda out: out.write(data))
        name = tmp.name('emqx-new')
        tail = runner.calls[-4:]
        self.assertEqual(tail[0][:3], ('volume', 'import', name))
        self.assertEqual(tail[1], ('volume', 'inspect', '--format', '{{.Mountpoint}}', name))
        self.assertEqual(tail[2], ('unshare', 'chown', '--no-dereference', '1000:1000', '--',
                                   '/store/volumes/woowbk-x/_data'))
        self.assertEqual(tail[3], ('unshare', 'chmod', '0700', '--', '/store/volumes/woowbk-x/_data'))

    def test_no_top_entry_changes_nothing(self):
        runner = FakeRunner()
        tmp = tempctr.TempObjects(runner, JOB)
        tmp.volume('src')
        data = self.tar_with_root(1000, 1000, 0o700, first='configs')
        tmp.volume_import('src', lambda out: out.write(data))
        self.assertFalse([c for c in runner.calls if c[:1] == ('unshare',) or c[:2] == ('volume', 'inspect')])

    def test_a_bad_mountpoint_refuses(self):
        runner = FakeRunner({('volume', 'inspect'): Result(0, b'relative/path', b'')})
        tmp = tempctr.TempObjects(runner, JOB)
        tmp.volume('src')
        data = self.tar_with_root(0, 0, 0o755)
        with self.assertRaises(BackupError):
            tmp.volume_import('src', lambda out: out.write(data))
        self.assertFalse([c for c in runner.calls if c[:1] == ('unshare',)])


class SweepTests(unittest.TestCase):
    def runner(self):
        containers = [{'Names': [f'woowbk-{JOB}-hapg'], 'Labels': {tempctr.LABEL: JOB}},
                      {'Names': [f'woowbk-{OTHER}-n8n-pg'], 'Labels': {tempctr.LABEL: OTHER}},
                      {'Names': ['odoo18-db'], 'Labels': {tempctr.LABEL: OTHER}},           # not our name
                      {'Names': [f'woowbk-{OTHER}-x'], 'Labels': {tempctr.LABEL: JOB}}]     # name and label differ
        volumes = [{'Name': f'woowbk-{OTHER}-n8nsrc', 'Labels': {tempctr.LABEL: OTHER}}]
        networks = [{'name': f'woowbk-{OTHER}-n8n-net', 'labels': {tempctr.LABEL: OTHER}}]
        return FakeRunner({('ps',): Result(0, json.dumps(containers).encode(), b''),
                           ('volume', 'ls'): Result(0, json.dumps(volumes).encode(), b''),
                           ('network', 'ls'): Result(0, json.dumps(networks).encode(), b'')})

    def test_only_objects_of_jobs_that_no_longer_run(self):
        runner = self.runner()
        notes = []
        removed, left = tempctr.sweep(runner, lambda job: job == JOB, log=notes.append)
        self.assertEqual(removed, [f'woowbk-{OTHER}-n8n-pg', f'woowbk-{OTHER}-n8nsrc', f'woowbk-{OTHER}-n8n-net'])
        self.assertEqual(left, [])
        self.assertNotIn(('rm', '--force', '--time', '10', 'odoo18-db'), runner.calls)
        self.assertTrue(notes)

    def test_one_dead_job(self):
        runner = self.runner()
        self.assertEqual(tempctr.sweep(runner, lambda _job: False, only_job=JOB), ([f'woowbk-{JOB}-hapg'], []))

    def test_an_object_that_cannot_be_removed_is_reported_not_forgotten(self):
        """Review C-07: a volume still in use, a storage lock timeout."""
        runner = self.runner()
        runner.answers[('volume', 'rm')] = Result(2, b'', b'volume is being used')
        runner.answers[('volume', 'exists')] = Result(0, b'', b'')
        notes = []
        removed, left = tempctr.sweep(runner, lambda _job: False, only_job=OTHER, log=notes.append)
        self.assertEqual(left, [f'woowbk-{OTHER}-n8nsrc'])
        self.assertIn(f'woowbk-{OTHER}-n8n-pg', removed)
        self.assertTrue(any('無法移除' in note for note in notes))
        runner.answers[('volume', 'exists')] = Result(1, b'', b'')  # gone meanwhile: removed after all
        self.assertEqual(tempctr.sweep(runner, lambda _job: False, only_job=OTHER)[1], [])

    def test_an_unreadable_listing_raises(self):
        runner = FakeRunner({('ps',): Result(0, b'not json', b'')})
        with self.assertRaises(BackupError):
            tempctr.sweep(runner, lambda _job: False)


class ScopeTests(unittest.TestCase):
    """DESIGN C2 (lane F3): what one app of a check could not remove never stands in the way of the next one's. A scoped
    TempObjects only takes a name of its own where the plain one is still held by another TempObjects of the job."""

    def stuck_first_app(self, runner=None, role='hapg'):
        """An earlier app of the job left its volume behind (its TempObjects stays referenced, as Work._stale keeps it)."""
        runner = runner or FakeRunner({('volume', 'rm'): Result(125, b'', b'busy'), ('volume', 'exists'): Result(0, b'', b'')})
        first = tempctr.TempObjects(runner, JOB, scope='0', log=[].append)
        first.volume(role)
        self.assertEqual(first.cleanup(), [f'woowbk-{JOB}-{role}'])
        return first, runner

    def test_the_names_stay_plain_while_nothing_is_there(self):
        self.assertIs(tempctr.SCOPES, True, 'haimport.Work.temp passes the scope')
        runner = FakeRunner()
        for scope in ('0', '1', None):
            tmp = tempctr.TempObjects(runner, JOB, scope=scope)
            self.assertEqual(tmp.name('hapg'), f'woowbk-{JOB}-hapg')
            argv = tmp.run_argv('hapg', 'img:1', [], detach=True)
            self.assertEqual(argv[argv.index('--name') + 1], f'woowbk-{JOB}-hapg')
            self.assertEqual(argv[argv.index('--label') + 1], f'{tempctr.LABEL}={JOB}')

    def test_the_next_app_gets_a_name_of_its_own_where_the_plain_one_is_stuck(self):
        first, _runner = self.stuck_first_app()
        runner = FakeRunner()
        second = tempctr.TempObjects(runner, JOB, scope='1')
        third = tempctr.TempObjects(runner, JOB, scope='2')
        self.assertEqual(second.volume('hapg'), f'woowbk-{JOB}-1-hapg')
        self.assertEqual(third.volume('hapg'), f'woowbk-{JOB}-2-hapg')
        self.assertEqual(second.name('db'), f'woowbk-{JOB}-db', 'only the role that is stuck is renamed')
        self.assertIn(('volume', 'create', '--label', f'{tempctr.LABEL}={JOB}', f'woowbk-{JOB}-1-hapg'), runner.calls)
        argv = second.run_argv('hapg', 'img:1', [], detach=True)
        self.assertEqual(argv[argv.index('--label') + 1], f'{tempctr.LABEL}={JOB}', 'the label stays the job id')
        self.assertEqual(tempctr.NAME_RE.fullmatch(second.name('hapg')).group(1), JOB, 'sweep and the recovery still find it')
        self.assertEqual(second.cleanup(), [])
        self.assertEqual(runner.calls[-1][:3], ('volume', 'rm', '--force'))
        self.assertTrue(first.volumes, 'the leftover is still listed by the app that made it')

    def test_two_instances_that_are_alive_together_do_not_meet_either(self):
        runner = FakeRunner()
        first, second = (tempctr.TempObjects(runner, JOB, scope=scope) for scope in ('0', '1'))
        self.assertEqual(first.volume('hapg'), f'woowbk-{JOB}-hapg')
        self.assertEqual(second.volume('hapg'), f'woowbk-{JOB}-1-hapg')
        self.assertEqual(first.cleanup(), [])
        self.assertEqual(second.volumes, [f'woowbk-{JOB}-1-hapg'], 'one app removes only its own objects')

    def test_without_a_scope_nothing_is_renamed_and_another_job_or_owner_is_not_touched(self):
        first, _runner = self.stuck_first_app()
        runner = FakeRunner()
        self.assertEqual(tempctr.TempObjects(runner, JOB).name('hapg'), f'woowbk-{JOB}-hapg')
        self.assertEqual(tempctr.TempObjects(runner, OTHER, scope='1').name('hapg'), f'woowbk-{OTHER}-hapg')
        elsewhere = FakeRunner()
        elsewhere.owner = 'someone-else'    # another account's Podman storage: the name is free there
        self.assertEqual(tempctr.TempObjects(elsewhere, JOB, scope='1').name('hapg'), f'woowbk-{JOB}-hapg')
        self.assertTrue(first.volumes)

    def test_the_name_an_object_has_never_changes_under_it(self):
        first, runner = self.stuck_first_app()
        second = tempctr.TempObjects(FakeRunner(), JOB, scope='1')
        before = second.name('hapg')
        self.assertEqual(before, f'woowbk-{JOB}-1-hapg')
        runner.answers[('volume', 'exists')] = Result(1, b'', b'')     # the old one goes after all
        self.assertEqual(first.cleanup(), [])
        self.assertEqual(second.name('hapg'), before, 'chosen once')
        self.assertEqual(tempctr.TempObjects(FakeRunner(), JOB, scope='2').name('hapg'), f'woowbk-{JOB}-hapg',
                         'once the leftover is gone the plain name is free again')

    def test_a_leftover_that_nobody_holds_any_more_is_forgotten(self):
        import gc
        first, _runner = self.stuck_first_app()
        self.assertEqual(tempctr.stuck(JOB, 'appowner'), {f'woowbk-{JOB}-hapg'})
        self.assertEqual(tempctr.stuck(OTHER, 'appowner'), frozenset(), 'only the names of the job that is asked for')
        self.assertEqual(tempctr.stuck(JOB, 'someone-else'), frozenset(), 'only the owner that is asked for')
        del first
        gc.collect()
        self.assertEqual(tempctr.stuck(JOB, 'appowner'), frozenset())
        self.assertEqual(tempctr.TempObjects(FakeRunner(), JOB, scope='1').name('hapg'), f'woowbk-{JOB}-hapg')

    def test_a_role_too_long_for_a_scoped_name_keeps_the_plain_one(self):
        role = 'r' * 30
        first, _runner = self.stuck_first_app(role=role)
        self.assertEqual(tempctr.TempObjects(FakeRunner(), JOB, scope='12').name(role), f'woowbk-{JOB}-{role}')
        self.assertTrue(first.volumes)

    def test_a_bad_scope_is_refused(self):
        runner = FakeRunner()
        for scope in ('', 'A', '123', 'a', 'x1', 'a b', 'a-b', -1, 5, b'0'):
            with self.subTest(scope=scope), self.assertRaises(BackupError):
                tempctr.TempObjects(runner, JOB, scope=scope)

    def test_the_sweep_finds_scoped_objects_of_a_dead_job(self):
        listing = [{'Names': [f'woowbk-{OTHER}-0-hapg'], 'Labels': {tempctr.LABEL: OTHER}},
                   {'Names': [f'woowbk-{OTHER}-1-odoo-db'], 'Labels': {tempctr.LABEL: OTHER}}]
        runner = FakeRunner({('ps',): Result(0, json.dumps(listing).encode(), b''),
                             ('volume', 'ls'): Result(0, b'[]', b''), ('network', 'ls'): Result(0, b'[]', b'')})
        removed, left = tempctr.sweep(runner, lambda _job: False, only_job=OTHER)
        self.assertEqual((removed, left), ([f'woowbk-{OTHER}-0-hapg', f'woowbk-{OTHER}-1-odoo-db'], []))

    def test_through_the_real_work_the_second_app_does_not_meet_the_first_ones_leftover(self):
        from woowbackup import haimport
        from . import test_ha_import as hi

        class Case(hi.FlowCase):
            def runTest(self):
                pass

        case = Case()
        case.setUp()
        self.addCleanup(case.doCleanups)     # setUp registered patcher.stop on the case: without this the patch of
        self.addCleanup(case.tearDown)       # flows.running_reserve outlives the test and breaks test_flows run after this file
        runner = FakeRunner({('volume', 'rm'): Result(125, b'', b'busy'), ('volume', 'exists'): Result(0, b'', b'')})
        runner.home = str(case.root)
        adapter = hi.FakeHaAdapter(hi.app('odoo', 'Odoo 18'), case.world)
        adapter.runner = runner
        case.deps.adapter_factory = lambda _app, **_kwargs: adapter
        work = haimport.Work(case.ctx(), None, None, case.root)
        work.guard.folders = []
        first, second = hi.app('odoo', 'Odoo 18'), hi.app('n8n', 'n8n')
        work.begin_app(0, 2, 'Odoo 18')
        work.temp(first).volume('hapg')
        work.reset_app(first)                       # the removal fails: the volume is left behind, Work keeps it
        work.begin_app(1, 2, 'n8n')
        self.assertEqual(work.temp(second).volume('hapg'), f'woowbk-{case.job_id}-1-hapg')
        self.assertEqual(work.temp(second).name('db'), f'woowbk-{case.job_id}-db')
        runner.answers[('volume', 'rm')] = Result(0, b'', b'')
        work.close()


class LeftoverTests(unittest.TestCase):
    """X-TC-05: an object that cannot be removed takes space and nothing more: the app goes on, the log says so once, the
    object stays listed for cleanup() and the sweeps."""

    def failing(self, kind):
        remove = {'container': ('rm',), 'volume': ('volume', 'rm')}[kind]
        runner = FakeRunner({remove: Result(125, b'', b'busy'), (kind, 'exists'): Result(0, b'', b'')})
        notes = []
        tmp = tempctr.TempObjects(runner, JOB, log=notes.append)
        return runner, tmp, notes, remove

    def test_a_container_or_volume_that_stays_is_a_note_not_a_stop(self):
        for kind, make, drop in (('container', lambda t: t.run('x', 'img:1', [], detach=True), 'remove'),
                                 ('volume', lambda t: t.volume('x'), 'remove_volume')):
            with self.subTest(kind=kind):
                runner, tmp, notes, _remove = self.failing(kind)
                make(tmp)
                self.assertFalse(getattr(tmp, drop)('x'))
                self.assertFalse(getattr(tmp, drop)('x'))
                self.assertEqual(len(notes), 1, 'one line however often it is tried')
                self.assertIn('暫用', notes[0])
                self.assertIn('不影響資料', notes[0])
                self.assertNotIn(JOB, notes[0], 'no job or object name in a line the customer reads')
                self.assertIn(tmp.name('x'), getattr(tmp, kind + 's'))

    def test_the_other_work_of_the_app_goes_on_and_cleanup_tries_again(self):
        stuck = {'on': True}
        runner = FakeRunner({
            ('volume', 'rm'): lambda args, _data: Result(125 if stuck['on'] and args[-1].endswith('-old') else 0, b'', b''),
            ('volume', 'exists'): lambda args, _data: Result(0 if stuck['on'] and args[-1].endswith('-old') else 1, b'', b'')})
        tmp = tempctr.TempObjects(runner, JOB, log=[].append)
        tmp.volume('old')
        self.assertFalse(tmp.remove_volume('old'))
        tmp.volume('next')                    # a second object, made after the failed removal
        tmp.run('db', 'img:1', [], detach=True)
        self.assertEqual(tmp.cleanup(), [tmp.name('old')], 'only the one that cannot go is left')
        self.assertEqual((tmp.containers, tmp.volumes), ([], [tmp.name('old')]))
        stuck['on'] = False
        self.assertEqual(tmp.cleanup(), [])
        self.assertEqual((tmp.containers, tmp.volumes), ([], []))

    def test_a_role_used_again_works_when_the_leftover_can_go_now_and_stops_the_app_when_not(self):
        runner, tmp, _notes, remove = self.failing('volume')
        tmp.volume('hapg')
        self.assertFalse(tmp.remove_volume('hapg'))
        with self.assertRaises(BackupError) as caught:
            tmp.volume('hapg')                # the old one is still there: this app cannot have the name
        self.assertEqual(caught.exception.code, 'job-failed')
        self.assertIn('同一個名稱', caught.exception.message)
        runner.answers[remove] = Result(0, b'', b'')
        self.assertEqual(tmp.volume('hapg'), tmp.name('hapg'), 'removed now: the name is free again')
        self.assertEqual(tmp.volumes, [tmp.name('hapg')])

    def test_a_name_that_was_never_let_go_is_still_a_programming_error(self):
        tmp = tempctr.TempObjects(FakeRunner(), JOB)
        tmp.volume('hapg')
        tmp.run('db', 'img:1', [], detach=True)
        tmp.network('net')
        for call in (lambda: tmp.volume('hapg'), lambda: tmp.run('db', 'img:1', [], detach=True),
                     lambda: tmp.network('net')):
            with self.assertRaises(BackupError) as caught:
                call()
            self.assertEqual(caught.exception.code, 'internal-error')

    def test_an_object_podman_does_not_know_is_gone_not_left(self):
        runner = FakeRunner({('rm',): Result(125, b'', b'no such container'), ('container', 'exists'): Result(1, b'', b'')})
        notes = []
        tmp = tempctr.TempObjects(runner, JOB, log=notes.append)
        tmp.run('x', 'img:1', [], detach=True)
        self.assertTrue(tmp.remove('x'))
        self.assertEqual((tmp.containers, notes), ([], []))


class PutBackTests(unittest.TestCase):
    """What a job changed on the device for its reading is put back first, also when it takes more than one try."""

    def test_it_runs_before_anything_is_removed_and_once(self):
        runner = FakeRunner()
        tmp = tempctr.TempObjects(runner, JOB)
        tmp.run('hapg', 'img:1', [], detach=True)
        tmp.put_back_later('db', lambda: runner.calls.append(('put-back', 'db')))
        runner.calls.clear()
        self.assertEqual(tmp.cleanup(), [])
        self.assertEqual(runner.calls, [('put-back', 'db'), ('rm', '--force', '--time', '10', f'woowbk-{JOB}-hapg')])
        runner.calls.clear()
        self.assertEqual(tmp.cleanup(), [])
        self.assertEqual(runner.calls, [], 'a finished put-back is not run again')

    def test_a_put_back_that_fails_is_reported_kept_and_never_raises(self):
        tmp = tempctr.TempObjects(FakeRunner(), JOB, log=(notes := []).append)
        calls = []

        def action():
            calls.append(1)
            if len(calls) < 3:
                raise BackupError('job-failed', 'cannot stop')

        tmp.put_back_later('Odoo 的資料庫', action)
        self.assertEqual(tmp.cleanup(), ['service:Odoo 的資料庫'])
        self.assertTrue(any('沒能恢復原狀' in note and 'Odoo 的資料庫' in note for note in notes), notes)
        self.assertEqual(tmp.cleanup(), ['service:Odoo 的資料庫'])
        self.assertEqual(tmp.cleanup(), [])
        self.assertEqual(tmp.cleanup(), [])
        self.assertEqual(len(calls), 3)

    def test_the_context_exit_puts_back_also_when_the_job_failed(self):
        undone = []
        with self.assertRaises(RuntimeError):
            with tempctr.TempObjects(FakeRunner(), JOB) as tmp:
                tmp.put_back_later('db', lambda: undone.append('db'))
                raise RuntimeError('the app failed')
        self.assertEqual(undone, ['db'])

    def test_the_newest_change_is_put_back_first(self):
        order = []
        tmp = tempctr.TempObjects(FakeRunner(), JOB)
        for label in ('a', 'b', 'c'):
            tmp.put_back_later(label, lambda label=label: order.append(label))
        tmp.cleanup()
        self.assertEqual(order, ['c', 'b', 'a'])


class SweepListingTests(unittest.TestCase):
    """X-TC-07: a list of throwaway objects that cannot be read only leaves old objects in place; it never stops an
    import (the sweep says so, its callers turn it into a line or ignore it)."""

    def test_the_sweep_says_it_could_not_read_and_removes_nothing(self):
        for answer in (Result(0, b'not json', b''), Result(0, b'{"a": 1}', b''), Result(125, b'', b'storage error')):
            with self.subTest(answer=answer):
                runner = FakeRunner({('ps',): answer})
                with self.assertRaises(BackupError) as caught:
                    tempctr.sweep(runner, lambda _job: False)
                self.assertEqual(caught.exception.code, 'job-failed')
                self.assertFalse([call for call in runner.calls if call[:1] == ('rm',)])

    def test_a_long_list_of_leftovers_is_read_not_refused(self):
        pad = 'x' * 1500
        rows = [{'Names': [f'woowbk-{OTHER}-{i}-hapg'], 'Labels': {tempctr.LABEL: OTHER}, 'Command': pad} for i in range(3500)]
        data = json.dumps(rows).encode()
        self.assertGreater(len(data), 4 * 1024 * 1024)
        self.assertLessEqual(len(data), tempctr.LIST_OUTPUT)
        runner = FakeRunner({('ps',): Result(0, data, b''), ('volume', 'ls'): Result(0, b'[]', b''),
                             ('network', 'ls'): Result(0, b'[]', b'')})
        removed, left = tempctr.sweep(runner, lambda _job: False, only_job=OTHER)
        self.assertEqual((len(removed), left), (3500, []))

    def test_the_recovery_reports_it_as_a_line_and_the_job_start_ignores_it(self):
        from unittest import mock

        from woowbackup import haimport

        class Owner:
            def __init__(self, _name):
                pass

            def podman(self, *_args, **_kwargs):
                raise BackupError('job-failed', 'podman ps 執行失敗（結束碼 125）。')

        with mock.patch('woowbackup.podman.OwnerRunner', Owner):
            problems = haimport.sweep_job(JOB, ['appowner'])
        self.assertEqual(len(problems), 1)
        self.assertTrue(problems[0].startswith('appowner：'), problems)
        with mock.patch('woowbackup.podman.OwnerRunner', Owner), \
                mock.patch.object(haimport, '_importable_owners', lambda _paths: ['appowner']):
            self.assertIsNone(haimport.sweep_finished(types.SimpleNamespace()), 'never fails the job that starts')


class ScaledWaitTests(unittest.TestCase):
    """X-PD-05: every wait of a throwaway container grows with the app's data; the value a call asked for is the floor."""

    def runner(self):
        seen = {}

        class Recording(FakeRunner):
            def podman(self, *args, **kwargs):
                seen[args[:2] if args[0] == 'volume' else args[:1]] = kwargs.get('timeout')
                return super().podman(*args, **kwargs)

            def relay(self, args, *, stdout, timeout=None, max_output=None, check=True):
                seen[('relay',)] = timeout
                return super().relay(args, stdout=stdout, timeout=timeout, max_output=max_output, check=check)

        return Recording(), seen

    def calls(self, tmp):
        tmp.run('db', 'img:1', [], detach=True, timeout=600)
        tmp.exec('db', ['pg_isready'], timeout=600)
        tmp.volume('v')
        tmp.volume_import('v', lambda out: out.write(b'tar'), timeout=3 * 3600)
        tmp.volume_export('v', io.BytesIO(), timeout=3 * 3600)

    WAITS = {('run',): 600, ('exec',): 600, ('volume', 'import'): 3 * 3600, ('relay',): 3 * 3600}

    def test_nothing_changes_while_the_size_is_not_known(self):
        runner, seen = self.runner()
        tmp = tempctr.TempObjects(runner, JOB, cpus=None)
        self.calls(tmp)
        self.assertEqual({key: seen[key] for key in self.WAITS}, self.WAITS)
        self.assertIsNone(tmp.size)

    def test_a_big_app_gets_more_time_never_less(self):
        runner, seen = self.runner()
        tmp = tempctr.TempObjects(runner, JOB, cpus=None)
        big = 500 * 1024 ** 3
        tmp.scale_to(big)
        self.calls(tmp)
        for key, base in self.WAITS.items():
            self.assertEqual(seen[key], podman.scaled_timeout(base, big), key)
            self.assertGreater(seen[key], base, key)
        self.assertEqual(seen[('volume', 'create')], 120, 'the short calls of the object itself are not stretched')

    def test_a_small_size_or_a_bad_one_changes_nothing(self):
        for size in (10, 0, -5, None, True, 'big'):
            with self.subTest(size=size):
                runner, seen = self.runner()
                tmp = tempctr.TempObjects(runner, JOB, cpus=None)
                tmp.scale_to(size)
                self.assertEqual(tmp.size, 10 if size == 10 else None, 'a size that is no size is not kept')
                tmp.run('db', 'img:1', [], detach=True, timeout=600)
                self.assertEqual(seen[('run',)], 600)
        tmp = tempctr.TempObjects(FakeRunner(), JOB, cpus=None)
        tmp.scale_to(5 * 1024 ** 3)
        tmp.scale_to(None)
        self.assertIsNone(tmp.size, 'a size can be taken back')


if __name__ == '__main__':
    unittest.main()
