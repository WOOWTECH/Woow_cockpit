"""Throwaway containers of a job (tempctr.py, CONTRACT section 8 "Throwaway containers"): exact command lines, the
Quadlet parsing that decides secrets/environment/images, clean-up and the sweep of a dead job's objects. Team E2."""
import json
import threading
import unittest

from woowbackup import tempctr
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
                with self.assertRaises(BackupError):
                    remove('item')
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
                with self.assertRaises(BackupError):
                    remove('item')
                self.assertIn(tmp.name('item'), getattr(tmp, kind + 's'))
                runner.answers[(kind, 'exists')] = Result(1, b'', b'')
                remove('item')
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


if __name__ == '__main__':
    unittest.main()
