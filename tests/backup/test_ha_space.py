"""HA import jobs: free space and cancellation while throwaway containers run (haimport.Watchdog, SpaceGuard,
tempctr's abort hook, podman.default_runner's `abort`; review HA-SEC-04, C-01, C-15). Team E2."""
import os
import subprocess
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest import mock

from woowbackup import flows, haimport, podman, tempctr
from woowbackup.errors import BackupError

from .test_ha_tempctr import JOB, FakeRunner

GIB = 1024 ** 3


class Stat:
    def __init__(self, free):
        self.f_bavail, self.f_frsize = free, 1


class FakeWork:
    """What the watchdog looks at: the guard, the job's reporter, its throwaway objects."""

    def __init__(self, free, floor=GIB, cancel=False, cancellable=True):
        self.frees = {'free': free}
        self.guard = haimport.SpaceGuard(['/data', '/home/appowner'], floor,
                                         statvfs=lambda _folder: Stat(self.frees['free']))
        self.reporter = types.SimpleNamespace(cancellable=cancellable, cancel_requested=lambda: cancel)
        self.ctx = types.SimpleNamespace(reporter=self.reporter)
        self.runner = FakeRunner()
        self._temps = {'appowner': tempctr.TempObjects(self.runner, JOB, cpus=None)}


class WatchdogTests(unittest.TestCase):
    def test_low_space_kills_the_containers_and_fails_the_job(self):
        work = FakeWork(free=5 * GIB)
        tmp = work._temps['appowner']
        tmp.containers.append(tmp.name('hapg'))
        dog = haimport.Watchdog(work)
        dog.poll()
        self.assertIsNone(dog.abort())
        work.frees['free'] = GIB - 1
        dog.poll()
        error = dog.abort()
        self.assertIsInstance(error, BackupError)
        self.assertEqual(error.code, 'insufficient-space')
        self.assertIn(('kill', '--signal', 'KILL', tmp.name('hapg')), work.runner.calls)
        dog.poll()  # a verdict stays; nothing is killed twice
        self.assertEqual(sum(1 for call in work.runner.calls if call[0] == 'kill'), 1)

    def test_a_cancel_request_stops_the_job_only_while_cancellable(self):
        dog = haimport.Watchdog(FakeWork(free=5 * GIB, cancel=True, cancellable=False))
        dog.poll()
        self.assertIsNone(dog.abort())
        dog = haimport.Watchdog(FakeWork(free=5 * GIB, cancel=True))
        dog.poll()
        self.assertIsInstance(dog.abort(), flows.Cancelled)

    def test_the_thread_looks_every_interval_until_stopped(self):
        work = FakeWork(free=5 * GIB)
        dog = haimport.Watchdog(work, interval=0.05)
        dog.start()
        work.frees['free'] = 10
        deadline = time.monotonic() + 5
        while dog.abort() is None and time.monotonic() < deadline:
            time.sleep(0.02)
        dog.stop()
        self.assertEqual(dog.abort().code, 'insufficient-space')


class AbortHookTests(unittest.TestCase):
    def test_the_runner_kills_a_long_command_when_abort_answers(self):
        started = time.monotonic()
        stop = {'error': None}

        def abort():
            if time.monotonic() - started > 0.5:
                stop['error'] = BackupError('insufficient-space', '空間不足。')
            return stop['error']

        with self.assertRaises(BackupError) as caught:
            podman.default_runner(['sleep', '30'], timeout=60, abort=abort)
        self.assertEqual(caught.exception.code, 'insufficient-space')
        self.assertLess(time.monotonic() - started, 10)

    def test_without_an_abort_answer_the_command_runs_and_timeouts_stay(self):
        result = podman.default_runner(['sh', '-c', 'sleep 1; echo done'], timeout=30, abort=lambda: None)
        self.assertEqual((result.returncode, result.stdout), (0, b'done\n'))
        with self.assertRaises(subprocess.TimeoutExpired):
            podman.default_runner(['sleep', '30'], timeout=1.5, abort=lambda: None)

    def test_temp_objects_hand_the_hook_to_long_calls_and_start_nothing_after_a_verdict(self):
        verdict = {'error': None}
        seen = []

        class Runner(FakeRunner):
            def podman(self, *args, abort=None, **kwargs):
                seen.append((args[0], abort))
                return super().podman(*args, **kwargs)

        tmp = tempctr.TempObjects(Runner(), JOB, cpus=None, abort=lambda: verdict['error'])
        tmp.volume('hapg')
        tmp.run('ids', 'docker.io/library/postgres:16.15-alpine', ['id'])
        self.assertEqual([call for call, hook in seen if hook is not None], ['run'])
        verdict['error'] = BackupError('insufficient-space', '空間不足。')
        with self.assertRaises(BackupError):
            tmp.run('hapg', 'docker.io/library/postgres:16.15-alpine', ['postgres'], detach=True)
        self.assertNotIn(tmp.name('hapg'), tmp.containers)


class CpuLimitTests(unittest.TestCase):
    def test_half_the_cpus_only_when_the_owner_can_limit_them(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'controllers-{uid}'
            Path(str(path).format(uid=1013)).write_text('cpu memory pids\n')
            Path(str(path).format(uid=1014)).write_text('memory pids\n')
            self.assertEqual(tempctr.default_cpus(1013, controllers=str(path), cpu_count=lambda: 8), '4')
            self.assertEqual(tempctr.default_cpus(1013, controllers=str(path), cpu_count=lambda: 1), '1')
            self.assertIsNone(tempctr.default_cpus(1014, controllers=str(path)))
            self.assertIsNone(tempctr.default_cpus(1015, controllers=str(path)))
            self.assertIsNone(tempctr.default_cpus(None, controllers=str(path)))
        argv = tempctr.TempObjects(FakeRunner(), JOB, cpus='4').run_argv('x', 'img:1')
        self.assertEqual(argv[argv.index('--cpus') + 1], '4')
        self.assertNotIn('--cpus', tempctr.TempObjects(FakeRunner(), JOB, cpus=None).run_argv('x', 'img:1'))


class GuardTests(unittest.TestCase):
    def test_the_owners_podman_storage_is_watched_from_the_start(self):
        with tempfile.TemporaryDirectory() as home:
            os.makedirs(os.path.join(home, '.local/share/containers/storage'))
            ctx = types.SimpleNamespace(job_id=JOB, reporter=None, paths=types.SimpleNamespace(reserve_bytes=0),
                                        storage=types.SimpleNamespace(total_bytes=lambda: 0))
            work = haimport.Work(ctx, None, None, home)
            app = types.SimpleNamespace(id='odoo', owner='appowner')
            work._adapters['odoo'] = types.SimpleNamespace(runner=types.SimpleNamespace(home=home))
            work.watchdog.start = lambda: None
            work.watch([app])
            self.assertEqual(work.guard.folders, [home, os.path.join(home, '.local/share/containers/storage')])
            self.assertEqual(work.floor, flows.RUNNING_RESERVE_MIN + haimport.WATCH_MARGIN)


if __name__ == '__main__':
    unittest.main()
