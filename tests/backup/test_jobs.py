"""Job records, dedup, busy, launcher injection, flock, recovery, cancel and signal handling.

Also the job-record races found by the release regression (16-repro_recover_race.py): recovery judging a job
from a stale listing, side effects taken from that listing, cancel vs. the job's own record writes, a launch
failure vs. a run-job that already started, and the retention that bounds what status/jobs/job-status read.
"""
import json
import os
import signal
import stat
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from woowbackup import flows, jobs
from woowbackup.errors import BackupError
from woowbackup.paths import Paths

from .test_flows import TEST_SECRET


class Launcher:
    def __init__(self, fail=False):
        self.launched = []
        self.fail = fail

    def __call__(self, job_id):
        self.launched.append(job_id)
        if self.fail:
            raise BackupError('internal-error', '無法啟動背景作業。')


class JobCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.paths = Paths(base=Path(self.tmp.name))
        self.store = jobs.JobStore(self.paths)
        self.launcher = Launcher()
        self.active_units = set()

    def tearDown(self):
        self.tmp.cleanup()

    def unit_active(self, unit):
        return unit in self.active_units

    def start(self, job_type='backup', params=None, request_id='req-00000001', **kwargs):
        kwargs.setdefault('launcher', self.launcher)
        kwargs.setdefault('unit_active', self.unit_active)
        return jobs.start_job(self.paths, job_type, params or {'apps': ['woowbk-demo'], 'include_images': False,
                                                               'note': ''}, request_id, **kwargs)

    def files_text(self):
        text = ''
        for base in (self.paths.data, self.paths.run):
            for path in Path(base).rglob('*'):
                if path.is_file():
                    text += path.read_text(errors='replace')
        return text


class StoreTests(JobCase):
    def test_record_shape_mode_and_atomic_write(self):
        record = self.store.create('restore', {'backup_id': 'x', 'apps': ['a']}, request_id='r')
        path = self.store.path(record['id'])
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertRegex(record['id'], jobs.JOB_ID_RE)
        public = jobs.public_job(self.store.get(record['id']))
        self.assertEqual(list(public), list(jobs.PUBLIC_KEYS))
        self.assertEqual(public['state'], 'queued')
        self.assertEqual([p['id'] for p in public['phases']], ['prepare', 'decrypt', 'preflight', 'safety', 'stop',
                                                               'restore', 'start', 'check'])
        self.assertEqual(public['progress'], {'percent': 0, 'message': '等待開始'})
        # No temp file is left; the record lock file (jobs/<id>.lock, 0600, empty) sits next to the record.
        self.assertEqual(sorted(p.name for p in Path(self.paths.jobs).iterdir()), [path.name, f'{record["id"]}.lock'])
        lock = self.store.lock_path(record['id'])
        self.assertEqual((stat.S_IMODE(lock.stat().st_mode), lock.stat().st_size), (0o600, 0))

    def test_list_newest_first_and_limit(self):
        ids = [self.store.create('verify', {'backup_id': str(i)}, now=1_700_000_000 + i)['id'] for i in range(5)]
        listed = [r['id'] for r in self.store.list(limit=3)]
        self.assertEqual(listed, list(reversed(ids))[:3])
        Path(self.paths.jobs, 'jbad.json').write_text('{')
        Path(self.paths.jobs, 'j20261113T020000Z-deadbeef.json').write_text('not json')
        self.assertEqual(len(self.store.list(limit=None)), 5)

    def test_invalid_ids_rejected(self):
        for bad in ('../x', 'j1', '', None, 'j20261113T020000Z-DEADBEEF'):
            with self.assertRaises(BackupError):
                self.store.get(bad)

    def test_log_redacts_and_limits(self):
        record = self.store.create('backup', {})
        self.store.append_log(record['id'], f'leak {TEST_SECRET} end\nsecond line')
        for i in range(250):
            self.store.append_log(record['id'], f'line {i}')
        log = self.store.read_log(record['id'])
        self.assertEqual(len(log), 200)
        self.assertNotIn(TEST_SECRET, Path(self.store.log_path(record['id'])).read_text())
        self.assertTrue(log[-1].endswith('line 249'))
        self.assertEqual(stat.S_IMODE(self.store.log_path(record['id']).stat().st_mode), 0o600)


class ReporterTests(JobCase):
    def test_phase_semantics_and_rollback_phase(self):
        record = self.store.create('restore', {})
        reporter = jobs.JobReporter(self.store, record, min_interval=0)
        reporter.phase('decrypt')
        reporter.phase('stop')
        states = {p['id']: p['state'] for p in record['phases']}
        self.assertEqual([states[k] for k in ('prepare', 'decrypt', 'preflight', 'safety', 'stop', 'restore')],
                         ['done', 'done', 'done', 'done', 'active', 'pending'])
        reporter.phase('restore')
        reporter.phase('stop')  # next app re-enters the cycle
        states = {p['id']: p['state'] for p in record['phases']}
        self.assertEqual((states['stop'], states['restore']), ('active', 'pending'))
        reporter.add_phase('rollback', '自動回復')
        reporter.phase('rollback')
        states = {p['id']: p['state'] for p in record['phases']}
        self.assertEqual((states['stop'], states['check'], states['rollback']), ('failed', 'skipped', 'active'))
        reporter.finish('rolled-back', result={'rolled_back': True}, error={'code': 'job-failed', 'message': 'x'})
        saved = self.store.get(record['id'])
        self.assertEqual(saved['phases'][-1], {'id': 'rollback', 'label': '自動回復', 'state': 'done'})
        self.assertEqual((saved['state'], saved['cancellable']), ('rolled-back', False))
        self.assertTrue(saved['finished'])

    def test_progress_fraction_and_throttle(self):
        clock = [0.0]
        record = self.store.create('verify', {})
        reporter = jobs.JobReporter(self.store, record, clock=lambda: clock[0], min_interval=10)
        reporter.phase('decrypt')
        reporter.progress(fraction=0.5, message=f'x {TEST_SECRET}')
        self.assertEqual(record['progress']['percent'], 50)
        self.assertNotIn(TEST_SECRET, record['progress']['message'])
        self.assertEqual(self.store.get(record['id'])['progress']['percent'], 33)  # throttled, not saved yet
        clock[0] = 11
        reporter.progress(fraction=0.6)
        self.assertEqual(self.store.get(record['id'])['progress']['percent'], 53)


class StartJobTests(JobCase):
    def test_start_writes_record_requests_and_launches(self):
        result = self.start()
        self.assertEqual(result['deduplicated'], False)
        self.assertEqual(self.launcher.launched, [result['job_id']])
        record = self.store.get(result['job_id'])
        self.assertEqual((record['state'], record['request_id'], record['unit']),
                         ('queued', 'req-00000001', f'woowtech-backup-{result["job_id"]}.service'))
        requests = json.loads(Path(self.paths.requests).read_text())['requests']
        self.assertEqual(requests['req-00000001']['job_id'], result['job_id'])
        self.assertEqual(stat.S_IMODE(Path(self.paths.requests).stat().st_mode), 0o600)

    def test_deduplication_within_24h(self):
        first = self.start(now=1_800_000_000)
        again = self.start(now=1_800_000_000 + 3600)
        self.assertEqual(again, {'job_id': first['job_id'], 'deduplicated': True})
        self.assertEqual(len(self.launcher.launched), 1)
        with self.assertRaises(BackupError) as caught:
            self.start(job_type='verify', params={'backup_id': 'x'}, now=1_800_000_000 + 7200)
        self.assertEqual(caught.exception.code, 'invalid-request')
        record = self.store.get(first['job_id'])
        record['state'] = 'succeeded'
        self.store.save(record)
        later = self.start(now=1_800_000_000 + 24 * 3600 + 1)
        self.assertEqual(later['deduplicated'], False)
        self.assertNotEqual(later['job_id'], first['job_id'])

    def test_busy_while_another_job_is_active(self):
        first = self.start()
        self.active_units.add(f'woowtech-backup-{first["job_id"]}.service')
        with self.assertRaises(BackupError) as caught:
            self.start(request_id='req-00000002')
        self.assertEqual(caught.exception.code, 'busy')
        self.assertEqual(caught.exception.details['job_id'], first['job_id'])

    def test_dead_job_does_not_block_forever(self):
        first = self.start(now=time.time() - 3600)
        second = self.start(request_id='req-00000002')
        self.assertEqual(self.store.get(first['job_id'])['state'], 'interrupted')
        self.assertEqual(self.store.get(second['job_id'])['state'], 'queued')

    def test_key_file_private_and_never_in_records(self):
        result = self.start(job_type='restore', params={'backup_id': 'b', 'apps': ['a'], 'key_provided': True},
                            key_text=f'  # pasted\n{TEST_SECRET.lower()}\n')
        key_path = self.store.key_path(result['job_id'])
        self.assertEqual(key_path, Path(self.paths.run) / f'key-{result["job_id"]}')
        self.assertEqual(stat.S_IMODE(key_path.stat().st_mode), 0o600)
        self.assertEqual(key_path.read_text(), TEST_SECRET + '\n')
        key_path.unlink()
        self.assertNotIn(TEST_SECRET, self.files_text())

    def test_invalid_key_rejected_before_anything_is_written(self):
        with self.assertRaises(BackupError) as caught:
            self.start(job_type='verify', params={'backup_id': 'b'}, key_text='AGE-SECRET-KEY-1-not-valid')
        self.assertEqual(caught.exception.code, 'invalid-request')
        self.assertNotIn('not-valid', caught.exception.message)
        self.assertEqual(self.store.list(), [])
        self.assertEqual(self.launcher.launched, [])

    def test_launch_failure_marks_failed_and_removes_key(self):
        with self.assertRaises(BackupError):
            self.start(job_type='verify', params={'backup_id': 'b'}, key_text=TEST_SECRET, launcher=Launcher(fail=True))
        record = self.store.list()[0]
        self.assertEqual(record['state'], 'failed')
        self.assertEqual(record['error']['code'], 'internal-error')
        self.assertEqual(list(Path(self.paths.run).glob('key-*')), [])

    def test_request_id_validation(self):
        for bad in ('short', 'x' * 129, 'bad id!', None, '-leading-dash'):
            with self.assertRaises(BackupError):
                self.start(request_id=bad)

    def test_default_launcher_argv(self):
        captured = {}

        def fake_run(argv, **kwargs):
            captured['argv'], captured['env'] = argv, kwargs['env']
            return type('R', (), {'returncode': 0, 'stderr': b''})()

        original = jobs.subprocess.run
        jobs.subprocess.run = fake_run
        try:
            jobs.systemd_run_launcher(Paths())('j20261113T020000Z-0123abcd')
        finally:
            jobs.subprocess.run = original
        self.assertEqual(captured['argv'], [
            '/usr/bin/systemd-run', '--unit=woowtech-backup-j20261113T020000Z-0123abcd.service', '--collect',
            '--quiet', '--property=KillMode=mixed', '--property=MemoryMax=50%', '--property=TasksMax=512',
            '/usr/local/libexec/woowtech-cockpit-backup', 'run-job', 'j20261113T020000Z-0123abcd'])
        self.assertEqual(captured['env'], jobs.SAFE_ENV)


class RunJobTests(JobCase):
    counter = 0

    def queue(self, job_type='backup', key=False):
        RunJobTests.counter += 1
        result = self.start(job_type=job_type, params={'backup_id': 'b', 'apps': ['a']},
                            key_text=TEST_SECRET if key else None, request_id=f'req-run-{self.counter:04d}')
        return result['job_id']

    def run_with(self, job_id, handler):
        calls = []

        def wrapped(ctx, params):
            calls.append((ctx, params))
            return handler(ctx, params)

        record = jobs.run_job(self.paths, job_id, deps=object(), handlers={'backup': wrapped, 'verify': wrapped,
                                                                            'restore': wrapped})
        return record, calls

    def test_success_holds_lock_and_cleans_up(self):
        job_id = self.queue(key=True)
        observed = {}

        def handler(ctx, params):
            observed['lock_free'] = jobs.lock_is_free(self.paths)
            observed['key_file'] = ctx.key_file
            observed['key_exists'] = ctx.key_file.exists()
            ctx.phase('check')
            return {'backup_id': 'x', 'size': 1, 'apps': ['a'], 'downtime_seconds': 0}

        record, calls = self.run_with(job_id, handler)
        self.assertEqual(observed['lock_free'], False)
        self.assertTrue(observed['key_exists'])
        self.assertEqual(record['state'], 'succeeded')
        self.assertTrue(all(p['state'] == 'done' for p in record['phases']))
        self.assertEqual(record['progress']['percent'], 100)
        self.assertTrue(record['started'] and record['finished'])
        self.assertFalse(observed['key_file'].exists())
        self.assertTrue(jobs.lock_is_free(self.paths))
        self.assertEqual(calls[0][1], {'backup_id': 'b', 'apps': ['a']})

    def test_backup_error_and_unexpected_error(self):
        job_id = self.queue(key=True)

        def fail(ctx, params):
            ctx.phase('stop')
            error = BackupError('job-failed', '資料庫匯出失敗。')
            error.result = {'safety_backup_id': None}
            raise error

        record, _ = self.run_with(job_id, fail)
        self.assertEqual((record['state'], record['error']), ('failed', {'code': 'job-failed', 'message': '資料庫匯出失敗。'}))
        self.assertEqual({p['id']: p['state'] for p in record['phases']}['stop'], 'failed')
        self.assertEqual(list(Path(self.paths.run).glob('key-*')), [])
        job_id = self.queue()
        record['state'] = 'failed'

        def crash(ctx, params):
            raise RuntimeError(f'internal detail {TEST_SECRET}')

        import contextlib
        import io
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            record, _ = self.run_with(job_id, crash)
        self.assertEqual(record['error']['code'], 'internal-error')
        self.assertNotIn('internal detail', json.dumps(record))
        self.assertIn('RuntimeError', err.getvalue())
        self.assertNotIn(TEST_SECRET, self.files_text())

    def test_finished_or_running_jobs_are_never_replayed(self):
        job_id = self.queue()
        record = self.store.get(job_id)
        record['state'] = 'running'
        self.store.save(record)
        result, calls = self.run_with(job_id, lambda ctx, p: {})
        self.assertEqual((calls, result['state']), ([], 'running'))

    def test_cancel_requested_before_start(self):
        job_id = self.queue(key=True)
        self.assertEqual(jobs.cancel_job(self.paths, job_id, wait_seconds=0), {'state': 'queued'})
        record, calls = self.run_with(job_id, lambda ctx, p: {})
        self.assertEqual((calls, record['state']), ([], 'cancelled'))
        self.assertFalse(self.store.cancel_requested(job_id))
        self.assertEqual(list(Path(self.paths.run).glob('key-*')), [])

    def test_cancel_at_checkpoint(self):
        job_id = self.queue()

        def handler(ctx, params):
            ctx.phase('prepare')
            jobs.cancel_job(self.paths, job_id, wait_seconds=0)
            ctx.checkpoint()
            raise AssertionError('checkpoint did not cancel')

        record, _ = self.run_with(job_id, handler)
        self.assertEqual(record['state'], 'cancelled')
        self.assertEqual(record['error'], None)

    def test_not_cancellable_after_destructive_window(self):
        job_id = self.queue()
        results = {}

        def handler(ctx, params):
            ctx.cancellable(False)
            try:
                jobs.cancel_job(self.paths, job_id, wait_seconds=0)
            except BackupError as error:
                results['code'] = error.code
            return {}

        record, _ = self.run_with(job_id, handler)
        self.assertEqual(results['code'], 'not-cancellable')
        self.assertEqual(record['state'], 'succeeded')
        self.assertEqual(jobs.cancel_job(self.paths, job_id), {'state': 'succeeded'})

    def test_rolled_back(self):
        job_id = self.queue(job_type='restore')

        def handler(ctx, params):
            ctx.phase('restore')
            ctx.reporter.add_phase('rollback', '自動回復')
            ctx.phase('rollback')
            raise flows.RolledBack(BackupError('job-failed', '資料卷匯入失敗。'), {'rolled_back': True,
                                                                              'safety_backup_id': 's'})

        record, _ = self.run_with(job_id, handler)
        self.assertEqual(record['state'], 'rolled-back')
        self.assertEqual(record['result'], {'rolled_back': True, 'safety_backup_id': 's'})
        self.assertEqual(record['error'], {'code': 'job-failed', 'message': '資料卷匯入失敗。'})

    def test_sigterm_becomes_interrupted_and_cleanup_runs(self):
        job_id = self.queue(key=True)
        cleanup = []

        def handler(ctx, params):
            try:
                ctx.phase('stop')
                os.kill(os.getpid(), signal.SIGTERM)
                time.sleep(5)
            finally:
                cleanup.append('writers restarted')

        previous = signal.getsignal(signal.SIGTERM)
        record, _ = self.run_with(job_id, handler)
        self.assertEqual(signal.getsignal(signal.SIGTERM), previous)
        self.assertEqual(cleanup, ['writers restarted'])
        self.assertEqual(record['state'], 'interrupted')
        self.assertEqual(list(Path(self.paths.run).glob('key-*')), [])

    def test_sigterm_during_restore_keeps_safety_guidance(self):
        job_id = self.queue(job_type='restore')

        def handler(ctx, params):
            ctx.reporter.set_partial(safety_backup_id='20261113T020000Z-a1b2c3d4')
            os.kill(os.getpid(), signal.SIGTERM)
            time.sleep(5)

        record, _ = self.run_with(job_id, handler)
        self.assertEqual(record['state'], 'interrupted')
        self.assertEqual(record['result']['safety_backup_id'], '20261113T020000Z-a1b2c3d4')
        self.assertIn('20261113T020000Z-a1b2c3d4', record['error']['message'])

    def test_sigterm_with_writers_still_stopped_restarts_them(self):
        # Review CR-14: a termination signal must not leave a writer stopped (the job's own restart may have
        # been interrupted); run-job starts what is still recorded, unless the machine is shutting down.
        job_id = self.queue()
        restarted = []

        class Adapter:
            def __init__(self, app, **kwargs):
                self.app = app

            def start_units(self, units):
                restarted.append(list(units))
                return []

        app = type('App', (), {'id': 'woowbk-demo', 'writer_units': ('woowbk-demo-app.service',)})()
        deps = flows.Deps(storage=None, keys=None, archive=None, load_catalog=lambda: {'woowbk-demo': app},
                          adapter_factory=lambda app, **kwargs: Adapter(app), host_info=dict,
                          system_stopping=lambda: False)

        def handler(ctx, params):
            ctx.note_writers('woowbk-demo', ['woowbk-demo-app.service'])
            os.kill(os.getpid(), signal.SIGTERM)
            time.sleep(5)

        record = jobs.run_job(self.paths, job_id, deps=deps, handlers={'backup': handler})
        self.assertEqual(record['state'], 'interrupted')
        self.assertEqual(restarted, [['woowbk-demo-app.service']])
        self.assertEqual(record['stopped_writers'], {})

    def test_record_with_lone_surrogates_is_still_written(self):
        # Review SEC-5: a hostile manifest string in a result must not keep the record "running" forever.
        job_id = self.queue()
        record, _ = self.run_with(job_id, lambda ctx, params: {'note': 'bad \ud800 text'})
        self.assertEqual(record['state'], 'succeeded')
        self.assertEqual(self.store.get(job_id)['result'], {'note': 'bad \ud800 text'})

    def test_engine_lock_is_exclusive(self):
        first = jobs.acquire_engine_lock(self.paths, timeout=0)
        try:
            self.assertIsNotNone(first)
            self.assertIsNone(jobs.acquire_engine_lock(self.paths, timeout=0.3))
            self.assertFalse(jobs.lock_is_free(self.paths))
            job_id = self.queue()
            record = jobs.run_job(self.paths, job_id, deps=object(), lock_timeout=0.3,
                                  handlers={'backup': lambda ctx, p: {}})
            self.assertEqual((record['state'], record['error']['code']), ('failed', 'busy'))
        finally:
            os.close(first)
        self.assertTrue(jobs.lock_is_free(self.paths))


class RecoveryTests(JobCase):
    def make(self, state, age, job_type='backup', **extra):
        record = self.store.create(job_type, {'apps': ['woowbk-demo']}, now=time.time() - age)
        record['state'] = state
        record['phases'][1]['state'] = 'active'
        record.update(extra)
        self.store.save(record)
        return record['id']

    def test_marks_dead_jobs_interrupted(self):
        running = self.make('running', 30)
        old_queued = self.make('queued', 600)
        young_queued = self.make('queued', 5)
        alive = self.make('running', 30)
        done = self.make('succeeded', 30)
        restore = self.make('running', 30, job_type='restore', safety_backup_id='20261113T020000Z-a1b2c3d4')
        self.active_units.add(f'woowtech-backup-{alive}.service')
        changed = jobs.recover_interrupted(self.paths, unit_active=self.unit_active)
        self.assertEqual(sorted(changed), sorted([running, old_queued, restore]))
        record = self.store.get(running)
        self.assertEqual((record['state'], record['error']['code'], record['phases'][1]['state']),
                         ('interrupted', 'job-failed', 'failed'))
        self.assertIn('中斷', record['error']['message'])
        self.assertEqual(self.store.get(young_queued)['state'], 'queued')
        self.assertEqual(self.store.get(alive)['state'], 'running')
        self.assertEqual(self.store.get(done)['state'], 'succeeded')
        restored = self.store.get(restore)
        self.assertEqual(restored['result']['safety_backup_id'], '20261113T020000Z-a1b2c3d4')
        self.assertIn('20261113T020000Z-a1b2c3d4', restored['error']['message'])

    def test_writers_left_stopped_by_a_dead_backup_are_restarted(self):
        dead = self.make('running', 30, stopped_writers={'woowbk-demo': ['woowbk-demo-app.service']})
        calls = []

        def restart(stopped):
            calls.append(stopped)
            return []

        jobs.recover_interrupted(self.paths, unit_active=self.unit_active, restart_writers=restart)
        self.assertEqual(calls, [{'woowbk-demo': ['woowbk-demo-app.service']}])
        record = self.store.get(dead)
        self.assertEqual(record['stopped_writers'], {})
        self.assertIn('已自動重新啟動', record['error']['message'])
        self.assertTrue(any('woowbk-demo-app.service' in line for line in self.store.read_log(dead)))
        failing = self.make('running', 30, stopped_writers={'woowbk-demo': ['woowbk-demo-app.service']})
        jobs.recover_interrupted(self.paths, unit_active=self.unit_active,
                                 restart_writers=lambda stopped: ['woowbk-demo-app.service'])
        self.assertIn('未能自動重新啟動', self.store.get(failing)['error']['message'])
        crashing = self.make('running', 30, stopped_writers={'woowbk-demo': ['woowbk-demo-app.service']})
        import contextlib
        import io
        with contextlib.redirect_stderr(io.StringIO()):
            jobs.recover_interrupted(self.paths, unit_active=self.unit_active,
                                     restart_writers=lambda stopped: 1 / 0)
        self.assertEqual(self.store.get(crashing)['state'], 'interrupted')

    def test_recovery_removes_plaintext_staging_and_key_of_dead_job(self):
        dead = self.make('running', 30)
        staging = Path(self.paths.staging) / dead
        (staging / 'apps' / 'woowbk-demo' / 'secrets').mkdir(parents=True)
        (staging / 'apps' / 'woowbk-demo' / 'secrets' / 'db-password').write_text('plaintext')
        key = self.store.key_path(dead)
        key.parent.mkdir(parents=True, exist_ok=True)
        key.write_text(TEST_SECRET)
        alive = self.make('running', 30)
        self.active_units.add(f'woowtech-backup-{alive}.service')
        (Path(self.paths.staging) / alive).mkdir()
        jobs.recover_interrupted(self.paths, unit_active=self.unit_active)
        self.assertFalse(staging.exists())
        self.assertFalse(key.exists())
        self.assertTrue((Path(self.paths.staging) / alive).exists())
        self.assertIn('已清除中斷作業留下的暫存資料', self.store.read_log(dead)[-1])

    def test_sweep_removes_staging_of_finished_or_unknown_jobs_only(self):
        done = self.make('succeeded', 30)
        queued = self.make('queued', 5)
        for name in (done, queued, 'j20200101T000000Z-00000000', 'upload-tmp'):
            (Path(self.paths.staging) / name).mkdir(parents=True)
        jobs.recover_interrupted(self.paths, unit_active=self.unit_active)
        self.assertEqual(sorted(p.name for p in Path(self.paths.staging).iterdir()), sorted([queued, 'upload-tmp']))

    def test_terminal_records_with_leftover_work_are_finished_by_recovery(self):
        # Review CR-14 / CR-05: a finished (interrupted) job can still list stopped writers or a fresh deployment.
        writers = self.make('interrupted', 30, stopped_writers={'woowbk-demo': ['woowbk-demo-app.service']},
                            error={'code': 'job-failed', 'message': '中斷。'})
        fresh = self.make('interrupted', 30, job_type='restore', fresh_apps=['woowbk-demo'],
                          error={'code': 'job-failed', 'message': '中斷。'})
        calls = []
        jobs.recover_interrupted(self.paths, unit_active=self.unit_active,
                                 restart_writers=lambda stopped: calls.append(('writers', stopped)) or [],
                                 cleanup_fresh=lambda apps: calls.append(('fresh', apps)) or [])
        self.assertEqual(sorted(calls, key=str), sorted([('writers', {'woowbk-demo': ['woowbk-demo-app.service']}),
                                                         ('fresh', ['woowbk-demo'])], key=str))
        self.assertEqual(self.store.get(writers)['stopped_writers'], {})
        self.assertEqual(self.store.get(fresh)['fresh_apps'], [])
        self.assertIn('已清除未完成的全新部署', self.store.get(fresh)['error']['message'])
        calls.clear()
        jobs.recover_interrupted(self.paths, unit_active=self.unit_active,
                                 restart_writers=lambda stopped: calls.append(stopped) or [],
                                 cleanup_fresh=lambda apps: calls.append(apps) or [])
        self.assertEqual(calls, [], 'done once, never repeated')

    def test_dead_fresh_restore_is_cleaned_up_and_explained(self):
        dead = self.make('running', 30, job_type='restore', fresh_apps=['woowbk-demo'])
        problems = [['無法移除資料卷 woowbk-demo-files']]
        jobs.recover_interrupted(self.paths, unit_active=self.unit_active,
                                 cleanup_fresh=lambda apps: problems.pop(0))
        record = self.store.get(dead)
        self.assertEqual(record['result']['fresh_apps'], ['woowbk-demo'])
        self.assertIn('需人工處理', record['error']['message'])
        self.assertEqual(record['fresh_apps'], [])

    def test_hd04_a_fresh_deployment_already_in_use_is_kept_and_reported_once(self):
        dead = self.make('running', 30, job_type='restore', fresh_apps=['woowbk-demo'])
        calls = []

        def cleanup(apps):
            calls.append(apps)
            return ['「示範筆記應用」的服務（woowbk-demo-app.service）已解除暫時停用或正在執行，可能已有新的資料，'
                    '因此沒有自動移除；需人工確認是否保留這個部署']
        jobs.recover_interrupted(self.paths, unit_active=self.unit_active, cleanup_fresh=cleanup)
        record = self.store.get(dead)
        self.assertEqual((record['state'], record['fresh_apps']), ('interrupted', []))
        self.assertIn('需人工確認', record['error']['message'])
        self.assertEqual(record['result']['warnings'], [])
        jobs.recover_interrupted(self.paths, unit_active=self.unit_active, cleanup_fresh=cleanup)
        self.assertEqual(calls, [['woowbk-demo']], 'decided once, never repeated')

    def test_host_directories_of_a_dead_restore_are_settled_once_before_fresh_removal(self):
        dead = self.make('running', 30, job_type='restore', dir_apps=['woowbk-demo'], fresh_apps=['woowbk-demo'])
        calls = []

        def settle(job_id, apps):
            calls.append(('dirs', job_id, apps))
            return ['已把 ~/woowbk-demo-data 的原內容移回（~/woowbk-demo-data.woowbk-old-x）',
                    '~/html 被取代前的內容保留在 ~/html.woowbk-old-x，確認應用正常後可刪除']
        jobs.recover_interrupted(self.paths, unit_active=self.unit_active, settle_dirs=settle,
                                 cleanup_fresh=lambda apps: calls.append(('fresh', apps)) or [])
        self.assertEqual(calls, [('dirs', dead, ['woowbk-demo']), ('fresh', ['woowbk-demo'])],
                         'a missing directory gets its copy back before a fresh deployment is removed')
        record = self.store.get(dead)
        self.assertEqual((record['state'], record['dir_apps']), ('interrupted', []))
        self.assertIn('主機資料夾：已把 ~/woowbk-demo-data 的原內容移回', record['error']['message'])
        self.assertIn('確認應用正常後可刪除', record['error']['message'])
        self.assertTrue(any('主機資料夾：' in line for line in self.store.read_log(dead)))
        jobs.recover_interrupted(self.paths, unit_active=self.unit_active, settle_dirs=settle)
        self.assertEqual(len(calls), 2, 'decided once, never repeated')

    def test_a_shutdown_interrupted_record_keeps_its_directories_for_the_recovery(self):
        # A restore cut by a shutdown ends `interrupted` itself and keeps `dir_apps` (flows); the next pass settles.
        finished = self.make('interrupted', 30, job_type='restore', dir_apps=['woowbk-demo'],
                             error={'code': 'job-failed', 'message': '中斷。'})
        self.assertTrue(jobs.has_leftovers(self.store.get(finished)))
        settled = []
        jobs.recover_interrupted(self.paths, unit_active=self.unit_active,
                                 settle_dirs=lambda job_id, apps: settled.append((job_id, apps)) or [])
        self.assertEqual(settled, [(finished, ['woowbk-demo'])])
        record = self.store.get(finished)
        self.assertEqual((record['dir_apps'], record['error']['message']), ([], '中斷。'), 'nothing to add')

    def test_settle_errors_never_break_recovery(self):
        import contextlib
        import io
        dead = self.make('running', 30, job_type='restore', dir_apps=['woowbk-demo'])
        with contextlib.redirect_stderr(io.StringIO()):
            jobs.recover_interrupted(self.paths, unit_active=self.unit_active,
                                     settle_dirs=lambda job_id, apps: 1 / 0)
        record = self.store.get(dead)
        self.assertEqual((record['state'], record['dir_apps']), ('interrupted', []))
        self.assertIn('需人工確認', record['error']['message'])

    def test_without_a_settle_hook_the_marker_waits(self):
        dead = self.make('running', 30, job_type='restore', dir_apps=['woowbk-demo'])
        jobs.recover_interrupted(self.paths, unit_active=self.unit_active)
        self.assertEqual(self.store.get(dead)['dir_apps'], ['woowbk-demo'], 'kept for a pass that can settle it')

    def test_interrupted_restore_result_says_what_was_reached(self):
        record = self.store.create('restore', {'backup_id': 'b', 'apps': ['woowbk-demo']})
        message, result = jobs.interrupted_details(record)
        self.assertIs(result['changed'], False)
        self.assertIsNone(result['safety_backup_id'])
        for item in record['phases']:
            if item['id'] in ('prepare', 'decrypt', 'preflight', 'safety', 'stop'):
                item['state'] = 'done'
        record['fresh_apps'] = ['woowbk-demo']
        message, result = jobs.interrupted_details(record)
        self.assertIs(result['changed'], True)
        self.assertEqual(result['fresh_apps'], ['woowbk-demo'])
        self.assertIn('全新部署（woowbk-demo）沒有完成', message)

    def test_stale_key_files_are_removed(self):
        # Review SEC-4: a helper killed during inspect left the pasted key on tmpfs until reboot.
        Path(self.paths.run).mkdir(parents=True, exist_ok=True)
        inspect_key = Path(self.paths.run) / 'key-inspect-0123456789abcdef'
        inspect_key.write_text(TEST_SECRET)
        finished = self.make('succeeded', 30)
        running = self.make('running', 30)
        self.active_units.add(f'woowtech-backup-{running}.service')
        for job_id in (finished, running):
            self.store.key_path(job_id).write_text(TEST_SECRET)
        jobs.recover_interrupted(self.paths, unit_active=self.unit_active)
        self.assertEqual(sorted(p.name for p in Path(self.paths.run).glob('key-*')),
                         sorted([inspect_key.name, f'key-{running}']), 'an inspect may still be using its key')
        jobs.recover_interrupted(self.paths, unit_active=self.unit_active,
                                 now=time.time() + jobs.KEY_FILE_MAX_AGE + 120)
        self.assertEqual(sorted(p.name for p in Path(self.paths.run).glob('key-*')), [f'key-{running}'])

    def test_held_lock_means_alive(self):
        running = self.make('running', 30)
        fd = jobs.acquire_engine_lock(self.paths, timeout=0)
        try:
            self.assertEqual(jobs.recover_interrupted(self.paths, unit_active=self.unit_active), [])
        finally:
            os.close(fd)
        self.assertEqual(jobs.recover_interrupted(self.paths, unit_active=self.unit_active), [running])

    def test_no_jobs_dir(self):
        self.assertEqual(jobs.recover_interrupted(Paths(base=Path(self.tmp.name) / 'empty'), unit_active=self.unit_active), [])


# ---------------------------------------------------------------- release regression 16: job-record races

class ListingHookStore(jobs.JobStore):
    """Runs `after_listing` once, right after the recovery listed every record: the window of the race."""

    def __init__(self, paths, after_listing):
        super().__init__(paths)
        self.after_listing = after_listing

    def list(self, limit=50):
        records = super().list(limit)
        if limit is None and self.after_listing is not None:
            hook, self.after_listing = self.after_listing, None
            hook()
        return records


class SimulatedRunJob:
    """What a run-job process does with its record: it holds the engine lock while it runs, writes through a
    JobReporter, writes its final state, and only then is the lock released and the unit inactive."""

    def __init__(self, case, job_type, params=None, **fields):
        self.case = case
        record = case.store.create(job_type, params or {}, now=time.time() - 30)
        self.engine_fd = jobs.acquire_engine_lock(case.paths, timeout=0)
        case.assertIsNotNone(self.engine_fd)
        record.update({'state': 'running', 'started': jobs.utc_iso(), **fields})
        self.reporter = jobs.JobReporter(case.store, record, min_interval=0)
        self.reporter.set_partial()  # saves the running record
        self.job_id = record['id']
        self.unit = jobs.unit_name(self.job_id)
        case.active_units.add(self.unit)

    def finish(self, state, **kwargs):
        self.reporter.finish(state, **kwargs)
        self.exit()

    def exit(self):
        """The process is gone (finished or SIGKILL): the kernel drops its flock, systemd marks the unit inactive."""
        if self.engine_fd is not None:
            os.close(self.engine_fd)
            self.engine_fd = None
        self.case.active_units.discard(self.unit)


class RecoveryRaceTests(JobCase):
    """A job that finishes while a helper command runs the recovery keeps the record it wrote itself."""

    def setUp(self):
        super().setUp()
        self.calls = {'restart_writers': [], 'cleanup_fresh': []}

    def restart_writers(self, stopped):
        self.calls['restart_writers'].append(stopped)
        return []

    def cleanup_fresh(self, apps):
        self.calls['cleanup_fresh'].append(apps)
        return []

    def recover(self, store=None, unit_active=None):
        return jobs._recover_locked(self.paths, store or self.store, unit_active or self.unit_active, time.time(),
                                    restart_writers=self.restart_writers, cleanup_fresh=self.cleanup_fresh)

    def assert_untouched(self, job_id, state, changed):
        record = self.store.get(job_id)
        self.assertEqual(record['state'], state)
        self.assertEqual(changed, [])
        self.assertEqual(self.calls, {'restart_writers': [], 'cleanup_fresh': []})
        self.assertFalse(any('作業被判定為已中斷' in line for line in self.store.read_log(job_id)))
        return record

    # The reproduction of the release regression, ported unchanged in substance: the unit probe plays the job's
    # last steps (clear markers, final record, exit) exactly between the listing and the decision.
    def repro(self, job_type, final_state, extra):
        record = self.store.create(job_type, {'apps': ['woowbk-demo']} if job_type == 'restore' else {})
        record.update({'state': 'running', 'phase': 'check', **extra})
        self.store.save(record)

        def unit_active(_unit):
            final = self.store.get(record['id'])
            final.update({'state': final_state, 'finished': jobs.utc_iso(), 'fresh_apps': [], 'stopped_writers': {},
                          'error': None if final_state == 'succeeded' else {'code': 'corrupt-archive', 'message': 'x'}})
            self.store.save(final)
            self.store.append_log(record['id'], f'作業結束：{final_state}')
            return False

        return self.assert_untouched(record['id'], final_state, self.recover(unit_active=unit_active))

    def test_repro_verify_that_failed_meanwhile_stays_failed(self):
        record = self.repro('verify', 'failed', {})
        self.assertEqual(record['error'], {'code': 'corrupt-archive', 'message': 'x'})

    def test_repro_backup_that_succeeded_meanwhile_keeps_writers_alone(self):
        self.repro('backup', 'succeeded', {'stopped_writers': {'woowbk-demo': ['woowbk-demo-app.service']}})

    def test_repro_fresh_restore_that_succeeded_meanwhile_is_not_removed(self):
        self.repro('restore', 'succeeded', {'fresh_apps': ['woowbk-demo'], 'safety_backup_id': None})

    def test_job_finishing_right_after_the_listing_keeps_its_final_record(self):
        # The same race with the real locking: the job holds the engine lock until its final record is written.
        cases = (('verify', {}, 'failed'),
                 ('backup', {'stopped_writers': {'woowbk-demo': ['woowbk-demo-app.service']}}, 'succeeded'),
                 ('restore', {'fresh_apps': ['woowbk-demo'], 'safety_backup_id': None}, 'succeeded'))
        for job_type, fields, final in cases:
            with self.subTest(job_type=job_type):
                job = SimulatedRunJob(self, job_type, {'apps': ['woowbk-demo']}, **fields)

                def last_steps(job=job, final=final):
                    job.reporter.set_partial(stopped_writers={}, fresh_apps=[])  # the flow's own clean-up
                    job.finish(final, error=None if final == 'succeeded' else {'code': 'corrupt-archive',
                                                                                  'message': 'x'})

                self.assert_untouched(job.job_id, final, self.recover(store=ListingHookStore(self.paths, last_steps)))

    def test_running_job_is_left_alone_without_probing_its_unit(self):
        job = SimulatedRunJob(self, 'verify')
        probes = []
        self.assertEqual(self.recover(unit_active=lambda unit: probes.append(unit) or False), [])
        self.assertEqual(probes, [], 'no systemctl call while the job holds the engine lock')
        self.assertEqual(self.store.get(job.job_id)['state'], 'running')
        job.finish('succeeded', result={'ok': True})
        self.assertEqual(self.recover(), [])
        self.assertEqual(self.store.get(job.job_id)['state'], 'succeeded')

    def test_killed_job_side_effects_come_from_its_last_record_not_the_listing(self):
        # A fresh deployment recorded after the listing, then SIGKILL: it is removed (was forgotten before).
        job = SimulatedRunJob(self, 'restore', {'apps': ['woowbk-demo']}, safety_backup_id=None)

        def recorded_then_killed():
            job.reporter.set_partial(fresh_apps=['woowbk-demo'])
            job.exit()

        self.assertEqual(self.recover(store=ListingHookStore(self.paths, recorded_then_killed)), [job.job_id])
        record = self.store.get(job.job_id)
        self.assertEqual(record['state'], 'interrupted')
        self.assertEqual(self.calls['cleanup_fresh'], [['woowbk-demo']])
        self.assertEqual((record['fresh_apps'], record['result']['fresh_apps']), ([], ['woowbk-demo']))
        self.assertIn('已清除未完成的全新部署', record['error']['message'])

        # Writers restarted by the backup itself after the listing, then SIGKILL: nothing is restarted again.
        self.calls = {'restart_writers': [], 'cleanup_fresh': []}
        job = SimulatedRunJob(self, 'backup', {'apps': ['woowbk-demo']},
                              stopped_writers={'woowbk-demo': ['woowbk-demo-app.service']})

        def restarted_then_killed():
            job.reporter.set_partial(stopped_writers={})
            job.exit()

        self.assertEqual(self.recover(store=ListingHookStore(self.paths, restarted_then_killed)), [job.job_id])
        self.assertEqual(self.store.get(job.job_id)['state'], 'interrupted')
        self.assertEqual(self.calls['restart_writers'], [])

    def test_queued_job_waits_while_recovery_holds_the_engine_lock_then_runs(self):
        dead = SimulatedRunJob(self, 'backup', {'apps': ['woowbk-demo']},
                               stopped_writers={'woowbk-demo': ['woowbk-demo-app.service']})
        dead.exit()  # SIGKILL; the recovery inside start_job (no restart_writers here) leaves its writers listed
        queued = self.start(job_type='verify', params={'backup_id': 'b'}, request_id='req-wait-00000001')['job_id']
        self.assertEqual(self.store.get(dead.job_id)['state'], 'interrupted')
        self.active_units.add(jobs.unit_name(queued))  # its run-job is alive, waiting for the engine lock
        in_clean_up, release = threading.Event(), threading.Event()

        def slow_restart(stopped):
            in_clean_up.set()
            release.wait(10)
            return []

        worker = threading.Thread(target=jobs.recover_interrupted, args=(self.paths,),
                                  kwargs={'unit_active': self.unit_active, 'restart_writers': slow_restart})
        worker.start()
        try:
            self.assertTrue(in_clean_up.wait(10))
            self.assertIsNone(jobs.try_engine_lock(self.paths), 'the recovery holds the engine lock while it cleans up')
            threading.Timer(0.5, release.set).start()
            record = jobs.run_job(self.paths, queued, deps=object(), lock_timeout=30,
                                  handlers={'verify': lambda ctx, params: {'ok': True}})
        finally:
            release.set()
            worker.join(10)
        self.assertEqual(record['state'], 'succeeded')
        self.assertEqual(self.store.get(dead.job_id)['stopped_writers'], {})

    def test_leftovers_of_a_finished_job_wait_while_another_job_runs(self):
        # Restarting writers of an old interrupted backup while a new backup has them stopped would break its dump.
        old = SimulatedRunJob(self, 'backup', {'apps': ['woowbk-demo']})
        old.finish('interrupted', error={'code': 'job-failed', 'message': '中斷。'})
        record = self.store.get(old.job_id)
        record['stopped_writers'] = {'woowbk-demo': ['woowbk-demo-app.service']}
        self.store.save(record)
        running = SimulatedRunJob(self, 'backup', {'apps': ['woowbk-demo']})
        self.recover()
        self.assertEqual(self.calls['restart_writers'], [])
        running.finish('succeeded', result={})
        self.recover()
        self.assertEqual(self.calls['restart_writers'], [{'woowbk-demo': ['woowbk-demo-app.service']}])
        self.assertEqual(self.store.get(old.job_id)['stopped_writers'], {})


class CancelRaceTests(JobCase):
    """job-cancel vs. the job's own record writes and its end."""

    def queue(self):
        return self.start(params={'apps': ['woowbk-demo']}, request_id=f'req-cancel-{time.monotonic_ns()}')['job_id']

    def run_handler(self, job_id, handler):
        return jobs.run_job(self.paths, job_id, deps=object(), handlers={'backup': handler})

    def test_cancel_accepted_just_before_the_window_closes_stops_the_job_there(self):
        job_id = self.queue()
        destructive = []

        def handler(ctx, params):
            ctx.checkpoint()
            # job-cancel arrives after the last checkpoint and before the job closes the cancellable window
            self.assertEqual(jobs.cancel_job(self.paths, job_id, wait_seconds=0), {'state': 'running'})
            ctx.cancellable(False)
            destructive.append('writers stopped')
            return {}

        record = self.run_handler(job_id, handler)
        self.assertEqual((record['state'], destructive), ('cancelled', []))
        self.assertEqual(self.store.get(job_id)['state'], 'cancelled')
        self.assertFalse(self.store.cancel_requested(job_id))

    def test_cancel_request_survives_whole_record_rewrites(self):
        job_id = self.queue()

        def handler(ctx, params):
            ctx.phase('prepare')
            jobs.cancel_job(self.paths, job_id, wait_seconds=0)
            for i in range(40):  # every progress/phase update rewrites the whole record
                ctx.reporter.progress(fraction=i / 40, message=str(i), force=True)
                ctx.phase('check' if i % 2 else 'prepare')
            ctx.checkpoint()
            raise AssertionError('the cancel request was lost')

        self.assertEqual(self.run_handler(job_id, handler)['state'], 'cancelled')

    def test_cancel_from_another_thread_while_progress_is_written(self):
        job_id = self.queue()
        started, stop = threading.Event(), threading.Event()
        replies, bad_reads, reads = [], [], [0]

        def reader():
            while not stop.is_set():
                try:
                    if self.store.get(job_id)['id'] != job_id:
                        bad_reads.append('wrong id')
                    reads[0] += 1
                except BackupError as error:
                    bad_reads.append(error.message)

        def canceller():
            if started.wait(10):
                replies.append(jobs.cancel_job(self.paths, job_id, wait_seconds=0))

        threads = [threading.Thread(target=reader), threading.Thread(target=canceller)]
        for thread in threads:
            thread.start()

        def handler(ctx, params):
            ctx.phase('prepare')
            started.set()
            deadline, i = time.monotonic() + 15, 0
            while time.monotonic() < deadline:
                i += 1
                ctx.reporter.progress(fraction=(i % 100) / 100, message=f'{i}', force=True)
                ctx.checkpoint()
            raise AssertionError('the cancel request was never honoured')

        try:
            record = self.run_handler(job_id, handler)
        finally:
            stop.set()
            for thread in threads:
                thread.join(15)
        self.assertEqual(record['state'], 'cancelled')
        self.assertEqual(replies, [{'state': 'running'}])
        self.assertEqual(bad_reads, [])
        self.assertGreater(reads[0], 0)

    def test_cancel_racing_with_the_end_of_the_job_leaves_no_stale_request(self):
        job_id = self.queue()
        record = self.store.get(job_id)
        record['state'] = 'running'
        self.store.save(record)
        original = jobs.JobStore.request_cancel
        seen = {}

        def request_cancel(store, jid):
            # The job (another process) ends between job-cancel's check and the request file.
            def job_ends():
                other = jobs.JobStore(self.paths)
                jobs.JobReporter(other, other.get(jid)).finish('succeeded', result={})
                other.clear_cancel(jid)  # run-job's finally

            thread = threading.Thread(target=job_ends)
            thread.start()
            thread.join(0.5)
            seen['thread'] = thread
            original(store, jid)

        with mock.patch.object(jobs.JobStore, 'request_cancel', request_cancel):
            jobs.cancel_job(self.paths, job_id, wait_seconds=0)
        seen['thread'].join(10)
        self.assertEqual(self.store.get(job_id)['state'], 'succeeded')
        self.assertFalse(self.store.cancel_requested(job_id), 'a finished job kept a cancel request')


class LaunchRaceTests(JobCase):
    def test_launcher_error_after_the_job_already_started_keeps_the_running_job(self):
        def launcher(job_id):
            # systemd-run started the unit and run-job took the job, then systemd-run reported a timeout
            record = self.store.get(job_id)
            record.update(state='running', started=jobs.utc_iso())
            self.store.save(record)
            raise BackupError('internal-error', '無法啟動背景作業。')

        result = self.start(job_type='verify', params={'backup_id': 'b'}, key_text=TEST_SECRET, launcher=launcher)
        self.assertEqual(result['deduplicated'], False)
        self.assertEqual(self.store.get(result['job_id'])['state'], 'running')
        self.assertTrue(self.store.key_path(result['job_id']).exists(), 'the running job still needs its key')

    def test_launch_failure_before_the_start_wins_and_a_late_run_job_refuses(self):
        with self.assertRaises(BackupError):
            self.start(job_type='verify', params={'backup_id': 'b'}, key_text=TEST_SECRET, launcher=Launcher(fail=True))
        record = self.store.list()[0]
        self.assertEqual(record['state'], 'failed')
        self.assertFalse(self.store.key_path(record['id']).exists())
        calls = []
        late = jobs.run_job(self.paths, record['id'], deps=object(),
                            handlers={'verify': lambda ctx, params: calls.append(params) or {}})
        self.assertEqual((late['state'], calls), ('failed', []))


class RetentionTests(JobCase):
    def make(self, job_type, state, age, params=None, **fields):
        record = self.store.create(job_type, params if params is not None else {'apps': ['woowbk-demo']},
                                   now=time.time() - age)
        record.update(state=state, **fields)
        self.store.save(record)
        self.store.append_log(record['id'], 'x')
        return record['id']

    def side_files(self, job_id):
        return sorted(p.name for p in Path(self.paths.jobs).iterdir() if job_id in p.name)

    def listed(self):
        return {record['id'] for record in self.store.list(limit=None)}

    def test_keeps_newest_finished_records_and_everything_still_needed(self):
        safety = '20261101T000000Z-00000001'
        pinning = self.make('restore', 'failed', 100_000, params={'backup_id': 'b', 'apps': ['woowbk-demo']},
                            result={'apps': ['woowbk-demo'], 'safety_backup_id': safety, 'rolled_back': False})
        settled = self.make('restore', 'failed', 99_000, params={'backup_id': 'b', 'apps': ['other-app']},
                            result={'apps': ['other-app'], 'safety_backup_id': '20261101T000000Z-00000002',
                                    'rolled_back': False})
        settling = self.make('restore', 'succeeded', 98_000, params={'backup_id': 'b', 'apps': ['other-app']})
        leftover = self.make('backup', 'interrupted', 97_000, error={'code': 'job-failed', 'message': '中斷。'},
                             stopped_writers={'woowbk-demo': ['woowbk-demo-app.service']})
        alive = self.make('backup', 'running', 96_000)
        self.active_units.add(jobs.unit_name(alive))
        finished = [self.make('verify', 'succeeded', 50_000 - i) for i in range(210)]  # oldest first
        self.store.request_cancel(finished[0])
        pinned_before = flows.pinned_safety(self.paths)
        self.assertEqual(pinned_before, {safety})
        jobs.recover_interrupted(self.paths, unit_active=self.unit_active)  # no restart_writers: leftover stays
        self.assertEqual(self.listed(), set(finished[10:]) | {pinning, leftover, alive})
        for gone in [*finished[:10], settled, settling]:
            self.assertEqual(self.side_files(gone), [], 'record, log, lock and cancel request are all removed')
        self.assertEqual(self.side_files(finished[10]), [f'{finished[10]}.json', f'{finished[10]}.lock',
                                                          f'{finished[10]}.log'])
        self.assertEqual(flows.pinned_safety(self.paths), pinned_before)
        jobs.recover_interrupted(self.paths, unit_active=self.unit_active)
        self.assertEqual(len(self.listed()), 203, 'stable once pruned')

    def test_unreadable_records_and_orphaned_side_files_are_cleaned_when_old(self):
        jobs_dir = Path(self.paths.jobs)
        finished = [self.make('verify', 'succeeded', 50_000 - i) for i in range(jobs.KEEP_TERMINAL)]
        unreadable = 'j20200101T000000Z-0badf00d'
        (jobs_dir / f'{unreadable}.json').write_text('not json')
        old, young = 'j20200102T000000Z-0000000a', 'j20200103T000000Z-0000000b'
        for name in (f'{old}.log', f'{old}.lock', f'{old}.cancel', f'.{finished[0]}.json.0123456789ab.tmp',
                     f'{young}.log'):
            (jobs_dir / name).write_text('')
        stale = time.time() - jobs.ORPHAN_MAX_AGE - 60
        for name in (f'{old}.log', f'{old}.lock', f'{old}.cancel', f'.{finished[0]}.json.0123456789ab.tmp'):
            os.utime(jobs_dir / name, (stale, stale))
        jobs.recover_interrupted(self.paths, unit_active=self.unit_active)
        names = {p.name for p in jobs_dir.iterdir()}
        self.assertNotIn(f'{unreadable}.json', names, 'the oldest, beyond the newest 200: deleted')
        self.assertEqual({n for n in names if old in n or n.endswith('.tmp')}, set())
        self.assertIn(f'{young}.log', names, 'an orphan younger than an hour is kept')
        self.assertEqual(self.listed(), set(finished))

    def test_status_jobs_and_job_status_read_a_bounded_number_of_records(self):
        for i in range(jobs.KEEP_TERMINAL + 60):
            self.make('verify', 'succeeded', 10_000 - i)
        jobs.recover_interrupted(self.paths, unit_active=self.unit_active)  # prunes to the newest 200
        reads = []
        original = jobs.read_json

        def counting(path, *args, **kwargs):
            reads.append(Path(path).name)
            return original(path, *args, **kwargs)

        with mock.patch.object(jobs, 'read_json', counting):
            jobs.recover_interrupted(self.paths, unit_active=self.unit_active)
            recovery_reads = len(reads)
            reads.clear()
            listed = self.store.list(50)
        self.assertLessEqual(recovery_reads, jobs.KEEP_TERMINAL)
        self.assertEqual((len(listed), len(reads)), (50, 50), 'jobs reads only what it returns')


class ConcurrentPollerTests(JobCase):
    def test_short_jobs_with_three_concurrent_pollers_are_never_misclassified(self):
        """The live probe in miniature: back-to-back short jobs while three threads run the recovery the way
        status/jobs/job-status do. Every job keeps the state it wrote itself."""
        current = {'unit': None}
        stop = threading.Event()
        errors, passes = [], [0]

        def unit_active(unit):
            return unit == current['unit']

        def poller():
            while not stop.is_set():
                try:
                    jobs.recover_interrupted(self.paths, unit_active=unit_active)
                    passes[0] += 1
                except Exception as exc:  # noqa: BLE001 - reported by the assertion below
                    errors.append(repr(exc))

        def handler(ctx, params):
            ctx.phase('decrypt')
            time.sleep(0.002)
            ctx.phase('check')
            return {'ok': True, 'entries': 1, 'bytes': 1}

        threads = [threading.Thread(target=poller, daemon=True) for _ in range(3)]
        for thread in threads:
            thread.start()
        ids = []
        try:
            for i in range(30):
                job_id = jobs.start_job(self.paths, 'verify', {'backup_id': 'b'}, f'req-stress-{i:04d}',
                                        launcher=lambda jid: current.update(unit=jobs.unit_name(jid)),
                                        unit_active=unit_active)['job_id']
                jobs.run_job(self.paths, job_id, deps=object(), handlers={'verify': handler})
                current['unit'] = None  # the process exited
                ids.append(job_id)
                time.sleep(0.003)
        finally:
            stop.set()
            for thread in threads:
                thread.join(15)
        self.assertEqual(errors, [])
        self.assertGreater(passes[0], 0)
        states = {job_id: self.store.get(job_id)['state'] for job_id in ids}
        self.assertEqual({s for s in states.values()}, {'succeeded'}, states)
        judged = [job_id for job_id in ids if any('作業被判定為已中斷' in line for line in self.store.read_log(job_id))]
        self.assertEqual(judged, [])


if __name__ == '__main__':
    unittest.main()
