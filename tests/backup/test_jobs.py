"""Job records, dedup, busy, launcher injection, flock, recovery, cancel and signal handling."""
import json
import os
import signal
import stat
import tempfile
import time
import unittest
from pathlib import Path

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
        self.assertEqual([p.name for p in Path(self.paths.jobs).iterdir()], [path.name])

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


if __name__ == '__main__':
    unittest.main()
