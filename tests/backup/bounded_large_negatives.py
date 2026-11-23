#!/usr/bin/env python3
"""Opt-in real >8GiB encrypted stream negatives on the public engine API, bounded for a shared host disk.
python3 tests/backup/bounded_large_negatives.py [--mib 8193] [--scratch-parent /tmp]

One fresh compressible keystream (the existing SHAKE256 tile generator) is streamed through the real age/zstd writer
by a sliding-window source (bounded_stream_window); the engine's own sha256 check proves every byte it read was the
keystream. Ephemeral age key in private scratch. Cases, all through public engine calls:
  control-verify      unchanged original: verify_archive passes (attributes the later failures to the mutations)
  flip-last-byte      verify_archive: corrupt-archive after >= payload-64MiB of progress
  truncate-last-byte  verify_archive, then extract_archive (harness punches holes behind the engine's write offset to
                      bound allocation): corrupt-archive late; the engine removes its partial output
  cancel-extract      restore 'decrypt' window: a second thread calls jobs.cancel_job (the job-cancel command's
                      function) at >= half; the real FlowContext.byte_progress raises flows.Cancelled; the engine
                      removes its partial output (really allocated, not punched) and the space comes back
  cancel-write        backup 'package' window, same real job cancel during write_archive: staged temp archive and the
                      recipient file are removed, the destination is never created
Each case counts age/zstd children while active and after return (must be 0), checks pipes/temp fds return to their
baseline and that no copy of the identity exists anywhere in scratch. No raw exception text, tool stderr, key
contents or key identifiers are recorded.
"""
import argparse
import json
import os
from pathlib import Path
import resource
import shutil
import signal
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / 'backup-engine')]
from tests.backup import bounded_large_archive as common
from tests.backup import bounded_stream_failures as failures
from tests.backup import bounded_stream_window as window
from tests.backup.test_archive import open_fds, tool_children
from tests.backup.test_archive_v2 import small_inner
from woowbackup import archive, flows, jobs, util
from woowbackup.errors import BackupError
from woowbackup.haimport import SpaceGuard
from woowbackup.keys import KeyStore
from woowbackup.paths import Paths

MIB = 1024 ** 2
GIB = 1024 ** 3
RESERVE, MARGIN, CAP = common.RESERVE, common.MARGIN, common.ARCHIVE_CAP
require = common.require
APP = 'large-probe'
ENTRY = f'apps/{APP}/config/payload.bin'
DEADLINE = 3600
SECRET_MARK = b'AGE-SECRET-KEY-'
LATE_SLACK = 64 * MIB


def storage_budget(size):
    """Peak bytes this probe adds: cancel-extract keeps about half the payload really allocated (plus the cancel
    latency of a few progress steps) next to the capped original; every other phase stays under the window/puncher
    bound next to at most two capped archives."""
    return size // 2 + 64 * MIB + 2 * CAP + 128 * MIB


def job_context(folder, job_type, params, phase):
    """A real job record, reporter and FlowContext in private scratch (Paths(base=...): nothing outside it)."""
    paths = Paths(base=folder / f'engine-{job_type}')
    store = jobs.JobStore(paths)
    record = store.create(job_type, params)
    reporter = jobs.JobReporter(store, record)
    reporter.start()
    ctx = flows.FlowContext(paths, record['id'], None, reporter)
    ctx.cancellable(True)
    ctx.phase(phase)
    return paths, store, record['id'], ctx


class UserCancel(threading.Thread):
    """Plays the administrator: once released it calls the job-cancel command's function from another thread while
    the engine keeps streaming (in production run-job and the cancel command are separate processes)."""

    def __init__(self, paths, job_id):
        super().__init__(name='probe-user-cancel', daemon=True)
        self.paths, self.job_id = paths, job_id
        self.release, self.done = threading.Event(), threading.Event()
        self.abandoned = False
        self.state = self.error = None

    def run(self):
        self.release.wait()
        if self.abandoned:
            return
        try:
            self.state = jobs.cancel_job(self.paths, self.job_id, wait_seconds=0)['state']
        except BaseException as exc:  # noqa: BLE001 - recorded by type only
            self.error = type(exc).__name__
        finally:
            self.done.set()

    def request(self, timeout=10):
        """Release the cancel command and let it record its request before this progress callback returns, so the
        engine meets the request at a known checkpoint (the engine code path is unchanged; it is only paused)."""
        self.release.set()
        return self.done.wait(timeout)

    def finish(self):
        if not self.release.is_set():
            self.abandoned = True
            self.release.set()
        self.join(timeout=30)
        return not self.is_alive()


def secret_copies(folder, identity):
    """Files in scratch (other than the ephemeral identity itself) containing an age secret key marker. Count only."""
    count = 0
    for path in sorted(Path(folder).rglob('*')):
        if path == identity or path.is_symlink() or not path.is_file():
            continue
        with path.open('rb') as handle:
            tail = b''
            while chunk := handle.read(MIB):
                if SECRET_MARK in tail + chunk:
                    count += 1
                    break
                tail = chunk[-len(SECRET_MARK):]
    return count


def manifest_for(key_id):
    inner = small_inner(APP, key_id, {ENTRY: b''}, encryption='age-x25519')
    manifest = {k: v for k, v in inner.items() if k not in ('app', 'backup_apps')}
    manifest['apps'] = [inner['app']]
    return manifest


def children_gone(pids):
    """True when none of the age/zstd pids seen during a case is still a child of this process (running or zombie)."""
    return not set(pids) & set(tool_children())


class Case:
    """Shared bookkeeping of one consumer run: progress, children, fds, partial output."""

    def __init__(self, name, consumer, size, monitor, report):
        self.r = report.setdefault('cases', {}).setdefault(name, {})
        self.r.update(consumer=consumer, max_progress_bytes=0, active_tool_children_observed=0)
        self.size, self.monitor = size, monitor
        self.pids = set()
        self.fd_baseline = open_fds()
        self.mark = time.monotonic()

    def observe(self, done, total):
        self.monitor()
        require(total == self.size, 'unexpected progress total')
        self.r['max_progress_bytes'] = max(self.r['max_progress_bytes'], done)
        children = tool_children()
        self.pids.update(children)
        self.r['active_tool_children_observed'] = max(self.r['active_tool_children_observed'], len(children))

    def after(self):
        self.r['tool_children_after_consumer'] = len(tool_children())
        self.r['observed_children_reaped'] = children_gone(self.pids)
        self.r['open_pipe_or_temp_fds_delta'] = open_fds() - self.fd_baseline
        self.r['elapsed_seconds'] = round(time.monotonic() - self.mark, 3)
        require(self.r['active_tool_children_observed'] >= 2, 'age/zstd children were not observed while active')
        require(self.r['tool_children_after_consumer'] == 0, 'consumer left tool children')
        require(self.r['observed_children_reaped'], 'an observed tool child survived')
        require(self.r['open_pipe_or_temp_fds_delta'] == 0, 'consumer leaked pipes or temp files')

    def late(self):
        self.r['late_failure_minimum_bytes'] = max(8 * MIB, self.size - LATE_SLACK)
        require(self.r['max_progress_bytes'] >= self.r['late_failure_minimum_bytes'],
                'failure occurred too early to count as late-tail')


def expect_corrupt(call):
    try:
        call()
    except BackupError as exc:
        require(exc.code == 'corrupt-archive', 'unexpected refusal code')
        return exc.code
    raise RuntimeError('negative unexpectedly succeeded')


def control_verify(original, identities, size, monitor, report):
    case = Case('control-verify', 'verify_archive', size, monitor, report)
    result = archive.verify_archive(original, identities, progress=case.observe)
    require(result['bytes'] == size and result['entries'] == 1, 'control verify counts mismatch')
    case.after()
    case.r.update(verified_bytes=result['bytes'], status='passed')


def tail_verify(name, mutated, identities, size, monitor, report):
    case = Case(name, 'verify_archive', size, monitor, report)
    case.r['error_code'] = expect_corrupt(lambda: archive.verify_archive(mutated, identities, progress=case.observe))
    case.after()
    case.late()
    case.r['status'] = 'passed'


def tail_extract(name, mutated, identities, root, size, monitor, report):
    """Late truncation during extraction. The harness punches holes behind the engine's write offset so the host keeps
    its reserve; the engine still writes every byte at its real offsets and must remove the file itself."""
    case = Case(name, 'extract_archive', size, monitor, report)
    root.mkdir(mode=0o700)
    puncher = window.OutputPuncher(root / ENTRY)

    def progress(done, total):
        case.observe(done, total)
        puncher.advance(done)

    try:
        case.r['error_code'] = expect_corrupt(
            lambda: archive.extract_archive(mutated, identities, root, progress=progress))
        case.after()
        case.late()
        case.r['output_bound'] = puncher.report()
        require(puncher.max_logical >= size - LATE_SLACK, 'engine did not write the late partial output')
        case.r['root_exists_before_harness_cleanup'] = root.exists()
        case.r['remaining_paths_before_harness_cleanup'] = len(list(root.rglob('*')))
        case.r['engine_removed_partial_contents'] = case.r['remaining_paths_before_harness_cleanup'] == 0
        require(case.r['engine_removed_partial_contents'], 'engine left partial content')
        case.r['status'] = 'passed'
    finally:
        shutil.rmtree(root, ignore_errors=True)
        case.r['harness_removed_owned_root'] = not root.exists()


def cancel_extract(original, identities, folder, size, monitor, guard, report):
    """Real job cancel in the restore's decrypt window; output really allocated (no punching)."""
    paths, store, job_id, ctx = job_context(folder, 'restore', {'backup_id': 'probe'}, 'decrypt')
    case = Case('cancel-extract', 'extract_archive', size, monitor, report)
    root = folder / 'cancel-extract'
    root.mkdir(mode=0o700)
    user = UserCancel(paths, job_id)
    user.start()
    threshold = size // 2 // archive.PROGRESS_STEP * archive.PROGRESS_STEP
    product = ctx.byte_progress('解密並驗證')  # flows.run_restore's label and callback for this phase
    target = root / ENTRY

    def progress(done, total):
        case.observe(done, total)
        if target.exists():
            st = target.stat()
            case.r['partial_file_bytes_observed'] = st.st_size
            case.r['partial_allocated_bytes_observed'] = st.st_blocks * 512
            case.r['free_bytes_with_partial_output'] = guard.free()
        if done >= threshold and not user.release.is_set():
            case.r['cancel_requested_at_bytes'] = done
            require(user.request(), 'job-cancel did not answer')
        product(done, total)

    try:
        free_before = guard.free()
        try:
            archive.extract_archive(original, identities, root, progress=progress, apps=[APP])
        except flows.Cancelled:
            case.r['exception'] = 'flows.Cancelled'
        else:
            raise RuntimeError('cancelled extraction unexpectedly succeeded')
        require(user.finish(), 'cancel thread did not finish')
        case.r.update(cancel_command_state=user.state, cancel_command_error=user.error,
                      cancel_request_recorded=store.cancel_requested(job_id),
                      cancellation_threshold_bytes=threshold)
        require(user.error is None and user.state == 'running', 'job-cancel did not accept the request')
        require(threshold <= case.r['max_progress_bytes'] < size, 'cancellation not mid-stream')
        case.after()
        case.r['root_exists_before_harness_cleanup'] = root.exists()
        case.r['remaining_paths_before_harness_cleanup'] = len(list(root.rglob('*')))
        case.r['engine_removed_partial_contents'] = case.r['remaining_paths_before_harness_cleanup'] == 0
        require(case.r.get('partial_allocated_bytes_observed', 0) >= threshold - 2 * archive.PROGRESS_STEP,
                'partial output was not really allocated')
        require(case.r['engine_removed_partial_contents'], 'engine left partial content')
        case.r['free_bytes_after_engine_cleanup'] = guard.free()
        # Sampled free space, not an exact accounting (other host writers continue).
        case.r['space_returned_bytes_sampled'] = (case.r['free_bytes_after_engine_cleanup']
                                                  - case.r['free_bytes_with_partial_output'])
        case.r['free_bytes_before_case'] = free_before
        case.r['status'] = 'passed'
    finally:
        user.finish()
        shutil.rmtree(root, ignore_errors=True)
        case.r['harness_removed_owned_root'] = not root.exists()


def cancel_write(folder, entry_sha256, mib, key, monitor, report):
    """Real job cancel in a backup's package window while write_archive streams the window source."""
    size = mib * MIB
    paths, store, job_id, ctx = job_context(folder, 'backup', {'apps': [APP], 'encrypt': True}, 'package')
    case = Case('cancel-write', 'write_archive', size, monitor, report)
    staging = folder / 'staging-cancel'
    staging.mkdir(mode=0o700)
    dest = staging / 'cancelled.tar'
    source = window.WindowSource(folder / 'source-cancel.bin', mib, window.compressible_block)
    user = UserCancel(paths, job_id)
    user.start()
    threshold = size // 2 // archive.PROGRESS_STEP * archive.PROGRESS_STEP
    product = ctx.byte_progress('加密封裝')  # flows._package's label for an encrypted backup

    def progress(done, total):
        case.observe(done, total)
        source.advance(done)
        names = [p.name for p in staging.iterdir()]
        case.r['staged_temp_archives_observed'] = max(case.r.get('staged_temp_archives_observed', 0),
                                                      sum(n.endswith('.tar.tmp') for n in names))
        case.r['staged_recipient_files_observed'] = max(case.r.get('staged_recipient_files_observed', 0),
                                                        sum(n.startswith('.recipient-') for n in names))
        if done >= threshold and not user.release.is_set():
            case.r['cancel_requested_at_bytes'] = done
            require(user.request(), 'job-cancel did not answer')
        product(done, total)

    try:
        try:
            archive.write_archive(dest, None, manifest_for(key.key_id),
                                  [archive.Entry(ENTRY, source.path, size, entry_sha256)], key.recipient,
                                  tmp_dir=staging, progress=progress)
        except flows.Cancelled:
            case.r['exception'] = 'flows.Cancelled'
        else:
            raise RuntimeError('cancelled write unexpectedly succeeded')
        require(user.finish(), 'cancel thread did not finish')
        case.r.update(cancel_command_state=user.state, cancel_command_error=user.error,
                      cancel_request_recorded=store.cancel_requested(job_id),
                      cancellation_threshold_bytes=threshold)
        require(user.error is None and user.state == 'running', 'job-cancel did not accept the request')
        require(threshold <= case.r['max_progress_bytes'] < size, 'cancellation not mid-stream')
        case.after()
        require(case.r.get('staged_temp_archives_observed') == 1, 'staged temp archive not observed while writing')
        require(case.r.get('staged_recipient_files_observed') == 1, 'recipient file not observed while writing')
        left = sorted(p.name for p in staging.iterdir())
        case.r['staging_entries_after_cancel'] = len(left)
        case.r['destination_created'] = dest.exists()
        require(not left and not dest.exists(), 'cancelled write left staged files')
        case.r['source_window'] = source.report()
        case.r['status'] = 'passed'
    finally:
        user.finish()
        source.close()
        Path(source.path).unlink(missing_ok=True)
        case.r['harness_removed_window_source'] = not Path(source.path).exists()
        shutil.rmtree(staging, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mib', type=int, default=8193)
    parser.add_argument('--scratch-parent', type=Path, default=Path('/tmp'))
    args = parser.parse_args()
    if not 128 <= args.mib <= 8193:
        parser.error('mib must be 128..8193; default 8193 is the actual >8GiB run')
    size = args.mib * MIB
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (size + MARGIN, size + MARGIN))
    if hasattr(os, 'sched_getaffinity'):
        os.sched_setaffinity(0, sorted(os.sched_getaffinity(0))[:2])
    started = time.monotonic()
    report = dict(schema=1, status='running', payload_bytes=size, over_8gib_payload=size > 8 * GIB,
                  payload_method='unique-shake256-4KiB-tile-per-MiB (compressible)', fixture_generations=0,
                  encryption='age-x25519', compression='zstd', reserve_bytes=RESERVE, guard_margin_bytes=MARGIN,
                  archive_cap_bytes=CAP, deadline_seconds=DEADLINE, planned_peak_storage_bytes=storage_budget(size),
                  required_free_bytes=RESERVE + MARGIN + storage_budget(size), service_restore=False,
                  hermes_attempts=0, commercial_acceptance='not-complete', cases={})
    try:
        with tempfile.TemporaryDirectory(prefix='woow-large-negatives-', dir=args.scratch_parent) as tmp:
            folder = Path(tmp)
            guard = SpaceGuard([folder], RESERVE + MARGIN)
            report['free_before'] = guard.free()
            require(report['free_before'] is not None, 'cannot measure free space')
            guard.check(storage_budget(size))
            report['minimum_free_observed'] = report['free_before']

            def monitor(*_):
                free = guard.free()
                require(free is not None, 'lost free space measurement')
                report['minimum_free_observed'] = min(report['minimum_free_observed'], free)
                guard.check()
                require(time.monotonic() - started < DEADLINE, 'deadline exceeded')

            def interrupted(*_):
                raise RuntimeError('interrupted')

            for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGXFSZ):
                signal.signal(signum, interrupted)
            signal.signal(signal.SIGALRM, monitor)
            signal.setitimer(signal.ITIMER_REAL, .25, .25)
            try:
                report['dependencies'] = common.encryption_dependencies()
                keys = KeyStore(Paths(base=folder / 'ephemeral-key'))
                key, _ = keys.ensure_device_key()
                require(key.path.is_relative_to(folder), 'identity outside scratch')
                require(key.path.stat().st_mode & 0o777 == 0o600, 'identity mode unsafe')
                require(key.path.parent.stat().st_mode & 0o777 == 0o700, 'identity directory unsafe')
                identities = keys.identities()
                report['ephemeral_key'] = dict(created=True, identity_mode='0600', directory_mode='0700',
                                               secret_logged=False)
                mark = time.monotonic()
                entry_sha256 = window.keystream_sha256(args.mib, window.compressible_block, monitor)
                report['keystream_sha256'] = entry_sha256
                report['keystream_hash_seconds'] = round(time.monotonic() - mark, 3)

                # Fixture: the real writer reads the window source; its sha256 check covers every byte read.
                staging = folder / 'staging'
                staging.mkdir(mode=0o700)
                original = folder / 'original.tar'
                source = window.WindowSource(folder / 'source.bin', args.mib, window.compressible_block)
                write = Case('fixture-write', 'write_archive', size, monitor, report)

                def write_progress(done, total):
                    write.observe(done, total)
                    source.advance(done)
                    # The window source is written by this process too, so RLIMIT_FSIZE cannot cap the archive here:
                    # a sampled cap on the staged temp archive replaces it (the free-space floor stays enforced).
                    staged = [p.stat().st_size for p in staging.glob('*.tar.tmp')]
                    require(all(s <= CAP for s in staged), 'staged archive exceeded cap')

                try:
                    written = archive.write_archive(original, None, manifest_for(key.key_id),
                                                    [archive.Entry(ENTRY, source.path, size, entry_sha256)],
                                                    key.recipient, tmp_dir=staging, progress=write_progress)
                    write.after()
                    write.r['source_window'] = source.report()
                    write.r['engine_sha256_check_of_every_read_byte'] = 'passed'
                finally:
                    source.close()
                    Path(source.path).unlink(missing_ok=True)
                write.r['harness_removed_window_source'] = not Path(source.path).exists()
                write.r['staging_entries_after_write'] = len(list(staging.iterdir()))
                require(write.r['staging_entries_after_write'] == 0, 'writer left temp or recipient files')
                write.r['status'] = 'passed'
                report['fixture_generations'] = 1
                require(original.stat().st_size <= CAP, 'archive cap exceeded')
                require(util.sha256_file(original) == written['sha256'], 'fixture hash mismatch')
                report['archive_bytes'], report['archive_sha256'] = written['size'], written['sha256']
                report['ciphertext_bytes'] = written['apps'][0]['size']

                control_verify(original, identities, size, monitor, report)
                mutated = folder / 'mutated.tar'
                for kind in ('flip-last-byte', 'truncate-last-byte'):
                    resource.setrlimit(resource.RLIMIT_FSIZE, (CAP, size + MARGIN))
                    mutation = failures.make_negative(original, mutated, kind)
                    resource.setrlimit(resource.RLIMIT_FSIZE, (size + MARGIN, size + MARGIN))
                    archive.read_manifest(mutated, identities)  # authenticated prefix accepted
                    mutation['authenticated_manifest_prefix_accepted'] = True
                    report.setdefault('mutations', {})[kind] = mutation
                    tail_verify(f'{kind}-verify', mutated, identities, size, monitor, report)
                    if kind == 'truncate-last-byte':
                        tail_extract(f'{kind}-extract', mutated, identities, folder / 'truncate-extract', size,
                                     monitor, report)
                    mutated.unlink()
                guard.check(size // 2 + 64 * MIB)
                cancel_extract(original, identities, folder, size, monitor, guard, report)
                cancel_write(folder, entry_sha256, args.mib, key, monitor, report)
                require(util.sha256_file(original) == written['sha256'], 'original fixture changed')
                report['original_fixture_unchanged'] = True
                report['identity_copies_in_scratch'] = secret_copies(folder, key.path)
                require(report['identity_copies_in_scratch'] == 0, 'identity material copied into scratch')
                monitor()
                report['status'] = 'passed'
            finally:
                signal.setitimer(signal.ITIMER_REAL, 0)
        report['harness_removed_private_scratch_and_key'] = not folder.exists()
    except Exception as exc:
        report.update(status='failed', error='negative probe failed (details suppressed)', error_type=type(exc).__name__)
        if isinstance(exc, BackupError):
            report['error_code'] = exc.code
        elif isinstance(exc, RuntimeError):
            report['harness_check'] = str(exc)[:120]
        if 'folder' in locals():
            report['harness_removed_private_scratch_and_key'] = not folder.exists()
    report['tool_children_at_end'] = len(tool_children())
    if report['tool_children_at_end']:
        report['status'] = 'failed'
    report['elapsed_seconds'] = round(time.monotonic() - started, 3)
    report['max_rss_kib'] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    report['minimum_reserve_preserved_in_samples'] = report.get('minimum_free_observed', 0) >= RESERVE
    report['free_after_cleanup'] = SpaceGuard([args.scratch_parent], RESERVE).free()
    print(json.dumps(report, indent=2, ensure_ascii=False), flush=True)
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__':
    sys.exit(main())
