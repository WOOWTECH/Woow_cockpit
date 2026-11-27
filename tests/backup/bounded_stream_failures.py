#!/usr/bin/env python3
"""Opt-in real encrypted stream negatives. One new fixture, no successful roundtrip.
python3 tests/backup/bounded_stream_failures.py [--mib 2048]
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import resource
import shutil
import signal
import sys
import tarfile
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / 'backup-engine')]
from tests.backup import bounded_large_archive as common
from tests.backup.test_archive import tool_children
from tests.backup.test_archive_v2 import small_inner
from woowbackup import archive, util
from woowbackup.errors import BackupError
from woowbackup.haimport import SpaceGuard
from woowbackup.keys import KeyStore
from woowbackup.paths import Paths

MIB = 1024 ** 2
RESERVE, MARGIN, CAP = common.RESERVE, common.MARGIN, common.ARCHIVE_CAP
require = common.require


class ProbeCancelled(Exception):
    """Cooperative caller cancellation, not a product error code."""


class CipherSlice:
    """Bounded actual ciphertext reads; never synthesize payload or sparse holes."""
    def __init__(self, fd, offset, size, flip_last=False):
        self.fd, self.offset, self.size = fd, offset, size
        self.pos, self.flip_last = 0, flip_last

    def read(self, size):
        count = min(size, self.size - self.pos, MIB)
        if count <= 0:
            return b''
        data = os.pread(self.fd, count, self.offset + self.pos)
        require(len(data) == count, 'fixture ciphertext unexpectedly short')
        self.pos += count
        if self.flip_last and self.pos == self.size:
            data = data[:-1] + bytes([data[-1] ^ 1])
        return data


def make_negative(source, target, kind):
    """Rewrap actual mutated ciphertext with matching untrusted outer metadata.
    Thus public consumers reach age tail authentication rather than outer EOF/hash checks.
    """
    fd = archive._open_archive(source)
    try:
        layout = archive._scan_layout(fd)
        member = layout.members[0]
        size = member.size - (1 if kind == 'truncate-last-byte' else 0)
        require(size > 65536, 'ciphertext too short for meaningful late-tail test')
        digest = hashlib.sha256()
        reader = CipherSlice(fd, member.offset, size, kind == 'flip-last-byte')
        while data := reader.read(MIB):
            digest.update(data)
        doc = json.loads(json.dumps(layout.doc))
        doc['apps'][0].update(size=size, sha256=digest.hexdigest())
        with tarfile.open(target, 'w|', format=tarfile.PAX_FORMAT, bufsize=MIB, copybufsize=MIB) as out:
            for name, data in [('backup.json', json.dumps(doc).encode()), ('README.txt', layout.readme.encode())]:
                out.addfile(archive._tarinfo(name, len(data), 0), io.BytesIO(data))
            out.addfile(archive._tarinfo(member.name, size, 0),
                        CipherSlice(fd, member.offset, size, kind == 'flip-last-byte'))
        require(target.stat().st_size <= CAP, 'mutated archive exceeded cap')
        # This authenticates neither the ciphertext nor inner content: outer consistency only.
        archive.describe(target, check_members=True)
        return dict(kind=kind, original_ciphertext_bytes=member.size, mutated_ciphertext_bytes=size,
                    bytes_changed=1, mutation_at_original_ciphertext_offset=member.size - 1,
                    outer_metadata_recomputed=True, outer_member_checksum_passed=True,
                    actual_archive_bytes=target.stat().st_size)
    finally:
        os.close(fd)


def run_case(path, identities, root, entry_path, size, mode, monitor, result=None):
    result = {} if result is None else result
    result.update(consumer='extract_archive' if mode != 'corrupt-verify' else 'verify_archive',
                  max_progress_bytes=0, active_tool_children_observed=0)
    extracting = mode != 'corrupt-verify'
    if extracting:
        root.mkdir(mode=0o700)
    cancelled = ProbeCancelled('intentional cooperative cancellation')
    threshold = (size // 2 // archive.PROGRESS_STEP) * archive.PROGRESS_STEP
    limits = archive.Limits(reserve_bytes=RESERVE + MARGIN)
    mark = time.monotonic()

    def progress(done, total):
        monitor()
        require(total == size, 'unexpected progress total')
        result['max_progress_bytes'] = max(result['max_progress_bytes'], done)
        if not result['active_tool_children_observed']:
            result['active_tool_children_observed'] = len(tool_children())
        if extracting:
            target = root / entry_path
            if target.exists():
                result['partial_file_bytes_observed'] = target.stat().st_size
                result['partial_allocated_bytes_observed'] = target.stat().st_blocks * 512
        if mode == 'cancel-extract' and done >= threshold:
            result['cancel_requested_at_bytes'] = done
            raise cancelled

    try:
        try:
            if extracting:
                archive.extract_archive(path, identities, root, limits=limits, progress=progress)
            else:
                archive.verify_archive(path, identities, limits=limits, progress=progress)
        except (BackupError, ProbeCancelled) as exc:
            result['failure_propagated'] = True
            result['exception_type'] = type(exc).__name__
            if mode == 'cancel-extract':
                require(exc is cancelled, 'cancellation did not propagate unchanged')
                result['same_cancellation_instance'] = True
                result['cancellation_threshold_bytes'] = threshold
                require(threshold <= result['max_progress_bytes'] < size, 'cancellation not mid-stream')
            else:
                require(isinstance(exc, BackupError) and exc.code == 'corrupt-archive', 'unexpected tail error')
                result['error_code'] = exc.code
                result['late_failure_minimum_bytes'] = max(8 * MIB, size - 64 * MIB)
                require(result['max_progress_bytes'] >= result['late_failure_minimum_bytes'],
                        'failure occurred too early to count as late-tail')
        else:
            raise RuntimeError('negative unexpectedly succeeded')
        result['tool_children_after_consumer'] = len(tool_children())
        require(result['tool_children_after_consumer'] == 0, 'consumer left tool children')
        if extracting:
            # Observe before ANY harness cleanup. Product owns partial contents;
            # caller owns the root directory and final removal.
            result['root_exists_before_harness_cleanup'] = root.exists()
            result['remaining_paths_before_harness_cleanup'] = len(list(root.rglob('*')))
            result['engine_removed_partial_contents'] = result['remaining_paths_before_harness_cleanup'] == 0
            require(result.get('partial_file_bytes_observed', 0) > 0, 'no actual partial output observed')
            require(result['engine_removed_partial_contents'], 'engine left partial content')
        result['status'] = 'passed'
        return result
    finally:
        if extracting:
            shutil.rmtree(root)
            result['harness_removed_owned_root'] = not root.exists()
        result['elapsed_seconds'] = time.monotonic() - mark


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mib', type=int, default=2048)
    parser.add_argument('--scratch-parent', type=Path, default=Path('/tmp'))
    args = parser.parse_args()
    if not 128 <= args.mib <= 2048:
        parser.error('mib must be 128..2048; default 2048 is the actual multiGiB run')
    size = args.mib * MIB
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (size + MARGIN, size + MARGIN))
    if hasattr(os, 'sched_getaffinity'):
        os.sched_setaffinity(0, sorted(os.sched_getaffinity(0))[:2])
    started = time.monotonic()
    report = dict(schema=1, status='running', payload_bytes=size, fixture_generations=0,
                  full_success_roundtrips=0, sparse=False, encryption='age-x25519', compression='zstd',
                  reserve_bytes=RESERVE, archive_cap_bytes=CAP, deadline_seconds=1200,
                  required_free_bytes=RESERVE + MARGIN + size + 2 * CAP + MARGIN,
                  service_restore=False, hermes_attempts=0, cases={})
    try:
        with tempfile.TemporaryDirectory(prefix='woow-stream-failures-', dir=args.scratch_parent) as tmp:
            folder = Path(tmp)
            guard = SpaceGuard([folder], RESERVE + MARGIN)
            report['free_before'] = guard.free()
            require(report['free_before'] is not None, 'cannot measure free space')
            guard.check(size + 2 * CAP + MARGIN)
            report['minimum_free_observed'] = report['free_before']

            def monitor(*_):
                free = guard.free()
                require(free is not None, 'lost free space measurement')
                report['minimum_free_observed'] = min(report['minimum_free_observed'], free)
                guard.check()
                require(time.monotonic() - started < 1200, 'deadline exceeded')

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
                source = folder / 'source.bin'
                digest = hashlib.sha256()
                with source.open('xb') as out:
                    for index in range(args.mib):
                        guard.check(MIB)
                        block = common.payload_block(index, True)
                        out.write(block)
                        digest.update(block)
                    out.flush()
                    os.fsync(out.fileno())
                report['fixture_generations'] = 1
                report['source_sha256'] = digest.hexdigest()
                report['source_allocated_bytes'] = source.stat().st_blocks * 512
                require(source.stat().st_size == size and source.stat().st_blocks * 512 >= size, 'source sparse/short')
                entry_path = 'apps/large-probe/config/payload.bin'
                inner = small_inner('large-probe', key.key_id, {entry_path: b''}, encryption='age-x25519')
                manifest = {k: v for k, v in inner.items() if k not in ('app', 'backup_apps')}
                manifest['apps'] = [inner['app']]
                original = folder / 'original.tar'
                resource.setrlimit(resource.RLIMIT_FSIZE, (CAP, size + MARGIN))
                written = archive.write_archive(original, None, manifest,
                    [archive.Entry(entry_path, source, size, digest.hexdigest())], key.recipient,
                    tmp_dir=folder, progress=lambda *_: monitor())
                require(original.stat().st_size <= CAP, 'archive cap exceeded')
                require(util.sha256_file(original) == written['sha256'], 'fixture hash mismatch')
                report['archive_bytes'], report['archive_sha256'] = written['size'], written['sha256']
                # Writer has checked actual source bytes/hash; do not repeat a successful full verify.
                source.unlink()
                report['source_removed_before_negatives'] = not source.exists()
                resource.setrlimit(resource.RLIMIT_FSIZE, (size + MARGIN, size + MARGIN))
                for kind, mode in [('flip-last-byte', 'corrupt-verify'), ('truncate-last-byte', 'truncated-extract')]:
                    mutated = folder / 'mutated.tar'
                    resource.setrlimit(resource.RLIMIT_FSIZE, (CAP, size + MARGIN))
                    mutation = make_negative(original, mutated, kind)
                    resource.setrlimit(resource.RLIMIT_FSIZE, (size + MARGIN, size + MARGIN))
                    archive.read_manifest(mutated, identities)  # prefix works, no successful full pass
                    mutation['authenticated_manifest_prefix_accepted'] = True
                    guard.check(size + MARGIN)
                    report['cases'][kind] = dict(mutation=mutation)
                    run_case(mutated, identities, folder / mode, entry_path, size, mode, monitor,
                             report['cases'][kind])
                    mutated.unlink()
                guard.check(size + MARGIN)
                report['cases']['cancel-extract'] = {}
                run_case(original, identities, folder / 'cancel-extract', entry_path, size,
                         'cancel-extract', monitor, report['cases']['cancel-extract'])
                require(util.sha256_file(original) == written['sha256'], 'original fixture changed')
                report['original_fixture_unchanged'] = True
                monitor()
                report['status'] = 'passed'
            finally:
                signal.setitimer(signal.ITIMER_REAL, 0)
        report['harness_removed_private_scratch_and_key'] = not folder.exists()
    except Exception as exc:
        report.update(status='failed', error='negative probe failed (details suppressed)', error_type=type(exc).__name__)
        if isinstance(exc, BackupError):
            report['error_code'] = exc.code
        if 'folder' in locals():
            report['harness_removed_private_scratch_and_key'] = not folder.exists()
    report['tool_children_at_end'] = len(tool_children())
    if report['tool_children_at_end']:
        report['status'] = 'failed'
    report['elapsed_seconds'] = time.monotonic() - started
    report['minimum_reserve_preserved_in_samples'] = report.get('minimum_free_observed', 0) >= RESERVE
    report['free_after_cleanup'] = SpaceGuard([args.scratch_parent], RESERVE).free()
    print(json.dumps(report, indent=2), flush=True)
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__':
    sys.exit(main())
