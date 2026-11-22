#!/usr/bin/env python3
"""Opt-in, local-only native archive probe; no containers, services, or existing data.
Run from checkout: python3 tests/backup/bounded_large_archive.py --mib 2048
Payloads are deleted even on failure; JSON evidence is printed to stdout.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / 'backup-engine')]
from woowbackup import archive, util
from woowbackup.errors import BackupError
from woowbackup.haimport import SpaceGuard
from tests.backup.test_archive_v2 import small_inner

GIB = 1024 ** 3
RESERVE = 12 * GIB
MARGIN = 256 * 1024 ** 2


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def header_probe(folder):
    results = []
    # Only actual headers are written: no sparse holes and no advertised payload.
    for size in (8 * GIB - 1, 8 * GIB, 8 * GIB + 1):
        path = folder / 'header.bin'
        raw = archive._outer_header('payload.bin', size, 0)
        path.write_bytes(raw)
        with path.open('rb') as src:
            reader = archive._FileReader(src.fileno(), len(raw))
            require(archive._next_member(reader) == ('payload.bin', size), 'PAX size mismatch')
            try:
                next(reader.chunks(size))
            except archive._Truncated:
                truncated = True
            else:
                raise RuntimeError('missing payload accepted')
        results.append(dict(declared_bytes=size, actual_header_bytes=len(raw),
                            parser_size_supported=True, missing_payload_rejected=truncated))
    # Public format detection requires backup.json itself first, not a leading PAX record.
    path.write_bytes(archive._outer_header('backup.json', 8 * GIB + 1, 0))
    try:
        archive.read_header(path)
    except BackupError as exc:
        require(exc.code == 'not-a-backup', 'wrong leading PAX error')
        results.append(dict(case='oversized backup.json', actual_header_bytes=path.stat().st_size,
                            error=exc.as_dict()))
    else:
        raise RuntimeError('oversized metadata accepted')
    path.write_bytes(archive._outer_header('backup.json', archive.MAX_BACKUP_JSON + 1, 0))
    try:
        archive.read_header(path)
    except BackupError as exc:
        require(exc.code == 'limit-exceeded', 'metadata limit changed')
        results.append(dict(case='metadata limit', actual_header_bytes=path.stat().st_size,
                            error=exc.as_dict()))
    else:
        raise RuntimeError('metadata limit bypassed')
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mib', type=int, default=2048, choices=range(1, 2049), metavar='1..2048')
    parser.add_argument('--scratch-parent', type=Path, default=Path('/tmp'))
    args = parser.parse_args()
    size = args.mib * 1024 ** 2
    os.umask(0o077)
    # Bound CPU concurrency and any individual file, without changing engine defaults.
    if hasattr(os, 'sched_getaffinity'):
        os.sched_setaffinity(0, sorted(os.sched_getaffinity(0))[:2])
    resource.setrlimit(resource.RLIMIT_FSIZE, (size + MARGIN, size + MARGIN))
    started = time.monotonic()
    report = dict(schema=1, status='running', payload_bytes=size, reserve_bytes=RESERVE,
                  sparse=False, encryption='none', compression='gzip', service_restore=False,
                  hermes_attempts=0, headers_only_over_8gib=True, phases={})
    try:
        with tempfile.TemporaryDirectory(prefix='woow-large-probe-', dir=args.scratch_parent) as tmp:
            folder = Path(tmp)
            guard = SpaceGuard([folder], RESERVE + MARGIN)
            report['free_before'] = guard.free()
            require(report['free_before'] is not None, 'cannot measure free space')
            # Source + worst-case compressed archive + extracted payload, plus overhead.
            guard.check(3 * size + 2 * MARGIN)
            report['minimum_free_observed'] = report['free_before']

            def monitor(*_):
                free = guard.free()
                require(free is not None, 'lost free space measurement')
                report['minimum_free_observed'] = min(report['minimum_free_observed'], free)
                guard.check()
                require(time.monotonic() - started < 1200, '20 minute deadline exceeded')

            def interrupted(signum, frame):
                raise RuntimeError(f'interrupted by signal {signum}')

            signal.signal(signal.SIGTERM, interrupted)
            signal.signal(signal.SIGINT, interrupted)
            signal.signal(signal.SIGALRM, monitor)
            signal.setitimer(signal.ITIMER_REAL, 0.25, 0.25)
            try:
                report['header_probes'] = header_probe(folder)
                source = folder / 'source.bin'
                digest = hashlib.sha256()
                mark = time.monotonic()
                with source.open('xb') as out:
                    for _ in range(args.mib):
                        guard.check(1024 ** 2)
                        block = os.urandom(1024 ** 2)
                        out.write(block)
                        digest.update(block)
                    out.flush()
                    os.fsync(out.fileno())
                report['phases']['generate_seconds'] = time.monotonic() - mark
                report['source_allocated_bytes'] = source.stat().st_blocks * 512
                report['source_sha256'] = digest.hexdigest()
                require(source.stat().st_size == size, 'source size mismatch')
                require(source.stat().st_blocks * 512 >= size, 'source appears sparse')
                entry_path = 'apps/large-probe/config/payload.bin'
                inner = small_inner('large-probe', None, {entry_path: b''}, encryption='none')
                manifest = {k: v for k, v in inner.items() if k not in ('app', 'backup_apps')}
                manifest['apps'] = [inner['app']]
                entries = [archive.Entry(entry_path, source, size, digest.hexdigest())]
                dest = folder / 'probe.tar'
                def progress(done, total):
                    monitor()
                mark = time.monotonic()
                written = archive.write_archive(dest, None, manifest, entries, None,
                                                tmp_dir=folder, progress=progress)
                report['phases']['write_seconds'] = time.monotonic() - mark
                report['archive_bytes'] = dest.stat().st_size
                report['archive_allocated_bytes'] = dest.stat().st_blocks * 512
                report['archive_sha256'] = written['sha256']
                require(util.sha256_file(dest) == written['sha256'], 'archive hash mismatch')
                limits = archive.Limits(reserve_bytes=RESERVE + MARGIN)
                mark = time.monotonic()
                verified = archive.verify_archive(dest, [], limits=limits, progress=progress)
                require(verified['bytes'] == size and verified['entries'] == 1, 'verify counts mismatch')
                report['verified_bytes'] = verified['bytes']
                report['phases']['verify_seconds'] = time.monotonic() - mark
                extracted = folder / 'extracted'
                extracted.mkdir(mode=0o700)
                mark = time.monotonic()
                archive.extract_archive(dest, [], extracted, limits=limits, progress=progress)
                target = extracted / entry_path
                report['extracted_sha256'] = util.sha256_file(target)
                report['extracted_bytes'] = target.stat().st_size
                require(target.stat().st_size == size and report['extracted_sha256'] == digest.hexdigest(),
                        'extracted payload mismatch')
                report['phases']['extract_hash_seconds'] = time.monotonic() - mark
                monitor()
                report['status'] = 'passed'
            finally:
                signal.setitimer(signal.ITIMER_REAL, 0)
        report['temporary_payloads_removed'] = not folder.exists()
    except Exception as exc:
        report.update(status='failed', error=str(exc), error_type=type(exc).__name__)
        if 'folder' in locals():
            report['temporary_payloads_removed'] = not folder.exists()
    report['elapsed_seconds'] = time.monotonic() - started
    report['max_rss_kib'] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    report['free_after_cleanup'] = SpaceGuard([args.scratch_parent], RESERVE).free()
    print(json.dumps(report, indent=2, ensure_ascii=False), flush=True)
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__':
    sys.exit(main())
