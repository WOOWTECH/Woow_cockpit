#!/usr/bin/env python3
"""Opt-in, local-only native archive probe; no containers, services, or existing data.
Run from checkout: python3 tests/backup/bounded_large_archive.py --mib 2048
Actual >8GiB: add --profile compressible-sequential (defaults to 8193 MiB).
Payloads are deleted even on failure; JSON evidence is printed to stdout.
"""
import argparse
import subprocess
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import sys
import tempfile
import tarfile
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / 'backup-engine')]
from woowbackup import archive, util
from woowbackup.errors import BackupError
from woowbackup.haimport import SpaceGuard
from woowbackup.keys import KeyStore
from woowbackup.paths import Paths
from tests.backup.test_archive import tool_children
from tests.backup.test_archive_v2 import small_inner

GIB = 1024 ** 3
RESERVE = 12 * GIB
MARGIN = 256 * 1024 ** 2
ARCHIVE_CAP = 256 * 1024 ** 2


def storage_budget(size, sequential):
    return size + ARCHIVE_CAP + MARGIN if sequential else 3 * size + 2 * MARGIN


def payload_block(index, sequential):
    # 4096 unique deterministic bytes per MiB, physically written 256 times.
    # Each block differs; this is compressible real data, never holes or truncate.
    if sequential:
        return hashlib.shake_256(f"woow-large-v1:{index}".encode()).digest(4096) * 256
    return os.urandom(1024 ** 2)


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


def encryption_dependencies():
    age, zstd = archive._tools()
    keygen = util.find_tool('age-keygen')
    require(keygen is not None, 'missing age-keygen dependency')
    versions = {}
    for name, executable in [('age', age), ('age-keygen', keygen), ('zstd', zstd)]:
        result = subprocess.run([executable, '--version'], capture_output=True, text=True,
                                timeout=10, env=util.clean_env())
        require(result.returncode == 0, 'dependency version check failed')
        versions[name] = (result.stdout + result.stderr).strip()
    return versions


def encrypted_header_view(dest, identities, entry_path, size):
    # tarfile independently parses the actual decrypted tar headers; only this
    # diagnostic pass stops early. verify/extract still consume/authenticate EOF.
    fd = archive._open_archive(dest)
    try:
        layout = archive._scan_layout(fd)
        usable = archive._usable_identities(identities, layout.doc['key_id'])
        src = archive._open_inner(fd, layout, layout.members[0], usable)
        try:
            with tarfile.open(fileobj=src, mode='r|') as inner:
                require(inner.next().name == 'manifest.json', 'missing encrypted manifest')
                member = inner.next()
                require(member.name == entry_path and member.size == size, 'encrypted inner size mismatch')
                return dict(size=member.size, pax=member.pax_headers)
        finally:
            src.close()
    finally:
        os.close(fd)


def rejected_identity(dest, identities, expected):
    try:
        archive.read_manifest(dest, identities)
    except BackupError as exc:
        require(exc.code == expected, 'unexpected key rejection code')
        return exc.code
    raise RuntimeError('invalid identity unexpectedly accepted')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', choices=('random', 'compressible-sequential'), default='random')
    parser.add_argument('--mib', type=int, default=None)
    parser.add_argument('--encrypted', action='store_true', help='ephemeral age X25519 + zstd')

    parser.add_argument('--scratch-parent', type=Path, default=Path('/tmp'))
    args = parser.parse_args()
    sequential = args.profile == 'compressible-sequential'
    if args.mib is None:
        args.mib = 8193 if sequential else 2048
    if not 1 <= args.mib <= (8193 if sequential else 2048):
        parser.error('mib must be 1..8193 for compressible-sequential, otherwise 1..2048')
    size = args.mib * 1024 ** 2
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    # Bound CPU concurrency and any individual file, without changing engine defaults.
    if hasattr(os, 'sched_getaffinity'):
        os.sched_setaffinity(0, sorted(os.sched_getaffinity(0))[:2])
    resource.setrlimit(resource.RLIMIT_FSIZE, (size + MARGIN, size + MARGIN))
    started = time.monotonic()
    report = dict(schema=3, status='running', payload_bytes=size, reserve_bytes=RESERVE,
                  sparse=False, encryption='age-x25519' if args.encrypted else 'none',
                  compression='zstd' if args.encrypted else 'gzip', service_restore=False,
                  hermes_attempts=0, headers_only_over_8gib=size <= 8 * GIB, phases={},
                  profile=args.profile, archive_cap_bytes=ARCHIVE_CAP if sequential else size + MARGIN,
                  payload_method='unique-shake256-4KiB-tile-per-MiB' if sequential else 'os.urandom',
                  planned_peak_storage_bytes=storage_budget(size, sequential),
                  required_free_bytes=RESERVE + MARGIN + storage_budget(size, sequential))
    try:
        with tempfile.TemporaryDirectory(prefix='woow-large-probe-', dir=args.scratch_parent) as tmp:
            folder = Path(tmp)
            guard = SpaceGuard([folder], RESERVE + MARGIN)
            report['free_before'] = guard.free()
            require(report['free_before'] is not None, 'cannot measure free space')
            # Sequential: one payload + capped archive; random: three copies.
            # Include overhead in both cases; the guard floor includes extra margin.
            guard.check(storage_budget(size, sequential))
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
            signal.signal(signal.SIGXFSZ, interrupted)
            signal.signal(signal.SIGALRM, monitor)
            signal.setitimer(signal.ITIMER_REAL, 0.25, 0.25)
            try:
                identities, recipient, key_id = [], None, None
                if args.encrypted:
                    report['encryption_dependencies'] = encryption_dependencies()
                    keys = KeyStore(Paths(base=folder / 'ephemeral-key'))
                    key, _ = keys.ensure_device_key()
                    identities, recipient, key_id = keys.identities(), key.recipient, key.key_id
                    require(key.path.is_relative_to(folder), 'key outside private scratch')
                    require(key.path.stat().st_mode & 0o777 == 0o600, 'identity permissions unsafe')
                    require(key.path.parent.stat().st_mode & 0o777 == 0o700, 'key directory permissions unsafe')
                    report['ephemeral_key'] = dict(created=True, identity_mode='0600', directory_mode='0700',
                                                   secret_logged=False)
                report['header_probes'] = header_probe(folder)
                source = folder / 'source.bin'
                digest = hashlib.sha256()
                mark = time.monotonic()
                with source.open('xb') as out:
                    for index in range(args.mib):
                        guard.check(1024 ** 2)
                        block = payload_block(index, sequential)
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
                inner = small_inner('large-probe', key_id, {entry_path: b''}, encryption=report['encryption'])
                manifest = {k: v for k, v in inner.items() if k not in ('app', 'backup_apps')}
                manifest['apps'] = [inner['app']]
                entries = [archive.Entry(entry_path, source, size, digest.hexdigest())]
                dest = folder / 'probe.tar'
                def progress(done, total):
                    monitor()
                mark = time.monotonic()
                if sequential:
                    resource.setrlimit(resource.RLIMIT_FSIZE, (ARCHIVE_CAP, size + MARGIN))
                written = archive.write_archive(dest, None, manifest, entries, recipient,
                                                tmp_dir=folder, progress=progress)
                report['phases']['write_seconds'] = time.monotonic() - mark
                if sequential:
                    require(dest.stat().st_size <= ARCHIVE_CAP, 'archive exceeded cap')
                    resource.setrlimit(resource.RLIMIT_FSIZE, (size + MARGIN, size + MARGIN))
                report['archive_bytes'] = dest.stat().st_size
                report['archive_allocated_bytes'] = dest.stat().st_blocks * 512
                report['archive_sha256'] = written['sha256']
                require(util.sha256_file(dest) == written['sha256'], 'archive hash mismatch')
                limits = archive.Limits(reserve_bytes=RESERVE + MARGIN)
                mark = time.monotonic()
                verified = archive.verify_archive(dest, identities, limits=limits, progress=progress)
                require(verified['bytes'] == size and verified['entries'] == 1, 'verify counts mismatch')
                report['verified_bytes'] = verified['bytes']
                report['phases']['verify_seconds'] = time.monotonic() - mark
                if args.encrypted:
                    report['key_rejections'] = {'missing': rejected_identity(dest, [], 'key-required')}
                    wrong_keys = KeyStore(Paths(base=folder / 'wrong-ephemeral-key'))
                    wrong_keys.ensure_device_key()
                    report['key_rejections']['wrong'] = rejected_identity(dest, wrong_keys.identities(), 'wrong-key')
                    report['actual_inner_member'] = encrypted_header_view(dest, identities, entry_path, size)
                else:
                    # Independent header view of the actual generated archive, not a fabricated fixture.
                    with tarfile.open(dest, 'r:') as outer:
                        with outer.extractfile(written['apps'][0]['file']) as packed:
                            with tarfile.open(fileobj=packed, mode='r|gz') as inner_tar:
                                require(inner_tar.next().name == 'manifest.json', 'missing inner manifest')
                                member = inner_tar.next()
                                require(member.name == entry_path and member.size == size, 'inner size mismatch')
                                report['actual_inner_member'] = dict(size=member.size, pax=member.pax_headers)
                if sequential:
                    # Only our freshly generated input is removed, after archive integrity passes.
                    source.unlink()
                    report['source_removed_before_extract'] = not source.exists()
                    guard.check(size + MARGIN)

                extracted = folder / 'extracted'
                extracted.mkdir(mode=0o700)
                mark = time.monotonic()
                archive.extract_archive(dest, identities, extracted, limits=limits, progress=progress)
                target = extracted / entry_path
                report['extracted_sha256'] = util.sha256_file(target)
                report['extracted_bytes'] = target.stat().st_size
                report['extracted_allocated_bytes'] = target.stat().st_blocks * 512
                require(target.stat().st_blocks * 512 >= size, 'extracted payload appears sparse')
                require(target.stat().st_size == size and report['extracted_sha256'] == digest.hexdigest(),
                        'extracted payload mismatch')
                report['phases']['extract_hash_seconds'] = time.monotonic() - mark
                monitor()
                report['status'] = 'passed'
            finally:
                signal.setitimer(signal.ITIMER_REAL, 0)
        report['temporary_payloads_removed'] = not folder.exists()
    except Exception as exc:
        report.update(status='failed', error='encrypted probe failed (details suppressed)' if args.encrypted else str(exc),
                      error_type=type(exc).__name__)
        if isinstance(exc, BackupError):
            report['error_code'] = exc.code
        if 'folder' in locals():
            report['temporary_payloads_removed'] = not folder.exists()
    if args.encrypted:
        report['ephemeral_keys_removed'] = report.get('temporary_payloads_removed', False)
        report['tool_children_remaining'] = len(tool_children())
        if report['tool_children_remaining']:
            report.update(status='failed', error='encryption tool children remain')
    report['elapsed_seconds'] = time.monotonic() - started
    report['max_rss_kib'] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    report['free_after_cleanup'] = SpaceGuard([args.scratch_parent], RESERVE).free()
    print(json.dumps(report, indent=2, ensure_ascii=False), flush=True)
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__':
    sys.exit(main())
