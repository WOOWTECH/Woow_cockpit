#!/usr/bin/env python3
"""Opt-in: an INCOMPRESSIBLE encrypted archive whose outer tar member is above 8GiB, read by the real engine paths.
python3 tests/backup/bounded_incompressible_outer.py [--mib 8193] [--scratch-parent /tmp] [--plan-only]

The disk need is computed first (engine's own archive bound + window + 12GiB reserve + guard margin). Without enough
free space nothing is generated: the report states the exact shortfall and the exit code is 3.
Otherwise one deterministic SHAKE256 keystream (1MiB per index, incompressible) is streamed through the real age/zstd
writer by a sliding-window source (only the archive itself is ever fully on disk; the engine's sha256 check proves
every byte it read was the keystream). Then, without any second full copy:
  outer header   raw bytes of the ciphertext member's header slot: PAX 'size' record above 8GiB, ustar field 0
  inner header   tarfile parse of the decrypted inner tar head: PAX size of the >8GiB payload member
  stream hash    describe_fd(check_members=True, hasher): the engine reader hashes every byte of the file in order;
                 must equal the writer's sha256 and backup.json's member sha256
  verify         verify_archive: full decrypt/decompress/parse/hash of the >8GiB ciphertext
  keys           missing key -> key-required, wrong key -> wrong-key
  late tail      in place: flip the last ciphertext byte and rewrite backup.json's member sha256 (same length) so the
                 outer metadata is consistent; verify_archive must refuse corrupt-archive after >= payload-64MiB;
                 then both edits are reverted and the file sha256 must equal the original again
All generated files are deleted. No raw exception text, tool stderr, key contents or key identifiers are recorded.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import shutil
import signal
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / 'backup-engine')]
from tests.backup import bounded_large_archive as common
from tests.backup import bounded_large_negatives as negatives
from tests.backup import bounded_stream_window as window
from tests.backup.test_archive import tool_children
from woowbackup import archive, util
from woowbackup.errors import BackupError
from woowbackup.haimport import SpaceGuard
from woowbackup.keys import KeyStore
from woowbackup.paths import Paths

MIB = 1024 ** 2
GIB = 1024 ** 3
RESERVE, MARGIN = common.RESERVE, common.MARGIN
require = common.require
ENTRY, APP = negatives.ENTRY, negatives.APP
DEADLINE = 3600
WINDOW_PEAK = 64 * MIB + 16 * MIB + archive.PROGRESS_STEP + archive.CHUNK
LATE_SLACK = negatives.LATE_SLACK
EXIT_NO_SPACE = 3


def archive_bound(size):
    """The writer's own reservation logic (ArchiveWriter.add_app) for one entry, plus a generous outer allowance
    (backup.json/README/headers/trailer stay far below 1MiB)."""
    inner = archive._tar_bound(4096, [archive.Entry(ENTRY, Path('/unused'), size, '0' * 64)])
    inner += inner // 500 + archive.CHUNK
    return inner + MIB


def expected_archive_bytes(size):
    """Model of the real output for incompressible input: inner tar (PAX header for >8GiB), zstd raw blocks
    (3-byte header per 128KiB block), age STREAM (16-byte tag per 64KiB chunk, ~200-byte header, 16-byte nonce)."""
    tar = size + 4 * archive.BLOCK + 4096 + archive.RECORD
    zstd = tar + 3 * (tar // (128 * 1024) + 1) + 32
    age = zstd + 16 * (zstd // (64 * 1024) + 1) + 256
    return age + 8 * archive.BLOCK + archive.RECORD


def plan(size, free):
    need = archive_bound(size) + WINDOW_PEAK
    required = RESERVE + MARGIN + need
    return dict(archive_bound_bytes=archive_bound(size), expected_archive_bytes_model=expected_archive_bytes(size),
                window_peak_bytes=WINDOW_PEAK, planned_peak_storage_bytes=need, reserve_bytes=RESERVE,
                guard_margin_bytes=MARGIN, required_free_bytes=required, free_bytes_at_plan=free,
                shortfall_bytes=max(0, required - free) if free is not None else None,
                outer_over_8gib_expected=expected_archive_bytes(size) > 8 * GIB)


def _octal_field(field):
    return None if field[0] & 0x80 else int(field.split(b'\0')[0].strip() or b'0', 8)


def outer_member_header(path, member):
    """Raw header bytes in front of the member data. Above the ustar limit the writer's PAX slot must carry the
    size: PAX extended header ('x', ././@PaxHeader) + its 'size' record, then a ustar header whose size field is 0."""
    start = max(0, member.offset - archive.PAX_SLOT)
    with open(path, 'rb') as handle:
        handle.seek(start)
        raw = handle.read(member.offset - start)
    block = archive.BLOCK
    ustar = raw[-block:]
    ustar_size = _octal_field(ustar[124:136])
    pax_size = None
    if (len(raw) == archive.PAX_SLOT and raw[156:157] == b'x' and raw[257:263] == b'ustar\x00'
            and raw[:14] == b'././@PaxHeader'):
        pax_len = _octal_field(raw[124:136])
        records = raw[block:block + pax_len].decode('utf-8')
        sizes = [line.split('=', 1)[1] for line in records.splitlines() if ' size=' in line]
        require(len(sizes) == 1, 'outer PAX size record missing')
        pax_size = int(sizes[0])
    effective = pax_size if pax_size is not None else ustar_size
    require(effective == member.size, 'outer header size differs from the member')
    if member.size > archive.USTAR_SIZE_MAX:
        require(pax_size == member.size and ustar_size == 0, 'member above the ustar limit without PAX size')
    return dict(pax_header=pax_size is not None, pax_size_record=pax_size, ustar_size_field=ustar_size,
                effective_size=effective, ustar_size_limit=archive.USTAR_SIZE_MAX,
                size_above_ustar_limit=member.size > archive.USTAR_SIZE_MAX)


def json_slot(path):
    """(offset, raw bytes) of backup.json's fixed-size slot (the writer pads it with spaces)."""
    fd = archive._open_archive(path)
    try:
        reader = archive._FileReader(fd, os.fstat(fd).st_size)
        name, length = archive._next_member(reader)
        require(name == archive.BACKUP_JSON, 'backup.json is not first')
        offset = reader.pos
        return offset, os.pread(fd, length, offset)
    finally:
        os.close(fd)


def member_sha256(path, member, flip_last, check):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        handle.seek(member.offset)
        left = member.size
        while left:
            data = handle.read(min(left, 8 * MIB))
            require(data, 'archive ended early')
            left -= len(data)
            if flip_last and not left:
                data = data[:-1] + bytes([data[-1] ^ 1])
            digest.update(data)
            check()
    return digest.hexdigest()


def rewrite_member_sha(raw, sha256):
    doc = json.loads(raw)
    doc['apps'][0]['sha256'] = sha256
    data = json.dumps(doc, ensure_ascii=False, indent=2).encode('utf-8')
    require(len(data) + 1 <= len(raw), 'backup.json slot too small')
    return data + b' ' * (len(raw) - len(data) - 1) + b'\n'


def late_tail_in_place(path, identities, size, written, monitor, report):
    """Flip the last ciphertext byte in place (outer metadata made consistent), verify must refuse late, then revert
    both edits and prove the file is bit-identical to the original. No copy of the >8GiB file is made."""
    fd0 = archive._open_archive(path)
    try:
        member = archive._scan_layout(fd0).members[0]
    finally:
        os.close(fd0)
    case = negatives.Case('flip-last-byte-in-place-verify', 'verify_archive', size, monitor, report)
    json_offset, json_raw = json_slot(path)
    last = member.offset + member.size - 1
    fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
    flipped = rewritten = False
    try:
        original_byte = os.pread(fd, 1, last)
        mutated_sha = member_sha256(path, member, True, monitor)
        os.pwrite(fd, bytes([original_byte[0] ^ 1]), last)
        flipped = True
        os.pwrite(fd, rewrite_member_sha(json_raw, mutated_sha), json_offset)
        rewritten = True
        os.fsync(fd)
        archive.describe(path, check_members=True)  # outer size/sha now consistent: only age can object
        case.r['outer_member_checksum_passed'] = True
        case.r['mutation_at_ciphertext_offset'] = member.size - 1
        case.r['ciphertext_offset_over_8gib'] = member.size - 1 > 8 * GIB
        case.r['error_code'] = negatives.expect_corrupt(
            lambda: archive.verify_archive(path, identities, progress=case.observe))
        case.after()
        case.late()
        case.r['status'] = 'passed'
    finally:
        if flipped:
            os.pwrite(fd, original_byte, last)
        if rewritten:
            os.pwrite(fd, json_raw, json_offset)
        os.fsync(fd)
        os.close(fd)
    report['original_restored_bit_exact'] = util.sha256_file(path) == written['sha256']
    require(report['original_restored_bit_exact'], 'in-place edits were not reverted exactly')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mib', type=int, default=8193)
    parser.add_argument('--scratch-parent', type=Path, default=Path('/tmp'))
    parser.add_argument('--plan-only', action='store_true', help='compute the disk need; generate nothing')
    args = parser.parse_args()
    if not 128 <= args.mib <= 8193:
        parser.error('mib must be 128..8193; default 8193 is the actual >8GiB outer archive')
    size = args.mib * MIB
    started = time.monotonic()
    report = dict(schema=1, status='running', payload_bytes=size, payload_method='shake256-1MiB-per-index '
                  '(incompressible)', fixture_generations=0, encryption='age-x25519', compression='zstd',
                  deadline_seconds=DEADLINE, service_restore=False, hermes_attempts=0,
                  commercial_acceptance='not-complete', cases={})
    report.update(plan(size, SpaceGuard([args.scratch_parent], RESERVE).free()))
    if args.plan_only or report['shortfall_bytes'] != 0:
        # Nothing is generated: the report carries the exact need and shortfall.
        report['status'] = 'plan-only' if args.plan_only else 'insufficient-space'
        report['generated_bytes'] = 0
        report['elapsed_seconds'] = round(time.monotonic() - started, 3)
        print(json.dumps(report, indent=2, ensure_ascii=False), flush=True)
        return 0 if args.plan_only else EXIT_NO_SPACE
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    cap = report['archive_bound_bytes']
    resource.setrlimit(resource.RLIMIT_FSIZE, (cap, cap))
    if hasattr(os, 'sched_getaffinity'):
        os.sched_setaffinity(0, sorted(os.sched_getaffinity(0))[:2])
    try:
        with tempfile.TemporaryDirectory(prefix='woow-incompressible-outer-', dir=args.scratch_parent) as tmp:
            folder = Path(tmp)
            guard = SpaceGuard([folder], RESERVE + MARGIN)
            report['free_before'] = guard.free()
            guard.check(report['planned_peak_storage_bytes'])
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
                require(key.path.stat().st_mode & 0o777 == 0o600, 'identity mode unsafe')
                require(key.path.parent.stat().st_mode & 0o777 == 0o700, 'identity directory unsafe')
                identities = keys.identities()
                mark = time.monotonic()
                entry_sha256 = window.keystream_sha256(args.mib, window.incompressible_block, monitor)
                report['keystream_sha256'] = entry_sha256
                report['keystream_hash_seconds'] = round(time.monotonic() - mark, 3)
                staging = folder / 'staging'
                staging.mkdir(mode=0o700)
                original = folder / 'original.tar'
                source = window.WindowSource(folder / 'source.bin', args.mib, window.incompressible_block)
                write = negatives.Case('fixture-write', 'write_archive', size, monitor, report)

                def write_progress(done, total):
                    write.observe(done, total)
                    source.advance(done)

                try:
                    written = archive.write_archive(original, None, negatives.manifest_for(key.key_id),
                                                    [archive.Entry(ENTRY, source.path, size, entry_sha256)],
                                                    key.recipient, tmp_dir=staging, progress=write_progress)
                    write.after()
                    write.r['source_window'] = source.report()
                    write.r['engine_sha256_check_of_every_read_byte'] = 'passed'
                finally:
                    source.close()
                    Path(source.path).unlink(missing_ok=True)
                write.r['harness_removed_window_source'] = not Path(source.path).exists()
                require(not list(staging.iterdir()), 'writer left temp or recipient files')
                write.r['status'] = 'passed'
                report['fixture_generations'] = 1
                st = original.stat()
                report.update(archive_bytes=written['size'], archive_sha256=written['sha256'],
                              archive_allocated_bytes=st.st_blocks * 512, ciphertext_bytes=written['apps'][0]['size'],
                              archive_over_8gib=written['size'] > 8 * GIB,
                              ciphertext_over_ustar_limit=written['apps'][0]['size'] > archive.USTAR_SIZE_MAX,
                              compression_ratio=round(written['apps'][0]['size'] / size, 6))
                require(st.st_blocks * 512 >= written['size'] - MIB, 'archive appears sparse')
                require(written['size'] <= cap, 'archive above the computed bound')

                fd = archive._open_archive(original)
                try:
                    member = archive._scan_layout(fd).members[0]
                    mark = time.monotonic()
                    hasher = hashlib.sha256()
                    archive.describe_fd(fd, check_members=True, hasher=hasher)
                    report['stream_hash'] = dict(reader='archive.describe_fd(check_members=True, hasher)',
                                                 file_sha256_equals_writer=hasher.hexdigest() == written['sha256'],
                                                 member_sha256_checked_against_backup_json=True,
                                                 seconds=round(time.monotonic() - mark, 3))
                finally:
                    os.close(fd)
                require(report['stream_hash']['file_sha256_equals_writer'], 'streamed file hash mismatch')
                report['outer_member_header'] = outer_member_header(original, member)
                require(report['outer_member_header']['effective_size'] == written['apps'][0]['size'],
                        'outer header size mismatch')
                report['inner_member_header'] = common.encrypted_header_view(original, identities, ENTRY, size)
                verify = negatives.Case('verify', 'verify_archive', size, monitor, report)
                result = archive.verify_archive(original, identities, progress=verify.observe)
                require(result['bytes'] == size and result['entries'] == 1, 'verify counts mismatch')
                verify.after()
                verify.r.update(verified_bytes=result['bytes'], status='passed')
                wrong = KeyStore(Paths(base=folder / 'wrong-ephemeral-key'))
                wrong.ensure_device_key()
                report['key_rejections'] = {'missing': common.rejected_identity(original, [], 'key-required'),
                                            'wrong': common.rejected_identity(original, wrong.identities(),
                                                                              'wrong-key')}
                shutil.rmtree(folder / 'wrong-ephemeral-key')
                late_tail_in_place(original, identities, size, written, monitor, report)
                original.unlink()
                report['identity_copies_in_scratch'] = negatives.secret_copies(folder, key.path)
                require(report['identity_copies_in_scratch'] == 0, 'identity material copied into scratch')
                monitor()
                report['status'] = 'passed'
            finally:
                signal.setitimer(signal.ITIMER_REAL, 0)
        report['harness_removed_private_scratch_and_keys'] = not folder.exists()
    except Exception as exc:
        report.update(status='failed', error='outer probe failed (details suppressed)', error_type=type(exc).__name__)
        if isinstance(exc, BackupError):
            report['error_code'] = exc.code
        elif isinstance(exc, RuntimeError):
            report['harness_check'] = str(exc)[:120]
        if 'folder' in locals():
            report['harness_removed_private_scratch_and_keys'] = not folder.exists()
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
