"""Bounded cross-physical archive probe, synthetic bytes only; no service restore.

Run with PYTHONPATH=backup-engine. Work directory must be fresh/private. No
Podman operation is performed by this file. Maximum extracted payload: 32 MiB.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import shutil
import tarfile

from woowbackup import archive, util

RESERVE = 12 * 1024 ** 3
MAX_BYTES = 32 * 1024 ** 2
PAYLOAD_BYTES = 8 * 1024 ** 2
APP = 'arm54-synthetic'


def capacity(root):
    free = shutil.disk_usage(root).free
    if free < RESERVE + 128 * 1024 ** 2:
        raise RuntimeError('capacity-reserve-refused')
    return free


def save(path, doc):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as out:
        json.dump(doc, out, sort_keys=True, indent=2)
        out.write('\n')


def pack(root, files, *, native=False):
    app = {'id': APP, 'name': 'Synthetic ARM archive probe', 'adapter': 'quadlet-postgres',
           'adapter_version': 1, 'catalog_sha256': 'a' * 64,
           'owner': {'name': 'synthetic', 'uid': 1001}, 'images': [], 'postgres': [],
           'volumes': [{'name': 'arm54-fixture', 'entry': f'apps/{APP}/volumes/arm54-fixture.tar'}],
           'secrets': [], 'config_files': [{'path': '.config/arm54/marker.json', 'mode': '0600',
                                           'entry': f'apps/{APP}/config/0'}],
           'quadlet_files': [], 'verify_snapshot': {}}
    manifest = {'format': 2, 'backup_id': '20261122T100000Z-' + ('a54a0002' if native else 'a54a0001'),
                'created': '2026-11-22T10:00:00Z', 'type': 'manual', 'note': 'synthetic cross-physical only',
                'key_id': None, 'encryption': 'none',
                'tool': {'name': 'woowtech-cockpit-backup', 'version': 'arm54-probe'},
                'source': {'hostname': 'synthetic-arm54' if native else 'synthetic-source',
                           'machine_id_sha256': '', 'arch': platform.machine(),
                           'os': platform.system(), 'podman': 'not-used'},
                'consistency': {'method': 'writers-stopped', 'downtime_seconds': 0},
                'apps': [app], 'entries': []}
    entries = [archive.entry_from_file(name, files[name]) for name in
               (f'apps/{APP}/volumes/arm54-fixture.tar', f'apps/{APP}/config/0')]
    result = archive.write_archive(root / 'roundtrip.tar', None, manifest, entries, None, tmp_dir=root)
    return {'archive_sha256': result['sha256'], 'archive_bytes': result['size'],
            'payload_sha256': {e.path: e.sha256 for e in entries}, 'writer_arch': platform.machine(),
            'format': 2, 'encryption': 'none'}


def make(root):
    payload = hashlib.shake_256(b'arm54 synthetic non-secret native probe v1').digest(PAYLOAD_BYTES)
    volume = root / 'volume.tar'
    with tarfile.open(volume, 'x', format=tarfile.PAX_FORMAT) as tar:
        info = tarfile.TarInfo('synthetic-marker.bin')
        info.size, info.mode = len(payload), 0o600
        tar.addfile(info, io.BytesIO(payload))
    volume.chmod(0o600)
    config = root / 'marker.json'
    config.write_bytes(b'{"kind":"synthetic-only","rows":37,"unicode":"ARM-aarch64"}\n')
    config.chmod(0o600)
    report = pack(root, {f'apps/{APP}/volumes/arm54-fixture.tar': volume, f'apps/{APP}/config/0': config})
    report['nested_payload_sha256'] = hashlib.sha256(payload).hexdigest()
    save(root / 'expected.json', report)
    return report


def unpack(root, expected_path, archive_path, *, require_arm):
    if require_arm and platform.machine() != 'aarch64':
        raise RuntimeError('native-arm-required')
    expected = json.loads(expected_path.read_text())
    if util.sha256_file(archive_path) != expected['archive_sha256']:
        raise RuntimeError('archive-transfer-sha256-mismatch')
    dest = root / 'unpacked'
    dest.mkdir(mode=0o700)
    limits = archive.Limits(max_members=16, max_total_bytes=MAX_BYTES, reserve_bytes=RESERVE)
    verified = archive.verify_archive(archive_path, [], limits=limits)
    archive.extract_archive(archive_path, [], dest, limits=limits)
    files = {name: dest / name for name in expected['payload_sha256']}
    actual = {name: util.sha256_file(path) for name, path in files.items()}
    if actual != expected['payload_sha256']:
        raise RuntimeError('unpacked-payload-sha256-mismatch')
    with tarfile.open(files[f'apps/{APP}/volumes/arm54-fixture.tar']) as tar:
        members = tar.getmembers()
        if len(members) != 1 or members[0].name != 'synthetic-marker.bin' or not members[0].isfile():
            raise RuntimeError('unexpected-nested-volume-layout')
        nested_hash = hashlib.sha256(tar.extractfile(members[0]).read(PAYLOAD_BYTES + 1)).hexdigest()
    if nested_hash != expected['nested_payload_sha256']:
        raise RuntimeError('nested-payload-sha256-mismatch')
    result = pack(root, files, native=require_arm)
    result.update(nested_payload_sha256=nested_hash, reader_arch=platform.machine(),
                  verified_entries=verified['entries'], verified_bytes=verified['bytes'],
                  received_sha256=expected['archive_sha256'], service_acceptance=False,
                  free_bytes_after=capacity(root))
    save(root / 'expected.json', result)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=('make', 'arm-unpack', 'source-unpack'))
    parser.add_argument('root', type=Path)
    parser.add_argument('--expected', type=Path)
    parser.add_argument('--archive', type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    capacity(args.root)
    result = make(args.root) if args.mode == 'make' else unpack(
        args.root, args.expected, args.archive, require_arm=args.mode == 'arm-unpack')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
