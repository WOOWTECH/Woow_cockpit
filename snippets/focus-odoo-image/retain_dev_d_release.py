#!/usr/bin/env python3
"""Retain the PASSED OD-23 release outside Git, after the driver cleaned its redundant new stores."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

REPO = Path(__file__).resolve().parents[2]
LAB = str(Path.home() / '.woowbk-lab/bin/labpodman')
ROOT = '/var/lib/woowbk-odoo-pg16-proof-20261127-od23-r5'
RESERVE = 13 * 1024**3


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True, help='NEW directory outside the Git worktree.')
    args = parser.parse_args()
    output = args.output.absolute()
    assert not output.is_relative_to(REPO) and not output.exists() and not output.is_symlink()
    report = json.loads((REPO / 'snippets/focus-odoo-image' / (Path(ROOT).name + '-result.json')).read_text())
    assert report['status'] == 'passed' and report['proof_root'] == ROOT and report['pulls'] == 0
    assert report['loads'] == 1 and report['anonymous_volumes'] == 0 and report['source_tag_unchanged']
    assert report['redundant_owned_stores_removed'] == 2
    assert shutil.disk_usage(output.parent).free - report['archive_size'] >= RESERVE
    pin = report['manifest_sha256']
    code = r'''
import os,pathlib,struct,sys
root=pathlib.Path(ROOT_VALUE)
sys.path.insert(0,str(root/'code/backup-engine'))
from woowbackup import pg16_bundle as bundle
with bundle.open_bundle(root/'release', PIN_VALUE, trusted=True) as (record,raw,stream):
    assert record['image_id'] == EXPECTED_ID and record['archive_size'] == EXPECTED_SIZE
    assert record['archive_sha256'] == EXPECTED_SHA
    sys.stdout.buffer.write(struct.pack('!I',len(raw)))
    sys.stdout.buffer.write(raw)
    while True:
        data=stream.read(bundle.CHUNK)
        if not data:break
        sys.stdout.buffer.write(data)
'''.replace('ROOT_VALUE', repr(ROOT)).replace('PIN_VALUE', repr(pin)).replace('EXPECTED_ID', repr(report['image_id']))
    code = code.replace('EXPECTED_SIZE', repr(report['archive_size'])).replace('EXPECTED_SHA', repr(report['archive_sha256']))
    with open('/tmp/woowbk-dev-d-mutation.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.umask(0o077)
        output.mkdir(mode=0o700)
        proc = subprocess.Popen([LAB, 'exec', '-i', 'woowbk-dev-d', 'python3', '-I', '-'],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        try:
            proc.stdin.write(code.encode())
            proc.stdin.close()
            header = proc.stdout.read(4)
            assert len(header) == 4
            size = int.from_bytes(header, 'big')
            assert 0 < size <= 1024**2
            manifest = proc.stdout.read(size)
            assert len(manifest) == size and hashlib.sha256(manifest).hexdigest() == pin
            digest, left = hashlib.sha256(), report['archive_size']
            with (output / '.archive.partial').open('xb') as target:
                while left:
                    assert shutil.disk_usage(output).free >= RESERVE
                    data = proc.stdout.read(min(left, 1024**2))
                    assert data
                    digest.update(data)
                    target.write(data)
                    left -= len(data)
                target.flush()
                os.fsync(target.fileno())
            assert proc.stdout.read(1) == b'' and proc.wait(timeout=120) == 0
            assert digest.hexdigest() == report['archive_sha256']
            (output / '.archive.partial').rename(output / 'postgres16.docker.tar')
            (output / 'manifest.json').write_bytes(manifest)
            (output / 'manifest.sha256').write_text(pin + '\n')
        except BaseException:
            proc.kill()
            proc.wait()
            (output / '.archive.partial').unlink(missing_ok=True)
            raise
        receipt = {'status': 'retained-and-hash-verified', 'path': str(output), 'manifest_sha256': pin,
                   'archive_sha256': report['archive_sha256'], 'archive_size': report['archive_size'],
                   'image_id': report['image_id'], 'reserve_bytes': RESERVE,
                   'host_free_bytes_after': shutil.disk_usage(output).free}
        receipt['redundant_owned_stores_removed'] = report['redundant_owned_stores_removed']
        with (REPO / 'snippets/focus-odoo-image/retained-release.json').open('x') as record:
            record.write(json.dumps(receipt, indent=2) + '\n')
        print(json.dumps(receipt, sort_keys=True))


if __name__ == '__main__':
    main()
