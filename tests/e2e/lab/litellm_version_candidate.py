"""Explicit dev-d-only version probe; accepts already loaded image IDs, never pulls."""
import argparse
import datetime
import json
import secrets
import subprocess
from pathlib import Path

from woowbackup import ha_litellm_candidate as candidate, tempctr
from woowbackup.errors import BackupError
from woowbackup.podman import Result

LABPODMAN = str(Path.home() / '.woowbk-lab/bin/labpodman')


class DevDRunner:
    uid = None

    def podman(self, *args, timeout=120, check=True, **kwargs):
        proc = subprocess.run([LABPODMAN, 'exec', '-i', 'woowbk-dev-d', 'woowbk-owner', 'podman', *args],
                              input=kwargs.get('input'), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=timeout, check=False)
        if check and proc.returncode:
            raise BackupError('job-failed', '隔離實驗室映像探測失敗。')
        return Result(proc.returncode, proc.stdout, b'')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--app-image-id', default='')
    parser.add_argument('--db-image-id', required=True)
    args = parser.parse_args()
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    job = 'j' + stamp + '-' + secrets.token_hex(4)
    with tempctr.TempObjects(DevDRunner(), job, cpus=None) as tmp:
        evidence = candidate.probe_target_images(tmp, running_app_image_id=args.app_image_id,
                                                  running_db_image_id=args.db_image_id)
        clean = not tmp.containers and not tmp.volumes and not tmp.networks
    print(json.dumps({'device': 'dev-d', 'probe': evidence, 'probe_objects_clean': clean,
                      'app_image_supplied': bool(args.app_image_id)}, sort_keys=True))
    return 0 if evidence['target_pg_major'] and clean else 1


if __name__ == '__main__':
    raise SystemExit(main())
