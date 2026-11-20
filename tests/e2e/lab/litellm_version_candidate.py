"""Explicit dev-d-only version probe; accepts already loaded image IDs, never pulls."""
import argparse
import datetime
import json
import secrets
import subprocess
from pathlib import Path

from woowbackup import ha_litellm_candidate as candidate, tempctr
from woowbackup.errors import BackupError
from woowbackup.podman import Result, OutputLimitExceeded, default_runner

LABPODMAN = str(Path.home() / '.woowbk-lab/bin/labpodman')


class DevDRunner:
    uid = None

    def podman(self, *args, input=None, stdout=None, timeout=120, check=True, max_output=None, abort=None):
        argv = [LABPODMAN, 'exec', '-i', 'woowbk-dev-d', 'woowbk-owner', 'podman', *args]
        try:
            result = default_runner(argv, input=input, stdout=stdout, timeout=timeout,
                                    max_output=max_output, abort=abort)
        except OutputLimitExceeded:
            raise BackupError('limit-exceeded', '隔離實驗室命令輸出超過上限。') from None
        except subprocess.TimeoutExpired:
            raise BackupError('job-failed', '隔離實驗室命令執行逾時。') from None
        except OSError:
            raise BackupError('job-failed', '無法執行隔離實驗室命令。') from None
        if check and result.returncode:
            raise BackupError('job-failed', '隔離實驗室映像探測失敗。')
        # default_runner keeps a bounded stderr tail; it may contain sensitive data.
        return Result(result.returncode, result.stdout, b'')



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
