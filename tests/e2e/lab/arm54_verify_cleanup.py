"""Read-only post-cleanup verification; no workspace/storage recreation."""
import datetime
import json
from pathlib import Path
import shutil
import subprocess
import sys

root = Path(sys.argv[1])
probe_started = float(sys.argv[2])
assert root.parent == Path('/var/tmp') and root.name.startswith('woow-arm54-ha-20261122-')


def read(args):
    return subprocess.check_output(args, timeout=45).decode().splitlines()


inventory = {'containers': read(['podman', 'ps', '-a', '--no-trunc', '--format', '{{.ID}} {{.Names}} {{.Image}} {{.State}} {{.Ports}}']),
             'images': read(['podman', 'images', '--no-trunc', '--format', '{{.ID}} {{.Repository}}:{{.Tag}}']),
             'volumes': read(['podman', 'volume', 'ls', '--format', '{{.Name}}']),
             'networks': read(['podman', 'network', 'ls', '--format', '{{.Name}}']),
             'store': read(['podman', 'info', '--format', '{{.Store.GraphRoot}} {{.Store.RunRoot}}'])}
ids = [row.split()[0] for row in inventory['containers']]
rows = [json.loads(line) for line in read(['podman', 'inspect', '--format',
    '{"id":"{{.Id}}","started":{{json .State.StartedAt}},"running":{{json .State.Running}}}', *ids])]
originals = all(row['running'] and datetime.datetime.fromisoformat(row['started'].replace('Z', '+00:00')).timestamp()
                < probe_started for row in rows)
mounts = [line.split()[4] for line in Path('/proc/self/mountinfo').read_text().splitlines()]
print(json.dumps({'inventory': inventory, 'original_started_at_after': rows,
                  'probe_started_epoch': probe_started,
                  'originals_started_before_probe_and_still_running': originals,
                  'workspace_removed': not root.exists(),
                  'workspace_mounts_remaining': any(p == str(root) or p.startswith(str(root) + '/') for p in mounts),
                  'free_bytes_after_cleanup': shutil.disk_usage('/var/tmp').free}, sort_keys=True))
