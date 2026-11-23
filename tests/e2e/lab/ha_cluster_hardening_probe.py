#!/usr/bin/env python3
"""Lab probe for the RECOMMENDED (not implemented) hardening of the shared throwaway HA PostgreSQL cluster
(`ha_odoo.start_ha_cluster`, used by the Odoo, n8n, Omnigent and LiteLLM imports): what `/tmp` noexec and a tighter
memory limit would block, and whether the HA-cluster server still starts with them.

Runs ONLY in the isolated lab Podman store (~/.woowbk-lab/bin/labpodman), every container with --network none; one
throwaway volume initialised by the image's own entrypoint (trust auth inside a network-less container, no password).
Two server containers on that volume, each started like the product starts HA's cluster (image entrypoint as root,
`postgres` with ha_odoo.HA_SERVER_SETTINGS, read-only root, data volume rw,noexec,nosuid,nodev, the tempctr flags):

  A = today's flags (tempctr.TempObjects.run_argv + start_ha_cluster)
  B = A + --read-only-tmpfs=false and explicit noexec tmpfs on /tmp, /var/tmp, /run (podman --tmpfs default options
      are rw,noexec,nosuid,nodev) + --memory 256m --memory-swap 256m + --oom-score-adj 1000

In each, as the database superuser (what code in a crafted HA catalog runs as, security review SR-2): copy an image
library and busybox into every writable place and try LOAD / execute; read the memory limits; in B only, one query
that asks for far more memory than the limit (the backend must die inside the container, nothing outside).

Output: fixed key=value facts only (no data, no secret).  Usage: ha_cluster_hardening_probe.py <out.json>
"""
import json
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'backup-engine'))
from woowbackup import ha_odoo, tempctr  # noqa: E402

LABPODMAN = str(Path.home() / '.woowbk-lab/bin/labpodman')
IMAGE = 'docker.io/library/postgres:16-alpine'
DATA = ha_odoo.HA_DATA
TAG = 'woowbk-hardprobe-' + secrets.token_hex(4)
FLOOR = 13 * 1024 ** 3


def pod(*args, timeout=180, check=True):
    proc = subprocess.run([LABPODMAN, *args], capture_output=True, timeout=timeout)
    if check and proc.returncode != 0:
        raise RuntimeError(f'labpodman {args[0]} exit {proc.returncode}: {proc.stderr.decode()[-200:]}')
    return proc


def base_flags(memory):
    # tempctr.TempObjects.run_argv for start_ha_cluster's container (no --cpus: lab)
    return ['--pull=never', '--log-driver', 'none', '--network', 'none', '--security-opt', 'no-new-privileges',
            '--pids-limit', str(tempctr.PIDS), '--memory', memory, '--read-only']


HARDENED = ['--read-only-tmpfs=false', '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777',
            '--tmpfs', '/var/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777',
            '--tmpfs', '/run:rw,noexec,nosuid,nodev,size=16m,mode=755',
            '--memory-swap', '256m', '--oom-score-adj', '1000']


def psql(name, sql, timeout=120):
    proc = pod('exec', '-u', 'postgres', name, 'psql', '-U', 'postgres', '-At', '-v', 'ON_ERROR_STOP=1', '-c', sql,
               timeout=timeout, check=False)
    text = (proc.stdout + proc.stderr).decode('utf-8', 'replace').strip().replace('\n', ' | ')
    return {'ok': proc.returncode == 0, 'out': text[:160]}


def wait_ready(name):
    for _ in range(90):
        if pod('exec', '-u', 'postgres', name, 'pg_isready', '-q', check=False, timeout=30).returncode == 0:
            return True
        time.sleep(1)
    return False


def facts(name):
    out = {}
    mounts = pod('exec', name, 'sh', '-c', "grep -E ' (/tmp|/var/tmp|/run|/dev/shm|/var/lib/postgresql/data) ' "
                 "/proc/self/mounts | awk '{print $2\" \"$4}'", check=False).stdout.decode().strip().splitlines()
    out['mounts'] = {line.split(' ', 1)[0]: ('noexec' in line.split(' ', 1)[1]) for line in mounts if ' ' in line}
    out['mounts'] = {k: ('noexec' if v else 'EXEC') for k, v in sorted(out['mounts'].items())}
    limits = pod('exec', name, 'sh', '-c', 'cat /sys/fs/cgroup/memory.max /sys/fs/cgroup/memory.swap.max '
                 '/proc/1/oom_score_adj 2>/dev/null', check=False).stdout.decode().split()
    out['memory_max'], out['memory_swap_max'], out['oom_score_adj'] = (limits + ['?'] * 3)[:3]
    out['socket_dir'] = pod('exec', name, 'sh', '-c', 'stat -c %a:%U /var/run/postgresql', check=False
                            ).stdout.decode().strip()
    tries = {}
    for where in ('/tmp', '/var/tmp', '/run/postgresql', '/dev/shm', DATA):
        lib = f'{where}/x{secrets.token_hex(2)}.so'
        copied = psql(name, f"COPY (SELECT 1) TO PROGRAM 'cp /usr/local/lib/postgresql/auto_explain.so {lib}'")
        load = psql(name, f"LOAD '{lib}'") if copied['ok'] else {'ok': False, 'out': 'not copied'}
        binary = f'{where}/b{secrets.token_hex(2)}'
        run = psql(name, f"COPY (SELECT 1) TO PROGRAM 'cp /bin/busybox {binary} && {binary} true'")
        tries[where] = {'copy_library': copied['ok'], 'load_library': load['ok'],
                        'load_error': '' if load['ok'] else load['out'][-90:],
                        'run_copied_busybox': run['ok']}
    out['writable_places'] = tries
    # the image's own binaries stay usable (the container, not noexec, is the boundary for shell code)
    out['image_shell_runs'] = psql(name, "COPY (SELECT 1) TO PROGRAM 'id -u > /dev/null'")['ok']
    return out


def main(argv):
    out = Path(argv[0])
    st = os.statvfs('/')
    if st.f_bavail * st.f_frsize < FLOOR:
        raise SystemExit('STOP: free disk below 13 GiB')
    doc = {'probe': 'tests/e2e/lab/ha_cluster_hardening_probe.py', 'image': IMAGE,
           'started': time.strftime('%Y-%m-%dT%H:%M:%S%z'), 'server_args': ha_odoo.ha_server_args()[1:],
           'variants': {}}
    volume = f'{TAG}-data'
    names = []
    try:
        pod('volume', 'create', volume)
        init = f'{TAG}-init'
        names.append(init)
        pod('run', '-d', '--name', init, '--network', 'none', '--pull=never', '-e', 'POSTGRES_HOST_AUTH_METHOD=trust',
            '-v', f'{volume}:{DATA}', IMAGE)
        doc['init_ready'] = wait_ready(init)
        pod('stop', '-t', '60', init, timeout=120)
        pod('rm', init)
        names.remove(init)
        for label, flags in (('A-today', base_flags('768m')), ('B-hardened', base_flags('256m') + HARDENED)):
            name = f'{TAG}-{label[0].lower()}'
            names.append(name)
            t0 = time.monotonic()
            proc = pod('run', '-d', '--name', name, *flags, '-v', f'{volume}:{DATA}:rw,noexec,nosuid,nodev', IMAGE,
                       *ha_odoo.ha_server_args(), check=False)
            res = {'started': proc.returncode == 0, 'flags': flags}
            if proc.returncode != 0:
                res['start_error'] = proc.stderr.decode('utf-8', 'replace')[-200:]
            elif not wait_ready(name):
                res['ready'] = False
            else:
                res['ready'] = True
                res['select_1'] = psql(name, 'SELECT 1')['ok']
                res.update(facts(name))
                if label.startswith('B'):
                    # far more memory than the 256m limit: the backend must be killed inside the container
                    hog = psql(name, "SET work_mem = '2GB'; SET hash_mem_multiplier = 1; "
                                     "SELECT count(*) FROM (SELECT DISTINCT g FROM generate_series(1, 40000000) g) s",
                               timeout=600)
                    res['memory_hog_query_ok'] = hog['ok']
                    res['memory_hog_error'] = hog['out'][-120:]
                    events = pod('exec', name, 'sh', '-c', 'cat /sys/fs/cgroup/memory.events', check=False
                                 ).stdout.decode().split()
                    res['oom_kill_events'] = dict(zip(events[::2], events[1::2])).get('oom_kill', '?')
                    res['server_ready_after_hog'] = wait_ready(name)
            res['seconds'] = round(time.monotonic() - t0, 1)
            pod('rm', '-f', '-t', '10', name, check=False, timeout=120)
            names.remove(name)
            doc['variants'][label] = res
            out.write_text(json.dumps(doc, indent=1, ensure_ascii=False))
    finally:
        for name in names:
            pod('rm', '-f', '-t', '10', name, check=False, timeout=120)
        pod('volume', 'rm', '-f', volume, check=False)
        left = pod('ps', '-a', '--filter', f'name={TAG}', '--format', '{{.Names}}', check=False).stdout.decode().split()
        left += [v for v in pod('volume', 'ls', '--format', '{{.Name}}', check=False).stdout.decode().split()
                 if v.startswith(TAG)]
        doc['left_after_cleanup'] = left
        doc['finished'] = time.strftime('%Y-%m-%dT%H:%M:%S%z')
        out.write_text(json.dumps(doc, indent=1, ensure_ascii=False))


if __name__ == '__main__':
    main(sys.argv[1:])
