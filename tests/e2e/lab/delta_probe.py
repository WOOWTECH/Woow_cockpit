#!/usr/bin/env python3
"""Live probes for the delta review findings on the lab devices (installed engine, real podman 4.9.3).

    python3 -I tests/e2e/lab/delta_probe.py <hd01|hd01a|hd02|hd04|hd07|hd08|all>

hd01  dev-a: the deployed database Quadlet says `Image=postgres:16-alpine` (podman saves it as
      docker.io/library/postgres:16-alpine); a backup with images restores in place, the archived image is loaded as
      localhost/postgres:16-alpine, data equals the snapshot. The Quadlet file, the image names and the units are put
      back afterwards and the probe's backups deleted.
hd01a dev-a: the same with a short-name alias for `postgres` (a probe file in /etc/containers/registries.conf.d, like
      the shipped aliases for ubuntu, python or node): after the backup the alias target is pointed at another image
      (alpine, as a later pull would); the in-place restore moves the alias target back to the backed-up image, the
      database runs it and the data equals the snapshot. Alias file, names, Quadlet and units are put back.
hd02  dev-a: a FIFO, a symlink with a second name (hard link), setuid/setgid files and a file capability in the
      app's volume (directory `hd-probe/` next to `files/`, which the app does not count): the backup succeeds and
      notes what a restore drops, the in-place restore keeps FIFO and hard link and reports the dropped bits in the
      result; a relative symlink leaving the volume then fails the backup with the volume and member named while the
      app keeps running. The probe files and backups are removed afterwards.
hd04  dev-b (fresh target, torn down first like cli_e2e s2): a fresh restore killed (SIGKILL) while its data import
      still runs is removed by the recovery; one killed after the import (health/data check) stays deployed and
      running with its data, and the recovery leaves it alone. Ends with the app deployed on dev-b, as after s2.
hd07  both devices: `status` latency (the bounded loopback health requests, apps probed side by side).
hd08  dev-b: a ~600 MB upload whose `upload-finish` gets SIGTERM while it reads the file for its sha256 (what
      cockpit-bridge sends when the page times out; a watcher in the device sends it once the helper has read past
      the first MiB) still records its result, and the retry returns the same backup at once; the crafted upload
      (a real backup's header and age header, then filler) is deleted again.

Evidence: ~/.woowbk-lab/evidence/delta-fix/<time>-<scenario>/ (driver.log, result.json, job records).
Only labpodman is used; keys come from ~/.woowbk-lab/secrets and are never printed.
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cli_e2e as e2e  # noqa: E402 - the lab helpers (helper/ok/owner/sh/wait_job/bridge upload)

e2e.EVIDENCE = Path.home() / '.woowbk-lab' / 'evidence' / 'delta-fix'
APP = e2e.APP
DB_QUADLET = '.config/containers/systemd/woowbk-demo-db.container'
FULL, SHORT, LOCAL = 'docker.io/library/postgres:16-alpine', 'postgres:16-alpine', 'localhost/postgres:16-alpine'
PROBE_DIR = 'hd-probe'
Failed = e2e.Failed

# Run inside `podman unshare` as the owner (root of the owner's user namespace): build or inspect the probe files.
MAKE_PROBE = r'''
import json, os, sys
root = os.path.join(sys.argv[1], 'hd-probe')
os.makedirs(root, exist_ok=True)
def put(name, data, mode):
    path = os.path.join(root, name)
    with open(path, 'wb') as handle:
        handle.write(data)
    os.chmod(path, mode)
os.mkfifo(os.path.join(root, 'pickup'), 0o622)
os.symlink('/etc/hostname', os.path.join(root, 'sym'))
os.link(os.path.join(root, 'sym'), os.path.join(root, 'sym-hardlink'), follow_symlinks=False)
put('suid-helper', b'#!/bin/sh\n', 0o4755)
put('sgid-helper', b'#!/bin/sh\n', 0o2755)
put('capfile', b'cap\n', 0o755)
cap = b'\x01\x00\x00\x02' + (1 << 10).to_bytes(4, 'little') + bytes(12)  # VFS_CAP v2: cap_net_bind_service=ep
try:
    os.setxattr(os.path.join(root, 'capfile'), 'security.capability', cap)
    capability = True
except OSError as error:
    capability = f'{type(error).__name__}: {error}'
print(json.dumps({'capability': capability}))
'''
LIST_PROBE = r'''
import json, os, stat, sys
root = os.path.join(sys.argv[1], 'hd-probe')
out = {}
for name in sorted(os.listdir(root)) if os.path.isdir(root) else []:
    st = os.lstat(os.path.join(root, name))
    kind = 'fifo' if stat.S_ISFIFO(st.st_mode) else 'symlink' if stat.S_ISLNK(st.st_mode) else \
        'file' if stat.S_ISREG(st.st_mode) else 'other'
    try:
        caps = len(os.getxattr(os.path.join(root, name), 'security.capability', follow_symlinks=False))
    except OSError:
        caps = 0
    out[name] = {'kind': kind, 'mode': oct(stat.S_IMODE(st.st_mode)), 'inode': st.st_ino, 'caps': caps}
print(json.dumps(out))
'''
ESCAPE = r'''
import os, sys
os.symlink('../../etc/passwd', os.path.join(sys.argv[1], 'hd-probe', 'esc'))
'''
# Removes only the probe's own entries, by name (no recursive removal).
CLEAN_PROBE = r'''
import os, sys
root = os.path.join(sys.argv[1], 'hd-probe')
for name in ('pickup', 'sym', 'sym-hardlink', 'suid-helper', 'sgid-helper', 'capfile', 'esc'):
    try:
        os.unlink(os.path.join(root, name))
    except FileNotFoundError:
        pass
try:
    os.rmdir(root)
except FileNotFoundError:
    pass
'''


def volume_root(dev, name='woowbk-demo-files'):
    out = e2e.owner(dev, 'podman', 'volume', 'inspect', '--format', '{{.Mountpoint}}', name).stdout.decode().strip()
    if not out.startswith('/'):
        raise Failed(f'no mountpoint for {name}: {out!r}')
    return out


def in_userns(dev, code, *args):
    return e2e.owner(dev, 'podman', 'unshare', 'python3', '-I', '-c', code, *args).stdout.decode()


def raw_record(dev, job_id):
    """The whole job record (also the fields job-status does not show, e.g. fresh_apps)."""
    out = e2e.sh(dev, f'cat /var/lib/woowtech-backup/jobs/{job_id}.json', check=False).stdout
    try:
        return json.loads(out)
    except ValueError:
        return {}


def run_job(dev, command, request, ev, label):
    start = e2e.ok(dev, command, {**request, 'request_id': e2e.request_id()}, ev=ev)
    job, log = e2e.wait_job(dev, start['job_id'], ev=ev, label=label)
    ev.save(f'{label}-job', {'job': job, 'log': log})
    return job, log


def delete_backups(dev, ids, ev):
    for backup_id in ids:
        if backup_id:
            rc, reply = e2e.helper(dev, 'delete', {'backup_id': backup_id}, ev=ev)
            ev.log(f'delete {backup_id}: {"ok" if rc == 0 else reply.get("error")}')


def image_id(dev, name):
    proc = e2e.owner(dev, 'podman', 'image', 'inspect', '--format', '{{.Id}}', name, check=False)
    return proc.stdout.decode().strip() if proc.returncode == 0 else None


# ------------------------------------------------------------------ HD-01

def scenario_hd01(ev):
    dev = 'a'
    created = []
    original = e2e.owner(dev, 'cat', DB_QUADLET).stdout
    ev.require('hd01 precondition: the deployed database Quadlet uses the full name',
               f'Image={FULL}\n'.encode() in original, original.decode()[:300])
    full_id = image_id(dev, FULL)
    ev.require('hd01 precondition: no localhost/ name for the image yet', image_id(dev, LOCAL) is None, LOCAL)
    try:
        edited = original.replace(f'Image={FULL}\n'.encode(), f'Image={SHORT}\n'.encode())
        e2e.owner(dev, 'python3', '-I', '-c', 'import sys; open(sys.argv[1], "wb").write(sys.stdin.buffer.read())',
                  DB_QUADLET, input=edited)
        e2e.owner(dev, 'systemctl', '--user', 'daemon-reload')
        snapshot = e2e.summary(dev)
        job, _log = run_job(dev, 'backup-start', {'apps': [APP], 'include_images': True, 'note': 'HD-01 probe'}, ev,
                            'hd01-backup')
        ev.require('hd01 backup with images of Image=postgres:16-alpine succeeds', job['state'] == 'succeeded',
                   job.get('error'))
        backup_id = job['result']['backup_id']
        created.append(backup_id)
        inspect = e2e.ok(dev, 'inspect', {'backup_id': backup_id}, ev=ev)
        refs = [img['ref'] for app in inspect['manifest']['apps'] for img in app['images']]
        ev.check('hd01 the manifest names the image as the Quadlet spells it', SHORT in refs, refs)
        app_pre = next(a for a in inspect['preflight']['apps'] if a['id'] == APP)
        ev.check('hd01 inspect preflight: restorable', app_pre['restorable'], app_pre['checks'])
        e2e.app_post(dev, '/api/notes', json.dumps({'title': 'HD-01 after backup', 'body': 'changed'}).encode(),
                     'application/json')
        job, log = run_job(dev, 'restore-start', {'backup_id': backup_id, 'apps': [APP], 'confirm': True}, ev,
                           'hd01-restore')
        created.append((job.get('result') or {}).get('safety_backup_id'))
        ev.check('hd01 in-place restore of the image-including backup succeeds (was corrupt-archive)',
                 job['state'] == 'succeeded', job.get('error'))
        ev.check('hd01 the archived image was loaded (log)', any('載入映像 postgres:16-alpine' in line for line in log),
                 [line for line in log if '映像' in line][:4])
        ev.check('hd01 loaded as localhost/postgres:16-alpine with the recorded id',
                 image_id(dev, LOCAL) == full_id and full_id is not None, {'local': image_id(dev, LOCAL), 'full': full_id})
        ev.check('hd01 data equals the backup-time snapshot', e2e.compare(e2e.summary(dev), snapshot) == {},
                 e2e.compare(e2e.summary(dev), snapshot))
        verification = (job.get('result') or {}).get('verification') or [{}]
        ev.check('hd01 the result says 資料一致 (match true)', verification[0].get('match') is True, verification)
    finally:
        e2e.owner(dev, 'python3', '-I', '-c', 'import sys; open(sys.argv[1], "wb").write(sys.stdin.buffer.read())',
                  DB_QUADLET, input=original)
        e2e.owner(dev, 'systemctl', '--user', 'daemon-reload')
        for unit in ('woowbk-demo-db.service', 'woowbk-demo-app.service'):
            e2e.owner(dev, 'systemctl', '--user', 'restart', unit, check=False)
        if image_id(dev, LOCAL):
            e2e.owner(dev, 'podman', 'untag', LOCAL, LOCAL, check=False)
        healthy = e2e.wait_healthy(dev)
        delete_backups(dev, created, ev)
    ev.check('hd01 lab state put back: Quadlet as before, no localhost/ name, app healthy',
             e2e.owner(dev, 'cat', DB_QUADLET).stdout == original and image_id(dev, LOCAL) is None and healthy)
    return {}


ALIAS_CONF = '/etc/containers/registries.conf.d/zz-woowbk-hd01-probe.conf'
OTHER = 'docker.io/library/alpine:3.20'  # stands in for a newer image pulled under the alias target


def scenario_hd01a(ev):
    """HD-01 with a short-name alias (like ubuntu, python, node in shortnames.conf): the alias target wins over
    localhost/<ref>, so after the backup a newer image under the alias target made the in-place restore fail as a
    corrupt archive (after the safety backup). Now the alias target name follows the restored image."""
    dev = 'a'
    created = []
    original = e2e.owner(dev, 'cat', DB_QUADLET).stdout
    ev.require('hd01a precondition: the deployed database Quadlet uses the full name',
               f'Image={FULL}\n'.encode() in original, original.decode()[:300])
    full_id, other_id = image_id(dev, FULL), image_id(dev, OTHER)
    ev.require('hd01a precondition: postgres and alpine images present and different, no localhost/ name, no probe alias',
               full_id and other_id and full_id != other_id and image_id(dev, LOCAL) is None
               and e2e.sh(dev, f'test -e {ALIAS_CONF}', check=False).returncode != 0, {'full': full_id, 'other': other_id})
    try:
        e2e.sh(dev, f"umask 022; printf '[aliases]\\n\"postgres\" = \"docker.io/library/postgres\"\\n' > {ALIAS_CONF}")
        edited = original.replace(f'Image={FULL}\n'.encode(), f'Image={SHORT}\n'.encode())
        e2e.owner(dev, 'python3', '-I', '-c', 'import sys; open(sys.argv[1], "wb").write(sys.stdin.buffer.read())',
                  DB_QUADLET, input=edited)
        e2e.owner(dev, 'systemctl', '--user', 'daemon-reload')
        ev.require('hd01a the probe alias is in effect (postgres:16-alpine resolves to the full name)',
                   image_id(dev, SHORT) == full_id)
        snapshot = e2e.summary(dev)
        job, _log = run_job(dev, 'backup-start', {'apps': [APP], 'include_images': True, 'note': 'HD-01 alias probe'},
                            ev, 'hd01a-backup')
        ev.require('hd01a backup with images of Image=postgres:16-alpine (aliased) succeeds', job['state'] == 'succeeded',
                   job.get('error'))
        created.append(job['result']['backup_id'])
        e2e.owner(dev, 'podman', 'tag', other_id, FULL)  # what a later `podman pull postgres:16-alpine` would do
        ev.require('hd01a the alias target now names another image', image_id(dev, SHORT) == other_id
                   and image_id(dev, FULL) == other_id)
        e2e.app_post(dev, '/api/notes', json.dumps({'title': 'HD-01 alias after backup', 'body': 'changed'}).encode(),
                     'application/json')
        job, log = run_job(dev, 'restore-start', {'backup_id': created[0], 'apps': [APP], 'confirm': True}, ev,
                           'hd01a-restore')
        created.append((job.get('result') or {}).get('safety_backup_id'))
        ev.check('hd01a in-place restore succeeds although the alias target named another image (was corrupt-archive)',
                 job['state'] == 'succeeded', job.get('error'))
        ev.check('hd01a the log says the alias target was moved',
                 any(f'已將 {FULL}（{SHORT} 的別名目標）指向備份時的映像版本' in line for line in log),
                 [line for line in log if '映像' in line][:6])
        running = e2e.owner(dev, 'podman', 'inspect', '--format', '{{.Image}}', 'woowbk-demo-db',
                            check=False).stdout.decode().strip()
        ev.check('hd01a postgres:16-alpine and the running database container use the backed-up image',
                 image_id(dev, SHORT) == full_id and image_id(dev, FULL) == full_id and running == full_id,
                 {'short': image_id(dev, SHORT), 'full': image_id(dev, FULL), 'container': running, 'want': full_id})
        ev.check('hd01a alpine keeps its own name', image_id(dev, OTHER) == other_id)
        ev.check('hd01a data equals the backup-time snapshot', e2e.compare(e2e.summary(dev), snapshot) == {},
                 e2e.compare(e2e.summary(dev), snapshot))
        verification = (job.get('result') or {}).get('verification') or [{}]
        ev.check('hd01a the result says 資料一致 (match true)', verification[0].get('match') is True, verification)
    finally:
        e2e.sh(dev, f'rm -f {ALIAS_CONF}', check=False)
        if full_id and image_id(dev, FULL) != full_id:
            e2e.owner(dev, 'podman', 'tag', full_id, FULL, check=False)
        e2e.owner(dev, 'python3', '-I', '-c', 'import sys; open(sys.argv[1], "wb").write(sys.stdin.buffer.read())',
                  DB_QUADLET, input=original)
        e2e.owner(dev, 'systemctl', '--user', 'daemon-reload')
        for unit in ('woowbk-demo-db.service', 'woowbk-demo-app.service'):
            e2e.owner(dev, 'systemctl', '--user', 'restart', unit, check=False)
        if image_id(dev, LOCAL):
            e2e.owner(dev, 'podman', 'untag', LOCAL, LOCAL, check=False)
        healthy = e2e.wait_healthy(dev)
        delete_backups(dev, created, ev)
    ev.check('hd01a lab state put back: Quadlet, image names and alias config as before, app healthy',
             e2e.owner(dev, 'cat', DB_QUADLET).stdout == original and image_id(dev, LOCAL) is None
             and image_id(dev, FULL) == full_id and image_id(dev, OTHER) == other_id
             and e2e.sh(dev, f'test -e {ALIAS_CONF}', check=False).returncode != 0 and healthy)
    return {}


# ------------------------------------------------------------------ HD-02, HD-03, HD-09

def scenario_hd02(ev):
    dev = 'a'
    created = []
    root = volume_root(dev)
    try:
        made = json.loads(in_userns(dev, MAKE_PROBE, root))
        ev.log(f'probe files created; file capability set: {made["capability"]}')
        before = json.loads(in_userns(dev, LIST_PROBE, root))
        ev.save('hd02-probe-before', before)
        snapshot = e2e.summary(dev)
        job, log = run_job(dev, 'backup-start', {'apps': [APP], 'include_images': False, 'note': 'HD-02 probe'}, ev,
                           'hd02-backup')
        ev.require('hd03 backup of a volume with a FIFO and a second name of a symlink succeeds',
                   job['state'] == 'succeeded', job.get('error'))
        created.append(job['result']['backup_id'])
        ev.check('hd09 the backup already notes the setuid/setgid bits a restore drops',
                 any('setuid／setgid' in line and 'woowbk-demo-files' in line for line in log),
                 [line for line in log if '注意' in line][:4])
        job, log = run_job(dev, 'restore-start', {'backup_id': created[0], 'apps': [APP], 'confirm': True}, ev,
                           'hd02-restore')
        created.append((job.get('result') or {}).get('safety_backup_id'))
        ev.require('hd03 the in-place restore of that backup succeeds (was refused: FIFO / hard link to a symlink)',
                   job['state'] == 'succeeded', job.get('error'))
        after = json.loads(in_userns(dev, LIST_PROBE, root))
        ev.save('hd02-probe-after', after)
        ev.check('hd03 the FIFO is back as a FIFO', after.get('pickup', {}).get('kind') == 'fifo', after.get('pickup'))
        ev.check('hd03 the second name of the symlink is the same inode again',
                 after.get('sym', {}).get('kind') == 'symlink'
                 and after['sym'].get('inode') == after.get('sym-hardlink', {}).get('inode'), after)
        ev.check('hd09 setuid/setgid dropped as documented',
                 after.get('suid-helper', {}).get('mode') == '0o755' and after.get('sgid-helper', {}).get('mode') == '0o755',
                 after)
        warnings = (job.get('result') or {}).get('warnings') or []
        ev.check('hd09 the restore result names what was dropped',
                 any('setuid／setgid' in note and 'suid-helper' in note for note in warnings), warnings)
        if made['capability'] is True:
            ev.check('hd09 the dropped file capability is named too',
                     any('security.capability' in note for note in warnings) and after['capfile']['caps'] == 0, warnings)
        ev.check('hd02 data equals the backup-time snapshot', e2e.compare(e2e.summary(dev), snapshot) == {},
                 e2e.compare(e2e.summary(dev), snapshot))
        in_userns(dev, ESCAPE, root)
        job, log = run_job(dev, 'backup-start', {'apps': [APP], 'include_images': False, 'note': 'HD-02 escape'}, ev,
                           'hd02-backup-escape')
        message = (job.get('error') or {}).get('message') or ''
        ev.check('hd02 a relative symlink leaving the volume fails the backup, naming volume and member',
                 job['state'] == 'failed' and 'woowbk-demo-files' in message and 'hd-probe/esc' in message, message)
        status = e2e.ok(dev, 'status', ev=ev)
        app = next(a for a in status['apps'] if a['id'] == APP)
        ev.check('hd02 the app runs again after the refused backup', app['state'] == 'running', app)
        listed = [b['id'] for b in e2e.ok(dev, 'list', ev=ev)['backups']]
        ev.check('hd02 the refused backup is not listed', (job.get('result') or {}).get('backup_id') not in listed)
    finally:
        in_userns(dev, CLEAN_PROBE, root)
        delete_backups(dev, created, ev)
    ev.check('hd02 probe files removed', json.loads(in_userns(dev, LIST_PROBE, root)) == {})
    return {}


# ------------------------------------------------------------------ HD-04

def fresh_restore_killed(dev, backup_id, key, ev, label, *, after_import):
    start = e2e.ok(dev, 'restore-start', {'backup_id': backup_id, 'apps': [APP], 'request_id': e2e.request_id(),
                                          'confirm': True, 'key': key}, ev=ev)
    job_id = start['job_id']
    deadline = time.monotonic() + 600
    killed = None
    while time.monotonic() < deadline:
        record = raw_record(dev, job_id)
        phase, state = record.get('phase'), record.get('state')
        if state not in ('queued', 'running', None):
            break
        marker = record.get('fresh_apps')
        if after_import and phase == 'check':
            killed = {'phase': phase, 'fresh_apps': marker}
        elif not after_import and phase in ('restore', 'start') and marker == [APP]:
            killed = {'phase': phase, 'fresh_apps': marker}
        if killed:
            e2e.sh(dev, f'systemctl kill --signal=SIGKILL woowtech-backup-{job_id}.service')
            break
        time.sleep(0.1)
    ev.log(f'{label}: job {job_id} killed in {killed}')
    time.sleep(2)
    job, log = e2e.wait_job(dev, job_id, ev=ev, timeout=180, label=label)
    ev.save(f'{label}-job', {'job': job, 'log': log, 'killed': killed, 'record': raw_record(dev, job_id)})
    return job, killed, log


def scenario_hd04(ev):
    dev = 'b'
    state = e2e.load_state()
    source = (state.get('s2') or {}).get('download')  # the s1 backup, downloaded from dev-a by s2
    if not source or not Path(source).exists():
        raise Failed('run cli_e2e s1 and s2 first (needs the downloaded dev-a backup)')
    key = e2e.kit_secret()
    e2e.reset_target(dev, ev)
    _begin, (rc, reply) = e2e.upload_file(dev, source, ev=ev)
    ev.require('hd04 the dev-a backup was uploaded to dev-b', rc == 0, reply.get('error'))
    backup_id = reply['backup']['id']
    snapshot = (state.get('s1') or {}).get('snapshot')

    job, killed, _log = fresh_restore_killed(dev, backup_id, key, ev, 'hd04-killed-during-import', after_import=False)
    ev.require('hd04 a fresh restore was killed while its import still ran (record still lists the app)',
               killed is not None and killed['fresh_apps'] == [APP], killed)
    ev.check('hd04 that job is interrupted and its partial deployment removed by the recovery',
             job['state'] == 'interrupted' and '已清除未完成的全新部署' in (job.get('error') or {}).get('message', ''),
             job.get('error'))
    # The recovery removes the deployment; an image the dead job loaded keeps its name (the record does not list
    # images, CONTRACT section 8), and the next fresh restore loads it again.
    left = e2e.owner_footprint(dev)
    ev.check('hd04 nothing of the deployment is left on dev-b (Quadlet files, env file, volumes, secrets)',
             [item for item in left if not item.startswith('image:')] == [], left)
    ev.log(f'hd04 images left by the dead job (kept by design): {[item for item in left if item.startswith("image:")]}')

    job, killed, _log = fresh_restore_killed(dev, backup_id, key, ev, 'hd04-killed-after-import', after_import=True)
    ev.require('hd04 a fresh restore was killed after its import (health/data check)', killed is not None, killed)
    ev.check('hd04 the record no longer listed the app once its import finished', killed['fresh_apps'] == [], killed)
    error = (job.get('error') or {}).get('message', '')
    ev.check('hd04 that job is interrupted and nothing was removed', job['state'] == 'interrupted'
             and '清除' not in error and (job.get('result') or {}).get('fresh_apps') == [], error)
    for _ in range(3):  # later status calls (recovery passes) must leave it alone too
        e2e.ok(dev, 'status', ev=ev)
    ev.check('hd04 the completed deployment stays and serves its data', e2e.wait_healthy(dev, 120)
             and (snapshot is None or e2e.compare(e2e.summary(dev), snapshot) == {}),
             e2e.summary(dev) if e2e.wait_healthy(dev, 5) else 'not healthy')
    status = e2e.ok(dev, 'status', ev=ev)
    app = next(a for a in status['apps'] if a['id'] == APP)
    ev.check('hd04 dev-b status: app deployed and running', app['deployed'] and app['state'] == 'running', app)
    return {}


# ------------------------------------------------------------------ HD-07

def scenario_hd07(ev):
    for dev in ('a', 'b'):
        times = []
        for _ in range(5):
            started = time.monotonic()
            reply = e2e.ok(dev, 'status', ev=ev)
            times.append(round(time.monotonic() - started, 2))
        apps = [(a['id'], a['state']) for a in reply['apps']]
        ev.check(f'hd07 dev-{dev} status answers in {sorted(times)[2]} s median (5 calls)', max(times) < 10,
                 {'seconds': times, 'apps': apps})
    return {}


# ------------------------------------------------------------------ HD-08

# Run as root in the device: find the upload-finish helper, wait until it has read past the first MiB of the upload's
# .part file (the header check is done, the sha256 pass runs) and send it SIGTERM; prints the file offset it had read.
TERM_WHILE_HASHING = r'''
import os, signal, sys, time
upload, size = sys.argv[1], int(sys.argv[2])
deadline = time.monotonic() + 120
while time.monotonic() < deadline:
    for pid in (p for p in os.listdir('/proc') if p.isdigit()):
        try:
            argv = open(f'/proc/{pid}/cmdline', 'rb').read().split(b'\0')
            if b'upload-finish' not in argv or not any(a.endswith(b'woowtech-cockpit-backup') for a in argv):
                continue
            for fd in os.listdir(f'/proc/{pid}/fd'):
                if os.readlink(f'/proc/{pid}/fd/{fd}').endswith(f'/uploads/{upload}.part'):
                    pos = int(open(f'/proc/{pid}/fdinfo/{fd}').read().split('pos:')[1].split()[0])
                    if (1 << 20) < pos < size:
                        os.kill(int(pid), signal.SIGTERM)
                        print(pos)
                        sys.exit(0)
        except (OSError, IndexError, ValueError):
            continue
    time.sleep(0.01)
sys.exit(1)
'''


def scenario_hd08(ev):
    dev = 'b'
    source = Path.home() / '.woowbk-lab' / 'downloads' / 'woowtech-backup-woowbk-dev-a-20261112-1905.woowbackup'
    with open(source, 'rb') as handle:
        prefix = handle.read(64 * 1024)
    header = json.loads(prefix.split(b'\n', 2)[1])
    work = Path.home() / '.woowbk-lab' / 'run' / 'hd08'
    work.mkdir(parents=True, exist_ok=True, mode=0o700)
    big = work / 'hd08-upload.woowbackup'
    size = 600 * 1024 * 1024
    with open(big, 'wb') as handle:
        os.fchmod(handle.fileno(), 0o600)
        handle.write(prefix)
        block = hashlib.sha256(b'hd08').digest() * (1 << 15)  # 1 MiB of filler
        while handle.tell() < size:
            handle.write(block[:size - handle.tell()])
    if any(b['id'] == header['backup_id'] for b in e2e.ok(dev, 'list', ev=ev)['backups']):
        raise Failed(f'{header["backup_id"]} is already on dev-b; delete it first')
    result = None
    proc = begin = None
    try:
        for attempt in range(1, 4):
            begin = e2e.ok(dev, 'upload-begin', {'filename': big.name, 'size': size}, ev=ev)
            e2e.bridge_upload(dev, begin['path'], str(big), ev=ev)
            proc = subprocess.Popen([e2e.LP, 'exec', '-i', e2e.dev_name(dev), e2e.HELPER, 'upload-finish'],
                                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            proc.stdin.write(json.dumps({'upload_id': begin['upload_id']}).encode())
            proc.stdin.close()
            proc.stdin = None  # communicate() must not flush the closed pipe
            # SIGTERM (what cockpit-bridge sends when the page times out) once the helper is reading the file
            term = subprocess.run([e2e.LP, 'exec', e2e.dev_name(dev), 'python3', '-I', '-c', TERM_WHILE_HASHING,
                                   begin['upload_id'], str(size)], capture_output=True, timeout=180)
            signalled = term.returncode == 0
            out, _err = proc.communicate(timeout=600)
            reply = json.loads(out.decode().strip().splitlines()[-1]) if out.strip() else {}
            done = e2e.sh(dev, f'test -f /var/lib/woowtech-backup/uploads/{begin["upload_id"]}.done', check=False)
            result = {'attempt': attempt, 'signalled_while_hashing': signalled,
                      'sigterm_at_byte': term.stdout.decode().strip() or None, 'of_bytes': size,
                      'first_call_ok': reply.get('ok'), 'first_call_rc': proc.returncode,
                      'done_marker': done.returncode == 0}
            ev.log(f'hd08 attempt {attempt}: {result}')
            if signalled and reply.get('ok'):
                break
            if reply.get('ok'):  # finished before the helper was caught reading: start over
                delete_backups(dev, [header['backup_id']], ev)
            else:
                e2e.helper(dev, 'upload-abort', {'upload_id': begin['upload_id']}, ev=ev)
        ev.require('hd08 SIGTERM arrived while upload-finish was reading the file, and the check still finished '
                   '(reply ok, .done written)',
                   result and result['signalled_while_hashing'] and result['first_call_ok'] and result['done_marker'],
                   result)
        started = time.monotonic()
        retry = e2e.ok(dev, 'upload-finish', {'upload_id': begin['upload_id']}, ev=ev)
        elapsed = round(time.monotonic() - started, 2)
        ev.check(f'hd08 the retry returns the same backup at once ({elapsed} s)',
                 retry['backup']['id'] == header['backup_id'] and retry['backup']['size'] == size, retry['backup'])
    finally:
        if proc is not None and proc.poll() is None:  # an upload-finish still checking: let it end before cleaning up
            try:
                proc.communicate(timeout=600)
            except Exception:  # noqa: BLE001 - cleanup continues
                proc.kill()
        if begin is not None:
            e2e.helper(dev, 'upload-abort', {'upload_id': begin['upload_id']}, ev=ev)  # not-found once finished
        delete_backups(dev, [header['backup_id']], ev)
        big.unlink(missing_ok=True)
    return {}


SCENARIOS = {'hd07': scenario_hd07, 'hd01': scenario_hd01, 'hd01a': scenario_hd01a, 'hd02': scenario_hd02,
             'hd08': scenario_hd08, 'hd04': scenario_hd04}


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('scenario', choices=[*SCENARIOS, 'all'])
    args = parser.parse_args()
    names = list(SCENARIOS) if args.scenario == 'all' else [args.scenario]
    all_ok = True
    for name in names:
        ev = e2e.Evidence(name)
        try:
            extra = SCENARIOS[name](ev) or {}
        except Failed as error:
            ev.log(f'ABORTED: {error}')
            extra = {'aborted': str(error)}
        except Exception as error:  # noqa: BLE001 - record and continue to the summary
            ev.log(f'ABORTED with {type(error).__name__}: {e2e.redact(str(error))}')
            extra = {'aborted': f'{type(error).__name__}: {e2e.redact(str(error))}'}
        all_ok = ev.finish(extra) and 'aborted' not in extra and all_ok
    return 0 if all_ok else 1


if __name__ == '__main__':
    sys.exit(main())
