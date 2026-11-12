#!/usr/bin/env python3
"""Hardening scenarios H1-H7 for backup & restore on the lab devices (lab hardening engineer).

Every engine call goes through the installed helper exactly as the Cockpit page makes it (see
cli_e2e.py: root, stdin JSON, one JSON object back); uploads and downloads use the device's real
cockpit-bridge (fsreplace1 / fsread1). Faults are injected only inside the lab devices.

    python3 -I tests/e2e/lab/hardening.py h1   # F5: crafted hostile archives (device key) via upload -> inspect/verify/restore
    python3 -I tests/e2e/lab/hardening.py h2   # F6: tiny backup filesystem (tmpfs over /var/lib/woowtech-backup)
    python3 -I tests/e2e/lab/hardening.py h3   # F7: pg_dump fails (non-zero, truncated-but-0, database stopped)
    python3 -I tests/e2e/lab/hardening.py h4   # SIGKILL a backup job in stop/dump/export (+ verify) windows
    python3 -I tests/e2e/lab/hardening.py h5   # device reboot (labpodman restart) during a restore
    python3 -I tests/e2e/lab/hardening.py h6   # ~600 MB files volume: backup, bridge download, in-place restore, memory
    python3 -I tests/e2e/lab/hardening.py h7   # manage.py plan/install/verify, rollback, re-install on a device
    python3 -I tests/e2e/lab/hardening.py leaks
    (H8, browser upload windows, is tests/e2e/lab/upload_window.mjs)

Evidence: ~/.woowbk-lab/evidence/hardening/<time>-<scenario>/ (driver.log, result.json, job records).
Key material never leaves the devices: hostile archives are built *inside* dev-a (its own device key
decrypts a fresh base backup and the result is re-encrypted to the device recipient), so only
ciphertext reaches the host. Only labpodman is used; the host's own Podman is never touched.
"""
import hashlib
import json
import os
import re
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cli_e2e as e2e  # noqa: E402  (shared helper/bridge/evidence code of the integration runner)
from cli_e2e import (APP, LAB, LP, Failed, app_get, compare, content_state, dev_name, helper,  # noqa: E402
                     ok, owner, phase_states, redact, request_id, sh, summary, wait_healthy, wait_job)

HARDENING = LAB / 'evidence' / 'hardening'
WORK = LAB / 'run' / 'hardening'
DATA = '/var/lib/woowtech-backup'


# ------------------------------------------------------------------ evidence

class Evidence(e2e.Evidence):
    def __init__(self, scenario):  # noqa: D107 - same as cli_e2e.Evidence, other directory
        stamp = time.strftime('%Y%m%dT%H%M%S')
        self.dir = HARDENING / f'{stamp}-{scenario}'
        self.dir.mkdir(parents=True, exist_ok=True)
        self.log_path = self.dir / 'driver.log'
        self.checks = []
        self.timings = {}
        self.t0 = time.monotonic()


def private_dir(path):
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    return path


# ------------------------------------------------------------------ device helpers

def py(dev, code, *args, timeout=600, check=True):
    """Run a Python program (code on stdin, `python3 -I -`) as root inside a device."""
    proc = subprocess.run([LP, 'exec', '-i', dev_name(dev), 'python3', '-I', '-', *map(str, args)],
                          input=code.encode(), capture_output=True, timeout=timeout)
    if check and proc.returncode != 0:
        raise Failed(f'device {dev}: python program failed rc={proc.returncode}: '
                     f'{redact(proc.stderr.decode("utf-8", "replace")[-600:])}')
    return proc


def backups(dev, ev):
    return ok(dev, 'list', ev=ev)['backups']


def backup_ids(dev, ev):
    return {b['id'] for b in backups(dev, ev)}


def app_status(dev, ev):
    return next(a for a in ok(dev, 'status', ev=ev)['apps'] if a['id'] == APP)


def staging_empty(dev):
    return sh(dev, f'ls -A {DATA}/staging').stdout.strip() == b''


def run_dir(dev):
    return sh(dev, 'ls -A /run/woowtech-backup').stdout.decode().split()


def no_job_keys(dev):
    return not any(name.startswith('key-') for name in run_dir(dev))


def archive_dir_listing(dev):
    return sh(dev, f'ls -A {DATA}/archives').stdout.decode().split()


def orphans(dev):
    """Archive files without an index sidecar (never listed, never cleaned) and stray temp files."""
    names = set(archive_dir_listing(dev))
    stray = []
    for name in sorted(names):
        if name.endswith('.woowbackup'):
            if name[:-len('.woowbackup')] + '.json' not in names:
                stray.append(name)
        elif not name.endswith('.json'):
            stray.append(name)
    return stray


def owner_fingerprint(dev):
    """sha256 of the owner's deployment files (Quadlets + env file); content never leaves the device."""
    script = ('cd "$HOME" && sha256sum .config/containers/systemd/woowbk-demo.network '
              '.config/containers/systemd/woowbk-demo-db.container .config/containers/systemd/woowbk-demo-app.container '
              '.config/woowbk-demo/app.env 2>&1; podman volume ls -q | sort; podman secret ls --format "{{.Name}}" | sort; '
              'ls -A .config/containers/systemd/')
    return owner(dev, 'sh', '-c', script).stdout.decode()


def units_active(dev):
    out = owner(dev, 'systemctl', '--user', 'is-active', 'woowbk-demo-db.service', 'woowbk-demo-app.service',
                check=False).stdout.decode().split()
    return out == ['active', 'active'], out


# Files changed since a marker: regular files/symlinks on the root fs, everything below the backup
# data dir and below /home. The host filters known background noise (journal, podman's own state,
# PostgreSQL data, the app's health probe) and reports anything else.
CHANGED_SCAN = r'''
import json, os, stat, sys
t0 = float(sys.argv[1])
SKIP = ('/proc', '/sys', '/dev', '/run', '/home', '/var/lib/woowtech-backup', '/var/lib/containers', '/tmp/.X11-unix')
def walk(top, xdev, skip=()):
    out = []
    try:
        dev0 = os.lstat(top).st_dev
    except OSError:
        return out
    for base, dirs, names in os.walk(top):
        keep = []
        for d in dirs:
            p = os.path.join(base, d)
            if p in skip:
                continue
            try:
                st = os.lstat(p)
            except OSError:
                continue
            if xdev and st.st_dev != dev0:
                continue
            keep.append(d)
            if max(st.st_mtime, st.st_ctime) > t0 and top != '/':
                out.append(p + '/')
        dirs[:] = keep
        for n in names:
            p = os.path.join(base, n)
            try:
                st = os.lstat(p)
            except OSError:
                continue
            if max(st.st_mtime, st.st_ctime) > t0:
                out.append(p)
    return out
print(json.dumps({'root': walk('/', True, SKIP), 'data': walk('/var/lib/woowtech-backup', False),
                  'home': walk('/home', False)}))
'''

NOISE = {
    'root': (re.compile(r'^/var/log/journal/'), re.compile(r'^/var/lib/systemd/'),
             re.compile(r'^/usr/local/lib/woowtech-cockpit-backup/.*/__pycache__/'), re.compile(r'^/var/cache/')),
    'data': (re.compile(r'^/var/lib/woowtech-backup/jobs/'), re.compile(r'^/var/lib/woowtech-backup/requests\.json$'),
             re.compile(r'^/var/lib/woowtech-backup/archives/'), re.compile(r'^/var/lib/woowtech-backup/uploads/'),
             re.compile(r'^/var/lib/woowtech-backup/(staging|jobs|archives|uploads)/$')),
    # Podman's own state (container DB, health check logs, layers, blob-info cache) and directory *mtimes*
    # only: a file created anywhere below still shows up under its own path and is reported. The directory
    # entries are needed because other lab users run short-lived `podman volume create/rm` and `podman load`
    # probes as appowner on the same device (seen in the device journal as woowbk-sec-probe-*).
    'home': (re.compile(r'^/home/appowner/\.local/share/containers/storage/(?!volumes/)'),
             re.compile(r'^/home/appowner/\.local/share/containers/storage/volumes/$'),
             re.compile(r'^/home/appowner/\.local/share/containers/storage/volumes/woowbk-demo-pgdata/'),
             re.compile(r'^/home/appowner/\.local/share/containers/storage/volumes/woowbk-demo-files/_data/$'),
             re.compile(r'^/home/appowner/\.local/share/containers/storage/volumes/woowbk-demo-files/_data/\.healthz-'),
             re.compile(r'^/home/appowner/\.local/share/containers/cache/'),
             re.compile(r'^/home/appowner/\.local/share/containers/storage/$'),
             re.compile(r'^/home/appowner/\.local/share/containers/$'),
             re.compile(r'^/home/appowner/$')),
}


def foreign_activity(dev, t0):
    """Podman events of other lab users in the window (journal lines naming woowbk-sec-probe-*)."""
    out = sh(dev, f'journalctl --no-pager -o cat --since @{int(t0)} | grep -c "sec-probe" || true', check=False)
    try:
        return int(out.stdout.decode().strip() or 0)
    except ValueError:
        return -1


def device_clock(dev):
    return float(sh(dev, 'date +%s.%N').stdout.decode().strip())


def changed_since(dev, t0):
    """Unexpected changed paths since device time t0 ({area: [paths]}; empty lists = clean)."""
    report = json.loads(py(dev, CHANGED_SCAN, f'{t0:.3f}', timeout=300).stdout)
    unexpected = {}
    for area, paths in report.items():
        bad = [p for p in paths if not any(rx.search(p) for rx in NOISE[area])]
        if bad:
            unexpected[area] = bad[:40]
    return unexpected, {area: len(paths) for area, paths in report.items()}


def scanner_selftest(dev, ev):
    """The changed-files scan must report planted writes in each area, otherwise its silence proves nothing."""
    t0 = device_clock(dev)
    time.sleep(1.1)
    probes = ['/etc/woowbk-scan-probe', '/home/appowner/.woowbk-scan-probe', f'{DATA}/woowbk-scan-probe',
              '/home/appowner/.local/share/containers/storage/volumes/woowbk-demo-files/_data/files/woowbk-scan-probe']
    sh(dev, 'touch ' + ' '.join(probes))
    try:
        unexpected, counts = changed_since(dev, t0)
    finally:
        sh(dev, 'rm -f ' + ' '.join(probes))
    found = {p for paths in unexpected.values() for p in paths}
    ev.check('changed-files scanner self-test: planted files on /etc, /home, the data dir and inside the app volume '
             'are all reported', set(probes) <= found, {'unexpected': unexpected, 'counts': counts})


# Diagnostic only: the installed engine's own verifier on an archive, to record *why* it is rejected
# (BackupError.details.reason; member names at most, never content).
REASON_PROBE = r'''
import json, sys
sys.path.insert(0, '/usr/local/lib/woowtech-cockpit-backup')
sys.dont_write_bytecode = True
from woowbackup import archive
from woowbackup.errors import BackupError
from woowbackup.keys import KeyStore
from woowbackup.paths import Paths
path = '/var/lib/woowtech-backup/archives/%s.woowbackup' % sys.argv[1]
try:
    result = archive.verify_archive(path, list(KeyStore(Paths()).identities()))
    print(json.dumps({'ok': True, 'entries': result['entries']}))
except BackupError as error:
    print(json.dumps({'ok': False, 'code': error.code, 'details': error.details}, ensure_ascii=False, default=str))
'''


def rejection_reason(dev, backup_id):
    return json.loads(py(dev, REASON_PROBE, backup_id, timeout=300).stdout)


def canaries(dev, pattern):
    """Paths whose name contains `pattern` anywhere on the device (root fs, /home, backup data, /tmp)."""
    script = (f'find / -xdev -name "*{pattern}*" 2>/dev/null; find /home /var/lib/woowtech-backup /var/lib/containers '
              f'-name "*{pattern}*" 2>/dev/null; true')
    return sorted(set(sh(dev, script, timeout=300).stdout.decode().split()))


# ------------------------------------------------------------------ in-device job watcher

# Follows the record of the next new job (or a given job id) and prints one JSON line per phase change.
# With a kill phase list it sends SIGKILL to the job's unit the moment the record shows one of them.
WATCH = r'''
import json, os, subprocess, sys, time
jobs_dir, wanted, kill_phases, timeout = sys.argv[1], sys.argv[2], sys.argv[3], float(sys.argv[4])
kill_phases = set(filter(None, kill_phases.split(',')))
before = set(os.listdir(jobs_dir)) if wanted == 'next' else set()
deadline = time.time() + timeout
job = None if wanted == 'next' else wanted
def say(**kw):
    kw['t'] = round(time.time(), 3)
    print(json.dumps(kw), flush=True)
say(ready=True)
while job is None and time.time() < deadline:
    fresh = sorted(n for n in os.listdir(jobs_dir) if n.endswith('.json') and n not in before and n.startswith('j'))
    if fresh:
        job = fresh[0][:-5]
        say(job=job)
        break
    time.sleep(0.02)
last = None
while job is not None and time.time() < deadline:
    try:
        with open(os.path.join(jobs_dir, job + '.json')) as fh:
            rec = json.load(fh)
    except (OSError, ValueError):
        time.sleep(0.02)
        continue
    if rec.get('phase') != last or rec.get('state') not in ('queued', 'running'):
        last = rec.get('phase')
        say(phase=last, state=rec.get('state'), stopped_writers=rec.get('stopped_writers'))
    if rec.get('state') == 'running' and last in kill_phases:
        r = subprocess.run(['systemctl', 'kill', '--signal=SIGKILL', 'woowtech-backup-%s.service' % job],
                           capture_output=True)
        say(killed_in=last, rc=r.returncode, stopped_writers=rec.get('stopped_writers'))
        sys.exit(0)
    if rec.get('state') not in ('queued', 'running'):
        sys.exit(2)
    time.sleep(0.02)
sys.exit(3)
'''


class Watcher:
    """Runs WATCH inside a device; `events` collects its JSON lines; `wait_for(key)` blocks for one."""

    def __init__(self, dev, *, job='next', kill_phases=(), timeout=900):
        self.proc = subprocess.Popen([LP, 'exec', '-i', dev_name(dev), 'python3', '-I', '-', f'{DATA}/jobs', job,
                                      ','.join(kill_phases), str(timeout)], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.proc.stdin.write(WATCH.encode())
        self.proc.stdin.close()
        self.events = []
        self.cond = threading.Condition()
        self.thread = threading.Thread(target=self._read, daemon=True)
        self.thread.start()

    def _read(self):
        for line in self.proc.stdout:
            try:
                event = json.loads(line)
            except ValueError:
                continue
            with self.cond:
                self.events.append(event)
                self.cond.notify_all()
        with self.cond:
            self.events.append({'eof': True})
            self.cond.notify_all()

    def wait_for(self, predicate, timeout):
        deadline = time.monotonic() + timeout
        with self.cond:
            while True:
                for event in self.events:
                    if predicate(event):
                        return event
                if any(e.get('eof') for e in self.events):
                    return None
                left = deadline - time.monotonic()
                if left <= 0:
                    return None
                self.cond.wait(left)

    def stop(self):
        if self.proc.poll() is None:
            self.proc.kill()
        self.proc.wait(timeout=30)
        self.thread.join(timeout=5)
        return self.events


# ------------------------------------------------------------------ host-side cgroup memory meter

class CgroupMeter:
    """Exact peak memory of a device over a window (per-fd reset of memory.peak from the host) plus sampled
    memory.current and memory.stat (anon, file, kernel, shmem) every 0.25 s and memory.events deltas."""

    def __init__(self, dev, interval=0.25):
        path = subprocess.run([LP, 'inspect', '--format', '{{.State.CgroupPath}}', dev_name(dev)], capture_output=True,
                              check=True).stdout.decode().strip()
        self.base = Path('/sys/fs/cgroup' + path)
        self.interval = interval
        self.max_bytes = int((self.base / 'memory.max').read_text().strip())
        self.events0 = self._events()
        self.peak_fd = os.open(self.base / 'memory.peak', os.O_RDWR)
        os.write(self.peak_fd, b'reset\n')
        self.samples = []
        self.stop_flag = threading.Event()
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.t0 = time.monotonic()
        self.thread.start()

    def _events(self):
        return dict(line.split() for line in (self.base / 'memory.events').read_text().splitlines())

    def _stat(self):
        values = {}
        for line in (self.base / 'memory.stat').read_text().splitlines():
            key, _, value = line.partition(' ')
            if key in ('anon', 'file', 'kernel', 'shmem', 'sock'):
                values[key] = int(value)
        values['current'] = int((self.base / 'memory.current').read_text())
        return values

    def _loop(self):
        while not self.stop_flag.is_set():
            try:
                sample = self._stat()
                sample['t'] = round(time.monotonic() - self.t0, 2)
                self.samples.append(sample)
            except OSError:
                pass
            self.stop_flag.wait(self.interval)

    def stop(self):
        self.stop_flag.set()
        self.thread.join(timeout=5)
        peak = int(os.pread(self.peak_fd, 64, 0).decode().strip())
        os.close(self.peak_fd)
        events1 = self._events()
        mib = 1024 * 1024

        def top(key):
            return max((s.get(key, 0) for s in self.samples), default=0)
        non_reclaimable = max((s.get('anon', 0) + s.get('kernel', 0) + s.get('shmem', 0) for s in self.samples), default=0)
        return {'limit_mib': round(self.max_bytes / mib, 1), 'peak_mib': round(peak / mib, 1),
                'sampled_current_max_mib': round(top('current') / mib, 1),
                'sampled_anon_max_mib': round(top('anon') / mib, 1),
                'sampled_kernel_max_mib': round(top('kernel') / mib, 1),
                'sampled_shmem_max_mib': round(top('shmem') / mib, 1),
                'sampled_file_cache_max_mib': round(top('file') / mib, 1),
                'sampled_anon_kernel_shmem_max_mib': round(non_reclaimable / mib, 1),
                'samples': len(self.samples), 'seconds': round(time.monotonic() - self.t0, 1),
                'events_delta': {k: int(events1.get(k, 0)) - int(self.events0.get(k, 0)) for k in events1}}


# ------------------------------------------------------------------ H1: hostile archives (F5)

# Runs as root inside the device. Decrypts the base backup with the device key (both stay in the device),
# applies one defect and writes the re-encrypted `.woowbackup` (device recipient) to stdout. stderr gets a
# one-line description (member names only, never content).
CRAFT = r'''
import glob, hashlib, io, json, secrets, subprocess, sys, tarfile, time
case, base_id = sys.argv[1], sys.argv[2]
ENV = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}
def run(argv, data):
    proc = subprocess.run(argv, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=ENV)
    if proc.returncode != 0:
        sys.stderr.write('%s failed rc=%d\n' % (argv[0], proc.returncode))
        sys.exit(2)
    return proc.stdout
keyfiles = sorted(glob.glob('/etc/woowtech-cockpit/backup/keys/device-*.key'))
if len(keyfiles) != 1:
    sys.exit('need exactly one device key')
recipient = run(['age-keygen', '-y', keyfiles[0]], b'').decode().split()[0]
raw = open('/var/lib/woowtech-backup/archives/%s.woowbackup' % base_id, 'rb').read()
magic, rest = raw.split(b'\n', 1)
assert magic == b'WOOWTECH-BACKUP/1'
hline, cipher = rest.split(b'\n', 1)
old_header = json.loads(hline)
plain = run(['zstd', '-d', '-c', '-q'], run(['age', '-d', '-i', keyfiles[0]], cipher))
members = []
with tarfile.open(fileobj=io.BytesIO(plain), mode='r:') as tar:
    for info in tar:
        if not info.isreg():
            sys.exit('base archive has a non-regular member')
        members.append([info.name, tar.extractfile(info).read()])
assert members[0][0] == 'manifest.json'
manifest = json.loads(members[0][1])
body = members[1:]
now = time.gmtime()
new_id = time.strftime('%Y%m%dT%H%M%SZ', now) + '-' + secrets.token_hex(4)
created = time.strftime('%Y-%m-%dT%H:%M:%SZ', now)
manifest.update(backup_id=new_id, created=created, note='H1 ' + case)
header = {'format': 1, 'backup_id': new_id, 'created': created, 'key_id': old_header['key_id'],
          'encryption': 'age-x25519', 'compression': 'zstd'}
app = manifest['apps'][0]
APP = app['id']
def entry(name, data):
    return {'path': name, 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
def sync_entries():
    manifest['entries'] = [entry(n, d) for n, d in body]
def find(section, key, value):
    return next(item for item in app[section] if item[key] == value)
def info(name, size=0, kind=tarfile.REGTYPE, link=''):
    ti = tarfile.TarInfo(name)
    ti.size, ti.mode, ti.uid, ti.gid, ti.uname, ti.gname = size, 0o600, 0, 0, 'root', 'root'
    ti.mtime, ti.type, ti.linkname = int(time.time()), kind, link
    return ti
def manifest_member(pad=0):
    data = json.dumps(manifest, ensure_ascii=False, separators=(',', ':')).encode()
    return ['manifest.json', data + b' ' * pad]
def build(items, trailing=b''):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w', format=tarfile.PAX_FORMAT) as tar:
        for item in items:
            if isinstance(item, tarfile.TarInfo):
                tar.addfile(item)
            elif isinstance(item[0], tarfile.TarInfo):
                tar.addfile(item[0], io.BytesIO(item[1]))
            else:
                name, data = item
                tar.addfile(info(name, len(data)), io.BytesIO(data))
    return buf.getvalue() + trailing
def rename(old, new):
    for item in body:
        if item[0] == old:
            item[0] = new
    for section in ('images', 'postgres', 'volumes', 'secrets', 'config_files', 'quadlet_files'):
        for item in app[section]:
            if item.get('entry') == old:
                item['entry'] = new
config0 = app['config_files'][0]['entry']
secret0 = app['secrets'][0]['entry']
index = {n: i for i, (n, _d) in enumerate(body)}
items, trailing = None, b''
if case == 'control':
    sync_entries()
elif case in ('traversal-member', 'absolute-member'):
    sync_entries()
    evil = '../../../../../../tmp/woowbk-h1-traversal' if case == 'traversal-member' else '/tmp/woowbk-h1-absolute'
    items = [manifest_member(), [evil, b'pwned\n']] + body
elif case == 'pax-path-override':
    sync_entries()
    ti = info(config0, len(body[index[config0]][1]))
    ti.pax_headers = {'path': '../../../../../../tmp/woowbk-h1-pax'}
    items = [manifest_member()] + [x if x[0] != config0 else (ti, x[1]) for x in body]
elif case in ('symlink-member', 'hardlink-member', 'device-member', 'dir-member'):
    sync_entries()
    kind = {'symlink-member': tarfile.SYMTYPE, 'hardlink-member': tarfile.LNKTYPE, 'device-member': tarfile.CHRTYPE,
            'dir-member': tarfile.DIRTYPE}[case]
    link = {'symlink-member': '/root/woowbk-h1-symlink-target', 'hardlink-member': 'manifest.json'}.get(case, '')
    special = info(config0, 0, kind, link)
    if case == 'device-member':
        special.devmajor, special.devminor = 1, 3
    items = [manifest_member()] + [x if x[0] != config0 else special for x in body]
elif case == 'extra-member':
    sync_entries()
    items = [manifest_member()] + body + [['apps/%s/config/9' % APP, b'EXTRA=1\n']]
elif case == 'missing-member':
    sync_entries()
    items = [manifest_member()] + body[:-1]
elif case == 'duplicate-member':
    sync_entries()
    items = [manifest_member(), body[0]] + body
elif case == 'reordered-members':
    sync_entries()
    items = [manifest_member(), body[1], body[0]] + body[2:]
elif case in ('size-lie-smaller', 'size-lie-larger', 'checksum-lie'):
    sync_entries()
    data = body[index[config0]][1]
    if case == 'size-lie-smaller':
        forged = data + b'# woowbk-h1 smuggled line\n'
    elif case == 'size-lie-larger':
        forged = data[:-1]
    else:
        forged = data[:-2] + bytes([data[-2] ^ 1]) + data[-1:]
    items = [manifest_member()] + [x if x[0] != config0 else [config0, forged] for x in body]
elif case == 'trailing-data':
    sync_entries()
    trailing = b'\x01woowbk-h1 trailing garbage after the end-of-archive marker\n'
elif case == 'manifest-not-first':
    sync_entries()
    items = [body[0], manifest_member()] + body[1:]
elif case == 'header-mismatch':
    sync_entries()
    manifest['backup_id'] = time.strftime('%Y%m%dT%H%M%SZ', now) + '-' + secrets.token_hex(4)
elif case == 'traversal-entry':
    rename(config0, 'apps/%s/config/../../../../tmp/woowbk-h1-entry' % APP)
    sync_entries()
elif case == 'duplicate-entry':
    sync_entries()
    manifest['entries'].insert(1, dict(manifest['entries'][0]))
    items = [manifest_member(), body[0]] + body
elif case == 'entry-other-app':
    rename(secret0, secret0.replace('apps/%s/' % APP, 'apps/woowbk-h1-other/'))
    sync_entries()
elif case in ('config-outside-prefix', 'config-dotdot', 'config-mode'):
    path = {'config-outside-prefix': '.ssh/authorized_keys', 'config-dotdot': '.config/../.ssh/authorized_keys',
            'config-mode': '.config/woowbk-h1/mode.env'}[case]
    app['config_files'].append({'path': path, 'mode': '0755' if case == 'config-mode' else '0600',
                                'entry': 'apps/%s/config/7' % APP})
    body.append(['apps/%s/config/7' % APP, b'ssh-ed25519 AAAAwoowbkh1 attacker\n'])
    sync_entries()
elif case == 'owner-root':
    app['owner'] = {'name': 'root', 'uid': 0}
    sync_entries()
elif case == 'oversize-manifest':
    sync_entries()
    size = len(manifest_member()[1])
    items = [manifest_member(pad=1024 * 1024 + 1 - size)] + body
elif case == 'too-many-members':
    sync_entries()
    while len(manifest['entries']) < 4000:
        manifest['entries'].append({'path': 'apps/%s/config/x%d' % (APP, len(manifest['entries'])), 'size': 1,
                                    'sha256': '0' * 64})
elif case == 'unknown-app':
    for item in body:
        item[0] = item[0].replace('apps/%s/' % APP, 'apps/woowbk-h1-evil/', 1)
    for section in ('images', 'postgres', 'volumes', 'secrets', 'config_files', 'quadlet_files'):
        for item in app[section]:
            if 'entry' in item:
                item['entry'] = item['entry'].replace('apps/%s/' % APP, 'apps/woowbk-h1-evil/', 1)
    app['id'], app['name'] = 'woowbk-h1-evil', 'H1 未登錄的應用'
    sync_entries()
elif case == 'undeclared-items':
    vol = io.BytesIO()
    with tarfile.open(fileobj=vol, mode='w', format=tarfile.PAX_FORMAT) as tar:
        payload = b'woowbk-h1 volume content\n'
        tar.addfile(info('woowbk-h1-evil.txt', len(payload)), io.BytesIO(payload))
    extra = [
        ('config_files', {'path': '.config/woowbk-h1/evil.env', 'mode': '0644', 'entry': 'apps/%s/config/1' % APP},
         b'WOOWBK_H1=1\n'),
        ('secrets', {'name': 'woowbk-h1-evil-secret', 'entry': 'apps/%s/secrets/woowbk-h1-evil-secret' % APP},
         b'woowbk-h1-not-a-real-secret'),
        ('volumes', {'name': 'woowbk-h1-evil-vol', 'entry': 'apps/%s/volumes/woowbk-h1-evil-vol.tar' % APP},
         vol.getvalue()),
        ('quadlet_files', {'name': 'woowbk-h1-evil.container',
                           'entry': 'apps/%s/quadlet/woowbk-h1-evil.container' % APP},
         b'[Container]\nImage=localhost/woowbk-h1-evil:1\nExec=/bin/sh -c "touch /tmp/woowbk-h1-quadlet-ran"\n'),
        ('images', {'ref': 'localhost/woowbk-h1-evil:1', 'id': 'sha256:' + 'ab' * 32, 'digest': '', 'arch': 'amd64',
                    'entry': 'apps/%s/images/9.oci.tar' % APP}, b'not an image archive (woowbk-h1)\n'),
        ('postgres', {'id': 'woowbk-h1-evil', 'database': 'evil', 'server_version': '16.4', 'major': 16,
                      'entry': 'apps/%s/postgres/woowbk-h1-evil.dump' % APP}, b'not a dump (woowbk-h1)\n'),
    ]
    for section, item, data in extra:
        app[section].append(item)
        body.append([item['entry'], data])
    sync_entries()
else:
    sys.exit('unknown case ' + case)
if items is None:
    items = [manifest_member()] + body
tar_bytes = build(items, trailing)
out = (b'WOOWTECH-BACKUP/1\n' + json.dumps(header, separators=(',', ':')).encode() + b'\n'
       + run(['age', '-e', '-r', recipient], run(['zstd', '-q', '-c', '-3'], tar_bytes)))
sys.stdout.buffer.write(out)
names = [i.name if isinstance(i, tarfile.TarInfo) else (i[0].name if isinstance(i[0], tarfile.TarInfo) else i[0])
         for i in items]
sys.stderr.write(json.dumps({'case': case, 'backup_id': new_id, 'members': len(items), 'entries': len(manifest['entries']),
                             'first_names': names[:4], 'last_name': names[-1], 'tar_bytes': len(tar_bytes)}) + '\n')
'''

# expected outcome per case: inspect (ok | error code), verify job (succeeded | error code), restore job
# (error code, phase that must fail) or 'succeeded'/None (not attempted)
MEMBER_DEFECT = {'inspect': 'ok', 'verify': 'corrupt-archive', 'restore': ('corrupt-archive', 'decrypt')}
H1_CASES = {
    'control': {'inspect': 'ok', 'verify': 'succeeded', 'restore': None},
    'traversal-member': MEMBER_DEFECT, 'absolute-member': MEMBER_DEFECT, 'pax-path-override': MEMBER_DEFECT,
    'symlink-member': MEMBER_DEFECT, 'hardlink-member': MEMBER_DEFECT, 'device-member': MEMBER_DEFECT,
    'dir-member': MEMBER_DEFECT, 'extra-member': MEMBER_DEFECT, 'missing-member': MEMBER_DEFECT,
    'duplicate-member': MEMBER_DEFECT, 'reordered-members': MEMBER_DEFECT, 'size-lie-smaller': MEMBER_DEFECT,
    'size-lie-larger': MEMBER_DEFECT, 'checksum-lie': MEMBER_DEFECT, 'trailing-data': MEMBER_DEFECT,
    'manifest-not-first': {'inspect': 'corrupt-archive', 'verify': 'corrupt-archive',
                           'restore': ('corrupt-archive', 'decrypt')},
    'header-mismatch': {'inspect': 'corrupt-archive', 'verify': 'corrupt-archive',
                        'restore': ('corrupt-archive', 'decrypt')},
    **{case: {'inspect': 'invalid-manifest', 'verify': 'invalid-manifest', 'restore': ('invalid-manifest', 'decrypt')}
       for case in ('traversal-entry', 'duplicate-entry', 'entry-other-app', 'config-outside-prefix', 'config-dotdot',
                    'config-mode', 'owner-root')},
    **{case: {'inspect': 'limit-exceeded', 'verify': 'limit-exceeded', 'restore': ('limit-exceeded', 'decrypt')}
       for case in ('oversize-manifest', 'too-many-members')},
    'unknown-app': {'inspect': 'ok', 'verify': 'succeeded', 'restore': ('incompatible', 'preflight')},
    'undeclared-items': {'inspect': 'ok', 'verify': 'succeeded', 'restore': 'succeeded'},
}


def craft(dev, case, base_id, ev):
    proc = subprocess.run([LP, 'exec', '-i', dev_name(dev), 'python3', '-I', '-', case, base_id], input=CRAFT.encode(),
                          capture_output=True, timeout=300)
    if proc.returncode != 0:
        raise Failed(f'craft {case}: rc={proc.returncode} {redact(proc.stderr.decode("utf-8", "replace")[-400:])}')
    meta = json.loads(proc.stderr.decode().strip().splitlines()[-1])
    path = private_dir(WORK / 'h1') / f'{case}.woowbackup'
    e2e.write_private(path, proc.stdout)
    meta.update(file=str(path), size=len(proc.stdout), sha256=hashlib.sha256(proc.stdout).hexdigest())
    return meta


def error_code(reply):
    return 'ok' if reply.get('ok') else reply['error']['code']


def h1_case(ev, dev, case, base_id, baseline):
    expect = H1_CASES[case]
    record = {'case': case, 'expect': {k: list(v) if isinstance(v, tuple) else v for k, v in expect.items()}}
    meta = craft(dev, case, base_id, ev)
    record['crafted'] = meta
    backup_id = meta['backup_id']
    ev.log(f'[{case}] crafted {meta["size"]} bytes, backup {backup_id}, first members {meta["first_names"]}')
    t_start = device_clock(dev)
    before_ids = backup_ids(dev, ev)

    # 1. upload exactly like the page: upload-begin -> fsreplace1 -> upload-finish
    _begin, (_rc, reply) = e2e.upload_file(dev, meta['file'], ev=ev, filename=f'woowbk-h1-{case}.woowbackup')
    record['upload_finish'] = error_code(reply)
    if not ev.check(f'H1 {case}: upload-finish accepts it (outer header and age header are valid)', reply.get('ok'),
                    reply.get('error')):
        return record
    ev.check(f'H1 {case}: uploaded as type uploaded with the crafted id', reply['backup']['id'] == backup_id
             and reply['backup']['type'] == 'uploaded' and reply['backup']['key_available'] is True, reply['backup'])

    # 2. inspect (manifest only) as the restore wizard does
    _rc, inspected = helper(dev, 'inspect', {'backup_id': backup_id}, ev=ev)
    record['inspect'] = error_code(inspected)
    if inspected.get('ok'):
        record['preflight'] = inspected['preflight']
    ev.check(f'H1 {case}: inspect -> {expect["inspect"]}', record['inspect'] == expect['inspect'],
             inspected.get('error') or {'preflight_ok': inspected['preflight']['ok']})

    # 3. full verification job
    start = ok(dev, 'verify-start', {'backup_id': backup_id, 'request_id': request_id()}, ev=ev)
    vjob, vlog = wait_job(dev, start['job_id'], ev=ev, timeout=300, label=f'verify[{case}]')
    record['verify'] = vjob['state'] if vjob['state'] == 'succeeded' else (vjob.get('error') or {}).get('code')
    record['verify_log_tail'] = vlog[-4:]
    ev.check(f'H1 {case}: verify job -> {expect["verify"]}', record['verify'] == expect['verify'],
             {'state': vjob['state'], 'error': vjob.get('error')})
    meta_after = next((b for b in backups(dev, ev) if b['id'] == backup_id), {})
    if expect['verify'] != 'succeeded':
        ev.check(f'H1 {case}: BackupMeta.verified.ok is false after the failed verify',
                 (meta_after.get('verified') or {}).get('ok') is False, meta_after.get('verified'))
    record['reason'] = rejection_reason(dev, backup_id)
    ev.log(f'[{case}] engine verifier says: {record["reason"]}')

    # 4. restore attempt (what a user would do after ignoring every warning)
    if expect['restore'] is not None:
        rstart = ok(dev, 'restore-start', {'backup_id': backup_id, 'apps': [APP], 'request_id': request_id(),
                                          'confirm': True}, ev=ev)
        rjob, rlog = wait_job(dev, rstart['job_id'], ev=ev, timeout=900, label=f'restore[{case}]')
        record['restore'] = {'state': rjob['state'], 'error': rjob.get('error'), 'phases': phase_states(rjob),
                             'result': rjob.get('result'), 'log_tail': rlog[-8:]}
        if expect['restore'] == 'succeeded':
            ev.check(f'H1 {case}: in-place restore succeeds (items unknown to the local catalog are ignored)',
                     rjob['state'] == 'succeeded', rjob.get('error'))
        else:
            code, phase = expect['restore']
            ev.check(f'H1 {case}: restore job fails with {code} in phase {phase}, before any destructive step',
                     rjob['state'] == 'failed' and (rjob.get('error') or {}).get('code') == code
                     and phase_states(rjob).get(phase) == 'failed' and phase_states(rjob).get('safety') == 'pending'
                     and phase_states(rjob).get('stop') == 'pending',
                     {'state': rjob['state'], 'error': rjob.get('error'), 'phases': phase_states(rjob)})
        save_job(ev, f'h1-{case}-restore', rjob, rlog)

    if case == 'unknown-app':
        apps = (record.get('preflight') or {}).get('apps') or []
        ev.check('H1 unknown-app: preflight marks the app not restorable because the local catalog lacks it',
                 len(apps) == 1 and apps[0]['id'] == 'woowbk-h1-evil' and apps[0]['restorable'] is False
                 and any(c['status'] == 'fail' and c['id'].endswith('/catalog') for c in apps[0]['checks']), apps)
        jobs_before = {j['id'] for j in ok(dev, 'jobs', ev=ev)['jobs']}
        _rc, reply = helper(dev, 'restore-start', {'backup_id': backup_id, 'apps': ['woowbk-h1-evil'],
                                                   'request_id': request_id(), 'confirm': True}, ev=ev)
        ev.check('H1 unknown-app: restore-start for the archive app id -> app-not-in-catalog, no job created',
                 error_code(reply) == 'app-not-in-catalog'
                 and {j['id'] for j in ok(dev, 'jobs', ev=ev)['jobs']} == jobs_before, reply.get('error'))

    # 5. nothing escaped staging, staging and keys cleaned, app untouched, no new backups but the upload
    unexpected, counts = changed_since(dev, t_start)
    record['changed_scan'] = {'unexpected': unexpected, 'counts': counts,
                              'foreign_podman_events_in_window': foreign_activity(dev, t_start)}
    if expect['restore'] != 'succeeded':
        ev.check(f'H1 {case}: no file written or changed outside the engine records/staging during the attempt',
                 unexpected == {}, unexpected)
        ev.check(f'H1 {case}: app data, deployment files, volumes and secrets unchanged; units active',
                 content_state(dev) == baseline['content'] and owner_fingerprint(dev) == baseline['owner']
                 and units_active(dev)[0])
    found = canaries(dev, 'woowbk-h1')
    ev.check(f'H1 {case}: no woowbk-h1 path exists anywhere on the device', found == [], found)
    ev.check(f'H1 {case}: staging empty, no job key files, no orphan archive files',
             staging_empty(dev) and no_job_keys(dev) and orphans(dev) == [], {'orphans': orphans(dev)})
    new_ids = backup_ids(dev, ev) - before_ids
    record['new_backups'] = sorted(new_ids)
    if expect['restore'] != 'succeeded':
        ev.check(f'H1 {case}: no backup listed except the upload itself', new_ids == {backup_id}, sorted(new_ids))
    return record


def save_job(ev, name, job, log):
    ev.save(name, {'job': job, 'log': log})


def scenario_h1(ev):
    dev = 'a'
    cases = [c for c in os.environ.get('H1_CASES', '').split(',') if c] or list(H1_CASES)
    status = ok(dev, 'status', ev=ev)
    ev.require('dev-a: device key present and app running',
               status['key'] and next(a for a in status['apps'] if a['id'] == APP)['state'] == 'running',
               status.get('key'))
    ev.require('dev-a: no orphan archives and empty staging before H1', orphans(dev) == [] and staging_empty(dev),
               orphans(dev))
    scanner_selftest(dev, ev)
    # Fresh base backup (no images) of the current state: every crafted archive starts from real app data,
    # so an archive that is accepted would really restore; only the injected defect may stop it.
    start = ok(dev, 'backup-start', {'apps': [APP], 'include_images': False, 'note': 'H1 惡意封存的基礎備份',
                                     'request_id': request_id()}, ev=ev)
    job, _log = wait_job(dev, start['job_id'], ev=ev, label='base-backup')
    ev.require('H1 base backup (no images) succeeded', job['state'] == 'succeeded', job.get('error'))
    base_id = job['result']['backup_id']
    baseline = {'summary': summary(dev), 'content': content_state(dev), 'owner': owner_fingerprint(dev)}
    ev.save('h1-baseline', {'base_backup': base_id, 'summary': baseline['summary']})
    results = []
    for case in cases:
        try:
            results.append(h1_case(ev, dev, case, base_id, baseline))
        except Failed as error:
            ev.check(f'H1 {case}: scenario ran to completion', False, str(error))
            results.append({'case': case, 'aborted': str(error)})
        finally:
            ev.save('h1-cases', results)
    # The undeclared-items restore must have ignored every extra item and kept the data.
    if 'undeclared-items' in cases:
        rec = next(r for r in results if r['case'] == 'undeclared-items')
        warn = [c for a in (rec.get('preflight') or {}).get('apps', []) for c in a['checks'] if c['status'] == 'warn']
        ev.check('H1 undeclared-items: preflight reports the extra config/secret/volume/database as ignored (warn)',
                 any('.config/woowbk-h1/evil.env' in c['message'] and 'woowbk-h1-evil-secret' in c['message']
                     and 'woowbk-h1-evil-vol' in c['message'] for c in warn), [c['message'] for c in warn])
        ev.check('H1 undeclared-items: the extra Quadlet file and image are not mentioned by preflight (never used)',
                 not any('woowbk-h1-evil.container' in c['message'] or 'woowbk-h1-evil:1' in c['message']
                         for a in (rec.get('preflight') or {}).get('apps', []) for c in a['checks']))
        leftovers = owner(dev, 'sh', '-c', 'cd "$HOME"; ls -A .config | grep woowbk-h1; '
                          'podman secret exists woowbk-h1-evil-secret && echo secret; '
                          'podman volume exists woowbk-h1-evil-vol && echo volume; '
                          'podman image exists localhost/woowbk-h1-evil:1 && echo image; '
                          'ls .config/containers/systemd | grep woowbk-h1; true').stdout.decode().split()
        ev.check('H1 undeclared-items: no extra config file, secret, volume, image or Quadlet file was created',
                 leftovers == [], leftovers)
        ev.check('H1 undeclared-items: data after the restore equals the base backup (= state before H1)',
                 compare(summary(dev), baseline['summary']) == {} and content_state(dev) == baseline['content'])
        ev.check('H1 undeclared-items: deployment files unchanged by the restore', owner_fingerprint(dev) == baseline['owner'])
    # Clean up: the crafted uploads and the base backup (safety backups of the restore stay, pruned to 3).
    for rec in results:
        backup_id = (rec.get('crafted') or {}).get('backup_id')
        if backup_id and backup_id in backup_ids(dev, ev):
            ok(dev, 'delete', {'backup_id': backup_id}, ev=ev)
    ok(dev, 'delete', {'backup_id': base_id}, ev=ev)
    ev.check('dev-a after H1: app running, staging empty, no orphans', app_status(dev, ev)['state'] == 'running'
             and staging_empty(dev) and orphans(dev) == [])
    table = {r['case']: {k: r.get(k) for k in ('upload_finish', 'inspect', 'verify')} | {
        'restore': (r.get('restore') or {}).get('state') and
        f'{r["restore"]["state"]}:{(r["restore"].get("error") or {}).get("code")}'} for r in results}
    ev.save('h1-summary', table)
    return {'cases': table}


# ------------------------------------------------------------------ pg_dump fault injection (H3, H4)

DB_CONTAINER = 'woowbk-demo-db'
REAL_DUMP = '/usr/local/bin/pg_dump.woowbk-real'
PG_DUMP_FAULTS = {
    # pg_dump writes part of the dump, then fails (what a crash or a lost connection looks like)
    'fails': f'{REAL_DUMP} "$@" | head -c 4096\necho "pg_dump: error: injected failure (woowbk hardening)" >&2\nexit 1',
    # pg_dump "succeeds" but the stream lost its last 64 bytes (silent truncation of the tail)
    'truncated-exit0': (f'{REAL_DUMP} "$@" > /tmp/woowbk-dump.$$ || exit $?\nsize=$(wc -c < /tmp/woowbk-dump.$$)\n'
                        'head -c $((size - 64)) /tmp/woowbk-dump.$$\nrm -f /tmp/woowbk-dump.$$\nexit 0'),
    # pg_dump "succeeds" but only the first half of the stream arrived (the table data is cut)
    'truncated-half-exit0': (f'{REAL_DUMP} "$@" > /tmp/woowbk-dump.$$ || exit $?\nsize=$(wc -c < /tmp/woowbk-dump.$$)\n'
                             'head -c $((size / 2)) /tmp/woowbk-dump.$$\nrm -f /tmp/woowbk-dump.$$\nexit 0'),
    # the database goes away while the dump runs (fast shutdown of the server, the container exits)
    'db-stopped': ('su-exec postgres pg_ctl -D /var/lib/postgresql/data -m fast -w stop >/dev/null 2>&1\n'
                   'echo "pg_dump: error: server closed the connection (woowbk hardening)" >&2\nexit 1'),
    # slow dump: holds the job in the dump phase (writers stopped) so it can be killed there
    'slow': f'sleep 25\nexec {REAL_DUMP} "$@"',
}


def inject_pg_dump(dev, fault):
    body = PG_DUMP_FAULTS[fault]
    script = (f'set -e; cd /usr/local/bin; [ -e {REAL_DUMP} ] || mv pg_dump {REAL_DUMP}\n'
              f"cat > pg_dump.woowbk-new <<'EOF'\n#!/bin/sh\n# woowbk hardening fault injection (lab only)\n{body}\nEOF\n"
              'chmod 0755 pg_dump.woowbk-new; mv -f pg_dump.woowbk-new pg_dump')
    owner(dev, 'podman', 'exec', '-u', '0', DB_CONTAINER, 'sh', '-c', script)


def restore_pg_dump(dev):
    """Put the real pg_dump back (a recreated container already has it); returns `pg_dump --version`."""
    script = f'cd /usr/local/bin; if [ -e {REAL_DUMP} ]; then mv -f {REAL_DUMP} pg_dump; fi; pg_dump --version'
    for _ in range(30):
        proc = owner(dev, 'podman', 'exec', '-u', '0', DB_CONTAINER, 'sh', '-c', script, check=False)
        if proc.returncode == 0:
            return proc.stdout.decode().strip()
        time.sleep(2)
    return f'unavailable rc={proc.returncode}'


def backup_once(dev, ev, note, *, images=False, label='backup', timeout=1800):
    start = ok(dev, 'backup-start', {'apps': [APP], 'include_images': images, 'note': note,
                                     'request_id': request_id()}, ev=ev)
    job, log = wait_job(dev, start['job_id'], ev=ev, timeout=timeout, label=label)
    return job, log


def failed_backup_checks(ev, dev, tag, job, before_ids, health):
    ev.check(f'{tag}: app units active and /healthz 200 afterwards', units_active(dev)[0] and wait_healthy(dev, 120),
             units_active(dev)[1])
    ev.check(f'{tag}: writers were paused only briefly (longest /healthz outage {health["longest_unhealthy_s"]} s)',
             health['longest_unhealthy_s'] < 60, health)
    ev.check(f'{tag}: nothing new listed', backup_ids(dev, ev) == before_ids, sorted(backup_ids(dev, ev) - before_ids))
    ev.check(f'{tag}: staging removed, no orphan archive or temp file, no job key',
             staging_empty(dev) and orphans(dev) == [] and no_job_keys(dev), {'orphans': orphans(dev)})
    ev.check(f'{tag}: job log says the writer was restarted',
             any('已恢復服務 woowbk-demo-app.service' in line for line in job.get('_log', [])), job.get('_log', [])[-6:])


def scenario_h3(ev):
    dev = 'a'
    ev.require('dev-a idle: no active job', ok(dev, 'status', ev=ev)['active_job'] is None)
    ev.log(f'pg_dump in the database container: {restore_pg_dump(dev)}')
    results = {}
    try:
        for fault in [f for f in os.environ.get('H3_FAULTS', 'fails,truncated-exit0,truncated-half-exit0,db-stopped').split(',') if f]:
            tag = f'H3 {fault}'
            before_ids = backup_ids(dev, ev)
            before = {'summary': summary(dev), 'content': content_state(dev)}
            inject_pg_dump(dev, fault)
            monitor = e2e.HealthMonitor(dev, 900)
            job, log = backup_once(dev, ev, f'H3 pg_dump {fault}', label=f'backup[{fault}]')
            health = monitor.stop()
            job['_log'] = log
            save_job(ev, f'h3-{fault}-job', job, log)
            ev.log(f'{tag}: phases {phase_states(job)}')
            results[fault] = {'state': job['state'], 'error': job.get('error'), 'phases': phase_states(job),
                              'health': health, 'log_tail': log[-10:]}
            version = restore_pg_dump(dev)
            ev.log(f'{tag}: pg_dump restored: {version}')
            if job['state'] == 'succeeded':
                # The dump exited 0 but lost bytes. Acceptable only if the backup really restores the same data.
                backup_id = job['result']['backup_id']
                results[fault]['listed_backup'] = backup_id
                rjob = probe_restore(dev, ev, backup_id, f'h3-{fault}')
                results[fault]['restore_of_that_backup'] = rjob
                ev.check(f'{tag}: a backup listed as verified despite the damaged dump really restores '
                         '(in-place restore succeeds and the data verification matches)',
                         rjob['state'] == 'succeeded', rjob)
                ok(dev, 'delete', {'backup_id': backup_id}, ev=ev)
                continue
            ev.check(f'{tag}: backup job failed with job-failed (pg_dump step)', job['state'] == 'failed'
                     and (job.get('error') or {}).get('code') == 'job-failed', job.get('error'))
            ev.check(f'{tag}: the failure is attributed to the database export (dump phase failed, later phases not run)',
                     phase_states(job).get('dump') == 'failed' and phase_states(job).get('export') in ('pending', 'skipped')
                     and phase_states(job).get('package') in ('pending', 'skipped'), phase_states(job))
            failed_backup_checks(ev, dev, tag, job, before_ids, health)
            ev.check(f'{tag}: application data unchanged', compare(summary(dev), before['summary']) == {}
                     and content_state(dev) == before['content'])
    finally:
        ev.log(f'pg_dump after H3: {restore_pg_dump(dev)}')
    job, _log = backup_once(dev, ev, 'H3 之後的正常備份', label='backup[after]')
    ev.check('H3: with the real pg_dump back, the next backup succeeds', job['state'] == 'succeeded', job.get('error'))
    if job['state'] == 'succeeded':
        ok(dev, 'delete', {'backup_id': job['result']['backup_id']}, ev=ev)
    return {'faults': results}


def probe_restore(dev, ev, backup_id, tag):
    """In-place restore of a suspicious backup: must fail safely (rollback, data equal to before)."""
    pre, pre_content = summary(dev), content_state(dev)
    start = ok(dev, 'restore-start', {'backup_id': backup_id, 'apps': [APP], 'request_id': request_id(),
                                      'confirm': True}, ev=ev)
    job, log = wait_job(dev, start['job_id'], ev=ev, label=f'restore[{tag}]')
    save_job(ev, f'{tag}-restore-job', job, log)
    ev.log(f'{tag}: restore of the suspicious backup ended {job["state"]} {job.get("error")}')
    ev.check(f'{tag}: whatever the restore outcome, the data afterwards equals the state before the restore',
             job['state'] in ('succeeded', 'rolled-back') and compare(summary(dev), pre) == {}
             and content_state(dev) == pre_content, {'state': job['state']})
    return {'state': job['state'], 'error': job.get('error'), 'phases': phase_states(job), 'log_tail': log[-8:]}


def wait_unit_gone(dev, job_id, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state = sh(dev, f'systemctl show --property=ActiveState --value woowtech-backup-{job_id}.service',
                   check=False).stdout.decode().strip()
        if state in ('inactive', 'failed', ''):
            return state or 'gone'
        time.sleep(0.3)
    return 'still-active'


H4_KILLS = {
    # name: (kill phases, pg_dump fault to hold the window open or None, include images)
    'dump': (('dump',), 'slow', False),
    'export': (('export',), None, False),
    'stop': (('stop',), None, False),
    'package': (('package',), None, True),
    'verify': (('verify',), None, True),
}


def scenario_h4(ev):
    dev = 'a'
    ev.require('dev-a idle: no active job', ok(dev, 'status', ev=ev)['active_job'] is None)
    results = {}
    names = [n for n in os.environ.get('H4_KILLS', ','.join(H4_KILLS)).split(',') if n]
    try:
        for name in names:
            phases, fault, images = H4_KILLS[name]
            tag = f'H4 kill in {name}'
            before_ids = backup_ids(dev, ev)
            before = {'summary': summary(dev), 'content': content_state(dev)}
            if fault:
                inject_pg_dump(dev, fault)
            watcher = Watcher(dev, kill_phases=phases, timeout=600)
            ev.require(f'{tag}: watcher ready', watcher.wait_for(lambda e: e.get('ready'), 60))
            start = ok(dev, 'backup-start', {'apps': [APP], 'include_images': images, 'note': f'H4 {name}',
                                             'request_id': request_id()}, ev=ev)
            killed = watcher.wait_for(lambda e: 'killed_in' in e or e.get('eof'), 600)
            events = watcher.stop()
            if fault:
                ev.log(f'{tag}: pg_dump restored: {restore_pg_dump(dev)}')
            ev.log(f'{tag}: watcher events {events}')
            if not ev.check(f'{tag}: job {start["job_id"]} was SIGKILLed in phase {name}',
                            killed and killed.get('killed_in') in phases and killed.get('rc') == 0, killed):
                wait_job(dev, start['job_id'], ev=ev, label='unkilled')
                results[name] = {'killed': False, 'events': events}
                continue
            unit = wait_unit_gone(dev, start['job_id'])
            # Observe the device *before* any helper call (status/jobs/job-status run the recovery).
            app_before_recovery = units_active(dev)[1]
            record_raw = json.loads(sh(dev, f'cat {DATA}/jobs/{start["job_id"]}.json').stdout)
            staging_before = sh(dev, f'ls -A {DATA}/staging').stdout.decode().split()
            ev.log(f'{tag}: unit {unit}; before recovery: record state {record_raw["state"]} phase {record_raw["phase"]}, '
                   f'stopped_writers {record_raw.get("stopped_writers")}, units {app_before_recovery}, '
                   f'staging {staging_before}, archives orphans {orphans(dev)}')
            orphan_before = orphans(dev)
            job, log = wait_job(dev, start['job_id'], ev=ev, timeout=120, label=f'killed[{name}]')
            save_job(ev, f'h4-{name}-job', job, log)
            writers_were_stopped = bool(record_raw.get('stopped_writers'))
            results[name] = {'killed_in': killed.get('killed_in'), 'stopped_writers_recorded': record_raw.get('stopped_writers'),
                             'units_before_recovery': app_before_recovery, 'staging_before_recovery': staging_before,
                             'orphans_before_recovery': orphan_before, 'state': job['state'], 'error': job.get('error'),
                             'phases': phase_states(job), 'log_tail': log[-6:]}
            ev.check(f'{tag}: the job becomes interrupted with zh-TW guidance', job['state'] == 'interrupted'
                     and (job.get('error') or {}).get('code') == 'job-failed'
                     and '備份作業意外中斷' in job['error']['message'], job.get('error'))
            if app_before_recovery != ['active', 'active']:
                # The kill left the writer stopped: only the recovery (job-status) can have restarted it.
                ev.check(f'{tag}: the writer was down after the kill; recovery restarted it and says so',
                         writers_were_stopped and units_active(dev)[0]
                         and '被暫停的應用服務已自動重新啟動' in job['error']['message'],
                         {'before': app_before_recovery, 'after': units_active(dev)[1],
                          'recorded': record_raw.get('stopped_writers')})
            else:
                ev.log(f'{tag}: the app was still running after the kill (stop not issued yet or already restarted)')
            ev.check(f'{tag}: app healthy after recovery', units_active(dev)[0] and wait_healthy(dev, 120),
                     units_active(dev)[1])
            ev.check(f'{tag}: staging removed by recovery, no job key', staging_empty(dev) and no_job_keys(dev),
                     sh(dev, f'ls -A {DATA}/staging').stdout.decode())
            ev.check(f'{tag}: nothing new listed and no orphan archive file left behind',
                     backup_ids(dev, ev) == before_ids and orphans(dev) == [],
                     {'new': sorted(backup_ids(dev, ev) - before_ids), 'orphans': orphans(dev)})
            ev.check(f'{tag}: application data unchanged', compare(summary(dev), before['summary']) == {}
                     and content_state(dev) == before['content'])
            ev.check(f'{tag}: nothing is replayed (job-status keeps interrupted)',
                     helper(dev, 'job-status', {'job_id': start['job_id']})[1]['job']['state'] == 'interrupted')
            job, _log = backup_once(dev, ev, f'H4 {name} 之後的備份', label=f'backup[after-{name}]')
            ev.check(f'{tag}: the next backup succeeds', job['state'] == 'succeeded', job.get('error'))
            if job['state'] == 'succeeded':
                ok(dev, 'delete', {'backup_id': job['result']['backup_id']}, ev=ev)
    finally:
        ev.log(f'pg_dump after H4: {restore_pg_dump(dev)}')
    return {'kills': results}


# ------------------------------------------------------------------ H2: insufficient space (F6)

H2_TMPFS = os.environ.get('H2_TMPFS', '600m')
RESERVE = 512 * 1024 * 1024
MIB = 1024 * 1024


def fs_type(dev, path):
    return sh(dev, f'findmnt -n -o FSTYPE --target {path}').stdout.decode().strip()


def scenario_h2(ev):
    """A small tmpfs is mounted over /var/lib/woowtech-backup inside the device (the real data stays below it,
    untouched, and is visible again after umount). The engine sees a 600 MiB backup filesystem."""
    dev = 'a'
    status = ok(dev, 'status', ev=ev)
    ev.require('dev-a idle and the data dir is the normal ext4 volume',
               status['active_job'] is None and fs_type(dev, DATA) == 'ext4', fs_type(dev, DATA))
    before_ids = backup_ids(dev, ev)
    big = max(e2e.DOWNLOADS.glob('*.woowbackup'), key=lambda p: p.stat().st_size)
    ev.log(f'foreign podman events in the last 10 min before the mount: {foreign_activity(dev, time.time() - 600)}')
    sh(dev, f'mount -t tmpfs -o size={H2_TMPFS},mode=0700 woowbk-h2 {DATA}')
    ev.log(f'mounted tmpfs size={H2_TMPFS} over {DATA} at {time.strftime("%H:%M:%S")}')
    results = {}
    try:
        storage = ok(dev, 'status', ev=ev)['storage']
        results['storage_on_tmpfs'] = storage
        ev.check('H2: the engine sees the small filesystem (no backups, ~600 MiB total)',
                 storage['backup_count'] == 0 and storage['total_bytes'] < 700 * MIB, storage)
        monitor = e2e.HealthMonitor(dev, 600)
        job, log = backup_once(dev, ev, 'H2 空間不足（含映像）', images=True, label='backup[images]')
        health = monitor.stop()
        save_job(ev, 'h2-backup-images-job', job, log)
        estimate = next((line for line in log if '預估資料量' in line), '')
        results['backup_with_images'] = {'state': job['state'], 'error': job.get('error'), 'phases': phase_states(job),
                                         'estimate_line': estimate, 'health': health}
        ev.log(f'H2 estimate: {estimate}')
        ev.check('H2: backup with images fails with insufficient-space', job['state'] == 'failed'
                 and (job.get('error') or {}).get('code') == 'insufficient-space', job.get('error'))
        ev.check('H2: it failed in the check phase, before any writer was stopped',
                 phase_states(job).get('check') == 'failed' and phase_states(job).get('stop') == 'pending'
                 and not any('暫停寫入服務' in line for line in log), phase_states(job))
        ev.check('H2: the app never went down during the attempt (/healthz sampled every 0.25 s)',
                 health['unhealthy_samples'] == 0 and health['samples'] > 0 and units_active(dev)[0], health)
        ev.check('H2: nothing listed, staging empty, archives/ empty',
                 backups(dev, ev) == [] and staging_empty(dev) and archive_dir_listing(dev) == [])

        free = ok(dev, 'status', ev=ev)['storage']['free_bytes']
        max_size = free - RESERVE
        results['free_bytes'], results['max_upload'] = free, max_size
        size = big.stat().st_size
        _rc, reply = helper(dev, 'upload-begin', {'filename': big.name, 'size': size}, ev=ev)
        results['upload_begin_real_backup'] = reply.get('error') or reply
        ev.check(f'H2: upload-begin for the real {size} byte backup is refused with insufficient-space '
                 f'(free {free}, reserve 512 MiB)', size > max_size and error_code(reply) == 'insufficient-space',
                 reply.get('error'))
        _rc, reply = helper(dev, 'upload-begin', {'filename': 'h2-boundary.woowbackup', 'size': max_size + MIB}, ev=ev)
        ev.check('H2: upload-begin 1 MiB above free - reserve is refused', error_code(reply) == 'insufficient-space',
                 reply.get('error'))
        reply = ok(dev, 'upload-begin', {'filename': 'h2-boundary.woowbackup', 'size': max_size - MIB}, ev=ev)
        ev.check('H2: upload-begin 1 MiB below free - reserve is accepted and reports max_size',
                 reply['max_size'] >= max_size - MIB, reply)
        ok(dev, 'upload-abort', {'upload_id': reply['upload_id']}, ev=ev)
        ev.check('H2: upload-abort leaves uploads/ empty', sh(dev, f'ls -A {DATA}/uploads').stdout.strip() == b'')

        job, log = backup_once(dev, ev, 'H2 對照：不含映像（應可放入）', label='backup[no-images]')
        save_job(ev, 'h2-backup-no-images-job', job, log)
        results['backup_without_images'] = {'state': job['state'], 'error': job.get('error'),
                                            'estimate_line': next((l for l in log if '預估資料量' in l), '')}
        ev.check('H2 control: a backup without images fits the same filesystem and succeeds (the check is size-based)',
                 job['state'] == 'succeeded', job.get('error'))
    finally:
        for _ in range(60):
            if ok(dev, 'status', ev=ev)['active_job'] is None:
                break
            time.sleep(2)
        sh(dev, f'umount {DATA}')
        ev.log(f'unmounted the tmpfs at {time.strftime("%H:%M:%S")}')
    ev.check('H2: after umount the original data is back (same backups listed, ext4)',
             fs_type(dev, DATA) == 'ext4' and backup_ids(dev, ev) == before_ids, sorted(backup_ids(dev, ev) ^ before_ids))
    ev.check('H2: app running afterwards', app_status(dev, ev)['state'] == 'running')
    return results


# ------------------------------------------------------------------ H5: reboot during a restore

def host_memory_ok():
    with open('/proc/meminfo') as handle:
        avail = next(int(line.split()[1]) // 1024 for line in handle if line.startswith('MemAvailable:'))
    return avail >= 1200, avail


def wait_device_ready(dev, timeout=300):
    uid = e2e.DEVICES[dev]['uid']
    deadline = time.monotonic() + timeout
    script = (f'systemctl is-system-running 2>/dev/null; systemctl is-active user@{uid}.service; '
              f'test -S /run/user/{uid}/bus && echo bus; systemctl is-active cockpit.socket')
    while time.monotonic() < deadline:
        proc = subprocess.run([LP, 'exec', dev_name(dev), 'sh', '-c', script], capture_output=True, timeout=60)
        words = proc.stdout.decode().split()
        if len(words) >= 4 and words[0] in ('running', 'degraded') and words[1] == 'active' and 'bus' in words \
                and words[-1] == 'active':
            return words
        time.sleep(2)
    raise Failed(f'dev-{dev} not ready after {timeout}s')


def scenario_h5(ev):
    dev = 'a'
    trigger = os.environ.get('H5_PHASE', 'start')
    ev.require('dev-a idle', ok(dev, 'status', ev=ev)['active_job'] is None)
    job, _log = backup_once(dev, ev, 'H5 還原目標（重新開機測試）', label='backup[target]')
    ev.require('H5 target backup succeeded', job['state'] == 'succeeded', job.get('error'))
    target = job['result']['backup_id']
    seeded = json.loads(owner(dev, 'python3', '/opt/woowbk-demo/tools/seed.py', '--notes', '2', '--files', '1').stdout)
    ev.log(f'pre-restore change: +{len(seeded["notes_added"])} notes, +{len(seeded["files_added"])} files')
    pre, pre_content = summary(dev), content_state(dev)
    ev.save('h5-pre-restore', {'summary': pre, 'target_backup': target})
    watcher = Watcher(dev, timeout=900)
    ev.require('watcher ready', watcher.wait_for(lambda e: e.get('ready'), 60))
    start = ok(dev, 'restore-start', {'backup_id': target, 'apps': [APP], 'request_id': request_id(), 'confirm': True},
               ev=ev)
    hit = watcher.wait_for(lambda e: e.get('phase') == trigger or e.get('state') in e2e_terminal(), 600)
    ev.require(f'H5 restore reached phase {trigger} (after the destructive stop)', hit and hit.get('phase') == trigger,
               hit)
    mem_ok, avail = host_memory_ok()
    ev.require(f'host MemAvailable >= 1200 MB before restarting the device ({avail} MB)', mem_ok)
    t0 = time.monotonic()
    restart = subprocess.run([LP, 'restart', dev_name(dev)], capture_output=True, timeout=300)
    restart_s = round(time.monotonic() - t0, 1)
    events = watcher.stop()
    ev.log(f'labpodman restart {dev_name(dev)} rc={restart.returncode} in {restart_s}s; watcher events {events}')
    ev.require('labpodman restart succeeded', restart.returncode == 0, restart.stderr.decode()[-300:])
    words = wait_device_ready(dev)
    boot_s = round(time.monotonic() - t0, 1)
    ev.timings.update(h5_restart_s=restart_s, h5_restart_to_ready_s=boot_s)
    ev.log(f'device ready after {boot_s}s: {words}')
    # The raw record and the app before any helper call (status/jobs/job-status run the recovery).
    raw = json.loads(sh(dev, f'cat {DATA}/jobs/{start["job_id"]}.json').stdout)
    units_after_boot = units_active(dev)[1]
    healthz_after_boot = app_get(dev, '/healthz', timeout=10)[0]
    after_boot_summary = app_get(dev, '/api/summary', timeout=20)
    ev.log(f'after boot, before recovery: record state={raw["state"]} phase={raw["phase"]} '
           f'safety={raw.get("safety_backup_id")}; units {units_after_boot}; /healthz {healthz_after_boot}; '
           f'summary {after_boot_summary}')
    log_tail_raw = sh(dev, f'tail -n 25 {DATA}/jobs/{start["job_id"]}.log').stdout.decode('utf-8', 'replace')
    ev.save('h5-after-boot', {'record_raw': redact(raw), 'units': units_after_boot, 'healthz': healthz_after_boot,
                              'summary': after_boot_summary, 'job_log_tail': log_tail_raw.splitlines()})
    # Review CR-06: the restore masks the app's non-database units until it finished, so a reboot in the middle
    # must not start the app on half-restored data (before the fix: units active, /healthz 503).
    ev.check('H5: after boot the half-restored app did not start (masked until a restore finishes)',
             len(units_after_boot) == 2 and units_after_boot[1] != 'active', units_after_boot)
    job, log = wait_job(dev, start['job_id'], ev=ev, timeout=120, label='restore-after-reboot')
    save_job(ev, 'h5-restore-job', job, log)
    safety = (job.get('result') or {}).get('safety_backup_id') or raw.get('safety_backup_id')
    ev.check('H5: after boot the restore is reported interrupted with zh-TW guidance naming the safety backup',
             job['state'] == 'interrupted' and safety and safety in (job.get('error') or {}).get('message', ''),
             {'state': job['state'], 'error': job.get('error')})
    ev.check('H5: nothing is replayed, staging removed, no job key, no orphan archive',
             helper(dev, 'job-status', {'job_id': start['job_id']})[1]['job']['state'] == job['state']
             and staging_empty(dev) and no_job_keys(dev) and orphans(dev) == [], {'orphans': orphans(dev)})
    status = ok(dev, 'status', ev=ev)
    ev.check('H5: the safety backup is listed and verified', any(b['id'] == safety and b['type'] == 'safety'
                                                                  and (b.get('verified') or {}).get('ok')
                                                                  for b in backups(dev, ev)), safety)
    app_view = next(a for a in status['apps'] if a['id'] == APP)
    ev.log(f'app after recovery: {app_view}')
    ev.check('H5: the overview does not call the half-restored app running',
             app_view['state'] == 'error' and any('暫時停用' in p for p in app_view['problems']), app_view)
    t1 = time.monotonic()
    rstart = ok(dev, 'restore-start', {'backup_id': safety, 'apps': [APP], 'request_id': request_id(), 'confirm': True},
                ev=ev)
    rjob, rlog = wait_job(dev, rstart['job_id'], ev=ev, label='restore-safety')
    save_job(ev, 'h5-restore-safety-job', rjob, rlog)
    ev.timings['h5_restore_safety_s'] = round(time.monotonic() - t1, 1)
    ev.check('H5: restoring the safety backup succeeds', rjob['state'] == 'succeeded', rjob.get('error'))
    after = summary(dev)
    ev.check('H5: data equals the pre-restore state (summary)', compare(after, pre) == {}, compare(after, pre))
    ev.check('H5: data equals the pre-restore state (full content incl. signatures and file hashes)',
             content_state(dev) == pre_content)
    ev.check('H5: app running, no active job', app_status(dev, ev)['state'] == 'running'
             and ok(dev, 'status', ev=ev)['active_job'] is None)
    ok(dev, 'delete', {'backup_id': target}, ev=ev)
    return {'trigger_phase': trigger, 'record_after_boot': {k: raw.get(k) for k in ('state', 'phase', 'safety_backup_id')},
            'units_after_boot': units_after_boot, 'healthz_after_boot': healthz_after_boot,
            'summary_after_boot': after_boot_summary, 'safety_backup': safety}


def e2e_terminal():
    return ('succeeded', 'failed', 'rolled-back', 'interrupted', 'cancelled')


# ------------------------------------------------------------------ H6: ~600 MB of files

GROW = r'''
import os, sys
count, mib = int(sys.argv[1]), int(sys.argv[2])
os.makedirs('/data/files', exist_ok=True)
for i in range(count):
    tmp, final = '/data/files/.h6-%02d.tmp' % i, '/data/files/h6-big-%02d.bin' % i
    with open(tmp, 'wb') as handle:
        for _ in range(mib):
            handle.write(os.urandom(1 << 20))
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, final)
print(count * mib)
'''


def timed_summary(dev):
    t0 = time.monotonic()
    status, body = app_get(dev, '/api/summary', timeout=60)
    return round(time.monotonic() - t0, 2), status, body


def scenario_h6(ev):
    import shutil
    dev = 'a'
    count, mib = int(os.environ.get('H6_FILES', '38')), 16
    host_free = shutil.disk_usage(LAB).free
    ev.require(f'host disk has >= 20 GB free ({host_free // 10**9} GB)', host_free >= 20 * 10**9)
    ev.require('dev-a idle', ok(dev, 'status', ev=ev)['active_job'] is None)
    pre, pre_content = summary(dev), content_state(dev)
    before_ids = backup_ids(dev, ev)
    t0 = time.monotonic()
    owner(dev, 'podman', 'exec', 'woowbk-demo-app', 'python3', '-c', GROW, str(count), str(mib), timeout=1800)
    ev.timings['h6_grow_s'] = round(time.monotonic() - t0, 1)
    du = owner(dev, 'podman', 'exec', 'woowbk-demo-app', 'du', '-sm', '/data/files').stdout.decode().split()[0]
    ev.timings['h6_files_volume_mib'] = int(du)
    seconds, status, _body = timed_summary(dev)
    ev.timings['h6_api_summary_s'] = seconds
    ev.log(f'files volume now {du} MiB; /api/summary took {seconds}s (HTTP {status})')
    big = summary(dev)
    big_content = content_state(dev)
    results = {}
    try:
        meter, monitor = CgroupMeter(dev), e2e.HealthMonitor(dev, 3600)
        t0 = time.monotonic()
        job, log = backup_once(dev, ev, f'H6 大量資料（{du} MiB，不含映像）', label='backup[h6]', timeout=3600)
        ev.timings['h6_backup_wall_s'] = round(time.monotonic() - t0, 1)
        results['backup_memory'], health = meter.stop(), monitor.stop()
        save_job(ev, 'h6-backup-job', job, log)
        ev.require('H6 backup of the large volume succeeded', job['state'] == 'succeeded', job.get('error'))
        backup_id = job['result']['backup_id']
        ev.timings.update(h6_backup_size_bytes=job['result']['size'], h6_backup_downtime_reported_s=
                          job['result']['downtime_seconds'], h6_backup_healthz_longest_unhealthy_s=health['longest_unhealthy_s'])
        ev.log(f'backup {backup_id}: {job["result"]["size"]} bytes in {ev.timings["h6_backup_wall_s"]}s; '
               f'memory {results["backup_memory"]}; healthz {health}')
        ev.check('H6 backup kept the data snapshot (verify snapshot recorded)',
                 not any('無法取得備份時的資料核對快照' in line for line in log), [l for l in log if '快照' in l])

        info = ok(dev, 'download-info', {'backup_id': backup_id}, ev=ev)
        local = private_dir(WORK / 'h6') / info['filename']
        meter = CgroupMeter(dev)
        got = e2e.bridge_download(dev, info['path'], local, ev=ev)
        results['download_memory'] = meter.stop()
        ev.timings['h6_download_s'] = got['seconds']
        meta = next(b for b in backups(dev, ev) if b['id'] == backup_id)
        ev.check('H6 download through the real bridge (fsread1): size and sha256 equal the index',
                 got['bytes'] == meta['size'] and got['sha256'] == meta['sha256'], {k: got[k] for k in ('bytes', 'seconds')})
        local.unlink()

        # change the data, then restore in place
        owner(dev, 'podman', 'exec', 'woowbk-demo-app', 'sh', '-c', 'rm -f /data/files/h6-big-00.bin /data/files/h6-big-01.bin')
        e2e.app_post(dev, '/api/notes', json.dumps({'title': 'H6 還原前新增', 'body': '會被還原掉'}, ensure_ascii=False).encode(),
                     'application/json')
        meter, monitor = CgroupMeter(dev), e2e.HealthMonitor(dev, 3600)
        t0 = time.monotonic()
        start = ok(dev, 'restore-start', {'backup_id': backup_id, 'apps': [APP], 'request_id': request_id(),
                                          'confirm': True}, ev=ev)
        rjob, rlog = wait_job(dev, start['job_id'], ev=ev, timeout=3600, label='restore[h6]')
        ev.timings['h6_restore_wall_s'] = round(time.monotonic() - t0, 1)
        results['restore_memory'], rhealth = meter.stop(), monitor.stop()
        save_job(ev, 'h6-restore-job', rjob, rlog)
        ev.timings['h6_restore_healthz_longest_unhealthy_s'] = rhealth['longest_unhealthy_s']
        ev.check('H6 in-place restore succeeded with data verification match', rjob['state'] == 'succeeded'
                 and [v['match'] for v in (rjob.get('result') or {}).get('verification', [])] == [True], rjob.get('error'))
        ev.check('H6 data after restore equals the backup time (summary and full content)',
                 compare(summary(dev), big) == {} and content_state(dev) == big_content)
        results['safety_backup'] = (rjob.get('result') or {}).get('safety_backup_id')
        for key in ('backup_memory', 'download_memory', 'restore_memory'):
            mem = results[key]
            ev.check(f'H6 {key}: no OOM kill in the device and non-reclaimable memory (anon+kernel+shmem) stays well '
                     f'under the {mem["limit_mib"]} MiB limit ({mem["sampled_anon_kernel_shmem_max_mib"]} MiB sampled max; '
                     f'peak incl. page cache {mem["peak_mib"]} MiB)',
                     mem['events_delta'].get('oom_kill', 0) == 0 and mem['events_delta'].get('oom', 0) == 0
                     and mem['sampled_anon_kernel_shmem_max_mib'] < 0.6 * mem['limit_mib'], mem)
    finally:
        # Clean up: the big files go, the data returns to the state before H6; large backups are deleted.
        owner(dev, 'podman', 'exec', 'woowbk-demo-app', 'sh', '-c', 'rm -f /data/files/h6-big-*.bin /data/files/.h6-*.tmp')
        for backup in backups(dev, ev):
            if backup['id'] not in before_ids and backup['size'] > 100 * MIB:
                ok(dev, 'delete', {'backup_id': backup['id']}, ev=ev)
                ev.log(f'deleted large H6 backup {backup["id"]} ({backup["type"]}, {backup["size"]} bytes)')
    ev.check('H6 cleanup: data equals the state before H6 again', compare(summary(dev), pre) == {}
             and content_state(dev) == pre_content)
    ev.check('H6 cleanup: staging empty, no orphan, no large backups left',
             staging_empty(dev) and orphans(dev) == [] and all(b['size'] < 100 * MIB or b['id'] in before_ids
                                                              for b in backups(dev, ev)))
    return results


# ------------------------------------------------------------------ H7: installer on a device

RUNTIME_FP = r'''
import hashlib, json, os
def tree(root):
    out = {}
    for base, dirs, names in os.walk(root):
        dirs.sort()
        for name in sorted(names):
            path = os.path.join(base, name)
            st = os.lstat(path)
            digest = hashlib.sha256()
            if os.path.isfile(path) and not os.path.islink(path):
                with open(path, 'rb') as handle:
                    for chunk in iter(lambda: handle.read(1 << 20), b''):
                        digest.update(chunk)
            out[os.path.relpath(path, root)] = [st.st_size, oct(st.st_mode), digest.hexdigest()]
    return out
data = tree('/var/lib/woowtech-backup')
keys = tree('/etc/woowtech-cockpit/backup/keys')
print(json.dumps({'data_files': len(data), 'data_bytes': sum(v[0] for v in data.values()),
                  'data_digest': hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest(),
                  'keys_names': sorted(keys), 'keys_dir_mode': oct(os.stat('/etc/woowtech-cockpit/backup/keys').st_mode),
                  'keys_digest': hashlib.sha256(json.dumps(keys, sort_keys=True).encode()).hexdigest()}))
'''
SRC = '/opt/woow-cockpit-src'


def manage(dev, *args, check=True):
    proc = sh(dev, f'cd {SRC} && python3 scripts/manage.py ' + ' '.join(args), check=False, timeout=600)
    out = proc.stdout.decode()
    try:
        result = json.loads(out)
    except ValueError:
        result = {'raw': out[-500:]}
    if check and proc.returncode != 0:
        raise Failed(f'manage.py {" ".join(args)} rc={proc.returncode}: {proc.stderr.decode()[-400:]}')
    return proc.returncode, result


def transactions(dev):
    script = ('for t in /var/backups/woowtech-cockpit-source/*/transaction.json; do python3 -c "import json,sys; '
              'j=json.load(open(sys.argv[1])); print(sys.argv[1].split(\'/\')[-2], j[\'status\'], len(j[\'files\']))" "$t"; done')
    return [line.split() for line in sh(dev, script).stdout.decode().splitlines() if line.strip()]


def helper_present(dev):
    return sh(dev, 'test -x /usr/local/libexec/woowtech-cockpit-backup && echo yes || echo no').stdout.decode().strip() == 'yes'


def page_listed(dev):
    return 'woowtechbackup' in sh(dev, 'cockpit-bridge --packages 2>/dev/null', check=False).stdout.decode()


def engine_digest(dev):
    return sh(dev, 'cd /usr/local/lib/woowtech-cockpit-backup && find . -name "*.py" -type f | sort | xargs sha256sum | '
                   'sha256sum', check=False).stdout.decode().split()[0]


def scenario_h7(ev):
    dev = 'a'
    full = os.environ.get('H7_FULL', '1') == '1'
    ev.require('dev-a idle', ok(dev, 'status', ev=ev)['active_job'] is None)
    fp0 = json.loads(py(dev, RUNTIME_FP).stdout)
    status0 = ok(dev, 'status', ev=ev)
    ids0 = backup_ids(dev, ev)
    digest0 = engine_digest(dev)
    ev.save('h7-fingerprint-before', fp0)
    ev.log(f'runtime data: {fp0["data_files"]} files {fp0["data_bytes"]} bytes, keys {fp0["keys_names"]}')
    rc, plan = manage(dev, 'plan', '--backup-demo-catalog')
    ev.save('h7-plan', plan)
    ev.check('H7 plan: nothing to change after deploy-src (working tree already installed)',
             rc == 0 and plan.get('changed') == [] and plan.get('directories') == [], {k: plan.get(k) for k in ('changed', 'directories')})
    rc, inst = manage(dev, 'install', '--backup-demo-catalog')
    ev.check('H7 install: already-current', rc == 0 and inst.get('status') == 'already-current', inst)
    rc, ver = manage(dev, 'verify', check=False)
    ev.check('H7 verify: verified, no drift', rc == 0 and ver.get('status') == 'verified', ver)
    chain = transactions(dev)
    ev.save('h7-transactions-before', chain)
    installed = [t for t in chain if t[1] == 'installed']
    latest = installed[-1][0]
    rc, rb = manage(dev, 'rollback', latest)
    ev.check(f'H7 rollback of the latest transaction {latest}', rc == 0 and rb.get('status') == 'rolled-back', rb)
    rc, ver = manage(dev, 'verify', check=False)
    ev.check('H7 verify after rollback: verified against the restored state', rc == 0 and ver.get('status') == 'verified', ver)
    ev.check('H7 after rollback: the previous engine is installed and the helper still works',
             engine_digest(dev) != digest0 and helper(dev, 'status')[1].get('ok') is True)
    fp1 = json.loads(py(dev, RUNTIME_FP).stdout)
    ev.check('H7 runtime data and keys untouched by the rollback', fp1 == fp0, {'before': fp0, 'after': fp1})
    removed = []
    if full:
        # Roll back further until the backup package itself is gone (helper, engine, page, catalog).
        for tid, state, _n in reversed(transactions(dev)):
            if state != 'installed' or tid == installed[0][0]:
                continue
            rc, rb = manage(dev, 'rollback', tid)
            removed.append([tid, rb.get('status')])
            if not helper_present(dev):
                break
        ev.log(f'further rollbacks: {removed}')
        ev.check('H7 package removed by rolling back its install transaction: no helper, no page, no catalog entry',
                 not helper_present(dev) and not page_listed(dev)
                 and sh(dev, 'test -e /etc/woowtech-cockpit/backup/apps/woowbk-demo.json && echo y || echo n'
                        ).stdout.decode().strip() == 'n', removed)
        fp2 = json.loads(py(dev, RUNTIME_FP).stdout)
        ev.check('H7 runtime data and keys untouched with the package removed (keys dir kept)', fp2 == fp0,
                 {'before': fp0, 'after': fp2})
        ev.check('H7 app keeps running without the backup package', units_active(dev)[0])
    rc, inst = manage(dev, 'install', '--backup-demo-catalog')
    ev.check('H7 re-install', rc == 0 and inst.get('status') == 'installed', inst)
    rc, ver = manage(dev, 'verify', check=False)
    ev.check('H7 verify after re-install: verified', rc == 0 and ver.get('status') == 'verified', ver)
    fp3 = json.loads(py(dev, RUNTIME_FP).stdout)
    ev.check('H7 runtime data and keys identical to before H7', fp3 == fp0, {'before': fp0, 'after': fp3})
    status3 = ok(dev, 'status', ev=ev)
    ev.check('H7 helper works again: same device key (kit confirmed), same backups, app running, page listed',
             status3['key'] == status0['key'] and backup_ids(dev, ev) == ids0 and page_listed(dev)
             and next(a for a in status3['apps'] if a['id'] == APP)['state'] == 'running'
             and engine_digest(dev) == digest0, {'key': status3['key']})
    smallest = min(backups(dev, ev), key=lambda b: b['size'])
    start = ok(dev, 'verify-start', {'backup_id': smallest['id'], 'request_id': request_id()}, ev=ev)
    job, _log = wait_job(dev, start['job_id'], ev=ev, label='verify[after-reinstall]')
    ev.check('H7 the device key still decrypts: verify job on an existing backup succeeds', job['state'] == 'succeeded',
             job.get('error'))
    ev.save('h7-transactions-after', transactions(dev))
    return {'rolled_back_latest': latest, 'further_rollbacks': removed, 'reinstall': inst.get('backup_id')}


# ------------------------------------------------------------------ leak scan (devices + hardening evidence)

def scenario_leaks(ev):
    secret = e2e.kit_secret() if e2e.KIT_FILE.exists() else None
    for dev in ('a', 'b'):
        proc = sh(dev, f'python3 -I - {e2e.DEVICES[dev]["uid"]}', input=e2e.LEAK_SCAN.encode(), timeout=300)
        report = json.loads(proc.stdout)
        ev.save(f'leaks-dev-{dev}', report)
        ev.check(f'dev-{dev}: no app secret or age key in job records/logs/index/requests/journal', report['hits'] == {},
                 report['hits'])
        ev.check(f'dev-{dev}: no transient key files in /run/woowtech-backup and no staging left',
                 not any(n.startswith('key-') for n in report['run_dir']) and report['staging'] == [],
                 {'run': report['run_dir'], 'staging': report['staging']})
        ev.check(f'dev-{dev}: no orphan archive files', orphans(dev) == [], orphans(dev))
    hits = []
    for root in (HARDENING, e2e.EVIDENCE, WORK):
        for base, _dirs, names in os.walk(root):
            for name in names:
                data = Path(base, name).read_bytes()
                if e2e.SECRET_RE.search(data.decode('utf-8', 'replace')) or (secret and secret.encode() in data):
                    hits.append(str(Path(base, name)))
    ev.check('host evidence (hardening + integration) and work files contain no key material', hits == [], hits)
    return {}


# ------------------------------------------------------------------ main

SCENARIOS = {'h1': scenario_h1, 'h2': scenario_h2, 'h3': scenario_h3, 'h4': scenario_h4, 'h5': scenario_h5,
             'h6': scenario_h6, 'h7': scenario_h7, 'leaks': scenario_leaks}


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('scenario', choices=[*SCENARIOS, 'all'])
    args = parser.parse_args()
    names = list(SCENARIOS) if args.scenario == 'all' else [args.scenario]
    all_ok = True
    for name in names:
        ev = Evidence(name)
        try:
            extra = SCENARIOS[name](ev) or {}
        except Failed as error:
            ev.log(f'ABORTED: {error}')
            extra = {'aborted': str(error)}
        except Exception as error:  # noqa: BLE001 - record and continue to the summary
            ev.log(f'ABORTED with {type(error).__name__}: {redact(str(error))}')
            extra = {'aborted': f'{type(error).__name__}: {redact(str(error))}'}
        all_ok = ev.finish(extra) and 'aborted' not in extra and all_ok
    return 0 if all_ok else 1


if __name__ == '__main__':
    sys.exit(main())
