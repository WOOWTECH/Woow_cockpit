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
    python3 -I tests/e2e/lab/hardening.py sec1      # SEC-1: nested volume/OCI tars with an absolute symlink + member below
    python3 -I tests/e2e/lab/hardening.py fidelity  # legitimate volume content: in-place and cross-device listing equal
    python3 -I tests/e2e/lab/hardening.py fresh     # dev-b fresh restore: leftovers refused, SIGKILL recovery, rollback tags
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
    """Archive files without an index sidecar (never listed, never cleaned) and stray temp files. Archives are
    `<id>.tar` (format 2, since 2026-11-13) or `<id>.woowbackup` (format 1)."""
    names = set(archive_dir_listing(dev))
    stray = []
    for name in sorted(names):
        ext = next((e for e in ('.woowbackup', '.tar') if name.endswith(e)), None)
        if ext and not name.startswith('.'):
            if name[:-len(ext)] + '.json' not in names:
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
             re.compile(r'^/home/appowner/$'),
             # woowbk-dirs (dirs_e2e.py, when deployed on dev-a): its /healthz probe file in its www/ host directory,
             # written by the container's own health check every 30 s, like woowbk-demo's in its volume above.
             re.compile(r'^/home/appowner/woowbk-dirs/data/www/$'),
             re.compile(r'^/home/appowner/woowbk-dirs/data/www/\.healthz-'),
             # ... and its running PostgreSQL's own data directory, like woowbk-demo-pgdata above: a timed checkpoint
             # five minutes after dirs_e2e.py last restarted it rewrites pg_control, pg_wal, pg_xact, ... by itself.
             re.compile(r'^/home/appowner/\.local/share/woowbk-dirs/postgres/'),
             # woowbk-inst (strengthen_e2e.py instance, when deployed on dev-a): the woowbk-demo app image and a
             # PostgreSQL of its own, so the same health check probe files and database writes as woowbk-demo's.
             re.compile(r'^/home/appowner/\.local/share/containers/storage/volumes/woowbk-inst-pgdata/'),
             re.compile(r'^/home/appowner/\.local/share/containers/storage/volumes/woowbk-inst-files/_data/$'),
             re.compile(r'^/home/appowner/\.local/share/containers/storage/volumes/woowbk-inst-files/_data/\.healthz-')),
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
import os
path = '/var/lib/woowtech-backup/archives/%s.tar' % sys.argv[1]
if not os.path.exists(path):
    path = path[:-len('.tar')] + '.woowbackup'
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
# applies one defect and writes the re-encrypted backup (device recipient) to stdout in the base's format: a format 2
# `.tar` (since 2026-11-13: backup.json + README + the app's age archive; backup.json is built from the app section
# BEFORE the defect, except where the defect is the app itself, so the authenticated manifest is what gets judged)
# or a format 1 `.woowbackup`. stderr gets a one-line description (member names only, never content).
CRAFT = r'''
import calendar, copy, glob, hashlib, io, json, os, secrets, subprocess, sys, tarfile, time
sys.path.insert(0, '/usr/local/lib/woowtech-cockpit-backup')
sys.dont_write_bytecode = True
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
V2_PATH = '/var/lib/woowtech-backup/archives/%s.tar' % base_id
FORMAT = 2 if os.path.exists(V2_PATH) else 1
if FORMAT == 2:
    with tarfile.open(V2_PATH) as outer:
        base_doc = json.loads(outer.extractfile('backup.json').read())
        cipher = outer.extractfile(base_doc['apps'][0]['file']).read()
    old_header = {'key_id': base_doc['key_id']}
else:
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
app = manifest['app'] if FORMAT == 2 else manifest['apps'][0]
APP = app['id']
original_app = copy.deepcopy(app)
head = {key: manifest[key] for key in ('backup_id', 'created', 'type', 'note', 'key_id', 'encryption', 'tool', 'source',
                                       'consistency')}
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
SECTIONS = ('images', 'postgres', 'volumes', 'secrets', 'config_files', 'quadlet_files', 'data_dirs', 'verify_digests')
def rename(old, new):
    for item in body:
        if item[0] == old:
            item[0] = new
    for section in SECTIONS:
        for item in app.get(section) or []:
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
    for section in SECTIONS:
        for item in app.get(section) or []:
            if 'entry' in item:
                item['entry'] = item['entry'].replace('apps/%s/' % APP, 'apps/woowbk-h1-evil/', 1)
            for db in item.get('databases') or []:  # instance-mode postgres items
                if 'entry' in db:
                    db['entry'] = db['entry'].replace('apps/%s/' % APP, 'apps/woowbk-h1-evil/', 1)
    app['id'], app['name'] = 'woowbk-h1-evil', 'H1 未登錄的應用'
    if FORMAT == 2:
        manifest['backup_apps'] = ['woowbk-h1-evil']
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
sealed = run(['age', '-e', '-r', recipient], run(['zstd', '-q', '-c', '-3'], tar_bytes))
if FORMAT == 2:
    from woowbackup import archive as warchive
    shown = app if case in ('unknown-app', 'undeclared-items') else original_app
    doc = warchive._head_view(head)
    doc['apps'] = [dict(warchive.display_app(shown), file=warchive.inner_name(shown['id'], 'age-x25519'), size=len(sealed),
                        sha256=hashlib.sha256(sealed).hexdigest())]
    doc_bytes = json.dumps(doc, ensure_ascii=False, indent=2).encode('utf-8') + b'\n'
    readme = warchive.readme_text(doc).encode('utf-8')
    mtime = calendar.timegm(time.strptime(created, '%Y-%m-%dT%H:%M:%SZ'))
    out = b''
    for name, data in (('backup.json', doc_bytes), ('README.txt', readme), (doc['apps'][0]['file'], sealed)):
        out += warchive._outer_header(name, len(data), mtime) + data + warchive._padding(len(data))
    end = len(out) + 2 * 512
    out += bytes(2 * 512 + (-end) % (20 * 512))
else:
    out = b'WOOWTECH-BACKUP/1\n' + json.dumps(header, separators=(',', ':')).encode() + b'\n' + sealed
sys.stdout.buffer.write(out)
names = [i.name if isinstance(i, tarfile.TarInfo) else (i[0].name if isinstance(i[0], tarfile.TarInfo) else i[0])
         for i in items]
sys.stderr.write(json.dumps({'case': case, 'format': FORMAT, 'backup_id': new_id, 'members': len(items), 'entries': len(manifest['entries']),
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
    # The deep verify (2026-11-13) checks every entry like a restore would, also items this device's catalog does not
    # declare: the junk image entry fails it, while a restore here ignores the undeclared items and succeeds.
    'undeclared-items': {'inspect': 'ok', 'verify': 'corrupt-archive', 'restore': 'succeeded'},
}
# Format 2 reads only the selected apps' archives: restoring woowbk-demo from a backup that holds only another app
# is refused while decrypting (the app is not in the backup), before the preflight.
H1_CASES_V2 = {'unknown-app': {'inspect': 'ok', 'verify': 'succeeded', 'restore': ('incompatible', 'decrypt')}}


def craft(dev, case, base_id, ev):
    proc = subprocess.run([LP, 'exec', '-i', dev_name(dev), 'python3', '-I', '-', case, base_id], input=CRAFT.encode(),
                          capture_output=True, timeout=300)
    if proc.returncode != 0:
        raise Failed(f'craft {case}: rc={proc.returncode} {redact(proc.stderr.decode("utf-8", "replace")[-400:])}')
    meta = json.loads(proc.stderr.decode().strip().splitlines()[-1])
    path = private_dir(WORK / 'h1') / f'{case}{".tar" if meta.get("format") == 2 else ".woowbackup"}'
    e2e.write_private(path, proc.stdout)
    meta.update(file=str(path), size=len(proc.stdout), sha256=hashlib.sha256(proc.stdout).hexdigest())
    return meta


def error_code(reply):
    return 'ok' if reply.get('ok') else reply['error']['code']


def h1_case(ev, dev, case, base_id, baseline):
    meta = craft(dev, case, base_id, ev)
    expect = (H1_CASES_V2.get(case) if meta.get('format') == 2 else None) or H1_CASES[case]
    record = {'case': case, 'expect': {k: list(v) if isinstance(v, tuple) else v for k, v in expect.items()}}
    record['crafted'] = meta
    backup_id = meta['backup_id']
    ev.log(f'[{case}] crafted {meta["size"]} bytes, backup {backup_id}, first members {meta["first_names"]}')
    t_start = device_clock(dev)
    before_ids = backup_ids(dev, ev)

    # 1. upload exactly like the page: upload-begin -> fsreplace1 -> upload-finish
    _begin, (_rc, reply) = e2e.upload_file(dev, meta['file'], ev=ev, filename=f'woowbk-h1-{case}{Path(meta["file"]).suffix}')
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
    # The largest backup a previous run downloaded (cli_e2e s2: with images): `.tar` (format 2) or `.woowbackup`.
    big = max([*e2e.DOWNLOADS.glob('*.tar'), *e2e.DOWNLOADS.glob('*.woowbackup')], key=lambda p: p.stat().st_size)
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


DEMO_ENTRY = '/etc/woowtech-cockpit/backup/apps/woowbk-demo.json'


def scenario_h7(ev):
    dev = 'a'
    full = os.environ.get('H7_FULL', '1') == '1'
    ev.require('dev-a idle', ok(dev, 'status', ev=ev)['active_job'] is None)
    # 應用設定 (catalog-install) may have replaced the lab fixture entry that `manage.py --backup-demo-catalog` manages
    # (e.g. with the generated digest checks): manage.py would list it and refuse to roll back a file changed after its
    # install. The managed bytes go back for the rollback chain; the administrator's entry is re-installed at the end.
    admin_entry = None
    if sh(dev, f'cmp -s {SRC}/catalog-examples/woowbk-demo/catalog.json {DEMO_ENTRY}', check=False).returncode != 0:
        admin_entry = json.loads(sh(dev, f'cat {DEMO_ENTRY}').stdout)
        sh(dev, f'install -o root -g root -m 0644 {SRC}/catalog-examples/woowbk-demo/catalog.json {DEMO_ENTRY}')
        ev.log('H7: the woowbk-demo entry had been changed through 應用設定; the file manage.py manages was put back '
               'for the rollback chain and the entry is re-installed with catalog-install at the end')
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
    if admin_entry is not None:
        preview = ok(dev, 'catalog-install', {'entry': admin_entry}, ev=ev)
        done = ok(dev, 'catalog-install', {'entry': admin_entry, 'confirm': True,
                                           'expected_sha256': preview['expected_sha256']}, ev=ev)
        ev.check('H7 the woowbk-demo entry from 應用設定 is installed again', done.get('installed') is True, done)
    return {'rolled_back_latest': latest, 'further_rollbacks': removed, 'reinstall': inst.get('backup_id')}


# ------------------------------------------------------------------ shared helpers of the release lab cases

def owner_images(dev):
    """{image name: image id} of the app owner's named images."""
    data = json.loads(owner(dev, 'podman', 'images', '--format', 'json').stdout or b'[]')
    return dict(sorted((name, image['Id']) for image in data for name in image.get('Names') or []))


def image_id(dev, name):
    proc = owner(dev, 'podman', 'image', 'inspect', '--format', '{{.Id}}', name, check=False)
    return proc.stdout.decode().strip() if proc.returncode == 0 else None


def owner_events(dev, since, until):
    """Image and volume events of the owner's podman between two device times (journald event log)."""
    proc = owner(dev, 'podman', 'events', '--stream=false', '--since', str(int(since)), '--until', str(int(until) + 1),
                 '--filter', 'type=image', '--filter', 'type=volume', '--format', 'json', check=False, timeout=120)
    events = []
    for line in proc.stdout.decode('utf-8', 'replace').splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if str(event.get('Name') or '').startswith('woowbk-sec-probe'):
            continue  # another lab user's probe (see README), not this engine
        events.append({key: event.get(key) for key in ('Type', 'Status', 'Name', 'Time')})
    return proc.returncode, events


def volume_mountpoint(dev, name):
    out = owner(dev, 'podman', 'volume', 'inspect', '--format', '{{.Mountpoint}}', name).stdout.decode().strip()
    if not out.startswith('/'):
        raise Failed(f'dev-{dev}: no mountpoint for volume {name}: {out!r}')
    return out


def in_userns(dev, code, *args, timeout=300):
    """Run Python as root of the owner's user namespace (`podman unshare`), the IDs a container sees."""
    return owner(dev, 'podman', 'unshare', 'python3', '-I', '-c', code, *map(str, args), timeout=timeout).stdout.decode()


def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def dev_a_image_backup(ev):
    """(host file, backup id, verify snapshot) of a dev-a backup *with* images: the one cli_e2e s1/s2 downloaded when it
    is still intact on the host, otherwise a new one (backup on dev-a + bridge download)."""
    state = e2e.load_state()
    s1, local = state.get('s1') or {}, Path((state.get('s2') or {}).get('download') or '/nonexistent')
    if s1.get('sha256') and local.is_file() and file_sha256(local) == s1['sha256']:
        return local, s1['backup_id'], s1.get('snapshot')
    snapshot = summary('a')
    job, _log = backup_once('a', ev, '發布回歸：跨設備來源（含映像）', images=True, label='backup[source]')
    ev.require('source backup with images on dev-a succeeded', job['state'] == 'succeeded', job.get('error'))
    backup_id = job['result']['backup_id']
    info = ok('a', 'download-info', {'backup_id': backup_id}, ev=ev)
    local = private_dir(WORK / 'source') / info['filename']
    e2e.bridge_download('a', info['path'], local, ev=ev)
    return local, backup_id, snapshot


# ------------------------------------------------------------------ SEC-1: nested tar symlink escape (live)

SEC1_TAG = 'woowbk-sec1'
SEC1_WORK = '/var/tmp/woowbk-sec1-work'  # device root fs: /tmp is a tmpfs that counts against the device memory limit
SEC1_APP_REF = 'localhost/woowbk-demo-app:1'

# Runs as the app owner in the device: the primitive the engine defends against, on the device's real podman 4.9.3.
# A tar holding an absolute symlink and a member below it goes to bare `podman volume import` and `podman load`; each
# writes the member through the symlink into a canary directory of the owner's home. Harmless text; all removed.
SEC1_CONTROL = r'''
import io, json, os, shutil, subprocess, sys, tarfile
tag = sys.argv[1]
home = os.path.expanduser('~')
canary = {'volume-import': os.path.join(home, tag + '-canary-vol'), 'load': os.path.join(home, tag + '-canary-img')}
work = os.path.join(home, '.' + tag + '-ctl')
def hostile(target, planted):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w', format=tarfile.PAX_FORMAT) as tar:
        link = tarfile.TarInfo(tag + '-esc')
        link.type, link.linkname, link.mode = tarfile.SYMTYPE, target, 0o777
        tar.addfile(link)
        data = b'woowbk SEC-1 lab control (harmless)\n'
        member = tarfile.TarInfo(tag + '-esc/' + planted)
        member.size, member.mode = len(data), 0o644
        tar.addfile(member, io.BytesIO(data))
    return buf.getvalue()
result = {}
try:
    for folder in (*canary.values(), work):
        os.mkdir(folder, 0o700)
    volume_tar, image_tar = os.path.join(work, 'volume.tar'), os.path.join(work, 'image.tar')
    with open(volume_tar, 'wb') as handle:
        handle.write(hostile(canary['volume-import'], tag + '-planted-by-volume-import'))
    with open(image_tar, 'wb') as handle:
        handle.write(hostile(canary['load'], tag + '-planted-by-load'))
    volume = tag + '-ctl-vol'
    subprocess.run(['podman', 'volume', 'create', volume], capture_output=True, check=True)
    try:
        result['volume_import_rc'] = subprocess.run(['podman', 'volume', 'import', volume, volume_tar],
                                                    capture_output=True).returncode
    finally:
        subprocess.run(['podman', 'volume', 'rm', '-f', volume], capture_output=True)
    run = subprocess.run(['podman', 'load', '-i', image_tar], capture_output=True)
    result['load_rc'] = run.returncode
    result['load_stderr_tail'] = run.stderr.decode('utf-8', 'replace')[-300:]
    result['written_through_symlink'] = {key: sorted(os.listdir(path)) for key, path in canary.items()}
finally:
    for folder in (*canary.values(), work):
        shutil.rmtree(folder, ignore_errors=True)
print(json.dumps(result))
'''

# Runs as root inside dev-a. Streams a base backup (with images) through the device key into a work directory on the
# device's disk, appends to the volume tar and to the app image's OCI archive an absolute symlink into the owner's home
# plus a member below it (after all real members: a check that streams into podman would already have changed the
# device), fixes the manifest entries (size, sha256) and re-encrypts to the device recipient, so only ciphertext leaves
# the device. All plaintext is deleted before it exits. stdout: one JSON report, including the verdicts of the installed
# engine's own nested checks on the original and the crafted entries (reason and member only).
CRAFT_SEC1 = r'''
import glob, hashlib, io, json, os, pwd, secrets, shutil, subprocess, sys, tarfile, time
base_id, work, app_ref, tag = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
sys.path.insert(0, '/usr/local/lib/woowtech-cockpit-backup')
sys.dont_write_bytecode = True
from woowbackup import nested
from woowbackup.errors import BackupError
ENV = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}
home = pwd.getpwnam('appowner').pw_dir
def pipeline(stages, source, sink):
    procs, stdin = [], source
    for i, argv in enumerate(stages):
        proc = subprocess.Popen(argv, stdin=stdin, stdout=sink if i == len(stages) - 1 else subprocess.PIPE, env=ENV)
        if stdin is not source:
            stdin.close()
        stdin = proc.stdout
        procs.append(proc)
    codes = [proc.wait() for proc in procs]
    if any(codes):
        raise SystemExit('%s exited %s' % ([s[0] for s in stages], codes))
def info(name, size=0, kind=tarfile.REGTYPE, link='', mode=0o644):
    ti = tarfile.TarInfo(name)
    ti.size, ti.type, ti.linkname, ti.mode, ti.uid, ti.gid, ti.mtime = size, kind, link, mode, 0, 0, int(time.time())
    return ti
def outer(name, size):
    ti = info(name, size, mode=0o600)
    ti.uname = ti.gname = 'root'
    return ti
def digest(path):
    h, size = hashlib.sha256(), 0
    with open(path, 'rb') as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b''):
            h.update(chunk)
            size += len(chunk)
    return h.hexdigest(), size
def verdict(check):
    try:
        check()
        return {'accepted': True}
    except BackupError as error:
        return {'accepted': False, 'code': error.code, 'reason': error.details.get('reason'),
                'member': error.details.get('member'), 'type': error.details.get('type')}
os.mkdir(work, 0o700)
report = {}
try:
    keyfiles = sorted(glob.glob('/etc/woowtech-cockpit/backup/keys/device-*.key'))
    if len(keyfiles) != 1:
        raise SystemExit('need exactly one device key')
    recipient = subprocess.run(['age-keygen', '-y', keyfiles[0]], capture_output=True, env=ENV,
                               check=True).stdout.decode().split()[0]
    # Format 2 (`.tar`, every backup since 2026-11-13): the app's age archive is copied out of the outer tar and
    # decrypted; format 1 (`.woowbackup`): the stream after the header line.
    v2_path = '/var/lib/woowtech-backup/archives/%s.tar' % base_id
    FORMAT = 2 if os.path.exists(v2_path) else 1
    plain_path = os.path.join(work, 'plain.tar')
    if FORMAT == 2:
        sealed_path = os.path.join(work, 'sealed.age')
        with tarfile.open(v2_path) as outer_tar:
            doc = json.loads(outer_tar.extractfile('backup.json').read())
            with outer_tar.extractfile(doc['apps'][0]['file']) as raw, open(sealed_path, 'wb') as out:
                shutil.copyfileobj(raw, out, 1 << 20)
        old_header = {'key_id': doc['key_id']}
        with open(sealed_path, 'rb') as source, open(plain_path, 'wb') as sink:
            pipeline([['age', '-d', '-i', keyfiles[0]], ['zstd', '-d', '-c', '-q']], source, sink)
        os.unlink(sealed_path)
    else:
        source_path = '/var/lib/woowtech-backup/archives/%s.woowbackup' % base_id
        with open(source_path, 'rb') as handle:
            magic, header_line = handle.readline(), handle.readline()
            offset = handle.tell()
        if magic != b'WOOWTECH-BACKUP/1\n':
            raise SystemExit('not a backup')
        old_header = json.loads(header_line)
        with open(source_path, 'rb') as source, open(plain_path, 'wb') as sink:
            source.seek(offset)
            pipeline([['age', '-d', '-i', keyfiles[0]], ['zstd', '-d', '-c', '-q']], source, sink)
    plain = tarfile.open(plain_path, 'r:')
    members = plain.getmembers()
    if members[0].name != 'manifest.json':
        raise SystemExit('manifest is not the first member')
    manifest = json.loads(plain.extractfile(members[0]).read())
    app = manifest['app'] if FORMAT == 2 else manifest['apps'][0]
    volume = app['volumes'][0]
    image = next((i for i in app['images'] if i.get('ref') == app_ref and i.get('entry')), None)
    if image is None:
        raise SystemExit('the base backup does not include ' + app_ref)
    by_name = {m.name: m for m in members}
    def extract(entry, dest):
        with plain.extractfile(by_name[entry]) as raw, open(dest, 'wb') as out:
            shutil.copyfileobj(raw, out, 1 << 20)
    def append_escape(original, dest, target, planted, payload):
        with open(original, 'rb') as raw, tarfile.open(fileobj=raw, mode='r|') as inner, \
                open(dest, 'wb') as out_file, tarfile.open(fileobj=out_file, mode='w|', format=tarfile.PAX_FORMAT) as out:
            count = 0
            for member in inner:
                out.addfile(member, inner.extractfile(member) if member.isreg() else None)
                count += 1
            out.addfile(info(tag + '-esc', kind=tarfile.SYMTYPE, link=target, mode=0o777))
            out.addfile(info(tag + '-esc/' + planted, len(payload)), io.BytesIO(payload))
        return count
    orig_volume, orig_image = os.path.join(work, 'volume.orig.tar'), os.path.join(work, 'image.orig.tar')
    new_volume, new_image = os.path.join(work, 'volume.tar'), os.path.join(work, 'image.tar')
    extract(volume['entry'], orig_volume)
    extract(image['entry'], orig_image)
    report.update(volume=volume['name'], volume_entry=volume['entry'], image_ref=image['ref'], image_entry=image['entry'],
                  volume_symlink_target=home + '/.config/systemd/user', image_symlink_target=home + '/.config/containers')
    report['volume_members_kept'] = append_escape(
        orig_volume, new_volume, report['volume_symlink_target'], tag + '-planted.service',
        b'[Unit]\nDescription=woowbk SEC-1 lab canary (harmless, never started)\n')
    report['image_members_kept'] = append_escape(orig_image, new_image, report['image_symlink_target'],
                                                 tag + '-planted.conf', b'# woowbk SEC-1 lab canary (harmless)\n')
    report['engine_checks'] = {
        'volume_original': verdict(lambda: nested.check_volume(orig_volume)),
        'volume_crafted': verdict(lambda: nested.check_volume(new_volume)),
        'image_original': verdict(lambda: nested.check_oci(orig_image, ref=image['ref'], image_id=image['id'])),
        'image_crafted': verdict(lambda: nested.check_oci(new_image, ref=image['ref'], image_id=image['id'])),
    }
    replaced = {volume['entry']: new_volume, image['entry']: new_image}
    entries = {e['path']: e for e in manifest['entries']}
    for entry, local in replaced.items():
        sha, size = digest(local)
        entries[entry].update(size=size, sha256=sha)
    now = time.gmtime()
    new_id = time.strftime('%Y%m%dT%H%M%SZ', now) + '-' + secrets.token_hex(4)
    created = time.strftime('%Y-%m-%dT%H:%M:%SZ', now)
    manifest.update(backup_id=new_id, created=created, note='SEC-1 lab: nested tar symlink escape')
    if FORMAT == 2:
        # Only the nested content is hostile: the engine's own writer re-seals the app with the device recipient
        # (valid per-app manifest, backup.json and checksums).
        from woowbackup import archive as warchive
        locals_ = {}
        for index, member in enumerate(members[1:]):
            if member.name in replaced:
                locals_[member.name] = replaced[member.name]
                continue
            path = os.path.join(work, 'm%d' % index)
            with plain.extractfile(member) as raw, open(path, 'wb') as out:
                shutil.copyfileobj(raw, out, 1 << 20)
            locals_[member.name] = path
        plain.close()
        os.unlink(plain_path)
        items = [warchive.Entry(e['path'], locals_[e['path']], int(e['size']), e['sha256']) for e in manifest['entries']]
        head = {key: manifest[key] for key in warchive.HEAD_FIELDS}
        out_path = os.path.join(work, 'crafted.tar')
        with warchive.ArchiveWriter(out_path, head, [app], recipient, tmp_dir=work) as writer:
            writer.add_app(app, items)
            writer.finish()
        report.update(backup_id=new_id, path=out_path, size=os.path.getsize(out_path), format=2,
                      plain_bytes=sum(int(e['size']) for e in manifest['entries']))
        raise SystemExit(0)
    data = json.dumps(manifest, ensure_ascii=False, separators=(',', ':')).encode()
    new_plain = os.path.join(work, 'plain.new.tar')
    with open(new_plain, 'wb') as out_file, tarfile.open(fileobj=out_file, mode='w', format=tarfile.PAX_FORMAT) as out:
        out.addfile(outer('manifest.json', len(data)), io.BytesIO(data))
        for member in members[1:]:
            if member.name in replaced:
                with open(replaced[member.name], 'rb') as handle:
                    out.addfile(outer(member.name, entries[member.name]['size']), handle)
            else:
                out.addfile(outer(member.name, member.size), plain.extractfile(member))
    plain.close()
    for path in (plain_path, orig_volume, orig_image, new_volume, new_image):
        os.unlink(path)
    header = {'format': 1, 'backup_id': new_id, 'created': created, 'key_id': old_header['key_id'],
              'encryption': 'age-x25519', 'compression': 'zstd'}
    out_path = os.path.join(work, 'crafted.woowbackup')
    with open(out_path, 'wb') as sink:
        sink.write(b'WOOWTECH-BACKUP/1\n' + json.dumps(header, separators=(',', ':')).encode() + b'\n')
        sink.flush()
        with open(new_plain, 'rb') as source:
            pipeline([['zstd', '-q', '-c', '-3'], ['age', '-e', '-r', recipient]], source, sink)
    report.update(backup_id=new_id, path=out_path, size=os.path.getsize(out_path), format=1,
                  plain_bytes=os.path.getsize(new_plain))
except SystemExit as stop:
    if stop.code not in (0, None):
        raise
finally:
    for name in os.listdir(work):
        if not name.startswith('crafted.'):
            os.unlink(os.path.join(work, name))
print(json.dumps(report))
'''


def sec1_craft(dev, base_id, ev):
    sh(dev, f'rm -rf {SEC1_WORK}', check=False)
    proc = py(dev, CRAFT_SEC1, base_id, SEC1_WORK, SEC1_APP_REF, SEC1_TAG, timeout=900, check=False)
    if proc.returncode != 0:
        sh(dev, f'rm -rf {SEC1_WORK}', check=False)
        raise Failed(f'SEC-1 craft failed rc={proc.returncode}: {redact(proc.stderr.decode("utf-8", "replace")[-600:])}')
    report = json.loads(proc.stdout)
    local = private_dir(WORK / 'sec1') / f'sec1-crafted{".tar" if report.get("format") == 2 else ".woowbackup"}'
    try:
        write_private_stream(dev, report['path'], local)
    finally:
        sh(dev, f'rm -rf {SEC1_WORK}', check=False)
    report.update(file=str(local), host_size=local.stat().st_size, sha256=file_sha256(local))
    return report


def write_private_stream(dev, device_path, local):
    """Copy a (ciphertext) file out of a device into a 0600 host file."""
    e2e.write_private(local, b'')
    with open(local, 'wb') as handle:
        proc = subprocess.run([LP, 'exec', dev_name(dev), 'cat', device_path], stdout=handle, stderr=subprocess.PIPE,
                              timeout=600)
    if proc.returncode != 0:
        raise Failed(f'copy of {device_path} from dev-{dev} failed rc={proc.returncode}')


def scenario_sec1(ev):
    """SEC-1 live: a backup encrypted to dev-a's own key whose volume tar and app-image OCI archive each hold an
    absolute symlink into the owner's home plus a member written through it. The restore must refuse it before any
    podman load or volume import; nothing may be written outside staging; the app stays untouched."""
    dev = 'a'
    status = ok(dev, 'status', ev=ev)
    ev.require('dev-a: device key present, app running, no active job',
               status['key'] and status['active_job'] is None
               and next(a for a in status['apps'] if a['id'] == APP)['state'] == 'running', status.get('key'))
    ev.require('dev-a: no orphan archives and empty staging before SEC-1', orphans(dev) == [] and staging_empty(dev),
               orphans(dev))
    ev.require('dev-a: no woowbk-sec1 path anywhere before the case', canaries(dev, SEC1_TAG) == [],
               canaries(dev, SEC1_TAG))
    scanner_selftest(dev, ev)

    # Control: the crafted shape really escapes with bare podman, so the engine's refusal is what protects the owner.
    control = json.loads(owner(dev, 'python3', '-I', '-c', SEC1_CONTROL, SEC1_TAG, timeout=300).stdout)
    ev.save('sec1-control', control)
    written = control.get('written_through_symlink') or {}
    ev.check('SEC-1 control: bare `podman volume import` writes the member through the absolute symlink into the '
             "owner's home (podman 4.9.3 on the device)", control.get('volume_import_rc') == 0
             and written.get('volume-import') == [f'{SEC1_TAG}-planted-by-volume-import'], control)
    ev.check("SEC-1 control: bare `podman load` (oci-archive attempt) writes it into the owner's home as well",
             written.get('load') == [f'{SEC1_TAG}-planted-by-load'], control)
    ev.check('SEC-1 control left nothing behind', canaries(dev, SEC1_TAG) == [], canaries(dev, SEC1_TAG))

    created = []
    try:
        job, _log = backup_once(dev, ev, 'SEC-1 基礎備份（含映像）', images=True, label='backup[sec1-base]')
        ev.require('SEC-1 base backup with images succeeded', job['state'] == 'succeeded', job.get('error'))
        base_id = job['result']['backup_id']
        created.append(base_id)
        meta = sec1_craft(dev, base_id, ev)
        ev.save('sec1-crafted', meta)
        checks = meta['engine_checks']
        ev.log(f'SEC-1 crafted {meta["host_size"]} bytes (plain {meta["plain_bytes"]}), backup {meta["backup_id"]}; '
               f'engine nested checks: {checks}')
        ev.check('SEC-1 crafting: the original volume tar and OCI archive pass the engine checks (only the planted '
                 'members differ)', checks['volume_original'] == {'accepted': True}
                 and checks['image_original'] == {'accepted': True}, checks)
        ev.check('SEC-1 crafting: the engine refuses the crafted volume tar (member below a symlink)',
                 checks['volume_crafted'].get('code') == 'corrupt-archive'
                 and 'below a symlink' in (checks['volume_crafted'].get('reason') or '')
                 and checks['volume_crafted'].get('member') == f'{SEC1_TAG}-esc/{SEC1_TAG}-planted.service',
                 checks['volume_crafted'])
        ev.check('SEC-1 crafting: the engine refuses the crafted OCI archive (the planted symlink is not a regular file '
                 'or directory)', checks['image_crafted'].get('code') == 'corrupt-archive'
                 and checks['image_crafted'].get('member') == f'{SEC1_TAG}-esc', checks['image_crafted'])
        with open(meta['file'], 'rb') as handle:
            head = handle.read(1 << 20)
        if meta.get('format') == 2:
            # Format 2: backup.json (names only) + README + the app's age archive; no plaintext manifest or data.
            ev.check('SEC-1 crafting: the host received ciphertext only (backup.json/README + age, no plaintext '
                     'manifest; README.txt only names manifest.json)', meta['host_size'] == meta['size']
                     and head[257:262] == b'ustar' and head.startswith(b'backup.json') and b'"entries"' not in head
                     and b'"backup_apps"' not in head and b'age-encryption.org/v1' in head and b'AGE-SECRET-KEY' not in head)
        else:
            ev.check('SEC-1 crafting: the host received ciphertext only (outer header + age, no plaintext manifest)',
                     meta['host_size'] == meta['size'] and head.startswith(b'WOOWTECH-BACKUP/1\n')
                     and b'"apps"' not in head and b'age-encryption.org/v1' in head)
        backup_id = meta['backup_id']
        created.append(backup_id)

        baseline = {'summary': summary(dev), 'content': content_state(dev), 'owner': owner_fingerprint(dev),
                    'images': owner_images(dev), 'home_config': owner_config_listing(dev)}
        before_ids = backup_ids(dev, ev)
        t_start = device_clock(dev)
        _begin, (_rc, reply) = e2e.upload_file(dev, meta['file'], ev=ev, filename=Path(meta['file']).name)
        uploaded = reply.get('backup') or {}
        ev.require('SEC-1 upload-finish accepts the archive (outer header, age header and size are valid)',
                   reply.get('ok') and uploaded.get('id') == backup_id and uploaded.get('key_available') is True,
                   reply.get('error'))
        _rc, inspected = helper(dev, 'inspect', {'backup_id': backup_id}, ev=ev)
        ev.save('sec1-inspect', inspected)
        ev.check('SEC-1 inspect (manifest only, what the wizard shows) answers; it cannot open nested tars, the restore '
                 "job's preflight checks them (CONTRACT section 5)", inspected.get('ok'), inspected.get('error'))
        start = ok(dev, 'verify-start', {'backup_id': backup_id, 'request_id': request_id()}, ev=ev)
        vjob, vlog = wait_job(dev, start['job_id'], ev=ev, timeout=600, label='verify[sec1]')
        save_job(ev, 'sec1-verify', vjob, vlog)
        ev.log(f'SEC-1 verify job: {vjob["state"]} {vjob.get("error")} {vjob.get("result")}')
        # Since 2026-11-13 the verify job checks every nested tar the way a restore does (deep verify, CONTRACT
        # section 5): the backup no longer shows as verified while a restore would refuse it.
        verified = (next((b for b in backups(dev, ev) if b['id'] == backup_id), {}) or {}).get('verified') or {}
        ev.check('SEC-1 the deep verify job refuses the hostile nested tars (corrupt-archive) and marks the backup '
                 'verified {ok: false, deep: true}; it changes nothing', vjob['state'] == 'failed'
                 and (vjob.get('error') or {}).get('code') == 'corrupt-archive' and verified.get('ok') is False
                 and verified.get('deep') is True, {'error': vjob.get('error'), 'verified': verified})
        ev.log('SEC-1 observation: inspect (manifests only, what the wizard shows first) still answers; the deep verify '
               'job and the restore job (preflight with the extracted archive) refuse it')

        rstart = ok(dev, 'restore-start', {'backup_id': backup_id, 'apps': [APP], 'request_id': request_id(),
                                          'confirm': True}, ev=ev)
        rjob, rlog = wait_job(dev, rstart['job_id'], ev=ev, timeout=900, label='restore[sec1]')
        save_job(ev, 'sec1-restore', rjob, rlog)
        phases = phase_states(rjob)
        message = (rjob.get('error') or {}).get('message') or ''
        ev.check('SEC-1 restore job fails in preflight, before the safety backup and before any stop',
                 rjob['state'] == 'failed' and (rjob.get('error') or {}).get('code') == 'incompatible'
                 and phases.get('preflight') == 'failed' and phases.get('safety') == 'pending'
                 and phases.get('stop') == 'pending' and (rjob.get('result') or {}).get('changed') is not True,
                 {'state': rjob['state'], 'error': rjob.get('error'), 'phases': phases})
        ev.check('SEC-1 both nested tars are refused on their own (image and volume each named in the error)',
                 '容器映像含有不安全' in message and '資料卷含有不安全' in message, message)
        ev.check('SEC-1 the job log names each refusal and never reaches 載入映像 or 已重建資料卷',
                 sum('未通過：' in line and '不安全' in line and '作業結束' not in line for line in rlog) == 2
                 and not any('載入映像' in line or '已重建資料卷' in line or '停止服務' in line for line in rlog),
                 [line for line in rlog if '未通過' in line])
        t_end = device_clock(dev)
        rc, events = owner_events(dev, t_start, t_end)
        ev.save('sec1-podman-events', {'rc': rc, 'events': events})
        ev.check('SEC-1 no podman image or volume event at all during upload, verify and restore (no load, tag, '
                 'volume create/remove or import)', rc == 0 and events == [], events)
        unexpected, counts = changed_since(dev, t_start)
        ev.save('sec1-changed-scan', {'unexpected': unexpected, 'counts': counts,
                                      'foreign_podman_events_in_window': foreign_activity(dev, t_start)})
        ev.check('SEC-1 no file written or changed outside the engine records/staging during the attempt',
                 unexpected == {}, unexpected)
        found = canaries(dev, SEC1_TAG)
        ev.check(f'SEC-1 no {SEC1_TAG} path exists anywhere on the device (nothing planted in ~/.config/systemd/user '
                 'or ~/.config/containers)', found == [], found)
        ev.check("SEC-1 the owner's ~/.config/systemd/user and ~/.config/containers are unchanged",
                 owner_config_listing(dev) == baseline['home_config'], owner_config_listing(dev))
        ev.check('SEC-1 app data, deployment files, volumes, secrets and image names unchanged; units active',
                 content_state(dev) == baseline['content'] and compare(summary(dev), baseline['summary']) == {}
                 and owner_fingerprint(dev) == baseline['owner'] and owner_images(dev) == baseline['images']
                 and units_active(dev)[0], {'images': owner_images(dev)})
        ev.check('SEC-1 staging empty, no job key files, no orphan archive files',
                 staging_empty(dev) and no_job_keys(dev) and orphans(dev) == [], {'orphans': orphans(dev)})
        new_ids = backup_ids(dev, ev) - before_ids
        ev.check('SEC-1 no backup listed except the upload itself (no safety backup was taken)', new_ids == {backup_id},
                 sorted(new_ids))
        return {'backup_id': backup_id, 'engine_checks': checks, 'verify_job': vjob['state'],
                'restore': {'state': rjob['state'], 'error': rjob.get('error'), 'phases': phases}}
    finally:
        for backup_id in created:
            if backup_id in backup_ids(dev, ev):
                ok(dev, 'delete', {'backup_id': backup_id}, ev=ev)
        sh(dev, f'rm -rf {SEC1_WORK}', check=False)
        ev.check('dev-a after SEC-1: app running, staging empty, no orphans, work directory removed',
                 app_status(dev, ev)['state'] == 'running' and staging_empty(dev) and orphans(dev) == []
                 and sh(dev, f'test -e {SEC1_WORK}', check=False).returncode != 0)


def owner_config_listing(dev):
    """Names, sizes and sha256 of the files in the owner's ~/.config/systemd/user and ~/.config/containers."""
    script = ('cd "$HOME"/.config && find systemd/user containers -xdev \\( -type f -o -type l \\) '
              '-printf "%y %s %p -> %l\\n" 2>/dev/null | sort; find systemd/user containers -xdev -type f '
              '-exec sha256sum {} + 2>/dev/null | sort; true')
    return owner(dev, 'sh', '-c', script).stdout.decode()


# ------------------------------------------------------------------ fidelity: legitimate volume content

FIDELITY_DIR = 'woowbk-fidelity'  # next to files/ in the app volume: the app does not count it
FIDELITY_FIELDS = ('type', 'uid', 'gid', 'mode', 'size', 'mtime', 'nlink', 'link', 'sha256', 'xattrs', 'link_group')

# Runs as root of the owner's user namespace (the IDs the container sees). argv[1]: the volume mountpoint.
MAKE_FIDELITY = r'''
import hashlib, json, os, sys
root = os.path.join(os.fsencode(sys.argv[1]), b'woowbk-fidelity')
os.mkdir(root, 0o755)
notes = {}
def path(rel):
    return os.path.join(root, os.fsencode(rel) if isinstance(rel, str) else rel)
def data(label, size):
    out, block = b'', hashlib.sha256(label.encode()).digest()
    while len(out) < size:
        block = hashlib.sha256(block).digest()
        out += block
    return out[:size]
def stamp(p, mtime, follow=True):
    ns = int(round(mtime * 10**9))
    os.utime(p, ns=(ns, ns), follow_symlinks=follow)
def put(rel, content, mode=0o644, uid=0, gid=0, mtime=1700000000):
    p = path(rel)
    with open(p, 'wb') as handle:
        handle.write(content)
    os.chown(p, uid, gid)
    os.chmod(p, mode)
    stamp(p, mtime)
def link(rel, target, uid=0, gid=0, mtime=1700000500):
    p = path(rel)
    os.symlink(os.fsencode(target), p)
    os.lchown(p, uid, gid)
    stamp(p, mtime, follow=False)
def mkdir(rel, mode=0o755, uid=0, gid=0):
    p = path(rel)
    os.mkdir(p)
    os.chown(p, uid, gid)
    os.chmod(p, mode)
long_dir = 'deep/' + 'd' * 120 + '/' + 'e' * 120
put('plain.bin', data('plain', 65536 + 17))
put('empty.txt', b'', mode=0o600, mtime=1700000001)
put('hard-a.txt', b'hardlinked content\n', mode=0o640, uid=1000, gid=1000, mtime=1700000002)
os.link(path('hard-a.txt'), path('hard-b.txt'))
link('abs-link-dir', '/data/files')
link('abs-link-file', '/data/woowbk-fidelity/plain.bin', uid=70, gid=70)
link('abs-dangling', '/etc/woowbk-fidelity-missing')
link('rel-link', '../files')
put('n' * 180 + '.txt', b'long name\n', mtime=1700000003)
mkdir('deep')
mkdir('deep/' + 'd' * 120)
mkdir(long_dir, mode=0o700)
put(long_dir + '/' + 'f' * 150 + '.dat', data('deep', 4096), mtime=1700000004)
mkdir('empty-dir', mode=0o750, uid=33, gid=33)
mkdir('sgid-dir', mode=0o2775, gid=1000)
put('sgid-dir/inner.txt', b'inherits the group\n', mode=0o664, gid=1000, mtime=1700000005)
mkdir('sticky-dir', mode=0o1777)
put('xattr.txt', b'has user xattrs\n', mtime=1700000006)
try:
    os.setxattr(path('xattr.txt'), 'user.woowbk.fidelity', 'value-中-\x01'.encode())
    os.setxattr(path('xattr.txt'), 'user.woowbk.second', b'2')
    notes['xattr'] = True
except OSError as error:
    notes['xattr'] = '%s: %s' % (type(error).__name__, error)
try:
    put(b'latin1-caf\xe9-\xff.bin', b'non-utf8 name\n', mtime=1700000007)
    notes['non_utf8_name'] = True
except OSError as error:
    notes['non_utf8_name'] = '%s: %s' % (type(error).__name__, error)
put('中文檔名-\U00020bb7.txt', '內容\n'.encode(), mtime=1700000008)
os.mkfifo(path('pipe'))
os.chmod(path('pipe'), 0o620)
stamp(path('pipe'), 1700000009)
put('subsecond.txt', b'sub-second mtime\n', mtime=1700000123.456789)
put('owned-70.txt', b'postgres-like owner\n', uid=70, gid=70, mtime=1700000010)
put('owned-54999.txt', b'high mapped owner\n', uid=54999, gid=54999, mtime=1700000011)
put('exec.sh', b'#!/bin/sh\necho fidelity\n', mode=0o755, mtime=1700000012)
put('ro.txt', b'read only\n', mode=0o444, mtime=1700000013)
for rel, t in ((long_dir, 1700000100), ('deep/' + 'd' * 120, 1700000101), ('deep', 1700000102), ('empty-dir', 1700000103),
               ('sgid-dir', 1700000104), ('sticky-dir', 1700000105)):
    stamp(path(rel), t)
stamp(root, 1700000106)
print(json.dumps(notes))
'''

# Changes after the backup, so the in-place restore has to put every kind of entry back.
MUTATE_FIDELITY = r'''
import os, sys
root = os.path.join(os.fsencode(sys.argv[1]), b'woowbk-fidelity')
def path(rel):
    return os.path.join(root, os.fsencode(rel) if isinstance(rel, str) else rel)
os.unlink(path('hard-b.txt'))
with open(path('plain.bin'), 'r+b') as handle:
    handle.write(b'MUTATED')
os.removexattr(path('xattr.txt'), 'user.woowbk.fidelity')
os.chmod(path('sgid-dir'), 0o755)
os.unlink(path(b'latin1-caf\xe9-\xff.bin'))
os.unlink(path('n' * 180 + '.txt'))
os.chown(path('owned-70.txt'), 0, 0)
os.unlink(path('abs-link-file'))
os.symlink(b'/etc/hostname', path('abs-link-file'))
os.rmdir(path('empty-dir'))
os.utime(path('ro.txt'), (1600000000, 1600000000))
with open(path('extra-after-backup.txt'), 'wb') as handle:
    handle.write(b'must not survive the restore\n')
print('mutated')
'''

REMOVE_FIDELITY = r'''
import os, shutil, sys
root = os.path.join(os.fsencode(sys.argv[1]), b'woowbk-fidelity')
if os.path.lexists(root):
    shutil.rmtree(root)
print(os.path.lexists(root))
'''

# Runs inside the app container (`podman exec`): the volume as the application sees it. One row per entry: type,
# uid/gid, mode, size, mtime, link count and hard-link group, symlink target, sha256, user.* xattrs; names as hex.
LIST_FIDELITY = r'''
import hashlib, json, os, stat, sys
root = os.fsencode(sys.argv[1])
rows, inodes = {}, {}
def row(p):
    st = os.lstat(p)
    rel = os.path.relpath(p, root)
    mode = st.st_mode
    kind = ('dir' if stat.S_ISDIR(mode) else 'file' if stat.S_ISREG(mode) else 'symlink' if stat.S_ISLNK(mode)
            else 'fifo' if stat.S_ISFIFO(mode) else 'other')
    r = {'name': rel.decode('utf-8', 'backslashreplace'), 'name_hex': rel.hex(), 'type': kind, 'uid': st.st_uid,
         'gid': st.st_gid, 'mode': oct(stat.S_IMODE(mode)), 'size': st.st_size if kind in ('file', 'symlink') else None,
         'mtime': st.st_mtime_ns // 10**9, 'mtime_ns': st.st_mtime_ns, 'nlink': None if kind == 'dir' else st.st_nlink}
    if kind == 'symlink':
        r['link'] = os.readlink(p).decode('utf-8', 'backslashreplace')
    if kind == 'file':
        h = hashlib.sha256()
        with open(p, 'rb') as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b''):
                h.update(chunk)
        r['sha256'] = h.hexdigest()
    try:
        names = sorted(n for n in os.listxattr(p, follow_symlinks=False) if n.startswith('user.'))
        r['xattrs'] = {n: os.getxattr(p, n, follow_symlinks=False).hex() for n in names}
    except OSError as error:
        r['xattrs'] = 'error %s' % error.errno
    if kind != 'dir' and st.st_nlink > 1:
        inodes.setdefault(st.st_ino, []).append(r['name'])
    r['_ino'] = st.st_ino
    rows[r['name_hex']] = r
for base, dirs, files in os.walk(root):
    row(base)
    for name in files:
        row(os.path.join(base, name))
    for name in dirs:
        if os.path.islink(os.path.join(base, name)):
            row(os.path.join(base, name))
groups = {ino: sorted(names)[0] for ino, names in inodes.items()}
for r in rows.values():
    r['link_group'] = groups.get(r.pop('_ino'))
print(json.dumps(sorted(rows.values(), key=lambda r: r['name_hex'])))
'''


def fidelity_listing(dev):
    """The probe directory as the running app container sees it."""
    out = owner(dev, 'podman', 'exec', '-i', 'woowbk-demo-app', 'python3', '-I', '-', f'/data/{FIDELITY_DIR}',
                input=LIST_FIDELITY.encode(), timeout=300).stdout
    return json.loads(out)


def fidelity_userns_listing(dev, mountpoint):
    """The same directory read from the device side through `podman unshare` (must equal the container view)."""
    return json.loads(in_userns(dev, LIST_FIDELITY, f'{mountpoint}/{FIDELITY_DIR}'))


def listing_diff(want, got, fields=FIDELITY_FIELDS):
    """{display name: {field: [want, got]} | 'missing' | 'unexpected'} over the union of both listings."""
    a = {row['name_hex']: row for row in want}
    b = {row['name_hex']: row for row in got}
    diff = {}
    for key in sorted(set(a) | set(b)):
        if key not in b:
            diff[a[key]['name']] = 'missing'
        elif key not in a:
            diff[b[key]['name']] = 'unexpected'
        else:
            changed = {f: [a[key].get(f), b[key].get(f)] for f in fields if a[key].get(f) != b[key].get(f)}
            if changed:
                diff[a[key]['name']] = changed
    return diff


def kinds_present(listing):
    """What the probe covers, from the listing itself (so a silently skipped entry fails the scenario)."""
    by_name = {row['name']: row for row in listing}
    return {
        'absolute symlink': any(r['type'] == 'symlink' and (r.get('link') or '').startswith('/') for r in listing),
        'hard link': any(r.get('link_group') for r in listing),
        'name > 100 bytes': any(len(bytes.fromhex(r['name_hex']).rsplit(b'/', 1)[-1]) > 100 for r in listing),
        'path > 255 bytes': any(len(bytes.fromhex(r['name_hex'])) > 255 for r in listing),
        'empty directory': by_name.get('empty-dir', {}).get('type') == 'dir',
        'setgid directory': by_name.get('sgid-dir', {}).get('mode') == '0o2775',
        'user xattr': bool((by_name.get('xattr.txt') or {}).get('xattrs')),
        'non-UTF-8 name': any(_not_utf8(r['name_hex']) for r in listing),
        'fifo': by_name.get('pipe', {}).get('type') == 'fifo',
        'owner other than root': any(r['uid'] not in (0,) for r in listing),
    }


def _not_utf8(name_hex):
    try:
        bytes.fromhex(name_hex).decode('utf-8')
        return False
    except UnicodeDecodeError:
        return True


def scenario_fidelity(ev):
    """Legitimate volume content survives backup -> in-place restore (dev-a) and -> cross-device fresh restore (dev-b):
    a full listing as the app container sees it (type, uid/gid, mode, size, mtime, link target, sha256, xattrs, hard
    links) must be identical."""
    dev = 'a'
    status = ok(dev, 'status', ev=ev)
    ev.require('dev-a: device key present, app running, no active job',
               status['key'] and status['active_job'] is None
               and next(a for a in status['apps'] if a['id'] == APP)['state'] == 'running')
    mount_a = volume_mountpoint(dev, 'woowbk-demo-files')
    in_userns(dev, REMOVE_FIDELITY, mount_a)  # a previous aborted run
    created_a, created_b, local = [], [], None
    try:
        notes = json.loads(in_userns(dev, MAKE_FIDELITY, mount_a))
        ev.save('fidelity-make', notes)
        ev.check('fidelity: the file system takes user xattrs and a non-UTF-8 file name', notes == {
            'xattr': True, 'non_utf8_name': True}, notes)
        before = fidelity_listing(dev)
        ev.save('fidelity-L0-dev-a-before-backup', before)
        present = kinds_present(before)
        ev.check(f'fidelity: the probe holds every kind of entry ({len(before)} entries)', all(present.values()),
                 present)
        userns_view = fidelity_userns_listing(dev, mount_a)
        ev.check('fidelity: the container view equals the `podman unshare` view (same IDs)',
                 listing_diff(before, userns_view, FIDELITY_FIELDS + ('mtime_ns',)) == {},
                 listing_diff(before, userns_view))
        snapshot = summary(dev)
        job, log = backup_once(dev, ev, '發布回歸：資料卷內容保真度', images=True, label='backup[fidelity]')
        save_job(ev, 'fidelity-backup', job, log)
        ev.require('fidelity backup with images succeeded', job['state'] == 'succeeded', job.get('error'))
        backup_id = job['result']['backup_id']
        created_a.append(backup_id)
        ev.check('fidelity backup: no warning about dropped modes or attributes (nothing here is dropped)',
                 not any('setuid' in line or '延伸屬性' in line for line in log), [l for l in log if '注意' in l][:5])

        in_userns(dev, MUTATE_FIDELITY, mount_a)
        mutated = fidelity_listing(dev)
        ev.check('fidelity: the mutation after the backup took effect (listing differs)',
                 len(listing_diff(before, mutated)) >= 8, sorted(listing_diff(before, mutated))[:12])
        start = ok(dev, 'restore-start', {'backup_id': backup_id, 'apps': [APP], 'request_id': request_id(),
                                          'confirm': True}, ev=ev)
        rjob, rlog = wait_job(dev, start['job_id'], ev=ev, label='restore[fidelity-inplace]')
        save_job(ev, 'fidelity-restore-inplace', rjob, rlog)
        created_a.append((rjob.get('result') or {}).get('safety_backup_id'))
        ev.require('fidelity: in-place restore on dev-a succeeded', rjob['state'] == 'succeeded', rjob.get('error'))
        ev.check('fidelity: the in-place restore reports no dropped attributes',
                 not (rjob.get('result') or {}).get('warnings'), (rjob.get('result') or {}).get('warnings'))
        after_a = fidelity_listing(dev)
        ev.save('fidelity-L1-dev-a-after-inplace-restore', after_a)
        diff_a = listing_diff(before, after_a)
        ev.check('fidelity: dev-a after the in-place restore equals the backup-time listing (type, uid/gid in the '
                 'container, mode, size, mtime, link target, sha256, xattrs, hard links)', diff_a == {}, diff_a)
        ns_a = sorted(k for k, v in listing_diff(before, after_a, ('mtime_ns',)).items())
        ev.check('fidelity: sub-second mtimes are the only nanosecond difference (tar keeps whole seconds)',
                 ns_a in ([], ['subsecond.txt']), ns_a)
        ev.check('fidelity: app data equals the backup-time snapshot on dev-a', compare(summary(dev), snapshot) == {},
                 compare(summary(dev), snapshot))

        # Cross-device: download from A, fresh restore on B (appowner UID 1007, same subordinate range).
        info = ok(dev, 'download-info', {'backup_id': backup_id}, ev=ev)
        local = private_dir(WORK / 'fidelity') / info['filename']
        got = e2e.bridge_download(dev, info['path'], local, ev=ev)
        ev.require('fidelity download: size equals the index', got['bytes'] == info['size'], got)
        e2e.reset_target('b', ev)
        _begin, (_rc, reply) = e2e.upload_file('b', local, ev=ev)
        ev.require('fidelity backup uploaded to dev-b', reply.get('ok'), reply.get('error'))
        created_b.append(backup_id)
        start = ok('b', 'restore-start', {'backup_id': backup_id, 'apps': [APP], 'request_id': request_id(),
                                          'confirm': True, 'key': e2e.kit_secret()}, ev=ev)
        bjob, blog = wait_job('b', start['job_id'], ev=ev, label='restore[fidelity-fresh-b]')
        save_job(ev, 'fidelity-restore-fresh-dev-b', bjob, blog)
        ev.require('fidelity: cross-device fresh restore on dev-b succeeded', bjob['state'] == 'succeeded',
                   bjob.get('error'))
        after_b = fidelity_listing('b')
        ev.save('fidelity-L2-dev-b-after-fresh-restore', after_b)
        diff_b = listing_diff(before, after_b)
        ev.check('fidelity: dev-b after the cross-device restore equals the dev-a backup-time listing (IDs as the '
                 'container sees them)', diff_b == {}, diff_b)
        ns_b = sorted(listing_diff(before, after_b, ('mtime_ns',)))
        ev.check('fidelity: on dev-b too only sub-second mtimes differ at nanosecond level', ns_b in ([], ['subsecond.txt']),
                 ns_b)
        device_ids = sh('b', 'stat -c "%u:%g" /home/appowner/.local/share/containers/storage/volumes/woowbk-demo-files/'
                             f'_data/{FIDELITY_DIR}/plain.bin').stdout.decode().strip()
        ev.check('fidelity: on the device a container-root file belongs to dev-b\'s own appowner (1007)',
                 device_ids == '1007:1007', device_ids)
        ev.check('fidelity: app data on dev-b equals the dev-a snapshot', compare(summary('b'), snapshot) == {},
                 compare(summary('b'), snapshot))
        return {'entries': len(before), 'kinds': present, 'diff_inplace': diff_a, 'diff_cross_device': diff_b}
    finally:
        in_userns(dev, REMOVE_FIDELITY, mount_a)
        ev.check('fidelity probe directory removed from dev-a', fidelity_absent(dev, mount_a))
        try:
            mount_b = volume_mountpoint('b', 'woowbk-demo-files')
            in_userns('b', REMOVE_FIDELITY, mount_b)
            ev.check('fidelity probe directory removed from dev-b', fidelity_absent('b', mount_b))
        except Failed as error:
            ev.log(f'dev-b has no app volume to clean: {error}')
        for backup_id in created_a:
            if backup_id and backup_id in backup_ids(dev, ev):
                ok(dev, 'delete', {'backup_id': backup_id}, ev=ev)
        for backup_id in created_b:
            if backup_id in backup_ids('b', ev):
                ok('b', 'delete', {'backup_id': backup_id}, ev=ev)
        if local is not None and local.exists():
            local.unlink()


def fidelity_absent(dev, mountpoint):
    return in_userns(dev, f'import os,sys; print(os.path.lexists(os.path.join(sys.argv[1], {FIDELITY_DIR!r})))',
                     mountpoint).strip() == 'False'


# ------------------------------------------------------------------ fresh restore: leftovers, SIGKILL, rollback

FRESH_PROBE_IMAGE = 'localhost/woowbk-fresh-probe:old'
KEEP = {'volume': 'woowbk-keep-vol', 'secret': 'woowbk-keep-secret', 'config': '.config/woowbk-keep/keep.env',
        'network': 'woowbk-keep-net', 'image': 'localhost/woowbk-keep:1'}
APP_IMAGE = 'localhost/woowbk-demo-app:1'
PG_IMAGE = 'docker.io/library/postgres:16-alpine'

# Objects of the same names as the app's (preflight must refuse a fresh restore) and unrelated objects (nothing may
# remove them). Random contents are generated in the device and never read back; only ids and sha256 are compared.
LEFTOVERS = {
    'secret': ('woowbk-demo-db-password', 'head -c 24 /dev/urandom | base64 | podman secret create woowbk-demo-db-password -'
               ' >/dev/null', 'podman secret rm woowbk-demo-db-password >/dev/null', 'secret-existing'),
    'config': ('.config/woowbk-demo/app.env', 'mkdir -p -m 700 .config/woowbk-demo && umask 077 && '
               '(echo "# leftover of an earlier deployment"; echo "APP_TITLE=leftover") > .config/woowbk-demo/app.env',
               'rm -f .config/woowbk-demo/app.env', 'config-existing'),
    'volume': ('woowbk-demo-files', 'podman volume create woowbk-demo-files >/dev/null && echo leftover > '
               '"$(podman volume inspect --format "{{.Mountpoint}}" woowbk-demo-files)/leftover.txt"',
               'podman volume rm -f woowbk-demo-files >/dev/null', 'volume-conflict'),
    'database-volume': ('woowbk-demo-pgdata', 'podman volume create woowbk-demo-pgdata >/dev/null && echo leftover > '
                        '"$(podman volume inspect --format "{{.Mountpoint}}" woowbk-demo-pgdata)/leftover.txt"',
                        'podman volume rm -f woowbk-demo-pgdata >/dev/null', 'volume-conflict'),
}

OBJECT_STATE = r'''
cd "$HOME"
for v in woowbk-demo-files woowbk-demo-pgdata woowbk-keep-vol; do
  if podman volume exists "$v"; then
    mp=$(podman volume inspect --format '{{.Mountpoint}} {{.CreatedAt}}' "$v"); echo "volume $v $mp"
    (cd "${mp%% *}" && find . -type f -exec sha256sum {} + 2>/dev/null | sort | sed "s|^|content $v |")
  fi
done
for s in woowbk-demo-db-password woowbk-demo-app-key woowbk-keep-secret; do
  podman secret exists "$s" && echo "secret $s $(podman secret inspect --format '{{.ID}} {{.CreatedAt}}' "$s")"
done
for f in .config/woowbk-demo/app.env .config/woowbk-keep/keep.env; do
  test -e "$f" && echo "config $f $(stat -c '%a %s %Y' "$f") $(sha256sum < "$f" | cut -c1-64)"
done
for n in woowbk-demo woowbk-keep-net; do
  podman network exists "$n" && echo "network $n $(podman network inspect --format '{{.ID}}' "$n")"
done
ls -A .config/containers/systemd/ 2>/dev/null | grep woowbk-demo | sed 's/^/quadlet /'
ls -A .config/systemd/user/ 2>/dev/null | grep woowbk-demo | sed 's/^/user-unit /'
true
'''


def object_state(dev):
    """Owner-side objects relevant to the fresh cases (names, ids, creation times, content digests; no contents).
    Only woowbk-demo's Quadlet files and unit masks: the host-directory fixture (woowbk-dirs) may be deployed too."""
    return owner(dev, 'sh', '-c', OBJECT_STATE).stdout.decode().splitlines()


def keep_objects(dev, create):
    if create:
        script = (f'cd "$HOME" && podman volume create {KEEP["volume"]} >/dev/null && head -c 4096 /dev/urandom > '
                  f'"$(podman volume inspect --format "{{{{.Mountpoint}}}}" {KEEP["volume"]})/keep.bin" && '
                  f'head -c 24 /dev/urandom | base64 | podman secret create {KEEP["secret"]} - >/dev/null && '
                  f'mkdir -p -m 700 "$(dirname {KEEP["config"]})" && umask 077 && head -c 64 /dev/urandom | base64 > '
                  f'{KEEP["config"]} && podman network create {KEEP["network"]} >/dev/null && '
                  f'podman tag {FRESH_PROBE_IMAGE} {KEEP["image"]}')
    else:
        script = (f'cd "$HOME"; podman volume rm -f {KEEP["volume"]} >/dev/null 2>&1; '
                  f'podman secret rm {KEEP["secret"]} >/dev/null 2>&1; rm -f {KEEP["config"]}; '
                  f'rmdir "$(dirname {KEEP["config"]})" 2>/dev/null; podman network rm {KEEP["network"]} >/dev/null 2>&1; '
                  f'podman untag {KEEP["image"]} {KEEP["image"]} >/dev/null 2>&1; true')
    owner(dev, 'sh', '-c', script)


def keep_state(state_lines, images):
    """The unrelated objects only, from object_state() lines and owner_images()."""
    return {'objects': [line for line in state_lines if 'woowbk-keep' in line], 'image': images.get(KEEP['image'])}


def deployment_left(state_lines):
    """Lines naming the app's own deployment (quadlets, env file, volumes, secrets, network, unit masks)."""
    return [line for line in state_lines if 'woowbk-keep' not in line and line.split(' ', 1)[0] in (
        'volume', 'secret', 'config', 'network', 'quadlet', 'user-unit')]


def make_probe_image(dev):
    owner(dev, 'sh', '-c', f'tar -cf - -T /dev/null | podman import --quiet - {FRESH_PROBE_IMAGE} >/dev/null')
    return image_id(dev, FRESH_PROBE_IMAGE)


def fresh_restore(dev, backup_id, ev):
    start = ok(dev, 'restore-start', {'backup_id': backup_id, 'apps': [APP], 'request_id': request_id(),
                                      'confirm': True, 'key': e2e.kit_secret()}, ev=ev)
    return start['job_id']


def scenario_fresh(ev):
    """Fresh restores on dev-b: (1) a leftover secret, config file, volume or database volume of the app's names makes
    the restore refuse before any change, deleting nothing; (2) a fresh restore SIGKILLed after its first destructive
    step is removed by the recovery, which leaves every unrelated object alone; (3) a fresh restore that fails after
    the destructive step rolls back in-process and remove_fresh puts the previous image names back (retag) or removes
    the name it added. Ends with the app deployed and running on dev-b again."""
    dev = 'b'
    local, backup_id, snapshot = dev_a_image_backup(ev)
    ev.require('dev-b idle: no active job', ok(dev, 'status', ev=ev)['active_job'] is None)
    e2e.reset_target(dev, ev)
    ev.require('dev-b torn down: no deployment left', deployment_left(object_state(dev)) == [], object_state(dev))
    _begin, (_rc, reply) = e2e.upload_file(dev, local, ev=ev)
    ev.require('dev-a backup (with images) uploaded to dev-b', reply.get('ok'), reply.get('error'))
    probe_id = make_probe_image(dev)
    ev.require('probe image created on dev-b (podman import of an empty tar)', probe_id, probe_id)
    keep_objects(dev, True)
    results = {}
    try:
        keep_before = keep_state(object_state(dev), owner_images(dev))
        ev.save('fresh-keep-before', keep_before)
        ev.require('unrelated objects exist (volume with data, secret, config file, network, image name)',
                   len(keep_before['objects']) >= 5 and keep_before['image'] == probe_id, keep_before)

        # (1) leftovers: each one alone must make the fresh restore refuse, and nothing is deleted.
        for name, (obj, create, remove, check_id) in LEFTOVERS.items():
            owner(dev, 'sh', '-c', f'cd "$HOME" && {create}')
            try:
                state0, images0 = object_state(dev), owner_images(dev)
                inspected = ok(dev, 'inspect', {'backup_id': backup_id, 'key': e2e.kit_secret()}, ev=ev)
                papp = inspected['preflight']['apps'][0]
                failing = [c for c in papp['checks'] if c['status'] == 'fail']
                ev.check(f'fresh leftover {name}: inspect preflight (fresh mode) fails with {check_id} naming {obj}',
                         papp['mode'] == 'fresh' and not papp['restorable']
                         and [c['id'] for c in failing] == [f'{APP}/{check_id}'] and obj in failing[0]['message'],
                         failing)
                job_id = fresh_restore(dev, backup_id, ev)
                job, log = wait_job(dev, job_id, ev=ev, label=f'restore[leftover-{name}]')
                save_job(ev, f'fresh-leftover-{name}', job, log)
                phases = phase_states(job)
                ev.check(f'fresh leftover {name}: the restore job fails in preflight (incompatible) before any step',
                         job['state'] == 'failed' and (job.get('error') or {}).get('code') == 'incompatible'
                         and phases.get('preflight') == 'failed' and phases.get('stop') == 'pending'
                         and obj in (job.get('error') or {}).get('message', ''),
                         {'error': job.get('error'), 'phases': phases})
                state1 = object_state(dev)
                ev.check(f'fresh leftover {name}: nothing deleted or created (leftover, unrelated objects and image '
                         'names unchanged)', state1 == state0 and owner_images(dev) == images0,
                         {'before': state0, 'after': state1})
                ev.check(f'fresh leftover {name}: staging empty, no job key', staging_empty(dev) and no_job_keys(dev))
                results[f'leftover-{name}'] = {'state': job['state'], 'error': job.get('error')}
            finally:
                owner(dev, 'sh', '-c', f'cd "$HOME" && {remove}')
        ev.require('leftovers removed again', deployment_left(object_state(dev)) == [], object_state(dev))

        # (2) SIGKILL after the first destructive step (phase start: templates installed, units masked, secrets,
        # config file and files volume created); the recovery removes the deployment and nothing else.
        owner(dev, 'podman', 'tag', FRESH_PROBE_IMAGE, APP_IMAGE)
        images_before = owner_images(dev)
        watcher = Watcher(dev, kill_phases=('start',), timeout=900)
        ev.require('fresh kill: watcher ready', watcher.wait_for(lambda e: e.get('ready'), 60))
        job_id = fresh_restore(dev, backup_id, ev)
        killed = watcher.wait_for(lambda e: 'killed_in' in e or e.get('eof'), 900)
        events = watcher.stop()
        ev.log(f'fresh kill: watcher events {events}')
        ev.require(f'fresh kill: job {job_id} SIGKILLed in phase start', killed and killed.get('killed_in') == 'start'
                   and killed.get('rc') == 0, killed)
        ev.log(f'fresh kill: unit {wait_unit_gone(dev, job_id)}')
        record = json.loads(sh(dev, f'cat {DATA}/jobs/{job_id}.json').stdout)
        before_recovery = object_state(dev)
        ev.save('fresh-kill-before-recovery', {'record_fresh_apps': record.get('fresh_apps'), 'phase': record.get('phase'),
                                                'objects': before_recovery, 'images': owner_images(dev)})
        ev.check('fresh kill: the dead job had created its deployment (quadlets, env file, files volume, secrets, unit '
                 'mask) and still listed the app in fresh_apps', record.get('fresh_apps') == [APP]
                 and len(deployment_left(before_recovery)) >= 7, deployment_left(before_recovery))
        job, log = wait_job(dev, job_id, ev=ev, timeout=300, label='killed[fresh]')
        save_job(ev, 'fresh-kill-job', job, log)
        ev.check('fresh kill: the job is interrupted and its message says the unfinished deployment was removed',
                 job['state'] == 'interrupted' and '已清除未完成的全新部署' in (job.get('error') or {}).get('message', ''),
                 job.get('error'))
        after_recovery = object_state(dev)
        ev.check('fresh kill: recovery removed the whole deployment (quadlets, env file, volumes, secrets, network, '
                 'masks)', deployment_left(after_recovery) == [], deployment_left(after_recovery))
        ev.check('fresh kill: recovery left every unrelated object as it was',
                 keep_state(after_recovery, owner_images(dev)) == keep_before,
                 keep_state(after_recovery, owner_images(dev)))
        images_after = owner_images(dev)
        ev.check('fresh kill: images the dead job loaded keep their names (CONTRACT section 8: only an in-process '
                 'rollback puts names back); the probe image still exists under its own name',
                 images_after.get(APP_IMAGE) not in (None, probe_id) and images_after.get(FRESH_PROBE_IMAGE) == probe_id
                 and images_after.get(PG_IMAGE) == images_before.get(PG_IMAGE),
                 {'before': images_before, 'after': images_after})
        ev.check('fresh kill: staging empty, no job key', staging_empty(dev) and no_job_keys(dev))
        results['kill'] = {'state': job['state'], 'error': job.get('error'), 'images_after': images_after}

        # (3) in-process rollback: the database start fails once (drop-in), remove_fresh must put image names back.
        for variant, previous in (('retag', probe_id), ('untag', None)):
            if previous:
                owner(dev, 'podman', 'tag', FRESH_PROBE_IMAGE, APP_IMAGE)
            else:
                owner(dev, 'podman', 'untag', APP_IMAGE, APP_IMAGE, check=False)
            images_before = owner_images(dev)
            ev.require(f'fresh rollback {variant}: {APP_IMAGE} before the restore -> {previous}',
                       images_before.get(APP_IMAGE) == previous, images_before)
            e2e.f8_inject(dev, True)
            try:
                job_id = fresh_restore(dev, backup_id, ev)
                job, log = wait_job(dev, job_id, ev=ev, label=f'restore[rollback-{variant}]')
            finally:
                e2e.f8_inject(dev, False)
            save_job(ev, f'fresh-rollback-{variant}', job, log)
            result = job.get('result') or {}
            ev.check(f'fresh rollback {variant}: the database start fails after the destructive step and the job rolls '
                     'back in-process', job['state'] == 'rolled-back' and result.get('rolled_back') is True
                     and result.get('changed') is True and phase_states(job).get('rollback') == 'done'
                     and phase_states(job).get('start') == 'failed', {'state': job['state'], 'error': job.get('error'),
                                                                      'phases': phase_states(job)})
            images_after = owner_images(dev)
            wanted = (f'已將映像 {APP_IMAGE} 改回還原前的版本' if previous else f'已移除這次還原加上的映像名稱 {APP_IMAGE}')
            ev.check(f'fresh rollback {variant}: remove_fresh puts {APP_IMAGE} back ({previous or "no name"}) and says so; '
                     f'{PG_IMAGE} unchanged', images_after.get(APP_IMAGE) == previous
                     and images_after.get(PG_IMAGE) == images_before.get(PG_IMAGE) and any(wanted in line for line in log),
                     {'before': images_before, 'after': images_after, 'log': [l for l in log if '映像' in l][-4:]})
            state = object_state(dev)
            ev.check(f'fresh rollback {variant}: the deployment is removed and the unrelated objects are untouched',
                     deployment_left(state) == [] and keep_state(state, images_after) == keep_before,
                     {'left': deployment_left(state), 'keep': keep_state(state, images_after)})
            ev.check(f'fresh rollback {variant}: staging empty, no job key', staging_empty(dev) and no_job_keys(dev))
            results[f'rollback-{variant}'] = {'state': job['state'], 'images_after': images_after}
    finally:
        e2e.f8_inject(dev, False)
        keep_objects(dev, False)
        owner(dev, 'sh', '-c', f'id=$(podman image inspect --format "{{{{.Id}}}}" {FRESH_PROBE_IMAGE} 2>/dev/null); '
                               f'test -n "$id" && podman rmi -f "$id" >/dev/null; true')
        if deployment_left(object_state(dev)):  # an aborted case left a leftover or a partial deployment
            ev.log(f'fresh: tearing down what an aborted case left: {deployment_left(object_state(dev))}')
            owner(dev, 'sh', '-c', e2e.TEARDOWN, timeout=600)
        final_fresh_restore(dev, backup_id, snapshot, ev)
    return {'cases': results, 'source_backup': backup_id}


def final_fresh_restore(dev, backup_id, snapshot, ev):
    """Leave dev-b as after cli_e2e s2: the app deployed from the same backup and running (failures are recorded)."""
    try:
        job_id = fresh_restore(dev, backup_id, ev)
        job, log = wait_job(dev, job_id, ev=ev, label='restore[final-fresh]')
        save_job(ev, 'fresh-final-restore', job, log)
        ev.check('fresh: a final fresh restore succeeds afterwards (nothing left behind blocks it)',
                 job['state'] == 'succeeded', job.get('error'))
        status = ok(dev, 'status', ev=ev)
        app = next(a for a in status['apps'] if a['id'] == APP)
        ev.check('dev-b after the fresh cases: app deployed and running, no unrelated or probe objects left, no active '
                 'job', app['state'] == 'running' and status['active_job'] is None
                 and keep_state(object_state(dev), owner_images(dev)) == {'objects': [], 'image': None}
                 and FRESH_PROBE_IMAGE not in owner_images(dev), app)
        if snapshot:
            ev.check('dev-b data equals the source backup snapshot', compare(summary(dev), snapshot) == {},
                     compare(summary(dev), snapshot))
    except (Failed, OSError, ValueError, subprocess.SubprocessError) as error:
        ev.check('fresh: final fresh restore of dev-b ran', False, f'{type(error).__name__}: {redact(str(error))}')


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
             'h6': scenario_h6, 'h7': scenario_h7, 'sec1': scenario_sec1, 'fidelity': scenario_fidelity,
             'fresh': scenario_fresh, 'leaks': scenario_leaks}


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
