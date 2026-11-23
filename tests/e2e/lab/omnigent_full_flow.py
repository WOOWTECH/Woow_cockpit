#!/usr/bin/env python3
"""Omnigent: a real b1 HA backup (x86 or the RPi5's ARM one, plain or encrypted) -> dev-d's INSTALLED Omnigent (the
WOOWTECH Podman package 0.21.0-2: omnigent-postgres, omnigent-server, omnigent-runner) through the product's full
HA-import flow, exactly the helper commands the Cockpit page sends (lane omnigent-product, 2026-11-23; the product path
that replaced the SECURITY_BLOCKER hold: trusted schema, HA's data only).

  python3 -I tests/e2e/lab/services_a_capture.py --private=FILE <evidence.json> <scope> -- \\
      python3 -I tests/e2e/lab/omnigent_full_flow.py --run --arch x86|arm --form plain|enc
  python3 -I tests/e2e/lab/omnigent_full_flow.py --self-check      (offline; never touches a device or a secret)

One run = one hold of the dev-d mutation lock (blocking like `flock -w 3600`, never taken while emqx-main's waiting
file exists), dev-d's outer isolation recorded before and after (`owner.sh d --verify-isolation`), the checkout
committed (no change outside the evidence folders). Every engine call is the root helper the page calls (one JSON
request on stdin, one JSON reply; /usr/local/libexec/woowtech-cockpit-backup inside dev-d), with the engine of THIS
tree installed by deploy-src.sh:

  setup     the scheduled-backup timer masked for the run (its state put back at the end), deploy-src.sh d --src <this
            tree> --no-demo-catalog, installed engine == tree (SHA-256 of every module and the helper); the `omnigent`
            catalog entry is the one carried by dev-d's own Omnigent baseline backup 20261119T072103Z-ea792b52 when it
            is missing (removed again at the end); key-init
  before    dev-d's own markers (batch1_markers.py read), the live schema signature (SHA-256), the runner's pi volume
            (SHA-256 of every file), the server's cookie key (SHA-256)
  upload    upload-begin, the file copied to the path the helper gave, upload-finish (hastore.publish)
  check     ha-check-start omnigent (the HA key for an encrypted backup): ok, no blocker, versions, the section equals
            the recorded source facts
  import    the real free space and the product's floor, ha-convert-start (real SpaceGuard/Watchdog), the list row,
            inspect (preflight), restore-start (safety backup, in place, health checks)
  verify    HA's admin and member log in with HA's passwords, this device's admin and runner (operator) with this
            device's, HA's admin not with this device's; users, agent, paused task, session title/labels/comment,
            attachment SHA-256, member session, alembic, every table count; this device's runner logs in and its host
            comes online; HA's cookie key installed; the runner's pi volume unchanged (pairing not moved); the live
            schema signature equal to before (this device's schema, not HA's); engine status and health URLs
  restart   systemctl --user restart omnigent-server.service omnigent-runner.service: verified again
  rollback  (a) automatic: a second restore with a one-shot ExecStartPre failure of omnigent-server must end
            `rolled-back` and leave the imported state; (b) the first restore's safety backup restored: dev-d's own
            markers back, HA's users gone, schema and pi volume as before
  cleanup   drop-in/marker gone, the test's converted and safety backups deleted, the HA store record deleted when this
            run created it, the catalog as found, no job container/volume/network, staging or key file
  leaks     every registered value (HA passwords and key, HA's cookie, issued login tokens, dev-d's Omnigent secrets,
            the 11-19 kit) looked for in the engine's records, uploads, staging, run dir, the whole device journal and
            this run's private evidence (tokens the server issues to the runner itself are not observable: stated)

stdout carries only fixed lines (`<check>: PASS|FAIL`, the isolation line, the source commit, lock time); details go to
the private, redacted evidence folder ~/.woowbk-lab/evidence/omnigent-product/<time>/ (0700).
Not covered (stated): the browser page itself (dev-d publishes no port; the helper calls are the page's), a host
reboot, the Pi agent / a model provider (out of scope), HA's own runner (offline after the move, by design).
"""
import argparse
import contextlib
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
LAB = Path.home() / '.woowbk-lab'
LOCK = Path('/tmp/woowbk-dev-d-mutation.lock')
WAITING = Path('/tmp/woowbk-dev-d-emqx-main-waiting')
LOCK_TIMEOUT = 3600
HOLD_BUDGET = 38 * 60          # no new phase after this many seconds of holding the lock
MIN_DEVICE_HEADROOM = 1280 * 1024 * 1024
MIN_HOST_AVAILABLE_KIB = 1024 * 1024
MIN_DISK_FREE = 13 * 1024 ** 3  # the team keeps >= 12 GiB free at every moment (plus the upload copy)
BASELINE = '20261119T072103Z-ea792b52'   # dev-d's own Omnigent baseline backup (11-19 device key)
OLD_KIT = LAB / 'secrets' / 'dev-d-kit.txt'
TIMER = 'woowtech-cockpit-backup-schedule.timer'
FIXTURES = LAB / 'ha-fixtures' / '20261119-b1'
FIXTURE_SHA = {('x86', 'plain'): '3871a468e2f3a11488df7c6a00a4a8ed7c5b89c3ba2dbc2903ec3bd677013516',
               ('arm', 'plain'): '1e6a4665315bc69fd114f8d43f7d429aecab53f07d07793ecf8c2c057a92c5d4',
               ('x86', 'enc'): 'f82422e327f151ec819d8e626011af965e40bf1ac78da3fa7a7bd0f869b69e1d',
               ('arm', 'enc'): '6d0647f0acb2e0d95043d66852c08bbc020d409d4f6747f817c10f94e2c33d1c'}
UNITS = ('omnigent-postgres.service', 'omnigent-server.service', 'omnigent-runner.service')
DROPIN_DIR_REL = '.config/systemd/user/omnigent-server.service.d'
DROPIN_REL = DROPIN_DIR_REL + '/zz-omni-product-fail-once.conf'
MARKER_REL = '.omni-product-fail-once'
OMNI_SECRETS = ['omnigent-postgres-password', 'omnigent-admin-password', 'omnigent-runner-password',
                'omnigent-database-url']
SAFE_LABEL = re.compile(r"[^A-Za-z0-9 ,()/:'<>.=_-]")


def _load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


drv = _load('ha_import_b1_e2e')
Failed = drv.Failed
drv.state_path = lambda: LAB / 'run' / 'omnigent_full_flow.json'   # never the b1 driver's own state file


# ---------------------------------------------------------------- fixed output and private evidence

def label(text):
    return SAFE_LABEL.sub(' ', str(text))[:140].strip() or 'check'


def emit(line):
    print(line, flush=True)


class Ev(drv.Evidence):
    """The b1 driver's private, redacted evidence folder; stdout gets only `<label>: PASS|FAIL`."""

    def log(self, text):
        line = f'{time.strftime("%H:%M:%S")} {self.secrets.redact(str(text))}'
        with open(self.log_path, 'a', encoding='utf-8') as handle:
            handle.write(line + '\n')

    def check(self, name, ok, detail=''):
        result = super().check(name, ok, detail)
        emit(f'{label(name)}: {"PASS" if result else "FAIL"}')
        return result


# ---------------------------------------------------------------- the team's dev-d rules (pure, unit-tested)

def acquire(lock=LOCK, waiting=WAITING, timeout=LOCK_TIMEOUT, *, sleep=time.sleep, clock=time.monotonic):
    """The dev-d mutation lock like `flock -w <timeout>`, never taken while emqx-main asks for the next turn (its
    waiting file exists). Returns (fd, waited seconds)."""
    fd = os.open(lock, os.O_RDWR | os.O_CREAT, 0o664)
    started = clock()
    try:
        while True:
            if not waiting.exists():
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    return fd, int(clock() - started)
                except BlockingIOError:
                    pass
            if clock() - started > timeout:
                raise Failed('dev-d mutation lock not acquired in time')
            sleep(5)
    except BaseException:
        os.close(fd)
        raise


def clean_tree(repo=REPO):
    """(clean, changed paths): only the evidence folders may differ from the commit."""
    out = subprocess.run(['git', '-C', str(repo), 'status', '--porcelain', '--untracked-files=all'],
                         capture_output=True, text=True, timeout=60, check=True).stdout
    changed = [line[3:] for line in out.splitlines() if line.strip()]
    dirty = [p for p in changed if not p.startswith(('tests/e2e/lab/evidence/', 'tests/backup/evidence/'))]
    return not dirty, dirty


def head(repo=REPO):
    return subprocess.run(['git', '-C', str(repo), 'rev-parse', 'HEAD'], capture_output=True, text=True, timeout=60,
                          check=True).stdout.strip()


def verify_isolation():
    proc = subprocess.run([str(HERE / 'owner.sh'), 'd', '--verify-isolation'], capture_output=True, text=True,
                          timeout=60)
    line = proc.stdout.strip()
    if proc.returncode != 0 or line != 'dev-d isolation: true none {}':
        raise Failed('dev-d isolation check failed')
    return line


def fixture_path(arch, form):
    name = f'woow-b1-{arch}-{form}'
    return FIXTURES / arch / name / f'{name}.tar'


def tar_digests(listing):
    """{path: sha256} of a volume's files from the device program's answer (names only; never content)."""
    return {k: v for k, v in sorted((listing or {}).items()) if isinstance(k, str) and isinstance(v, str)}


def expected_count_keys(src):
    return sorted(src['db_counts'])


# ---------------------------------------------------------------- device-side programs (no secret ever printed)

ENGINE_HASHES = r'''
import hashlib, json, os
lib = "/usr/local/lib/woowtech-cockpit-backup/woowbackup"
out = {"lib": {}, "helper": None}
for d, dirs, files in os.walk(lib):
    dirs[:] = [x for x in dirs if x != "__pycache__"]
    for f in files:
        if f.endswith(".py"):
            p = os.path.join(d, f)
            out["lib"][os.path.relpath(p, lib)] = hashlib.sha256(open(p, "rb").read()).hexdigest()
out["helper"] = hashlib.sha256(open("/usr/local/libexec/woowtech-cockpit-backup", "rb").read()).hexdigest()
print(json.dumps(out))
'''

SPACE = r'''
import json, os, sys
sys.path.insert(0, "/usr/local/lib/woowtech-cockpit-backup")
from types import SimpleNamespace
from woowbackup import flows, haimport, storage
from woowbackup.paths import Paths
paths = Paths()
st = storage.Storage(paths)
ctx = SimpleNamespace(storage=st, paths=paths)
reserve = flows.running_reserve(ctx)
folders = ["/var/lib/woowtech-backup/staging", "/home/appowner", "/home/appowner/.local/share/containers/storage"]
free = {}
for f in folders:
    s = os.statvfs(f)
    free[f] = s.f_bavail * s.f_frsize
print(json.dumps({"total": int(st.total_bytes()), "reserve_bytes": int(paths.reserve_bytes), "running_reserve": int(reserve),
                  "watch_margin": int(haimport.WATCH_MARGIN), "floor": int(reserve + haimport.WATCH_MARGIN),
                  "free": free, "min_free": min(free.values())}))
'''

# As appowner: the live schema signature (the installed engine's own SQL) as a SHA-256, the pi volume's files and the
# server's cookie key as SHA-256 -- never a value.
STATE_PROBE = r'''
import hashlib, json, subprocess, sys
sys.path.insert(0, "/usr/local/lib/woowtech-cockpit-backup")
from woowbackup import ha_omnigent
def run(*argv):
    p = subprocess.run(list(argv), capture_output=True, timeout=120)
    return p.returncode, p.stdout
rc, so = run("podman", "exec", "omnigent-postgres", "psql", "-X", "-A", "-t", "-q", "-v", "ON_ERROR_STOP=1", "-U",
             "omnigent", "-d", "omnigent", "-c", ha_omnigent.SCHEMA_SIGNATURE_SQL)
sig = json.loads(so) if rc == 0 else None
rc2, cols = run("podman", "exec", "omnigent-postgres", "psql", "-X", "-A", "-t", "-q", "-v", "ON_ERROR_STOP=1", "-U",
                "omnigent", "-d", "omnigent", "-c", ha_omnigent.SCHEMA_COLUMNS_SQL)
def canon(v):
    return hashlib.sha256(json.dumps(v, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
out = {"signature_sha256": canon(sig) if sig is not None else None,
       "signature_parts": {k: canon(v) for k, v in (sig or {}).items()},
       "columns_sha256": canon(json.loads(cols)) if rc2 == 0 else None,
       "tables": len([r for r in (sig or {}).get("relations", []) if r[1] in ("r", "p")])}
rc, mount = run("podman", "volume", "inspect", "omnigent-pi-data", "--format", "{{.Mountpoint}}")
rc, listing = run("podman", "unshare", "sh", "-c",
                  'cd "$1" && find . -type f -print0 | sort -z | xargs -0 -r sha256sum', "sh", mount.decode().strip())
pi = {}
for line in listing.decode("utf-8", "replace").splitlines():
    digest, _, name = line.partition("  ")
    pi[name] = digest
out["pi_files"] = pi
rc, cookie = run("podman", "exec", "omnigent-server", "cat", "/data/artifacts/accounts-cookie-secret")
out["cookie_sha256"] = hashlib.sha256(cookie).hexdigest() if rc == 0 and cookie else None
print(json.dumps(out))
'''

MARKERS = (HERE / 'batch1_markers.py').read_text(encoding='utf-8')


# ---------------------------------------------------------------- the run

class Run:
    def __init__(self, args, ev):
        self.args = args
        self.ev = ev
        self.arch, self.form = args.arch, args.form
        self.src = drv.source(self.arch)['omnigent']
        self.fixture = fixture_path(self.arch, self.form)
        self.installed_entry = False
        self.created_store = None
        self.timer_masked_here = False
        self.dropin = False
        self.lock_started = time.monotonic()
        self.before, self.before_markers = {}, {}
        self.converted = self.safety = self.store_id = self.kit = self.ha_cookie_sha = None

    # -------- guards
    def budget(self, phase):
        if time.monotonic() - self.lock_started > HOLD_BUDGET:
            raise Failed(f'lock hold budget reached before {phase}')

    def headroom(self):
        proc = drv.root('sh', '-c', 'echo "$(cat /sys/fs/cgroup/memory.current) $(cat /sys/fs/cgroup/memory.max)"',
                        timeout=60)
        try:
            current, maximum = (int(x) for x in drv.out(proc).split())
        except ValueError:
            raise Failed('cannot read dev-d cgroup memory') from None
        available = next(int(line.split()[1]) for line in Path('/proc/meminfo').read_text().splitlines()
                         if line.startswith('MemAvailable:'))
        st = os.statvfs('/')
        free = st.f_bavail * st.f_frsize
        emit(f'dev-d memory current={current} limit={maximum}; headroom >= {MIN_DEVICE_HEADROOM / 1024 ** 3:.2f} GiB; '
             f'host MemAvailable {available} KiB')
        if maximum - current < MIN_DEVICE_HEADROOM:
            raise Failed('dev-d memory headroom too small')
        if available < MIN_HOST_AVAILABLE_KIB:
            raise Failed('host MemAvailable below 1 GiB')
        if free - self.fixture.stat().st_size < MIN_DISK_FREE:
            raise Failed('host disk free below the reserve')

    # -------- secrets (read through the b1 harness reader only; never printed)
    def load_secrets(self):
        s = self.args.secrets
        for name in ('B1_OMNI_ADMIN_USER', 'B1_OMNI_ADMIN_PW', 'B1_OMNI_MEMBER_USER', 'B1_OMNI_MEMBER_PW'):
            if not s.values.get(name):
                raise Failed('a b1 Omnigent credential is missing from the harness reader')
        if self.form == 'enc' and not s.values.get('HA_BACKUP_KEY'):
            raise Failed('the HA backup key is missing from the harness reader')
        if s['B1_OMNI_ADMIN_USER'] != next(u['id'] for u in self.src['users'] if u['is_admin']):
            raise Failed('the b1 admin is not the source fact admin')
        plain = fixture_path(self.arch, 'plain')
        cookie = ha_cookie(plain)
        s.register('HA_OMNI_COOKIE', cookie.decode('latin-1'))
        if cookie.strip() != cookie:
            s.register('HA_OMNI_COOKIE_TRIMMED', cookie.strip().decode('latin-1'))
        self.ha_cookie_sha = hashlib.sha256(cookie).hexdigest()
        kit = OLD_KIT.read_text(encoding='utf-8')
        lines = [line.strip() for line in kit.splitlines() if line.strip().startswith('AGE-SECRET-KEY-')]
        if len(lines) != 1:
            raise Failed('the 11-19 kit does not hold exactly one key line')
        s.register('DEV_D_KIT_1119', lines[0])
        self.kit = kit
        self.ev.check("secrets: HA's Omnigent logins, HA key, HA's cookie key and the 11-19 kit registered (memory only)",
                      True, {'form': self.form})

    # -------- setup
    def setup(self):
        ev = self.ev
        state = drv.out(drv.root('systemctl', 'is-enabled', TIMER, timeout=60)).strip()
        if state != 'masked':
            proc = drv.root('systemctl', 'mask', '--now', TIMER, timeout=120)
            self.timer_masked_here = proc.returncode == 0
            ev.check('setup: the scheduled-backup timer is masked for the run (shared lab)', proc.returncode == 0,
                     {'before': state})
        else:
            ev.check('setup: the scheduled-backup timer is masked for the run (shared lab)', True, {'before': state})
        proc = drv.run(['bash', str(HERE / 'deploy-src.sh'), 'd', '--src', str(REPO), '--no-demo-catalog'], timeout=1800)
        ev.save('deploy.log', drv.out(proc)[-20000:] + proc.stderr.decode('utf-8', 'replace')[-5000:])
        if not ev.check('setup: deploy-src.sh d --src <this tree> --no-demo-catalog', proc.returncode == 0,
                        f'rc {proc.returncode}'):
            raise Failed('deploy failed')
        installed = drv.device_python(ENGINE_HASHES, {}, as_owner=False, timeout=300)
        base = REPO / 'backup-engine' / 'woowbackup'
        tree = {str(p.relative_to(base)): sha256_file(p) for p in base.rglob('*.py') if '__pycache__' not in p.parts}
        lib = installed.get('lib') or {}
        differ = sorted(k for k in set(tree) | set(lib) if tree.get(k) != lib.get(k))
        if not ev.check('setup: the installed engine is this tree (every module and the helper SHA-256 equal)',
                        not differ and installed.get('helper') == sha256_file(REPO / 'backup-engine' /
                                                                              'woowtech-cockpit-backup'),
                        {'modules': len(tree), 'differ': differ[:10]}):
            raise Failed('installed engine differs')
        status = drv.ok('status', ev=ev)
        catalog = {a['id'] for a in status.get('apps') or []}
        if 'omnigent' not in catalog:
            reply = drv.ok('inspect', {'backup_id': BASELINE, 'key': self.kit}, ev=ev, timeout=900)
            apps = (reply.get('preflight') or {}).get('apps') or []
            carried = next((a.get('settings') or {} for a in apps if a.get('id') == 'omnigent'), {})
            entry = carried.get('entry')
            ev.check("setup: dev-d's Omnigent baseline backup opens with the 11-19 emergency kit and carries its "
                     'catalog entry', isinstance(entry, dict) and entry.get('id') == 'omnigent'
                     and carried.get('state') == 'missing', {'state': carried.get('state'),
                                                             'owner': (entry or {}).get('owner')})
            if not isinstance(entry, dict):
                raise Failed('no carried Omnigent catalog entry')
            ev.save('catalog-entry-omnigent.json', entry)
            preview = drv.ok('catalog-install', {'entry': entry}, ev=ev, timeout=300)
            if not ev.check('setup: catalog-install preview of the carried entry is valid', preview.get('valid') is True,
                            {k: preview.get(k) for k in ('valid', 'errors', 'warnings', 'conflicts')}):
                raise Failed('catalog preview refused')
            drv.ok('catalog-install', {'entry': entry, 'confirm': True,
                                       'expected_sha256': preview.get('expected_sha256')}, ev=ev, timeout=300)
            self.installed_entry = True
        entry = drv.catalog('omnigent')
        ev.save('catalog-omnigent-installed.json', entry)
        ev.check("setup: the omnigent catalog entry names the package's units, its three volumes, its secrets and its "
                 'health URL', set(UNITS) <= set(entry.get('units') or [])
                 and sorted(v['name'] for v in entry.get('volumes') or []) == ['omnigent-pi-data',
                                                                               'omnigent-postgres-data',
                                                                               'omnigent-server-data']
                 and set(OMNI_SECRETS) <= {s['name'] for s in entry.get('secrets') or []}
                 and len(entry.get('health') or []) >= 1,
                 {'units': entry.get('units'), 'volumes': [v['name'] for v in entry.get('volumes') or []],
                  'secrets': [s['name'] for s in entry.get('secrets') or []],
                  'health': [h.get('url') for h in entry.get('health') or []]})
        key = drv.ok('key-init', ev=ev)
        ev.check('setup: a device key exists (key-init; the kit is never read for it)',
                 bool((key.get('key') or {}).get('key_id')), {'created': key.get('created')})
        self.wait_units('setup')

    # -------- small helpers
    def wait_units(self, label_text, timeout=240):
        deadline = time.monotonic() + timeout
        states = {}
        while time.monotonic() < deadline:
            states = {u: drv.out(drv.owner('systemctl', '--user', 'is-active', u, timeout=60)).strip() for u in UNITS}
            if all(v == 'active' for v in states.values()):
                break
            time.sleep(3)
        self.ev.check(f'{label_text}: omnigent-postgres, omnigent-server and omnigent-runner are active',
                      all(v == 'active' for v in states.values()), states)

    def markers(self, label_text):
        proc = drv.run([drv.LP, 'exec', '-i', drv.DEVICE, drv.OWNER, 'python3', '-I', '-c', MARKERS, 'omnigent', 'read'],
                       input=b'', timeout=180)
        try:
            found = json.loads(drv.out(proc).strip().splitlines()[-1])
        except (ValueError, IndexError):
            raise Failed(f'{label_text}: marker read failed (rc {proc.returncode})') from None
        self.ev.save(f'markers-{label_text.replace(" ", "-")}.json', found)
        return found

    def state(self, label_text):
        found = drv.device_python(STATE_PROBE, {}, as_owner=True, timeout=300)
        self.ev.save(f'state-{label_text.replace(" ", "-")}.json', found)
        return found

    def has_own_markers(self, found):
        return ('woowbk-lab-baseline:false' in (found.get('users') or [])
                and 'woowbk-lab-baseline' in (found.get('projects') or [])
                and any(t.startswith('woowbk-lab-baseline:state=2') for t in found.get('scheduled_tasks') or []))

    # -------- before
    def step_before(self):
        ev = self.ev
        found = self.markers('before')
        self.before_markers = found
        ev.check("before: dev-d's own Omnigent markers (woowbk-lab-baseline user, project, paused task)",
                 self.has_own_markers(found), found)
        state = self.state('before')
        self.before = state
        ev.check('before: the live schema signature, the pi volume files and the cookie key are readable (SHA-256 only)',
                 bool(state.get('signature_sha256')) and state.get('tables', 0) >= 20 and state.get('pi_files')
                 and state.get('cookie_sha256') and state.get('cookie_sha256') != self.ha_cookie_sha,
                 {'tables': state.get('tables'), 'pi_files': sorted(state.get('pi_files') or {})})
        drv.app_health(ev, 'omnigent', 'before')

    # -------- upload (page path) and check
    def step_upload(self):
        ev = self.ev
        sha = sha256_file(self.fixture)
        tag = f'{self.arch}-{self.form}'
        if not ev.check(f'upload {tag}: the local file is the recorded b1 fixture (sha256)',
                        sha == FIXTURE_SHA[(self.arch, self.form)], sha[:16]):
            raise Failed('fixture changed')
        store_id = 'ha-' + sha[:20]
        listed = {h.get('id') for h in drv.ok('list', ev=ev).get('ha_backups') or []}
        started = time.monotonic()
        rc, reply = drv.upload(self.fixture, ev=ev)
        took = time.monotonic() - started
        meta = reply.get('ha_backup') or {}
        ev.save('upload-reply.json', reply)
        ev.check(f'upload {tag}: upload-begin, copy, upload-finish answer the HA store record (id from the SHA-256)',
                 rc == 0 and meta.get('id') == store_id, {'took_s': round(took, 1), 'id': meta.get('id'),
                                                         'existed_before': store_id in listed})
        found = {a['app_id']: a['installed'] for a in meta.get('importable_apps') or []}
        ev.check(f'upload {tag}: omnigent is importable and installed here', found.get('omnigent') is True, found)
        if store_id not in listed:
            self.created_store = store_id
        self.store_id = store_id
        if rc != 0 or meta.get('id') != store_id:
            raise Failed('upload refused')

    def key(self):
        return self.args.secrets['HA_BACKUP_KEY'] if self.form == 'enc' else None

    def step_check(self):
        ev = self.ev
        tag = f'{self.arch}-{self.form}'
        job, took = drv.run_check(self.store_id, ['omnigent'], ev=ev, key=self.key(), tag=f'check-{tag}-omnigent')
        if not ev.check(f'check {tag}/omnigent: job succeeded', job['state'] == 'succeeded',
                        f'{took:.0f} s {job.get("error")}'):
            raise Failed('check job failed')
        result = job['result']['ha_check']['apps'][0]
        ev.save(f'check-{tag}-omnigent.json', result)
        ev.check(f'check {tag}/omnigent: ok, no blockers (no security hold; the schema equals this device\'s)',
                 result.get('ok') is True and not result.get('blockers'), result.get('blockers'))
        ev.check(f'check {tag}/omnigent: source {drv.ARCH[self.arch]}, add-on 0.1.23, target 0.21.0',
                 result.get('arch') == drv.ARCH[self.arch] and result.get('version') == '0.1.23'
                 and result.get('target_version') == '0.21.0',
                 {k: result.get(k) for k in ('arch', 'version', 'target_version')})
        section = result.get('omnigent') or {}
        src = self.src
        want = {'alembic': src['alembic'], 'users': len([u for u in src['users']]),
                'admins': len([u for u in src['users'] if u['is_admin']])}
        ev.check(f'check {tag}/omnigent: alembic, users and admins equal the recorded source facts',
                 section.get('alembic') == want['alembic'] and section.get('admins') == want['admins']
                 and section.get('users', -1) >= want['admins'],
                 {k: section.get(k) for k in ('alembic', 'users', 'admins', 'conversations', 'agents', 'hosts')})
        leftovers = drv.labelled()
        ev.check('check: no throwaway container, volume or network left', not any(leftovers.values()), leftovers)

    # -------- import (convert, inspect, restore)
    def step_import(self):
        ev = self.ev
        tag = f'{self.arch}-{self.form}'
        space = drv.device_python(SPACE, {}, as_owner=False, timeout=120)
        ev.save('space-before-convert.json', space)
        ev.check(f"import {tag}: real space: free space of staging/home/storage above the product's floor (running "
                 'reserve + watch margin) the convert job enforces', isinstance(space.get('floor'), int)
                 and space['floor'] >= 2 * 1024 ** 3 and space['min_free'] > space['floor'],
                 {k: space.get(k) for k in ('total', 'running_reserve', 'watch_margin', 'floor', 'min_free')})
        before_ids = {b['id'] for b in drv.ok('list', ev=ev)['backups']}
        job, took = drv.convert(self.store_id, ['omnigent'], False, ev=ev, key=self.key(),
                                tag=f'convert-{tag}-omnigent')
        ev.save('convert-job.json', job)
        if not ev.check(f'import {tag}: ha-convert-start job succeeded with a backup id', job['state'] == 'succeeded'
                        and (job.get('result') or {}).get('backup_id'), f'{took:.0f} s {job.get("error")}'):
            raise Failed('convert failed')
        result = job['result']
        self.converted = result['backup_id']
        drv.created_backup(self.converted)
        imp = result.get('ha_import') or {}
        ev.check(f'import {tag}: ha_import: apps omnigent, not test mode, the trusted-schema note and the runner reminder',
                 imp.get('apps') == ['omnigent'] and imp.get('test_mode') is False
                 and any('資料庫結構' in n and '這台' in n for n in imp.get('notes') or [])
                 and any('runner' in line for line in (imp.get('reminders_by_app') or {}).get('omnigent') or []),
                 {k: imp.get(k) for k in ('apps', 'test_mode')})
        log = '\n'.join(str(line) for line in (drv.ok('job-status', {'job_id': job['id']}, ev=ev).get('log') or []))
        ev.check(f'import {tag}: the job log names the trusted schema steps (this device\'s schema in one snapshot, '
                 'only HA data loaded by the role without privileges, HA structure entries skipped)',
                 '只當作資料來源' in log and '同一個快照' in log and '沒有任何管理權限的暫用角色' in log and '略過' in log
                 and '資料庫結構和這台的相同' in log, {'log_lines': log.count('\n') + 1})
        listing = drv.ok('list', ev=ev)
        row = next((b for b in listing['backups'] if b['id'] == self.converted), {})
        ev.check(f'import {tag}: the converted backup is listed as manual with its HA origin',
                 self.converted not in before_ids and row.get('type') == 'manual'
                 and (row.get('from_ha') or {}).get('ha_backup_id') == self.store_id,
                 {'type': row.get('type'), 'from_ha': bool(row.get('from_ha')), 'encrypted': row.get('encrypted')})
        inspect = drv.ok('inspect', {'backup_id': self.converted}, ev=ev, timeout=900)
        pre = inspect.get('preflight') or {}
        failed = [c for c in pre.get('checks') or [] if c.get('status') == 'fail']
        ev.check(f'import {tag}: inspect: preflight passes, settings same, in place',
                 pre.get('ok') and not failed and all((a.get('settings') or {}).get('state') == 'same'
                                                      and a.get('mode') == 'inplace' for a in pre.get('apps') or []),
                 failed[:3] or [(a.get('id'), a.get('mode'), (a.get('settings') or {}).get('state')) for a in
                                pre.get('apps') or []])
        rjob, rtook = drv.restore(self.converted, ['omnigent'], ev=ev, tag=f'restore-{tag}-omnigent')
        ev.save('restore-job.json', rjob)
        rresult = rjob.get('result') or {}
        self.safety = rresult.get('safety_backup_id')
        drv.created_backup(self.safety)
        health = rresult.get('health') or []
        if not ev.check(f'import {tag}: restore-start of the converted backup succeeded with a safety backup, not rolled '
                        'back, every health check ok', rjob['state'] == 'succeeded' and self.safety
                        and rresult.get('rolled_back') is False and health and all(h.get('status') == 'ok' for h in health),
                        {'state': rjob['state'], 'error': rjob.get('error'), 'safety': self.safety,
                         'health': [(h.get('id'), h.get('status')) for h in health], 'took_s': round(rtook, 1)}):
            raise Failed('restore failed')
        drv.save_state()

    # -------- verification of the imported app
    def verify(self, label_text):
        ev = self.ev
        self.wait_units(label_text)
        drv.verify_omnigent(ev, self.args, self.arch, label_text, test_mode=False, upload=f'{self.arch}-{self.form}')
        state = self.state(label_text)
        ev.check(f"{label_text}: HA's cookie key is installed (SHA-256)", state.get('cookie_sha256') == self.ha_cookie_sha,
                 {'equal': state.get('cookie_sha256') == self.ha_cookie_sha})
        ev.check(f"{label_text}: the runner's pi volume is unchanged (pairing and identity not moved)",
                 tar_digests(state.get('pi_files')) == tar_digests(self.before.get('pi_files')),
                 {'files': sorted(state.get('pi_files') or {})})
        ev.check(f"{label_text}: the live database schema is this device's (signature equal to before the import)",
                 state.get('signature_sha256') == self.before.get('signature_sha256')
                 and state.get('columns_sha256') == self.before.get('columns_sha256'),
                 {'differ': sorted(k for k, v in (state.get('signature_parts') or {}).items()
                                   if v != (self.before.get('signature_parts') or {}).get(k))})
        found = self.markers(label_text)
        ev.check(f"{label_text}: none of dev-d's own markers is left (HA's data replaced them)",
                 not found.get('users') and not found.get('projects') and not found.get('scheduled_tasks'), found)
        drv.app_health(ev, 'omnigent', label_text)

    def step_restart(self):
        ev = self.ev
        started = time.monotonic()
        proc = drv.owner('systemctl', '--user', 'restart', 'omnigent-server.service', 'omnigent-runner.service',
                         timeout=420)
        ev.check('restart: systemctl --user restart omnigent-server.service omnigent-runner.service',
                 proc.returncode == 0, f'rc {proc.returncode} {time.monotonic() - started:.0f} s')
        self.verify('restart')

    def inject_on(self):
        drv.owner('mkdir', '-p', f'/home/appowner/{DROPIN_DIR_REL}', timeout=60)
        text = ('[Service]\nExecStartPre=/bin/sh -c \'if test -f %h/' + MARKER_REL + '; then rm -f %h/' + MARKER_REL
                + '; exit 1; fi\'\n')
        write_owner_file(DROPIN_REL, text.encode(), '0644')
        self.dropin = True
        owner_ok('systemctl', '--user', 'daemon-reload')
        write_owner_file(MARKER_REL, b'fail-once\n', '0600')

    def inject_off(self):
        if not self.dropin:
            return
        drv.owner('rm', '-f', f'/home/appowner/{DROPIN_REL}', f'/home/appowner/{MARKER_REL}', timeout=60)
        drv.owner('rmdir', f'/home/appowner/{DROPIN_DIR_REL}', timeout=60)
        drv.owner('systemctl', '--user', 'daemon-reload', timeout=120)
        self.dropin = owner_exists(DROPIN_REL) or owner_exists(MARKER_REL)

    def step_auto_rollback(self):
        ev = self.ev
        self.inject_on()
        try:
            job, took = drv.restore(self.converted, ['omnigent'], ev=ev, tag=f'restore-inject-{self.arch}-omnigent')
        finally:
            consumed = not owner_exists(MARKER_REL)
            self.inject_off()
        ev.save('restore-inject-job.json', job)
        result = job.get('result') or {}
        drv.created_backup(result.get('safety_backup_id'))
        ev.check('auto rollback: a restore with a one-shot ExecStartPre failure of omnigent-server ends rolled-back '
                 '(automatic rollback, the failure was consumed)', job['state'] == 'rolled-back'
                 and result.get('rolled_back') is True and consumed,
                 {'state': job['state'], 'error': job.get('error'), 'took_s': round(took, 1),
                  'safety': result.get('safety_backup_id')})
        ev.check('auto rollback: the injected drop-in and marker are gone', not self.dropin, '')
        self.verify('auto rollback')

    def step_rollback_to_own(self):
        """dev-d's own state back (also when a probe's credential coverage broke: the shared lab comes first; the leak
        scan still runs afterwards)."""
        ev = self.ev
        started = time.monotonic()
        reply = drv.ok('restore-start', {'backup_id': self.safety, 'apps': ['omnigent'], 'confirm': True,
                                         'request_id': drv.request_id(f'rollback-{self.arch}-omnigent')}, ev=ev, timeout=300)
        job = drv.wait_job(reply['job_id'], ev=ev, timeout=5400)
        took = time.monotonic() - started
        ev.save('rollback-job.json', job)
        result = job.get('result') or {}
        drv.created_backup(result.get('safety_backup_id'))
        health = result.get('health') or []
        ev.check("rollback: restore-start of the import's safety backup succeeded, every health check ok",
                 job['state'] == 'succeeded' and result.get('rolled_back') is False and health
                 and all(h.get('status') == 'ok' for h in health),
                 {'state': job['state'], 'error': job.get('error'), 'took_s': round(took, 1),
                  'health': [(h.get('id'), h.get('status')) for h in health]})
        self.wait_units('rollback')
        found = self.markers('rollback')
        ev.check("rollback: dev-d's own markers are back (batch1_markers.py read)", self.has_own_markers(found), found)
        state = self.state('rollback')
        ev.check("rollback: dev-d's schema, pi volume and its own cookie key are as before the import; no HA user left",
                 state.get('signature_sha256') == self.before.get('signature_sha256')
                 and tar_digests(state.get('pi_files')) == tar_digests(self.before.get('pi_files'))
                 and state.get('cookie_sha256') == self.before.get('cookie_sha256')
                 and found.get('user_count') == self.before_markers.get('user_count'),
                 {'cookie_is_own': state.get('cookie_sha256') == self.before.get('cookie_sha256'),
                  'user_count': [self.before_markers.get('user_count'), found.get('user_count')]})
        drv.app_health(ev, 'omnigent', 'rollback')

    # -------- cleanup and leaks
    def step_cleanup(self):
        ev = self.ev
        objects = drv.labelled()
        ev.check('cleanup: no throwaway container, volume or network of a job left', not any(objects.values()), objects)
        listing = drv.device_python(drv.RUN_LIST, as_owner=False)
        staging = listing.get(drv.STAGING)
        keys = [n for n in listing.get('/run/woowtech-backup') or [] if isinstance(n, str) and n.startswith('key-')]
        ev.check('cleanup: no staging folder and no key file left', staging in ([], 'missing') and not keys, listing)
        present = {b['id'] for b in drv.ok('list', ev=ev)['backups']}
        created = [b for b in drv.STATE.get('created_backups') or [] if b != BASELINE]
        deleted, refused = [], []
        for backup_id in created:
            if backup_id in present:
                rc, _reply = drv.helper('delete', {'backup_id': backup_id})
                (deleted if rc == 0 else refused).append(backup_id)
        left = {b['id'] for b in drv.ok('list', ev=ev)['backups']}
        ev.check("cleanup: the test's converted and safety backups are deleted, dev-d's baseline stays",
                 BASELINE in left and not (left & set(created)), {'deleted': len(deleted), 'refused': refused})
        drv.STATE['created_backups'] = [b for b in drv.STATE.get('created_backups') or [] if b not in deleted]
        if self.created_store:
            rc, _reply = drv.helper('ha-delete', {'ha_backup_id': self.created_store, 'confirm': True})
            ev.check('cleanup: the HA store record this run created is deleted', rc == 0, self.created_store)
        if self.installed_entry:
            preview = drv.ok('catalog-remove', {'id': 'omnigent'}, ev=ev)
            rc, reply = drv.helper('catalog-remove', {'id': 'omnigent', 'confirm': True,
                                                      'expected_sha256': preview.get('expected_sha256')})
            ev.check('cleanup: the omnigent catalog entry this run installed is removed again (catalog as found)',
                     rc == 0, {'rc': rc, 'error': (reply or {}).get('error')})
        if self.timer_masked_here:
            proc = drv.root('systemctl', 'unmask', TIMER, timeout=120)
            drv.root('systemctl', 'start', TIMER, timeout=120)
            ev.check('cleanup: the scheduled-backup timer is back as found (unmasked)', proc.returncode == 0, '')
        drv.save_state()

    def step_leaks(self):
        ev = self.ev
        s = self.args.secrets
        names = [n for n in s.values if n not in s.names and (n.startswith(('B1_OMNI_', 'HA_BACKUP_KEY', 'HA_OMNI_',
                                                                            'DEV_D_KIT_', 'ISSUED_TOKEN_')))]
        request = {'secrets': {n: s[n] for n in names if s[n]}, 'podman_secrets': OMNI_SECRETS, 'uid': 1019}
        if len(request['secrets']) < 4:
            raise Failed('a lane secret is missing from the scan request')
        report = drv.device_python(drv.LEAK_SCAN, request, as_owner=False, timeout=900)
        host = drv.scan_host_evidence(ev.dir, s)
        ev.save('leaks.json', {'device': report, 'host': host,
                               'issued_tokens_registered': len([n for n in names if n.startswith('ISSUED_TOKEN_')])})
        ev.check('leaks: no registered value (HA logins and key, HA cookie key, issued login tokens, dev-d Omnigent '
                 "secrets, kit) in the engine records, uploads, staging, journal or this run's evidence",
                 isinstance(report, dict) and report.get('hits') == 0 and report.get('scanned', 0) > 0
                 and host.get('hits') == 0, {'device': report, 'host': host})


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def ha_cookie(backup):
    """HA's Omnigent cookie key bytes from the plain b1 backup (registered as a secret at once, never printed)."""
    sys.path.insert(0, str(REPO / 'backup-engine'))
    from woowbackup import ha_omnigent, habackup, hastore
    with habackup.open_backup(backup) as ha:
        found = [m for m in ha.layout.members if m.role == 'addon' and hastore.addon_suffix(m.slug) == 'woow-omnigent']
        if len(found) != 1:
            raise Failed('omnigent member missing')
        select = habackup.Select(include=(ha_omnigent.ARTIFACTS + '/' + ha_omnigent.COOKIE,), symlinks=(),
                                 hardlinks=False)
        value = None
        with ha.open_member(found[0].name) as stream:
            for entry in habackup.iter_entries(stream, select, habackup.Report()):
                if entry.kind != 'file' or value is not None:
                    raise Failed('cookie is not a single file')
                value = entry.read_all(4096)
    if not value:
        raise Failed('HA cookie missing')
    return value


def owner(*argv):
    return drv.owner(*argv, timeout=600)


def owner_ok(*argv, timeout=600):
    proc = drv.owner(*argv, timeout=timeout)
    if proc.returncode != 0:
        raise Failed(f'owner command failed: {argv[0]} rc {proc.returncode}')
    return drv.out(proc)


def write_owner_file(rel, data, mode='0644'):
    proc = drv.run([drv.LP, 'exec', '-i', drv.DEVICE, drv.OWNER, 'sh', '-c',
                    'umask 077 && cat > "$1" && chmod "$2" "$1"', 'sh', f'/home/appowner/{rel}', mode],
                   input=data, timeout=60)
    if proc.returncode != 0:
        raise Failed(f'writing ~/{rel} failed')


def owner_exists(rel):
    return drv.owner('test', '-e', f'/home/appowner/{rel}', timeout=60).returncode == 0


def run_all(run):
    ev = run.ev
    phases = [('secrets', run.load_secrets), ('setup', run.setup), ('before', run.step_before),
              ('upload', run.step_upload), ('check', run.step_check), ('import', run.step_import),
              ('verify', lambda: run.verify('restore')), ('restart', run.step_restart),
              ('auto rollback', run.step_auto_rollback)]
    failure = None
    try:
        for name, step in phases:
            run.budget(name)
            ev.log(f'== {name}')
            step()
    except Exception as error:  # noqa: BLE001 - whatever stopped a phase, the cleanup below always runs
        failure = error
        ev.check(f'phase stopped: {type(error).__name__}', False, str(error)[:300])
    for name, step in (('inject off', run.inject_off),):
        try:
            step()
        except Exception as error:  # noqa: BLE001 - keep cleaning up
            ev.check(f'{name}: ran', False, type(error).__name__)
    if getattr(run, 'safety', None):
        try:
            run.step_rollback_to_own()
        except Exception as error:  # noqa: BLE001
            failure = failure or error
            ev.check('rollback: ran', False, type(error).__name__)
    try:
        run.step_cleanup()
    except Exception as error:  # noqa: BLE001
        failure = failure or error
        ev.check('cleanup: ran', False, type(error).__name__)
    try:
        run.step_leaks()
    except Exception as error:  # noqa: BLE001
        failure = failure or error
        ev.check('leaks: ran', False, type(error).__name__)
    return failure


def self_check():
    for name, program in (('SPACE', SPACE), ('STATE_PROBE', STATE_PROBE), ('ENGINE_HASHES', ENGINE_HASHES),
                          ('MARKERS', MARKERS)):
        compile(program, name, 'exec')
    for key in FIXTURE_SHA:
        if not re.fullmatch(r'[0-9a-f]{64}', FIXTURE_SHA[key]):
            raise SystemExit('bad fixture digest')
    print('offline self-check passed: 4 embedded programs compiled, 4 fixture digests')


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--self-check', action='store_true')
    parser.add_argument('--run', action='store_true')
    parser.add_argument('--arch', choices=('x86', 'arm'))
    parser.add_argument('--form', choices=('plain', 'enc'))
    args = parser.parse_args(argv)
    if args.self_check:
        self_check()
        return 0
    if not args.run or not args.arch or not args.form:
        parser.error('--run --arch x86|arm --form plain|enc required')
    clean, _dirty = clean_tree()
    commit = head()
    emit(f'source commit {commit}')
    if not clean:
        emit('source tree committed: FAIL')
        return 2
    emit('source tree committed: PASS')
    fd, waited = acquire()
    started = time.monotonic()
    emit(f'dev-d mutation lock acquired: PASS (waited {waited} s)')
    rc = 1
    try:
        emit(verify_isolation())
        args.secrets = drv.Secrets([drv.SECRET_DIR / 'b1-creds.env', drv.SECRET_DIR / 'ha-import-creds.env'],
                                   drv.SECRET_DIR / 'dev-d-markers.json')
        ev = Ev(args.secrets, 'omnigent-product')
        drv.STATE.clear()
        drv.load_state()
        drv.STATE['created_backups'] = []
        run = Run(args, ev)
        run.lock_started = started
        run.headroom()
        failure = run_all(run)
        failed = [r for r in ev.results if not r['ok']]
        ev.save('results.json', {'passed': len(ev.results) - len(failed), 'failed': len(failed),
                                 'failed_checks': [r['check'] for r in failed], 'results': ev.results,
                                 'source_commit': commit, 'arch': args.arch, 'form': args.form})
        drv.save_state()
        emit(f'omnigent full flow {args.arch} {args.form}: {len(ev.results) - len(failed)}/{len(ev.results)} '
             f'{"PASS" if not failed and failure is None else "FAIL"}')
        rc = 0 if not failed and failure is None else 1
    finally:
        try:
            emit(verify_isolation())
        except Failed:
            emit('dev-d isolation after the run: FAIL')
            rc = 1
        emit(f'lock held for {int(time.monotonic() - started)} s')
        os.close(fd)
    return rc


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
