#!/usr/bin/env python3
"""EMQX: the REAL package upgrade after a Home Assistant import, on lab device woowbk-dev-d, open-source images only
(owner 2026-11-28, option B: an older open-source 5.8.x, then the package's own upgrade.sh to the version it pins today).

  python3 -B -I tests/e2e/lab/emqx_upgrade_after_import.py                 offline self-check (no device, no secret)
  python3 -B -I tests/e2e/lab/emqx_upgrade_after_import.py --lease-template --source P --package K [--minutes 150]
  HEAVY_FREE=/tmp/woowbk-dev-d-mutation.lock HEAVY_WAIT=600 .../heavy.sh python3 -B -I tests/e2e/lab/services_a_capture.py \\
      --private=FILE <evidence.json> emqx-upgrade-after-import -- \\
      python3 -B -I tests/e2e/lab/emqx_upgrade_after_import.py --run --lease LEASE.json
  (before it: emqx_upgrade_image_prep.py --pull, then --stream; the lease names the image receipt's SHA-256 and digest)

Why: the H2 lab proof (2026-11-25) showed that after an HA import the package's tests/smoke.sh failed A4/A10, so
scripts/upgrade.sh would roll every upgrade back; Woow_podman_emqx PR #11 (c01c897) turned those checks into warnings
when the import marker is there. upgrade.sh itself was never run: it pulls images and the lab has no network. The
package's own rule makes that unnecessary: scripts/lib/quadlet-lib.sh ql_pull_images skips `podman pull` when `podman
image exists <ref>`, and the version the package pins today (5.8.9) is already in dev-d's owner store.

The older version: docker.io/emqx/emqx:5.8.8 (index sha256:4593b6e3..., amd64 manifest sha256:2bbadcd6..., image ID
5a96e360..., Apache-2.0 open-source edition, the same OTP 26.2.5.14-1 as 5.8.9, curl installed for the package's
HealthCmd), the nearest older open-source 5.8.x. Its 5.8.9 successor changes no data format or setting this package or
HA's import uses (release notes v5.8.9: HTTP action timeout from request_ttl, MQTT connector static_clientids users,
{allow|deny, all} matching, empty-username validation; breaking: macOS 13 packages only). Never a BSL/Enterprise image.

THE ORDER, and why: the product refuses an EMQX import whose versions differ (haissues.version_issues: HA's add-on 5.9.1
runs EMQX 5.8.9; this device's version comes from its Quadlet image's label; both known and different = a stop line,
`version.different`). So the import cannot run on 5.8.8: it runs on dev-d's own 5.8.9, as the product requires. Then
the package's installer moves dev-d's EMQX to 5.8.8 and the package's upgrade.sh brings it back to 5.8.9:
  1. the import on 5.8.9 (the product's normal path: check + one-action import, the marker in the data volume);
  2. the older copy's scripts/install.sh (c01c897 with only its Image= lines repinned: 5.8.8 at dev-d's loaded digest,
     the installed entrance pin) - the older broker starts ONCE, on the imported data the product's 5.8.9 candidate wrote,
     never on dev-d's own baseline data (the owner accepted that an older 5.8.x may not read 5.8.9-written data: a broker
     that does not start fails install.sh's own health wait, and the recovery brings dev-d back);
  3. the REAL upgrade: the upgrade copy's scripts/upgrade.sh (c01c897, pinned 5.8.9 at dev-d's loaded digest; the image
     is there, so nothing is pulled), no option.
Both copies are `git archive` of Woow_podman_emqx c01c897 (the leased checkout, never changed) with only their Image=
lines changed (a `podman load` changes a manifest digest; deploy-batch1.sh repinned the same way), so the upgrade
changes exactly ONE unit line: emqx.container's Image=. They live in ~/woowbk-emqx-upgrade-<run id>/ (0700) next to the
private exact copies of dev-d's EMQX files, and are removed again; dev-d's own package copy ~/Woow_podman_emqx (ea5886c)
is never touched.

One run = the heavy seat (HEAVY_FREE = the dev-d lock: heavy.sh waited for it), one hold of /tmp/woowbk-dev-d-mutation.lock
(dev_d_guard.acquire: waits up to 10 minutes, yields to emqx-main), a clean committed checkout at the leased commit, the
clean product source the device runs and the clean package checkout, the leased image receipt, no earlier run pending
(receipt ~/.woowbk-lab/run/emqx_upgrade_after_import.json, written at every change, complete only when nothing of the run
is left on dev-d).

  preflight   dev-d isolated (network none, no port); host memory/disk and dev-d headroom; installed engine == the leased
              product source; the leak scan is the reviewed program; no job; the backup schedule masked; the engine says
              EMQX running from its catalog entry; dev-d runs 5.8.9 from its own units (Image= pins, image IDs of both
              containers); the OLDER image is in dev-d's owner store with the pinned ID and the leased digest (and
              `podman image exists <tag>@<digest>`); dev-d's own package copy is ea5886c, no run folder yet; dev-d's own
              EMQX holds its baseline markers and no import marker; the 11-19 baseline opens with the kit and restores
              without a confirmation; no unowned EMQX safety backup can be pruned by the two restores; the fixture's HA
              record is absent (uploaded by this run) or the protected one at the fixture SHA-256
  capture     (first change) exact private copies of dev-d's EMQX files, env file and Quadlet state inside dev-d
  stage       the two throwaway copies (only their Image= lines differ from c01c897), checked file by file
  import      upload when needed, ha-check-start (EMQX importable, nothing stops it, confirmation lines keyed), the
              one-action ha-import-start (conversion + restore, every listed key once), not rolled back, the import
              marker in the data volume, dev-d's EMQX files untouched by it, EMQX serving HA's data (the b1 probe as
              HA's admin: Dashboard and MQTT accounts, ACL, retained, rules, banned client, API key; MQTT logins and
              refusals), on 5.8.9 from dev-d's own units
  downgrade   the older copy's scripts/install.sh (no option), as appowner, bounded; judged: exit 0, installed and
              healthy, its smoke lines the imported set, no dev-d secret in its output, the broker on the 5.8.8 image ID,
              only emqx.container (the template diff ea5886c -> c01c897 at the two pins) and the Quadlet manifest changed,
              no backup folder, the marker still there, and the 5.8.8 broker serves EXACTLY what 5.8.9 served
  upgrade     the upgrade copy's scripts/upgrade.sh, NO option (hot pre-upgrade backup, unit snapshot, install.sh
              --no-smoke -> no pull, restart, health, then tests/smoke.sh), as appowner, bounded; judged: exit 0, NOT
              rolled back, smoke lines exactly the imported set (A4 and A5/A6/A10 WARN, 11 PASS, 0 FAIL), no dev-d secret
              in its output, the container moved from the 5.8.8 image ID to the 5.8.9 one, only emqx.container's Image=
              line and the Quadlet manifest changed, exactly its backup and snapshot folders new, the marker still there
  after       the node reports 5.8.9 (was 5.8.8) and serves EXACTLY what it served before the upgrade (accounts,
              authenticators, authorization settings and sources, ACL rows, retained, rules, connectors, actions, banned,
              API keys, MQTT behaviour)
  recovery    whatever stopped the run (a failed check, an error, SIGTERM/SIGINT): a running package script is stopped
              (TERM, then KILL of its group), every job of the run waited for (30 min), dev-d's EMQX files written back
              byte for byte (+ daemon-reload), the 11-19 baseline restored with the kit on dev-d's own 5.8.9 units, then
              compared: image IDs, Image= lines and units as before, dev-d's markers exactly back, no import marker,
              dev-d's own smoke.sh --quick 10 PASS 0 FAIL 0 WARN
  cleanup     only what this run made, only once dev-d is verifiably back: the conversion and the two safety backups,
              the HA record when uploaded, the package's backup/snapshot folders of this run (they hold dev-d's secrets
              and the export), the run folder; no job object, staging folder or key file. Otherwise all stays (receipt
              pending) for the coordinator
  leaks       registered values (HA key, HA test passwords, markers, kit, every issued Dashboard token) and dev-d's EMQX
              secrets in the engine roots and the device journal since the start; every issued token registered; the
              private evidence: 0 hits
  after       isolation; backups and HA records exactly as before; image list, containers, EMQX secrets and volumes (names),
              units, EMQX files, dev-d's package copy, timer as before; no job running

stdout carries only fixed lines (`<check>: PASS|FAIL`, the source commit, the lock time, the count line); details go to the
private, redacted evidence folder ~/.woowbk-lab/evidence/emqx-upgrade-after-import/<time>/ (0700, files 0600). A passing
run has 61 checks. Exit status: 0 every check passed, 1 a check failed (the recovery ran), 2 refused before the lock
(nothing on dev-d read), 3 the lock stayed taken. Not covered (stated): an import ON an older version (the product refuses
it), a browser, production, ARM, a cold (--cold) pre-upgrade backup, a downgrade by the package (the recovery uses the
product's baseline restore instead).
"""
import argparse
import base64
import collections
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import inspect
import io
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tarfile
import time

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
LAB = Path.home() / '.woowbk-lab'
DEVICE = 'woowbk-dev-d'
LOCK = '/tmp/woowbk-dev-d-mutation.lock'
CASE = 'emqx-upgrade-after-import'
PHASE = 'older-then-upgrade'
AREA = 'emqx-upgrade-after-import'
RECEIPT = LAB / 'run' / 'emqx_upgrade_after_import.json'
IMAGE_RECEIPT = LAB / 'run' / 'emqx_upgrade_image_prep.json'
LOCK_WAIT = 10 * 60               # heavy.sh waited for the lock to be free: a short race only
HOLD_BUDGET = 60 * 60             # no new forward phase after this many seconds of the hold (recovery always runs)
RECOVERY_RESERVE = 25 * 60        # a forward phase starts only with this much of the lease left
MIN_LEASE_LEFT = 90 * 60
MAX_LEASE_WINDOW = 180 * 60
JOB_WAIT = 30 * 60                # one job (11-25: check 232-527 s, convert 261-454 s, restore 66-348 s)
INSTALL_TIMEOUT = 15 * 60         # install.sh: health 180 + 90 s, the dashboard 120 s, smoke (A2 waits 270 s)
UPGRADE_TIMEOUT = 25 * 60         # upgrade.sh: backup, install --no-smoke, smoke, a rollback with its own waits
READY_TIMEOUT = 5 * 60
SMOKE_TIMEOUT = 10 * 60
FLOOR = 13 * 1024 ** 3            # the team keeps >= 12 GiB free on the host at every moment (+1 GiB margin)
RUN_WRITES = 1024 ** 3            # upload 132 MiB into dev-d, conversion and safety backups and the package backup < 10 MiB
MIN_HOST_AVAILABLE_KIB = 1200 * 1024
MIN_HEADROOM = 1900 * 1024 ** 2   # dev-d cgroup: the HA check's throwaway broker and the jobs (page-emqx's floor)
APP = 'emqx'
FIXTURE = LAB / 'ha-fixtures' / '20261119-b1' / 'x86' / 'woow-b1-x86-emqx-stopped-enc' / 'woow-b1-x86-emqx-stopped-enc.tar'
FIXTURE_SHA = '0a53e93888209316040af505484bba3ee3891c2ad2df7ae689bc0d4fd02690f9'   # the real x86 HA, EMQX stopped (H2's)
HA_ID = 'ha-' + FIXTURE_SHA[:20]
BASELINE = '20261119T072831Z-168aaa02'      # dev-d's own EMQX baseline backup (11-19 device key: dev-d-kit.txt)
TIMER = 'woowtech-cockpit-backup-schedule.timer'
PACKAGE_COMMIT = 'c01c897f524e0c7a231c21e823482cdfd1593ede'     # Woow_podman_emqx main with PR #11 (smoke after import)
INSTALLED_COMMIT = 'ea5886c58ef2c6ab1f4e6a4d01908cc9dc4525de'   # dev-d's own package copy (deploy-batch1.sh REV)
# The older open-source image the installer puts dev-d's EMQX on (pulled into the LAB store, streamed into dev-d).
OLDER = {'name': 'docker.io/emqx/emqx:5.8.8', 'version': '5.8.8',
         'index_digest': 'sha256:4593b6e30196754779fa14483332cb0be56c233f1c8a387b1308bec4337c0144',
         'amd64_manifest': 'sha256:2bbadcd6ebdf1e2d032bdd8149c9615867ed25f32b1a09ec5bd92ddcf159e1aa',
         'image_id': '5a96e36027e748efeb6fef8d05ea6d9b3036810540fd7286227b2e0f951a447f'}
# The version the package pins today (c01c897: docker.io/emqx/emqx:5.8.9@sha256:35b46f7a..., the registry index) as dev-d
# has it: deploy-batch1.sh streamed it in, its loaded digest pins dev-d's own units.
CURRENT = {'ref': 'docker.io/emqx/emqx:5.8.9@sha256:d4ec63c4065c745507e7652d9c0213134697dc1317d8a431b167ae7651c4e937',
           'image_id': '3f60addfad2bfc6c09400aa48cfbc1b2b2aab04fb6a64d6392c016e02d7fb57b', 'version': '5.8.9'}
ENTRANCE = {'ref': 'docker.io/nginxinc/nginx-unprivileged:1.27-alpine@sha256:'
                   '7b40c8ed6a73bda24d7510e3be1db31a19878acf65062271302a8a7aafd1682e',
            'image_id': '47ce8258a10e28ce4b4498588c25ef77ae328f4c56cbe3e8d5dcf4f6d8019997'}
NODE = 'emqx@127.0.0.1'
CONTAINERS = ('woow-emqx', 'woow-emqx-entrance')
UNITS = ('emqx.service', 'emqx-entrance.service', 'emqx-data-volume.service', 'emqx-log-volume.service',
         'emqx-network.service')
QUADLET = '.config/containers/systemd/emqx.container'
STATE_MANIFEST = '.local/state/woow-quadlet/emqx/manifest'
EXPECTED_CHANGED = sorted((QUADLET, STATE_MANIFEST))
PODMAN_SECRETS = ('woow-emqx-dashboard-password', 'woow-emqx-node-cookie', 'woow-emqx-mqtt-password')
NEEDED = ('HA_BACKUP_KEY', 'B1_EMQX_ADMIN_PW', 'B1_EMQX_USER2', 'B1_EMQX_USER2_PW', 'B1_MQTT_USER1', 'B1_MQTT_PW1',
          'B1_MQTT_USER2', 'B1_MQTT_PW2', 'B1_MQTT_USER3', 'B1_MQTT_PW3', 'B1_X86_EMQX_API_KEY', 'B1_X86_EMQX_API_SECRET',
          'DEV_D_MARKER_EMQX', 'DEV_D_KIT')
EMQX_AUTH = [('/api/v5/login', ('token',), False)] * 3     # the b1 probe's three Dashboard logins (ha_import_b1_e2e)
SAFE_LABEL = re.compile(r"[^A-Za-z0-9 ,()/:'<>.=_-]")
SHA = re.compile(r'[0-9a-f]{64}\Z')
COMMIT = re.compile(r'[0-9a-f]{40}\Z')
RUN_ID = re.compile(r'[0-9a-f]{12}\Z')
DIGEST = re.compile(r'sha256:[0-9a-f]{64}\Z')
# The package's smoke.sh lines (tests/smoke.sh of c01c897 after an import; of ea5886c --quick on dev-d's own EMQX).
SMOKE_ROW = re.compile(r'(PASS|FAIL|WARN) (A[0-9]+(?:/A[0-9]+)*)\b')
SMOKE_SUMMARY = re.compile(r'[0-9]+ passed, [0-9]+ failed, [0-9]+ warnings( \(quick\))?')
IMPORTED_SMOKE = {'PASS A1': 2, 'PASS A2': 2, 'PASS A3': 1, 'WARN A4': 1, 'PASS A9': 3, 'WARN A5/A6/A10': 1,
                  'PASS A7': 2, 'PASS A8': 1}
IMPORTED_SUMMARY = '11 passed, 0 failed, 2 warnings'
RESTORE_SMOKE = {'PASS A1': 2, 'PASS A2': 2, 'PASS A3': 1, 'PASS A4': 2, 'PASS A9': 3}
RESTORE_SUMMARY = '10 passed, 0 failed, 0 warnings (quick)'
ROLLBACK_WORDS = ('rolling back', 'rolled back', 'rollback failed', 'rollback is unhealthy')
COMPLETE = re.compile(r'upgrade complete \(unit snapshot: (?:\S*/)?(upgrade-[0-9]{8}-[0-9]{6}(?:-[0-9]+)?)\)')
DATA_BACKUP = re.compile(r'pre-upgrade data backup: (?:\S*/)?(backup-[0-9]{8}-[0-9]{6}(?:-[0-9]+)?)\s*\Z')
INSTALLED_LINE = 'emqx is installed and healthy.'          # scripts/install.sh's last words (c01c897)


def _load(name):
    # -I removes the script directory from sys.path: load the adjacent module explicitly.
    spec = importlib.util.spec_from_file_location(name, HERE / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


h = _load('ha_import_e2e')
h.DEVICE = DEVICE                 # every helper/owner/root call of ha_import_e2e goes to dev-d (its default is dev-c)
b1 = _load('ha_import_b1_e2e')    # Secrets, the EMQX probe and its credential event transport, the scan needles
pe = _load('focus_acceptance_ui_page_emqx')   # the reviewed EMQX check/chain/ownership/safety gates (page-emqx 81/81)
ui = _load('focus_acceptance_ui')             # the marker program with issued-token capture, the strict leak scan
guard = _load('dev_d_guard')
ops = _load('emqx_upgrade_device')
Failed = h.Failed
DEVICE_PROGRAM = (HERE / 'emqx_upgrade_device.py').read_text(encoding='utf-8') + ops.ENTRY
SCAN_SNIPPET = REPO / 'snippets' / 'focus-acceptance' / 'r8-scan-rendered.py'


class Stopped(BaseException):
    """SIGTERM/SIGINT: the run stops and the recovery runs (signals during the recovery are counted, never raised). A
    BaseException, so that no `except Exception` on the way swallows it."""


SIGNALS = {'recovering': False, 'ignored': 0}


def _stop(signum, _frame):
    if SIGNALS['recovering']:
        SIGNALS['ignored'] += 1
        return
    raise Stopped(f'signal {signum}')


# ---------------------------------------------------------------- fixed device programs (python3 -I -c, stdin JSON)

HEADROOM = r'''
import json
from pathlib import Path
stat = Path("/sys/fs/cgroup/memory.stat").read_text().splitlines()
used = sum(int(x.split()[1]) for x in stat if x.startswith(("anon ", "kernel ")))
limit = Path("/sys/fs/cgroup/memory.max").read_text().strip()
print(json.dumps({"used": used, "limit": int(limit) if limit.isdigit() else None}))
'''

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

CATALOG = r'''
import hashlib, json
from pathlib import Path
p = Path("/etc/woowtech-cockpit/backup/apps")
print(json.dumps({x.name: hashlib.sha256(x.read_bytes()).hexdigest() for x in sorted(p.glob("*.json"))}))
'''

SIDECARS = r'''
import json
from pathlib import Path
print(json.dumps(len(list(Path("/var/lib/woowtech-backup/archives").rglob("*.json")))))
'''


def scan_program():
    """The strict engine-roots + journal scan of page-emqx / R1 (focus_acceptance_ui.scan_program), unchanged."""
    return ui.scan_program(inspect.getsource(b1.secret_scan_needles))


# ---------------------------------------------------------------- small host-side helpers

def label(text):
    return SAFE_LABEL.sub(' ', str(text))[:140].strip() or 'check'


def emit(line):
    """One fixed status line. A capture wrapper that is gone (a broken pipe) never stops the recovery: the private
    evidence records every check anyway."""
    try:
        print(line, flush=True)
    except (BrokenPipeError, OSError):
        pass


def git(path, *args):
    proc = subprocess.run(['git', '-C', str(path), *args], capture_output=True, timeout=120)
    return proc.returncode, proc.stdout


def git_text(path, *args):
    code, out = git(path, *args)
    return out.decode('utf-8', 'replace').strip() if code == 0 else None


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def host_resources():
    available = next(int(line.split()[1]) for line in Path('/proc/meminfo').read_text().splitlines()
                     if line.startswith('MemAvailable:'))
    stat = os.statvfs(str(LAB))
    return available, stat.f_bavail * stat.f_frsize


def tree_engine(product):
    base = Path(product) / 'backup-engine' / 'woowbackup'
    return {'lib': {str(p.relative_to(base)): sha256_file(p) for p in base.rglob('*.py') if '__pycache__' not in p.parts},
            'helper': sha256_file(Path(product) / 'backup-engine' / 'woowtech-cockpit-backup')}


def private_file(path):
    path = Path(path)
    try:
        st = path.lstat()
    except OSError:
        return False
    return path.is_file() and not path.is_symlink() and st.st_uid == os.getuid() and not st.st_mode & 0o077


def request_id(run_id, tag):
    return f'emqx-upg-{run_id}-{tag}-{int(time.time() * 1000)}'


def needles(values):
    found = set()
    for value in values:
        raw = value.encode('utf-8')
        found.add(raw)
        for ascii_only in (False, True):
            found.add(json.dumps(value, ensure_ascii=ascii_only)[1:-1].encode('utf-8'))
    return found


def scan_evidence(directory, values):
    """{files, hits} of `values` in every file below `directory` (a link fails the scan)."""
    probes = needles(values)
    files = hits = 0
    for root, dirs, names in os.walk(directory, followlinks=False):
        for name in dirs + names:
            if (Path(root) / name).is_symlink():
                raise Failed('evidence scan met a symlink')
        for name in names:
            data = (Path(root) / name).read_bytes()
            files += 1
            hits += sum(data.count(probe) for probe in probes)
    return {'files': files, 'hits': hits}


# ---------------------------------------------------------------- the lease and the image receipt

def validate_lease(lease, *, driver_commit, now):
    """The exact, fresh lease of this case: granted for dev-d, this case/phase and run id, this driver commit, the product
    source and package checkouts at their commits, the pinned older image at the leased device digest, the image receipt's
    SHA-256, and an expiry 90-180 minutes ahead."""
    try:
        expires = datetime.fromisoformat(lease['expires']).timestamp()
        aware = datetime.fromisoformat(lease['expires']).tzinfo is not None
    except (KeyError, TypeError, ValueError):
        raise ValueError('exact fresh emqx-upgrade lease required') from None
    if (lease.get('granted') is not True or lease.get('device') != DEVICE or lease.get('case') != CASE
            or lease.get('phase') != PHASE or not RUN_ID.fullmatch(str(lease.get('run_id', '')))
            or not COMMIT.fullmatch(str(driver_commit or '')) or lease.get('driver_commit') != driver_commit
            or not isinstance(lease.get('source'), str) or not os.path.isabs(lease['source'])
            or not COMMIT.fullmatch(str(lease.get('source_commit', '')))
            or not isinstance(lease.get('package'), str) or not os.path.isabs(lease['package'])
            or lease.get('package_commit') != PACKAGE_COMMIT
            or lease.get('older_image') != OLDER['name'] or lease.get('older_image_id') != OLDER['image_id']
            or not DIGEST.fullmatch(str(lease.get('older_device_digest', '')))
            or not SHA.fullmatch(str(lease.get('image_receipt_sha256', '')))
            or not aware or not now + MIN_LEASE_LEFT <= expires <= now + MAX_LEASE_WINDOW):
        raise ValueError('exact fresh emqx-upgrade lease required')
    return lease


def image_receipt_ok(raw, lease):
    """The receipt emqx_upgrade_image_prep.py --stream wrote: this device, the pinned older image, loaded, the leased
    digest."""
    try:
        doc = json.loads(raw)
    except (TypeError, ValueError):
        return False
    return (hashlib.sha256(raw).hexdigest() == lease.get('image_receipt_sha256') and isinstance(doc, dict)
            and doc.get('device') == DEVICE and doc.get('image') == OLDER['name']
            and doc.get('image_id') == OLDER['image_id'] and doc.get('index_digest') == OLDER['index_digest']
            and doc.get('device_digest') == lease.get('older_device_digest') and doc.get('loaded') is True
            and doc.get('removed') is not True)


def lease_template(*, driver_commit, source, source_commit, package, receipt_sha, run_id, minutes, now=None):
    now = now or datetime.now(timezone.utc)
    return {'granted': False, 'device': DEVICE, 'case': CASE, 'phase': PHASE, 'run_id': run_id,
            'driver_commit': driver_commit, 'source': str(source), 'source_commit': source_commit,
            'package': str(package), 'package_commit': PACKAGE_COMMIT, 'older_image': OLDER['name'],
            'older_image_id': OLDER['image_id'], 'older_device_digest': None, 'image_receipt_sha256': receipt_sha,
            'expires': (now + timedelta(minutes=minutes)).replace(microsecond=0).isoformat(),
            'note': 'set granted true (and older_device_digest from the image receipt) after review'}


# ---------------------------------------------------------------- the throwaway package copy

class PackageSource:
    """The leased Woow_podman_emqx checkout, read through git objects only (never its working tree, never changed)."""

    def __init__(self, path):
        self.path = Path(path)

    def head(self):
        return git_text(self.path, 'rev-parse', 'HEAD')

    def clean(self):
        code, out = git(self.path, 'status', '--porcelain', '--untracked-files=no')
        return code == 0 and not out.strip()

    def show(self, commit, rel):
        code, out = git(self.path, 'show', f'{commit}:{rel}')
        if code != 0:
            raise Failed(f'the package checkout has no {rel} at {commit[:8]}')
        return out

    def files(self, commit):
        """{relative path: (bytes, mode)} of `git archive <commit>` (regular files only)."""
        code, out = git(self.path, 'archive', '--format=tar', commit)
        if code != 0:
            raise Failed('git archive of the package commit failed')
        found = {}
        with tarfile.open(fileobj=io.BytesIO(out), mode='r:') as archive:
            for member in archive:
                if member.isdir():
                    continue
                if not member.isfile():
                    raise Failed('the package commit holds a link or a special file')
                found[member.name] = (archive.extractfile(member).read(), member.mode)
        return found


def repin(files, lines):
    """`files` with exactly one Image= line replaced in each named file: (new files, {file: {old, new}})."""
    out, report = dict(files), {}
    for rel, line in lines.items():
        data, mode = files[rel]
        rows = data.decode('utf-8').split('\n')
        index = [n for n, row in enumerate(rows) if row.startswith('Image=')]
        if len(index) != 1 or not line.startswith('Image=') or '\n' in line:
            raise Failed(f'{rel}: exactly one Image= line is required')
        report[rel] = {'old': rows[index[0]], 'new': line}
        rows[index[0]] = line
        out[rel] = ('\n'.join(rows).encode('utf-8'), mode)
    return out, report


def repin_exact(before, after, lines):
    """Only the named files changed, each by exactly its one Image= line."""
    if set(before) != set(after) or {rel for rel in before if before[rel] != after[rel]} != set(lines):
        return False
    for rel, line in lines.items():
        delta = ops.line_delta(before[rel][0].decode('utf-8'), after[rel][0].decode('utf-8'))
        if len(delta['removed']) != 1 or not delta['removed'][0].startswith('Image=') or delta['added'] != [line]:
            return False
    return True


def pack(files):
    """(base64 tar of regular files, {relative path: [sha256, executable]})."""
    buffer = io.BytesIO()
    expected = {}
    with tarfile.open(fileobj=buffer, mode='w', format=tarfile.PAX_FORMAT) as archive:
        for rel in sorted(files):
            data, mode = files[rel]
            info = tarfile.TarInfo(rel)
            info.size, info.mode, info.mtime = len(data), 0o755 if mode & 0o111 else 0o644, 0
            archive.addfile(info, io.BytesIO(data))
            expected[rel] = [hashlib.sha256(data).hexdigest(), bool(mode & 0o111)]
    return base64.b64encode(buffer.getvalue()).decode('ascii'), expected


def pinned(text, line):
    rows = text.split('\n')
    index = [n for n, row in enumerate(rows) if row.startswith('Image=')]
    if len(index) != 1:
        raise Failed('a Quadlet template without exactly one Image= line')
    rows[index[0]] = line
    return '\n'.join(rows)


# ---------------------------------------------------------------- judging the package's output

def smoke_rows(lines):
    rows, summaries = collections.Counter(), []
    for line in lines:
        match = SMOKE_ROW.match(str(line))
        if match:
            rows[f'{match[1]} {match[2]}'] += 1
        if SMOKE_SUMMARY.fullmatch(str(line).strip()):
            summaries.append(str(line).strip())
    return dict(rows), summaries


def judge_script(result):
    """The package script's output (the older copy's install.sh or the upgrade copy's upgrade.sh): exit status, the one
    success line (install.sh: installed and healthy; upgrade.sh: upgrade complete, its snapshot named), no rollback line,
    smoke.sh's lines exactly the imported set, no dev-d secret value."""
    lines = [str(line) for line in result.get('lines') or []]
    rows, summaries = smoke_rows(lines)
    snapshot = [m[1] for m in (COMPLETE.search(line) for line in lines) if m]
    data = [m[1] for m in (DATA_BACKUP.search(line) for line in lines) if m]
    rollback = [line for line in lines if any(word in line for word in ROLLBACK_WORDS)]
    installed = sum(1 for line in lines if line.strip() == INSTALLED_LINE)
    # upgrade.sh runs install.sh --no-smoke first, so install.sh's last words appear once in its output too (dev-d,
    # 2026-11-28 emqx-upgrade-02: line 26 'emqx is installed and healthy.', line 46 'upgrade complete (unit snapshot: ...)').
    success = (len(snapshot) == 1 and installed == 1) if result.get('copy') == 'upgrade' else (installed == 1 and not snapshot)
    return {'exit_zero': result.get('rc') == 0 and result.get('timed_out') is False,
            'complete': success and not rollback, 'rolled_back': bool(rollback),
            'smoke_exact': rows == IMPORTED_SMOKE and summaries == [IMPORTED_SUMMARY],
            'secret_free': result.get('device_secret_hits') == 0 and result.get('truncated') is False,
            'snapshot': snapshot[0] if len(snapshot) == 1 else None, 'data_backup': data[0] if len(data) == 1 else None,
            'rows': rows, 'summaries': summaries, 'seconds': result.get('seconds'), 'rc': result.get('rc'),
            'timed_out': result.get('timed_out'), 'copy': result.get('copy')}


def unit_delta(before_lines, after_lines):
    """What changed in the installed emqx.container between two reads of its lines (None when a read is missing)."""
    if not isinstance(before_lines, list) or not isinstance(after_lines, list):
        return None
    return ops.line_delta('\n'.join(before_lines), '\n'.join(after_lines))


def judge_restore_smoke(result):
    rows, summaries = smoke_rows(result.get('lines') or [])
    return (result.get('rc') == 0 and result.get('timed_out') is False and result.get('device_secret_hits') == 0
            and rows == RESTORE_SMOKE and summaries == [RESTORE_SUMMARY]), {'rows': rows, 'summaries': summaries,
                                                                             'rc': result.get('rc')}


def imported_view(probe):
    """What the b1 EMQX probe (ha_import_b1_e2e.EMQX_PROBE) read, in the groups the upgrade must keep exactly."""
    probe = probe if isinstance(probe, dict) else {}
    mq = probe.get('mqtt') or {}
    retained = mq.get('gateway_retained') or {}
    return {
        'accounts': {'logins': [probe.get('dashboard_admin_ha_password'), probe.get('dashboard_user2_ha_password'),
                                probe.get('dashboard_admin_device_password')],
                     'dashboard_users': probe.get('dashboard_users'), 'mqtt_users': probe.get('mqtt_users'),
                     'authenticators': probe.get('authenticators'), 'authz_settings': probe.get('authz_settings'),
                     'authz_sources': probe.get('authz_sources'), 'acl': probe.get('acl')},
        'data': {'retained': sorted(str(t) for t in probe.get('retained') or [] if not str(t).startswith('$SYS/')),
                 'rules': probe.get('rules'),
                 'connectors': sorted([str(x[0]), str(x[1])] for x in probe.get('connectors') or [] if len(x) >= 2),
                 'actions': sorted([str(x[0]), str(x[1])] for x in probe.get('actions') or [] if len(x) >= 2),
                 'banned': probe.get('banned'), 'api_keys': probe.get('api_keys'),
                 'api_key_works': probe.get('api_key_works')},
        'mqtt': {'logins': {k: v for k, v in sorted(mq.items()) if k.startswith('login_')},
                 'bootstrap_woow': mq.get('bootstrap_woow'),
                 'gateway_retained': {'suback': retained.get('suback'), 'topics': retained.get('topics')},
                 'sensor_denied_topic_suback': mq.get('sensor_denied_topic_suback'),
                 'sensor_unlisted_topic_suback': mq.get('sensor_unlisted_topic_suback'),
                 'refused': {k: mq.get(k) not in (0, None) for k in ('anonymous', 'wrong_password', 'banned_client')}},
        'node': {'nodes': probe.get('nodes'),
                 'started': any('is started' in str(line) for line in probe.get('ctl_status') or [])}}


def ha_data_ok(view, src):
    """EMQX serves HA's data (the b1 source facts of the x86 broker): HA's Dashboard users, MQTT users (+ only this device's
    bootstrap user), retained messages, rules, the banned client and the API key; none of dev-d's lab markers."""
    accounts, data = view['accounts'], view['data']
    users = accounts.get('mqtt_users') or []
    ids = {str(u[0]) for u in users if isinstance(u, list) and u}
    ha_users = [[u['user_id'], u['is_superuser']] for u in src['mqtt_users']]
    return (accounts.get('logins') == [200, 200, 401]
            and sorted(accounts.get('dashboard_users') or []) == sorted(src['dashboard_users'])
            and all(u in users for u in ha_users) and ids - {u[0] for u in ha_users} <= {'woow'}
            and not any(i.startswith('woowbk-lab-') for i in ids)
            and set(src['retained_messages']) <= set(data.get('retained') or [])
            and set(src['rules']) <= {str(r[0]) for r in data.get('rules') or [] if r}
            and all(['clientid', who] in (data.get('banned') or []) for who in src['banned'])
            and not any('woowbk-lab-' in str(b) for b in data.get('banned') or [])
            and all([name, True] in (data.get('api_keys') or []) for name in src['api_keys'])
            and data.get('api_key_works') == 200)


def ha_mqtt_ok(view, src):
    mq = view['mqtt']
    retained = mq.get('gateway_retained') or {}
    return (len(mq.get('logins') or {}) == len(src['mqtt_users']) and all(v == 0 for v in mq['logins'].values())
            and mq.get('bootstrap_woow') == 0 and all((mq.get('refused') or {}).values())
            and len(mq.get('refused') or {}) == 3 and retained.get('suback') in (0, 1)
            and set(src['retained_messages']) <= set(retained.get('topics') or []))


def node_version(view):
    nodes = view['node'].get('nodes') or []
    return [n[1] for n in nodes if isinstance(n, list) and len(n) == 3 and n[0] == NODE and n[2] == 'running']


def file_changes(before, after):
    changed = sorted(rel for rel in set(before) & set(after) if before[rel] != after[rel])
    return changed, sorted(set(after) - set(before)), sorted(set(before) - set(after))


def manifest_follows(before, after, files_after):
    """The manifest after a package script == before with only emqx.container's line at the new file's SHA-256."""
    if not isinstance(before, dict) or not isinstance(after, dict) or set(before) != set(after):
        return False
    keys = [k for k in before if k.endswith('/' + QUADLET)]
    new = (files_after.get(QUADLET) or {}).get('sha256')
    return len(keys) == 1 and after == dict(before, **{keys[0]: new})


# ---------------------------------------------------------------- evidence and the receipt

class Ev:
    """The private, redacted evidence folder (0700, files 0600); stdout gets only `<label>: PASS|FAIL`."""

    def __init__(self, secrets, root=None):
        root = Path(root or LAB / 'evidence' / AREA)
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(root, 0o700)
        stamp = time.strftime('%Y%m%dT%H%M%S')
        self.dir, number = root / stamp, 1
        while os.path.lexists(self.dir):
            number += 1
            self.dir = root / f'{stamp}-{number}'
        self.dir.mkdir(mode=0o700)
        os.chmod(self.dir, 0o700)
        self.secrets, self.results, self.log_path = secrets, [], self.dir / 'run.log'

    def _write(self, path, text, mode='w'):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | (os.O_APPEND if mode == 'a' else os.O_TRUNC), 0o600)
        with os.fdopen(fd, mode, encoding='utf-8') as handle:
            handle.write(text)
        os.chmod(path, 0o600)

    def redact(self, value):
        return self.secrets.redact(value if isinstance(value, str) else json.dumps(
            self.secrets.redact_structure(value), ensure_ascii=False, sort_keys=True, default=str))

    def log(self, text):
        self._write(self.log_path, f'{time.strftime("%H:%M:%S")} {self.redact(str(text))}\n', 'a')

    def check(self, name, ok, detail=''):
        ok = bool(ok)
        self.results.append({'check': self.redact(str(name)), 'ok': ok, 'detail': self.redact(detail)[:1500]})
        self.log(f'{"PASS" if ok else "FAIL"} {name}')
        emit(f'{label(name)}: {"PASS" if ok else "FAIL"}')
        return ok

    def save(self, name, value):
        self._write(self.dir / name, self.redact(value) if isinstance(value, str) else json.dumps(
            self.secrets.redact_structure(value), ensure_ascii=False, indent=1, sort_keys=True, default=str))

    def finish(self):
        failed = [r for r in self.results if not r['ok']]
        self.save('results.json', {'passed': len(self.results) - len(failed), 'failed': len(failed), 'results': self.results})
        return not failed


class Receipt:
    """~/.woowbk-lab/run/emqx_upgrade_after_import.json (0600): what this run made, rewritten at every change; complete only
    when nothing of it is left on dev-d. A pending one refuses the next run before the lock."""

    def __init__(self, path=RECEIPT):
        self.path, self.data = Path(path), None

    def pending(self):
        if not os.path.lexists(self.path):
            return False
        try:
            return json.loads(self.path.read_text(encoding='utf-8')).get('complete') is not True
        except (OSError, ValueError):
            return True

    def write(self, **changes):
        self.data = dict(self.data or {}, **changes, updated=time.strftime('%Y-%m-%dT%H:%M:%S'))
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        temp = self.path.with_name(self.path.name + '.tmp')
        if os.path.lexists(temp):
            temp.unlink()
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            json.dump(self.data, handle, indent=1, ensure_ascii=False, sort_keys=True)
            handle.write('\n')
        os.replace(temp, self.path)


# ---------------------------------------------------------------- the real device (labpodman exec only)

class LabDevice:
    """dev-d through the lab's own paths: the helper as root (what Cockpit sends), fixed programs as root or as appowner
    (woowbk-owner), the b1 probe through its acknowledged credential-event transport."""

    def __init__(self, secrets, run_id):
        self.secrets, self.run_id = secrets, run_id
        self.marker_program = ui.marker_program((HERE / 'batch1_markers.py').read_text(encoding='utf-8'))
        self.observed = []        # every issued Dashboard token value seen by this run (marker reads and probes)

    def isolated(self):
        try:
            guard.verify_isolation(HERE / 'owner.sh')
            return True
        except guard.GuardError:
            return False

    def helper(self, command, request=None, timeout=1800):
        return h.helper(command, request, timeout=timeout)

    def root_json(self, script, request=None, timeout=300):
        proc = h.root('python3', '-I', '-c', script, input=json.dumps(request or {}).encode(), timeout=timeout)
        try:
            reply = json.loads(proc.stdout.decode('utf-8', 'replace').strip().splitlines()[-1])
        except (ValueError, IndexError):
            reply = None
        if proc.returncode != 0 or reply is None:
            raise Failed('a fixed device program failed')
        return reply

    def op(self, op, request=None, timeout=300):
        payload = dict(request or {}, op=op, run_id=self.run_id)
        proc = h.owner('python3', '-B', '-I', '-c', DEVICE_PROGRAM, input=json.dumps(payload).encode(), timeout=timeout)
        try:
            reply = json.loads(proc.stdout.decode('utf-8', 'replace').strip().splitlines()[-1])
        except (ValueError, IndexError):
            raise Failed(f'device operation {op}: no fixed reply (rc {proc.returncode})') from None
        if proc.returncode != 0 or reply.get('ok') is not True:
            raise Failed(f'device operation {op} refused: {reply.get("fixed_code") or reply.get("error_class")}')
        return reply['result']

    def timer(self):
        proc = h.root('systemctl', 'show', TIMER, '--property=UnitFileState,ActiveState', timeout=60)
        if proc.returncode:
            raise Failed('schedule state probe failed')
        return dict(line.split('=', 1) for line in proc.stdout.decode().splitlines() if '=' in line)

    def markers(self):
        """dev-d's own EMQX markers (batch1_markers as dev-d's admin); every issued token registered before return."""
        proc = h.owner('python3', '-I', '-c', self.marker_program, 'emqx', 'read', input=b'{}', timeout=300)
        try:
            reply = json.loads(proc.stdout.decode('utf-8', 'replace').strip().splitlines()[-1])
        except (ValueError, IndexError):
            reply = {}
        issued = [value for value in reply.get('issued') or [] if isinstance(value, str)]
        self.secrets.register_issued(issued)
        self.observed.extend(issued)
        if proc.returncode or 'markers' not in reply or not issued:
            raise Failed('read-only marker probe failed')
        return reply['markers']

    def probe(self, request):
        """The b1 EMQX probe as HA's admin; each issued login value is registered before it is acknowledged."""
        recorder = b1.IssuedRecorder(self.secrets)
        try:
            return b1.event_device_python(b1.EMQX_PROBE, request, recorder, EMQX_AUTH, timeout=900)
        finally:
            self.observed.extend(recorder.values)

    def upload(self, path, ev):
        return h.upload(path, ev=ev)

    def scenario_cleanup(self, ev):
        h.scenario_cleanup(ev, None)


# ---------------------------------------------------------------- the run

class Run:
    def __init__(self, args, ev, dev, receipt=None, *, sleep=time.sleep, host=host_resources, src=None, package=None,
                 scan_text=None):
        self.args, self.ev, self.dev = args, ev, dev
        self.lease = args.lease_doc
        self.run_id = self.lease['run_id']
        self.secrets = args.secrets
        self.receipt = receipt or Receipt()
        self.sleep, self.host = sleep, host
        self.src = src                              # HA's x86 broker facts (b1-source summary), read when needed
        self.package = package or PackageSource(self.lease['package'])
        self.scan_text = scan_text
        self.lock_started = time.monotonic()
        self.started_wall = int(time.time()) - 1
        self.lease_expires = datetime.fromisoformat(self.lease['expires']).timestamp()
        self.older_ref = OLDER['name'] + '@' + self.lease['older_device_digest']
        self.changed = False
        self.facts_before = self.facts_imported = self.facts_older = self.markers_before = None
        self.timer_before = self.catalog_before = None
        self.templates = {}                         # the unit templates the deltas are judged by
        self.backups_before = self.ha_before = None
        self.jobs_before, self.jobs_recorded = set(), False
        self.ha_owned = None
        self.created_ha = None
        self.created = []
        self.capture_requested = self.captured = False
        self.staged = False
        self.import_requested = False
        self.chain_root = None
        self.chain = []
        self.view_import = self.view_older = self.view_after = None
        self.started_scripts, self.finished_scripts = [], []
        self.files_restored = False
        self.baseline_restored = False
        self.restored = False
        self.settled = True
        self.cleaned = False

    # -------- helpers
    def require(self, name, ok, detail=''):
        if not self.ev.check(name, ok, detail):
            raise Failed(name)

    def note(self, **changes):
        self.receipt.write(**changes)

    def budget(self, phase):
        if time.monotonic() - self.lock_started > HOLD_BUDGET:
            raise Failed(f'lock hold budget reached before {phase}')
        if time.time() > self.lease_expires - RECOVERY_RESERVE:
            raise Failed(f'the lease leaves too little time for {phase} and the recovery')

    def ok(self, command, request=None, timeout=1800):
        rc, reply = self.dev.helper(command, request, timeout=timeout)
        if rc != 0:
            raise Failed(f'{command} refused: {self.ev.redact((reply or {}).get("error"))}')
        return reply

    def wait(self, job_id, timeout=JOB_WAIT):
        deadline = time.monotonic() + timeout
        while True:
            reply = self.ok('job-status', {'job_id': job_id})
            job = reply['job']
            if job.get('state') not in ('queued', 'running'):
                self.ev.save(f'job-{job_id}.json', {'job': job, 'log': reply.get('log')})
                return job
            if time.monotonic() >= deadline:
                raise Failed(f'job {job_id} did not end in {timeout} s')
            self.sleep(3)

    def own(self, backup_id):
        if isinstance(backup_id, str) and backup_id and backup_id not in self.created:
            self.created.append(backup_id)
            self.note(created_backups=list(self.created))

    def facts(self, **request):
        request.setdefault('refs', [CURRENT['ref'], ENTRANCE['ref'], OLDER['name'], self.older_ref])
        request.setdefault('containers', list(CONTAINERS))
        request.setdefault('units', list(UNITS))
        return self.dev.op('facts', request, timeout=600)

    def kit(self):
        return self.secrets['DEV_D_KIT']

    def listing(self):
        reply = self.ok('list')
        return reply.get('backups') or [], reply.get('ha_backups') or []

    def source_facts(self):
        if self.src is None:
            self.src = b1.source('x86')['emqx']
        return self.src

    def probe_request(self):
        s = self.secrets
        users = [[s[f'B1_MQTT_USER{i}'], s[f'B1_MQTT_PW{i}']] for i in (1, 2, 3)]
        return {'ha_admin_password': s['B1_EMQX_ADMIN_PW'], 'user2': s['B1_EMQX_USER2'],
                'user2_password': s['B1_EMQX_USER2_PW'], 'mqtt': users, 'sensor': users[0], 'gateway': users[1],
                'api_key': s['B1_X86_EMQX_API_KEY'], 'api_secret': s['B1_X86_EMQX_API_SECRET']}

    def probe(self, name):
        ready = self.dev.op('ready', {'timeout': READY_TIMEOUT}, timeout=READY_TIMEOUT + 120)
        summary = self.dev.probe(self.probe_request()) if ready.get('ready') else {}
        self.ev.save(f'probe-{name}.json', summary)
        return ready, imported_view(summary)

    def save_output(self, result, name):
        self.ev.save(name, '\n'.join(str(line) for line in result.get('lines') or []) + '\n')

    def run_script(self, copy, timeout):
        """One copy's package script on the device (install.sh of the older copy, upgrade.sh of the upgrade copy)."""
        self.started_scripts.append(copy)
        self.note(started_scripts=list(self.started_scripts))     # before the call: a lost reply still stops it
        result = self.dev.op('script', {'copy': copy, 'timeout': timeout}, timeout=timeout + 240)
        self.finished_scripts.append(copy)
        self.note(finished_scripts=list(self.finished_scripts))
        self.save_output(result, f'{copy}-output.txt')
        verdict = judge_script(result)
        self.ev.save(f'{copy}-verdict.json', verdict)
        return result, verdict

    # -------- preflight (read-only: any failure stops the run before a change)
    def step_preflight(self):
        ev = self.ev
        self.require('preflight: dev-d runs with network none and no published port', self.dev.isolated())
        available, free = self.host()
        memory = self.dev.root_json(HEADROOM, {}, timeout=60)
        room = (memory.get('limit') or 0) - (memory.get('used') or 0) if isinstance(memory.get('limit'), int) else None
        self.require('preflight: host MemAvailable >= 1200 MiB, host disk keeps 13 GiB after the run, dev-d headroom >= 1900 MiB',
                     available >= MIN_HOST_AVAILABLE_KIB and free - RUN_WRITES >= FLOOR and room is not None
                     and room >= MIN_HEADROOM, {'mem_available_mib': available >> 10, 'free_gib': round(free / 1024 ** 3, 2),
                                                'headroom_mib': None if room is None else room >> 20})
        installed, tree = self.dev.root_json(ENGINE_HASHES, {}, timeout=300), tree_engine(self.lease['source'])
        differ = sorted(k for k in set(tree['lib']) | set(installed.get('lib') or {})
                        if tree['lib'].get(k) != (installed.get('lib') or {}).get(k))
        self.require('preflight: the installed engine is the leased product source (every module and the helper)',
                     not differ and installed.get('helper') == tree['helper'], {'modules': len(tree['lib']), 'differ': differ[:10]})
        scan_text = self.scan_text if self.scan_text is not None else scan_program()
        self.require('preflight: the leak scan is the reviewed program (snippets/focus-acceptance/r8-scan-rendered.py)',
                     SCAN_SNIPPET.is_file() and SCAN_SNIPPET.read_text(encoding='utf-8') == scan_text)
        status, timer = self.ok('status'), self.dev.timer()
        self.timer_before = timer
        self.require('preflight: no job is running on dev-d and its backup schedule timer is masked and inactive',
                     not status.get('active_job') and timer.get('UnitFileState') in ('masked', 'masked-runtime')
                     and timer.get('ActiveState') == 'inactive', {'timer': timer})
        app = next((row for row in status.get('apps') or [] if row.get('id') == APP), {})
        catalog = self.dev.root_json(CATALOG, {}, timeout=60)
        self.catalog_before = catalog
        self.require('preflight: the engine reports EMQX running without problems from its installed catalog entry',
                     app.get('state') == 'running' and not app.get('problems') and 'emqx.json' in catalog,
                     {'state': app.get('state'), 'problems': len(app.get('problems') or [])})
        facts = self.facts()
        self.facts_before = facts
        ev.save('facts-before.json', facts)
        images, containers, quadlet, units = facts['images'], facts['containers'], facts['quadlet'], facts['units']
        self.require('preflight: dev-d runs EMQX 5.8.9 from its own units: both Image= pins and both containers on the '
                     'recorded image IDs, units active',
                     quadlet['emqx.container']['image'] == CURRENT['ref'] and quadlet['emqx-entrance.container']['image']
                     == ENTRANCE['ref'] and (images.get(CURRENT['ref']) or {}).get('id') == CURRENT['image_id']
                     and (images.get(ENTRANCE['ref']) or {}).get('id') == ENTRANCE['image_id']
                     and containers['woow-emqx'].get('image_id') == CURRENT['image_id']
                     and containers['woow-emqx'].get('running')
                     and containers['woow-emqx-entrance'].get('image_id') == ENTRANCE['image_id']
                     and containers['woow-emqx-entrance'].get('running')
                     and units.get('emqx.service') == ['active', 'running']
                     and units.get('emqx-entrance.service') == ['active', 'running'],
                     {'quadlet': quadlet, 'containers': containers, 'units': units})
        older, by_digest = images.get(OLDER['name']) or {}, images.get(self.older_ref) or {}
        self.require('preflight: the older image emqx:5.8.8 is in dev-d\'s owner store with the pinned ID and the leased '
                     'digest (tag and digest resolve)',
                     older.get('present') and older.get('id') == OLDER['image_id']
                     and older.get('digest') == self.lease['older_device_digest']
                     and OLDER['name'] in (older.get('tags') or []) and by_digest.get('exists') is True
                     and by_digest.get('id') == OLDER['image_id'], {'image': older, 'by_digest': by_digest})
        smoke = hashlib.sha256(self.package.show(INSTALLED_COMMIT, 'tests/smoke.sh')).hexdigest()
        self.require('preflight: dev-d\'s own package copy is ea5886c (lab-source, its smoke.sh as in git), no run folder of '
                     'this run id yet', facts.get('lab_source') == INSTALLED_COMMIT
                     and (facts.get('package') or {}).get('smoke_sha256') == smoke and facts['run'].get('exists') is False,
                     {'lab_source': facts.get('lab_source'), 'package': facts.get('package'), 'run': facts['run']})
        self.markers_before = self.dev.markers()
        ev.save('markers-before.json', self.markers_before)
        self.require('preflight: dev-d\'s own EMQX holds its baseline markers and no HA import marker',
                     b1.marker_names(self.markers_before) == b1.BASELINE_MARKERS[APP] and facts['marker'].get('present') is False,
                     {'markers': sorted(b1.marker_names(self.markers_before)), 'marker': facts['marker']})
        pre = self.ok('inspect', {'backup_id': BASELINE, 'key': self.kit()})
        self.require('preflight: dev-d\'s EMQX baseline backup opens with the 11-19 kit and restores without a confirmation',
                     pre.get('ok') is True and pe.baseline_ready(pre.get('preflight') or {}))
        backups, ha = self.listing()
        risk = pe.safety_at_risk(backups, [])
        self.require('preflight: no unowned EMQX safety backup can be pruned by this run\'s two restores (keep 3 newest)',
                     not risk, {'at_risk': risk[:10]})
        try:
            self.ha_owned = pe.original_record_owned(ha, HA_ID, FIXTURE_SHA)
            fixture = True
        except ValueError:
            fixture = False
        self.require('preflight: the fixture\'s HA record is absent (uploaded by this run) or the protected one at the fixture '
                     'SHA-256', fixture, {'existing': self.ha_owned is False})
        self.backups_before = sorted(row.get('id') for row in backups)
        self.ha_before = sorted(row.get('id') for row in ha)
        self.jobs_before = {row.get('id') for row in self.ok('jobs').get('jobs') or []}
        self.jobs_recorded = True   # from here on every new job on dev-d is this run's (the lock is held)

    # -------- capture (the first change)
    def step_capture(self):
        self.changed = self.capture_requested = True
        self.note(schema=2, case=CASE, run_id=self.run_id, device=DEVICE, evidence=str(self.ev.dir),
                  driver_commit=self.lease['driver_commit'], source_commit=self.lease['source_commit'],
                  package_commit=PACKAGE_COMMIT, older=self.older_ref, current=CURRENT['ref'],
                  run_dir=f'~/woowbk-emqx-upgrade-{self.run_id}', capture_requested=True, staged=False,
                  ha_record_owned=self.ha_owned, created_ha_record=None, created_backups=[], import_requested=False,
                  import_root=None, started_scripts=[], finished_scripts=[], files_restored=False,
                  baseline_restored=False, restored=False, cleaned=False, complete=False)
        result = self.dev.op('capture', {}, timeout=300)
        self.captured = True
        self.require('capture: dev-d\'s installed EMQX files, env file and Quadlet state are copied privately inside dev-d '
                     '(equal to the read)', result.get('files') == self.facts_before['files']
                     and result.get('dirs') == self.facts_before['dirs'], {'files': len(result.get('files') or {})})

    # -------- the two throwaway package copies (c01c897, only their Image= lines repinned)
    def step_stage(self):
        files = self.package.files(PACKAGE_COMMIT)
        pins = {'older': {'quadlet/emqx.container': 'Image=' + self.older_ref,
                          'quadlet/emqx-entrance.container': 'Image=' + ENTRANCE['ref']},
                'upgrade': {'quadlet/emqx.container': 'Image=' + CURRENT['ref'],
                            'quadlet/emqx-entrance.container': 'Image=' + ENTRANCE['ref']}}
        staged, reports = {}, {}
        for copy, lines in pins.items():
            staged[copy], reports[copy] = repin(files, lines)
        self.templates = {'installed': self.package.show(INSTALLED_COMMIT, 'quadlet/emqx.container').decode('utf-8'),
                          'older': staged['older']['quadlet/emqx.container'][0].decode('utf-8'),
                          'upgrade': staged['upgrade']['quadlet/emqx.container'][0].decode('utf-8')}
        self.ev.save('stage-repin.json', reports)
        self.require('stage: two copies of c01c897, each with only its Image= lines repinned (older: 5.8.8, upgrade: '
                     '5.8.9) at dev-d\'s digests', all(repin_exact(files, staged[copy], pins[copy]) and len(staged[copy])
                                                     == len(files) for copy in pins), reports)
        self.staged = True
        self.note(staged=True)
        results = {}
        for copy in pins:
            tar_b64, expected = pack(staged[copy])
            reply = self.dev.op('stage', {'copy': copy, 'tar_b64': tar_b64, 'files': expected}, timeout=300)
            results[copy] = reply.get('equal') is True and reply.get('files') == len(expected)
        self.require('stage: both copies are in place inside dev-d, every file equal to its staged tree', all(results.values()),
                     results)

    # -------- the HA import through the product, on dev-d's own 5.8.9 (the version the product requires)
    def step_import(self):
        ev = self.ev
        if self.ha_owned:
            rc, reply = self.dev.upload(FIXTURE, ev)
            meta = (reply or {}).get('ha_backup') or {}
            if meta.get('id') == HA_ID:
                self.created_ha = HA_ID
                self.note(created_ha_record=HA_ID)
            uploaded = rc == 0 and meta.get('id') == HA_ID
        else:
            uploaded = HA_ID in {row.get('id') for row in self.listing()[1]}
        self.require('import: the HA record of the real x86 cold EMQX backup is in dev-d\'s store (uploaded now or the '
                     'protected one)', uploaded, {'uploaded_by_this_run': bool(self.ha_owned)})
        key = self.secrets['HA_BACKUP_KEY']
        rid = request_id(self.run_id, 'check')
        self.note(check_request_id=rid)
        started = self.ok('ha-check-start', {'ha_backup_id': HA_ID, 'apps': [APP], 'request_id': rid, 'key': key}, timeout=300)
        check = self.wait(started['job_id'])
        try:
            expected, section = pe.check_accepted(check, HA_ID)
        except ValueError as error:
            expected, section = None, str(error)
        ev.save('check-emqx.json', {'section': section, 'expected_acknowledged': expected})
        self.require('import: the check calls EMQX importable, nothing stops it, every confirmation line keyed',
                     expected is not None, {'refusal': None if expected is not None else section})
        rid = request_id(self.run_id, 'import')
        self.import_requested = True
        self.note(import_requested=True, import_request_id=rid)
        started = self.ok('ha-import-start', {'ha_backup_id': HA_ID, 'apps': [APP], 'request_id': rid, 'confirm': True,
                                              'test_mode': False, 'then_restore': True, 'overwrite': True,
                                              'check_job_id': check['id'], 'key': key, 'acknowledged': expected},
                          timeout=300)
        self.chain_root = started.get('job_id')
        self.note(import_root=self.chain_root)
        self.chain = self.follow(self.chain_root)
        params = (self.chain[0].get('params') or {}) if self.chain else {}
        self.require('import: one EMQX conversion and its restore succeeded as two linked jobs, every listed key acknowledged '
                     'once', pe.chain_complete(self.chain, HA_ID) and pe.acknowledged_exactly(expected, params, expected),
                     {'jobs': [j.get('id') for j in self.chain], 'states': [j.get('state') for j in self.chain]})
        result = self.chain[-1].get('result') or {}
        self.require('import: the restore made its own safety backup and was not rolled back',
                     isinstance(result.get('safety_backup_id'), str) and result.get('rolled_back') is False,
                     {'rolled_back': result.get('rolled_back'), 'warnings': len(result.get('warnings') or [])})
        facts = self.facts()
        self.facts_imported = facts
        ev.save('facts-imported.json', facts)
        self.require('import: the HA import marker woow-ha-import.json is in the data volume with its fixed content',
                     facts['marker'].get('present') is True and facts['marker'].get('exact') is True, facts['marker'])
        self.require('import: dev-d\'s EMQX Quadlets, config and env files and Quadlet state are byte for byte as before '
                     '(HA\'s settings live in the data volume)', facts['files'] == self.facts_before['files']
                     and facts['dirs'] == self.facts_before['dirs'] and facts['manifest'] == self.facts_before['manifest']
                     and facts['quadlet'] == self.facts_before['quadlet'],
                     {'changed': file_changes(self.facts_before['files'], facts['files'])})
        ready, view = self.probe('imported')
        self.view_import = view
        src = self.source_facts()
        self.require('import: EMQX serves HA\'s data: Dashboard users, MQTT users, retained messages, rules, banned client, '
                     'API key', ready.get('ready') is True and ha_data_ok(view, src), {'ready': ready, 'accounts': view['accounts'],
                                                                                     'data': view['data']})
        self.require('import: MQTT as HA: HA\'s users and the bootstrap user log in, retained delivered, anonymous, wrong '
                     'password and banned client refused', ha_mqtt_ok(view, src), view['mqtt'])
        self.require('import: it ran on 5.8.9 from dev-d\'s own units (node version, container image ID, Image=)',
                     node_version(view) == [CURRENT['version']] and view['node']['started']
                     and facts['containers']['woow-emqx'].get('image_id') == CURRENT['image_id']
                     and facts['quadlet']['emqx.container']['image'] == CURRENT['ref'], {'node': view['node']})

    def follow(self, root, timeout=JOB_WAIT):
        """The import's linked jobs from its root (at most two), each waited for; what they made is owned."""
        records, current, seen = [], root, set()
        while current and len(records) < 2:
            if current in seen:
                raise Failed('a job of the import came back')
            seen.add(current)
            job = self.wait(current, timeout)
            records.append(job)
            result = job.get('result') or {}
            self.own(result.get('backup_id') if job.get('type') == 'backup' else result.get('safety_backup_id'))
            current = (result.get('group') or {}).get('next_job_id')
        if current:
            raise Failed('the import has more than two jobs')
        self.note(chain_job_ids=[job.get('id') for job in records])
        return records

    # -------- the package's installer puts dev-d's EMQX on the older open-source 5.8.8 (the imported data stays)
    def step_older(self):
        ev = self.ev
        result, verdict = self.run_script('older', INSTALL_TIMEOUT)
        checks = [
            ev.check('older: the older copy\'s scripts/install.sh ran as appowner, exited 0 in time and says installed and '
                     'healthy', verdict['exit_zero'] and verdict['complete'],
                     {'rc': verdict['rc'], 'timed_out': verdict['timed_out'], 'seconds': verdict['seconds']}),
            ev.check('older: its smoke.sh lines are the imported set (A4 and A5/A6/A10 WARN, 11 PASS, 0 FAIL)',
                     verdict['smoke_exact'], {'rows': verdict['rows'], 'summaries': verdict['summaries']}),
            ev.check('older: no dev-d EMQX secret value in the installer output', verdict['secret_free'],
                     {'hits': result.get('device_secret_hits'), 'truncated': result.get('truncated')})]
        facts = self.facts()
        self.facts_older = facts
        ev.save('facts-older.json', facts)
        containers, quadlet, units = facts['containers'], facts['quadlet'], facts['units']
        checks.append(ev.check(
            'older: the broker runs the 5.8.8 image ID from the older emqx.container, the entrance unchanged, units active',
            containers['woow-emqx'].get('image_id') == OLDER['image_id'] and containers['woow-emqx'].get('running')
            and quadlet['emqx.container']['image'] == self.older_ref
            and containers['woow-emqx-entrance'].get('image_id') == ENTRANCE['image_id']
            and quadlet['emqx-entrance.container']['image'] == ENTRANCE['ref']
            and units.get('emqx.service') == ['active', 'running'] and units.get('emqx-entrance.service') == ['active', 'running'],
            {'containers': containers, 'quadlet': quadlet, 'units': units}))
        base = self.facts_imported
        changed, added, removed = file_changes(base['files'], facts['files'])
        want = ops.line_delta(pinned(self.templates['installed'], 'Image=' + CURRENT['ref']), self.templates['older'])
        delta = unit_delta(base.get('quadlet_text'), facts.get('quadlet_text'))
        checks.append(ev.check(
            'older: only emqx.container (template diff ea5886c to c01c897, two pins) and the Quadlet manifest changed, '
            'no backup folder, marker kept', changed == EXPECTED_CHANGED and not added and not removed and delta == want
            and manifest_follows(base['manifest'], facts['manifest'], facts['files']) and facts['dirs'] == base['dirs']
            and facts.get('backup_root') == base.get('backup_root') and facts['marker'].get('present') is True
            and facts['marker'].get('exact') is True,
            {'changed': changed, 'added': added, 'removed': removed, 'delta': delta, 'expected_delta': want}))
        ready, view = self.probe('older')
        self.view_older = view
        checks.append(ev.check(
            'older: the 5.8.8 broker serves exactly what 5.8.9 served after the import (accounts, ACL, data, MQTT)',
            ready.get('ready') is True and node_version(view) == [OLDER['version']] and view['node']['started']
            and all(view[group] == self.view_import[group] for group in ('accounts', 'data', 'mqtt')),
            {'ready': ready, 'node': view['node'],
             'differ': [group for group in ('accounts', 'data', 'mqtt') if view[group] != self.view_import[group]]}))
        if not all(checks):
            raise Failed('the older version is not in place')

    # -------- the package's own upgrade back to the version it pins (5.8.9)
    def step_upgrade(self):
        ev = self.ev
        result, verdict = self.run_script('upgrade', UPGRADE_TIMEOUT)
        checks = [
            ev.check('upgrade: the upgrade copy\'s scripts/upgrade.sh ran as appowner and exited 0 within its time',
                     verdict['exit_zero'], {'rc': verdict['rc'], 'timed_out': verdict['timed_out'], 'seconds': verdict['seconds']}),
            ev.check('upgrade: it was not rolled back (upgrade complete reported, no rollback line)', verdict['complete'],
                     {'rolled_back': verdict['rolled_back'], 'snapshot': verdict['snapshot']}),
            ev.check('upgrade: its smoke.sh lines are exactly the imported set: A4 and A5/A6/A10 WARN, 11 PASS, 0 FAIL',
                     verdict['smoke_exact'], {'rows': verdict['rows'], 'summaries': verdict['summaries']}),
            ev.check('upgrade: no dev-d EMQX secret value in the upgrade output', verdict['secret_free'],
                     {'hits': result.get('device_secret_hits'), 'truncated': result.get('truncated')})]
        facts = self.facts()
        ev.save('facts-upgraded.json', facts)
        containers, quadlet, units = facts['containers'], facts['quadlet'], facts['units']
        base = self.facts_older
        checks.append(ev.check(
            'upgrade: the container moved from the 5.8.8 image ID to the 5.8.9 one from the new emqx.container, units active',
            base['containers']['woow-emqx'].get('image_id') == OLDER['image_id']
            and containers['woow-emqx'].get('image_id') == CURRENT['image_id'] and containers['woow-emqx'].get('running')
            and quadlet['emqx.container']['image'] == CURRENT['ref']
            and containers['woow-emqx-entrance'].get('image_id') == ENTRANCE['image_id']
            and units.get('emqx.service') == ['active', 'running'] and units.get('emqx-entrance.service') == ['active', 'running'],
            {'containers': containers, 'quadlet': quadlet, 'units': units}))
        changed, added, removed = file_changes(base['files'], facts['files'])
        want = ops.line_delta(self.templates['older'], self.templates['upgrade'])
        delta = unit_delta(base.get('quadlet_text'), facts.get('quadlet_text'))
        checks.append(ev.check(
            'upgrade: only emqx.container\'s Image= line (5.8.8 to 5.8.9) and the Quadlet manifest changed, all else byte for byte',
            changed == EXPECTED_CHANGED and not added and not removed and delta == want
            and want == {'removed': ['Image=' + self.older_ref], 'added': ['Image=' + CURRENT['ref']]}
            and manifest_follows(base['manifest'], facts['manifest'], facts['files']) and facts['dirs'] == base['dirs'],
            {'changed': changed, 'added': added, 'removed': removed, 'delta': delta}))
        before = {row[0] for row in base.get('backup_root') or []}
        now = {row[0]: row[1] for row in facts.get('backup_root') or []}
        new = sorted(set(now) - before)
        checks.append(ev.check(
            'upgrade: its pre-upgrade backup and unit snapshot are the only new folders under the package backup root',
            verdict['snapshot'] is not None and verdict['data_backup'] is not None
            and new == sorted([verdict['snapshot'], verdict['data_backup']]) and all(now[name] == 'dir' for name in new),
            {'new': new, 'snapshot': verdict['snapshot'], 'data_backup': verdict['data_backup']}))
        checks.append(ev.check('upgrade: the HA import marker is still in the data volume',
                               facts['marker'].get('present') is True and facts['marker'].get('exact') is True, facts['marker']))
        if not all(checks):
            raise Failed('the upgrade did not pass')

    def step_after_upgrade(self):
        ready, view = self.probe('upgraded')
        self.view_after = view
        before = self.view_older
        names = lambda v: [n[0] for n in v['node'].get('nodes') or [] if isinstance(n, list) and n]   # noqa: E731
        checks = [
            self.ev.check('after upgrade: the node reports EMQX 5.8.9 (was 5.8.8), the same node name, started',
                          ready.get('ready') is True and node_version(view) == [CURRENT['version']]
                          and node_version(before) == [OLDER['version']] and names(view) == names(before) == [NODE]
                          and view['node']['started'], {'ready': ready, 'node': view['node']}),
            self.ev.check('after upgrade: Dashboard and MQTT accounts, authenticators, authorization settings, sources and ACL '
                          'rows exactly as before it', view['accounts'] == before['accounts'],
                          {'after': view['accounts'], 'before': before['accounts']}),
            self.ev.check('after upgrade: retained messages, rules, connectors, actions, banned clients and API keys exactly as '
                          'before it', view['data'] == before['data'], {'after': view['data'], 'before': before['data']}),
            self.ev.check('after upgrade: MQTT behaves as before it (logins, retained delivery, ACL deny, refusals)',
                          view['mqtt'] == before['mqtt'], {'after': view['mqtt'], 'before': before['mqtt']})]
        if not all(checks):
            raise Failed('the upgraded broker does not serve the imported data')

    # -------- recovery: whatever stopped the run, dev-d's own EMQX back on its own 5.8.9 units and data
    def new_jobs(self):
        return [row for row in self.ok('jobs').get('jobs') or [] if row.get('id') not in self.jobs_before]

    def settle(self):
        deadline = time.monotonic() + JOB_WAIT
        for row in self.new_jobs():
            if row.get('state') in ('queued', 'running'):
                self.wait(row['id'], max(1, int(deadline - time.monotonic())))
        rows = self.new_jobs()
        root = self.chain_root or next((row.get('id') for row in rows if row.get('type') == 'backup'
                                        and (row.get('params') or {}).get('source') == 'ha'
                                        and (row.get('params') or {}).get('ha_backup_id') == HA_ID), None)
        if root and not self.chain:
            self.chain_root = root
            self.note(import_root=root)
            self.chain = self.follow(root, max(1, int(deadline - time.monotonic())))

    def recover(self):
        ev = self.ev
        if self.started_scripts:
            try:
                stop = self.dev.op('stop-scripts', {}, timeout=180)
                ok = stop.get('running') is False
            except (Failed, OSError, subprocess.TimeoutExpired, ValueError) as error:
                stop, ok = {'error': type(error).__name__}, False
            ev.check('recovery: no package script of this run is running (stopped when a stop came during it)', ok, stop)
            if not ok:
                self.settled = False
                return
            for copy in self.started_scripts:
                if copy in self.finished_scripts:
                    continue
                try:
                    self.save_output(self.dev.op('script-log', {'copy': copy}, timeout=180), f'{copy}-output-recovered.txt')
                except (Failed, OSError, subprocess.TimeoutExpired, ValueError):
                    ev.log(f'the interrupted {copy} script left no readable output')
        if self.jobs_recorded:
            try:
                self.settle()
                ok, detail = True, {'chain': [job.get('id') for job in self.chain]}
            except (Failed, OSError, subprocess.TimeoutExpired, ValueError) as error:
                ok, detail = False, str(error)[:200]
            ev.check('recovery: every job of this run has ended (otherwise everything stays for the coordinator)', ok, detail)
            if not ok:
                self.settled = False
                return
        self.restore_files()
        if self.import_requested or self.started_scripts:
            self.restore_baseline()
        self.verify_restored()

    def restore_files(self):
        name = ('recovery: dev-d\'s installed EMQX files, env file and Quadlet state are byte for byte as captured '
                '(daemon-reload done)')
        try:
            state = {} if self.captured else (self.dev.op('facts', {'refs': [], 'containers': [], 'units': []},
                                                         timeout=600).get('run') or {})
            if self.captured or state.get('capture'):
                result = self.dev.op('restore-files', {}, timeout=300)
                ok = (result.get('equal') is True and result.get('reload_rc') == 0
                      and result.get('files') == self.facts_before['files'] and result.get('dirs') == self.facts_before['dirs'])
                detail = {'written': result.get('written'), 'removed': result.get('removed')}
            else:   # the capture never finished: nothing of the EMQX files was changed by this run
                now = self.facts()
                ok = now['files'] == self.facts_before['files'] and now['dirs'] == self.facts_before['dirs']
                detail = {'capture': False}
        except (Failed, OSError, subprocess.TimeoutExpired, ValueError, KeyError) as error:
            ok, detail = False, {'error': type(error).__name__}
        self.files_restored = ok
        self.note(files_restored=ok)
        self.ev.check(name, ok, detail)

    def restore_baseline(self):
        name = 'recovery: the baseline restore of dev-d\'s EMQX succeeded with the 11-19 kit (own 5.8.9 units, not rolled back)'
        try:
            pre = self.ok('inspect', {'backup_id': BASELINE, 'key': self.kit()})
            if not (pre.get('ok') is True and pe.baseline_ready(pre.get('preflight') or {})):
                raise Failed('the baseline restore would need a confirmation')
            rid = request_id(self.run_id, 'baseline')
            self.note(baseline_request_id=rid)
            started = self.ok('restore-start', {'backup_id': BASELINE, 'apps': [APP], 'confirm': True, 'key': self.kit(),
                                                'request_id': rid}, timeout=300)
            self.note(baseline_job=started.get('job_id'))
            job = self.wait(started['job_id'])
            result = job.get('result') or {}
            self.own(result.get('safety_backup_id'))
            ok = job.get('state') == 'succeeded' and result.get('rolled_back') is False
            detail = {'state': job.get('state'), 'rolled_back': result.get('rolled_back')}
        except (Failed, OSError, subprocess.TimeoutExpired, ValueError, KeyError) as error:
            ok, detail = False, {'error': type(error).__name__}
        self.baseline_restored = ok
        self.note(baseline_restored=ok)
        self.ev.check(name, ok, detail)

    def verify_restored(self):
        ev = self.ev
        results = []
        try:
            ready = self.dev.op('ready', {'timeout': READY_TIMEOUT}, timeout=READY_TIMEOUT + 120)
            facts = self.facts()
            ev.save('facts-restored.json', facts)
            before = self.facts_before
            results.append(ev.check(
                'recovery: dev-d runs EMQX 5.8.9 again from its own units (container image IDs, Image= lines, units as before)',
                ready.get('ready') is True and facts['containers'] == before['containers']
                and facts['quadlet'] == before['quadlet'] and facts['units'] == before['units'],
                {'ready': ready, 'containers': facts['containers'], 'units': facts['units']}))
            markers = self.dev.markers()
            ev.save('markers-restored.json', markers)
            results.append(ev.check('recovery: dev-d\'s own EMQX markers are back exactly and the import marker is gone',
                                    markers == self.markers_before and facts['marker'].get('present') is False,
                                    {'markers': sorted(b1.marker_names(markers)), 'marker': facts['marker']}))
            smoke = self.dev.op('smoke', {'timeout': SMOKE_TIMEOUT}, timeout=SMOKE_TIMEOUT + 120)
            self.save_output(smoke, 'smoke-restored.txt')
            passed, detail = judge_restore_smoke(smoke)
            results.append(ev.check('recovery: dev-d\'s own package smoke.sh --quick passes (10 PASS, 0 FAIL, 0 WARN)',
                                    passed, detail))
        except (Failed, OSError, subprocess.TimeoutExpired, ValueError, KeyError) as error:
            results.append(ev.check(f'recovery: the restored state could not be read ({type(error).__name__})', False,
                                    str(error)[:200]))
        data_needed = self.import_requested or bool(self.started_scripts)
        self.restored = (self.files_restored and (self.baseline_restored or not data_needed) and len(results) == 3
                         and all(results))
        self.note(restored=self.restored)

    # -------- cleanup: only what this run made (each part on its own)
    def cleanup(self):
        for part in (self.cleanup_backups, self.cleanup_ha, self.cleanup_device, lambda: self.dev.scenario_cleanup(self.ev)):
            try:
                part()
            except Exception as error:   # noqa: BLE001 - reported; the next part still runs
                self.ev.check(f'cleanup: failed ({type(error).__name__})', False, str(error)[:300])

    def cleanup_backups(self):
        name = 'cleanup: every backup this run made is deleted (the conversion and the two safety backups)'
        if not self.restored:
            self.ev.check(name, False, {'kept_for_the_coordinator': list(self.created)})
            return
        for backup_id in list(self.created):
            rc, _reply = self.dev.helper('delete', {'backup_id': backup_id})
            self.ev.log(f'delete {backup_id}: rc {rc}')
        left = sorted({row.get('id') for row in self.listing()[0]} & set(self.created))
        self.created = left
        self.note(created_backups=list(left))
        self.ev.check(name, not left, {'left': left})

    def cleanup_ha(self):
        backups, ha = self.listing()
        if HA_ID not in (self.ha_before or []) and HA_ID in {row.get('id') for row in ha}:
            self.created_ha = HA_ID
        if self.created_ha and not self.ok('status').get('active_job'):
            rc, _reply = self.dev.helper('ha-delete', {'ha_backup_id': self.created_ha, 'confirm': True})
            self.ev.log(f'ha-delete {self.created_ha}: rc {rc}')
            ha = self.listing()[1]
        now = sorted(row.get('id') for row in ha)
        if self.created_ha not in now:
            self.created_ha = None
        self.note(created_ha_record=self.created_ha)
        self.ev.check('cleanup: the HA records are as before (the one this run uploaded is deleted)', now == self.ha_before,
                      {'left': self.created_ha})

    def cleanup_device(self):
        name = ('cleanup: the package backup folders of this run and the private run folder (copies, throwaway packages) are '
                'removed inside dev-d')
        if not self.restored or not self.settled:
            self.ev.check(name, False, {'kept_for_the_coordinator': f'~/woowbk-emqx-upgrade-{self.run_id}'})
            return
        result = self.dev.op('cleanup', {'backup_root_before': self.facts_before.get('backup_root'),
                                         'backup_parent_before': self.facts_before.get('backup_parent'),
                                         'remove_run_dir': True}, timeout=300)
        ok = (not result.get('unexplained') and result.get('run_dir_removed') is True
              and result.get('backup_root') == self.facts_before.get('backup_root')
              and result.get('backup_parent') == self.facts_before.get('backup_parent'))
        self.cleaned = ok
        self.note(cleaned=ok)
        self.ev.check(name, ok, {'removed': result.get('removed'), 'unexplained': result.get('unexplained')})

    # -------- leaks
    def leaks(self):
        for part in (self.leaks_device, self.leaks_tokens, self.leaks_evidence):
            try:
                part()
            except Exception as error:   # noqa: BLE001 - a scan that cannot run fails, the next one still runs
                self.ev.check(f'leaks: scan failed ({type(error).__name__})', False, str(error)[:300])

    def leaks_device(self):
        report = self.dev.root_json(scan_program(), {'values': self.secrets.secret_values(), 'since': self.started_wall,
                                                     'podman_secrets': list(PODMAN_SECRETS)}, timeout=900)
        sidecars = self.dev.root_json(SIDECARS, {}, timeout=120)
        self.ev.save('leaks.json', report)
        self.ev.check('leaks: no registered value nor dev-d EMQX secret in the engine records, uploads, staging and the device '
                      'journal since the start', report.get('hits') == 0 and report.get('scanned', 0) > 0
                      and report.get('regular_json_roots_scanned') == 2
                      and report.get('archive_index_sidecars_scanned') == sidecars,
                      {'scanned': report.get('scanned'), 'journal_bytes': report.get('journal_bytes'), 'sidecars': sidecars})

    def leaks_tokens(self):
        known = set(self.secrets.secret_values())
        tokens = list(dict.fromkeys(getattr(self.dev, 'observed', [])))
        self.ev.check('leaks: every issued Dashboard token of this run was registered before any output was saved',
                      bool(tokens) and all(token in known for token in tokens), {'tokens': len(tokens)})

    def leaks_evidence(self):
        values = [value for value in self.secrets.secret_values() if isinstance(value, str) and len(value) >= 6]
        found = scan_evidence(self.ev.dir, values)
        self.ev.check('leaks: no registered value in this run\'s private evidence', found['hits'] == 0 and found['files'] > 0,
                      {'files': found['files'], 'values': len(values), 'hits': found['hits']})

    # -------- after
    def after(self):
        ev = self.ev
        ev.check('after: dev-d still runs with network none and no published port', self.dev.isolated())
        if not self.changed:
            return
        backups, ha = self.listing()
        now = sorted(row.get('id') for row in backups)
        ev.check('after: dev-d\'s backups and HA records are exactly the ones it had before',
                 now == self.backups_before and sorted(row.get('id') for row in ha) == self.ha_before,
                 {'new': sorted(set(now) - set(self.backups_before or [])),
                  'gone': sorted(set(self.backups_before or []) - set(now))})
        facts = self.facts()
        keys = ('image_list', 'container_names', 'secrets', 'volumes', 'units', 'containers', 'quadlet', 'quadlet_text',
                'files', 'dirs', 'manifest', 'package', 'lab_source', 'backup_root', 'backup_parent')
        differ = [key for key in keys if facts.get(key) != self.facts_before.get(key)]
        timer = self.dev.timer()
        ev.check('after: images, containers, EMQX secrets and volumes, units, EMQX files, dev-d\'s package copy and timer as '
                 'before, no job running', not differ and timer == self.timer_before and not facts['run'].get('exists')
                 and not self.ok('status').get('active_job') and self.dev.root_json(CATALOG, {}, timeout=60) == self.catalog_before,
                 {'differ': differ, 'run_dir_left': facts['run'].get('exists')})

    def finish_receipt(self):
        if not self.changed:
            return
        complete = (self.restored and not self.created and not self.created_ha and self.cleaned and self.settled)
        self.note(restored=self.restored, complete=complete, signals_ignored=SIGNALS['ignored'])


def run_all(run):
    """The forward phases, then -- whatever stopped them -- recovery, cleanup, leak scans and the after checks."""
    ev = run.ev
    steps = (('preflight', run.step_preflight), ('capture', run.step_capture), ('stage', run.step_stage),
             ('import', run.step_import), ('older', run.step_older), ('upgrade', run.step_upgrade),
             ('after upgrade', run.step_after_upgrade))
    failed = None
    try:
        for name, step in steps:
            run.budget(name)
            ev.log(f'== {name}')
            step()
    except (Exception, Stopped) as error:   # noqa: BLE001 - any stop: the recovery runs
        SIGNALS['recovering'] = True
        failed = error
        ev.check(f'run stopped in a step ({type(error).__name__})', False, str(error)[:300])
    finally:
        SIGNALS['recovering'] = True
        parts = ((('recovery', run.recover), ('cleanup', run.cleanup), ('leaks', run.leaks)) if run.changed else ())
        for name, part in parts + (('after', run.after),):
            try:
                ev.log(f'== {name}')
                part()
            except (Exception, Stopped) as error:   # noqa: BLE001 - reported; the next part still runs
                ev.check(f'{name}: failed ({type(error).__name__})', False, str(error)[:300])
        run.finish_receipt()
    return failed is None


# ---------------------------------------------------------------- offline self-check

def self_check():
    compile(DEVICE_PROGRAM, '<emqx upgrade device program>', 'exec')
    for program in (HEADROOM, ENGINE_HASHES, CATALOG, SIDECARS):
        compile(program, '<device program>', 'exec')
    assert len(DEVICE_PROGRAM.encode()) < 120 * 1024          # one argv string (MAX_ARG_STRLEN 128 KiB)
    assert HA_ID == 'ha-0a53e93888209316040a' and SHA.fullmatch(FIXTURE_SHA)
    assert all(SHA.fullmatch(x) for x in (OLDER['image_id'], CURRENT['image_id'], ENTRANCE['image_id']))
    assert all(DIGEST.fullmatch(x) for x in (OLDER['index_digest'], OLDER['amd64_manifest']))
    assert OLDER['name'].startswith('docker.io/emqx/emqx:5.8.') and CURRENT['ref'].startswith('docker.io/emqx/emqx:5.8.9@')
    assert COMMIT.fullmatch(PACKAGE_COMMIT) and COMMIT.fullmatch(INSTALLED_COMMIT)
    assert sum(IMPORTED_SMOKE.values()) == 13 and sum(RESTORE_SMOKE.values()) == 10
    assert all(len(label(name)) == len(name) for name in (
        'upgrade: its smoke.sh lines are exactly the imported set: A4 and A5/A6/A10 WARN, 11 PASS, 0 FAIL',
        'recovery: dev-d\'s own package smoke.sh --quick passes (10 PASS, 0 FAIL, 0 WARN)'))
    print('self-check: PASS')
    return 0


# ---------------------------------------------------------------- command line

def load_secrets():
    folder = LAB / 'secrets'
    secrets = b1.Secrets([folder / 'b1-creds.env', folder / 'ha-import-creds.env'], folder / 'dev-d-markers.json')
    secrets.register('DEV_D_KIT', (folder / 'dev-d-kit.txt').read_text(encoding='utf-8').strip())
    return secrets


def admission(args, *, environ=os.environ, receipt=None, now=None):
    """Before the lock, the secrets or the device: [(label, ok)] of what must hold for a run to start."""
    now = time.time() if now is None else now
    found = []
    found.append(('admission: the heavy seat (HEAVY_FREE is the dev-d lock: run through heavy.sh)',
                  environ.get('HEAVY_FREE') == LOCK))
    lease, driver = None, git_text(REPO, 'rev-parse', 'HEAD')
    try:
        path = Path(args.lease)
        if path.is_symlink() or not path.is_file() or path.stat().st_uid != os.getuid():
            raise ValueError('lease file')
        lease = validate_lease(json.loads(path.read_bytes()), driver_commit=driver, now=now)
    except (TypeError, ValueError, OSError):
        lease = None
    found.append(('admission: the lease is granted for this case, run id, driver, product source, package, target image '
                  'and window', lease is not None))
    if lease is not None:
        package = PackageSource(lease['package'])
        clean = (guard.clean_tree(REPO)[0] and git_text(lease['source'], 'rev-parse', 'HEAD') == lease['source_commit']
                 and not (git(lease['source'], 'status', '--porcelain', '--untracked-files=no')[1] or b'').strip()
                 and package.head() == PACKAGE_COMMIT and package.clean()
                 and git(lease['package'], 'cat-file', '-e', INSTALLED_COMMIT + '^{commit}')[0] == 0)
        found.append(('admission: this checkout, the product source and the package checkout are clean and at the leased '
                      'commits', clean))
        raw = IMAGE_RECEIPT.read_bytes() if private_file(IMAGE_RECEIPT) else b''
        found.append(('admission: the private image receipt matches the lease (pinned image loaded at the leased digest)',
                      image_receipt_ok(raw, lease)))
    found.append(('admission: no earlier run of this case is pending', not (receipt or Receipt()).pending()))
    sha = sha256_file(FIXTURE) if FIXTURE.is_file() and not FIXTURE.is_symlink() else None
    found.append(('admission: the fixture is the recorded real x86 cold EMQX HA backup', sha == FIXTURE_SHA))
    return found, lease


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--run', action='store_true')
    parser.add_argument('--lease', type=Path)
    parser.add_argument('--lease-template', action='store_true')
    parser.add_argument('--source', type=Path)
    parser.add_argument('--package', type=Path)
    parser.add_argument('--minutes', type=int, default=150)
    args = parser.parse_args(argv)
    if args.lease_template:
        if not args.source or not args.package:
            parser.error('--lease-template needs --source and --package')
        raw = IMAGE_RECEIPT.read_bytes() if private_file(IMAGE_RECEIPT) else b''
        doc = json.loads(raw) if raw else {}
        template = lease_template(driver_commit=git_text(REPO, 'rev-parse', 'HEAD'), source=args.source.resolve(),
                                  source_commit=git_text(args.source, 'rev-parse', 'HEAD'), package=args.package.resolve(),
                                  receipt_sha=hashlib.sha256(raw).hexdigest() if raw else None,
                                  run_id=os.urandom(6).hex(), minutes=args.minutes)
        template['older_device_digest'] = doc.get('device_digest')
        print(json.dumps(template, indent=1))
        return 0
    if not args.run:
        return self_check()
    refused, lease = admission(args)
    refused = [name for name, ok in refused if not ok]
    if refused:
        for name in refused:
            emit(f'{label(name)}: FAIL')
        return 2
    try:
        secrets = load_secrets()
        missing = [name for name in NEEDED if name not in secrets.values
                   or len(secrets.values.get(name) or '') < (16 if name == 'HA_BACKUP_KEY' else 1 if name in secrets.names else 6)]
    except (OSError, UnicodeDecodeError, ValueError, Failed):
        missing = ['unreadable']
    if missing:   # never a value
        emit(f'{label("admission: the test credential files name every value the run and its leak scan need")}: FAIL')
        return 2
    secrets.redact_tree = secrets.redact_structure
    args.secrets, args.lease_doc = secrets, lease
    emit(f'source commit {lease["driver_commit"]}')
    try:
        fd, waited = guard.acquire(timeout=LOCK_WAIT)
    except guard.GuardError:
        emit('lock: FAIL')
        return 3
    previous = {signum: signal.signal(signum, _stop) for signum in (signal.SIGTERM, signal.SIGINT)}
    ok, passed, ev = False, False, None
    try:
        ev = Ev(secrets)
        ev.save('run.json', {'driver_commit': lease['driver_commit'], 'source_commit': lease['source_commit'],
                             'package_commit': PACKAGE_COMMIT, 'older': OLDER, 'current': CURRENT, 'run_id': lease['run_id'],
                             'lock_waited_s': waited, 'commercial_acceptance': 'not-complete'})
        run = Run(args, ev, LabDevice(secrets, lease['run_id']))
        try:
            ok = run_all(run)
        finally:
            emit(f'lock held for {int(time.monotonic() - run.lock_started)} s')
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
        SIGNALS['recovering'] = False
        os.close(fd)
    if ev is not None:
        passed = ev.finish()
        results = ev.results
        emit(f'emqx upgrade after import: {sum(r["ok"] for r in results)}/{len(results)} {"PASS" if ok and passed else "FAIL"}')
    return 0 if ok and passed else 1


if __name__ == '__main__':
    sys.exit(main())
