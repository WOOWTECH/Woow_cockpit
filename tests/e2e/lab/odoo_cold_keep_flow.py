#!/usr/bin/env python3
"""Odoo cold keep: the real x86 encrypted Odoo+n8n HA backup (woow-import-test-enc, 2026-11-18) -> dev-c's Odoo on the
documented SUBSTITUTE images, with one extra database in its cluster, through the product's one-action HA import with the
database choice woowtest2 (first real runs 2026-11-26 from scratchpad scripts, 37/37; this is the repo driver).

  python3 -I tests/e2e/lab/odoo_cold_keep_flow.py                     offline self-check (no device, no secret)
  HEAVY_FREE=/tmp/woowbk-dev-c-mutation.lock .../heavy.sh python3 -B -I tests/e2e/lab/services_a_capture.py \\
      --private=FILE <evidence.json> odoo-cold-keep-page -- \\
      python3 -B -I tests/e2e/lab/odoo_cold_keep_flow.py --run --via-page [--source PRODUCT]
  ... odoo_cold_keep_flow.py --run [--source PRODUCT]                 (the same import through the helper calls)

--via-page: the upload, the check and the one-action import go through dev-c's REAL Cockpit page (focus_page_bridge.py,
under this run's own lock hold, choices={'odoo': {'database': 'woowtest2'}}): the page uploads the file, selects only
odoo, takes the HA key, picks woowtest2 from what the check offers, shows the confirmation lines of that database, ticks
the one acknowledgement and starts the import (the conversion and its restore as two linked jobs in one unit). Without
--via-page the run sends the helper commands the page sends (upload-begin/finish, ha-check-start, ha-import-start with the
same choice and every listed key acknowledged once), for comparison. Everything else is the same in both modes.

SUBSTITUTE IMAGES (stated): dev-c's original tenant image localhost/woow-odoo-tenant-ha:20261101.1152-51856b0 is not
available. On 2026-11-26 dev-c's three Odoo Quadlets and ~/.config/odoo18/odoo18.env were repinned (the original files kept
next to them as *.lab-original-20261126) to public images streamed into dev-c through the isolated lab store:
odoo:18.0-20260926, pgvector/pgvector:0.8.6-pg17, nginxinc/nginx-unprivileged:1.27-alpine (SUBSTITUTE: refs, device
digests, image IDs). A pass is evidence of the HA import against that substitute stack, NOT original-tenant acceptance.

The service set is started and stopped by THIS driver, under its lock, through ha_import_e2e.owner, the lab's owner path
(`labpodman exec -i woowbk-dev-c /usr/local/bin/woowbk-owner systemctl --user start|stop <unit>`, what
`tests/e2e/lab/owner.sh c systemctl --user ...` runs): only when all three units are inactive and pin the substitute
images, in the order odoo-db -> odoo -> odoo-gateway, each active with its container healthcheck and HTTP health; stopped
again in reverse order at the end, once dev-c's own Odoo is verifiably back. Units found active are used and left as they
are; any other state refuses before a change. Nothing is pulled, loaded, deployed or repinned here.

One run = the heavy seat (HEAVY_FREE = the dev-c lock: heavy.sh waited for it) and one hold of /tmp/woowbk-dev-c-mutation.lock
(flock, waiting up to 10 minutes; the page bridge requires this very process to hold it), a committed checkout (no
tracked change; the same for --source), no earlier run of this case pending (its receipt ~/.woowbk-lab/run/
odoo_cold_keep_flow.json lists what it made; written at every change, complete only when nothing of the run is left).

  preflight  dev-c network none without a port, the fixture's SHA-256, host memory and disk (12 GiB floor after this
             run's writes), installed engine == --source (default this checkout; it must hold the cold-keep fixes
             816e4889/647fe670), no job running, the Quadlets/env pin the substitute images (each loaded with its
             recorded ID), the three units all inactive or all active, the retention policy keeps every manual Odoo
             backup, no older Odoo safety backup the run's two restores would make the product prune (keep 3 newest)
  setup      the stack up (started when found inactive, after a memory check), the engine reports Odoo running, the
             containers run the substitute image IDs and Odoo's upgrade marker names the substitute web image, the
             device headroom for the jobs and the Cockpit session (1280 MiB)
  before     web and gateway health; facts (web.base.url, upgrade marker), partner count and databases recorded; no
             database woowbk_lab_other; every backup, HA record and job id recorded
  baseline   a FRESH backup of dev-c's own Odoo (this run's: it opens, its restore preflight passes, retention deleted
             nothing), then the extra database woowbk_lab_other with one marker row (this run's)
  import     page or helper: the check (exactly odoo; importable; the choice offers exactly woowtest and woowtest2; the
             whole-cluster line restore.other-databases names woowbk_lab_other; every confirmation line of woowtest2 is a
             reviewed one, keyed), the chain (conversion with the choice, restore not rolled back, health ok, no warning,
             the kept whole-cluster copy, woowbk_lab_other put back, nothing left out); the page adds its own checks and
             gates (expected outcome, every key once, chain in one unit, the choice exactly, the issued cookie scan). The
             page acknowledges what its check lists and imports in the same flow: its check is judged after the import
  verify     the converted backup (manual, from this HA record, pointing to the kept copy), the kept copy listed kept,
             woowtest2's partner count live, the databases exactly dev-c's own plus woowbk_lab_other with its marker
             row, web.base.url and the upgrade marker dev-c's own, odoo.service active, health, engine status
  recovery   whatever stopped the run (a failed check, an error, SIGTERM/SIGINT; the page's own soft stop): every job of
             the run is waited for (30 min), then -- once an import job exists -- the baseline is restored and dev-c's
             own Odoo compared exactly with the record (facts, partners, databases; woowbk_lab_other dropped when still
             there); without an import job the same comparison without a restore
  cleanup    only what this run made, and only once dev-c's own Odoo is verifiably back: the conversion, the safety
             backups, the kept copy, the baseline; the HA record when this run uploaded it; the units it started; no job
             object, staging folder or key file. Otherwise everything stays for the coordinator (receipt pending)
  leaks      the HA test values (key, passwords, the n8n credential value) in the engine's records, uploads, run dir and
             the device journal; with --via-page devadmin's Cockpit password too; every registered value in this run's
             private evidence: 0 hits
  after      isolation; backups and HA records exactly as before; Quadlets and env byte for byte; no job running

stdout carries only fixed lines (`<check>: PASS|FAIL`, the source commit, the lock time and the count line); details go to
the private, redacted evidence folder ~/.woowbk-lab/evidence/odoo-cold-keep/<time>/ (0700, files 0600). A passing run has
52 checks (helper path) or 78 (--via-page: 27 of them the page's own and the bridge's gates). Exit status: 0 every check
passed, 1 a check failed (the recovery ran), 2 refused before the lock (nothing on dev-c read), 3 the lock stayed taken.
The page's restore keeps a whole-cluster copy that only the restore's result names: focus_page_bridge.created_by counts it
as the page's own backup (19f77889), otherwise the gate no_unexplained_backups fails and the copy escapes the cleanup.
Not covered (stated): the original tenant image and its custom modules, an Odoo login (the HA test logins are not used),
a host reboot, roles in the extra database's put-back (the database and its rows only).
"""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
LAB = Path.home() / '.woowbk-lab'
DEVICE = 'woowbk-dev-c'
LOCK = '/tmp/woowbk-dev-c-mutation.lock'
LOCK_WAIT = 10 * 60              # heavy.sh waited for the lock to be free: a short race only
HOLD_BUDGET = 45 * 60            # no new phase after this many seconds of the hold (recovery and cleanup always run)
PAGE_STEP_BUDGET = 25 * 60       # the page's own 20 minutes and reading its jobs
REST_RESERVE = 10 * 60           # left of the hold budget after the page step
JOB_WAIT = 30 * 60               # one job (measured 11-26: 20 s to 55 s each)
UNIT_READY = 10 * 60             # one unit to active and healthy
FLOOR = 12 * 1024 ** 3           # the team keeps >= 12 GiB free on the host at every moment
RUN_WRITES = 1024 ** 3           # 11-26: upload 36 MiB, baseline 13 MiB, conversion 9 MiB, safety and kept copies: < 1 GiB
MIN_HOST_AVAILABLE_KIB = 1200 * 1024          # the browser (focus_page_bridge.HOST_MIN_AVAILABLE_KIB)
START_HEADROOM = 2304 * 1024 ** 2             # before starting Odoo: its three containers plus MIN_HEADROOM
MIN_HEADROOM = 1280 * 1024 ** 2               # with Odoo up: the jobs and the Cockpit session (the bridge's own floor)
FIXTURE = LAB / 'ha-fixtures' / '20261118' / 'woow-import-test-enc' / 'woow-import-test-enc.tar'
FIXTURE_SHA = '1840b054568cb54d9b796874385af35e64c85e7a24c70b9f4e4653b6b137b731'
APP = 'odoo'
HA_DATABASES = ('woowtest', 'woowtest2')     # the HA backup's two Odoo databases (11-26 check: both can move, no default)
DATABASE = 'woowtest2'                       # the one imported, as on 11-26
EXTRA_DB = 'woowbk_lab_other'                # this run's extra database in dev-c's Odoo cluster
MARKER = 'preserved'
REVIEWED = ('odoo.databases-left', 'restore.other-databases')   # the confirmation lines of woowtest2 (11-26 check)
SHARED = '_shared'
KEY = re.compile(r'[a-z0-9.-]{4,70}:[0-9a-f]{16}\Z')            # haissues.KEY_RE
LEAK_NAMES = ('HA_BACKUP_KEY', 'ODOO_ADMIN_PW', 'ODOO_PROBE_PW', 'N8N_OWNER_PW', 'N8N_CREDENTIAL_VALUE', 'ODOO_MASTER_PW',
              'ODOO_DB_PW')                                       # ha_import_e2e.scenario_leaks
# The cold-keep fixes the product source must hold: the commit, or (after a squash merge) a line it added.
COLD_KEEP = {'816e48896152de86f51c2091891abb101a5ab33d': ('backup-engine/woowbackup/kept.py', "'_cold_ha_pg'"),
             '647fe670a92953a98c8fdecea879c537c6a2aa76': ('backup-engine/woowbackup/haimport.py',
                                                          'def _preview_cold_odoo_databases(')}
UNITS = (('odoo-db.service', 'odoo18-db', None),
         ('odoo.service', 'odoo18-web', 'http://127.0.0.1:18069/web/health'),
         ('odoo-gateway.service', 'odoo18-gateway', 'http://127.0.0.1:18080/nginx-health'))
UNIT_NAMES = tuple(unit for unit, _container, _url in UNITS)
HEALTH = ('http://127.0.0.1:18069/web/health', 'http://127.0.0.1:18080/web/health')
# The 2026-11-26 repin (parity-real odoo-substitute-{pull,transfer,repin,start}): what each Quadlet runs, its source.
SUBSTITUTE = {
    'web': {'ref': 'localhost/woow-odoo-substitute:18.0-20260926'
                   '@sha256:accb85d54241b3e8b0b2228cd84e4a63fc68d6b756fa83127e4ba8d9d8c98ccd',
            'id': '1616522ef3185fc8bd7522224877cd8542ad99090a7507a824e7c203f54bb26d', 'container': 'odoo18-web',
            'source': 'docker.io/library/odoo:18.0-20260926'
                      '@sha256:60eb1b5006df85f900e300b6cc120d51ebd979379ee9588340adc2a84ffcd718'},
    'db': {'ref': 'localhost/woow-odoo-pg17-substitute:0.8.6'
                  '@sha256:e2617d4623ec0981a9a3f6fadecd879ab260d4afe0649231adcb2d67a79ec9d1',
           'id': '17a06c0a60bf6fb548a8493b8f6057dc830b791bbbe1f1ab706ca4b9d97c8180', 'container': 'odoo18-db',
           'source': 'docker.io/pgvector/pgvector:0.8.6-pg17'
                     '@sha256:cf134a767f474095eeba57e0117be8e568e011a63f33fbf252f14c9b760f8e6f'},
    'gateway': {'ref': 'localhost/woow-odoo-gateway-substitute:1.27-alpine'
                       '@sha256:7b40c8ed6a73bda24d7510e3be1db31a19878acf65062271302a8a7aafd1682e',
                'id': '47ce8258a10e28ce4b4498588c25ef77ae328f4c56cbe3e8d5dcf4f6d8019997', 'container': 'odoo18-gateway',
                'source': 'docker.io/nginxinc/nginx-unprivileged:1.27-alpine'
                          '@sha256:7b40c8ed6a73bda24d7510e3be1db31a19878acf65062271302a8a7aafd1682e'}}
ENV_IMAGES = {'WOOW_ODOO_IMAGE': 'web', 'WOOW_ODOO_DB_IMAGE': 'db'}
PAGE_FILES = ('backup.js', 'backup.css', 'index.html', 'manifest.json')   # focus_page_bridge.PAGE_FILES
# The files' SHA-256 right after that repin (recorded, compared only for the evidence: a later legitimate change is allowed)
REPIN_SHA = {'web': 'a147d805c2bb9c7fb36a4b88731475ab8d0160bb4bcea23ab9160780e4000fa4',
             'db': 'da653a68695651140fbc7b93602a88b6cbd85dd868a9b8ee91ed3068d2e36d59',
             'gateway': 'd0f726947d7012063d816f46ac33609259a9c291ccc8f584749231706062f579',
             'env': '7e973eb42dae8f0b7e452b405d31e5782e20acae9bf9e5221b0f29e38da98aeb'}
SAFE_LABEL = re.compile(r"[^A-Za-z0-9 ,()/:'<>.=_-]")
SQL_DATABASES = 'SELECT datname FROM pg_database WHERE datistemplate=false ORDER BY datname;'
SQL_PARTNERS = 'SELECT count(*) FROM res_partner;'
SQL_MARKER = "SELECT coalesce(string_agg(marker, ',' ORDER BY marker), '') || '|' || count(*) FROM lab_keep;"


def _load(name):
    # -I removes the script directory from sys.path: load the adjacent module explicitly.
    spec = importlib.util.spec_from_file_location(name, HERE / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


h = _load('ha_import_e2e')
h.DEVICE = DEVICE                 # every helper/owner/root call of the dev-c driver goes to dev-c (its default too)
Failed = h.Failed
HA_ID = 'ha-' + FIXTURE_SHA[:20]


def load_bridge():
    """focus_page_bridge, only for --via-page."""
    return _load('focus_page_bridge')


class Stopped(BaseException):
    """SIGTERM/SIGINT outside the page's own soft stop: the run stops and the recovery runs (signals during the recovery
    are ignored). A BaseException, like the bridge's _Stop, so that no `except Exception` on the way swallows it."""


SIGNALS = {'recovering': False, 'ignored': 0}


def _stop(signum, _frame):
    if SIGNALS['recovering']:
        SIGNALS['ignored'] += 1
        return
    raise Stopped(f'signal {signum}')


# ---------------------------------------------------------------- device-side programs (python3 -I -c, stdin JSON)

# As appowner: only the Image= line of each Odoo Quadlet and the two image keys of odoo18.env leave the device (plus each
# file's SHA-256), the loaded image ID of each ref, the units' states and the running containers' image IDs.
UNITS_PROGRAM = r'''
import hashlib, json, subprocess, sys
from pathlib import Path
req = json.loads(sys.stdin.read() or "{}")
home = Path.home()
quadlets = home / ".config/containers/systemd"
files = {"web": quadlets / "odoo.container", "db": quadlets / "odoo-db.container",
         "gateway": quadlets / "odoo-gateway.container", "env": home / ".config/odoo18/odoo18.env"}
out = {"sha256": {}, "images": {}, "env_images": {}, "ids": {}, "units": {}, "containers": {}}
def run(argv):
    p = subprocess.run(argv, capture_output=True, timeout=120)
    return p.stdout.decode("utf-8", "replace").strip() if p.returncode == 0 else None
for name, path in files.items():
    try:
        data = path.read_bytes()
    except OSError:
        out["sha256"][name] = None
        continue
    out["sha256"][name] = hashlib.sha256(data).hexdigest()
    lines = data.decode("utf-8", "replace").splitlines()
    if name == "env":
        for key in ("WOOW_ODOO_IMAGE", "WOOW_ODOO_DB_IMAGE"):
            found = [line.split("=", 1)[1].strip() for line in lines if line.startswith(key + "=")]
            out["env_images"][key] = found[0] if len(found) == 1 else None
    else:
        found = [line.split("=", 1)[1].strip() for line in lines if line.startswith("Image=")]
        out["images"][name] = found[0] if len(found) == 1 else None
for name, ref in out["images"].items():
    out["ids"][name] = run(["podman", "image", "inspect", "--format", "{{.Id}}", ref]) if ref else None
for unit in req.get("units", []):
    p = subprocess.run(["systemctl", "--user", "is-active", unit], capture_output=True, timeout=60)
    out["units"][unit] = p.stdout.decode("utf-8", "replace").strip() or "unknown"
for container in req.get("containers", []):
    out["containers"][container] = run(["podman", "container", "inspect", "--format", "{{.Image}}", container])
print(json.dumps(out))
'''

# As root: the device's memory in use (anon + kernel) and its cap.
HEADROOM = r'''
import json
from pathlib import Path
stat = Path("/sys/fs/cgroup/memory.stat").read_text().splitlines()
used = sum(int(x.split()[1]) for x in stat if x.startswith(("anon ", "kernel ")))
limit = Path("/sys/fs/cgroup/memory.max").read_text().strip()
print(json.dumps({"used": used, "limit": int(limit) if limit.isdigit() else None}))
'''

# As root: the installed engine's modules and helper, and the installed Cockpit page (SHA-256).
ENGINE_HASHES = r'''
import hashlib, json, os
lib = "/usr/local/lib/woowtech-cockpit-backup/woowbackup"
out = {"lib": {}, "helper": None, "page": {}}
for d, dirs, files in os.walk(lib):
    dirs[:] = [x for x in dirs if x != "__pycache__"]
    for f in files:
        if f.endswith(".py"):
            p = os.path.join(d, f)
            out["lib"][os.path.relpath(p, lib)] = hashlib.sha256(open(p, "rb").read()).hexdigest()
out["helper"] = hashlib.sha256(open("/usr/local/libexec/woowtech-cockpit-backup", "rb").read()).hexdigest()
for name in ("backup.js", "backup.css", "index.html", "manifest.json"):
    try:
        out["page"][name] = hashlib.sha256(open("/usr/local/share/cockpit/woowtechbackup/" + name, "rb").read()).hexdigest()
    except OSError:
        out["page"][name] = None
print(json.dumps(out))
'''


def device_json(call, script, request=None, timeout=300):
    """The JSON a fixed `python3 -I -c` program printed inside dev-c (call: h.root or h.owner)."""
    proc = call('python3', '-I', '-c', script, input=json.dumps(request or {}).encode(), timeout=timeout)
    if proc.returncode != 0:
        raise Failed('a fixed device program failed')
    try:
        return json.loads(proc.stdout.decode('utf-8', 'replace').strip().splitlines()[-1])
    except (ValueError, IndexError):
        raise Failed('a fixed device program printed no JSON') from None


def root_json(script, request=None, timeout=300):
    return device_json(h.root, script, request, timeout)


def owner_json(script, request=None, timeout=300):
    return device_json(h.owner, script, request, timeout)


# ---------------------------------------------------------------- host-side helpers

def label(text):
    return SAFE_LABEL.sub(' ', str(text))[:140].strip() or 'check'


def emit(line):
    print(line, flush=True)


def git(path, *args):
    proc = subprocess.run(['git', '-C', str(path), *args], capture_output=True, text=True, timeout=60)
    return proc.returncode, proc.stdout.strip()


def clean(path):
    code, out = git(path, 'status', '--porcelain', '--untracked-files=no')
    return code == 0 and not out


def holds_cold_keep(path):
    """{commit: True|False}: the product source holds each cold-keep fix (the commit, or the line it added)."""
    found = {}
    for commit, (rel, line) in COLD_KEEP.items():
        try:
            text = (Path(path) / rel).read_text(encoding='utf-8')
        except OSError:
            text = ''
        found[commit] = git(path, 'merge-base', '--is-ancestor', commit, 'HEAD')[0] == 0 or line in text
    return found


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def host_available_kib():
    return next(int(line.split()[1]) for line in Path('/proc/meminfo').read_text().splitlines()
                if line.startswith('MemAvailable:'))


def host_free():
    stat = os.statvfs(str(LAB))
    return stat.f_bavail * stat.f_frsize


def tree_engine(product):
    """What dev-c must have installed from the product source: the engine's modules, the helper and the Cockpit page."""
    base = Path(product) / 'backup-engine' / 'woowbackup'
    return {'lib': {str(p.relative_to(base)): sha256_file(p) for p in base.rglob('*.py') if '__pycache__' not in p.parts},
            'helper': sha256_file(Path(product) / 'backup-engine' / 'woowtech-cockpit-backup'),
            'page': {name: sha256_file(Path(product) / 'backup' / name) for name in PAGE_FILES}}


def needles(values):
    """Raw bytes and one JSON string-escaping layer (both Unicode modes) of every value (ha_import_b1_e2e's rule)."""
    found = set()
    for value in values:
        raw = value.encode('utf-8')
        found.add(raw)
        for ascii_only in (False, True):
            found.add(json.dumps(value, ensure_ascii=ascii_only)[1:-1].encode('utf-8'))
    return found


def scan_evidence(directory, values):
    """{files, hits} of `values` in every file below `directory` (a symlink or an unreadable file fails the scan)."""
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


def private(directory):
    """The page's own files (screenshots, browser record, cookie metadata) made 0600 in 0700 folders."""
    if not directory.is_dir() or directory.is_symlink():
        return
    for root, dirs, names in os.walk(directory, followlinks=False):
        for name in dirs:
            if not (Path(root) / name).is_symlink():
                os.chmod(Path(root) / name, 0o700)
        for name in names:
            if not (Path(root) / name).is_symlink():
                os.chmod(Path(root) / name, 0o600)


# ---------------------------------------------------------------- what a check offers and what is acknowledged

def odoo_row(result):
    rows = [row for row in (result or {}).get('apps') or [] if isinstance(row, dict)]
    return rows[0] if len(rows) == 1 and rows[0].get('app_id') == APP else None


def confirm_lines(result, database=DATABASE):
    """(group, issue) of every confirmation line the import acknowledges for `database`: the shared part's and Odoo's own
    that name no database or this one (focus_page_bridge._check_outcome_chosen lists the same)."""
    lines = [(SHARED, issue) for issue in (result or {}).get('shared') or []
             if isinstance(issue, dict) and issue.get('level') == 'confirm']
    row = odoo_row(result) or {}
    lines += [(APP, issue) for issue in row.get('issues') or []
              if isinstance(issue, dict) and issue.get('level') == 'confirm' and issue.get('database') in (None, database)]
    return lines


def acknowledgement(lines):
    """{group: sorted distinct keys}: what one acknowledgement sends for these lines."""
    found = {}
    for group, issue in lines:
        found.setdefault(group, set()).add(issue.get('key'))
    return {group: sorted(keys) for group, keys in found.items()}


def section_database(row, name):
    return next((db for db in ((row or {}).get('odoo') or {}).get('databases') or []
                 if isinstance(db, dict) and db.get('name') == name), None)


def is_root(job):
    params = (job or {}).get('params') or {}
    group = params.get('group') or {}
    return (job.get('type') == 'backup' and params.get('source') == 'ha' and group.get('kind') == 'ha-import'
            and group.get('index') == 0)


def owned_from(records):
    """The backups the import's jobs made: the conversion's backup, each restore's safety backup and kept copies."""
    found = []
    for job in records:
        result = job.get('result') or {}
        values = [result.get('backup_id') if job.get('type') == 'backup' else result.get('safety_backup_id')]
        if job.get('type') == 'restore' and isinstance(result.get('kept'), dict):
            values += [item.get('backup_id') for item in result['kept'].values() if isinstance(item, dict)]
        found += [value for value in values if isinstance(value, str) and value and value not in found]
    return found


def safety_at_risk(backups):
    """The Odoo safety backups (not kept copies) that exist now: once this run's two restores add theirs and the kept copy,
    those are the 3 newest per app, so the product's own keep-3 rule (flows.prune_safety) would delete these."""
    return sorted(row.get('id') for row in backups if isinstance(row, dict) and row.get('type') == 'safety'
                  and row.get('kept') is not True and APP in {a.get('id') for a in row.get('apps') or [] if isinstance(a, dict)})


def keep_last(policy, app_id):
    """retention.keep_last: the app's own value, else the default (None keeps every manual backup)."""
    item = ((policy or {}).get('apps') or {}).get(app_id)
    return item.get('keep_last') if item is not None else (policy or {}).get('default_keep_last')


# ---------------------------------------------------------------- evidence and the receipt

class Ev(h.Evidence):
    """ha_import_e2e's private, redacted evidence folder (0700, files 0600); stdout gets only `<label>: PASS|FAIL`."""

    def __init__(self, secrets, area='odoo-cold-keep'):
        super().__init__(secrets, area)
        os.chmod(self.dir.parent, 0o700)

    def log(self, text):
        line = f'{time.strftime("%H:%M:%S")} {self.secrets.redact(str(text))}\n'
        fd = os.open(self.log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'a', encoding='utf-8') as handle:
            handle.write(line)

    def check(self, name, ok, detail=''):
        result = super().check(name, ok, detail)
        emit(f'{label(name)}: {"PASS" if result else "FAIL"}')
        return result


class Receipt:
    """~/.woowbk-lab/run/odoo_cold_keep_flow.json (0600): what this run made, rewritten at every change; complete only
    when nothing of it is left on dev-c. A pending one stops the next run before any change."""

    def __init__(self, path):
        self.path = Path(path)
        self.data = None

    def pending(self):
        if not self.path.exists() and not self.path.is_symlink():
            return False
        try:
            return json.loads(self.path.read_text(encoding='utf-8')).get('complete') is not True
        except (OSError, ValueError):
            return True

    def write(self, **changes):
        self.data = dict(self.data or {}, **changes, updated=time.strftime('%Y-%m-%dT%H:%M:%S'))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp = self.path.with_name(self.path.name + '.tmp')
        if temp.is_symlink():
            temp.unlink()
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            json.dump(self.data, handle, indent=1, ensure_ascii=False)
            handle.write('\n')
        os.replace(temp, self.path)


# ---------------------------------------------------------------- the run

class Run:
    def __init__(self, args, ev, receipt=None):
        self.args, self.ev = args, ev
        self.via_page = bool(getattr(args, 'via_page', False))
        self.product = Path(getattr(args, 'source', None) or REPO)
        self.secrets = args.secrets
        self.receipt = receipt or Receipt(LAB / 'run' / 'odoo_cold_keep_flow.json')
        self.lock_started = time.monotonic()
        self.changed = False          # set at the first change (the receipt says so first)
        self.found = {}               # unit -> its state before the run
        self.started = []             # the units this run started (stopped again at the end)
        self.files_before = None      # SHA-256 of the three Quadlets and the env file
        self.backups_before = self.ha_before = None
        self.jobs_before, self.jobs_recorded = set(), False
        self.before = None            # dev-c's own Odoo: facts, partners, databases
        self.baseline = None
        self.baseline_requested = False
        self.own_jobs = []            # the baseline's and the own restore's job ids (waited for in the recovery)
        self.extra_db = False
        self.created = []             # backups this run made besides the baseline
        self.created_ha = None
        self.chain_root = None
        self.chain = []
        self.partners = None          # woowtest2's partner count from the check
        self.ack = None               # what the one acknowledgement sends
        self.restored = False         # dev-c's own Odoo verifiably as before (restored, or never changed)

    # -------- helpers
    def require(self, name, ok, detail=''):
        if not self.ev.check(name, ok, detail):
            raise Failed(name)

    def budget(self, phase):
        if time.monotonic() - self.lock_started > HOLD_BUDGET:
            raise Failed(f'lock hold budget reached before {phase}')

    def note(self, **changes):
        self.receipt.write(**changes)

    def own(self, backup_id):
        if isinstance(backup_id, str) and backup_id and backup_id != self.baseline and backup_id not in self.created:
            self.created.append(backup_id)
            self.note(created_backups=list(self.created))

    def units(self, containers=()):
        return owner_json(UNITS_PROGRAM, {'units': list(UNIT_NAMES), 'containers': list(containers)})

    def headroom(self):
        memory = root_json(HEADROOM, {}, timeout=60)
        if not isinstance(memory.get('limit'), int) or not isinstance(memory.get('used'), int):
            return None, memory
        return memory['limit'] - memory['used'], memory

    def listing(self):
        reply = h.ok('list', ev=self.ev)
        return reply.get('backups') or [], reply.get('ha_backups') or []

    def databases(self):
        return h.psql('odoo18-db', 'postgres', 'postgres', SQL_DATABASES).splitlines()

    def partner_count(self):
        return h.psql('odoo18-db', 'postgres', 'odoo', SQL_PARTNERS)

    def marker(self):
        return h.psql('odoo18-db', 'postgres', EXTRA_DB, SQL_MARKER)

    def odoo_status(self):
        app = next((row for row in h.ok('status', ev=self.ev).get('apps') or [] if row.get('id') == APP), {})
        return app.get('state') == 'running' and not app.get('problems'), {'state': app.get('state'),
                                                                           'problems': len(app.get('problems') or [])}

    def health(self):
        return {url: h.http_code(url) for url in HEALTH}

    def wait(self, job_id, timeout=JOB_WAIT):
        return h.wait_job(job_id, ev=self.ev, timeout=timeout)

    # -------- preflight (read-only: any failure stops the run before a change)
    def preflight(self):
        ev = self.ev
        try:
            h.require_isolated_device()
            isolated = True
        except Failed:
            isolated = False
        self.require('preflight: dev-c runs with network none and no published port', isolated)
        trees = {'checkout': clean(REPO), 'product': clean(self.product)}
        self.require('preflight: the checkout has no tracked change (the source commit describes the code), nor has the '
                     'product source', all(trees.values()), trees)
        fixes = holds_cold_keep(self.product)
        self.require('preflight: the product source holds the cold-keep fixes (816e4889 kept copy and put-back, 647fe670 '
                     'first-check line)', all(fixes.values()), {k[:8]: v for k, v in fixes.items()})
        self.require('preflight: no earlier run of this case is pending (its receipt would list what it made)',
                     not self.receipt.pending(), str(self.receipt.path))
        sha = sha256_file(FIXTURE) if FIXTURE.is_file() and not FIXTURE.is_symlink() else None
        self.require('preflight: the local file is the recorded real x86 encrypted Odoo and n8n HA backup (SHA-256)',
                     sha == FIXTURE_SHA, (sha or 'missing')[:16])
        available, free = host_available_kib(), host_free()
        self.require('preflight: host MemAvailable >= 1200 MiB (the browser) and the host disk keeps the 12 GiB floor '
                     'after this run\'s writes', available >= MIN_HOST_AVAILABLE_KIB and free - RUN_WRITES >= FLOOR,
                     {'mem_available_mib': available >> 10, 'free_gib': round(free / 1024 ** 3, 2)})
        installed, tree = root_json(ENGINE_HASHES, {}, timeout=300), tree_engine(self.product)
        differ = sorted(k for k in set(tree['lib']) | set(installed.get('lib') or {})
                        if tree['lib'].get(k) != (installed.get('lib') or {}).get(k))
        page = installed.get('page') == tree['page']   # the bridge requires it too (installed page == the source's)
        self.require('preflight: the installed engine is the product source (every module and the helper SHA-256, the '
                     'page for --via-page)', not differ and installed.get('helper') == tree['helper']
                     and (page or not self.via_page), {'modules': len(tree['lib']), 'differ': differ[:10], 'page': page})
        status = h.ok('status', ev=ev)
        self.require('preflight: no job is running on dev-c', not status.get('active_job'))
        state = self.units()
        self.files_before = state.get('sha256')
        ev.save('units-before.json', state)
        pins = {name: state.get('images', {}).get(name) == item['ref'] and state.get('ids', {}).get(name) == item['id']
                for name, item in SUBSTITUTE.items()}
        pins.update({key: state.get('env_images', {}).get(key) == SUBSTITUTE[name]['ref'] for key, name in ENV_IMAGES.items()})
        self.require('preflight: the Odoo Quadlets and env file pin the documented substitute images, each loaded with its '
                     'recorded image ID', all(pins.values()),
                     {'pins': pins, 'files_as_repinned_20261126': {k: (self.files_before or {}).get(k) == v
                                                                    for k, v in REPIN_SHA.items()}})
        self.found = dict(state.get('units') or {})
        states = {self.found.get(unit) for unit in UNIT_NAMES}
        self.require('preflight: odoo-db, odoo and odoo-gateway are all inactive (started for this run) or all active '
                     '(used as they are)', states in ({'inactive'}, {'active'}), self.found)
        policy = h.ok('retention-plan', {}, ev=ev)
        keep = keep_last(policy.get('saved_policy'), APP)
        self.require('preflight: the retention policy keeps every manual Odoo backup (the baseline makes it delete none)',
                     keep is None, {'keep_last': keep, 'policy_problem': bool(policy.get('policy_problem'))})
        backups, ha = self.listing()
        risk = safety_at_risk(backups)
        self.require('preflight: no earlier Odoo safety backup that this run\'s two restores would make the product prune '
                     '(keep 3 newest)', not risk, {'at_risk': risk[:10]})
        self.backups_before = sorted(row.get('id') for row in backups)
        self.ha_before = sorted(row.get('id') for row in ha)

    # -------- setup (the first change: the stack up when found inactive)
    def setup(self):
        ev = self.ev
        self.changed = True
        self.note(schema=1, case='odoo-cold-keep', mode='page' if self.via_page else 'helper', device=DEVICE,
                  evidence=str(ev.dir), product=str(self.product), found_units=self.found, started_units=[],
                  baseline_id=None, extra_database=False, created_backups=[], created_ha_record=None, chain_root=None,
                  restored=False, complete=False)
        detail = {'found': self.found}
        ok = True
        if set(self.found.values()) == {'inactive'}:
            room, memory = self.headroom()
            detail['headroom_mib'] = None if room is None else room >> 20
            ok = room is not None and room >= START_HEADROOM
            for unit, container, url in UNITS if ok else ():
                self.started.append(unit)   # before the start: a half-started unit is stopped again
                self.note(started_units=list(self.started))
                proc = h.owner('systemctl', '--user', 'start', unit, timeout=900)
                if proc.returncode != 0 or not self.ready(unit, container, url):
                    detail['failed'] = unit
                    ok = False
                    break
        else:
            ok = all(self.ready(unit, container, url, seconds=60) for unit, container, url in UNITS)
        self.require('setup: dev-c\'s substitute Odoo stack is up: odoo-db, odoo and odoo-gateway active and healthy '
                     '(started by this run when found inactive)', ok, detail)
        running, view = self.odoo_status()
        self.require('setup: the engine reports Odoo running without problems', running, view)
        state = self.units([item['container'] for item in SUBSTITUTE.values()])
        facts = h.live_odoo_facts()
        try:
            marker = json.loads(facts.get('marker') or '{}')
        except ValueError:
            marker = {}
        images = {name: state.get('containers', {}).get(item['container']) == item['id'] for name, item in SUBSTITUTE.items()}
        self.require('setup: the running containers are the substitute images and Odoo\'s upgrade marker names the '
                     'substitute web image', all(images.values()) and marker.get('digest') == 'sha256:' + SUBSTITUTE['web']['id'],
                     {'images': images, 'marker_core_date': marker.get('core_date')})
        room, memory = self.headroom()
        self.require('setup: dev-c memory headroom with Odoo up >= 1280 MiB (the jobs and the Cockpit session)',
                     room is not None and room >= MIN_HEADROOM,
                     {'headroom_mib': None if room is None else room >> 20, 'limit_mib': (memory.get('limit') or 0) >> 20})

    def ready(self, unit, container, url, seconds=UNIT_READY):
        """The unit active, its container's healthcheck passing and (web, gateway) its HTTP health 200."""
        deadline = time.monotonic() + seconds
        while True:
            state = h.owner('systemctl', '--user', 'is-active', unit, timeout=60).stdout.decode('utf-8', 'replace').strip()
            if state == 'active' and h.owner('podman', 'healthcheck', 'run', container, timeout=60).returncode == 0 \
                    and (url is None or h.http_code(url) == '200'):
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(5)

    # -------- before
    def step_before(self):
        ev = self.ev
        self.before = {'facts': h.live_odoo_facts(), 'partners': self.partner_count(), 'databases': self.databases()}
        codes = self.health()
        ev.save('odoo-before.json', dict(self.before, health=codes))
        self.require('before: dev-c\'s own Odoo answers (web and gateway health 200), its facts, partner count and '
                     'databases are recorded', all(code == '200' for code in codes.values())
                     and str(self.before['partners']).isdigit() and 'odoo' in self.before['databases'],
                     {'health': codes, 'partners': self.before['partners'], 'databases': self.before['databases']})
        self.require('before: no database woowbk_lab_other exists in dev-c\'s Odoo cluster (nothing of an earlier run)',
                     EXTRA_DB not in self.before['databases'])
        self.jobs_before = {row.get('id') for row in h.ok('jobs', ev=ev).get('jobs') or []}
        self.jobs_recorded = True     # from here every new job on dev-c is this run's (it holds the lock)

    # -------- the fresh baseline and the extra database
    def step_baseline(self):
        ev = self.ev
        self.baseline_requested = True   # a stop from here on looks for the baseline job among the new jobs
        started = h.ok('backup-start', {'apps': [APP], 'include_images': False,
                                        'note': 'woowbk lab: odoo cold keep baseline (deleted by its run)',
                                        'request_id': h.request_id('odoo-ck-baseline')}, ev=ev, timeout=300)
        self.own_jobs.append(started['job_id'])
        job = self.wait(started['job_id'])
        result = job.get('result') or {}
        if job.get('state') == 'succeeded' and isinstance(result.get('backup_id'), str):
            self.baseline = result['backup_id']
            self.note(baseline_id=self.baseline)
        self.require('baseline: a fresh backup of dev-c\'s own Odoo succeeded (this run\'s own, deleted at the end)',
                     self.baseline is not None, {'state': job.get('state'), 'size': result.get('size')})
        inspected = h.ok('inspect', {'backup_id': self.baseline}, ev=ev, timeout=900)
        pre = inspected.get('preflight') or {}
        failed = [c.get('id') for c in pre.get('checks') or [] if c.get('status') == 'fail']
        self.require('baseline: it opens and its restore preflight passes (Odoo in place, no failed check)',
                     inspected.get('ok') is True and pre.get('ok') is True and not failed
                     and [(a.get('id'), a.get('mode')) for a in pre.get('apps') or []] == [(APP, 'inplace')],
                     {'failed': failed[:5], 'apps': [(a.get('id'), a.get('mode')) for a in pre.get('apps') or []]})
        backups, _ha = self.listing()
        row = next((b for b in backups if b.get('id') == self.baseline), {})
        self.require('baseline: it deleted no backup (retention) and is listed as a manual Odoo backup',
                     not result.get('retention_deleted') and set(self.backups_before) <= {b.get('id') for b in backups}
                     and row.get('type') == 'manual' and [a.get('id') for a in row.get('apps') or []] == [APP],
                     {'retention_deleted': result.get('retention_deleted'), 'type': row.get('type')})

    def step_extra_db(self):
        self.extra_db = True             # before the call: a stop half-way still drops it
        self.note(extra_database=True)
        h.psql('odoo18-db', 'postgres', 'postgres', f'CREATE DATABASE {EXTRA_DB};')
        h.psql('odoo18-db', 'postgres', EXTRA_DB,
               f"CREATE TABLE lab_keep(marker text PRIMARY KEY); INSERT INTO lab_keep VALUES ('{MARKER}');")
        self.require('extra database: woowbk_lab_other with one marker row created in dev-c\'s Odoo cluster (this run\'s '
                     'own)', EXTRA_DB in self.databases() and self.marker() == f'{MARKER}|1')

    # -------- the import: the helper calls the page sends
    def space(self):
        free = host_free()
        self.require('import: host disk keeps the 12 GiB floor after the upload, check, conversion and restore writes',
                     free - RUN_WRITES >= FLOOR, {'free_gib': round(free / 1024 ** 3, 2)})

    def step_import(self):
        ev = self.ev
        self.space()
        rc, reply = h.upload(FIXTURE, ev=ev)
        meta = reply.get('ha_backup') or {}
        if meta.get('id') == HA_ID and HA_ID not in self.ha_before:
            self.created_ha = HA_ID
            self.note(created_ha_record=HA_ID)
        found = {a.get('app_id'): a.get('installed') for a in meta.get('importable_apps') or []}
        self.require('upload: upload-begin, copy, upload-finish answer the HA record (id from the SHA-256), Odoo importable '
                     'and installed here', rc == 0 and meta.get('id') == HA_ID and found.get(APP) is True,
                     {'existed_before': HA_ID in self.ha_before, 'apps': found})
        check = h.run_check(HA_ID, [APP], ev=ev, key=self.secrets['HA_BACKUP_KEY'], tag='odoo-ck-check')
        self.judge_check(check)
        started = h.ok('ha-import-start', {'ha_backup_id': HA_ID, 'apps': [APP], 'request_id': h.request_id('odoo-ck-import'),
                                           'confirm': True, 'test_mode': False, 'then_restore': True, 'overwrite': True,
                                           'check_job_id': check['id'], 'key': self.secrets['HA_BACKUP_KEY'],
                                           'choices': {APP: {'database': DATABASE}}, 'acknowledged': self.ack},
                       ev=ev, timeout=300)
        self.chain_root = started.get('job_id')
        self.note(chain_root=self.chain_root)
        self.require('import: one-action import started with the database woowtest2 and every listed key acknowledged '
                     'once', isinstance(self.chain_root, str) and bool(started.get('group')))
        self.chain = self.follow(self.chain_root)
        self.judge_chain(self.chain)

    def follow(self, root, timeout=JOB_WAIT):
        """The import's linked jobs from its root (at most two), each waited for to its end; what they made is owned."""
        records, current, seen = [], root, set()
        while current and len(records) < 2:
            if current in seen:
                raise Failed('a job of the import came back')
            seen.add(current)
            job = self.wait(current, timeout)
            records.append(job)
            for backup_id in owned_from([job]):
                self.own(backup_id)
            current = ((job.get('result') or {}).get('group') or {}).get('next_job_id')
        if current:
            raise Failed('the import has more than two jobs')
        return records

    # -------- the import: dev-c's real Cockpit page
    def step_page_import(self, bridge=None):
        ev = self.ev
        bridge = bridge or load_bridge()
        self.space()
        ops = bridge.Ops(helper=lambda command, request=None: h.ok(command, request, ev=ev),
                         wait_job=lambda job_id, timeout: h.wait_job(job_id, ev=ev, timeout=timeout),
                         root_json=lambda script, request: root_json(script, request))
        deadline = min(time.monotonic() + PAGE_STEP_BUDGET, self.lock_started + HOLD_BUDGET - REST_RESERVE)
        try:
            page = bridge.import_via_page(device=DEVICE, lock=LOCK, apps=[APP], importable=[APP], stops=[], fixture=FIXTURE,
                                          key=self.secrets['HA_BACKUP_KEY'], choices={APP: {'database': DATABASE}},
                                          password=self.secrets['COCKPIT_PASSWORD'], evidence=ev.dir / 'page',
                                          deadline=deadline, ops=ops, source=self.product)
        except bridge.BridgeError as error:
            self.adopt(error.summary)
            refused = isinstance(error, bridge.Refused)
            ev.check('page import: refused before the page started (nothing changed)' if refused
                     else 'page import: stopped by a signal (the browser closed in order, the relay reaped)', False,
                     {'reasons': error.summary.get('reasons'), 'phase': error.summary.get('phase'),
                      'check_job_ids': error.summary.get('check_job_ids'), 'root_job_ids': error.summary.get('root_job_ids')})
            raise Failed('page import did not run to the end') from None
        finally:
            private(ev.dir / 'page')
        self.adopt(page.summary)
        for backup_id in owned_from(page.chain):
            self.own(backup_id)
        summary, gates = page.summary, page.gates
        for item in page.browser_checks:
            ev.check(f'page: {item.get("check")}', item.get('ok') is True)
        ev.check('page: bounded (20 min), the browser closed in order and every relay exec child reaped',
                 gates.get('page_bounded') and gates.get('cleanup'), summary.get('page'))
        ev.check('page: the uploaded HA record is the fixture (id and SHA-256)', gates.get('record'),
                 {'ha_id': summary.get('ha_id'), 'existed_before': summary.get('ha_record_existed')})
        ev.check('page: exactly the page\'s own check and import jobs, none left running, no other new backup (the kept '
                 'copy is the restore\'s)', gates.get('own_jobs') and gates.get('no_unexplained_backups'),
                 {'checks': summary.get('check_job_ids'), 'chain': summary.get('chain_job_ids'),
                  'unexplained': summary.get('unexplained_new_backups'), 'reasons': summary.get('reasons')})
        ev.check('page: the check calls odoo importable, stops nothing, and lists every confirmation line of woowtest2 '
                 'keyed (read from the actual check)', gates.get('expected_outcome'),
                 {'lines': summary.get('confirmation_lines'), 'groups': sorted(summary.get('expected_acknowledged') or {}),
                  'reasons': summary.get('reasons')})
        ev.check('page: the one acknowledgement, the import and its jobs carry every listed confirmation key exactly once',
                 gates.get('acknowledged_exact'))
        ev.check('page: one conversion and its restore succeeded as two linked jobs in the first job\'s unit',
                 gates.get('chain') and gates.get('native_units'), {'jobs': summary.get('chain_job_ids')})
        ev.check('page: woowtest2 picked from what the check offers, both requests, the conversion and the chain carry '
                 'exactly it', gates.get('choices'), summary.get('chosen'))
        ev.check('page: every issued Cockpit session value is absent from the records, the journal and the private evidence',
                 gates.get('issued_scan'), (summary.get('browser') or {}).get('issued_scan'))
        self.require('page import passed every gate', page.passed, {k: v for k, v in gates.items() if not v})
        if not isinstance(page.check_job, dict):
            raise Failed('the page left no check')
        self.judge_check(page.check_job)
        self.chain = list(page.chain)
        self.judge_chain(self.chain)

    def adopt(self, summary):
        """What the page made goes to this run's own cleanup at once: its backups, its HA record, its import's root."""
        for backup_id in summary.get('created_backups') or []:
            self.own(backup_id)
        root = summary.get('root_job_id') or next(iter(summary.get('root_job_ids') or []), None)
        if isinstance(root, str):
            self.chain_root = root
            self.note(chain_root=root)
        if summary.get('phase') not in (None, 'preconditions', 'refused') and HA_ID not in (self.ha_before or []):
            try:
                present = HA_ID in {row.get('id') for row in self.listing()[1]}
            except (Failed, subprocess.TimeoutExpired, OSError, ValueError, KeyError):
                present = True   # unknown: the cleanup tries to delete it and says whether that worked
            if present:
                self.created_ha = HA_ID
                self.note(created_ha_record=HA_ID)

    # -------- the facts of the check and of the chain (the helper's, or the page's own jobs)
    def judge_check(self, job):
        ev = self.ev
        params = job.get('params') or {}
        result = (job.get('result') or {}).get('ha_check') or {}
        row = odoo_row(result)
        ev.save('check-odoo.json', row or {})
        self.require('check: the job succeeded and checks exactly odoo of this HA record',
                     job.get('state') == 'succeeded' and params.get('apps') == [APP] and params.get('ha_backup_id') == HA_ID
                     and result.get('ha_backup_id') == HA_ID and row is not None, {'state': job.get('state')})
        stops = [issue.get('id') for issue in [*(result.get('shared') or []), *(row.get('issues') or [])]
                 if isinstance(issue, dict) and issue.get('level') == 'stop' and issue.get('database') in (None, DATABASE)]
        self.require('check: Odoo is importable, no stop line for the app, the shared part or woowtest2',
                     row.get('importable') is True and not stops, {'stops': stops[:5]})
        offer = {item.get('value'): item.get('ok') is not False
                 for item in (row.get('choices') or {}).get('database') or [] if isinstance(item, dict)}
        chosen = section_database(row, DATABASE) or {}
        partners = chosen.get('partners')
        self.require('check: the database choice offers exactly woowtest and woowtest2, both can move, woowtest2\'s partner '
                     'count is read', sorted(offer) == sorted(HA_DATABASES) and all(offer.values())
                     and chosen.get('ok') is True and isinstance(partners, int) and not isinstance(partners, bool)
                     and partners > 0, {'offer': offer, 'partners': partners})
        cluster = [issue for issue in row.get('issues') or [] if isinstance(issue, dict)
                   and issue.get('id') == 'restore.other-databases']
        self.require('check: the whole-cluster line (restore.other-databases) names woowbk_lab_other',
                     len(cluster) == 1 and cluster[0].get('level') == 'confirm' and cluster[0].get('database') is None
                     and EXTRA_DB in (cluster[0].get('items') or []), {'items': (cluster[0].get('items') if cluster else None)})
        lines = confirm_lines(result)
        keyed = all(isinstance(issue.get('key'), str) and KEY.fullmatch(issue['key']) and issue.get('message')
                    for _group, issue in lines)
        ids = sorted({issue.get('id') for _group, issue in lines})
        self.require('check: every confirmation line of woowtest2 is a reviewed one (odoo.databases-left, '
                     'restore.other-databases), each keyed', ids == sorted(REVIEWED) and keyed
                     and any(issue.get('database') == DATABASE for _group, issue in lines), {'ids': ids, 'keyed': keyed})
        self.partners, self.ack = partners, acknowledgement(lines)

    def judge_chain(self, records):
        ev = self.ev
        types = [job.get('type') for job in records]
        linked = (len(records) == 2 and ((records[0].get('result') or {}).get('group') or {}).get('next_job_id')
                  == records[1].get('id') and not ((records[1].get('result') or {}).get('group') or {}).get('next_job_id'))
        self.require('import: two linked jobs, the conversion then the restore, both succeeded',
                     types == ['backup', 'restore'] and linked and all(job.get('state') == 'succeeded' for job in records),
                     {'types': types, 'states': [job.get('state') for job in records]})
        convert, restore = records
        params, result = convert.get('params') or {}, convert.get('result') or {}
        imported = result.get('ha_import') or {}
        converted = result.get('backup_id')
        self.require('import: the conversion moved odoo with the database woowtest2 (choices, odoo_database), not in test '
                     'mode, with exactly the acknowledged keys',
                     params.get('apps') == [APP] and params.get('choices') == {APP: {'database': DATABASE}}
                     and params.get('odoo_database') == DATABASE and params.get('test_mode') is False
                     and imported.get('apps') == [APP] and imported.get('odoo_database') == DATABASE
                     and imported.get('test_mode') is False and (params.get('chain') or {}).get('acknowledged') == self.ack
                     and (restore.get('params') or {}).get('backup_id') == converted,
                     {'odoo_database': imported.get('odoo_database'), 'test_mode': imported.get('test_mode')})
        rows = ((restore.get('result') or {}).get('group') or {}).get('results') or []
        self.require('import: the group reports odoo imported',
                     [(row.get('app_id'), row.get('status')) for row in rows if isinstance(row, dict)] == [(APP, 'imported')])
        rresult = restore.get('result') or {}
        health = rresult.get('health') or []
        self.require('import: the restore made a safety backup, was not rolled back, every health check ok, no warning',
                     bool(rresult.get('safety_backup_id')) and rresult.get('rolled_back') is False and bool(health)
                     and all(item.get('status') == 'ok' for item in health) and not rresult.get('warnings'),
                     {'health': [item.get('status') for item in health], 'warnings': len(rresult.get('warnings') or [])})
        view = (rresult.get('kept') or {}).get(APP) or {}
        self.require('import: the restore kept a whole-cluster copy and put woowbk_lab_other back automatically, nothing '
                     'left out', isinstance(view.get('backup_id'), str) and EXTRA_DB in (view.get('databases') or [])
                     and view.get('put_back') == [EXTRA_DB] and view.get('not_put_back') == [],
                     {k: view.get(k) for k in ('databases', 'put_back', 'not_put_back')})
        ev.save('kept-view.json', view)

    # -------- the imported Odoo
    def verify_import(self):
        convert, restore = self.chain
        converted = (convert.get('result') or {}).get('backup_id')
        safety = (restore.get('result') or {}).get('safety_backup_id')
        kept = (((restore.get('result') or {}).get('kept') or {}).get(APP) or {}).get('backup_id')
        rows = {row.get('id'): row for row in self.listing()[0]}
        origin = rows.get(converted, {}).get('from_ha') or {}
        self.require('verify: the converted backup is a manual one from this HA record pointing to the kept copy, which is '
                     'listed as kept',
                     rows.get(converted, {}).get('type') == 'manual' and origin.get('ha_backup_id') == HA_ID
                     and origin.get('kept') == kept and rows.get(kept, {}).get('type') == 'safety'
                     and rows.get(kept, {}).get('kept') is True and rows.get(safety, {}).get('type') == 'safety',
                     {'converted': rows.get(converted, {}).get('type'), 'kept': rows.get(kept, {}).get('kept')})
        partners = self.partner_count()
        self.require('verify: woowtest2\'s partner count from the check reached dev-c\'s live Odoo database',
                     partners == str(self.partners), {'live': partners, 'check': self.partners})
        databases = self.databases()
        self.require('verify: the databases are exactly dev-c\'s own plus woowbk_lab_other, whose marker row survived',
                     databases == sorted(self.before['databases'] + [EXTRA_DB]) and self.marker() == f'{MARKER}|1',
                     {'databases': databases})
        facts = h.live_odoo_facts()
        self.require('verify: web.base.url and the upgrade marker are dev-c\'s own, as before the import',
                     facts == self.before['facts'])
        gate = h.owner('systemctl', '--user', 'is-active', 'odoo.service', timeout=60).stdout.decode('utf-8', 'replace').strip()
        codes = self.health()
        running, view = self.odoo_status()
        self.require('verify: odoo.service active (the upgrade gate passed), web and gateway health 200, the engine reports '
                     'Odoo running', gate == 'active' and all(code == '200' for code in codes.values()) and running,
                     {'odoo.service': gate, 'health': codes, 'status': view})

    # -------- recovery: whatever stopped the run, dev-c's own Odoo back
    def new_jobs(self):
        """Every job since the before-record (≤ 50 newest): this run's alone, it holds dev-c's lock."""
        if not self.jobs_recorded:
            return []
        return [row for row in h.ok('jobs', ev=self.ev).get('jobs') or [] if row.get('id') not in self.jobs_before]

    def settle(self):
        """Every job of this run has ended (bounded; Failed when one still runs); returns the import's chain followed
        from its root ([] when no import job exists)."""
        deadline = time.monotonic() + JOB_WAIT

        def left():
            return max(1, int(deadline - time.monotonic()))
        running = [row.get('id') for row in self.new_jobs() if row.get('state') in ('queued', 'running')]
        for job_id in dict.fromkeys(self.own_jobs + running):
            self.wait(job_id, left())
        rows = self.new_jobs()
        if self.baseline is None:   # a stop while the baseline was being made: its backup is this run's
            for row in rows:
                params, result = row.get('params') or {}, row.get('result') or {}
                if (row.get('type') == 'backup' and params.get('source') != 'ha' and params.get('apps') == [APP]
                        and row.get('state') == 'succeeded' and isinstance(result.get('backup_id'), str)):
                    self.baseline = result['backup_id']
                    self.note(baseline_id=self.baseline)
        root = self.chain_root or next((row.get('id') for row in rows if is_root(row)
                                        and (row.get('params') or {}).get('ha_backup_id') == HA_ID), None)
        if not root:
            return []
        self.chain_root = root
        return self.follow(root, left())

    def recover(self):
        ev = self.ev
        if self.baseline is None and not self.baseline_requested:
            self.restored = True   # nothing of dev-c's Odoo data was touched (the units are the cleanup's)
            return
        try:
            chain = self.settle()
        except Failed as error:
            ev.check('recovery: every job of this run ended in time (otherwise everything stays for the coordinator)', False,
                     str(error)[:200])
            return
        if self.baseline is None:
            self.restored = True   # the baseline job failed: nothing was made, nothing imported
            return
        if chain:
            self.restore_own()
        else:
            self.verify_unchanged()

    def restore_own(self):
        ev = self.ev
        started = h.ok('restore-start', {'backup_id': self.baseline, 'apps': [APP], 'confirm': True,
                                         'request_id': h.request_id('odoo-ck-own')}, ev=ev, timeout=300)
        self.own_jobs.append(started['job_id'])
        job = self.wait(started['job_id'])
        result = job.get('result') or {}
        self.own(result.get('safety_backup_id'))
        health = result.get('health') or []
        ok = ev.check('recovery: the baseline restore of dev-c\'s own Odoo succeeded (not rolled back, every health check ok)',
                      job.get('state') == 'succeeded' and result.get('rolled_back') is False and bool(health)
                      and all(item.get('status') == 'ok' for item in health),
                      {'state': job.get('state'), 'error': job.get('error')})
        if ok:
            self.compare_own('recovery: dev-c\'s own Odoo is back: facts, partner count and databases exactly as before '
                             '(woowbk_lab_other gone)')

    def verify_unchanged(self):
        """No import job exists: dev-c's own Odoo data was never touched, only the extra database is this run's."""
        if self.before is None or (h.live_odoo_facts() == self.before['facts']
                                   and self.partner_count() == self.before['partners']):
            self.compare_own('recovery: no import ran, dev-c\'s own Odoo is as before (facts, partner count, '
                             'woowbk_lab_other dropped, databases exactly as before)')
        else:
            self.restore_own()   # something changed it anyway: the baseline brings it back

    def compare_own(self, name):
        if self.before is None:
            self.restored = self.ev.check(name, not self.extra_db)
            return
        if EXTRA_DB in self.databases():
            h.psql('odoo18-db', 'postgres', 'postgres', f'DROP DATABASE {EXTRA_DB} WITH (FORCE);')
        facts, partners, databases = h.live_odoo_facts(), self.partner_count(), self.databases()
        self.restored = self.ev.check(name, facts == self.before['facts'] and partners == self.before['partners']
                                      and databases == self.before['databases'],
                                      {'partners': partners, 'databases': databases, 'facts_equal': facts == self.before['facts']})
        if self.restored:
            self.extra_db = False
            self.note(extra_database=False, restored=True)

    # -------- cleanup: only what this run made (each part on its own: one that fails does not skip the others)
    def cleanup(self):
        parts = (self.cleanup_backups, self.cleanup_ha, self.cleanup_units, lambda: h.scenario_cleanup(self.ev, SimpleNamespace()))
        for part in parts:
            try:
                part()
            except Exception as error:   # noqa: BLE001 - reported; the next part still runs
                self.ev.check(f'cleanup: failed ({type(error).__name__})', False, str(error)[:300])

    def cleanup_backups(self):
        ev = self.ev
        owned = list(self.created) + ([self.baseline] if self.baseline else [])
        name = ('cleanup: every backup this run made is deleted (the conversion, the safety backups, the kept copy, the '
                'baseline)')
        if not self.restored:   # dev-c's own Odoo is not verifiably back: the baseline and the rest stay
            ev.check(name, False, {'kept_for_the_coordinator': owned})
            return
        for backup_id in owned:
            rc, _reply = h.helper('delete', {'backup_id': backup_id})
            ev.log(f'delete {backup_id}: rc {rc}')
        left = sorted({row.get('id') for row in self.listing()[0]} & set(owned))
        self.created = [backup_id for backup_id in self.created if backup_id in left]
        self.baseline = self.baseline if self.baseline in left else None
        self.note(created_backups=list(self.created), baseline_id=self.baseline)
        ev.check(name, not left, {'owned': len(owned), 'left': left})

    def cleanup_ha(self):
        """The fixture's HA record is this run's when it was not there before (its id is the fixture's SHA-256 prefix)."""
        ev = self.ev
        if HA_ID not in self.ha_before and HA_ID in {row.get('id') for row in self.listing()[1]}:
            self.created_ha = HA_ID
        if self.created_ha and not h.ok('status', ev=ev).get('active_job'):
            rc, _reply = h.helper('ha-delete', {'ha_backup_id': self.created_ha, 'confirm': True})
            ev.log(f'ha-delete {self.created_ha}: rc {rc}')
        ha = sorted(row.get('id') for row in self.listing()[1])
        if self.created_ha not in ha:
            self.created_ha = None
        self.note(created_ha_record=self.created_ha)
        ev.check('cleanup: the HA records are as before (the one this run uploaded is deleted)', ha == self.ha_before,
                 {'left': self.created_ha})

    def cleanup_units(self):
        if self.started and self.restored:
            for unit in reversed(self.started):
                h.owner('systemctl', '--user', 'stop', unit, timeout=300)
            for unit in self.started:   # a start of this run that failed left the unit `failed`: inactive again, as found
                h.owner('systemctl', '--user', 'reset-failed', unit, timeout=60)
        states = self.units().get('units') or {}
        if self.started and all(states.get(unit) == 'inactive' for unit in self.started):
            self.started = []
            self.note(started_units=[])
        self.ev.check('cleanup: dev-c\'s Odoo units are as found (stopped again when this run started them)',
                      {unit: states.get(unit) for unit in UNIT_NAMES} == {unit: self.found.get(unit) for unit in UNIT_NAMES},
                      {'now': states, 'found': self.found})

    def leaks(self):
        parts = [lambda: h.scenario_leaks(self.ev, SimpleNamespace(secrets=self.secrets))]
        if self.via_page:   # the page logged in to Cockpit with devadmin's password
            parts.append(self.leaks_cockpit)
        parts.append(self.leaks_evidence)
        for part in parts:
            try:
                part()
            except Exception as error:   # noqa: BLE001 - a scan that cannot run fails, the next one still runs
                self.ev.check(f'leaks: scan failed ({type(error).__name__})', False, str(error)[:300])

    def leaks_cockpit(self):
        proc = h.root('python3', '-I', '-c', h.LEAK_SCAN, input=json.dumps([self.secrets['COCKPIT_PASSWORD']]).encode(),
                      timeout=600)
        try:
            report = json.loads(proc.stdout.decode('utf-8', 'replace').strip().splitlines()[-1])
        except (ValueError, IndexError):
            report = None
        self.ev.save('leaks-cockpit-login.json', report if isinstance(report, dict) else {})
        self.ev.check('no Cockpit login password in the engine\'s records, logs, index, registry or the device journal',
                      isinstance(report, dict) and not report.get('hits') and report.get('scanned', 0) > 0,
                      {'scanned': (report or {}).get('scanned'), 'journal_bytes': (report or {}).get('journal_bytes')})

    def leaks_evidence(self):
        values = [value for value in self.secrets.values.values() if isinstance(value, str) and len(value) >= 6]
        found = scan_evidence(self.ev.dir, values)
        self.ev.check('leaks: no registered value (HA key, HA test credentials, Cockpit password) in this run\'s private '
                      'evidence', found['hits'] == 0 and found['files'] > 0,
                      {'files': found['files'], 'values': len(values), 'hits': found['hits']})

    def after(self):
        ev = self.ev
        try:
            h.require_isolated_device()
            isolated = True
        except Failed:
            isolated = False
        ev.check('after: dev-c still runs with network none and no published port', isolated)
        if not self.changed:
            return
        backups, ha = self.listing()
        now = sorted(row.get('id') for row in backups)
        ev.check('after: dev-c\'s backups and HA records are exactly the ones it had before',
                 now == self.backups_before and sorted(row.get('id') for row in ha) == self.ha_before,
                 {'new': sorted(set(now) - set(self.backups_before or [])),
                  'gone': sorted(set(self.backups_before or []) - set(now))})
        files = self.units().get('sha256')
        ev.check('after: the Odoo Quadlets and env file are byte for byte as before, no job running',
                 files == self.files_before and not h.ok('status', ev=ev).get('active_job'),
                 {'files_equal': files == self.files_before})

    def finish_receipt(self):
        if not self.changed:
            return
        complete = (self.restored and not self.created and not self.baseline and not self.created_ha
                    and not self.started and not self.extra_db)
        self.note(restored=self.restored, complete=complete, signals_ignored=SIGNALS['ignored'])


def run_all(run):
    """The run's phases, then -- whatever stopped them -- the recovery, cleanup, leak scans and the after checks."""
    ev = run.ev
    steps = (('preflight', run.preflight), ('setup', run.setup), ('before', run.step_before),
             ('baseline', run.step_baseline), ('extra database', run.step_extra_db),
             ('import', run.step_page_import if run.via_page else run.step_import), ('verify', run.verify_import))
    failed = None
    try:
        for name, step in steps:
            run.budget(name)
            ev.log(f'== {name}')
            step()
    except (Exception, Stopped) as error:   # noqa: BLE001 - any stop (Failed, a signal, an error): the recovery runs
        failed = error
        ev.check(f'run stopped in a step ({type(error).__name__})', False, str(error)[:300])
    finally:
        SIGNALS['recovering'] = True
        parts = (('recovery', run.recover), ('cleanup', run.cleanup), ('leaks', run.leaks)) if run.changed else ()
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
    for program in (UNITS_PROGRAM, HEADROOM, ENGINE_HASHES):
        compile(program, '<device program>', 'exec')
    assert HA_ID == 'ha-1840b054568cb54d9b79' and len(FIXTURE_SHA) == 64
    for item in SUBSTITUTE.values():
        assert '@sha256:' in item['ref'] and len(item['id']) == 64 and '@sha256:' in item['source']
    assert set(ENV_IMAGES.values()) <= set(SUBSTITUTE) and set(REPIN_SHA) == set(SUBSTITUTE) | {'env'}
    # The acknowledgement rule on the shape of the 11-26 check: two database lines, the whole-cluster line, notices.
    key = {name: f'{name}:{n:016x}' for n, name in enumerate(('odoo.databases-left', 'restore.other-databases'), 1)}
    result = {'shared': [], 'apps': [{'app_id': APP, 'importable': True, 'issues': [
        {'id': 'odoo.databases-left', 'level': 'confirm', 'database': 'woowtest', 'key': 'odoo.databases-left:' + 'a' * 16},
        {'id': 'odoo.databases-left', 'level': 'confirm', 'database': DATABASE, 'key': key['odoo.databases-left']},
        {'id': 'restore.other-databases', 'level': 'confirm', 'database': None, 'key': key['restore.other-databases']},
        {'id': 'odoo.crons-active', 'level': 'notice', 'database': DATABASE}]}]}
    assert acknowledgement(confirm_lines(result)) == {APP: sorted(key.values())}
    assert keep_last({'default_keep_last': 5, 'apps': {APP: {'keep_last': None}}}, APP) is None
    assert safety_at_risk([{'id': 'a', 'type': 'safety', 'apps': [{'id': APP}]},
                           {'id': 'b', 'type': 'safety', 'kept': True, 'apps': [{'id': APP}]},
                           {'id': 'c', 'type': 'safety', 'apps': [{'id': 'n8n'}]}]) == ['a']
    assert owned_from([{'type': 'backup', 'result': {'backup_id': 'c1'}},
                       {'type': 'restore', 'result': {'safety_backup_id': 's1', 'kept': {APP: {'backup_id': 'k1'}}}}]) \
        == ['c1', 's1', 'k1']
    assert all(len(label(name)) == len(name) for name in (
        'preflight: no earlier Odoo safety backup that this run\'s two restores would make the product prune (keep 3 newest)',
        'import: the restore kept a whole-cluster copy and put woowbk_lab_other back automatically, nothing left out'))
    print('self-check: PASS')
    return 0


# ---------------------------------------------------------------- command line

def admission(args):
    """Before the lock, the secrets or the device: [(label, ok)] of what must hold for a run to start."""
    product = Path(args.source or REPO)
    sha = sha256_file(FIXTURE) if FIXTURE.is_file() and not FIXTURE.is_symlink() else None
    return [('admission: the heavy seat (HEAVY_FREE is the dev-c lock: run through heavy.sh)',
             os.environ.get('HEAVY_FREE') == LOCK),
            ('admission: the checkout and the product source have no tracked change', clean(REPO) and clean(product)),
            ('admission: the product source holds the cold-keep fixes 816e4889 and 647fe670',
             all(holds_cold_keep(product).values())),
            ('admission: no earlier run of this case is pending', not Receipt(LAB / 'run' / 'odoo_cold_keep_flow.json').pending()),
            ('admission: the fixture is the recorded real x86 encrypted Odoo and n8n HA backup', sha == FIXTURE_SHA)]


def load_secrets(via_page):
    secret_dir = LAB / 'secrets'
    secrets = h.Secrets(secret_dir / 'ha-import-creds.env', secret_dir / 'ha-import-n8n-testdata.sh')
    if via_page:   # devadmin's Cockpit login (shared by every lab device): redacted and scanned like the others
        secrets.values['COCKPIT_PASSWORD'] = (secret_dir / 'devadmin.pass').read_text(encoding='utf-8').strip()
    return secrets


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--run', action='store_true')
    parser.add_argument('--self-check', action='store_true')
    parser.add_argument('--via-page', action='store_true',
                        help='upload, check and import through dev-c\'s real Cockpit page (focus_page_bridge.py)')
    parser.add_argument('--source', type=Path,
                        help='the product checkout whose engine and page dev-c runs (default: this checkout)')
    args = parser.parse_args(argv)
    if args.self_check or not args.run:
        return self_check()
    refused = [name for name, ok in admission(args) if not ok]
    if refused:
        for name in refused:
            emit(f'{label(name)}: FAIL')
        return 2
    try:
        secrets = load_secrets(args.via_page)
        missing = [name for name in LEAK_NAMES + (('COCKPIT_PASSWORD',) if args.via_page else ())
                   if len(secrets.values.get(name) or '') < (16 if name == 'HA_BACKUP_KEY' else 6)]
    except (OSError, UnicodeDecodeError, Failed):
        missing = ['unreadable']
    if missing:   # never a value
        emit(f'{label("admission: the test credential files name every value the run and its leak scan need")}: FAIL')
        return 2
    args.secrets = secrets
    commit = git(REPO, 'rev-parse', 'HEAD')[1]
    emit(f'source commit {commit}')
    ev = Ev(secrets)
    ev.save('run.json', {'source_commit': commit, 'product': str(args.source or REPO), 'via_page': args.via_page,
                         'product_commit': git(args.source or REPO, 'rev-parse', 'HEAD')[1], 'substitute_images': True,
                         'commercial_acceptance': 'not-complete', 'original_tenant_acceptance': False})
    fd = os.open(LOCK, os.O_RDWR | os.O_CREAT, 0o600)
    waited = time.monotonic()
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            break
        except BlockingIOError:
            if time.monotonic() - waited > LOCK_WAIT:
                os.close(fd)
                emit('lock: FAIL')
                return 3
            time.sleep(5)
    previous = {signum: signal.signal(signum, _stop) for signum in (signal.SIGTERM, signal.SIGINT)}
    run = Run(args, ev)
    run.lock_started = time.monotonic()
    try:
        ok = run_all(run)
    finally:
        emit(f'lock held for {int(time.monotonic() - run.lock_started)} s')
        for signum, handler in previous.items():
            signal.signal(signum, handler)
        SIGNALS['recovering'] = False
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
    passed = ev.finish()
    results = ev.results
    emit(f'odoo cold keep flow: {sum(r["ok"] for r in results)}/{len(results)} {"PASS" if ok and passed else "FAIL"}')
    return 0 if ok and passed else 1


if __name__ == '__main__':
    sys.exit(main())
