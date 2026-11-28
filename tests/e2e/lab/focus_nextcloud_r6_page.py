#!/usr/bin/env python3
"""R6-style case: the NO-SHARE Nextcloud HA import through dev-e's REAL Cockpit page (focus_page_bridge), cold to cold.

  python3 -I tests/e2e/lab/focus_nextcloud_r6_page.py                   offline: the plan (no device, no secret)
  python3 -I tests/e2e/lab/focus_nextcloud_r6_page.py --lease-template  the lease fields this checkout binds
  HEAVY_FREE=/tmp/woowbk-dev-e-mutation.lock .../heavy.sh python3 -I tests/e2e/lab/services_a_capture.py \\
      --private=FILE <evidence.json> nextcloud-x86-noshare-page -- \\
      python3 -I tests/e2e/lab/focus_nextcloud_r6_page.py --run --lease FILE

The real x86 showcase backup WITHOUT HA's share folder (woow-b2-nextcloud-x86-enc-noshare, add-on 0.2.3) is importable
with one line to confirm, nextcloud.no-share (the users' files stay behind); on 2026-11-26 it took 36/36 through the
helper's one-action import (ha-import-start; the parity-real scratchpad's nextcloud_noshare_full.py). Here the page makes
that import: it uploads the file, selects only nextcloud, takes the HA key, shows the check and its one confirmation (the
lines read from the actual check), ticks it once and starts the import (the conversion and its restore as two linked
jobs in one unit). nextcloud_flow.py and the R6 modules are used as they are; the whole run holds
/tmp/woowbk-dev-e-mutation.lock (the bridge requires this very process to hold it) and keeps the R6 safety model:

  admission  a committed checkout, an exact lease (lane nextcloud-r6, phase noshare-page, this commit, the fixture, the
             pin policy, the 13 GiB reserve, the 3 GiB device cap, 75 minutes left), the heavy seat (HEAVY_FREE = the
             dev-e lock); dev-e network none without a port, the five original images loaded, every Nextcloud unit
             inactive (cold), host and device memory and disk (focus_nextcloud_r6_case.admission), the host reserve after
             the import's historical peak, no job running, no earlier run of this case pending
  deploy     the scheduled-backup timer masked; deploy-src.sh e --src <this checkout> --no-demo-catalog while Nextcloud is
             cold: the page the bridge requires and this checkout's engine (nextcloud_flow's model; R6's frozen-product
             source transaction installs no page)
  wake       the five Quadlets pinned to their loaded config IDs (same config only; the exact prior bytes kept and put
             back), the stack started under the R6 resource watch, batch2_baseline.py --verify nextcloud before the import
  case       setup (engine == tree, the original catalog entry, five healthy units, a device key), before (the encrypted
             baseline opens with the existing kit, dev-e's markers and own account, fresh live sizes), the page import
             (the reserve after its peak from the live sizes), the same facts as the helper path on the page's own check
             and chain jobs, the import verified (status.php, HA's users live and dev-e's marker user gone, OCS login and
             a refused wrong password, Office settings and cron mode exactly this device's, Office capabilities, the
             discovery, a new data fingerprint, nothing served below the data dir, storage and table owners), the manual
             rollback (the import's safety backup restored: markers exact, HA-only users gone, dev-e's own login, the
             baseline verified), after (everything read before is unchanged)
  cleanup    only what this run made (the R6 guard): the page's converted backup and the safety backups (never the
             baseline), the HA record when the page's upload created it; no job object, staging folder or key file; the
             leak scan (HA key, HA test credentials, dev-e's marker password, devadmin's Cockpit password, the kit)
  return     no job running, the stack stopped cold (only this run's own Office failed flag cleared), the Quadlets back
             byte for byte, the timer as found; units, Quadlets, images, catalog, baseline archive, isolation and memory
             cap as before; the installed engine modules are this checkout's

A whole-run watchdog (R6 ResourceWatch) stops the run on a reserve or memory breach or at the lease end and cancels only
jobs this run started (new since its start). Whatever stops the case, the import's safety backup is restored first (the
recovery), the baseline verified and the stack returned cold, within 30 minutes past the lease; backups are cleaned up
only once dev-e's own Nextcloud is verifiably back (otherwise they stay for the coordinator, the receipt stays pending).
The page acknowledges whatever its check lists and imports in the same flow: the reviewed outcome (nextcloud.no-share the
only line to confirm) is judged on the page's own check after the import, and a failure there is recovered as above.
stdout: fixed lines only (`<check>: PASS|FAIL`, the source commit, the lock time and the count line).
"""
import argparse
import datetime
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import focus_nextcloud_r6 as r6                    # noqa: E402  ResourceWatch, owned_command (no I/O at import)
import focus_nextcloud_r6_case as control          # noqa: E402  admission, QUIESCENT, RESOURCE, BASELINE_INSPECT
import focus_nextcloud_r6_cold as cold             # noqa: E402  CLAIM, stop (only this run's own Office flag)
import focus_nextcloud_r6_wake as wake             # noqa: E402  unit_program (pin/revert), CONTROL, BASELINE_HASH
from focus_nextcloud_r6_inventory import collect   # noqa: E402
from focus_nextcloud_r6_plan import (BASELINE, DEVICE_CAP, GIB, MARGIN, RESERVE,  # noqa: E402
                                      acceptance_budget, lease_check)

REPO = HERE.parents[2]
LAB = Path.home() / '.woowbk-lab'
LOCK = '/tmp/woowbk-dev-e-mutation.lock'
DEVICE = 'woowbk-dev-e'
PHASE = 'noshare-page'
RECEIPT_NAME = 'focus_nextcloud_r6_page.json'      # LAB/run/<this>: the run's own receipt (R6's stays untouched)
PIN_POLICY = control.PIN_POLICY                    # same config only, private copy, revert
RECOVERY_GRACE = 1800                              # recovery and the cold return may run this long past the lease
LEASE_HEADROOM = 75 * 60                           # lease seconds still left when the dev-e lock is held
CASE_BUDGET = 100 * 60                             # timed steps of the case (never the recovery)
PAGE_STEP_BUDGET = 25 * 60                         # the page's own 20 minutes and reading its jobs
REST_RESERVE = 20 * 60                             # kept after the page: verify, the manual rollback, after, cleanup
WATCH_INTERVAL = 2
TIMER = 'woowtech-cockpit-backup-schedule.timer'
ORIGINAL_CATALOG_SHA = '3a7af03b966f90a172e417a3ea69d7b36bf98a23af8d27b0c074bd01b6f335d6'   # R6 setup's binding
HA_USER = 'woow-import-test'                       # the HA test user of the no-share backup (showcase lane)
APPS = ['nextcloud']
NO_SHARE = 'nextcloud.no-share'
ENGINE_MODULES = ('ha_nextcloud.py', 'haadapters.py', 'haapps.py', 'hacommands.py', 'flows.py', 'hatarget.py',
                  'habackup.py')                   # what the R6 inventory hashes in dev-e
# The historical live sizes R6's plan uses (html, postgres, data): the admission's estimate of the import's peak;
# the case recomputes it from fresh sizes before the page.
HISTORICAL_SIZES = (849259813, 75382634, 234187031)


def _load(name, alias=None):
    # -I removes the script directory from sys.path: load the adjacent module explicitly.
    spec = importlib.util.spec_from_file_location(alias or name, HERE / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def emit(line):
    print(line, flush=True)


def load_flow():
    """nextcloud_flow.py as this case uses it: the R6 reserve as its floors, this case's own receipt."""
    nc = _load('nextcloud_flow', 'focus_r6_page_flow')
    nc.FLOOR = nc.WATCH_FLOOR = RESERVE
    nc.drv.state_path = lambda: LAB / 'run' / RECEIPT_NAME
    return nc


def baseline_verify():
    """The independent read-only verifier (batch2_baseline.py --verify nextcloud), private output."""
    p = subprocess.run([sys.executable, '-I', str(HERE / 'batch2_baseline.py'), '--verify', 'nextcloud'],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1200)
    return p.returncode == 0


def expiry(lease):
    return datetime.datetime.fromisoformat(lease['expires_utc'].replace('Z', '+00:00')).timestamp()


def page_peak(sizes, fixture_bytes):
    """The import's additional peak on dev-e's disk (R6 acceptance_budget: the upload, the conversion, then the restore
    with the converted and safety copies kept), from (html, postgres, data) live sizes."""
    html, pg, data = sizes
    return acceptance_budget(html, pg, data, GIB, GIB, uploaded=fixture_bytes)


# Read-only client of the imported Nextcloud (as appowner inside dev-e): codes and booleans only, never a value.
NOSHARE_CLIENT = r'''
import base64, json, subprocess, sys, urllib.error, urllib.request
REQ = json.loads(sys.stdin.read())
NC = "http://127.0.0.1:18081"
def call(method, path, user=None, password=None, headers=None):
    h = dict(headers or {})
    if user is not None:
        h["Authorization"] = "Basic " + base64.b64encode(("%s:%s" % (user, password)).encode()).decode()
    req = urllib.request.Request(NC + path, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
def sql(statement):
    p = subprocess.run(["podman", "exec", "nextcloud-db", "psql", "-X", "-At", "-U", "nextcloud", "-d", "nextcloud",
                        "-c", statement], capture_output=True, timeout=120)
    return p.stdout.decode().strip() if p.returncode == 0 else None
def app_sh(script, *args):
    p = subprocess.run(["podman", "exec", "-u", "www-data", "nextcloud-app", "sh", "-c", script, "sh", *args],
                       capture_output=True, timeout=300)
    return p.stdout.decode("utf-8", "replace").strip() if p.returncode == 0 else "rc%d" % p.returncode
user, pw = REQ["user"], REQ["user_pw"]
out = {}
code, body = call("GET", "/status.php")
try:
    status = json.loads(body) if code == 200 else {}
except ValueError:
    status = {}
out["status"] = {k: status.get(k) for k in ("installed", "version", "maintenance", "needsDbUpgrade")}
ocs = {}
for kind, secret in (("password", pw), ("wrong", pw + "-wrong")):
    c, data = call("GET", "/ocs/v2.php/cloud/user?format=json", user, secret, {"OCS-APIRequest": "true"})
    try:
        ident = json.loads(data)["ocs"]["data"]["id"] if c == 200 else None
    except (ValueError, KeyError, TypeError):
        ident = None
    ocs[kind] = [c, ident == user]
out["ocs"] = ocs
c, data = call("GET", "/ocs/v2.php/cloud/capabilities?format=json", user, pw, {"OCS-APIRequest": "true"})
office = None
if c == 200:
    try:
        rd = json.loads(data)["ocs"]["data"]["capabilities"].get("richdocuments") or {}
        cfg = rd.get("config") if isinstance(rd.get("config"), dict) else {}
        col = rd.get("collabora")
        office = {"keys": sorted(rd)[:40], "config": {k: cfg[k] for k in ("wopi_url", "public_wopi_url", "wopi_callback_url",
                                                                       "disable_certificate_verification") if k in cfg},
                  "collabora": sorted(col)[:30] if isinstance(col, dict) else bool(col),
                  "product": str(rd.get("productName") or "")[:60]}
    except (ValueError, KeyError, TypeError, AttributeError):
        office = "unreadable"
out["capabilities"] = [c, office]
c, data = call("GET", "/hosting/discovery")
out["discovery"] = [c, b"<wopi-discovery" in data and b"urlsrc" in data]
out["web"] = {"control": call("GET", "/core/img/logo/logo.svg")[0],
              "codes": [call("GET", p)[0] for p in ("/data/.ncdata", "/data/index.html", "/data/nextcloud.log")],
              "htaccess": app_sh("sha256sum /var/www/html/data/.htaccess | cut -c1-64"),
              "htaccess_below": app_sh('find /var/www/html/data -mindepth 2 -name .htaccess | wc -l')}
out["storage"] = sql("SELECT id FROM oc_storages WHERE id LIKE 'local::%' ORDER BY numeric_id")
out["owners"] = sql("SELECT string_agg(DISTINCT tableowner, ',') FROM pg_tables WHERE schemaname = 'public'")
print(json.dumps(out))
'''


# ---------------------------------------------------------------- lease

def lease_template(commit):
    """The lease fields this checkout binds; the time window is the coordinator's."""
    nc = load_flow()
    return {'device': DEVICE, 'lane': 'nextcloud-r6', 'phases': [PHASE], 'source_commit': commit,
            'reserve_bytes': RESERVE, 'memory_cap_bytes': DEVICE_CAP, 'not_before_utc': '<UTC start>',
            'expires_utc': '<UTC end, at least 75 minutes after the lock is held>',
            'fixture_sha256': nc.FIXTURE_SHA, 'pin_refresh_policy': PIN_POLICY,
            'recovery_grace_seconds': RECOVERY_GRACE, 'source_deployment': 'deploy-src-this-checkout',
            'page_device': DEVICE}


def admit_lease(lease, commit, fixture_sha, now=None):
    """The exact lease of this checkout (lease_check: device, lane, phase, commit, reserve, cap, window) with every bound
    value and LEASE_HEADROOM left; raises ValueError with a fixed reason."""
    lease_check(lease, commit, PHASE)
    if (lease.get('fixture_sha256') != fixture_sha or lease.get('pin_refresh_policy') != PIN_POLICY
            or lease.get('recovery_grace_seconds') != RECOVERY_GRACE
            or lease.get('source_deployment') != 'deploy-src-this-checkout' or lease.get('page_device') != DEVICE):
        raise ValueError('fixed-r6-page-lease-binding-refused')
    if expiry(lease) - (time.time() if now is None else now) < LEASE_HEADROOM:
        raise ValueError('fixed-r6-page-lease-headroom-required')


# ---------------------------------------------------------------- the case (inside the woken stack)

def make_run(nc, bridge, ev, secrets, lease, commit, case):
    """nextcloud_flow.Run for this case: R6's budget and guards, the page import, the no-share verification, R6's manual
    rollback and leak scan. `case` holds the run's shared state (tripped, inflight, jobs_before, expires)."""
    d = nc.drv

    def require(label, ok, detail=''):
        if not ev.check(label, ok, detail):
            raise nc.Failed(label)

    class Run(nc.Run):
        imported_users = None
        baseline_verified = False
        after_done = False

        def budget(self, phase, need=0, *, timed=True):
            if not timed and time.time() >= case.expires + RECOVERY_GRACE:
                raise nc.Failed('fixed-recovery-grace-expired')
            if timed:
                lease_check(lease, commit, PHASE)
                if time.monotonic() - self.lock_started > CASE_BUDGET or case.tripped.is_set():
                    raise nc.Failed('fixed-case-budget-reached')
            if wake.device(control.RESOURCE, root=True, timeout=30)['free'] < RESERVE + MARGIN + need:
                raise nc.Failed('fixed-reserve-preflight-refused')

        def watch_host(self, stop, tripped):
            stop.wait()   # the whole-run watchdog owns cancellation

        # -------- setup and before
        def setup(self):
            installed = d.device_python(nc.ENGINE_HASHES, as_owner=False)
            tree = nc.tree_hashes()
            differ = sorted(k for k in set(tree) | set(installed) if tree.get(k) != installed.get(k))
            require('setup: the installed engine is exactly this tree', not differ, {'modules': len(tree), 'differ': differ[:10]})
            status = d.ok('status', ev=ev)
            require('setup: the helper answers status with this tree\'s VERSION; a device key exists',
                    status.get('version') == (REPO / 'VERSION').read_text().strip()
                    and bool((status.get('key') or {}).get('key_id')), status.get('version'))
            entry = d.catalog('nextcloud')
            ev.save('catalog-nextcloud.json', entry)
            require('setup: the original nextcloud catalog entry (R6 hash) names the five units and the four data dirs',
                    case.before['root']['catalog_sha256'] == ORIGINAL_CATALOG_SHA
                    and set(nc.UNITS) <= set(entry.get('units') or []) and not entry.get('postgres')
                    and not entry.get('volumes') and len(entry.get('data_dirs') or []) == 4,
                    {'units': entry.get('units'), 'data_dirs': len(entry.get('data_dirs') or [])})
            state = self.state()
            ev.save('state-setup.json', state)
            status = state.get('status') or {}
            require('setup: five units active and Nextcloud healthy (status.php installed 35.0.1.1, no maintenance)',
                    set(state.get('units') or {}) == set(nc.UNITS)
                    and all(v == 'active' for v in state['units'].values()) and status.get('installed') is True
                    and status.get('version') == '35.0.1.1' and status.get('maintenance') is False,
                    {'units': state.get('units'), 'status': status})

        def before_state(self):
            inspected = wake.device(control.BASELINE_INSPECT, {'key': secrets['R6_BASELINE_KIT']}, root=True, timeout=900)
            ev.save('original-encrypted-baseline-inspect.json', inspected)
            require('before: the original encrypted baseline opens with the existing private kit (preflight in place)',
                    inspected.get('encrypted_manifest_opened') is True
                    and inspected.get('preflight_ok_settings_same_inplace') is True)
            super().before_state()
            sizes = self.before['sizes']
            require('before: fresh live directory sizes available',
                    all(isinstance(sizes.get(k), int) for k in ('html', 'postgres', 'data')), sizes)

        # -------- the page import
        def adopt_page(self, summary, existed):
            """What the page created goes to this run's own cleanup at once, before any judgement can stop the run."""
            for backup_id in summary.get('created_backups') or []:
                if backup_id != BASELINE:
                    d.created_backup(backup_id)
            self.store_id = 'ha-' + nc.FIXTURE_SHA[:20]
            if not existed:
                try:
                    present = self.store_id in {h.get('id') for h in d.ok('list', ev=ev).get('ha_backups') or []}
                except (nc.Failed, subprocess.TimeoutExpired, OSError, ValueError, KeyError):
                    present = True   # unknown: the cleanup tries to delete it and says whether that worked
                if present:
                    self.created_store = self.store_id
                    d.STATE['ha_backup_id'] = self.store_id   # the R6 guard: only this record may be deleted
            d.save_state()

        def page_import(self):
            sizes = self.before['sizes']
            bound = page_peak((sizes['html'], sizes['postgres'], sizes['data']), nc.FIXTURE.stat().st_size)
            ev.save('page-budget.json', bound)
            free = wake.device(control.RESOURCE, root=True, timeout=30)['free']
            require('page import: dev-e keeps the 13 GiB reserve after the import\'s peak (upload, check, conversion and '
                    'restore, from the live sizes)', free >= RESERVE + MARGIN + bound['additional_peak_bytes'],
                    {'free_mib': free >> 20, 'peak_mib': bound['additional_peak_bytes'] >> 20})
            listing = d.ok('list', ev=ev)
            before_ids = {b['id'] for b in listing['backups']}
            existed = 'ha-' + nc.FIXTURE_SHA[:20] in {h.get('id') for h in listing.get('ha_backups') or []}
            ops = bridge.Ops(helper=lambda command, request=None: d.ok(command, request, ev=ev),
                             wait_job=lambda job_id, timeout: d.wait_job(job_id, ev=ev, timeout=timeout),
                             root_json=lambda script, request: d.device_python(script, request, as_owner=False, timeout=300))
            now = time.monotonic()
            deadline = min(now + PAGE_STEP_BUDGET, now + (case.expires - time.time()) - REST_RESERVE)
            try:
                page = bridge.import_via_page(device=DEVICE, lock=LOCK, apps=list(APPS), importable=list(APPS), stops=[],
                                              fixture=nc.FIXTURE, key=secrets['HA_BACKUP_KEY'],
                                              password=secrets['COCKPIT_PASSWORD'], evidence=ev.dir / 'page',
                                              deadline=deadline, ops=ops, source=REPO)
            except bridge.BridgeError as error:
                self.adopt_page(error.summary, existed)
                ev.check('page import: refused before the page started (nothing changed)'
                         if isinstance(error, bridge.Refused)
                         else 'page import: stopped by a signal (the browser closed in order, the relay reaped)', False,
                         {'reasons': error.summary.get('reasons'), 'phase': error.summary.get('phase'),
                          'check_job_ids': error.summary.get('check_job_ids'),
                          'root_job_ids': error.summary.get('root_job_ids')})
                raise nc.Failed('page import did not run to the end') from None
            self.adopt_page(page.summary, existed)
            summary, gates = page.summary, page.gates
            for item in page.browser_checks:
                ev.check(f'page: {item.get("check")}', item.get('ok') is True)
            ev.check('page: bounded (20 min), the browser closed in order and every relay exec child reaped',
                     gates.get('page_bounded') and gates.get('cleanup'), summary.get('page'))
            ev.check('page: the uploaded HA record is the fixture (id and SHA-256)', gates.get('record'),
                     {'ha_id': summary.get('ha_id'), 'existed_before': summary.get('ha_record_existed')})
            ev.check('page: exactly the page\'s own check and import jobs, none left running, no other new backup',
                     gates.get('own_jobs') and gates.get('no_unexplained_backups'),
                     {'check': summary.get('check_job_id'), 'chain': summary.get('chain_job_ids'),
                      'unexplained': summary.get('unexplained_new_backups'), 'reasons': summary.get('reasons')})
            ev.check('page: the check calls nextcloud importable, stops nothing, and lists every confirmation line keyed '
                     '(read from the actual check)', gates.get('expected_outcome'),
                     {'lines': summary.get('confirmation_lines'),
                      'groups': sorted(summary.get('expected_acknowledged') or {}), 'reasons': summary.get('reasons')})
            ev.check('page: the one acknowledgement, the import and its jobs carry every listed confirmation key exactly '
                     'once', gates.get('acknowledged_exact'))
            ev.check('page: one conversion and its restore succeeded as two linked jobs in the first job\'s unit',
                     gates.get('chain') and gates.get('native_units'), {'jobs': summary.get('chain_job_ids')})
            ev.check('page: every issued Cockpit session value is absent from the records, the journal and the private '
                     'evidence', gates.get('issued_scan'), (summary.get('browser') or {}).get('issued_scan'))
            if len(page.chain) == 2:   # the import's safety backup is known at once (recovery needs it even on a FAIL)
                self.safety = ((page.chain[1].get('result') or {}).get('safety_backup_id')) or None
            if not page.passed:
                raise nc.Failed('page import')
            record = next((h for h in d.ok('list', ev=ev).get('ha_backups') or [] if h.get('id') == self.store_id), {})
            found = {a.get('app_id'): a.get('installed') for a in record.get('importable_apps') or []}
            ev.check('upload: nextcloud is importable and installed here', found.get('nextcloud') is True, found)
            job = page.check_job
            require('check: the page\'s check job succeeded', job.get('state') == 'succeeded', job.get('error'))
            self.judge_check(job)
            convert, restore = page.chain
            ev.save('convert-job.json', {'state': convert.get('state'), 'error': convert.get('error'),
                                         'result': convert.get('result')})
            require('import: the page\'s conversion job succeeded with a backup id',
                    convert.get('state') == 'succeeded' and bool((convert.get('result') or {}).get('backup_id')),
                    convert.get('error'))
            self.judge_convert(convert, before_ids)
            ev.save('restore-job.json', {'state': restore.get('state'), 'error': restore.get('error'),
                                         'health': (restore.get('result') or {}).get('health')})
            self.judge_restore(restore)

        def judge_check(self, job):
            """The facts of the page's own check: the reviewed outcome (nextcloud.no-share the only line to confirm,
            nothing stops), the backup's section, the versions, no throwaway object left."""
            result = (job.get('result') or {}).get('ha_check') or {}
            apps = result.get('apps') or []
            app = apps[0] if len(apps) == 1 else {}
            ev.save('check-result.json', result)
            issues = [i for i in (result.get('shared') or []) + (app.get('issues') or []) if isinstance(i, dict)]
            confirms = [i for i in issues if i.get('level') == 'confirm']
            require('check: the job answers one app: nextcloud importable, the missing share folder (nextcloud.no-share) '
                    'its only line to confirm, nothing stops',
                    app.get('app_id') == 'nextcloud' and app.get('importable') is True
                    and [i.get('id') for i in confirms] == [NO_SHARE] and bool(confirms[0].get('key'))
                    and not any(i.get('level') == 'stop' for i in issues),
                    {'importable': app.get('importable'), 'lines': [(i.get('id'), i.get('level')) for i in issues]})
            section = self.section = app.get('nextcloud') or {}
            differ = {k: [v, section.get(k)] for k, v in nc.SECTION.items() if section.get(k) != v}
            ev.check('check: the section equals the backup facts (HA cluster opened and read: users, files, tokens, apps)',
                     not differ, differ or section)
            ev.check('check: amd64, add-on 0.2.3, target 35.0.1.1',
                     (app.get('arch'), app.get('version'), app.get('target_version')) == ('amd64', '0.2.3', '35.0.1.1'),
                     {k: app.get(k) for k in ('arch', 'version', 'target_version')})
            leftovers = d.labelled()
            ev.check('check: no throwaway container, volume or network left', not any(leftovers.values()), leftovers)

        def judge_convert(self, job, before_ids):
            result = job.get('result') or {}
            self.converted = result['backup_id']
            d.created_backup(self.converted)
            row = result.get('ha_import') or {}
            ev.check('import: the notes and reminders name Collabora and the MCP admin lines',
                     row.get('apps') == ['nextcloud'] and row.get('test_mode') is False
                     and any('Collabora' in n for n in row.get('notes') or [])
                     and any('Woow Nextcloud MCP Server' in r for r in (row.get('reminders_by_app') or {}).get('nextcloud') or []),
                     {'notes': len(row.get('notes') or []), 'reminders': len((row.get('reminders_by_app') or {}).get('nextcloud') or [])})
            listed = next((b for b in d.ok('list', ev=ev).get('backups') or [] if b['id'] == self.converted), {})
            ev.check('import: the converted backup is listed as manual with its HA origin, encrypted',
                     self.converted not in before_ids and listed.get('type') == 'manual'
                     and (listed.get('from_ha') or {}).get('ha_backup_id') == self.store_id and bool(listed.get('key_id')),
                     {'type': listed.get('type'), 'from_ha': bool(listed.get('from_ha')), 'size': listed.get('size')})

        def judge_restore(self, job):
            result = job.get('result') or {}
            self.safety = result.get('safety_backup_id') or self.safety
            d.created_backup(self.safety)
            health = result.get('health') or []
            require('import: the page\'s restore of the converted backup succeeded with a safety backup, not rolled back, '
                    'every health check ok', job.get('state') == 'succeeded' and bool(result.get('safety_backup_id'))
                    and result.get('rolled_back') is False and bool(health) and all(h.get('status') == 'ok' for h in health),
                    {'state': job.get('state'), 'error': job.get('error'), 'downtime_s': result.get('downtime_seconds')})
            d.save_state()

        # -------- the imported Nextcloud
        def verify_import(self):
            found = d.device_python(NOSHARE_CLIENT, {'user': HA_USER, 'user_pw': secrets['B2_NC_X86_NOSHARE_USER_PW']},
                                    timeout=900)
            state = self.state()
            ev.save('client-import.json', {'client': found, 'state': state})
            self.imported_users = list(state.get('users') or [])
            status = found.get('status') or {}
            ev.check('import: status.php installed 35.0.1.1, no maintenance, no database upgrade needed',
                     status.get('installed') is True and status.get('version') == '35.0.1.1'
                     and status.get('maintenance') is False and status.get('needsDbUpgrade') is False, status)
            users = self.imported_users
            ev.check('import: HA\'s users are live (the HA test user there, dev-e\'s own marker user gone, the check\'s '
                     'user count)', HA_USER in users and nc.BASE_USER not in users and len(users) == nc.SECTION['users'],
                     {'users': users})
            ocs = found.get('ocs') or {}
            ev.check('import: the HA test user logs in (OCS, HA\'s password moved); a wrong password gets 401',
                     ocs.get('password') == [200, True] and (ocs.get('wrong') or [None])[0] == 401, ocs)
            before = self.before['state']
            ev.check('import: Office settings (richdocuments wopi keys) and the cron mode are exactly this device\'s',
                     state.get('office') == before.get('office') and bool(before.get('office')),
                     {'before': before.get('office'), 'now': state.get('office')})
            caps = found.get('capabilities') or [None, None]
            base_caps = (self.before.get('client') or {}).get('capabilities') or [None, None]
            ev.check('import: Nextcloud reports this device\'s Office server (capabilities as for dev-e\'s own account)',
                     caps[0] == 200 and isinstance(caps[1], dict) and caps[1] == base_caps[1],
                     {'now': caps, 'before': base_caps})
            ev.check('import: Collabora discovery is served on this device\'s gateway', found.get('discovery') == [200, True],
                     found.get('discovery'))
            ev.check('import: config.php carries a new data fingerprint (the restored-from-backup signal)',
                     bool(state.get('fingerprint')) and state.get('fingerprint') != before.get('fingerprint'),
                     {'set': bool(state.get('fingerprint'))})
            web = found.get('web') or {}
            ev.check('import: the web server serves nothing below the data dir (Nextcloud\'s own protection file; static '
                     'control served)', web.get('control') == 200 and len(web.get('codes') or []) == 3
                     and all(code in (403, 404) for code in web['codes']) and web.get('htaccess_below') == '0'
                     and web.get('htaccess') == hashlib.sha256(nc.ha_nextcloud.DATA_HTACCESS).hexdigest(),
                     web)
            ev.check('import: database: root storage is this device\'s data dir, tables owned by oc_admin',
                     found.get('storage') == 'local::/var/www/html/data/' and found.get('owners') == 'oc_admin',
                     {k: found.get(k) for k in ('storage', 'owners')})

        # -------- back to dev-e's own Nextcloud
        def manual_rollback(self, phase):
            """The import's safety backup restored (dev-e's own Nextcloud before the import): the manual rollback, and the
            recovery when a case stops after the import's restore. Never limited by the case budget; the reserve holds."""
            self.restored_back = False
            self.budget(phase, self.restore_need(self.safety), timed=False)
            job, took = d.restore(self.safety, APPS, ev=ev, tag=f'nc-noshare-page-{phase}')
            result = job.get('result') or {}
            d.created_backup(result.get('safety_backup_id'))
            ev.save(f'{phase}-job.json', {'state': job.get('state'), 'error': job.get('error'), 'health': result.get('health')})
            require(f'{phase}: the import\'s safety backup restored (manual rollback), every health check ok',
                    job.get('state') == 'succeeded' and all(h.get('status') == 'ok' for h in result.get('health') or []),
                    {'state': job.get('state'), 'took_s': round(took, 1)})
            found = self.markers()
            users = self.state().get('users') or []
            ha_only = set(self.imported_users or [HA_USER]) - set(self.before['state'].get('users') or [])
            require(f'{phase}: dev-e\'s own markers are back exactly and the HA-only users are gone',
                    found == self.before['markers'] and bool(ha_only) and not ha_only & set(users),
                    {'markers_same': found == self.before['markers'], 'users': users, 'ha_only': sorted(ha_only)})
            client = self.base_client()
            require(f'{phase}: dev-e\'s own account logs in again (OCS)',
                    (client.get('ocs') or {}).get('password') == [200, True], client.get('ocs'))
            self.baseline_verified = baseline_verify()
            require(f'{phase}: the original baseline verified (batch2_baseline.py --verify nextcloud)', self.baseline_verified)
            self.restored_back = True

        def after_state(self):
            super().after_state()
            self.after_done = True

        def leaks(self):
            names = ['HA_BACKUP_KEY', 'B2_NC_X86_NOSHARE_USER_PW', 'B2_NC_X86_NOSHARE_APP_PW', 'DEV_D_MARKER_NEXTCLOUD',
                     'COCKPIT_PASSWORD'] + sorted(k for k in secrets.values if k.startswith('R6_BASELINE_'))
            report = d.device_python(nc.LEAKS, {'secrets': {n: secrets[n] for n in names}, 'url_tokens': []},
                                     as_owner=False, timeout=900)
            host = d.scan_host_evidence(ev.dir, secrets)
            ev.save('leaks.json', {'device': report, 'host': host, 'names': len(names)})
            ev.check('leaks: no HA key, HA test credential, marker or Cockpit password or kit in engine records, uploads, '
                     'staging, run dir, journal or evidence', report.get('hits') == 0 and report.get('scanned', 0) > 0 and not host.get('hits'),
                     {'device': report, 'host_hits': host.get('hits')})

    return Run


def run_case(nc, bridge, ev, secrets, lease, commit, case):
    """Inside the woken stack: the steps, then (always) the recovery, the cleanup gate, the owned cleanup and the leak
    scan. Returns whether dev-e's own Nextcloud is verifiably back and nothing of this run is left."""
    d = nc.drv
    Run = make_run(nc, bridge, ev, secrets, lease, commit, case)
    run_args = SimpleNamespace(run=False, candidate=False, draft_entry=False, facts={}, secrets=secrets)
    run = Run(run_args, ev)
    run.lock_started = case.lock_started
    case.run = run
    original_helper, original_wait = d.helper, d.wait_job

    def guarded_helper(command, request=None, **kwargs):
        r6.owned_command(command, request, d.STATE)   # delete/restore-start only of owned backups, never the baseline
        return original_helper(command, request, **kwargs)

    def record_job(job):
        """Every job this run waits for is its own (the page's check and chain jobs, its restores, its reconciled
        jobs): what it made goes to the owned cleanup at once (R6 record_job)."""
        d.STATE.setdefault('jobs', {})[job['id']] = {'state': job.get('state')}
        for field in ('backup_id', 'safety_backup_id'):
            value = (job.get('result') or {}).get(field)
            if value and value != BASELINE:
                d.created_backup(value)
        d.save_state()

    def wait(job_id, *, ev, timeout=5400):
        case.inflight.add(job_id)
        try:
            job = original_wait(job_id, ev=ev, timeout=min(timeout, max(1, int(case.expires + RECOVERY_GRACE - time.time()))))
        finally:
            case.inflight.discard(job_id)
        record_job(job)
        return job

    d.helper, d.wait_job = guarded_helper, wait
    steps = (('setup', run.setup), ('before', run.before_state), ('page import', run.page_import),
             ('verify', run.verify_import), ('rollback', lambda: run.manual_rollback('rollback')),
             ('after', run.after_state))
    try:
        for name, step in steps:
            run.budget(name)
            ev.log(f'== {name}')
            step()
    except Exception as error:   # noqa: BLE001 - every stop leads to the same recovery
        ev.check('case stopped; recovery and the cold return follow', False, r6.stop_detail(error, secrets))
    safe = False
    try:
        case.recovery.set()
        reconcile(nc, ev, case)
        adopt_safety(nc, case, run)
        if run.safety and not run.restored_back:
            try:
                run.manual_rollback('recovery')
            except Exception as error:   # noqa: BLE001
                ev.check('recovery stopped; the safety backup is kept', False, r6.stop_detail(error, secrets))
        if not run.baseline_verified:
            run.baseline_verified = baseline_verify()
            ev.check('cleanup gate: the original baseline verified (batch2_baseline.py --verify nextcloud)',
                     run.baseline_verified)
        if run.before and not run.after_done:
            run.after_state()
        exact = run.after_done and all(r['ok'] for r in ev.results if r['check'].startswith('after:'))
        safe = run.baseline_verified and (not run.safety or run.restored_back) and not case.inflight and (
            exact or not run.before)
        if not safe:
            raise nc.Failed('fixed-dev-e-not-verifiably-back-backups-kept')
        run.cleanup()
        run.leaks()
        clean = all(r['ok'] for r in ev.results if r['check'].startswith(('cleanup:', 'leaks:')))
        d.STATE['pending'] = not clean
        d.save_state()
        return clean
    except Exception as error:   # noqa: BLE001
        ev.check('cleanup gate: what this run made is kept for the coordinator (receipt pending)', False,
                 r6.stop_detail(error, secrets))
        return False
    finally:
        d.helper, d.wait_job = original_helper, original_wait


def reconcile(nc, ev, case):
    """No recovery or cleanup races a job of this run: every job new since the run's start that still runs is cancelled
    and waited for (bounded by the recovery grace)."""
    d = nc.drv
    rows = d.ok('jobs', ev=ev).get('jobs') or []
    for row in rows:
        if row.get('id') in case.jobs_before or row.get('state') not in ('queued', 'running'):
            continue
        d.helper('job-cancel', {'job_id': row['id']}, timeout=30)
        d.wait_job(row['id'], ev=ev, timeout=min(900, max(1, int(case.expires + RECOVERY_GRACE - time.time()))))


def adopt_safety(nc, case, run):
    """The import's safety backup even when the page or a judgement stopped before the run learned it: the restore job
    of this run's HA record (the page's chain) that made one."""
    if run.safety:
        return
    d = nc.drv
    store = 'ha-' + nc.FIXTURE_SHA[:20]
    for row in d.ok('jobs', ev=run.ev).get('jobs') or []:
        params, result = row.get('params') or {}, row.get('result') or {}
        if (row.get('id') not in case.jobs_before and row.get('type') == 'restore' and params.get('ha_backup_id') == store
                and result.get('safety_backup_id') and result['safety_backup_id'] != BASELINE):
            run.safety = result['safety_backup_id']
            d.created_backup(run.safety)
            if params.get('backup_id') and params['backup_id'] != BASELINE:
                d.created_backup(params['backup_id'])
            d.save_state()
            return


def watchdog(nc, ev, case, metrics):
    """R6's whole-run watch: a reserve or memory breach or the lease end stops the run at once (a failed probe only after
    three in a row); then only this run's jobs (new since its start) are cancelled."""
    d = nc.drv
    watch = r6.ResourceWatch(metrics)
    while not case.stop.wait(WATCH_INTERVAL):
        expired = time.time() >= case.expires + (RECOVERY_GRACE if case.recovery.is_set() else 0)
        try:
            reason = watch.sample(wake.device(control.RESOURCE, root=True, timeout=30), expired=expired)
        except Exception as error:   # noqa: BLE001
            reason = 'lease-expired' if expired else watch.failed(error)
        if reason is None:
            continue
        metrics['trip'] = {'reason': reason, 'at': time.time()}
        ev.log(f'watchdog: stopping this run: {reason}')
        case.tripped.set()
        try:
            rows = d.ok('jobs', ev=ev).get('jobs') or []
        except Exception:   # noqa: BLE001
            rows = [{'id': job_id, 'state': 'running'} for job_id in case.inflight]
        for row in rows:
            if row.get('id') not in case.jobs_before and row.get('state') in ('queued', 'running'):
                try:
                    d.helper('job-cancel', {'job_id': row['id']}, timeout=30)
                except Exception:   # noqa: BLE001
                    pass
        return


# ---------------------------------------------------------------- cold to cold (the whole run under the dev-e lock)

def control_run(lease, commit, lock_started):
    """Admission, deploy, pin and wake, the case, the cold return: (exit status, evidence)."""
    nc, bridge = load_flow(), _load('focus_page_bridge', 'focus_r6_page_bridge')
    d = nc.drv
    secrets = d.Secrets(nc.SECRET_FILES, nc.MARKERS)
    secrets.register('COCKPIT_PASSWORD', (LAB / 'secrets' / 'devadmin.pass').read_text().strip())
    kit = (LAB / 'secrets' / 'dev-e-kit.txt').read_text()
    secrets.register('R6_BASELINE_KIT', kit)
    for number, line in enumerate(kit.splitlines()):
        if line.startswith('AGE-SECRET-KEY-1'):
            secrets.register('R6_BASELINE_AGE_' + str(number), line)
    ev = nc.Ev(secrets, area='focus-nextcloud-r6-page')
    expires = expiry(lease)
    case = SimpleNamespace(expires=expires, lock_started=lock_started, tripped=threading.Event(), stop=threading.Event(),
                           recovery=threading.Event(), inflight=set(), jobs_before=set(), before=None, run=None)
    try:             # an earlier run's receipt stays as it is (its pending flag too) until this run is admitted
        receipt = d.state_path()
        d.STATE.update(json.loads(receipt.read_text()) if receipt.exists() else {})
        pending = d.STATE.get('pending') is True
    except (OSError, ValueError):
        pending = True   # an unreadable receipt is the coordinator's to look at
    # Admission (cold): nothing below changes dev-e before every check passed.
    try:
        before = collect()
        control.admission(before)
        if any(str(image).startswith('sha256:') for quadlet in before['owner']['quadlets'].values()
               for image in quadlet.get('images') or []):
            raise ValueError('fixed-r6-page-quadlets-still-pinned')   # an earlier cold return did not finish
        admitted = True
    except (ValueError, RuntimeError, KeyError) as error:
        before, admitted = None, str(error)
    if not ev.check('admission: dev-e is cold and isolated (network none, no port, 3 GiB cap), five original images '
                    'loaded, Quadlets unpinned, wake admitted', admitted is True, admitted):
        return 2, ev
    estimate = page_peak(HISTORICAL_SIZES, nc.FIXTURE.stat().st_size)['additional_peak_bytes']
    free = min(before['host_free_bytes'], before['root']['varlib_free_bytes'])
    if not ev.check('admission: the host keeps the 13 GiB reserve after the page import\'s historical peak (upload, '
                    'check, conversion, restore)', free >= RESERVE + MARGIN + estimate,
                    {'free_mib': free >> 20, 'peak_mib': estimate >> 20}):
        return 2, ev
    try:             # read only: the jobs, the exact prior Quadlets (kept to put back) and the baseline archive
        active = wake.device(control.QUIESCENT, root=True)['active_jobs']
        snapshot = wake.device(wake.unit_program(), {'action': 'snapshot'})
        archive = wake.device(wake.BASELINE_HASH, root=True, timeout=600)
    except (RuntimeError, KeyError, TypeError):
        active, snapshot, archive = None, None, None
    if not ev.check('admission: no job is running on dev-e and no earlier run of this case is pending',
                    active == 0 and not pending and snapshot is not None and archive is not None,
                    {'active_jobs': active, 'pending': pending, 'prior_units_read': snapshot is not None}):
        return 2, ev
    case.before = before
    d.STATE.clear()
    d.STATE.update(pending=True, source_commit=commit, case=PHASE, created_backups=[], jobs={},
                   original_baseline_id=BASELINE, ha_backup_id=None)
    d.save_state()
    ev.save('prior-units.json', snapshot)
    ev.save('prior-inventory.json', before)
    ev.save('baseline-hashes.json', archive)
    timer_found, office_claim, safe = None, None, False
    metrics = {'minimum_free_bytes': None, 'peak_memory_current_bytes': 0}
    watcher = threading.Thread(target=watchdog, args=(nc, ev, case, metrics), daemon=True)
    try:
        timer_found = nc.drv.out(d.root('systemctl', 'is-enabled', TIMER, timeout=60)).strip()
        proc = d.root('systemctl', 'mask', TIMER, timeout=120)
        if not ev.check('deploy: the scheduled-backup timer is masked (shared lab, no schedule)', proc.returncode == 0,
                        timer_found):
            raise nc.Failed('timer')
        proc = d.run(['bash', str(HERE / 'deploy-src.sh'), 'e', '--src', str(REPO), '--no-demo-catalog'], timeout=1800)
        ev.save('deploy.log', d.out(proc)[-20000:] + proc.stderr.decode('utf-8', 'replace')[-5000:])
        if not ev.check('deploy: deploy-src.sh e --src <this tree> --no-demo-catalog (the page and the engine of this '
                        'checkout; Nextcloud cold)', proc.returncode == 0, f'rc {proc.returncode}'):
            raise nc.Failed('deploy')
        jobs = d.ok('jobs', ev=ev).get('jobs') or []
        case.jobs_before.update(row['id'] for row in jobs)
        wake.device(wake.unit_program(), {'action': 'pin', 'snapshot': snapshot})
        control.reload_units()
        watcher.start()
        started = wake.device(wake.CONTROL, {'action': 'start', 'expires_epoch': expires}, timeout=1200)
        ev.save('wake-result.json', started)
        office_claim = wake.device(cold.CLAIM)
        ev.save('owned-office-invocation.json', office_claim)
        if not ev.check('wake: the five Quadlets pinned to their loaded config IDs and the stack started within the '
                        'reserve and the memory cap', started.get('status') == 'started' and not case.tripped.is_set(),
                        {k: started.get(k) for k in ('status', 'minimum_free_bytes', 'peak_memory_bytes')}):
            raise nc.Failed('wake')
        if not ev.check('wake: the original baseline verified before the import (batch2_baseline.py --verify nextcloud)',
                        baseline_verify()):
            raise nc.Failed('baseline before the import')
        safe = run_case(nc, bridge, ev, secrets, lease, commit, case)
    except Exception as error:   # noqa: BLE001 - the cold return below runs either way
        ev.check('control stopped before or around the case; the cold return follows', False,
                 r6.stop_detail(error, secrets))
        if case.run is None:      # stopped before the case: nothing was imported; the receipt is settled
            d.STATE['pending'] = False
            d.save_state()
    finally:
        case.recovery.set()
        case.stop.set()
        if watcher.is_alive():
            watcher.join(timeout=40)
        returned = cold_return(nc, ev, case, snapshot, archive, office_claim)
        if not returned:
            safe = False                  # the next run refuses until the coordinator restored the prior copies
            d.STATE['pending'] = True
            d.save_state()
        if timer_found not in (None, 'masked', 'masked-runtime'):
            if returned:
                proc = d.root('systemctl', 'unmask', TIMER, timeout=120)
                ev.check('return: the scheduled-backup timer is unmasked again (as found)', proc.returncode == 0,
                         timer_found)
            else:                         # no scheduled job may race the coordinator's recovery of the stack
                ev.check('return: the scheduled-backup timer stays masked until the coordinator finished the cold return',
                         False, timer_found)
    ev.save('scope.json', {'source_commit': commit, 'case': PHASE, 'safe': safe, 'sampled_resources': metrics,
                           'device_memory_cap_bytes': DEVICE_CAP, 'reserve_bytes': RESERVE, 'image_pulls': 0})
    return (0 if safe else 1), ev


def cold_return(nc, ev, case, snapshot, archive, office_claim):
    """No job running, the stack stopped cold (only this run's own Office failed flag cleared), the Quadlets reverted,
    then everything the R6 inventory reads compared with the admission's (the engine modules with this checkout).
    Returns whether every step of it passed."""
    first = len(ev.results)
    try:
        active = wake.device(control.QUIESCENT, root=True)['active_jobs']
        if not ev.check('return: no job is running on dev-e (before the stop)', active == 0, {'active_jobs': active}):
            raise RuntimeError('fixed-r6-page-job-writer-not-quiescent-retain-units')
        stopped = cold.stop(case.before['owner']['units']['nextcloud-office.service'], office_claim)
        ev.save('cold-stop-result.json', stopped)
        now = collect()
        ev.check('return: the Nextcloud stack is cold again (every unit inactive; only this run\'s own Office failed flag '
                 'cleared)', all(x.get('ActiveState') == 'inactive' for x in now['owner']['units'].values()),
                 {'office_flag_cleared': stopped.get('only_owned_office_failed_flag_cleared')})
        wake.device(wake.unit_program(), {'action': 'revert', 'snapshot': snapshot})
        control.reload_units()
        ev.check('return: the five Quadlets are byte for byte as before (pins reverted)',
                 wake.device(wake.unit_program(), {'action': 'snapshot'}) == snapshot)
        after = collect()
        archive_after = wake.device(wake.BASELINE_HASH, root=True, timeout=600)
        ev.save('after-inventory.json', after)
        before = case.before
        engine = {name: nc.tree_hashes().get(name) for name in ENGINE_MODULES}
        ev.check('return: units, Quadlets, images, catalog, baseline archive, isolation, memory cap as before; the '
                 'engine modules are this checkout\'s',
                 after['owner']['units'] == before['owner']['units'] and after['owner']['quadlets'] == before['owner']['quadlets']
                 and after['owner']['images'] == before['owner']['images']
                 and after['root']['catalog_sha256'] == before['root']['catalog_sha256'] and archive_after == archive
                 and after['isolation'] == before['isolation'] and after['root']['memory_max'] == str(DEVICE_CAP)
                 and after['root']['installed_hashes'] == engine,
                 {'units': after['owner']['units'] == before['owner']['units'],
                  'quadlets': after['owner']['quadlets'] == before['owner']['quadlets'],
                  'archive': archive_after == archive, 'engine': after['root']['installed_hashes'] == engine})
    except Exception as error:   # noqa: BLE001
        ev.check('return: the cold return needs the private prior copies (coordinator)', False, type(error).__name__)
    return all(r['ok'] for r in ev.results[first:]) and len(ev.results) - first == 4


def finish(ev, code):
    passed = ev.finish()
    results = ev.results
    ok = code == 0 and passed
    emit(f'nextcloud no-share page: {sum(r["ok"] for r in results)}/{len(results)} {"PASS" if ok else "FAIL"}')
    return code if code else (0 if ok else 1)


def plan():
    nc = load_flow()
    return {'status': 'offline-preparation-only', 'phase': PHASE, 'device': DEVICE, 'fixture': nc.FIXTURE.name,
            'fixture_sha256': nc.FIXTURE_SHA, 'apps': APPS, 'confirmation': NO_SHARE, 'baseline_id': BASELINE,
            'reserve_bytes': RESERVE, 'device_cap_bytes': DEVICE_CAP,
            'historical_peak_bytes': page_peak(HISTORICAL_SIZES, 248 * 1024 ** 2)['additional_peak_bytes'],
            'requires': ['dev-e Nextcloud cold with the five original images loaded (R6)', 'an exact noshare-page lease',
                         'heavy.sh with HEAVY_FREE=' + LOCK, 'a committed checkout'],
            'mutations': 0}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--run', action='store_true')
    parser.add_argument('--lease', type=Path)
    parser.add_argument('--lease-template', action='store_true')
    args = parser.parse_args(argv)
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=REPO, text=True).strip()
    if args.lease_template:
        print(json.dumps(lease_template(commit), indent=2, sort_keys=True))
        return 0
    if not args.run:
        print(json.dumps(plan(), indent=2))
        return 0
    if args.lease is None:
        parser.error('--run requires a reviewed --lease')
    try:
        if subprocess.check_output(['git', 'status', '--porcelain'], cwd=REPO, text=True).strip():
            raise ValueError('fixed-committed-source-required')
        lease = json.loads(args.lease.read_text())
        admit_lease(lease, commit, load_flow().FIXTURE_SHA)
        if os.environ.get('HEAVY_FREE') != LOCK:
            raise ValueError('fixed-heavy-seat-required')
        with open(LOCK, 'a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            started = time.monotonic()
            try:
                admit_lease(lease, commit, load_flow().FIXTURE_SHA)
                emit(f'source commit {commit}')
                code, ev = control_run(lease, commit, started)
            finally:
                emit(f'lock held for {int(time.monotonic() - started)} s')
    except (ValueError, BlockingIOError) as error:
        print(f'fixed-r6-page-preflight-refused ({str(error)[:60]}); no case mutation started', file=sys.stderr)
        return 2
    return finish(ev, code)


if __name__ == '__main__':
    sys.exit(main())
