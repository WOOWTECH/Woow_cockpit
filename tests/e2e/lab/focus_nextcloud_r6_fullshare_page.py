#!/usr/bin/env python3
"""R6 case: the FULL-SHARE Nextcloud HA import through dev-e's REAL Cockpit page (focus_page_bridge), cold to cold.

  python3 -I tests/e2e/lab/focus_nextcloud_r6_fullshare_page.py                   offline: the plan and resource model
  python3 -I tests/e2e/lab/focus_nextcloud_r6_fullshare_page.py --lease-template  the lease fields this checkout binds
  HEAVY_FREE=/tmp/woowbk-dev-e-mutation.lock .../heavy.sh python3 -I tests/e2e/lab/services_a_capture.py \\
      --private=FILE <evidence.json> nextcloud-x86-fullshare-page -- \\
      python3 -I tests/e2e/lab/focus_nextcloud_r6_fullshare_page.py --run --lease FILE

The original encrypted x86 HA backup WITH HA's share folder (woow-b2-nextcloud-x86-enc-share, 4,467,947,520 bytes)
passed 118/118 through the helper path on 2026-11-27 (fullshare05: focus_nextcloud_r6.py on nextcloud_flow's share-run
harness and the share run's private facts). Here the real page makes that import: it uploads the 4.47 GB file, selects
only nextcloud, takes the HA key, shows the check with every confirmation line it lists (the full share lists none, a
valid zero), ticks the one acknowledgement once and starts the import (the conversion and its restore as two linked
jobs in one unit). The page gets a longer bound and longer waits for this file (focus_page_bridge waits, page config
waits_ms: upload 30, check 10, import 25 minutes, the page at most 50 minutes); earlier page configs are unchanged.
nextcloud_flow.py and the R6 modules are used as they are; the case is the no-share page case's control
(focus_nextcloud_r6_page.py) with the full-share facts, the whole run holding /tmp/woowbk-dev-e-mutation.lock:

  admission  a committed checkout, the share run's facts (r6.validate_facts: the original fixture, credential names only,
             the share data dir; their SHA-256 bound by the lease), an exact lease (lane nextcloud-r6, phase fullshare-page,
             this commit, the fixture, the facts, the page bound, the pin policy, the 13 GiB reserve, the 3 GiB device cap,
             120 minutes left), the heavy seat (HEAVY_FREE = the dev-e lock); the facts name only credentials this lab
             holds and the fixture is the original file; dev-e network none without a port, the five original images
             loaded, every Nextcloud unit inactive (cold), host and device memory and disk; the host reserve after the
             page import's historical peak (the uploaded file stays through the conversion AND its restore: the page
             deletes nothing in between); no job running, no earlier run of this case pending
  deploy     the scheduled-backup timer masked; deploy-src.sh e --src <this checkout> --no-demo-catalog while cold
  wake       the five Quadlets pinned to their loaded config IDs, the stack started under the R6 resource watch,
             batch2_baseline.py --verify nextcloud before the import
  case       setup, before (the encrypted baseline opens with the existing kit, dev-e's markers and own account, fresh
             live sizes), the page import (the reserve after its peak from the live sizes; this run's pending uploads
             noted), the page's own check (nothing stops, no line to confirm, the section equals the facts, the file lists
             agree, amd64/0.2.3/35.0.1.1), its conversion (notes and reminders, listed with its HA origin, inspect:
             preflight, settings same, in place) and its restore (safety backup, health), the page's uploaded HA file
             deleted after the import (as the page allows; the rollbacks get the space the helper run gave them), then
             the helper run's facts on the imported Nextcloud (nextcloud_flow.Run.verify: status, the HA users' WebDAV
             files and per-user digests, OCS with the HA password and app password, the user share, the password-protected
             public link, CalDAV, CardDAV, versions, this device's Office settings, capabilities and discovery, a new data
             fingerprint, occ files:scan, the data dir protected (setup check and web server), storage and table owners,
             Office opening, reading and saving a document over WOPI), the same after a restart, the automatic rollback
             (a restore with a one-shot ExecStartPre failure ends rolled-back, verified again, its safety deleted), the
             manual rollback (the import's safety backup restored: markers exact, the HA users gone, dev-e's own login,
             the baseline verified), after (everything read before is unchanged)
  cleanup    only what this run made (the R6 guard): the converted and safety backups (never the baseline), the HA
             record when the page's upload created it, a pending upload of this run (an interrupted page upload); no job
             object, staging folder or key file; the leak scan (HA key, every credential the facts name, dev-e's marker
             password, devadmin's Cockpit password, the kit; the public link's token only in the access logs)
  return     no job running, the stack stopped cold, the Quadlets back byte for byte, the timer as found; units,
             Quadlets, images, catalog, baseline archive, isolation and memory cap as before; the engine is this checkout's

A whole-run watchdog (R6 ResourceWatch) trips on a reserve or memory breach or at the lease end; from then on every job
this run starts (the page's check, conversion or restore included) is cancelled as soon as it is seen, until the
recovery begins. Whatever stops the case, the import's safety backup is restored first, the baseline verified and the
stack returned cold, within 30 minutes past the lease; backups are cleaned up only once dev-e's own Nextcloud is
verifiably back (otherwise they stay for the coordinator, the receipt stays pending).
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
import secrets as nonce_source
import subprocess
import sys
import threading
import time
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import focus_nextcloud_r6 as r6                    # noqa: E402  ResourceWatch, owned_command, validate_facts, FACTS
import focus_nextcloud_r6_case as control          # noqa: E402  admission, QUIESCENT, RESOURCE, BASELINE_INSPECT
import focus_nextcloud_r6_cold as cold             # noqa: E402  CLAIM, stop (only this run's own Office flag)
import focus_nextcloud_r6_wake as wake             # noqa: E402  unit_program (pin/revert), CONTROL, BASELINE_HASH
from focus_nextcloud_r6_inventory import FIXTURE, FIXTURE_SHA, collect   # noqa: E402
from focus_nextcloud_r6_plan import (BASELINE, DEVICE_CAP, FIXTURE_BYTES, GIB, MARGIN, RESERVE,  # noqa: E402
                                      acceptance_budget, confirmation_keys, lease_check)

REPO = HERE.parents[2]
LAB = Path.home() / '.woowbk-lab'
LOCK = '/tmp/woowbk-dev-e-mutation.lock'
DEVICE = 'woowbk-dev-e'
PHASE = 'fullshare-page'
CASE = 'fullshare'                                 # R6's case: validate_facts, confirmation_keys (no line to confirm)
RECEIPT_NAME = 'focus_nextcloud_r6_fullshare_page.json'   # LAB/run/<this>: the run's own receipt
AREA = 'focus-nextcloud-r6-fullshare-page'         # LAB/evidence/<this>/<time>: private, redacted
FACTS = r6.FACTS                                   # the share run's private facts (names and digests, never a value)
FACT_SECRETS = ('user_pw', 'app_pw', 'user2_pw', 'link_pw', 'link_token')   # names of lab credentials in the facts
PIN_POLICY = control.PIN_POLICY                    # same config only, private copy, revert
RECOVERY_GRACE = 1800                              # recovery and the cold return may run this long past the lease
LEASE_HEADROOM = 120 * 60                          # lease seconds still left when the dev-e lock is held
CASE_BUDGET = 120 * 60                             # timed steps of the case (never the recovery)
PAGE_SECONDS = 50 * 60                             # the page's bound for the 4.47 GB file (focus_page_bridge waits)
PAGE_WAITS = {'upload': 30 * 60, 'check': 10 * 60, 'result': 25 * 60}   # the page's own waits for this file
PAGE_STEP_BUDGET = PAGE_SECONDS + 5 * 60           # the page, hashing the fixture before it and reading its jobs
REST_RESERVE = 40 * 60                             # kept after the page: verify, restart, both rollbacks, after
WATCH_INTERVAL = 2
TIMER = 'woowtech-cockpit-backup-schedule.timer'
ORIGINAL_CATALOG_SHA = '3a7af03b966f90a172e417a3ea69d7b36bf98a23af8d27b0c074bd01b6f335d6'   # R6 setup's binding
APPS = ['nextcloud']
ENGINE_MODULES = ('ha_nextcloud.py', 'haadapters.py', 'haapps.py', 'hacommands.py', 'flows.py', 'hatarget.py',
                  'habackup.py')                   # what the R6 inventory hashes in dev-e
# The historical live sizes R6's plan uses (html, postgres, data); the case recomputes the peak from fresh sizes.
HISTORICAL_SIZES = (849259813, 75382634, 234187031)
CONVERTED_BOUND = 5 * GIB // 4                     # the page's converted backup (fullshare05: about 1.2 GiB)
SAFETY_BOUND = GIB                                 # the import's safety backup of dev-e's own Nextcloud
EXPECTED_CHECKS = 145                              # a passing run whose upload created the HA record
PAGE_LABEL = f'page: bounded ({PAGE_SECONDS // 60} min), the browser closed in order and every relay exec child reaped'


def _load(name, alias=None):
    # -I removes the script directory from sys.path: load the adjacent module explicitly.
    spec = importlib.util.spec_from_file_location(alias or name, HERE / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def emit(line):
    print(line, flush=True)


def load_flow(facts=None):
    """nextcloud_flow.py as this case uses it: the R6 reserve as its floors, this case's own receipt and, with the share
    run's facts, their fixture, SHA-256 and check section (as focus_nextcloud_r6.run_locked sets them)."""
    nc = _load('nextcloud_flow', 'focus_r6_fullshare_page_flow')
    nc.FLOOR = nc.WATCH_FLOOR = RESERVE
    nc.drv.state_path = lambda: LAB / 'run' / RECEIPT_NAME
    if facts is not None:
        nc.FIXTURE, nc.FIXTURE_SHA, nc.SECTION = Path(facts['fixture']), facts['sha256'], dict(facts['section'])
    return nc


def load_facts(path):
    """The share run's private facts and the SHA-256 of their bytes; r6.validate_facts refuses anything but the original
    full-share fixture with credential NAMES (B2_NC_*) and the share data dir. Raises ValueError with a fixed reason."""
    try:
        data = Path(path).read_bytes()
        facts = json.loads(data)
    except (OSError, ValueError):
        raise ValueError('fixed-r6-fullshare-page-facts-unreadable') from None
    if not isinstance(facts, dict):
        raise ValueError('fixed-r6-fullshare-page-facts-unreadable')
    r6.validate_facts(facts, CASE)
    return facts, hashlib.sha256(data).hexdigest()


def baseline_verify():
    """The independent read-only verifier (batch2_baseline.py --verify nextcloud), private output."""
    p = subprocess.run([sys.executable, '-I', str(HERE / 'batch2_baseline.py'), '--verify', 'nextcloud'],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1200)
    return p.returncode == 0


def expiry(lease):
    return datetime.datetime.fromisoformat(lease['expires_utc'].replace('Z', '+00:00')).timestamp()


def page_peak(sizes, fixture_bytes):
    """The page import's additional peak on dev-e's disk from (html, postgres, data) live sizes. The page uploads the
    file (Cockpit's fsreplace1 preallocates it once next to the upload's placeholder, which is renamed into the HA store:
    one copy) and keeps it through the whole chain: it is added to the larger of the conversion's staging and the restore
    with the converted and safety copies kept (R6 acceptance_budget without its upload term, the converted backup bounded
    by what fullshare05 made)."""
    html, pg, data = sizes
    bound = acceptance_budget(html, pg, data, CONVERTED_BOUND, SAFETY_BOUND, uploaded=fixture_bytes)
    conversion = bound['upload_and_convert_peak_bytes'] - fixture_bytes
    restore = bound['restore_with_retained_safety_peak_bytes']
    peak = fixture_bytes + max(conversion, restore) + MARGIN
    return {'uploaded_bytes': fixture_bytes, 'conversion_bytes': conversion, 'restore_bytes': restore,
            'converted_bound_bytes': CONVERTED_BOUND, 'safety_bound_bytes': SAFETY_BOUND,
            'upload_kept_through_the_chain': True, 'additional_peak_bytes': peak,
            'minimum_free_bytes': RESERVE + MARGIN + peak, 'reserve_bytes': RESERVE,
            'helper_path_additional_peak_bytes': bound['additional_peak_bytes']}


def job_seconds(job):
    """Wall seconds of a finished job from its own record (started, finished); 0.0 when it does not say."""
    try:
        start, end = (datetime.datetime.fromisoformat(str(job[k]).replace('Z', '+00:00')) for k in ('started', 'finished'))
        return max(0.0, (end - start).total_seconds())
    except (KeyError, TypeError, ValueError):
        return 0.0


# Read-only: the engine's upload area by upload id, names only (storage.UPLOAD_FILE_RE and BRIDGE_TEMP_RE).
UPLOADS = r'''
import json, os, re
root = "/var/lib/woowtech-backup/uploads"
found = {}
try:
    names = os.listdir(root)
except FileNotFoundError:
    names = []
for name in names:
    plain = re.fullmatch(r"(u[0-9a-f]{16})\.(part|json|done)", name)
    temp = re.fullmatch(r"\.(u[0-9a-f]{16})\.part-.+", name)
    if plain:
        found.setdefault(plain.group(1), set()).add(plain.group(2))
    elif temp:
        found.setdefault(temp.group(1), set()).add("temp")
print(json.dumps({key: sorted(value) for key, value in sorted(found.items())}))
'''


def pending_uploads(listing):
    """The upload ids that still have a placeholder, a record or Cockpit's temp file (a finished one keeps only .done)."""
    return {upload_id for upload_id, kinds in (listing or {}).items() if set(kinds) & {'part', 'json', 'temp'}}


# ---------------------------------------------------------------- lease

def lease_template(commit, facts_path=FACTS):
    """The lease fields this checkout binds (the facts by the SHA-256 of their bytes); the time window is the
    coordinator's."""
    _facts, facts_sha = load_facts(facts_path)
    return {'device': DEVICE, 'lane': 'nextcloud-r6', 'phases': [PHASE], 'source_commit': commit,
            'reserve_bytes': RESERVE, 'memory_cap_bytes': DEVICE_CAP, 'not_before_utc': '<UTC start>',
            'expires_utc': '<UTC end, at least 120 minutes after the lock is held>',
            'fixture_sha256': FIXTURE_SHA, 'facts_sha256': facts_sha, 'page_seconds': PAGE_SECONDS,
            'pin_refresh_policy': PIN_POLICY, 'recovery_grace_seconds': RECOVERY_GRACE,
            'source_deployment': 'deploy-src-this-checkout', 'page_device': DEVICE}


def admit_lease(lease, commit, fixture_sha, facts_sha, now=None):
    """The exact lease of this checkout (lease_check: device, lane, phase, commit, reserve, cap, window) with every bound
    value and LEASE_HEADROOM left; raises ValueError with a fixed reason."""
    lease_check(lease, commit, PHASE)
    if (lease.get('fixture_sha256') != fixture_sha or lease.get('facts_sha256') != facts_sha
            or lease.get('page_seconds') != PAGE_SECONDS or lease.get('pin_refresh_policy') != PIN_POLICY
            or lease.get('recovery_grace_seconds') != RECOVERY_GRACE
            or lease.get('source_deployment') != 'deploy-src-this-checkout' or lease.get('page_device') != DEVICE):
        raise ValueError('fixed-r6-fullshare-page-lease-binding-refused')
    if expiry(lease) - (time.time() if now is None else now) < LEASE_HEADROOM:
        raise ValueError('fixed-r6-fullshare-page-lease-headroom-required')


# ---------------------------------------------------------------- the case (inside the woken stack)

def make_run(nc, bridge, ev, secrets, lease, commit, case):
    """nextcloud_flow.Run for this case: R6's budget and guards, the page import and its judgement on the page's own
    jobs, then nextcloud_flow's share-run verify, restart and rollback with R6's owned injection paths, the manual
    rollback and leak scan of this case. `case` holds the run's shared state (tripped, inflight, jobs_before, expires,
    uploads_before, own_uploads)."""
    d = nc.drv

    def require(label, ok, detail=''):
        if not ev.check(label, ok, detail):
            raise nc.Failed(label)

    class Run(nc.Run):
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

        # -------- setup and before (the no-share page case's)
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
            now = time.monotonic()
            deadline = min(now + PAGE_STEP_BUDGET, now + (case.expires - time.time()) - REST_RESERVE)
            if deadline - now < PAGE_STEP_BUDGET:   # never a page without its whole bound and the rest of the case after it
                raise nc.Failed('fixed-page-bound-and-rest-do-not-fit-the-lease')
            sizes = self.before['sizes']
            bound = page_peak((sizes['html'], sizes['postgres'], sizes['data']), nc.FIXTURE.stat().st_size)
            ev.save('page-budget.json', bound)
            free = wake.device(control.RESOURCE, root=True, timeout=30)['free']
            require('page import: dev-e keeps the 13 GiB reserve after the import\'s peak (the upload kept through '
                    'conversion and restore, live sizes)', free >= bound['minimum_free_bytes'],
                    {'free_mib': free >> 20, 'peak_mib': bound['additional_peak_bytes'] >> 20})
            listing = d.ok('list', ev=ev)
            before_ids = {b['id'] for b in listing['backups']}
            existed = 'ha-' + nc.FIXTURE_SHA[:20] in {h.get('id') for h in listing.get('ha_backups') or []}
            case.uploads_before = d.device_python(UPLOADS, as_owner=False, timeout=120)
            ops = bridge.Ops(helper=lambda command, request=None: d.ok(command, request, ev=ev),
                             wait_job=lambda job_id, timeout: d.wait_job(job_id, ev=ev, timeout=timeout),
                             root_json=lambda script, request: d.device_python(script, request, as_owner=False, timeout=300))
            try:
                page = bridge.import_via_page(device=DEVICE, lock=LOCK, apps=list(APPS), importable=list(APPS), stops=[],
                                              fixture=nc.FIXTURE, key=secrets['HA_BACKUP_KEY'],
                                              password=secrets['COCKPIT_PASSWORD'], evidence=ev.dir / 'page',
                                              deadline=deadline, ops=ops, source=REPO, page_seconds=PAGE_SECONDS,
                                              waits=dict(PAGE_WAITS))
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
            ev.time('page', 'fullshare', 'nextcloud', float((summary.get('page') or {}).get('elapsed_s') or 0))
            for item in page.browser_checks:
                ev.check(f'page: {item.get("check")}', item.get('ok') is True)
            ev.check(PAGE_LABEL, gates.get('page_bounded') and gates.get('cleanup'), summary.get('page'))
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
            ev.time('check', 'fullshare-page', 'nextcloud', job_seconds(job), job)
            self.judge_check(job)
            convert, restore = page.chain
            ev.save('convert-job.json', {'state': convert.get('state'), 'error': convert.get('error'),
                                         'result': convert.get('result')})
            require('import: the page\'s conversion job succeeded with a backup id',
                    convert.get('state') == 'succeeded' and bool((convert.get('result') or {}).get('backup_id')),
                    convert.get('error'))
            ev.time('convert', 'fullshare-page', 'nextcloud', job_seconds(convert), convert)
            self.judge_convert(convert, before_ids)
            ev.save('restore-job.json', {'state': restore.get('state'), 'error': restore.get('error'),
                                         'health': (restore.get('result') or {}).get('health')})
            ev.time('restore', 'fullshare-page', 'nextcloud', job_seconds(restore), restore)
            self.judge_restore(restore)
            self.drop_upload()

        def judge_check(self, job):
            """The facts of the page's own check: one app, importable, nothing stops and no line to confirm (the full
            share, r6.confirmation_keys; the shared part lists none either), the section equals the share run's facts,
            the file lists agree, the versions, no throwaway object left."""
            result = (job.get('result') or {}).get('ha_check') or {}
            apps = result.get('apps') or []
            app = apps[0] if len(apps) == 1 else {}
            ev.save('check-result.json', result)
            issues = [i for i in (result.get('shared') or []) + (app.get('issues') or []) if isinstance(i, dict)]
            try:
                keys = confirmation_keys(job, CASE)
            except ValueError as error:
                keys = str(error)
            require('check: the job answers one app: nextcloud importable, nothing stops and no line to confirm (the full '
                    'share, as the actual check lists it)',
                    keys == [] and not any(i.get('level') in ('stop', 'confirm') for i in issues),
                    {'importable': app.get('importable'), 'lines': [(i.get('id'), i.get('level')) for i in issues],
                     'keys': keys})
            section = self.section = app.get('nextcloud') or {}
            differ = {k: [v, section.get(k)] for k, v in nc.SECTION.items() if section.get(k) != v}
            ev.check('check: current facts match the original full-share source (HA cluster opened and read, the data dir '
                     'in the backup)', not differ, differ or section)
            ev.check('check: the file lists of HA\'s database equal the files in the backup (no warning)',
                     not any('檔案清單' in str(w) for w in app.get('warnings') or []), app.get('warnings'))
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
            reminders = (row.get('reminders_by_app') or {}).get('nextcloud') or []
            ev.check('import: the notes and reminders name Collabora, the data fingerprint and the MCP admin lines',
                     row.get('apps') == ['nextcloud'] and row.get('test_mode') is False
                     and any('Collabora' in n for n in row.get('notes') or [])
                     and any('資料指紋' in n for n in row.get('notes') or [])
                     and any('Woow Nextcloud MCP Server' in r for r in reminders),
                     {'notes': len(row.get('notes') or []), 'reminders': len(reminders)})
            listed = next((b for b in d.ok('list', ev=ev).get('backups') or [] if b['id'] == self.converted), {})
            ev.check('import: the converted backup is listed as manual with its HA origin, encrypted',
                     self.converted not in before_ids and listed.get('type') == 'manual'
                     and (listed.get('from_ha') or {}).get('ha_backup_id') == self.store_id and bool(listed.get('key_id')),
                     {'type': listed.get('type'), 'from_ha': bool(listed.get('from_ha')), 'size': listed.get('size')})
            inspect = d.ok('inspect', {'backup_id': self.converted}, ev=ev, timeout=900)
            ev.save('inspect.json', inspect)
            pre = inspect.get('preflight') or {}
            failed = [c for c in pre.get('checks') or [] if c.get('status') == 'fail']
            ev.check('import: inspect of the page\'s converted backup: preflight passes, settings same, in place',
                     pre.get('ok') is True and not failed and bool(pre.get('apps'))
                     and all((a.get('settings') or {}).get('state') == 'same' and a.get('mode') == 'inplace'
                             for a in pre.get('apps') or []),
                     failed[:3] or [(a.get('id'), a.get('mode')) for a in pre.get('apps') or []])

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

        def drop_upload(self):
            """The page's own uploaded HA file is deleted once its import is judged, before the rollbacks (as the page
            allows; the helper run deleted it before its restore). A record that existed before this run stays."""
            if not self.created_store:
                ev.log('import: the HA record existed before this run; it stays (not this run\'s)')
                return
            rc, _reply = d.helper('ha-delete', {'ha_backup_id': self.created_store, 'confirm': True})
            ev.check('import: the page\'s uploaded HA file is deleted after the import, as the page allows (space for the '
                     'rollbacks)', rc == 0)
            if rc == 0:
                self.created_store = None
                d.save_state()

        def client(self):
            found = super().client()
            self.link_used = True   # the client ran to its end: its own public-link requests are in the access logs
            return found

        # -------- the automatic rollback's injection: R6's owned paths (focus_nextcloud_r6.run_locked's Run.inject)
        def inject(self, on):
            home = '/home/appowner/'
            if on:
                require('rollback: new owned injection paths are absent', all(
                    d.owner('test', '-e', home + path, timeout=30).returncode == 1
                    for path in (nc.DROPIN_REL, nc.FAIL_MARKER_REL)))
                self.preexisting_dropin_dir = d.owner('test', '-d', home + nc.DROPIN_DIR_REL, timeout=30).returncode == 0
                super().inject(True)
            else:
                d.owner('rm', '-f', home + nc.DROPIN_REL, home + nc.FAIL_MARKER_REL, timeout=60)
                if not getattr(self, 'preexisting_dropin_dir', True):
                    d.owner('rmdir', home + nc.DROPIN_DIR_REL, timeout=60)
                d.owner('systemctl', '--user', 'daemon-reload', timeout=120)

        # -------- back to dev-e's own Nextcloud
        def manual_rollback(self, phase):
            """The import's safety backup restored (dev-e's own Nextcloud before the import): the manual rollback, and the
            recovery when a case stops after the import's restore. Never limited by the case budget; the reserve holds."""
            self.restored_back = False
            self.budget(phase, self.restore_need(self.safety), timed=False)
            job, took = d.restore(self.safety, APPS, ev=ev, tag=f'nc-fullshare-page-{phase}')
            result = job.get('result') or {}
            d.created_backup(result.get('safety_backup_id'))
            ev.save(f'{phase}-job.json', {'state': job.get('state'), 'error': job.get('error'), 'health': result.get('health')})
            ev.time('restore', f'fullshare-page-{phase}', 'nextcloud', took, job)
            require(f'{phase}: the import\'s safety backup restored (manual rollback), every health check ok',
                    job.get('state') == 'succeeded' and all(h.get('status') == 'ok' for h in result.get('health') or []),
                    {'state': job.get('state'), 'took_s': round(took, 1)})
            found = self.markers()
            users = self.state().get('users') or []
            facts = self.args.facts
            ha_only = (({facts.get('user'), facts.get('user2')} | set(facts.get('digests') or {})) - {None}
                       - set(self.before['state'].get('users') or []))
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

        def cleanup(self):
            super().cleanup()
            self.abort_own_uploads()

        def abort_own_uploads(self):
            """A pending upload this run's page left (a placeholder, its record or Cockpit's temp file of an interrupted
            upload; a finished one keeps only the engine's own .done) is aborted; uploads that existed before stay."""
            label = 'cleanup: no upload of this run is left pending (an interrupted page upload is aborted)'
            if case.uploads_before is None:
                ev.check(label, True, 'the page never started')
                return
            own = sorted(pending_uploads(d.device_python(UPLOADS, as_owner=False, timeout=120)) - set(case.uploads_before))
            case.own_uploads.update(own)
            for upload_id in own:
                d.helper('upload-abort', {'upload_id': upload_id}, timeout=120)
            left = sorted(pending_uploads(d.device_python(UPLOADS, as_owner=False, timeout=120)) - set(case.uploads_before))
            ev.check(label, not left, {'aborted': len(own), 'left': len(left)})

        def leaks(self):
            facts = self.args.facts
            names = (['HA_BACKUP_KEY', 'DEV_D_MARKER_NEXTCLOUD', 'COCKPIT_PASSWORD']
                     + [n for n in ('B2_NC_X86_NOSHARE_USER_PW', 'B2_NC_X86_NOSHARE_APP_PW') if n in secrets.values]
                     + [facts[k] for k in FACT_SECRETS if facts.get(k)]
                     + sorted(k for k in secrets.values if k.startswith('R6_BASELINE_')))
            url_tokens = [facts['link_token']] if facts.get('link_token') else []
            report = d.device_python(nc.LEAKS, {'secrets': {n: secrets[n] for n in names}, 'url_tokens': url_tokens},
                                     as_owner=False, timeout=900)
            host = d.scan_host_evidence(ev.dir, secrets)
            ev.save('leaks.json', {'device': report, 'host': host, 'names': len(set(names))})
            ev.check('leaks: no HA key, HA test credential, marker or Cockpit password or kit in engine records, uploads, '
                     'staging, run dir, journal or evidence',
                     report.get('hits') == 0 and report.get('scanned', 0) > 0 and not host.get('hits'),
                     {'device': report, 'host_hits': host.get('hits')})
            if url_tokens:   # found in those access logs once the client used the link (a stopped run may not have)
                used = getattr(self, 'link_used', False)
                ev.check('leaks: the public link token is only in the web servers\' access logs of the client\'s own '
                         'public-link requests', report.get('url_token_hits_elsewhere') == 0
                         and (report.get('url_token_access_log_hits', 0) > 0 or not used),
                         {'client_used_the_link': used,
                          **{k: report.get(k) for k in ('url_token_access_log_hits', 'url_token_hits_elsewhere')}})

    return Run


def run_case(nc, bridge, ev, secrets, lease, commit, case, facts):
    """Inside the woken stack: the steps, then (always) the recovery, the cleanup gate, the owned cleanup and the leak
    scan. Returns whether dev-e's own Nextcloud is verifiably back and nothing of this run is left."""
    d = nc.drv
    Run = make_run(nc, bridge, ev, secrets, lease, commit, case)
    run_args = SimpleNamespace(run=True, candidate=False, draft_entry=False, facts=facts, secrets=secrets)
    run = Run(run_args, ev)
    run.lock_started = case.lock_started
    case.run = run
    original_helper, original_wait = d.helper, d.wait_job

    def guarded_helper(command, request=None, **kwargs):
        r6.owned_command(command, request, d.STATE)   # delete/restore-start only of owned backups, never the baseline
        if command == 'upload-abort' and (request or {}).get('upload_id') not in case.own_uploads:
            raise ValueError('fixed-upload-abort-not-owned-by-this-run')
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
             ('verify', lambda: run.verify('import')), ('restart', run.restart), ('rollback', run.rollback),
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


def cancel_new_jobs(d, ev, case, *, until_recovery=False):
    """Cancel every job of this run (new since its start) that is queued or running; a failed read falls back to the
    jobs this run is waiting for. `until_recovery`: nothing more once the recovery has begun (its own restore of the
    import's safety backup must run)."""
    try:
        rows = d.ok('jobs', ev=ev).get('jobs') or []
    except Exception:   # noqa: BLE001
        rows = [{'id': job_id, 'state': 'running'} for job_id in case.inflight]
    for row in rows:
        if until_recovery and case.recovery.is_set():
            return
        if row.get('id') not in case.jobs_before and row.get('state') in ('queued', 'running'):
            try:
                d.helper('job-cancel', {'job_id': row['id']}, timeout=30)
            except Exception:   # noqa: BLE001
                pass


def watchdog(nc, ev, case, metrics):
    """R6's whole-run watch: a reserve or memory breach or the lease end trips it at once (a failed probe only after
    three in a row). Then this run's jobs (new since its start) are cancelled, and while the case still runs every job
    it starts later too (the page goes on after a trip until its own wait ends: its check, conversion or restore is
    cancelled as soon as it appears); once the recovery has begun the watch ends, as in R6 (a trip during the recovery
    cancels its restore once)."""
    d = nc.drv
    watch = r6.ResourceWatch(metrics)
    while not case.stop.wait(WATCH_INTERVAL):
        if case.tripped.is_set():
            if case.recovery.is_set():
                return
            cancel_new_jobs(d, ev, case, until_recovery=True)
            continue
        expired = time.time() >= case.expires + (RECOVERY_GRACE if case.recovery.is_set() else 0)
        try:
            reason = watch.sample(wake.device(control.RESOURCE, root=True, timeout=30), expired=expired)
        except Exception as error:   # noqa: BLE001
            reason = 'lease-expired' if expired else watch.failed(error)
        if reason is None:
            continue
        metrics['trip'] = {'reason': reason, 'at': time.time()}
        ev.log(f'watchdog: stopping this run: {reason}')
        in_recovery = case.recovery.is_set()
        case.tripped.set()
        cancel_new_jobs(d, ev, case, until_recovery=not in_recovery)
        if in_recovery:
            return


# ---------------------------------------------------------------- cold to cold (the whole run under the dev-e lock)

def control_run(lease, commit, lock_started, facts):
    """Admission, deploy, pin and wake, the case, the cold return: (exit status, evidence)."""
    nc, bridge = load_flow(facts), _load('focus_page_bridge', 'focus_r6_fullshare_page_bridge')
    d = nc.drv
    secrets = d.Secrets(nc.SECRET_FILES, nc.MARKERS)
    secrets.register('COCKPIT_PASSWORD', (LAB / 'secrets' / 'devadmin.pass').read_text().strip())
    kit = (LAB / 'secrets' / 'dev-e-kit.txt').read_text()
    secrets.register('R6_BASELINE_KIT', kit)
    for number, line in enumerate(kit.splitlines()):
        if line.startswith('AGE-SECRET-KEY-1'):
            secrets.register('R6_BASELINE_AGE_' + str(number), line)
    # The Office client's relay and the injected failure use this run's own names (focus_nextcloud_r6.run_locked).
    nonce = nonce_source.token_hex(6)
    nc.OFFICE = r6.render_office(nc.OFFICE, nonce)
    nc.DROPIN_REL = nc.DROPIN_DIR_REL + '/zz-focus-nextcloud-r6-page-' + nonce + '.conf'
    nc.FAIL_MARKER_REL = '.focus-nextcloud-r6-page-fail-' + nonce
    ev = nc.Ev(secrets, area=AREA)
    expires = expiry(lease)
    case = SimpleNamespace(expires=expires, lock_started=lock_started, tripped=threading.Event(), stop=threading.Event(),
                           recovery=threading.Event(), inflight=set(), jobs_before=set(), before=None, run=None,
                           uploads_before=None, own_uploads=set())
    try:             # an earlier run's receipt stays as it is (its pending flag too) until this run is admitted
        receipt = d.state_path()
        d.STATE.update(json.loads(receipt.read_text()) if receipt.exists() else {})
        pending = d.STATE.get('pending') is True
    except (OSError, ValueError):
        pending = True   # an unreadable receipt is the coordinator's to look at
    # Admission (cold): nothing below changes dev-e before every check passed.
    missing = sorted(k for k in FACT_SECRETS if not facts.get(k) or facts[k] not in secrets.values)
    try:
        st = nc.FIXTURE.lstat()
        fixture_ok = (nc.FIXTURE == FIXTURE and nc.FIXTURE_SHA == FIXTURE_SHA and nc.FIXTURE.is_file()
                      and not nc.FIXTURE.is_symlink() and st.st_size == FIXTURE_BYTES)
    except OSError:
        fixture_ok = False
    ev.save('facts-binding.json', {'case': CASE, 'fixture': nc.FIXTURE.name, 'fixture_ok': fixture_ok,
                                   'credential_names_missing': missing, 'files': len(facts.get('files') or {}),
                                   'users': len(facts.get('digests') or {})})
    if not ev.check('admission: the share run\'s facts name the original full-share fixture and only credentials this '
                    'lab holds', fixture_ok and not missing and 'HA_BACKUP_KEY' in secrets.values
                    and 'DEV_D_MARKER_NEXTCLOUD' in secrets.values, {'fixture_ok': fixture_ok, 'missing': missing}):
        return 2, ev
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
    estimate = page_peak(HISTORICAL_SIZES, nc.FIXTURE.stat().st_size)
    free = min(before['host_free_bytes'], before['root']['varlib_free_bytes'])
    if not ev.check('admission: the host keeps the 13 GiB reserve after the page import\'s historical peak (the upload '
                    'kept through conversion and restore)', free >= estimate['minimum_free_bytes'],
                    {'free_mib': free >> 20, 'peak_mib': estimate['additional_peak_bytes'] >> 20,
                     'required_mib': estimate['minimum_free_bytes'] >> 20}):
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
    ev.save('admission-budget.json', estimate)
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
        safe = run_case(nc, bridge, ev, secrets, lease, commit, case, facts)
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
                           'device_memory_cap_bytes': DEVICE_CAP, 'reserve_bytes': RESERVE, 'image_pulls': 0,
                           'page_seconds': PAGE_SECONDS, 'page_waits_seconds': PAGE_WAITS})
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
    emit(f'nextcloud full-share page: {sum(r["ok"] for r in results)}/{len(results)} {"PASS" if ok else "FAIL"}')
    return code if code else (0 if ok else 1)


def plan():
    """The offline plan: what the case binds, its resource model and its expected duration (no device, no secret)."""
    estimate = page_peak(HISTORICAL_SIZES, FIXTURE_BYTES)
    return {'status': 'offline-preparation-only', 'phase': PHASE, 'device': DEVICE, 'fixture': FIXTURE.name,
            'fixture_bytes': FIXTURE_BYTES, 'fixture_sha256': FIXTURE_SHA, 'apps': APPS,
            'confirmation_lines': 'as the actual check lists them (the full share: none)', 'baseline_id': BASELINE,
            'page': {'bound_seconds': PAGE_SECONDS, 'waits_seconds': PAGE_WAITS, 'step_budget_seconds': PAGE_STEP_BUDGET,
                     'rest_reserve_seconds': REST_RESERVE},
            'resources': {'reserve_bytes': RESERVE, 'watchdog_stop_free_bytes': RESERVE + MARGIN,
                          'historical_page_peak_bytes': estimate['additional_peak_bytes'],
                          'minimum_free_bytes_host_and_dev_e_var_lib': estimate['minimum_free_bytes'],
                          'helper_path_peak_bytes': estimate['helper_path_additional_peak_bytes'],
                          'device_cap_bytes': DEVICE_CAP, 'watchdog_stop_device_memory_bytes': DEVICE_CAP - MARGIN,
                          'admission_host_memory_available_mib': 2200, 'admission_device_headroom_mib': 1536,
                          'page_host_memory_available_mib': 1200, 'page_device_headroom_mib': 1280},
            'lease': {'headroom_seconds': LEASE_HEADROOM, 'case_budget_seconds': CASE_BUDGET,
                      'recovery_grace_seconds': RECOVERY_GRACE},
            'expected': {'checks': EXPECTED_CHECKS, 'minutes': '55-90 (page 20-50)'},
            'requires': ['dev-e Nextcloud cold with the five original images loaded (R6)', 'an exact fullshare-page lease',
                         'the share run\'s facts (--facts, default ' + str(FACTS) + ')',
                         'heavy.sh with HEAVY_FREE=' + LOCK, 'a committed checkout'],
            'mutations': 0}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--run', action='store_true')
    parser.add_argument('--lease', type=Path)
    parser.add_argument('--lease-template', action='store_true')
    parser.add_argument('--facts', type=Path, default=FACTS)
    args = parser.parse_args(argv)
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=REPO, text=True).strip()
    if args.lease_template:
        try:
            template = lease_template(commit, args.facts)
        except ValueError as error:
            print(f'fixed-r6-fullshare-page-facts-refused ({str(error)[:60]})', file=sys.stderr)
            return 2
        print(json.dumps(template, indent=2, sort_keys=True))
        return 0
    if not args.run:
        print(json.dumps(plan(), indent=2))
        return 0
    if args.lease is None:
        parser.error('--run requires a reviewed --lease')
    try:
        if subprocess.check_output(['git', 'status', '--porcelain'], cwd=REPO, text=True).strip():
            raise ValueError('fixed-committed-source-required')
        try:
            lease = json.loads(args.lease.read_text())
        except (OSError, ValueError):
            raise ValueError('fixed-lease-unreadable') from None
        facts, facts_sha = load_facts(args.facts)
        admit_lease(lease, commit, FIXTURE_SHA, facts_sha)
        if os.environ.get('HEAVY_FREE') != LOCK:
            raise ValueError('fixed-heavy-seat-required')
        with open(LOCK, 'a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            started = time.monotonic()
            try:
                admit_lease(lease, commit, FIXTURE_SHA, facts_sha)
                emit(f'source commit {commit}')
                code, ev = control_run(lease, commit, started, facts)
            finally:
                emit(f'lock held for {int(time.monotonic() - started)} s')
    except (ValueError, BlockingIOError) as error:
        print(f'fixed-r6-fullshare-page-preflight-refused ({str(error)[:60]}); no case mutation started', file=sys.stderr)
        return 2
    return finish(ev, code)


if __name__ == '__main__':
    sys.exit(main())
