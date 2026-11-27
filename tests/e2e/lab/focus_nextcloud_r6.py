#!/usr/bin/env python3
"""R6 full-share acceptance using the saved 113-check client/rollback harness.

Default prints the offline plan. --run requires an exact reviewed lease, an
cold original stack and a committed checkout. The source-only transaction uses
frozen d09f4fe8; no image recovery, installer, key creation or catalog replacement.
Separate conversion/restore lets the original 4.47GB upload be deleted before
restoring. The original source fixture and baseline archive are never deleted.
"""
import argparse
import hashlib
import fcntl
import datetime
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import secrets as nonce_source
import sys
import threading
import time
from types import SimpleNamespace

# Also works with python3 -I; imports are restricted to this committed directory.
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from focus_nextcloud_r6_inventory import collect, ORIGINALS, FIXTURE, FIXTURE_SHA
from focus_nextcloud_r6_plan import (BASELINE, CASES, DEVICE_CAP, FIXTURE_BYTES, MARGIN, MIB, RESERVE,
                                      acceptance_budget, confirmation_keys, lease_check, verified_credit_budget)

REPO = HERE.parents[2]
LAB = Path.home() / '.woowbk-lab'
LOCK = '/tmp/woowbk-dev-e-mutation.lock'
FACTS = Path('/tmp/claude-1000/-home-woowtechopenclaw/a15a4de1-3ce4-4692-84a2-243bd175349a/scratchpad/nc-import/share-facts.json')
RECEIPT = LAB / 'run/focus_nextcloud_r6.json'
INACTIVE_UNITS = ('nextcloud.target', 'nextcloud-app.service', 'nextcloud-db.service',
                  'nextcloud-redis.service', 'nextcloud-office.service', 'nextcloud-gateway.service',
                  'nextcloud-cron.timer', 'woowtech-backup-schedule.timer')


def baseline_verify():
    """Independent existing verifier, with private output (never argv/credentials)."""
    p = subprocess.run([sys.executable, '-I', str(HERE / 'batch2_baseline.py'), '--verify', 'nextcloud'],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1200)
    return p.returncode == 0


def load_flow(receipt=None):
    """A fresh nextcloud_flow (and b1 driver) whose receipt is `receipt` (default: this R6 case's own)."""
    spec = importlib.util.spec_from_file_location('focus_r6_original_flow', HERE / 'nextcloud_flow.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.FLOOR = mod.WATCH_FLOOR = RESERVE
    path = RECEIPT if receipt is None else receipt
    mod.drv.state_path = lambda: path
    return mod


def validate_facts(facts, case):
    """Full-share uses the original exact file; derivative cases need separate provenance."""
    if case not in CASES:
        raise ValueError('fixed-case-refused')
    if not facts.get('digests') or not facts.get('files') or not facts.get('section', {}).get('datadir_in_backup'):
        raise ValueError('fixed-full-share-facts-required')
    if any(not str(facts.get(k, '')).startswith('B2_NC_')
           for k in ('user_pw', 'app_pw', 'user2_pw', 'link_pw', 'link_token')):
        raise ValueError('fixed-secret-name-facts-required')
    if case == 'fullshare' and (Path(facts['fixture']) != FIXTURE or facts['sha256'] != FIXTURE_SHA):
        raise ValueError('fixed-original-fixture-required')
    if case != 'fullshare':
        # These require separately reviewed real fixture construction and oracles.
        # No switch or synthetic database flag is accepted as an encryption proof.
        raise ValueError('fixed-derived-fixture-review-required')


def render_office(body, nonce):
    body = body.replace('woowbk-ncoffice-relay', 'woowbk-r6-relay-' + nonce)
    body = body.replace('~/.woowbk-ncoffice', '~/.woowbk-r6-office-' + nonce)
    body = body.replace('"--pull=never",', '"--pull=never", "--image-volume=ignore",')
    return body.replace('docker.io/nginxinc/nginx-unprivileged:1.29.3-alpine',
                        'sha256:' + ORIGINALS['docker.io/nginxinc/nginx-unprivileged:1.29.3-alpine'])


def owned_command(command, request, state):
    if command in ('delete', 'restore-start'):
        bid = (request or {}).get('backup_id')
        if not bid or bid == BASELINE or bid not in state.get('created_backups', []):
            raise ValueError('fixed-backup-command-not-owned-by-this-case')
    if command == 'ha-delete' and ((request or {}).get('ha_backup_id') is None or
                                   request['ha_backup_id'] != state.get('ha_backup_id')):
        raise ValueError('fixed-ha-delete-not-owned-by-this-case')


def convert_request(ha, apps, test_mode, key, keys, request_id):
    """The ha-convert-start request: only fields of the product's schema (cli.SPECS). The check job this conversion
    follows stays in the case's own records; only ha-import-start takes a check_job_id (fullshare03 sent one and the
    helper refused the whole request)."""
    return {'ha_backup_id': ha, 'apps': list(apps), 'test_mode': test_mode, 'confirm': True,
            'request_id': request_id, 'key': key, 'acknowledged': {'nextcloud': list(keys)}}


def stop_detail(error, secrets):
    """Why the case stopped, for the private run log: the exception class and its redacted text, bounded."""
    return (type(error).__name__ + ': ' + secrets.redact(str(error)))[:600]


PROBE_TRIES = 3  # failed or timed-out resource probes in a row before the watchdog stops the case


class ResourceWatch:
    """The watchdog's decision. A breach of the reserve or of the memory limit, or the lease end, stops the case at
    once; a failed or timed-out probe only after PROBE_TRIES in a row (fullshare04 lost its auto-rollback restore to
    one probe on a host at load 26 while the device had 27.3 GiB free and used 1.59 GiB). Between readings the
    kernel still enforces the device's memory.max and the engine its own space guard."""

    def __init__(self, metrics, tries=PROBE_TRIES):
        self.metrics, self.tries, self.failures = metrics, tries, 0

    def sample(self, resource, *, expired):
        """None while the reading is within bounds, else why to stop (a malformed reading raises: a failed probe)."""
        free, memory = resource['free'], resource['memory']
        self.failures = 0
        m = self.metrics
        m['minimum_free_bytes'] = min(m['minimum_free_bytes'] or free, free)
        m['peak_memory_current_bytes'] = max(m['peak_memory_current_bytes'], memory)
        if expired:
            return 'lease-expired'
        if free < RESERVE + MARGIN or memory > DEVICE_CAP - MARGIN:
            return {'free': free, 'memory': memory}
        return None

    def failed(self, error):
        """None until PROBE_TRIES probes in a row failed, then why to stop."""
        self.failures += 1
        self.metrics['probe_failures'] = self.metrics.get('probe_failures', 0) + 1
        if self.failures < self.tries:
            return None
        return f'{self.failures} resource probes in a row failed, the last with {type(error).__name__}'


def cleanup_after_refusal(run,args,lease,driver,ev,deadline,*,baseline_safe,baseline_exact):
    """Opt in to keeping a proven owned HA after refusal before any conversion request."""
    receipt=getattr(args,'retained_upload',None)
    requested=any(r.get('command') in ('ha-convert-start','restore-start')
                  for r in driver.STATE.get('requests',{}).values())
    if (lease.get('retain_verified_ha_on_preconversion_refusal') is not True or receipt is None
            or run.created_store is None or getattr(run,'converted',None) or getattr(run,'safety',None) or requested):
        run.cleanup();return False
    if not baseline_safe or not baseline_exact:
        raise RuntimeError('fixed-retained-ha-baseline-not-proven')
    expected=lease.get('retained_upload_receipt_sha256')
    if (not expected or driver.STATE.get('retained_upload_receipt_sha256')!=expected
            or driver.STATE.get('ha_backup_id')!=run.created_store or driver.STATE.get('upload_id') is not None
            or receipt.get('ha_backup_id')!=run.created_store):
        raise ValueError('fixed-retained-ha-owner-binding-refused')
    import focus_nextcloud_r6_case as control
    import focus_nextcloud_r6_upload as upload_proof
    def quiescent():
        # CLI jobs is limited to50; the existing native probe checks the complete bounded store.
        if control.wake.device(control.QUIESCENT,root=True)['active_jobs']!=0:
            raise RuntimeError('fixed-retained-ha-native-writer-active')
    quiescent()
    trace=upload_proof.Evidence(LAB/'evidence/focus-nextcloud-r6-retained-after-refusal'/time.strftime('%Y%m%dT%H%M%S'))
    current=upload_proof.verify_retained(run.created_store,deadline,trace)
    upload_proof.retained_credit(receipt,current)  # Recheck full SHA/bytes/inode/sidecar/provenance; add no budget credit.
    quiescent()
    ev.save('preconversion-owned-ha-retained.json',{
        'ha_backup_id':run.created_store,'retained_upload_receipt_sha256':expected,'current_proof':current,
        'baseline_exact':True,'complete_native_jobs_quiescent':True,'conversion_requested':False})
    driver.STATE['retained_verified_ha_id']=run.created_store;driver.save_state()
    owned_ha=run.created_store;run.created_store=None
    try:run.cleanup()  # Keep this HA only; retain all existing owned-object cleanup and leak gates.
    finally:run.created_store=owned_ha
    ev.check('cleanup: verified owned HA retained after preconversion refusal',True)
    return True


def execute(args):
    import focus_nextcloud_r6_case as case
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=REPO, text=True).strip()
    if subprocess.check_output(['git', 'status', '--porcelain'], cwd=REPO, text=True).strip():
        raise ValueError('fixed-committed-source-required')
    lease = json.loads(args.lease.read_text())
    lease_check(lease, commit, args.case)
    if sorted(lease.get('original_inactive_units', [])) != sorted(INACTIVE_UNITS):
        raise ValueError('fixed-original-inactive-unit-scope-required')
    facts = json.loads(args.facts.read_text())
    validate_facts(facts, args.case)
    with open(LOCK, 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return case.run(args, lease, commit, facts, sys.modules[__name__])


def run_locked(args, lease, commit, facts, inventory, variant=None):
    """The R6 case body. `variant` (None = the full share) is another case of this lane on the same machinery
    (focus_nextcloud_r6_s5b.Variant): its receipt and evidence area, secrets registered before any evidence, a Run
    subclass with its own steps, its convert request (schema fields only), its upload size and scope fields. The
    request recording, job waits, watchdog, recovery, rollback, cleanup and leak gates below stay the same."""
    import focus_nextcloud_r6_case as control
    nc = load_flow(variant.receipt if variant else None)
    nc.tree_hashes = lambda: args.product_hashes
    d = nc.drv
    secrets = d.Secrets(nc.SECRET_FILES, nc.MARKERS)
    if variant:
        variant.prepare(secrets)
    ev = nc.Ev(secrets, area=variant.area if variant else 'focus-nextcloud-r6')
    d.STATE.clear()  # Only the NEW R6 receipt; legacy nextcloud_flow.json is untouched.
    d.STATE.update(pending=True, source_commit=commit, case=args.case, created_backups=[],
                   jobs={}, original_baseline_id=BASELINE, upload_id=None, ha_backup_id=None)
    d.save_state()
    nc.FIXTURE, nc.FIXTURE_SHA, nc.SECTION = Path(facts['fixture']), facts['sha256'], dict(facts['section'])
    nonce = nonce_source.token_hex(6)
    # The old client's relay uses this run's own paths/name and a loaded exact ID.
    nc.OFFICE = render_office(nc.OFFICE, nonce)
    nc.DROPIN_REL = nc.DROPIN_DIR_REL + '/zz-focus-nextcloud-r6-' + nonce + '.conf'
    nc.FAIL_MARKER_REL = '.focus-nextcloud-r6-fail-' + nonce
    run_args = SimpleNamespace(run=True, candidate=False, draft_entry=False, facts=facts, secrets=secrets)
    original_helper = d.helper
    def guarded_helper(command, request=None, **kwargs):
        owned_command(command, request, d.STATE)
        if command.endswith('-start'):
            request_id = (request or {}).get('request_id')
            if not request_id:
                raise nc.Failed('fixed-start-request-id-required')
            d.STATE.setdefault('requests', {})[request_id] = {'command': command, 'reply_job_id': None}
            d.save_state()  # No key/credential/request body is persisted.
        result = original_helper(command, request, **kwargs)
        if command.endswith('-start') and result[0] == 0:
            job_id = result[1].get('job_id')
            if job_id:
                d.STATE['requests'][request_id]['reply_job_id'] = job_id
                d.STATE['jobs'].setdefault(job_id, {'state': 'queued'})
                d.save_state()
        return result
    d.helper = guarded_helper
    expires = datetime.datetime.fromisoformat(lease['expires_utc'].replace('Z', '+00:00')).timestamp()
    recovery_mode = threading.Event()
    original_wait = d.wait_job
    inflight = set()
    stop = threading.Event()
    tripped = threading.Event()
    metrics = {'minimum_free_bytes': None, 'peak_memory_current_bytes': 0}

    def require(label, ok):
        if not ev.check(label, ok):
            raise nc.Failed(label)

    def record_job(job):
        row = d.STATE['jobs'].setdefault(job['id'], {})
        row.update(state=job.get('state'))
        for field in ('backup_id', 'safety_backup_id'):
            value = (job.get('result') or {}).get(field)
            if value and value != BASELINE:
                d.created_backup(value)
        d.save_state()

    # Record the pre-existing jobs so a lost start reply cannot make a writer
    # invisible to recovery. Unexpected running jobs block cleanup, not get cancelled.
    jobs_before = {x['id'] for x in d.ok('jobs', ev=ev).get('jobs') or []}
    require('preflight: no existing job is running', not any(
        x.get('state') in ('queued', 'running') for x in d.ok('jobs', ev=ev).get('jobs') or []))

    def wait(job_id, *, ev, timeout=5400):
        inflight.add(job_id)
        d.STATE['jobs'][job_id] = {'state': 'running'}
        d.save_state()  # Persist BEFORE waiting, including when the wait raises.
        deadline = expires + (1800 if recovery_mode.is_set() else 0)
        job = original_wait(job_id, ev=ev, timeout=min(timeout, 3600, max(1, int(deadline-time.time()))))
        record_job(job)
        inflight.discard(job_id)
        return job

    d.wait_job = wait

    class Run(nc.Run):
        def budget(self, phase, need=0, *, timed=True):
            if not timed and time.time() >= expires + 1800:
                raise nc.Failed('fixed-recovery-grace-expired')
            if timed:
                lease_check(lease, commit, args.case)
                if time.monotonic() - self.lock_started > 100 * 60 or tripped.is_set():
                    raise nc.Failed('fixed-case-budget-reached')
            if control.wake.device(control.RESOURCE, root=True, timeout=30)['free'] < RESERVE + MARGIN + need:
                raise nc.Failed('fixed-reserve-preflight-refused')

        def setup(self):
            require('setup: installed engine equals committed source',
                    d.device_python(nc.ENGINE_HASHES, as_owner=False) == nc.tree_hashes())
            require('setup: original catalog hash retained',
                    inventory['root']['catalog_sha256'] ==
                    '3a7af03b966f90a172e417a3ea69d7b36bf98a23af8d27b0c074bd01b6f335d6')
            state = self.state()
            require('setup: five units active and Nextcloud healthy',
                    set(state.get('units', {})) == set(nc.UNITS)
                    and all(x == 'active' for x in state['units'].values())
                    and state.get('status', {}).get('installed') is True
                    and state['status'].get('version') == '35.0.1.1'
                    and state['status'].get('maintenance') is False)

        def before_state(self):
            kit = (LAB / 'secrets/dev-e-kit.txt').read_text()
            secrets.register('R6_BASELINE_KIT', kit)
            for number, line in enumerate(kit.splitlines()):
                if line.startswith('AGE-SECRET-KEY-1'):
                    secrets.register('R6_BASELINE_AGE_' + str(number), line)
            inspected = control.wake.device(control.BASELINE_INSPECT, {'key': kit}, root=True, timeout=900)
            ev.save('original-encrypted-baseline-inspect.json', inspected)
            require('before: original encrypted baseline opens with existing private kit',
                    inspected.get('encrypted_manifest_opened') is True)
            super().before_state()
            sizes = self.before['sizes']
            require('before: fresh live directory sizes available',
                    all(isinstance(sizes.get(k), int) for k in ('html', 'postgres', 'data')))
            bound = acceptance_budget(sizes['html'], sizes['postgres'],
                                      max(sizes['data'], 234187031), 1024**3, 1024**3,
                                      uploaded=variant.uploaded_bytes if variant else FIXTURE_BYTES)
            bound=verified_credit_budget(bound,getattr(args,'retained_credit_bytes',0))
            ev.save('fresh-budget.json', bound)
            self.budget('fullshare admission', bound['additional_peak_bytes'])

        def upload(self):
            retained=getattr(args,'retained_upload',None)
            if retained is not None:
                self.created_store=retained['ha_backup_id']
                d.STATE.update(ha_backup_id=self.created_store,upload_id=None,retained_upload_receipt_sha256=lease['retained_upload_receipt_sha256'])
                d.save_state();require('upload: verified owned retained store reused without transfer',True)
                return
            self.budget('upload', nc.FIXTURE.stat().st_size + 3 * 1024**3)
            require('upload: original fixture exact size retained', nc.FIXTURE.stat().st_size == 4467947520)
            begin = d.ok('upload-begin', {'filename': nc.FIXTURE.name, 'size': nc.FIXTURE.stat().st_size}, ev=ev)
            d.STATE['upload_id'] = begin['upload_id']
            d.save_state()
            proc = subprocess.Popen([str(d.LP), 'exec', '-i', d.DEVICE, 'python3', '-I', '-c', control.UPLOAD,
                                     begin['path'], str(nc.FIXTURE.stat().st_size), nc.FIXTURE_SHA, str(expires)],
                                    stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            h = hashlib.sha256(); count = 0
            try:
                with nc.FIXTURE.open('rb') as source:
                    for chunk in iter(lambda: source.read(1 << 20), b''):
                        if count % (16 * MIB) == 0: self.budget('upload stream')
                        h.update(chunk); count += len(chunk)
                        if count > 4467947520: raise nc.Failed('fixed-upload-size-bound-refused')
                        proc.stdin.write(chunk)
                proc.stdin.close()
                require('upload: bounded stream completed', proc.wait(timeout=120) == 0)
            finally:
                if not proc.stdin.closed:
                    proc.stdin.close()  # EOF stops the exact upload writer, not unrelated jobs.
                if proc.poll() is None:
                    proc.wait(timeout=120)
            require('upload: streaming bytes and SHA256 match before finish',
                    count == 4467947520 and h.hexdigest() == nc.FIXTURE_SHA)
            result = d.ok('upload-finish', {'upload_id': begin['upload_id']}, ev=ev, timeout=1800)
            self.created_store = result['ha_backup']['id']
            d.STATE.update(upload_id=None, ha_backup_id=self.created_store)
            d.save_state()

        def check(self):
            job, took = d.run_check(self.created_store, ['nextcloud'], ev=ev, key=secrets['HA_BACKUP_KEY'])
            self.check_id = job['id']
            self.keys = confirmation_keys(job, args.case)
            app = job['result']['ha_check']['apps'][0]
            self.section = app.get('nextcloud') or {}
            require('check: current facts match original full-share source',
                    all(self.section.get(k) == v for k, v in nc.SECTION.items()))
            require('check: original full-share needs no confirmation', self.keys == [])
            ev.time('check', args.case, 'nextcloud', took, job)

        def watch_host(self, stop, tripped):
            # A single whole-case watcher below owns cancellation.
            stop.wait()

        def inject(self, on):
            if on:
                require('rollback: new owned injection paths are absent', all(
                    d.owner('test', '-e', '/home/appowner/' + path, timeout=30).returncode == 1
                    for path in (nc.DROPIN_REL, nc.FAIL_MARKER_REL)))
                self.preexisting_dropin_dir = d.owner('test', '-d', '/home/appowner/' + nc.DROPIN_DIR_REL,
                                                     timeout=30).returncode == 0
                super().inject(True)
            else:
                d.owner('rm', '-f', '/home/appowner/' + nc.DROPIN_REL,
                        '/home/appowner/' + nc.FAIL_MARKER_REL, timeout=60)
                if not getattr(self, 'preexisting_dropin_dir', True):
                    d.owner('rmdir', '/home/appowner/' + nc.DROPIN_DIR_REL, timeout=60)
                d.owner('systemctl', '--user', 'daemon-reload', timeout=120)

        def leaks(self):
            super().leaks()
            values = {k: v for k, v in secrets.values.items() if k.startswith('R6_BASELINE_')}
            report = d.device_python(nc.LEAKS, {'secrets': values, 'url_tokens': []}, as_owner=False, timeout=900)
            host = d.scan_host_evidence(ev.dir, secrets)
            ev.save('baseline-kit-leak-summary.json', {'device': report, 'host': host})
            require('leaks: existing baseline kit absent from records and evidence',
                    report.get('hits') == 0 and report.get('scanned', 0) > 0 and not host.get('hits'))

        def manual_rollback(self, phase):
            self.restored_back = False
            first = len(ev.results)
            super().manual_rollback(phase)
            self.restored_back = False
            require('recovery: original baseline independently verified', baseline_verify())
            require('recovery: exact pre-import markers restored', self.markers() == self.before['markers'])
            require('recovery: all rollback checks passed', all(x['ok'] for x in ev.results[first:]))
            self.restored_back = True

    if variant:
        Run = variant.run_class(Run, SimpleNamespace(d=d, nc=nc, ev=ev, secrets=secrets, require=require, wait=wait,
                                                     lease=lease, commit=commit, args=args, expires=expires,
                                                     control=control))
    r = Run(run_args, ev)

    def convert(ha, apps, test_mode, *, ev, key, tag):
        build = variant.convert_request if variant else convert_request
        request = build(ha, apps, test_mode, key, r.keys, d.request_id('focus-r6-convert'))
        started = time.monotonic()
        reply = d.ok('ha-convert-start', request, ev=ev, timeout=300)
        return wait(reply['job_id'], ev=ev), time.monotonic() - started

    d.convert = convert

    def watchdog():
        watch = ResourceWatch(metrics)
        while not stop.wait(1):
            expired = time.time() >= expires + (1800 if recovery_mode.is_set() else 0)
            try:
                reason = watch.sample(control.wake.device(control.RESOURCE, root=True, timeout=30), expired=expired)
            except Exception as error:
                reason = 'lease-expired' if expired else watch.failed(error)
            if reason is None: continue
            metrics['trip'] = {'reason': reason, 'at': time.time()}
            ev.log(f'watchdog: stopping this run: {reason}')
            tripped.set()
            # Cancel only this run's recorded jobs; leave other device jobs untouched.
            for job_id in tuple(inflight):
                try: d.helper('job-cancel', {'job_id': job_id}, timeout=30)
                except Exception: pass
            return

    watcher = threading.Thread(target=watchdog, daemon=True)
    watcher.start()
    safe = False
    steps = variant.steps(r) if variant else (r.setup, r.before_state, r.upload, r.check, r.import_real,
                                              lambda: r.verify('import'), r.restart, r.rollback, r.after_state)
    try:
        for step in steps:
            r.budget('next acceptance step')
            step()
        safe = r.restored_back
    except Exception as error:
        ev.check('case stopped; recovery required', False, stop_detail(error, secrets))
    finally:
        try:
            stop.set(); watcher.join(timeout=40)
            require('recovery: admission watcher has returned', not watcher.is_alive())
            recovery_mode.set(); stop.clear()
            watcher = threading.Thread(target=watchdog, daemon=True); watcher.start()
            new_jobs = {x['id'] for x in d.ok('jobs', ev=ev).get('jobs') or []} - jobs_before
            require('recovery: every new job has a recorded ID', new_jobs <= set(d.STATE['jobs']))
            # No recovery/cleanup may race a timed-out job. Reconcile exact IDs first.
            for job_id in tuple(inflight):
                d.helper('job-cancel', {'job_id': job_id}, timeout=30)
                job = original_wait(job_id, ev=ev, timeout=min(900,max(1,int(expires+1800-time.time()))))
                record_job(job)
                inflight.discard(job_id)
            # Adopt a safety ID even if the original wait failed before returning it to Run.
            if not r.safety:
                for job_id in d.STATE['jobs']:
                    job = d.ok('job-status', {'job_id': job_id}, ev=ev)['job']
                    if (job.get('result') or {}).get('safety_backup_id'):
                        r.safety = job['result']['safety_backup_id']
                        break
            if r.safety and not r.restored_back:
                r.manual_rollback('recovery')
            safe = baseline_verify() and (not r.safety or r.restored_back) and not inflight
            require('cleanup gate: original baseline independently verified', safe)
            baseline_exact=False
            if r.before:
                r.after_state()
                after_checks=[x for x in ev.results if x['check'].startswith('after:')]
                baseline_exact=bool(after_checks) and all(x['ok'] for x in after_checks)
                require('cleanup gate: exact baseline state comparisons passed',baseline_exact)
            cleanup_after_refusal(r,args,lease,d,ev,expires+1800,baseline_safe=safe,baseline_exact=baseline_exact)
            if d.STATE.get('upload_id'):
                d.ok('upload-abort', {'upload_id': d.STATE['upload_id']}, ev=ev)
            r.leaks()
            require('cleanup: all deletion and leak checks passed', all(
                x['ok'] for x in ev.results if x['check'].startswith(('cleanup:', 'leaks:'))))
            d.STATE['pending'] = False
            d.save_state()
        except Exception as error:
            safe = False
            ev.check('recovery copies retained; coordinator must reconcile receipt', False, type(error).__name__)
        stop.set()
        watcher.join(timeout=40)
        if watcher.is_alive():
            safe = False; d.STATE['pending'] = True; d.save_state()
    ev.save('scope.json', {'source_commit': commit, 'product_commit': control.source.PRODUCT_COMMIT, 'case': args.case, 'baseline_safe': safe,
                          'original_fixture_reused': True, 'image_pulls': 0,
                          'device_memory_cap_bytes': DEVICE_CAP, 'reserve_bytes': RESERVE, 'sampled_resources': metrics,
                          **(variant.scope(r) if variant else {})})
    return 0 if ev.finish() and safe else 1


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--run', action='store_true')
    p.add_argument('--lease', type=Path)
    p.add_argument('--facts', type=Path, default=FACTS)
    from focus_nextcloud_r6_source import FROZEN
    p.add_argument('--retained-upload-receipt',type=Path)
    p.add_argument('--product-source', type=Path, default=FROZEN)
    p.add_argument('--case', choices=tuple(CASES), default='fullshare')
    args = p.parse_args()
    if not args.run:
        print(json.dumps({'status': 'offline-preparation-only', 'prepared_case': 'fullshare',
                          'derivative_cases': 'require genuine fixtures and separate review',
                          'requires': ['original five images recovered and stack cold', 'frozen d09 source-only transaction',
                                       'exact source/device/phase lease', 'heavy.sh', 'whole device mutex'],
                          'baseline_id': BASELINE, 'reserve_bytes': RESERVE, 'device_cap_bytes': DEVICE_CAP,
                          'mutations': 0}, indent=2))
        return 0
    if args.lease is None:
        p.error('--run requires a reviewed --lease')
    return execute(args)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, BlockingIOError):
        print('fixed-r6-preflight-refused; no case mutation started', file=sys.stderr)
        sys.exit(2)
